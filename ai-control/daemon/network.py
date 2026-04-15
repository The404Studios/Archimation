"""
Network control module - full network management.

Provides:
- NetworkManager control via D-Bus
- Connection status
- WiFi management
- DNS configuration

All subprocess operations are async to avoid blocking the FastAPI event loop.
"""

import asyncio
import ipaddress
import json
import logging
import re
import time

logger = logging.getLogger("ai-control.network")

# Cache DNS / routes / wifi scan for a short TTL. These data sources rarely
# change between back-to-back requests, and nmcli/ip/resolvectl spawns are
# not free on slow hardware. Per-function TTL since stale WiFi data is more
# harmful than stale route tables.
_DNS_CACHE_TTL = 10.0
_ROUTES_CACHE_TTL = 5.0
_IPADDR_CACHE_TTL = 5.0
_WIFI_SCAN_TTL = 15.0


def _sanitize_log(s) -> str:
    if not isinstance(s, str):
        s = str(s)
    return s.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")[:512]


def _valid_hostname(host: str) -> bool:
    """Accept either a plain IPv4/IPv6 literal or a DNS label chain.

    Refuses anything that starts with '-' (argument injection into ping/nmcli),
    contains shell metacharacters, or contains whitespace/NUL.
    """
    if not isinstance(host, str) or not host or len(host) > 253:
        return False
    if host.startswith("-"):
        return False
    if any(c in host for c in "\x00\n\r \t;|&$`<>*?\"'\\"):
        return False
    # IP literal?
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Hostname: labels of [A-Za-z0-9-], separated by '.'. Underscores allowed
    # for SRV-style names.
    return all(
        re.fullmatch(r"[A-Za-z0-9_]([A-Za-z0-9_\-]{0,61}[A-Za-z0-9_])?", lbl) is not None
        for lbl in host.rstrip(".").split(".")
    )


def _valid_ssid(ssid: str) -> bool:
    """SSIDs can be up to 32 bytes; reject flag-lead and control chars."""
    if not isinstance(ssid, str) or not ssid:
        return False
    if ssid.startswith("-"):
        return False
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in ssid):
        return False
    try:
        if len(ssid.encode("utf-8")) > 32:
            return False
    except UnicodeEncodeError:
        return False
    return True


def _valid_wifi_password(pw: str) -> bool:
    """WPA-PSK passphrases are 8..63 printable ASCII, or 64 hex."""
    if not isinstance(pw, str) or not pw:
        return False
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in pw):
        return False
    if not (8 <= len(pw) <= 63 or (len(pw) == 64 and all(c in "0123456789abcdefABCDEF" for c in pw))):
        return False
    return True


def _valid_connection_name(name: str) -> bool:
    """NetworkManager connection name — saved-connection identifier."""
    if not isinstance(name, str) or not name:
        return False
    if name.startswith("-"):
        return False
    if any(c in name for c in "\x00\n\r"):
        return False
    return len(name) <= 256


def _valid_nm_device(dev: str) -> bool:
    if not isinstance(dev, str) or not dev or dev.startswith("-"):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9._:\-]{1,32}", dev))


async def _run(*args, timeout: int = 10):
    """Run a subprocess asynchronously."""
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except asyncio.TimeoutError:
        if proc is not None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await proc.wait()  # Reap the killed process to prevent zombies
            except Exception:
                pass
        return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", f"{args[0]} not found"
    except Exception as exc:
        # Ensure the process is reaped on any unexpected error
        if proc is not None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await proc.wait()
            except Exception:
                pass
        return -1, "", str(exc)


class NetworkController:
    """Full network control capabilities."""

    def __init__(self):
        # Per-call TTL caches — bounded by time, not size.
        self._ipaddr_cache: tuple[list, float] | None = None
        self._routes_cache: tuple[list, float] | None = None
        self._dns_cache: tuple[list, float] | None = None
        self._wifi_scan_cache: tuple[dict, float] | None = None

    async def get_connections(self) -> list[dict]:
        # Use \n as field separator to avoid colon-splitting issues
        # (connection names and states can contain colons)
        rc, out, _ = await _run(
            "nmcli", "-t", "-f", "NAME,TYPE,DEVICE,STATE",
            "-e", "no", "connection", "show",
            timeout=10,
        )
        connections = []
        for line in out.strip().split("\n"):
            if not line:
                continue
            # nmcli -t uses : as separator; use rsplit to handle colons in names
            # Fields: NAME:TYPE:DEVICE:STATE (STATE is last, no colons)
            parts = line.rsplit(":", 3)
            if len(parts) >= 4:
                connections.append({
                    "name": parts[0],
                    "type": parts[1],
                    "device": parts[2],
                    "state": parts[3],
                })
        return connections

    async def get_wifi_list(self) -> list[dict]:
        await _run("nmcli", "device", "wifi", "rescan", timeout=15)
        rc, out, _ = await _run(
            "nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY",
            "-e", "no", "device", "wifi", "list",
            timeout=10,
        )
        networks = []
        for line in out.strip().split("\n"):
            if not line:
                continue
            # SECURITY is last field and can contain colons (WPA2/WPA3)
            # SIGNAL is numeric, no colons. SSID can have colons.
            # Split from right: last field = SECURITY, second-to-last = SIGNAL
            parts = line.rsplit(":", 2)
            if len(parts) >= 3:
                networks.append({
                    "ssid": parts[0],
                    "signal": parts[1],
                    "security": parts[2],
                })
        return networks

    async def wifi_scan(self) -> dict:
        """Force a WiFi rescan and return deduplicated results with full info.

        Cached for _WIFI_SCAN_TTL seconds. NetworkManager throttles its own
        rescan internally (min 30s between hard scans), so polling this API
        faster than the TTL wastes a 2s sleep + nmcli fork per request.
        """
        now = time.monotonic()
        cached = self._wifi_scan_cache
        if cached is not None and (now - cached[1]) < _WIFI_SCAN_TTL:
            return cached[0]
        await _run("nmcli", "device", "wifi", "rescan", timeout=15)
        # Brief pause so NetworkManager populates scan results
        await asyncio.sleep(2)
        rc, out, _ = await _run(
            "nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY,FREQ,BSSID,IN-USE",
            "-e", "no", "device", "wifi", "list",
            timeout=10,
        )
        networks = []
        for line in out.strip().split("\n"):
            if not line.strip():
                continue
            # nmcli -t uses ':' separator; BSSID contains colons so we split carefully.
            # Fields: SSID:SIGNAL:SECURITY:FREQ:BSSID(XX\:XX\:XX\:XX\:XX\:XX):IN-USE
            # nmcli escapes colons inside values with '\:' when -e no is NOT set,
            # but with -e no, colons are literal. We split from the right since
            # IN-USE is single char, BSSID is fixed 17 chars with 5 colons.
            # Strategy: split on ':', last field is IN-USE, preceding 5+1 fields
            # are BSSID (6 parts joined by ':'), then FREQ, SECURITY, SIGNAL, SSID.
            parts = line.split(":")
            if len(parts) < 6:
                continue
            # IN-USE is last element
            in_use = parts[-1].strip()
            # BSSID is 6 hex pairs = parts[-7] through parts[-2]
            if len(parts) >= 11:
                bssid = ":".join(parts[-7:-1])
                freq = parts[-8] if len(parts) >= 12 else ""
                security = parts[-9] if len(parts) >= 12 else ""
                signal_str = parts[-10] if len(parts) >= 12 else ""
                ssid = ":".join(parts[:-10]) if len(parts) > 12 else parts[0] if len(parts) >= 12 else ""
            elif len(parts) >= 6:
                # Fallback: simpler parsing when BSSID may not have all parts
                bssid = parts[4] if len(parts) > 4 else ""
                freq = parts[3] if len(parts) > 3 else ""
                security = parts[2] if len(parts) > 2 else ""
                signal_str = parts[1] if len(parts) > 1 else "0"
                ssid = parts[0]
            else:
                continue
            networks.append({
                "ssid": ssid,
                "signal": int(signal_str) if signal_str.isdigit() else 0,
                "security": security,
                "frequency": freq,
                "bssid": bssid,
                "connected": in_use == "*",
            })
        # Sort by signal strength descending, deduplicate by SSID
        seen = set()
        unique = []
        for n in sorted(networks, key=lambda x: x["signal"], reverse=True):
            if n["ssid"] and n["ssid"] not in seen:
                seen.add(n["ssid"])
                unique.append(n)
        result = {"status": "ok", "networks": unique}
        # Re-sample time: the rescan + 2s sleep + nmcli list can take 15s+.
        self._wifi_scan_cache = (result, time.monotonic())
        return result

    async def connect_wifi(self, ssid: str, password: str = None) -> dict:
        if not _valid_ssid(ssid):
            return {"status": "error", "connected": False,
                    "message": "invalid SSID"}
        if password is not None and not _valid_wifi_password(password):
            return {"status": "error", "connected": False,
                    "message": "invalid password"}
        # `--` ends option parsing so an SSID that happens to start with '-'
        # (even after passing the validator change in the future) can't be
        # reinterpreted as a flag by nmcli.
        cmd = ["nmcli", "device", "wifi", "connect", "--", ssid]
        if password:
            cmd.extend(["password", password])
        rc, out, err = await _run(*cmd, timeout=30)
        return {
            "status": "ok" if rc == 0 else "error",
            "connected": rc == 0,
            "message": out.strip() if rc == 0 else (err.strip() or out.strip()),
        }

    async def disconnect_wifi(self) -> dict:
        """Disconnect the active WiFi device."""
        # Find the active wifi device
        rc, out, _ = await _run(
            "nmcli", "-t", "-f", "DEVICE,TYPE,STATE",
            "-e", "no", "device", "status",
            timeout=10,
        )
        wifi_dev = None
        for line in out.strip().split("\n"):
            parts = line.split(":")
            if len(parts) >= 3 and parts[1] == "wifi" and "connected" in parts[2]:
                wifi_dev = parts[0]
                break
        if not wifi_dev:
            return {"status": "ok", "message": "No active WiFi connection"}
        rc, out, err = await _run("nmcli", "device", "disconnect", wifi_dev, timeout=10)
        return {
            "status": "ok" if rc == 0 else "error",
            "message": out.strip() if rc == 0 else err.strip(),
        }

    async def disconnect(self, device: str = "wlan0") -> dict:
        if not _valid_nm_device(device):
            return {"success": False}
        rc, _, _ = await _run("nmcli", "device", "disconnect", "--", device, timeout=10)
        return {"success": rc == 0}

    async def wifi_saved(self) -> dict:
        """List saved/known WiFi connections."""
        rc, out, _ = await _run(
            "nmcli", "-t", "-f", "NAME,TYPE,AUTOCONNECT,TIMESTAMP",
            "-e", "no", "connection", "show",
            timeout=10,
        )
        saved = []
        for line in out.strip().split("\n"):
            if not line:
                continue
            parts = line.rsplit(":", 3)
            if len(parts) >= 4 and "wireless" in parts[1]:
                saved.append({
                    "name": parts[0],
                    "type": parts[1],
                    "autoconnect": parts[2].lower() == "yes",
                    "last_used": parts[3],
                })
        return {"status": "ok", "saved": saved}

    async def wifi_forget(self, name: str) -> dict:
        """Delete a saved WiFi connection by name."""
        if not _valid_connection_name(name):
            return {"status": "error", "message": "invalid connection name"}
        rc, out, err = await _run(
            "nmcli", "connection", "delete", "--", name,
            timeout=10,
        )
        return {
            "status": "ok" if rc == 0 else "error",
            "message": out.strip() if rc == 0 else err.strip(),
        }

    async def wifi_status(self) -> dict:
        """Get current WiFi connection status including SSID, signal, IP, speed."""
        # Get wifi device info
        rc, out, _ = await _run(
            "nmcli", "-t", "-f",
            "DEVICE,TYPE,STATE,CONNECTION",
            "-e", "no", "device", "status",
            timeout=10,
        )
        wifi_dev = None
        wifi_conn = None
        wifi_state = "disconnected"
        for line in out.strip().split("\n"):
            parts = line.split(":")
            if len(parts) >= 4 and parts[1] == "wifi":
                wifi_dev = parts[0]
                wifi_state = parts[2]
                wifi_conn = parts[3] if parts[3] != "--" else None
                break

        if not wifi_dev:
            return {
                "status": "ok",
                "wifi_enabled": False,
                "connected": False,
                "device": None,
            }

        # Check if wifi radio is enabled
        rc_radio, radio_out, _ = await _run(
            "nmcli", "radio", "wifi", timeout=5,
        )
        wifi_enabled = "enabled" in radio_out.lower()

        result = {
            "status": "ok",
            "wifi_enabled": wifi_enabled,
            "device": wifi_dev,
            "state": wifi_state,
            "connected": "connected" in wifi_state and wifi_conn is not None,
            "ssid": wifi_conn,
            "signal": 0,
            "speed": "",
            "ip_address": "",
            "security": "",
        }

        if result["connected"] and wifi_dev:
            # Get detailed connection info
            rc2, out2, _ = await _run(
                "nmcli", "-t", "-f",
                "GENERAL.CONNECTION,WIFI.SSID,WIFI.SIGNAL,WIFI.SECURITY,WIFI.BITRATE,IP4.ADDRESS",
                "-e", "no", "device", "show", wifi_dev,
                timeout=10,
            )
            for line in out2.strip().split("\n"):
                if ":" not in line:
                    continue
                key, _, val = line.partition(":")
                key = key.strip()
                val = val.strip()
                if key == "GENERAL.CONNECTION":
                    result["ssid"] = val
                elif key == "WIFI.SSID":
                    result["ssid"] = val
                elif key == "WIFI.SIGNAL":
                    result["signal"] = int(val) if val.isdigit() else 0
                elif key == "WIFI.SECURITY":
                    result["security"] = val
                elif key == "WIFI.BITRATE":
                    result["speed"] = val
                elif key == "IP4.ADDRESS[1]" or key == "IP4.ADDRESS":
                    result["ip_address"] = val

        return result

    async def get_ip_addresses(self) -> list[dict]:
        now = time.monotonic()
        cached = self._ipaddr_cache
        if cached is not None and (now - cached[1]) < _IPADDR_CACHE_TTL:
            return cached[0]
        rc, out, _ = await _run("ip", "-j", "addr", "show", timeout=5)
        if rc == 0:
            try:
                result = json.loads(out)
                self._ipaddr_cache = (result, now)
                return result
            except json.JSONDecodeError:
                pass
        rc, out, _ = await _run("ip", "addr", "show", timeout=5)
        result = [{"raw": out}]
        self._ipaddr_cache = (result, now)
        return result

    async def get_routes(self) -> list[dict]:
        now = time.monotonic()
        cached = self._routes_cache
        if cached is not None and (now - cached[1]) < _ROUTES_CACHE_TTL:
            return cached[0]
        rc, out, _ = await _run("ip", "-j", "route", "show", timeout=5)
        if rc == 0:
            try:
                result = json.loads(out)
                self._routes_cache = (result, now)
                return result
            except json.JSONDecodeError:
                pass
        return []

    async def get_dns_servers(self) -> list[str]:
        now = time.monotonic()
        cached = self._dns_cache
        if cached is not None and (now - cached[1]) < _DNS_CACHE_TTL:
            return cached[0]
        rc, out, _ = await _run("resolvectl", "status", timeout=5)
        if rc == 0:
            servers = []
            for line in out.split("\n"):
                if "DNS Servers:" in line:
                    servers.extend(line.split(":")[1].strip().split())
            if servers:
                self._dns_cache = (servers, now)
                return servers

        # Fallback to /etc/resolv.conf
        loop = asyncio.get_running_loop()
        servers = await loop.run_in_executor(None, self._read_resolv_conf)
        self._dns_cache = (servers, now)
        return servers

    @staticmethod
    def _read_resolv_conf() -> list[str]:
        try:
            with open("/etc/resolv.conf", "r") as f:
                return [
                    line.split()[1]
                    for line in f
                    if line.startswith("nameserver")
                ]
        except Exception:
            return []

    async def ping(self, host: str, count: int = 4) -> dict:
        if not _valid_hostname(host):
            return {"success": False, "output": "invalid host"}
        try:
            count = int(count)
        except (TypeError, ValueError):
            return {"success": False, "output": "invalid count"}
        count = max(1, min(count, 20))
        rc, out, _ = await _run(
            "ping", "-c", str(count), "-W", "2", "--", host,
            timeout=count * 3 + 5,
        )
        return {"success": rc == 0, "output": out}
