"""
System control module - full system management capabilities.

Provides:
- Package management (pacman)
- Service control (systemd)
- Process management
- System information

All subprocess operations are async to avoid blocking the FastAPI event loop.
"""

import asyncio
import logging
import os
import re
import signal
import time

logger = logging.getLogger("ai-control.system")

# os.uname() and os.cpu_count() are static after boot — cache once.
_uname = os.uname()
_HOSTNAME = _uname.nodename
_KERNEL = _uname.release
_CPU_COUNT = os.cpu_count() or 1

# PIDs we never allow to be signalled from the API boundary.
_PROTECTED_PIDS = {0, 1}


def _sanitize_log(s) -> str:
    if not isinstance(s, str):
        s = str(s)
    return s.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")[:512]


def _validate_unit_name(name: str) -> bool:
    """Validate a systemd unit name. Rejects flag-like / shell-metachar names."""
    if not isinstance(name, str) or not name or name.startswith("-"):
        return False
    if any(c in name for c in "\x00\n\r \t;|&$`<>*?\\\"'"):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9._@:\-]{1,253}", name))


def _validate_package_name(name: str) -> bool:
    """Validate a pacman package name or search query."""
    if not isinstance(name, str) or not name or name.startswith("-"):
        return False
    if "/" in name or "\\" in name:
        return False
    if any(c in name for c in "\x00\n\r \t;|&$`<>*?\"'"):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9._+\-]{1,128}", name))


def _validate_search_query(q: str) -> bool:
    """Search queries can include spaces but no shell metachars or flag leads."""
    if not isinstance(q, str) or not q or q.startswith("-"):
        return False
    if any(c in q for c in "\x00\n\r;|&$`<>"):
        return False
    return len(q) <= 128


async def _run_async(*args, timeout: int = 30, shell: bool = False) -> dict:
    """Run a subprocess asynchronously and return result dict."""
    proc = None
    try:
        if shell:
            proc = await asyncio.create_subprocess_shell(
                args[0],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return {
            "returncode": proc.returncode,
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace"),
        }
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
        return {"returncode": -1, "stdout": "", "stderr": "timeout"}
    except FileNotFoundError as exc:
        return {"returncode": -1, "stdout": "", "stderr": str(exc)}


class SystemController:
    """Full system control running as root."""

    def __init__(self):
        self.is_root = os.geteuid() == 0
        # Short-TTL caches for expensive queries that get polled by
        # dashboards. Process list is the biggest win: /system/processes
        # was running `ps aux` (fork + full /proc scan + formatting) on
        # every request.
        self._proc_list_cache: tuple[list, float] | None = None
        self._PROC_LIST_TTL = 2.0
        self._services_cache: tuple[list, float] | None = None
        self._SERVICES_TTL = 5.0
        self._installed_cache: tuple[list, float] | None = None
        self._INSTALLED_TTL = 30.0

    # --- Package Management ---

    def _invalidate_package_cache(self) -> None:
        """Drop cached pacman -Q output after install/remove/update."""
        self._installed_cache = None

    async def install_package(self, package: str) -> dict:
        if not _validate_package_name(package):
            return {"success": False, "stdout": "", "stderr": "invalid package name"}
        r = await _run_async("pacman", "-S", "--noconfirm", "--", package, timeout=300)
        if r["returncode"] == 0:
            self._invalidate_package_cache()
        return {"success": r["returncode"] == 0, "stdout": r["stdout"], "stderr": r["stderr"]}

    async def remove_package(self, package: str) -> dict:
        if not _validate_package_name(package):
            return {"success": False, "stdout": "", "stderr": "invalid package name"}
        r = await _run_async("pacman", "-R", "--noconfirm", "--", package, timeout=120)
        if r["returncode"] == 0:
            self._invalidate_package_cache()
        return {"success": r["returncode"] == 0, "stdout": r["stdout"], "stderr": r["stderr"]}

    async def update_system(self) -> dict:
        r = await _run_async("pacman", "-Syu", "--noconfirm", timeout=600)
        if r["returncode"] == 0:
            self._invalidate_package_cache()
        return {"success": r["returncode"] == 0, "stdout": r["stdout"], "stderr": r["stderr"]}

    async def search_packages(self, query: str) -> dict:
        if not _validate_search_query(query):
            return {"success": False, "results": "invalid search query"}
        r = await _run_async("pacman", "-Ss", "--", query, timeout=30)
        return {"success": r["returncode"] == 0, "results": r["stdout"]}

    async def list_installed(self) -> list[str]:
        # Installed packages change only when pacman runs. Cache aggressively
        # so repeated /packages/installed polls don't shell out each time.
        now = time.monotonic()
        cached = self._installed_cache
        if cached is not None and (now - cached[1]) < self._INSTALLED_TTL:
            return cached[0]
        r = await _run_async("pacman", "-Q", timeout=30)
        if r["returncode"] == 0:
            result = r["stdout"].strip().split("\n")
            self._installed_cache = (result, now)
            return result
        return []

    # --- Update Checking ---

    async def check_updates(self) -> list[dict]:
        """Check for available package updates using checkupdates (pacman-contrib)."""
        r = await _run_async("checkupdates", timeout=60)
        updates = []
        if r["returncode"] == 0:
            for line in r["stdout"].strip().split("\n"):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        updates.append({
                            "package": parts[0],
                            "current": parts[1],
                            "new": parts[3],
                        })
        return updates

    # --- Service Control ---

    async def start_service(self, service: str) -> dict:
        if not _validate_unit_name(service):
            return {"success": False, "stderr": "invalid service name"}
        r = await _run_async("systemctl", "start", "--", service, timeout=30)
        self._services_cache = None  # state changed, drop stale cache
        return {"success": r["returncode"] == 0, "stderr": r["stderr"]}

    async def stop_service(self, service: str) -> dict:
        if not _validate_unit_name(service):
            return {"success": False, "stderr": "invalid service name"}
        r = await _run_async("systemctl", "stop", "--", service, timeout=30)
        self._services_cache = None
        return {"success": r["returncode"] == 0, "stderr": r["stderr"]}

    async def restart_service(self, service: str) -> dict:
        if not _validate_unit_name(service):
            return {"success": False, "stderr": "invalid service name"}
        r = await _run_async("systemctl", "restart", "--", service, timeout=30)
        self._services_cache = None
        return {"success": r["returncode"] == 0, "stderr": r["stderr"]}

    async def enable_service(self, service: str) -> dict:
        if not _validate_unit_name(service):
            return {"success": False, "stderr": "invalid service name"}
        r = await _run_async("systemctl", "enable", "--", service, timeout=30)
        return {"success": r["returncode"] == 0, "stderr": r["stderr"]}

    async def service_status(self, service: str) -> dict:
        if not _validate_unit_name(service):
            return {"active": False, "output": "invalid service name"}
        r = await _run_async("systemctl", "status", "--", service, timeout=10)
        return {"active": r["returncode"] == 0, "output": r["stdout"]}

    async def list_services(self) -> list[dict]:
        # Cache the systemctl list — dashboards poll this several times per
        # second, but service state rarely changes that fast.
        now = time.monotonic()
        cached = self._services_cache
        if cached is not None and (now - cached[1]) < self._SERVICES_TTL:
            return cached[0]
        r = await _run_async(
            "systemctl", "list-units", "--type=service", "--no-pager",
            "--plain", "--no-legend", timeout=10
        )
        services = []
        for line in r["stdout"].strip().split("\n"):
            parts = line.split(None, 4)
            if len(parts) >= 4:
                services.append({
                    "unit": parts[0],
                    "load": parts[1],
                    "active": parts[2],
                    "sub": parts[3],
                    "description": parts[4] if len(parts) > 4 else "",
                })
        self._services_cache = (services, now)
        return services

    # --- Process Management ---

    async def list_processes(self) -> list[dict]:
        # Cache process list. /system/processes is hit several times per
        # second by some dashboards. Running `ps aux` each time is wasteful:
        # fork + /proc enumeration + formatting. A 2s TTL is invisible to
        # humans but dramatically reduces subprocess load.
        now = time.monotonic()
        cached = self._proc_list_cache
        if cached is not None and (now - cached[1]) < self._PROC_LIST_TTL:
            return cached[0]
        r = await _run_async("ps", "aux", "--no-headers", timeout=10)
        processes = []
        for line in r["stdout"].strip().split("\n"):
            parts = line.split(None, 10)
            if len(parts) >= 11:
                try:
                    processes.append({
                        "user": parts[0],
                        "pid": int(parts[1]),
                        "cpu": float(parts[2]),
                        "mem": float(parts[3]),
                        "command": parts[10],
                    })
                except (ValueError, IndexError):
                    continue
        self._proc_list_cache = (processes, now)
        return processes

    def kill_process(self, pid: int, sig: int = signal.SIGTERM) -> bool:
        # Reject protected PIDs (init, kernel), negative PIDs (process groups),
        # and our own PID so a bad call can't take down the daemon itself.
        try:
            pid = int(pid)
            sig = int(sig)
        except (TypeError, ValueError):
            return False
        if pid in _PROTECTED_PIDS or pid <= 1 or pid == os.getpid():
            logger.warning("Blocked kill of protected pid %s", pid)
            return False
        if sig < 0 or sig > 64:
            return False
        try:
            os.kill(pid, sig)
            return True
        except (ProcessLookupError, PermissionError):
            return False

    async def run_command(self, command: str, timeout: int = 60) -> dict:
        import shlex
        if not isinstance(command, str) or not command:
            return {"status": "error", "error": "command must be a non-empty string",
                    "returncode": -1, "stdout": "", "stderr": ""}
        try:
            args = shlex.split(command)
        except ValueError as e:
            return {"status": "error",
                    "error": f"Invalid command syntax: {e}",
                    "returncode": -1, "stdout": "", "stderr": ""}
        if not args:
            return {"status": "error", "error": "empty command",
                    "returncode": -1, "stdout": "", "stderr": ""}
        # Clamp timeout — caller-controlled values shouldn't be able to pin
        # subprocess slots for hours or produce integer-overflow surprises.
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            timeout = 60
        timeout = max(1, min(timeout, 3600))
        r = await _run_async(*args, timeout=timeout, shell=False)
        return {"returncode": r["returncode"], "stdout": r["stdout"], "stderr": r["stderr"]}

    # --- System Information ---

    async def get_system_info(self) -> dict:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._get_system_info_sync)

    def _get_system_info_sync(self) -> dict:
        info = {}
        info["hostname"] = _HOSTNAME
        info["kernel"] = _KERNEL

        try:
            with open("/proc/uptime", "r") as f:
                info["uptime_seconds"] = float(f.read().split()[0])
        except OSError:
            info["uptime_seconds"] = 0

        try:
            with open("/proc/meminfo", "r") as f:
                meminfo = {}
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip().split()[0]
                        meminfo[key] = int(val)
                info["memory"] = {
                    "total_kb": meminfo.get("MemTotal", 0),
                    "available_kb": meminfo.get("MemAvailable", 0),
                    "free_kb": meminfo.get("MemFree", 0),
                }
        except OSError:
            info["memory"] = {"total_kb": 0, "available_kb": 0, "free_kb": 0}

        info["cpu_count"] = _CPU_COUNT

        try:
            load1, load5, load15 = os.getloadavg()
            info["load_average"] = {"1m": load1, "5m": load5, "15m": load15}
        except OSError:
            info["load_average"] = {"1m": 0, "5m": 0, "15m": 0}

        try:
            stat = os.statvfs("/")
            info["disk"] = {
                "total_bytes": stat.f_blocks * stat.f_frsize,
                "free_bytes": stat.f_bfree * stat.f_frsize,
                "available_bytes": stat.f_bavail * stat.f_frsize,
            }
        except OSError:
            info["disk"] = {"total_bytes": 0, "free_bytes": 0, "available_bytes": 0}

        return info
