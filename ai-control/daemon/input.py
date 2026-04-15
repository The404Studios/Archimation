"""
Input event aggregator for the AI Control daemon.

Responsibilities:
  - Enumerate /dev/input/event* devices and classify each (keyboard, mouse,
    gamepad, touchpad, etc.).
  - Expose a snapshot of current input state for the dashboard.
  - Optional (deferred) uhid write path to inject synthetic HID reports
    below evdev -- currently returns NotImplementedError.

Design:
  - Pure enumeration + read; the heavy evdev read loop is off by default.
  - Non-Linux hosts see an empty device list; FastAPI endpoints degrade to
    503-style empty responses rather than crashing.
  - Module-level imports avoid evdev dependency (uses /sys + /proc/bus/input).

Public API:
  - InputController: cached enumeration + optional uhid helpers.
  - build_router(): FastAPI APIRouter with /input/* endpoints.

Endpoints:
  GET  /input/list     -- [{index, name, path, classes}]
  GET  /input/state    -- {devices, uhid_available, uhid_loaded}
  POST /input/uhid     -- reserved; currently raises NotImplemented
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ai-control.input")


# /proc/bus/input/devices record fields (kernel-stable for 20+ years).
# Example record:
#   I: Bus=0003 Vendor=054c Product=05c4 Version=8111
#   N: Name="Sony Computer Entertainment Wireless Controller"
#   P: Phys=usb-0000:00:14.0-2/input0
#   S: Sysfs=/devices/pci0000:00/0000:00:14.0/usb1/1-2/...
#   U: Uniq=...
#   H: Handlers=event8 js0 kbd mouse0
#   B: PROP=0
#   B: EV=20001b
#   B: KEY=...
#   B: ABS=...


def _parse_proc_bus_input() -> List[Dict[str, Any]]:
    """Parse /proc/bus/input/devices into a list of dicts."""
    path = Path("/proc/bus/input/devices")
    if not path.is_file():
        return []
    try:
        data = path.read_text(errors="replace")
    except OSError:
        return []

    devices: List[Dict[str, Any]] = []
    cur: Dict[str, Any] = {}
    for raw_line in data.splitlines():
        line = raw_line.strip()
        if not line:
            if cur:
                devices.append(cur)
                cur = {}
            continue
        if len(line) < 3 or line[1] != ":":
            continue
        tag, payload = line[0], line[3:].strip()
        if tag == "I":
            # Bus=0003 Vendor=054c Product=05c4 Version=8111
            for kv in payload.split():
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    cur[k.lower()] = v.lower()
        elif tag == "N":
            # Name="..."
            if payload.lower().startswith("name="):
                v = payload[len("Name="):].strip()
                if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                    v = v[1:-1]
                cur["name"] = v
        elif tag == "P":
            if payload.lower().startswith("phys="):
                cur["phys"] = payload[len("Phys="):].strip()
        elif tag == "S":
            if payload.lower().startswith("sysfs="):
                cur["sysfs"] = payload[len("Sysfs="):].strip()
        elif tag == "H":
            if payload.lower().startswith("handlers="):
                handlers = payload[len("Handlers="):].strip().split()
                cur["handlers"] = handlers
                # Extract the primary event node if present
                for h in handlers:
                    if h.startswith("event"):
                        cur["event"] = f"/dev/input/{h}"
                        break
        elif tag == "B":
            if payload.startswith("EV="):
                try:
                    cur["ev_mask"] = int(payload[3:], 16)
                except ValueError:
                    cur["ev_mask"] = 0

    if cur:
        devices.append(cur)
    return devices


# evdev EV_* codes -- kernel ABI, stable.
EV_SYN   = 0x00
EV_KEY   = 0x01
EV_REL   = 0x02
EV_ABS   = 0x03
EV_MSC   = 0x04
EV_SW    = 0x05


def _classify(dev: Dict[str, Any]) -> List[str]:
    """Return a list of role tags for a device based on handlers + EV mask."""
    tags: List[str] = []
    handlers = set(dev.get("handlers", []))
    ev = dev.get("ev_mask", 0)

    if "kbd" in handlers:
        tags.append("keyboard")
    if "mouse" in handlers or "mouse0" in handlers:
        tags.append("mouse")
    if any(h.startswith("js") for h in handlers):
        tags.append("gamepad")
    # Touchpad: EV_ABS set AND mouse handler
    if (ev & (1 << EV_ABS)) and "mouse" in handlers:
        if "touchpad" not in tags and "gamepad" not in tags:
            tags.append("touchpad")
    # Switch devices (lid / tablet-mode / headphone-jack)
    if ev & (1 << EV_SW):
        tags.append("switch")

    # Heuristic by name when handlers are ambiguous
    name = dev.get("name", "").lower()
    if "power button" in name:
        tags.append("power")
    if "lid" in name:
        tags.append("lid")

    if not tags:
        tags.append("unknown")
    return tags


class InputController:
    """Enumerates /dev/input devices and provides uhid probing helpers."""

    _CACHE_TTL_SEC: float = 5.0  # input devices DO hot-add; short TTL

    def __init__(
        self,
        uhid_path: str = "/dev/uhid",
        bypass_script: str = "/usr/lib/ai-arch/hid-bypass.sh",
    ) -> None:
        self.uhid_path = uhid_path
        self.bypass_script = bypass_script
        self._cache: Optional[List[Dict[str, Any]]] = None
        self._cache_mtime: float = 0.0

    # ------------------------------------------------------------------
    def enumerate(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        now = time.time()
        if (
            not force_refresh
            and self._cache is not None
            and (now - self._cache_mtime) < self._CACHE_TTL_SEC
        ):
            return self._cache

        # Linux-only
        if not sys.platform.startswith("linux"):
            self._cache = []
            self._cache_mtime = now
            return []

        raw = _parse_proc_bus_input()
        devices: List[Dict[str, Any]] = []
        for idx, d in enumerate(raw):
            entry = {
                "index": idx,
                "name": d.get("name", "unknown"),
                "vendor": d.get("vendor", ""),
                "product": d.get("product", ""),
                "bus": d.get("bus", ""),
                "event": d.get("event", ""),
                "handlers": d.get("handlers", []),
                "classes": _classify(d),
                "phys": d.get("phys", ""),
            }
            devices.append(entry)

        self._cache = devices
        self._cache_mtime = now
        return devices

    # ------------------------------------------------------------------
    def uhid_status(self) -> Dict[str, Any]:
        """Return whether uhid is loaded + writable."""
        status: Dict[str, Any] = {
            "loaded": False,
            "dev_exists": False,
            "writable": False,
            "path": self.uhid_path,
        }
        if not sys.platform.startswith("linux"):
            return status
        loaded = Path("/sys/module/uhid").is_dir()
        status["loaded"] = loaded
        try:
            st = os.stat(self.uhid_path)
            status["dev_exists"] = True
            status["mode"] = oct(st.st_mode & 0o7777)
            status["writable"] = os.access(self.uhid_path, os.W_OK)
        except FileNotFoundError:
            pass
        except OSError as e:
            status["error"] = str(e)
        return status

    def uhid_enable(self, timeout: float = 5.0) -> Dict[str, Any]:
        """Invoke hid-bypass.sh enable.  Returns {'ok': bool, 'output': str}."""
        if not Path(self.bypass_script).is_file():
            return {"ok": False, "output": f"{self.bypass_script} not installed"}
        try:
            proc = subprocess.run(
                [self.bypass_script, "enable"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return {"ok": False, "output": str(e)}
        ok = proc.returncode == 0
        return {"ok": ok, "output": (proc.stdout or "") + (proc.stderr or "")}

    # ------------------------------------------------------------------
    def inject_hid(self, descriptor: bytes, reports: List[bytes]) -> None:
        """Inject HID reports via uhid (DEFERRED -- not yet implemented).

        Stubbed out until the v2 HID injection protocol is finalised.  Raises
        NotImplementedError so callers can feature-detect.
        """
        raise NotImplementedError(
            "uhid write path is reserved; see future roadmap."
        )

    # ------------------------------------------------------------------
    def state(self) -> Dict[str, Any]:
        """Aggregate snapshot: devices + uhid status."""
        return {
            "devices": self.enumerate(),
            "uhid": self.uhid_status(),
            "timestamp": time.time(),
        }


# ----------------------------------------------------------------------
# FastAPI router
# ----------------------------------------------------------------------
def build_router(controller: Optional[InputController] = None):
    """Return a FastAPI APIRouter with /input/* endpoints."""
    try:
        from fastapi import APIRouter, HTTPException, Query
    except ImportError:
        logger.error("FastAPI missing; /input/* endpoints unavailable")
        return None

    ctrl = controller or InputController()

    router = APIRouter(prefix="/input", tags=["input"])

    @router.get("/list")
    async def list_inputs(refresh: bool = Query(False)):
        try:
            devs = ctrl.enumerate(force_refresh=refresh)
        except Exception as e:
            logger.exception("input enumerate failed")
            raise HTTPException(status_code=500, detail=str(e))
        return {"count": len(devs), "devices": devs}

    @router.get("/state")
    async def input_state():
        return ctrl.state()

    @router.get("/uhid/status")
    async def uhid_status():
        return ctrl.uhid_status()

    @router.post("/uhid/enable")
    async def uhid_enable():
        return ctrl.uhid_enable()

    @router.post("/uhid/inject")
    async def uhid_inject():
        # Reserved for future use.  We return 501 so clients can feature-detect
        # without triggering a 500 alert in the audit log.
        raise HTTPException(
            status_code=501,
            detail="uhid write path not yet implemented",
        )

    return router


__all__ = ["InputController", "build_router"]
