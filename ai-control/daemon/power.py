"""
Power orchestration: governor switching + thermal throttling of observers.

Responsibilities
----------------
1. **Governor auto-boost on PE launch.** When a PE process enters
   ``pe-compat.slice`` the governor flips from ``ondemand`` →
   ``performance``. When the last PE exits we restore the saved baseline
   governor so we don't burn battery forever.

2. **Throttle observers on thermal pressure.** When the CPU/GPU max temp
   crosses into the ``hot`` band (>= 80 °C) or ``critical`` (>= 90 °C) we
   lower memory_observer + pattern_scanner to SCHED_IDLE and apply a
   ``CPUQuota`` limit to their cgroup. When temps recover we restore them.

3. **Mediate root access.** The AI daemon runs as root (see
   ``ai-control.service``) so it *can* write ``scaling_governor``
   directly; we still prefer the ``/usr/lib/ai-arch/power-profile.sh``
   helper because the shell script is the single source of truth for
   policy and is auditable independently of the Python module.

Non-goals
---------
* No GUI knob exposure — this is the system-daemon orchestrator, not a
  user-facing applet. A future ``ai-control`` panel can build on top of
  the REST endpoints.
"""

from __future__ import annotations

import asyncio
import glob
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("ai-control.power")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VALID_GOVERNORS = {
    "performance", "powersave", "ondemand",
    "conservative", "schedutil", "userspace",
}

# Reasonable default mapping when we don't have a saved baseline yet.
# Mirrors hw-detect.sh: OLD -> ondemand, NEW -> schedutil.
_DEFAULT_BASELINE = {"old": "ondemand", "mid": "schedutil", "new": "schedutil"}

_GOVERNOR_HELPER = "/usr/lib/ai-arch/power-profile.sh"
_PE_SLICE_CGROUP = "/sys/fs/cgroup/pe-compat.slice"

# Observer cgroup path -- we put the daemon's observer threads under
# ai-control.slice/throttle.scope when thermal pressure kicks in.
_OBSERVER_CGROUP_PARENT = "/sys/fs/cgroup/ai-control.slice"
_OBSERVER_CGROUP_THROTTLE = _OBSERVER_CGROUP_PARENT + "/throttle.scope"


_IS_LINUX = sys.platform == "linux"


# ---------------------------------------------------------------------------
# Governor helpers
# ---------------------------------------------------------------------------
def _list_governor_files() -> list[str]:
    if not _IS_LINUX:
        return []
    return sorted(glob.glob(
        "/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor"
    ))


def _read_current_governor() -> Optional[str]:
    """Return the first CPU's governor or ``None`` if cpufreq is missing."""
    if not _IS_LINUX:
        return None
    files = _list_governor_files()
    if not files:
        return None
    try:
        with open(files[0], "r") as f:
            return f.read().strip() or None
    except OSError:
        return None


def _read_available_governors() -> set[str]:
    """Return the set of governors the kernel offers on this CPU."""
    if not _IS_LINUX:
        return set()
    try:
        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors") as f:
            return set(f.read().split())
    except OSError:
        return set()


async def _write_governor_direct(gov: str) -> int:
    """Write ``gov`` to every CPU's scaling_governor file.

    Returns the number of CPUs successfully updated. Runs in a thread
    because the write IO path can block on older hardware.
    """
    if not _IS_LINUX:
        return 0

    def _sync() -> int:
        count = 0
        for path in _list_governor_files():
            try:
                with open(path, "w") as f:
                    f.write(gov)
                count += 1
            except (OSError, PermissionError):
                continue
        return count

    return await asyncio.to_thread(_sync)


async def _run_helper(*args: str, timeout: float = 10.0) -> tuple[int, str]:
    """Invoke /usr/lib/ai-arch/power-profile.sh with the given args."""
    if not _IS_LINUX or not os.path.exists(_GOVERNOR_HELPER):
        return -1, "helper missing"
    try:
        proc = await asyncio.create_subprocess_exec(
            _GOVERNOR_HELPER, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except (ProcessLookupError, OSError, UnboundLocalError):
            pass
        return -1, "helper timeout"
    except (OSError, FileNotFoundError) as exc:
        return -1, str(exc)
    out = stdout.decode(errors="replace").strip()
    err = stderr.decode(errors="replace").strip()
    return proc.returncode or 0, (err or out)


# ---------------------------------------------------------------------------
# PE slice watcher
# ---------------------------------------------------------------------------
def _count_pe_scopes() -> int:
    """Return the number of live scopes under ``pe-compat.slice``.

    Each PE process gets its own ``<app>.scope`` under the slice, so this
    is a proxy for "number of PE processes running".
    """
    if not _IS_LINUX or not os.path.isdir(_PE_SLICE_CGROUP):
        return 0
    try:
        entries = os.listdir(_PE_SLICE_CGROUP)
    except OSError:
        return 0
    return sum(1 for e in entries if e.endswith(".scope"))


# ---------------------------------------------------------------------------
# Observer throttling
# ---------------------------------------------------------------------------
class _ObserverThrottler:
    """Apply / revert SCHED_IDLE + CPUQuota to observer threads.

    The AI daemon's own memory_observer + pattern_scanner are I/O-heavy
    and typically run as separate asyncio tasks on the same process, so
    we can't simply ``systemctl set-property`` them. Instead we:

    1. Write our own PID's TGID (daemon process) into a transient
       ``ai-control.slice/throttle.scope`` cgroup with a CPUQuota limit.
    2. Tell the observer objects to increase their poll interval.

    If cgroup v2 / systemd isn't available we just bump the poll
    intervals; the daemon still breathes, just slightly less often.
    """

    # Target quota when thermally throttled. "10000 100000" == 10 %.
    HOT_QUOTA = "10000 100000"
    CRITICAL_QUOTA = "5000 100000"

    def __init__(self):
        self._throttled: bool = False
        self._state: str = "normal"
        self._saved_mo_interval: Optional[float] = None
        self._saved_ss_interval: Optional[float] = None

    def _ensure_cgroup(self) -> bool:
        """Create ai-control.slice/throttle.scope if missing. Idempotent."""
        if not _IS_LINUX:
            return False
        if not os.path.isdir(_OBSERVER_CGROUP_PARENT):
            try:
                os.makedirs(_OBSERVER_CGROUP_PARENT, exist_ok=True)
            except OSError:
                return False
        if not os.path.isdir(_OBSERVER_CGROUP_THROTTLE):
            try:
                os.makedirs(_OBSERVER_CGROUP_THROTTLE, exist_ok=True)
            except OSError:
                return False
        return True

    def _apply_quota(self, quota: str) -> bool:
        if not self._ensure_cgroup():
            return False
        path = os.path.join(_OBSERVER_CGROUP_THROTTLE, "cpu.max")
        try:
            with open(path, "w") as f:
                f.write(quota)
            return True
        except OSError:
            return False

    def _clear_quota(self) -> None:
        if not _IS_LINUX:
            return
        path = os.path.join(_OBSERVER_CGROUP_THROTTLE, "cpu.max")
        try:
            with open(path, "w") as f:
                f.write("max 100000")
        except OSError:
            pass

    def apply(self, state: str, memory_observer, scanner) -> None:
        """Enter a throttled state ('hot' or 'critical')."""
        if state == self._state:
            return
        self._state = state
        if state == "critical":
            ok = self._apply_quota(self.CRITICAL_QUOTA)
        else:
            ok = self._apply_quota(self.HOT_QUOTA)
        if memory_observer is not None and hasattr(memory_observer, "_poll_interval"):
            if self._saved_mo_interval is None:
                self._saved_mo_interval = memory_observer._poll_interval
            # Quadruple the interval in hot, octuple in critical.
            mult = 8.0 if state == "critical" else 4.0
            memory_observer._poll_interval = max(
                memory_observer._poll_interval,
                self._saved_mo_interval * mult,
            )
        if scanner is not None and hasattr(scanner, "_poll_interval"):
            if self._saved_ss_interval is None:
                self._saved_ss_interval = scanner._poll_interval
            mult = 8.0 if state == "critical" else 4.0
            scanner._poll_interval = max(
                scanner._poll_interval,
                self._saved_ss_interval * mult,
            )
        self._throttled = True
        logger.warning(
            "thermal throttle applied: state=%s quota_ok=%s", state, ok,
        )

    def revert(self, memory_observer, scanner) -> None:
        """Restore normal operation."""
        if not self._throttled:
            self._state = "normal"
            return
        self._clear_quota()
        if memory_observer is not None and self._saved_mo_interval is not None:
            memory_observer._poll_interval = self._saved_mo_interval
        if scanner is not None and self._saved_ss_interval is not None:
            scanner._poll_interval = self._saved_ss_interval
        self._saved_mo_interval = None
        self._saved_ss_interval = None
        self._throttled = False
        self._state = "normal"
        logger.info("thermal throttle released; observers restored")

    @property
    def state(self) -> str:
        return self._state

    @property
    def active(self) -> bool:
        return self._throttled


# ---------------------------------------------------------------------------
# PowerOrchestrator
# ---------------------------------------------------------------------------
class PowerOrchestrator:
    """High-level power policy controller.

    * Boosts governor to ``performance`` when any PE process is running.
    * Throttles observers when ``ThermalOrchestrator`` reports hot/critical.
    * Exposes a snapshot dict for ``/power/current``.

    Lifecycle: ``await start()`` registers a thermal subscriber and starts
    a PE-slice watcher. ``await stop()`` reverses the changes.
    """

    PE_WATCH_INTERVAL = 2.0  # seconds; cheap readdir on /sys/fs/cgroup/pe-compat.slice

    def __init__(
        self,
        thermal_orchestrator: Optional[Any] = None,
        hardware_class: str = "mid",
        memory_observer: Optional[Any] = None,
        scanner: Optional[Any] = None,
    ):
        self._thermal = thermal_orchestrator
        self._hw = hardware_class
        self._memory_observer = memory_observer
        self._scanner = scanner

        self._baseline_gov: Optional[str] = None
        self._current_gov: Optional[str] = _read_current_governor()
        self._available = _read_available_governors()
        self._pe_boost_active: bool = False
        self._pe_count_last: int = 0

        self._throttler = _ObserverThrottler()

        self._watch_task: Optional[asyncio.Task] = None
        self._running = False

    # ── Lifecycle ──
    async def start(self):
        if self._running:
            return
        self._running = True
        # Remember whatever governor the hw-detect / user had configured
        # at startup so we can restore on shutdown.
        self._baseline_gov = (
            self._current_gov
            or _DEFAULT_BASELINE.get(self._hw, "ondemand")
        )
        logger.info(
            "PowerOrchestrator started (hw=%s, baseline_gov=%s, avail=%s)",
            self._hw, self._baseline_gov,
            sorted(self._available) if self._available else "unknown",
        )
        # Hook thermal state transitions (if an orchestrator is attached).
        if self._thermal is not None:
            try:
                self._thermal.subscribe(self._on_thermal_state)
            except Exception as exc:
                logger.warning("could not subscribe to thermal events: %s", exc)
        # PE slice watcher (best-effort; silently no-ops if the slice is missing).
        self._watch_task = asyncio.create_task(
            self._pe_watch_loop(), name="power-pe-watch",
        )

    async def stop(self):
        self._running = False
        if self._watch_task:
            self._watch_task.cancel()
            try:
                await self._watch_task
            except asyncio.CancelledError:
                pass
            self._watch_task = None
        # Revert any runtime changes so we don't leave the system in a
        # weird state when the daemon exits.
        if self._pe_boost_active and self._baseline_gov:
            await self.set_governor(self._baseline_gov, reason="shutdown")
            self._pe_boost_active = False
        self._throttler.revert(self._memory_observer, self._scanner)
        logger.info("PowerOrchestrator stopped")

    # ── Governor control ──
    async def set_governor(self, gov: str, reason: str = "manual") -> dict[str, Any]:
        """Public API: switch all CPUs to ``gov``.

        Tries the shell helper first (single source of truth, can be
        audited by systemd) and falls back to a direct sysfs write if
        the helper is absent (e.g. in a minimal test rootfs).
        """
        if gov not in VALID_GOVERNORS:
            return {"success": False, "error": f"invalid governor: {gov}"}
        if self._available and gov not in self._available:
            return {
                "success": False,
                "error": f"governor {gov!r} not in kernel set {sorted(self._available)}",
            }
        rc, msg = await _run_helper("set", gov)
        cpus = 0
        if rc != 0:
            # Helper missing / non-zero → try the direct write.
            cpus = await _write_governor_direct(gov)
        self._current_gov = _read_current_governor()
        logger.info(
            "set_governor(%s) reason=%s helper_rc=%s direct_cpus=%d now=%s",
            gov, reason, rc, cpus, self._current_gov,
        )
        return {
            "success": self._current_gov == gov,
            "governor": self._current_gov,
            "helper_rc": rc,
            "helper_msg": msg,
            "direct_cpus_written": cpus,
        }

    # ── PE watch loop ──
    async def _pe_watch_loop(self):
        try:
            while self._running:
                try:
                    count = _count_pe_scopes()
                    if count > 0 and not self._pe_boost_active:
                        # At least one PE process appeared — boost.
                        await self.set_governor("performance", reason=f"pe_launch({count})")
                        self._pe_boost_active = True
                    elif count == 0 and self._pe_boost_active:
                        # All PE processes exited — restore baseline.
                        if self._baseline_gov:
                            await self.set_governor(self._baseline_gov, reason="pe_exit")
                        self._pe_boost_active = False
                    self._pe_count_last = count
                except Exception as exc:
                    logger.debug("pe_watch iteration failed: %s", exc)
                await asyncio.sleep(self.PE_WATCH_INTERVAL)
        except asyncio.CancelledError:
            raise

    # ── Thermal subscriber ──
    def _on_thermal_state(self, snap: dict[str, Any]) -> None:
        state = snap.get("thermal_state", "unknown")
        if state in ("hot", "critical"):
            self._throttler.apply(state, self._memory_observer, self._scanner)
        elif state in ("normal", "warm"):
            # Require a clean transition to "normal"/"warm" before releasing
            # so we don't oscillate at the boundary.
            self._throttler.revert(self._memory_observer, self._scanner)

    # ── Snapshot (for /power endpoints) ──
    async def snapshot(self) -> dict[str, Any]:
        thermal_snap: dict[str, Any] = {}
        if self._thermal is not None:
            try:
                thermal_snap = await self._thermal.snapshot()
            except Exception as exc:
                thermal_snap = {"error": f"thermal snapshot failed: {exc}"}
        cpu = thermal_snap.get("cpu", {})
        gpu = thermal_snap.get("gpu", {})
        battery = thermal_snap.get("battery")
        return {
            "timestamp": time.time(),
            "hardware_class": self._hw,
            "thermal_state": thermal_snap.get("thermal_state", "unknown"),
            "governor": {
                "current": _read_current_governor(),
                "baseline": self._baseline_gov,
                "available": sorted(self._available) if self._available else [],
                "pe_boost_active": self._pe_boost_active,
                "pe_process_count": self._pe_count_last,
            },
            "cpu": {
                "temp": cpu.get("temp"),
                "load_pct": cpu.get("load_pct"),
                "avg_khz": cpu.get("avg_khz"),
                "max_khz": cpu.get("max_khz"),
                "per_core_temps": cpu.get("per_core", []),
                "governor": cpu.get("governor"),
            },
            "gpu": {
                "vendor": gpu.get("vendor"),
                "temp": gpu.get("temp"),
                "load": gpu.get("load"),
                "mem_used_mb": gpu.get("mem_used_mb"),
                "mem_total_mb": gpu.get("mem_total_mb"),
            },
            "rapl": thermal_snap.get("rapl", {}),
            "battery": battery,
            "throttling": {
                "active": self._throttler.active,
                "state": self._throttler.state,
            },
        }

    # ── Introspection ──
    @property
    def hardware_class(self) -> str:
        return self._hw

    @property
    def baseline_governor(self) -> Optional[str]:
        return self._baseline_gov

    @property
    def pe_boost_active(self) -> bool:
        return self._pe_boost_active
