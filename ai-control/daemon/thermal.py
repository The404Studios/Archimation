"""
Thermal + power telemetry reader for AI Control Daemon.

Reads live CPU temperature, frequency, load; GPU temperature, load, memory;
battery state; RAPL power counters. Emits compact binary events over the
event bus for subscribers (cortex, observers) and exposes a snapshot dict
for the /thermal and /power REST endpoints.

Design notes
------------
* **Pure stdlib** — ``struct``, ``os``, ``glob``, ``pathlib``, ``subprocess``
  only. No ``psutil``, no ``pynvml``.
* **Graceful degradation**: module imports cleanly on Windows (``sys.platform
  != "linux"``) and on Linux hosts without MSR access / thermal zones / GPU.
* **250 ms TTL cache** on hot snapshot to keep dashboard polls cheap.
* **MSR reads** are ``pread(2)``-based on ``/dev/cpu/<N>/msr`` and are run
  via ``asyncio.to_thread`` because they block on non-MSR hardware.
* **Compact event packing**: ``H`` (temp-centi-°C), ``I`` (freq-kHz), ``B``
  (thermal state enum). 24 bytes/event instead of 150+ for JSON.
* **RAPL**: we store the delta since the last read, not the absolute counter
  value, so a long-lived ring buffer doesn't accumulate huge numbers.

Poll-rate tier (from ``config._detect_hardware_class``)
-------------------------------------------------------
* ``old``: 0.25 Hz (every 4 s) — spinning disks / Pentium 4 era.
* ``mid``: 1 Hz (every 1 s).
* ``new``: 4 Hz (every 250 ms) — matches the cache TTL.

Thermal state thresholds
------------------------
* ``normal`` < 70 °C
* ``warm``   70-79 °C
* ``hot``    80-89 °C       — emits ``thermal_warning`` event
* ``critical`` >= 90 °C     — emits ``thermal_critical`` event
"""

from __future__ import annotations

import asyncio
import glob
import logging
import os
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger("ai-control.thermal")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Intel MSR addresses (IA32 architectural).
MSR_IA32_THERM_STATUS = 0x19C           # bits 0-6: thermal status,
                                        # bits 16-22: digital readout (TjMax − temp),
                                        # bit 31: reading valid.
MSR_IA32_PACKAGE_THERM_STATUS = 0x1B1   # bits 16-22: package digital readout.
MSR_IA32_TEMPERATURE_TARGET = 0x1A2     # bits 16-23: TjMax (°C).
MSR_IA32_MPERF = 0xE7                   # Maximum Performance counter.
MSR_IA32_APERF = 0xE8                   # Actual Performance counter.
MSR_PLATFORM_INFO = 0xCE                # bits 8-15: max non-turbo ratio.

# Thermal state thresholds (°C)
THERMAL_NORMAL = 70.0
THERMAL_WARM = 80.0
THERMAL_HOT = 90.0
# "critical" is anything >= THERMAL_HOT, reported as a separate bucket.

# Default TjMax if the MSR read fails (sane for most desktop CPUs).
DEFAULT_TJMAX = 100.0

# Snapshot cache TTL.
_SNAPSHOT_TTL_DEFAULT = 0.25  # seconds

# Event-pack layout:
#   uint32 timestamp (seconds since boot, truncated)
#   uint16 cpu_temp_centi_c     (e.g. 7523 = 75.23 °C)
#   uint16 gpu_temp_centi_c
#   uint32 cpu_freq_khz
#   uint8  cpu_load_pct
#   uint8  gpu_load_pct
#   uint8  thermal_state (0=normal, 1=warm, 2=hot, 3=critical, 255=unknown)
#   uint8  battery_pct (0..100, 255=absent)
#   uint32 rapl_pkg_delta_uj
#   uint32 rapl_dram_delta_uj
# => 4+2+2+4+1+1+1+1+4+4 = 24 bytes.
_EVENT_PACK_FMT = "<IHHIBBBBII"
EVENT_SIZE = struct.calcsize(_EVENT_PACK_FMT)
assert EVENT_SIZE == 24, "thermal event packing expected 24 bytes"

_THERMAL_STATE_CODE = {
    "normal": 0,
    "warm": 1,
    "hot": 2,
    "critical": 3,
    "unknown": 255,
}
_THERMAL_STATE_NAME = {v: k for k, v in _THERMAL_STATE_CODE.items()}


# ---------------------------------------------------------------------------
# Platform gate
# ---------------------------------------------------------------------------
_IS_LINUX = sys.platform == "linux"


# ---------------------------------------------------------------------------
# Low-level sysfs helpers
# ---------------------------------------------------------------------------
def _read_int(path: str) -> Optional[int]:
    """Read a small integer from a sysfs file. Returns None on any error."""
    try:
        with open(path, "r") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# MSR reader
# ---------------------------------------------------------------------------
class _MSRReader:
    """Per-CPU /dev/cpu/N/msr descriptor pool.

    Opens each MSR device lazily on first read and keeps the descriptor
    cached. Close with :meth:`close` on shutdown to avoid FD leaks.

    pread(fd, 8, msr_addr) is the canonical MSR read. Requires root
    plus the ``msr`` kernel module. Silently degrades when unavailable.
    """

    def __init__(self):
        self._fds: dict[int, int] = {}
        self._cpu_count = os.cpu_count() or 1
        # Cap: reading all 256 cores of a Threadripper is overkill. Sample
        # at most 32 cores; package temp is already aggregated by MSR 0x1B1.
        self._max_cpus = min(self._cpu_count, 32)
        self._available: Optional[bool] = None

    def available(self) -> bool:
        """True iff MSR access is likely to succeed (module loaded, root)."""
        if self._available is not None:
            return self._available
        if not _IS_LINUX:
            self._available = False
            return False
        # Test the first CPU only; permissions are uniform across cores.
        try:
            fd = os.open("/dev/cpu/0/msr", os.O_RDONLY)
            os.close(fd)
            self._available = True
        except OSError as exc:
            logger.info("MSR unavailable: %s (falling back to sysfs thermal)", exc)
            self._available = False
        return self._available

    def _open(self, cpu: int) -> Optional[int]:
        fd = self._fds.get(cpu)
        if fd is not None:
            return fd
        try:
            fd = os.open(f"/dev/cpu/{cpu}/msr", os.O_RDONLY)
            self._fds[cpu] = fd
            return fd
        except OSError:
            return None

    def read(self, cpu: int, msr: int) -> Optional[int]:
        """Read a 64-bit MSR. Returns None on error."""
        if not self.available():
            return None
        fd = self._open(cpu)
        if fd is None:
            return None
        try:
            data = os.pread(fd, 8, msr)
        except OSError:
            # Core offline / MSR not implemented on this chip — drop the fd
            # so a later retry doesn't keep hitting the same broken handle.
            try:
                os.close(fd)
            except OSError:
                pass
            self._fds.pop(cpu, None)
            return None
        if len(data) < 8:
            return None
        return struct.unpack("<Q", data)[0]

    def close(self):
        for fd in list(self._fds.values()):
            try:
                os.close(fd)
            except OSError:
                pass
        self._fds.clear()


# ---------------------------------------------------------------------------
# CPU telemetry
# ---------------------------------------------------------------------------
class _CpuTelemetry:
    """CPU temperature, frequency, governor, and load reader."""

    def __init__(self, msr: _MSRReader):
        self._msr = msr
        self._cpu_count = os.cpu_count() or 1
        # TjMax cached per boot (reads MSR 0x1A2 once).
        self._tjmax: Optional[float] = None
        # Cache the discovered coretemp/k10temp hwmon directory.
        self._cpu_hwmon: Optional[str] = self._find_cpu_hwmon()
        # load avg baseline for ΔAPERF/ΔMPERF (effective freq).
        self._last_aperf: dict[int, int] = {}
        self._last_mperf: dict[int, int] = {}
        # /proc/stat cpu totals — delta for aggregate load%.
        self._last_stat_total: int = 0
        self._last_stat_idle: int = 0

    # ── hwmon discovery ──
    @staticmethod
    def _find_cpu_hwmon() -> Optional[str]:
        """Find the hwmon directory backing coretemp / k10temp."""
        if not _IS_LINUX:
            return None
        for path in glob.glob("/sys/class/hwmon/hwmon*"):
            name = _read_text(os.path.join(path, "name"))
            if name in ("coretemp", "k10temp", "zenpower", "cpu_thermal"):
                return path
        return None

    # ── TjMax ──
    def tjmax(self) -> float:
        if self._tjmax is not None:
            return self._tjmax
        val = self._msr.read(0, MSR_IA32_TEMPERATURE_TARGET)
        if val is not None:
            self._tjmax = float((val >> 16) & 0xFF)
            if self._tjmax < 50.0 or self._tjmax > 120.0:
                # MSR returned a garbage TjMax (AMD chips ignore this register
                # and can return 0 or 0xFF). Fall back.
                self._tjmax = DEFAULT_TJMAX
        else:
            self._tjmax = DEFAULT_TJMAX
        return self._tjmax

    # ── Temperature ──
    def read_temp(self) -> tuple[Optional[float], dict[str, Any]]:
        """Return (package_temp_°C, details).

        Prefers IA32_PACKAGE_THERM_STATUS (MSR 0x1B1) then falls back to
        coretemp hwmon, then thermal zones. Returns the MAX across
        discovered zones as the package temperature.
        """
        details: dict[str, Any] = {"source": None, "per_core": [], "zones": []}
        if not _IS_LINUX:
            return None, details

        # 1. MSR package temp (most accurate when available).
        pkg_val = self._msr.read(0, MSR_IA32_PACKAGE_THERM_STATUS)
        if pkg_val is not None:
            # bits 16-22 = digital readout (TjMax - temp)
            readout = (pkg_val >> 16) & 0x7F
            if readout:
                tjmax = self.tjmax()
                pkg_temp = tjmax - float(readout)
                details["source"] = "msr_package"
                details["tjmax"] = tjmax
                return pkg_temp, details

        # 2. coretemp hwmon (per-core + package).
        if self._cpu_hwmon:
            temps = []
            for temp_file in sorted(glob.glob(
                    os.path.join(self._cpu_hwmon, "temp*_input"))):
                raw = _read_int(temp_file)
                if raw is not None:
                    temps.append(raw / 1000.0)
            if temps:
                details["source"] = "hwmon"
                details["per_core"] = temps
                return max(temps), details

        # 3. /sys/class/thermal fallback — picks the hottest zone.
        max_temp: Optional[float] = None
        for zone_dir in sorted(glob.glob("/sys/class/thermal/thermal_zone*")):
            raw = _read_int(os.path.join(zone_dir, "temp"))
            if raw is None:
                continue
            # Some ACPI zones report in °C rather than m°C (values < 1000).
            # Heuristic: values > 1000 are milli-°C.
            celsius = raw / 1000.0 if raw > 1000 else float(raw)
            # Sanity clamp: ignore obvious sentinels like 0 or 127.
            if celsius <= 0 or celsius >= 127:
                continue
            zone_type = _read_text(os.path.join(zone_dir, "type")) or "unknown"
            details["zones"].append({"type": zone_type, "temp": celsius})
            if max_temp is None or celsius > max_temp:
                max_temp = celsius
        if max_temp is not None:
            details["source"] = "thermal_zone"
        return max_temp, details

    # ── Frequency + governor ──
    def read_freq(self) -> dict[str, Any]:
        """Per-CPU scaling_cur_freq + governor + policy."""
        if not _IS_LINUX:
            return {"per_cpu": [], "governor": None, "max_khz": 0, "min_khz": 0}
        per_cpu = []
        govs: set[str] = set()
        max_khz = 0
        min_khz = 0
        for cpu_dir in sorted(glob.glob("/sys/devices/system/cpu/cpu[0-9]*")):
            cur = _read_int(os.path.join(cpu_dir, "cpufreq/scaling_cur_freq"))
            gov = _read_text(os.path.join(cpu_dir, "cpufreq/scaling_governor"))
            if cur is None:
                continue
            per_cpu.append({"cpu": os.path.basename(cpu_dir), "khz": cur, "governor": gov})
            if gov:
                govs.add(gov)
            mx = _read_int(os.path.join(cpu_dir, "cpufreq/cpuinfo_max_freq"))
            mn = _read_int(os.path.join(cpu_dir, "cpufreq/cpuinfo_min_freq"))
            if mx is not None and mx > max_khz:
                max_khz = mx
            if mn is not None and (min_khz == 0 or mn < min_khz):
                min_khz = mn
        # A single reported governor is the common case (systemd sets all
        # cores to the same policy). Multiple values = mixed (rare).
        gov = next(iter(govs)) if len(govs) == 1 else (
            "mixed" if govs else None
        )
        avg_khz = (sum(c["khz"] for c in per_cpu) // len(per_cpu)) if per_cpu else 0
        return {
            "per_cpu": per_cpu,
            "governor": gov,
            "avg_khz": avg_khz,
            "max_khz": max_khz,
            "min_khz": min_khz,
        }

    # ── Load (aggregate) ──
    def read_load(self) -> Optional[float]:
        """Return aggregate CPU load % since last call (0..100)."""
        if not _IS_LINUX:
            return None
        try:
            with open("/proc/stat", "r") as f:
                line = f.readline()
        except OSError:
            return None
        parts = line.split()
        if len(parts) < 5 or parts[0] != "cpu":
            return None
        try:
            vals = [int(x) for x in parts[1:8]]
        except ValueError:
            return None
        # user, nice, system, idle, iowait, irq, softirq — pad to 7.
        while len(vals) < 7:
            vals.append(0)
        total = sum(vals)
        idle = vals[3] + vals[4]
        dt = total - self._last_stat_total
        di = idle - self._last_stat_idle
        self._last_stat_total = total
        self._last_stat_idle = idle
        if dt <= 0:
            return 0.0
        return max(0.0, min(100.0, 100.0 * (dt - di) / dt))


# ---------------------------------------------------------------------------
# GPU telemetry
# ---------------------------------------------------------------------------
class _GpuTelemetry:
    """GPU temp/load/mem reader. Branches by vendor."""

    def __init__(self):
        self._vendor: Optional[str] = None
        self._amd_hwmon: Optional[str] = None
        self._intel_drm: Optional[str] = None
        self._nvidia_smi_path: Optional[str] = None
        self._detect()

    def _detect(self):
        if not _IS_LINUX:
            return
        # NVIDIA: look for nvidia-smi in common locations.
        for cand in ("/usr/bin/nvidia-smi", "/usr/local/bin/nvidia-smi"):
            if os.path.exists(cand):
                self._vendor = "nvidia"
                self._nvidia_smi_path = cand
                return
        # AMD: hwmon under /sys/class/drm/card*/device/hwmon/
        for hwmon in glob.glob("/sys/class/drm/card*/device/hwmon/hwmon*"):
            name = _read_text(os.path.join(hwmon, "name"))
            if name in ("amdgpu", "radeon"):
                self._vendor = "amd"
                self._amd_hwmon = hwmon
                return
        # Intel: check for i915 gt_cur_freq_mhz.
        for card in glob.glob("/sys/class/drm/card*"):
            if os.path.exists(os.path.join(card, "gt_cur_freq_mhz")):
                self._vendor = "intel"
                self._intel_drm = card
                return

    def vendor(self) -> Optional[str]:
        return self._vendor

    async def read(self) -> dict[str, Any]:
        """Return {temp, load, mem_used_mb, mem_total_mb, vendor}."""
        out = {
            "vendor": self._vendor,
            "temp": None,
            "load": None,
            "mem_used_mb": None,
            "mem_total_mb": None,
        }
        if self._vendor == "nvidia":
            return await self._read_nvidia(out)
        if self._vendor == "amd":
            return self._read_amd(out)
        if self._vendor == "intel":
            return self._read_intel(out)
        return out

    async def _read_nvidia(self, out: dict[str, Any]) -> dict[str, Any]:
        """Spawn nvidia-smi --query-gpu=... --format=csv,noheader,nounits.

        This is the slow path (~80 ms fork); cache caller prevents it from
        running more than once per snapshot-TTL.
        """
        if not self._nvidia_smi_path:
            return out
        try:
            proc = await asyncio.create_subprocess_exec(
                self._nvidia_smi_path,
                "--query-gpu=temperature.gpu,utilization.gpu,memory.used,memory.total",
                "--format=csv,noheader,nounits",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3.0)
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            return out
        # First GPU only. "temp, load, mem_used, mem_total"
        first_line = stdout.decode(errors="replace").strip().splitlines()
        if not first_line:
            return out
        try:
            parts = [p.strip() for p in first_line[0].split(",")]
            if len(parts) >= 4:
                out["temp"] = float(parts[0])
                out["load"] = float(parts[1])
                out["mem_used_mb"] = float(parts[2])
                out["mem_total_mb"] = float(parts[3])
        except (ValueError, IndexError):
            pass
        return out

    def _read_amd(self, out: dict[str, Any]) -> dict[str, Any]:
        if not self._amd_hwmon:
            return out
        raw = _read_int(os.path.join(self._amd_hwmon, "temp1_input"))
        if raw is not None:
            out["temp"] = raw / 1000.0
        # gpu_busy_percent is one dir up.
        drm = os.path.dirname(os.path.dirname(self._amd_hwmon))
        busy = _read_int(os.path.join(drm, "gpu_busy_percent"))
        if busy is not None:
            out["load"] = float(busy)
        mem_used = _read_int(os.path.join(drm, "mem_info_vram_used"))
        mem_total = _read_int(os.path.join(drm, "mem_info_vram_total"))
        if mem_used is not None:
            out["mem_used_mb"] = mem_used / (1024 * 1024)
        if mem_total is not None:
            out["mem_total_mb"] = mem_total / (1024 * 1024)
        return out

    def _read_intel(self, out: dict[str, Any]) -> dict[str, Any]:
        if not self._intel_drm:
            return out
        # Intel iGPU doesn't expose temperature — inherits CPU package temp.
        cur = _read_int(os.path.join(self._intel_drm, "gt_cur_freq_mhz"))
        mx = _read_int(os.path.join(self._intel_drm, "gt_max_freq_mhz"))
        if cur is not None and mx:
            out["load"] = min(100.0, 100.0 * cur / mx)
        return out


# ---------------------------------------------------------------------------
# RAPL (Running Average Power Limit)
# ---------------------------------------------------------------------------
class _RaplReader:
    """Read /sys/class/powercap/intel-rapl:0/energy_uj and emit deltas."""

    def __init__(self):
        self._pkg_path: Optional[str] = None
        self._dram_path: Optional[str] = None
        self._last_pkg: Optional[int] = None
        self._last_dram: Optional[int] = None
        self._last_ts: Optional[float] = None
        self._max_uj: int = 0  # wrap boundary (max_energy_range_uj)
        self._discover()

    def _discover(self):
        if not _IS_LINUX:
            return
        for base in glob.glob("/sys/class/powercap/intel-rapl:*"):
            name = _read_text(os.path.join(base, "name")) or ""
            if name == "package-0":
                self._pkg_path = base
                mx = _read_int(os.path.join(base, "max_energy_range_uj"))
                if mx:
                    self._max_uj = mx
                # DRAM subdomain sits as a child intel-rapl:0:0
                for sub in glob.glob(os.path.join(base, "intel-rapl:*")):
                    sub_name = _read_text(os.path.join(sub, "name")) or ""
                    if sub_name == "dram":
                        self._dram_path = sub
                        break
                break

    def read(self) -> dict[str, Any]:
        """Return {pkg_delta_uj, dram_delta_uj, pkg_watts, dram_watts}.

        Stores deltas since the last read. First call returns zeros because
        no baseline is available yet.
        """
        out = {
            "pkg_delta_uj": 0,
            "dram_delta_uj": 0,
            "pkg_watts": 0.0,
            "dram_watts": 0.0,
        }
        if not self._pkg_path:
            return out
        pkg = _read_int(os.path.join(self._pkg_path, "energy_uj"))
        dram = _read_int(os.path.join(self._dram_path, "energy_uj")) if self._dram_path else None
        now = time.monotonic()
        if pkg is None:
            return out
        if self._last_pkg is not None and self._last_ts is not None:
            dt = now - self._last_ts
            delta = pkg - self._last_pkg
            if delta < 0:
                # counter wraparound
                delta += self._max_uj
            out["pkg_delta_uj"] = delta
            if dt > 0:
                out["pkg_watts"] = (delta / 1e6) / dt
            if dram is not None and self._last_dram is not None:
                ddelta = dram - self._last_dram
                if ddelta < 0:
                    ddelta += self._max_uj
                out["dram_delta_uj"] = ddelta
                if dt > 0:
                    out["dram_watts"] = (ddelta / 1e6) / dt
        self._last_pkg = pkg
        self._last_dram = dram
        self._last_ts = now
        return out


# ---------------------------------------------------------------------------
# Battery
# ---------------------------------------------------------------------------
def _read_battery() -> Optional[dict[str, Any]]:
    """Return the first laptop battery's state, or None if no battery."""
    if not _IS_LINUX:
        return None
    for base in sorted(glob.glob("/sys/class/power_supply/BAT*")):
        capacity = _read_int(os.path.join(base, "capacity"))
        status = _read_text(os.path.join(base, "status"))
        energy_now = _read_int(os.path.join(base, "energy_now"))
        if capacity is None and status is None:
            continue
        return {
            "name": os.path.basename(base),
            "capacity_pct": capacity,
            "status": status,
            "energy_now_uwh": energy_now,
        }
    return None


# ---------------------------------------------------------------------------
# Event packer (compact binary for event bus)
# ---------------------------------------------------------------------------
def pack_event(snapshot: dict[str, Any]) -> bytes:
    """Pack a thermal snapshot into a 24-byte wire event.

    Missing values encode as 0 (uint) or 255 (special sentinels where noted).
    """
    ts = int(time.time()) & 0xFFFFFFFF
    cpu_temp = snapshot.get("cpu", {}).get("temp")
    gpu_temp = snapshot.get("gpu", {}).get("temp")
    cpu_freq = snapshot.get("cpu", {}).get("avg_khz") or 0
    cpu_load = snapshot.get("cpu", {}).get("load_pct")
    gpu_load = snapshot.get("gpu", {}).get("load")
    state = snapshot.get("thermal_state", "unknown")
    battery = snapshot.get("battery") or {}
    bat_pct = battery.get("capacity_pct")
    pkg_delta = snapshot.get("rapl", {}).get("pkg_delta_uj", 0) or 0
    dram_delta = snapshot.get("rapl", {}).get("dram_delta_uj", 0) or 0

    return struct.pack(
        _EVENT_PACK_FMT,
        ts,
        int(round((cpu_temp or 0) * 100)) & 0xFFFF,
        int(round((gpu_temp or 0) * 100)) & 0xFFFF,
        int(cpu_freq) & 0xFFFFFFFF,
        int(round(cpu_load or 0)) & 0xFF,
        int(round(gpu_load or 0)) & 0xFF,
        _THERMAL_STATE_CODE.get(state, 255) & 0xFF,
        (int(bat_pct) & 0xFF) if bat_pct is not None else 255,
        int(pkg_delta) & 0xFFFFFFFF,
        int(dram_delta) & 0xFFFFFFFF,
    )


def unpack_event(buf: bytes) -> dict[str, Any]:
    """Inverse of :func:`pack_event`. Returns a readable dict."""
    if len(buf) != EVENT_SIZE:
        raise ValueError(f"expected {EVENT_SIZE} bytes, got {len(buf)}")
    (ts, cpu_c, gpu_c, freq, cpu_l, gpu_l, st, bat, pkg, dram) = struct.unpack(
        _EVENT_PACK_FMT, buf
    )
    return {
        "timestamp": ts,
        "cpu_temp": cpu_c / 100.0 if cpu_c else None,
        "gpu_temp": gpu_c / 100.0 if gpu_c else None,
        "cpu_freq_khz": freq,
        "cpu_load": cpu_l,
        "gpu_load": gpu_l,
        "thermal_state": _THERMAL_STATE_NAME.get(st, "unknown"),
        "battery_pct": bat if bat != 255 else None,
        "rapl_pkg_delta_uj": pkg,
        "rapl_dram_delta_uj": dram,
    }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
def _classify_state(temp: Optional[float]) -> str:
    if temp is None:
        return "unknown"
    if temp >= THERMAL_HOT:
        return "critical"
    if temp >= THERMAL_WARM:
        return "hot"
    if temp >= THERMAL_NORMAL:
        return "warm"
    return "normal"


class ThermalOrchestrator:
    """Aggregator: polls CPU + GPU + RAPL + battery on a hw-tier interval.

    Usage::

        orch = ThermalOrchestrator(hardware_class="new")
        await orch.start()
        snap = await orch.snapshot()            # dict
        event = await orch.snapshot_packed()    # 24-byte bytes
        orch.subscribe(lambda ev: ...)          # callback for threshold events
        await orch.stop()

    The poll loop is only started if ``start()`` is awaited; otherwise the
    object works as a pure on-demand reader (dashboard polls drive it).
    """

    # Poll interval per hw class (seconds).
    POLL_INTERVAL = {"old": 4.0, "mid": 1.0, "new": 0.25}

    def __init__(
        self,
        hardware_class: str = "mid",
        snapshot_ttl: float = _SNAPSHOT_TTL_DEFAULT,
    ):
        self._hw = hardware_class if hardware_class in self.POLL_INTERVAL else "mid"
        self._snapshot_ttl = max(0.05, float(snapshot_ttl))
        self._poll_interval = self.POLL_INTERVAL[self._hw]

        self._msr = _MSRReader()
        self._cpu = _CpuTelemetry(self._msr)
        self._gpu = _GpuTelemetry()
        self._rapl = _RaplReader()

        self._snapshot: Optional[dict[str, Any]] = None
        self._snapshot_ts: float = 0.0
        self._snapshot_lock = asyncio.Lock()

        self._task: Optional[asyncio.Task] = None
        self._running = False

        # Event subscribers: callables that take a dict snapshot.
        # Used by cortex + power orchestrator for governor auto-switching.
        self._subscribers: list[Callable[[dict[str, Any]], None]] = []
        self._last_state: str = "unknown"

        # Bounded ring buffer of packed events (for future zstd log rotation).
        # Each entry is 24 bytes — 1024 entries = 24 KiB. Tiny.
        self._event_ring: list[bytes] = []
        self._RING_MAX = 1024

    # ── Lifecycle ──
    async def start(self):
        if self._running:
            return
        self._running = True
        # Prime once synchronously so /thermal returns data immediately.
        await self._refresh()
        self._task = asyncio.create_task(self._poll_loop(), name="thermal-poll")
        logger.info(
            "ThermalOrchestrator started (hw_class=%s, poll=%.2fs, msr=%s, gpu=%s, rapl=%s)",
            self._hw, self._poll_interval, self._msr.available(),
            self._gpu.vendor() or "none",
            "yes" if self._rapl._pkg_path else "no",
        )

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        self._msr.close()
        logger.info("ThermalOrchestrator stopped")

    # ── Subscribers ──
    def subscribe(self, cb: Callable[[dict[str, Any]], None]):
        """Register a state-change callback. Called when thermal_state flips.

        Signature: ``cb(snapshot_dict) -> None``. Exceptions in the callback
        are caught and logged — we never want a bad subscriber to take down
        the poll loop.
        """
        self._subscribers.append(cb)

    def _notify(self, snap: dict[str, Any]):
        new_state = snap.get("thermal_state", "unknown")
        if new_state == self._last_state:
            return
        prev = self._last_state
        self._last_state = new_state
        logger.info("thermal state: %s -> %s (cpu=%s gpu=%s)",
                    prev, new_state,
                    snap.get("cpu", {}).get("temp"),
                    snap.get("gpu", {}).get("temp"))
        for cb in list(self._subscribers):
            try:
                cb(snap)
            except Exception as exc:
                logger.warning("thermal subscriber raised: %s", exc)

    # ── Poll loop ──
    async def _poll_loop(self):
        try:
            while self._running:
                try:
                    await self._refresh()
                except Exception as exc:
                    logger.warning("thermal refresh failed: %s", exc)
                await asyncio.sleep(self._poll_interval)
        except asyncio.CancelledError:
            raise

    async def _refresh(self):
        """Re-read all telemetry sources and rebuild the snapshot."""
        loop = asyncio.get_running_loop()

        # CPU telemetry: _read_temp walks hwmon/thermal_zone (fast stat()s).
        # Still run in a thread because on old-HW broken i2c buses can block.
        def _cpu_sync():
            temp, details = self._cpu.read_temp()
            freq = self._cpu.read_freq()
            load = self._cpu.read_load()
            return temp, details, freq, load

        cpu_temp, cpu_details, cpu_freq, cpu_load = await loop.run_in_executor(
            None, _cpu_sync
        )

        gpu = await self._gpu.read()

        def _rapl_sync():
            return self._rapl.read()

        rapl = await loop.run_in_executor(None, _rapl_sync)
        battery = await loop.run_in_executor(None, _read_battery)

        # Composite thermal state = max of CPU & GPU temps.
        max_temp: Optional[float] = None
        for t in (cpu_temp, gpu.get("temp")):
            if t is None:
                continue
            if max_temp is None or t > max_temp:
                max_temp = t
        state = _classify_state(max_temp)

        snap = {
            "timestamp": time.time(),
            "hardware_class": self._hw,
            "thermal_state": state,
            "max_temp": max_temp,
            "cpu": {
                "temp": cpu_temp,
                "temp_source": cpu_details.get("source"),
                "tjmax": cpu_details.get("tjmax"),
                "per_core": cpu_details.get("per_core", []),
                "zones": cpu_details.get("zones", []),
                "avg_khz": cpu_freq.get("avg_khz"),
                "max_khz": cpu_freq.get("max_khz"),
                "min_khz": cpu_freq.get("min_khz"),
                "governor": cpu_freq.get("governor"),
                "per_cpu": cpu_freq.get("per_cpu", []),
                "load_pct": cpu_load,
            },
            "gpu": gpu,
            "rapl": rapl,
            "battery": battery,
        }

        async with self._snapshot_lock:
            self._snapshot = snap
            self._snapshot_ts = time.monotonic()
            # Append packed event to ring (binary, not JSON).
            try:
                self._event_ring.append(pack_event(snap))
                if len(self._event_ring) > self._RING_MAX:
                    self._event_ring = self._event_ring[-self._RING_MAX:]
            except (struct.error, TypeError):
                pass

        self._notify(snap)

    # ── Public getters ──
    async def snapshot(self, force: bool = False) -> dict[str, Any]:
        """Return the latest snapshot dict.

        If older than ``snapshot_ttl`` (or ``force=True``) we refresh inline.
        This lets /thermal work even when the poll loop isn't running
        (e.g. during test harness or module-level degraded mode).
        """
        now = time.monotonic()
        async with self._snapshot_lock:
            fresh = (
                self._snapshot is not None
                and (now - self._snapshot_ts) < self._snapshot_ttl
            )
        if force or not fresh:
            try:
                await self._refresh()
            except Exception as exc:
                logger.warning("thermal snapshot refresh failed: %s", exc)
        async with self._snapshot_lock:
            return dict(self._snapshot) if self._snapshot else {
                "timestamp": time.time(),
                "thermal_state": "unknown",
                "error": "no telemetry sources available",
            }

    async def snapshot_packed(self) -> bytes:
        """Return the 24-byte wire-format event for the latest snapshot."""
        snap = await self.snapshot()
        return pack_event(snap)

    def recent_events(self, n: int = 64) -> list[bytes]:
        """Return up to ``n`` most recent packed events (newest last)."""
        if n <= 0:
            return []
        return list(self._event_ring[-n:])

    def is_thermal_throttled(self) -> bool:
        """True iff the last observed state warrants throttling."""
        return self._last_state in ("hot", "critical")

    # ── Introspection (for /power endpoint) ──
    @property
    def hardware_class(self) -> str:
        return self._hw

    @property
    def poll_interval(self) -> float:
        return self._poll_interval

    @property
    def msr_available(self) -> bool:
        return self._msr.available()

    @property
    def gpu_vendor(self) -> Optional[str]:
        return self._gpu.vendor()
