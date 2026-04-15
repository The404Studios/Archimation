"""
Memory Observer -- Userspace PE memory translator.

Receives raw memory events from the kernel Trust Memory Scanner (TMS) via
netlink or /dev/trust fallback, translates them into semantic PE objects,
and maintains a per-process cached memory map.

In simulation mode (default until TMS is built) it reads /proc/PID/maps
and constructs the semantic map from that data, matching regions against
known PE DLL stub paths.
"""

import asyncio
import collections
import logging
import os
import re
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ai-control.memory_observer")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Paths where our PE-compat DLL stubs live
PE_DLL_SEARCH_PATHS = [
    "/usr/lib/pe-compat/dlls",
    "/usr/lib64/pe-compat/dlls",
    "/opt/pe-compat/dlls",
]

# Netlink family for TMS events (matches trust kernel module)
NETLINK_TMS = 31

# TMS event types from the kernel
class TMSEventType(IntEnum):
    MMAP = 1
    MUNMAP = 2
    MPROTECT = 3
    BRK = 4
    PE_LOAD = 5
    PE_DLL_LOAD = 6
    PE_DLL_UNLOAD = 7

# TMS event header: type(u8) pid(u32) addr(u64) len(u64) prot(u32) pad(u8*3)
# Total: 1 + 4 + 8 + 8 + 4 + 3 = 28 bytes
TMS_HEADER_FORMAT = "<BIQQI3x"
TMS_HEADER_SIZE = struct.calcsize(TMS_HEADER_FORMAT)

# Process TTL: evict tracking data after this many seconds of no events
PROCESS_TTL = 300.0

# Maximum number of tracked processes
MAX_TRACKED_PROCESSES = 512

# Poll interval for /proc/PID/maps in simulation mode
SIMULATION_POLL_INTERVAL = 5.0

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MemoryRegion:
    """A single mapped memory region within a process."""
    va_start: int
    va_end: int
    size: int
    prot: str             # "r-x", "rw-", "r--", "rwx", etc.
    tag: str              # "text", "data", "iat", "dll", "heap", "stack", "vdso", "anon"
    label: str            # "kernel32.dll .text", "main.exe .rdata", "[heap]"
    dll_name: str         # Which DLL this belongs to (if applicable), else ""
    load_time: float


@dataclass
class ProcessMemoryMap:
    """Full memory map for a tracked PE process."""
    pid: int
    subject_id: int
    exe_name: str
    regions: dict[int, MemoryRegion]      # keyed by va_start
    dlls_loaded: dict[str, dict]          # dll_name -> {base, size, sections}
    iat_locations: dict[str, int]         # "kernel32.dll!CreateFileA" -> VA
    last_updated: float
    event_count: int


@dataclass
class MemoryAnomaly:
    """A detected memory anomaly."""
    pid: int
    timestamp: float
    severity: str          # "warning", "critical"
    kind: str              # "rwx_text", "executable_heap", "iat_hook", "unbacked_rx"
    description: str
    va_start: int
    va_end: int
    details: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# /proc/PID/maps parser
# ---------------------------------------------------------------------------

# Line format: 7f8a00000000-7f8a00021000 rw-p 00000000 08:01 12345 /path/to/lib
_MAPS_RE = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+"    # address range
    r"([rwxsp-]{4})\s+"                 # permissions
    r"([0-9a-f]+)\s+"                   # offset
    r"([0-9a-f]+:[0-9a-f]+)\s+"        # dev
    r"(\d+)\s*"                         # inode
    r"(.*)$",                           # pathname (may be empty)
    re.IGNORECASE,
)

# Known PE DLL stub filename patterns
_PE_DLL_RE = re.compile(r"libpe_(\w+)\.so", re.IGNORECASE)

# Section heuristics based on permissions and offset
def _classify_region(prot: str, pathname: str, offset: int, size: int) -> tuple[str, str]:
    """Return (tag, label) for a memory region based on heuristics."""
    name = pathname.strip()

    if not name:
        # Anonymous mapping
        if "x" in prot:
            return ("anon_exec", "anonymous executable region")
        if size >= 0x100000:
            return ("heap", "[heap-like anonymous]")
        return ("anon", "[anonymous]")

    if name == "[heap]":
        return ("heap", "[heap]")
    if name == "[stack]":
        return ("stack", "[stack]")
    if name in ("[vdso]", "[vvar]"):
        return ("vdso", name)
    if name == "[vsyscall]":
        return ("vdso", "[vsyscall]")

    # File-backed mapping -- determine section type from permissions
    basename = os.path.basename(name)

    # Check if this is a PE DLL stub
    dll_match = _PE_DLL_RE.search(basename)
    dll_name = ""
    if dll_match:
        dll_name = dll_match.group(1) + ".dll"
    elif basename.endswith(".so") or ".so." in basename:
        dll_name = basename

    if "x" in prot and "w" not in prot:
        section = ".text"
        tag = "text"
    elif "w" in prot and "x" not in prot:
        if offset == 0:
            section = ".data"
            tag = "data"
        else:
            section = ".data/.bss"
            tag = "data"
    elif "x" in prot and "w" in prot:
        section = ".text (RWX!)"
        tag = "text_rwx"
    elif "r" in prot and "w" not in prot and "x" not in prot:
        section = ".rodata"
        tag = "rodata"
    else:
        section = "unknown"
        tag = "unknown"

    if dll_name:
        label = f"{dll_name} {section}"
    else:
        label = f"{basename} {section}"

    return (tag, label)


def _extract_dll_name(pathname: str) -> str:
    """Extract a DLL name from a pathname, if it's a PE-compat DLL stub."""
    basename = os.path.basename(pathname.strip())
    m = _PE_DLL_RE.search(basename)
    if m:
        return m.group(1) + ".dll"
    return ""


def _is_pe_related_path(pathname: str) -> bool:
    """Check if a path is related to PE-compat infrastructure."""
    name = pathname.strip()
    if not name:
        return False
    for prefix in PE_DLL_SEARCH_PATHS:
        if name.startswith(prefix):
            return True
    if "pe-compat" in name or "pe_" in os.path.basename(name):
        return True
    return False


def parse_proc_maps(pid: int) -> Optional[list[dict]]:
    """Parse /proc/PID/maps and return a list of region dicts."""
    maps_path = f"/proc/{pid}/maps"
    try:
        with open(maps_path, "r") as f:
            lines = f.readlines()
    except (OSError, PermissionError):
        return None

    regions = []
    for line in lines:
        m = _MAPS_RE.match(line.strip())
        if not m:
            continue

        va_start = int(m.group(1), 16)
        va_end = int(m.group(2), 16)
        perms = m.group(3)
        offset = int(m.group(4), 16)
        _dev = m.group(5)
        _inode = int(m.group(6))
        pathname = m.group(7).strip()

        # Convert rwxp/s to simpler form
        prot = perms[:3].replace("-", "")
        if not prot:
            prot = "---"

        size = va_end - va_start
        tag, label = _classify_region(perms, pathname, offset, size)
        dll_name = _extract_dll_name(pathname)

        regions.append({
            "va_start": va_start,
            "va_end": va_end,
            "size": size,
            "prot": perms[:3],
            "tag": tag,
            "label": label,
            "dll_name": dll_name,
            "pathname": pathname,
            "offset": offset,
        })

    return regions


def _get_exe_name(pid: int) -> str:
    """Get the executable name for a PID."""
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
        return os.path.basename(exe)
    except (OSError, PermissionError):
        return "unknown"


def _find_pe_processes() -> list[int]:
    """Find PIDs that are likely running PE executables.

    Heuristic: processes whose memory maps include PE-compat DLL stubs
    or whose exe path suggests they were loaded by the PE loader.

    Fast-path via readlink(/proc/PID/exe): pe-loader processes link
    directly to /usr/bin/peloader or similar, which avoids reading
    /proc/PID/maps for every single PID on the system (hundreds of
    opens and short reads on a busy box). Falls back to maps scanning
    for non-loader PE processes (e.g. launched via binfmt_misc).
    """
    pe_pids = []
    try:
        proc_entries = os.listdir("/proc")
    except (OSError, PermissionError):
        return []

    # First pass: cheap readlink() filter. Most idle PIDs fail here fast
    # (no need to open /proc/PID/maps, which can be 1000+ lines).
    maps_candidates = []
    for entry in proc_entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except (OSError, PermissionError):
            continue
        if "peloader" in exe or "pe-loader" in exe:
            pe_pids.append(pid)
            continue
        # Only scan maps for PIDs whose exe is suspicious (e.g. .exe
        # binfmt trampolines or unusual locations).
        if exe.endswith(".exe") or "pe-compat" in exe:
            pe_pids.append(pid)
            continue
        maps_candidates.append(pid)

    # Second pass: maps content scan for remaining candidates. Skip this
    # entirely if we've already found enough PE processes — saves a lot
    # of I/O on systems with many idle non-PE processes.
    if len(pe_pids) < 256:
        for pid in maps_candidates:
            maps_path = f"/proc/{pid}/maps"
            try:
                with open(maps_path, "r") as f:
                    content = f.read(8192)  # Read first 8K only
                if "pe-compat" in content or "libpe_" in content:
                    pe_pids.append(pid)
            except (OSError, PermissionError):
                continue
    return pe_pids


# ---------------------------------------------------------------------------
# Memory Observer
# ---------------------------------------------------------------------------

class MemoryObserver:
    """
    Userspace PE memory translator.

    Receives raw memory events from the kernel TMS (Trust Memory Scanner),
    translates them into semantic PE objects, and maintains a per-process
    cached memory map with anomaly detection.

    Falls back to /proc/PID/maps polling when TMS is not available.
    """

    def __init__(
        self,
        dev_path: str = "/dev/trust",
        poll_interval: float = SIMULATION_POLL_INTERVAL,
        process_ttl: float = PROCESS_TTL,
        max_processes: int = MAX_TRACKED_PROCESSES,
    ):
        self._dev_path = dev_path
        self._poll_interval = poll_interval
        self._process_ttl = process_ttl
        self._max_processes = max_processes

        # Per-process memory maps
        self._processes: dict[int, ProcessMemoryMap] = {}

        # Anomaly log (bounded ring buffer -- deque gives O(1) eviction
        # instead of the O(n) list-slice previously used in the hot path)
        self._max_anomalies = 1000
        self._anomalies: collections.deque = collections.deque(maxlen=self._max_anomalies)

        # Lifecycle
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._mode: str = "idle"  # "tms", "simulation", "idle"

        # Stats
        self._stats = {
            "events_processed": 0,
            "anomalies_detected": 0,
            "processes_tracked": 0,
            "scans_completed": 0,
            "last_scan_time": 0.0,
        }

        # Netlink socket (if TMS available)
        self._nl_sock = None

    # ── Lifecycle ──

    async def start(self):
        """Start the memory observer. Tries TMS netlink first, falls back to simulation."""
        self._running = True

        # Try to connect to TMS via netlink
        if self._try_connect_tms():
            self._mode = "tms"
            self._task = asyncio.create_task(self._tms_event_loop())
            logger.info("Memory observer started in TMS mode (netlink)")
        else:
            # Fall back to /proc/PID/maps simulation
            self._mode = "simulation"
            self._task = asyncio.create_task(self._simulation_loop())
            logger.info(
                "Memory observer started in simulation mode "
                "(polling /proc/PID/maps every %.1fs)",
                self._poll_interval,
            )

    async def stop(self):
        """Stop the memory observer and clean up."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._nl_sock is not None:
            try:
                self._nl_sock.close()
            except OSError:
                pass
            self._nl_sock = None
        logger.info(
            "Memory observer stopped. mode=%s tracked=%d anomalies=%d events=%d",
            self._mode, len(self._processes),
            self._stats["anomalies_detected"],
            self._stats["events_processed"],
        )
        self._mode = "idle"

    def _try_connect_tms(self) -> bool:
        """Try to open a netlink socket to the kernel TMS.

        Returns True if the connection succeeded, False otherwise.
        """
        sock = None
        try:
            import socket
            sock = socket.socket(
                socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_TMS
            )
            sock.bind((os.getpid(), 0))
            sock.setblocking(False)
            self._nl_sock = sock
            logger.info("Connected to TMS via netlink (family=%d)", NETLINK_TMS)
            return True
        except (OSError, AttributeError, ImportError) as e:
            # Close the socket if it was created but bind/setblocking failed,
            # otherwise we leak an FD on every retry.
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            logger.debug("TMS netlink unavailable: %s", e)
            return False

    # ── TMS event loop ──

    async def _tms_event_loop(self):
        """Read and process TMS events from the netlink socket."""
        loop = asyncio.get_running_loop()
        while self._running:
            try:
                data = await loop.sock_recv(self._nl_sock, 4096)
                if data:
                    self._process_tms_event(data)
            except asyncio.CancelledError:
                break
            except OSError:
                if self._running:
                    await asyncio.sleep(1.0)

    def _process_tms_event(self, data: bytes):
        """Parse a raw TMS event and update the memory map."""
        if len(data) < TMS_HEADER_SIZE:
            return

        try:
            etype, pid, addr, length, prot = struct.unpack(
                TMS_HEADER_FORMAT, data[:TMS_HEADER_SIZE]
            )
        except struct.error:
            return

        # Path string follows the header (null-terminated)
        path_data = data[TMS_HEADER_SIZE:]
        pathname = path_data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

        now = time.time()
        self._stats["events_processed"] += 1

        etype_enum = TMSEventType(etype) if etype in TMSEventType._value2member_map_ else None

        if etype_enum in (TMSEventType.MMAP, TMSEventType.PE_LOAD, TMSEventType.PE_DLL_LOAD):
            self._handle_mmap(pid, addr, length, prot, pathname, now)
        elif etype_enum == TMSEventType.MUNMAP:
            self._handle_munmap(pid, addr, length, now)
        elif etype_enum == TMSEventType.MPROTECT:
            self._handle_mprotect(pid, addr, length, prot, now)
        elif etype_enum == TMSEventType.PE_DLL_UNLOAD:
            self._handle_dll_unload(pid, pathname, now)

    # ── Simulation loop (fallback) ──

    async def _simulation_loop(self):
        """Poll /proc for PE processes and build memory maps from /proc/PID/maps."""
        while self._running:
            try:
                await self._scan_all_processes()
                self._evict_dead_processes()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in simulation loop")

            try:
                await asyncio.sleep(self._poll_interval)
            except asyncio.CancelledError:
                break

    async def _scan_all_processes(self):
        """Discover and scan all PE-related processes."""
        loop = asyncio.get_running_loop()
        # Run the blocking /proc scan in an executor
        pe_pids = await loop.run_in_executor(None, _find_pe_processes)

        # Also rescan already-tracked processes
        known_pids = set(self._processes.keys())
        all_pids = set(pe_pids) | known_pids

        for pid in all_pids:
            if not self._running:
                break
            if len(self._processes) >= self._max_processes and pid not in self._processes:
                continue  # Don't add new processes beyond the cap
            await self._scan_process(pid)

        self._stats["scans_completed"] += 1
        self._stats["last_scan_time"] = time.time()
        self._stats["processes_tracked"] = len(self._processes)

    async def _scan_process(self, pid: int):
        """Scan a single process and update its memory map."""
        loop = asyncio.get_running_loop()
        raw_regions = await loop.run_in_executor(None, parse_proc_maps, pid)
        if raw_regions is None:
            # Process may have exited
            self._processes.pop(pid, None)
            return

        now = time.time()

        # Get or create the process entry
        if pid not in self._processes:
            # Evict stale entries if too many processes tracked
            if len(self._processes) >= self._max_processes:
                # Remove entries for PIDs that no longer exist
                stale_pids = [p for p in self._processes
                              if not os.path.exists(f"/proc/{p}")]
                for p in stale_pids:
                    del self._processes[p]
                # If still over cap, evict the oldest
                if len(self._processes) >= self._max_processes:
                    oldest_pid = min(
                        self._processes,
                        key=lambda p: self._processes[p].last_updated,
                    )
                    del self._processes[oldest_pid]

            exe_name = await loop.run_in_executor(None, _get_exe_name, pid)
            self._processes[pid] = ProcessMemoryMap(
                pid=pid,
                subject_id=0,  # Will be populated when trust module is available
                exe_name=exe_name,
                regions={},
                dlls_loaded={},
                iat_locations={},
                last_updated=now,
                event_count=0,
            )

        pmap = self._processes[pid]
        old_regions = pmap.regions
        new_regions: dict[int, MemoryRegion] = {}
        new_dlls: dict[str, dict] = {}

        for r in raw_regions:
            region = MemoryRegion(
                va_start=r["va_start"],
                va_end=r["va_end"],
                size=r["size"],
                prot=r["prot"],
                tag=r["tag"],
                label=r["label"],
                dll_name=r["dll_name"],
                load_time=now,
            )
            new_regions[r["va_start"]] = region

            # Track DLLs
            dll_name = r["dll_name"]
            if dll_name:
                if dll_name not in new_dlls:
                    new_dlls[dll_name] = {
                        "base": r["va_start"],
                        "size": 0,
                        "sections": [],
                        "pathname": r.get("pathname", ""),
                    }
                dll_info = new_dlls[dll_name]
                dll_info["size"] += r["size"]
                dll_info["sections"].append({
                    "va_start": r["va_start"],
                    "va_end": r["va_end"],
                    "prot": r["prot"],
                    "tag": r["tag"],
                })

        # Detect anomalies by comparing old and new regions
        self._detect_anomalies(pid, old_regions, new_regions, pmap.exe_name)

        # Update the process map
        pmap.regions = new_regions
        pmap.dlls_loaded = new_dlls
        pmap.last_updated = now
        pmap.event_count += 1

    # ── Event handlers (for TMS mode) ──

    def _handle_mmap(self, pid: int, addr: int, length: int, prot: int,
                     pathname: str, now: float):
        """Handle an mmap event from TMS."""
        prot_str = self._prot_int_to_str(prot)
        tag, label = _classify_region(prot_str + "p", pathname, 0, length)
        dll_name = _extract_dll_name(pathname)

        self._ensure_process(pid, now)
        pmap = self._processes[pid]

        region = MemoryRegion(
            va_start=addr,
            va_end=addr + length,
            size=length,
            prot=prot_str,
            tag=tag,
            label=label,
            dll_name=dll_name,
            load_time=now,
        )
        pmap.regions[addr] = region
        pmap.last_updated = now
        pmap.event_count += 1

        # Track DLL loading
        if dll_name:
            if dll_name not in pmap.dlls_loaded:
                pmap.dlls_loaded[dll_name] = {
                    "base": addr, "size": length, "sections": [],
                    "pathname": pathname,
                }
                logger.info(
                    "[pid=%d] DLL loaded: %s at 0x%x (size=0x%x)",
                    pid, dll_name, addr, length,
                )

        # Anomaly: executable heap / RWX anon
        if "x" in prot_str and "w" in prot_str and not pathname:
            self._record_anomaly(MemoryAnomaly(
                pid=pid, timestamp=now, severity="critical",
                kind="executable_heap",
                description=(
                    f"Executable anonymous allocation at 0x{addr:x} "
                    f"(size=0x{length:x}, prot={prot_str}) -- possible shellcode"
                ),
                va_start=addr, va_end=addr + length,
            ))

    def _handle_munmap(self, pid: int, addr: int, length: int, now: float):
        """Handle a munmap event from TMS."""
        if pid not in self._processes:
            return
        pmap = self._processes[pid]
        pmap.regions.pop(addr, None)
        pmap.last_updated = now
        pmap.event_count += 1

    def _handle_mprotect(self, pid: int, addr: int, length: int,
                         new_prot: int, now: float):
        """Handle an mprotect event from TMS."""
        if pid not in self._processes:
            return
        pmap = self._processes[pid]
        prot_str = self._prot_int_to_str(new_prot)

        # Find the region being modified
        region = pmap.regions.get(addr)
        if region is None:
            # Look for a region that contains this address
            for va, r in pmap.regions.items():
                if va <= addr < r.va_end:
                    region = r
                    break

        if region:
            old_prot = region.prot

            # Anomaly: text section made writable
            if region.tag == "text" and "w" in prot_str and "w" not in old_prot:
                severity = "critical" if region.dll_name else "warning"
                self._record_anomaly(MemoryAnomaly(
                    pid=pid, timestamp=now, severity=severity,
                    kind="rwx_text",
                    description=(
                        f"{region.label} made writable "
                        f"(0x{addr:x}, old={old_prot}, new={prot_str}) "
                        f"-- possible IAT hook or code patching"
                    ),
                    va_start=addr, va_end=addr + length,
                    details={"old_prot": old_prot, "new_prot": prot_str,
                             "dll": region.dll_name},
                ))

            # Anomaly: read-only data made executable
            if region.tag in ("data", "rodata") and "x" in prot_str and "x" not in old_prot:
                self._record_anomaly(MemoryAnomaly(
                    pid=pid, timestamp=now, severity="warning",
                    kind="data_exec",
                    description=(
                        f"{region.label} made executable "
                        f"(0x{addr:x}, old={old_prot}, new={prot_str})"
                    ),
                    va_start=addr, va_end=addr + length,
                    details={"old_prot": old_prot, "new_prot": prot_str},
                ))

            region.prot = prot_str

        pmap.last_updated = now
        pmap.event_count += 1

    def _handle_dll_unload(self, pid: int, pathname: str, now: float):
        """Handle a DLL unload event from TMS."""
        if pid not in self._processes:
            return
        pmap = self._processes[pid]
        dll_name = _extract_dll_name(pathname)
        if dll_name and dll_name in pmap.dlls_loaded:
            dll_info = pmap.dlls_loaded.pop(dll_name)
            # Remove regions belonging to this DLL
            to_remove = [
                va for va, r in pmap.regions.items()
                if r.dll_name == dll_name
            ]
            for va in to_remove:
                del pmap.regions[va]
            logger.info("[pid=%d] DLL unloaded: %s", pid, dll_name)
        pmap.last_updated = now
        pmap.event_count += 1

    # ── Anomaly detection ──

    def _detect_anomalies(self, pid: int, old_regions: dict[int, MemoryRegion],
                          new_regions: dict[int, MemoryRegion],
                          exe_name: str):
        """Compare old and new region maps to detect anomalies."""
        now = time.time()

        for va, new_r in new_regions.items():
            old_r = old_regions.get(va)

            # New RWX anonymous mapping
            if old_r is None and "x" in new_r.prot and "w" in new_r.prot:
                if not new_r.dll_name and new_r.tag in ("anon_exec", "anon"):
                    self._record_anomaly(MemoryAnomaly(
                        pid=pid, timestamp=now, severity="critical",
                        kind="executable_heap",
                        description=(
                            f"New RWX anonymous mapping at 0x{va:x} "
                            f"(size=0x{new_r.size:x}) in {exe_name} "
                            f"-- possible shellcode injection"
                        ),
                        va_start=va, va_end=new_r.va_end,
                    ))

            # Permission change on existing region
            if old_r is not None and old_r.prot != new_r.prot:
                # Text section made writable
                if old_r.tag == "text" and "w" in new_r.prot and "w" not in old_r.prot:
                    self._record_anomaly(MemoryAnomaly(
                        pid=pid, timestamp=now, severity="critical",
                        kind="rwx_text",
                        description=(
                            f"{old_r.label} protection changed "
                            f"({old_r.prot} -> {new_r.prot}) in {exe_name} "
                            f"-- possible IAT hook"
                        ),
                        va_start=va, va_end=new_r.va_end,
                        details={
                            "old_prot": old_r.prot,
                            "new_prot": new_r.prot,
                            "dll": old_r.dll_name,
                        },
                    ))

        # Detect DLL unloads (region disappeared and it was a DLL)
        for va, old_r in old_regions.items():
            if va not in new_regions and old_r.dll_name:
                logger.debug(
                    "[pid=%d] Region for %s at 0x%x disappeared",
                    pid, old_r.dll_name, va,
                )

    def _record_anomaly(self, anomaly: MemoryAnomaly):
        """Record an anomaly, maintaining the ring buffer."""
        self._anomalies.append(anomaly)
        self._stats["anomalies_detected"] += 1
        logger.warning(
            "[MEMORY ANOMALY] pid=%d severity=%s kind=%s: %s",
            anomaly.pid, anomaly.severity, anomaly.kind, anomaly.description,
        )

    # ── Helpers ──

    def _ensure_process(self, pid: int, now: float):
        """Ensure a ProcessMemoryMap entry exists for the given PID."""
        if pid not in self._processes:
            if len(self._processes) >= self._max_processes:
                # Evict the least recently updated process
                oldest_pid = min(
                    self._processes, key=lambda p: self._processes[p].last_updated
                )
                del self._processes[oldest_pid]

            self._processes[pid] = ProcessMemoryMap(
                pid=pid,
                subject_id=0,
                exe_name=_get_exe_name(pid),
                regions={},
                dlls_loaded={},
                iat_locations={},
                last_updated=now,
                event_count=0,
            )

    def _evict_dead_processes(self):
        """Remove tracking data for processes that no longer exist or are stale."""
        now = time.time()
        to_remove = []
        for pid, pmap in self._processes.items():
            # Check if process still exists
            if not os.path.exists(f"/proc/{pid}"):
                to_remove.append(pid)
                continue
            # Check TTL
            if now - pmap.last_updated > self._process_ttl:
                to_remove.append(pid)

        for pid in to_remove:
            del self._processes[pid]
            logger.debug("Evicted stale process pid=%d", pid)

    @staticmethod
    def _prot_int_to_str(prot: int) -> str:
        """Convert mmap prot integer flags to a string like 'rwx'."""
        s = ""
        s += "r" if prot & 0x1 else "-"
        s += "w" if prot & 0x2 else "-"
        s += "x" if prot & 0x4 else "-"
        return s

    # ── Query API ──

    async def get_process_map(self, pid: int) -> Optional[dict]:
        """Get the full memory map for a process.

        Returns None if the process is not tracked. Triggers a fresh scan
        if in simulation mode.
        """
        if self._mode == "simulation" and pid not in self._processes:
            # Try to scan this specific process on demand
            await self._scan_process(pid)

        pmap = self._processes.get(pid)
        if pmap is None:
            return None

        return {
            "pid": pmap.pid,
            "subject_id": pmap.subject_id,
            "exe_name": pmap.exe_name,
            "region_count": len(pmap.regions),
            "regions": [
                {
                    "va_start": f"0x{r.va_start:x}",
                    "va_end": f"0x{r.va_end:x}",
                    "size": r.size,
                    "size_human": _human_size(r.size),
                    "prot": r.prot,
                    "tag": r.tag,
                    "label": r.label,
                    "dll_name": r.dll_name,
                }
                for r in sorted(pmap.regions.values(), key=lambda r: r.va_start)
            ],
            "dlls_loaded": pmap.dlls_loaded,
            "iat_locations": {
                k: f"0x{v:x}" for k, v in pmap.iat_locations.items()
            },
            "last_updated": pmap.last_updated,
            "event_count": pmap.event_count,
        }

    async def get_loaded_dlls(self, pid: int) -> Optional[list[dict]]:
        """Get loaded DLLs for a process."""
        if self._mode == "simulation" and pid not in self._processes:
            await self._scan_process(pid)

        pmap = self._processes.get(pid)
        if pmap is None:
            return None

        dlls = []
        for name, info in sorted(pmap.dlls_loaded.items()):
            dlls.append({
                "name": name,
                "base": f"0x{info['base']:x}",
                "size": info["size"],
                "size_human": _human_size(info["size"]),
                "sections": info.get("sections", []),
                "pathname": info.get("pathname", ""),
            })
        return dlls

    async def get_iat_status(self, pid: int) -> Optional[dict]:
        """Get IAT status for a process -- which IAT entries might be hooked.

        This is best-effort. In simulation mode we check for RWX regions
        overlapping known DLL text sections.
        """
        if self._mode == "simulation" and pid not in self._processes:
            await self._scan_process(pid)

        pmap = self._processes.get(pid)
        if pmap is None:
            return None

        suspicious = []
        for va, region in pmap.regions.items():
            # RWX text sections in DLLs are suspicious
            if region.dll_name and region.tag == "text_rwx":
                suspicious.append({
                    "dll": region.dll_name,
                    "va_start": f"0x{va:x}",
                    "va_end": f"0x{region.va_end:x}",
                    "prot": region.prot,
                    "reason": "DLL text section is RWX (possible IAT hook)",
                })

        return {
            "pid": pid,
            "exe_name": pmap.exe_name,
            "iat_entries": {
                k: f"0x{v:x}" for k, v in pmap.iat_locations.items()
            },
            "suspicious_regions": suspicious,
            "status": "clean" if not suspicious else "suspicious",
        }

    async def get_memory_anomalies(self, pid: Optional[int] = None) -> list[dict]:
        """Get detected memory anomalies, optionally filtered by PID."""
        # Single-pass filter+transform: avoid materializing an intermediate
        # filtered list before building the output (relevant once the ring
        # buffer grows toward _max_anomalies on long-running daemons).
        return [
            {
                "pid": a.pid,
                "timestamp": a.timestamp,
                "severity": a.severity,
                "kind": a.kind,
                "description": a.description,
                "va_start": f"0x{a.va_start:x}",
                "va_end": f"0x{a.va_end:x}",
                "details": a.details,
            }
            for a in self._anomalies
            if pid is None or a.pid == pid
        ]

    async def get_all_tracked(self) -> list[dict]:
        """Get a summary of all tracked processes."""
        # Build per-PID anomaly counts in one pass to avoid O(N_procs * N_anoms)
        # scans when both the process table and anomaly ring buffer are full.
        anomalies_by_pid: dict[int, int] = {}
        for a in self._anomalies:
            anomalies_by_pid[a.pid] = anomalies_by_pid.get(a.pid, 0) + 1

        summaries = []
        for pid, pmap in sorted(self._processes.items()):
            pe_dll_count = sum(
                1 for d in pmap.dlls_loaded
                if d.endswith(".dll")
            )
            anomaly_count = anomalies_by_pid.get(pid, 0)
            total_mapped = sum(r.size for r in pmap.regions.values())

            summaries.append({
                "pid": pid,
                "exe_name": pmap.exe_name,
                "region_count": len(pmap.regions),
                "dll_count": len(pmap.dlls_loaded),
                "pe_dll_count": pe_dll_count,
                "total_mapped": total_mapped,
                "total_mapped_human": _human_size(total_mapped),
                "anomaly_count": anomaly_count,
                "last_updated": pmap.last_updated,
                "event_count": pmap.event_count,
            })

        return summaries

    async def search_pattern(self, pid: int, pattern: bytes) -> list[dict]:
        """Search for a byte pattern in a process's readable memory.

        Returns a list of matches with virtual addresses.
        WARNING: This reads /proc/PID/mem and can be slow for large processes.
        """
        if pid not in self._processes:
            return []

        pmap = self._processes[pid]
        matches = []
        mem_path = f"/proc/{pid}/mem"

        try:
            fd = os.open(mem_path, os.O_RDONLY)
        except (OSError, PermissionError):
            return []

        try:
            for va, region in sorted(pmap.regions.items()):
                # Only scan readable regions, skip very large ones
                if "r" not in region.prot:
                    continue
                if region.size > 64 * 1024 * 1024:  # Skip regions > 64MB
                    continue

                try:
                    os.lseek(fd, va, os.SEEK_SET)
                    data = os.read(fd, region.size)
                except OSError:
                    continue

                # Search for pattern in this chunk
                offset = 0
                while True:
                    idx = data.find(pattern, offset)
                    if idx == -1:
                        break
                    match_va = va + idx
                    matches.append({
                        "va": f"0x{match_va:x}",
                        "va_int": match_va,
                        "region_label": region.label,
                        "region_tag": region.tag,
                        "offset_in_region": idx,
                    })
                    offset = idx + 1
                    # Cap results
                    if len(matches) >= 1000:
                        break

                if len(matches) >= 1000:
                    break
        finally:
            os.close(fd)

        self._stats["scans_completed"] += 1
        return matches

    # ── Introspection ──

    def get_stats(self) -> dict:
        """Return observer statistics."""
        return {
            **self._stats,
            "mode": self._mode,
            "processes_tracked": len(self._processes),
            "anomalies_total": len(self._anomalies),
            "running": self._running,
        }


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _human_size(size: int) -> str:
    """Convert a byte count to a human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(size) < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
