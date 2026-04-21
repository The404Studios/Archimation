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

try:
    # Event-driven process tracker.  Import is safe on any platform --
    # the listener's probe() returns False off Linux.  Daemon modules
    # are loaded by filename (main.py adds the daemon/ dir to sys.path)
    # so a flat "cn_proc" import is the canonical form; we also try the
    # dotted form for benchmarks / test runners.
    from cn_proc import CnProcListener, CnProcEvent, ProcEvent
    _CN_PROC_IMPORT_OK = True
except Exception:
    try:
        from daemon.cn_proc import CnProcListener, CnProcEvent, ProcEvent  # type: ignore
        _CN_PROC_IMPORT_OK = True
    except Exception:
        CnProcListener = None  # type: ignore[assignment]
        CnProcEvent = None     # type: ignore[assignment]
        ProcEvent = None       # type: ignore[assignment]
        _CN_PROC_IMPORT_OK = False

# io_uring batch reader -- same flat/dotted import dance as cn_proc.
# The shim never raises at import time, but the module itself may not
# exist on older checkouts.  Treat the import failure as "feature off".
try:
    from iouring import IOUring, batch_read_proc_files
    _IOURING_IMPORT_OK = True
except Exception:
    try:
        from daemon.iouring import IOUring, batch_read_proc_files  # type: ignore
        _IOURING_IMPORT_OK = True
    except Exception:
        IOUring = None  # type: ignore[assignment]
        batch_read_proc_files = None  # type: ignore[assignment]
        _IOURING_IMPORT_OK = False

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


def _parse_maps_text(text: str) -> list[dict]:
    """Parse the text of a ``/proc/<pid>/maps`` file.

    Split out of :func:`parse_proc_maps` so the io_uring batch reader
    (which has raw bytes already in hand) can reuse the same parser
    without doing another open()+read().
    """
    regions = []
    for line in text.splitlines():
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


def parse_proc_maps(pid: int) -> Optional[list[dict]]:
    """Parse /proc/PID/maps and return a list of region dicts."""
    maps_path = f"/proc/{pid}/maps"
    try:
        with open(maps_path, "r") as f:
            text = f.read()
    except (OSError, PermissionError):
        return None
    return _parse_maps_text(text)


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
        use_iouring: bool = False,
        iouring_sqpoll: bool = False,
        iouring_sq_cpu: Optional[int] = None,
        iouring_depth: int = 32,
    ):
        self._dev_path = dev_path
        self._poll_interval = poll_interval
        self._process_ttl = process_ttl
        self._max_processes = max_processes
        # io_uring feature flag + params.  Set by daemon/main.py from
        # config.  When False we stay on classic blocking /proc reads,
        # which is correct on old HW (SQPOLL would burn a core) and on
        # kernels <5.1 (no io_uring syscall).
        self._use_iouring = bool(use_iouring and _IOURING_IMPORT_OK)
        self._iouring_sqpoll = bool(iouring_sqpoll)
        self._iouring_sq_cpu = iouring_sq_cpu
        self._iouring_depth = max(8, int(iouring_depth))
        # Runtime-disable flag: if any io_uring call fails we stop trying
        # for the rest of this process's life.  Avoids spamming logs.
        self._iouring_disabled: bool = False

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

        # cn_proc event-driven process tracker (simulation-mode assist).
        # When this is active we stop walking /proc every poll and only
        # scan on exec() events, which is a huge idle-CPU saving on
        # low-end hardware.  If CAP_NET_ADMIN is unavailable we transparently
        # stay on the polling path.
        self._cnproc: Optional["CnProcListener"] = None
        self._cnproc_active: bool = False
        # PIDs that need a memory-map scan on the next loop iteration.
        # Populated from cn_proc exec events; drained by the simulation
        # loop.  A set dedupes rapid-fire execs from shell pipelines.
        self._pending_exec_pids: set[int] = set()
        # PIDs that need eviction (exit events).
        self._pending_exit_pids: set[int] = set()
        # Set whenever an event landed -- wakes the simulation loop.
        self._event_wake: Optional[asyncio.Event] = None

        # S75 Agent B: DLL-load observer hooks. Callbacks registered here
        # are fired with (pid, dll_name) whenever we first observe a DLL
        # in a PID's memory map (either via a TMS mmap event or via the
        # simulation-mode /proc/PID/maps re-parse).
        # Kept as a list so multiple consumers can subscribe (library_census
        # is the first; future RNA/ROS/microbiome sub-observers can stack).
        # Stored as list[Callable[[int, str], None]]; exceptions are
        # swallowed so one bad consumer can't poison the hot path.
        self._dll_load_callbacks: list = []

    def register_dll_load_callback(self, cb) -> None:
        """Register *cb* for per-DLL-load events.

        Signature: ``cb(pid: int, dll_name: str) -> None``.

        Called whenever a DLL first appears in a tracked PID's memory
        map. Both TMS-mode (event-driven) and simulation-mode (periodic
        /proc/PID/maps re-parse) paths invoke the callback. The hook is
        additive -- callers that don't register see no behavioral change.
        """
        if callable(cb) and cb not in self._dll_load_callbacks:
            self._dll_load_callbacks.append(cb)

    def _fire_dll_load(self, pid: int, dll_name: str) -> None:
        """Fire DLL-load callbacks; swallow consumer exceptions."""
        if not self._dll_load_callbacks or not dll_name:
            return
        for cb in self._dll_load_callbacks:
            try:
                cb(pid, dll_name)
            except Exception:
                logger.debug("DLL-load callback failed for pid=%d dll=%s",
                             pid, dll_name, exc_info=True)

    # ── Lifecycle ──

    async def start(self):
        """Start the memory observer. Tries TMS netlink first, falls back to simulation."""
        self._running = True
        self._event_wake = asyncio.Event()

        # Try to connect to TMS via netlink
        if self._try_connect_tms():
            self._mode = "tms"
            self._task = asyncio.create_task(self._tms_event_loop())
            logger.info("Memory observer started in TMS mode (netlink)")
        else:
            # Try the cn_proc fast path before committing to a plain poll
            # loop.  If it succeeds we get event-driven process discovery
            # and drop the per-poll /proc walk; if not we fall back.
            await self._try_start_cnproc()
            self._mode = "simulation"
            self._task = asyncio.create_task(self._simulation_loop())
            if self._cnproc_active:
                logger.info(
                    "Memory observer started in simulation mode "
                    "(cn_proc event-driven, lazy rescan interval %.1fs)",
                    self._poll_interval,
                )
            else:
                logger.info(
                    "Memory observer started in simulation mode "
                    "(polling /proc/PID/maps every %.1fs)",
                    self._poll_interval,
                )

    async def stop(self):
        """Stop the memory observer and clean up."""
        self._running = False
        # Wake the simulation loop so it observes the stop flag promptly
        # instead of sitting out the full poll interval.
        if self._event_wake is not None:
            try:
                self._event_wake.set()
            except RuntimeError:
                pass
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
        if self._cnproc is not None:
            try:
                self._cnproc.stop()
            except Exception:
                pass
            self._cnproc = None
            self._cnproc_active = False
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

    async def _try_start_cnproc(self) -> bool:
        """Subscribe to PROC_CN_MCAST_LISTEN if the platform permits.

        Requires CAP_NET_ADMIN.  When the subscribe succeeds we register
        fork/exec/exit callbacks that queue PIDs for the simulation loop
        to pick up -- the loop itself then stops enumerating all of
        /proc on every tick.
        """
        if not _CN_PROC_IMPORT_OK or CnProcListener is None:
            return False
        if not CnProcListener.probe():
            return False
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return False

        listener = CnProcListener()
        ok = await listener.start(loop)
        if not ok:
            return False

        # Bind event handlers.  These run in the event-loop thread with
        # no await, so they must be cheap -- just enqueue PIDs and set
        # the wake event.
        listener.on_exec(self._on_cnproc_exec)
        listener.on_exit(self._on_cnproc_exit)
        # Fork is informational; we wait for exec before scanning because
        # forked-without-exec children inherit the parent's mapping.

        self._cnproc = listener
        self._cnproc_active = True
        return True

    def _on_cnproc_exec(self, ev: "CnProcEvent") -> None:
        """exec() event: a new program is running under this PID.

        Queue a memory-map rescan on the next simulation loop tick.
        """
        if not self._running:
            return
        self._pending_exec_pids.add(ev.pid)
        if self._event_wake is not None:
            self._event_wake.set()

    def _on_cnproc_exit(self, ev: "CnProcEvent") -> None:
        """exit() event: drop tracking so we don't rescan a dead PID."""
        if not self._running:
            return
        self._pending_exit_pids.add(ev.pid)
        if self._event_wake is not None:
            self._event_wake.set()

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
        """Drive the /proc/PID/maps scanner.

        Two modes:

        * **cn_proc-driven** (preferred): wait on an asyncio Event that
          the event callbacks fire.  Each wake processes only the PIDs
          that exec'd or exited, then does a cheap refresh of already-
          tracked processes.  A long-interval tick still runs in the
          background so we catch any events we may have missed (e.g.
          during a brief buffer overflow).

        * **polling fallback**: every ``poll_interval`` seconds walk
          /proc top-to-bottom for PE processes.
        """
        # Initial full scan so we don't start empty.
        try:
            await self._scan_all_processes()
            self._evict_dead_processes()
        except asyncio.CancelledError:
            return
        except Exception:
            logger.exception("Error during initial simulation scan")

        # Longer idle interval when events drive us -- cn_proc wakes us
        # immediately on interesting changes, so the periodic rescan is
        # just a safety net.
        idle_interval = max(self._poll_interval * 6.0, 30.0) if self._cnproc_active \
            else self._poll_interval

        while self._running:
            try:
                if self._cnproc_active and self._event_wake is not None:
                    try:
                        await asyncio.wait_for(
                            self._event_wake.wait(),
                            timeout=idle_interval,
                        )
                    except asyncio.TimeoutError:
                        # Safety-net rescan -- rare under cn_proc mode.
                        pass
                    self._event_wake.clear()
                    await self._process_pending_events()
                else:
                    # Classic polling: sleep first, then scan.
                    try:
                        await asyncio.sleep(self._poll_interval)
                    except asyncio.CancelledError:
                        break
                    await self._scan_all_processes()
                    self._evict_dead_processes()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in simulation loop")

    async def _process_pending_events(self):
        """Drain PID queues produced by cn_proc callbacks.

        Called from the simulation loop when an event fired.  Scans any
        newly-exec'd PIDs and drops any PIDs that exited, then refreshes
        the PIDs we already track (cheap -- only reads /proc/PID/maps).

        On kernels that support io_uring we batch-read every PID's
        ``/proc/PID/maps`` in one SQ + CQ round-trip (Round 32).  That
        replaces ``N opens + N reads + N closes`` worth of blocking
        syscalls with a single submit + drain -- a ~30-50% CPU saving
        on the memory observer tick for hosts with 100s of tracked
        processes.  Falls back to the per-PID executor path automatically
        when io_uring is disabled.
        """
        exec_pids = self._pending_exec_pids
        exit_pids = self._pending_exit_pids
        self._pending_exec_pids = set()
        self._pending_exit_pids = set()

        # Evict exited PIDs first -- saves doing a wasted scan if an
        # exec + exit arrived in the same wake.
        for pid in exit_pids:
            self._processes.pop(pid, None)

        # Build the PE candidate set from exec events, then union with
        # already-tracked PIDs so we also detect mprotect/mmap drift in
        # known processes.
        candidates: list[int] = []
        for pid in exec_pids:
            if pid in exit_pids:
                continue
            if self._is_pe_candidate(pid):
                candidates.append(pid)
        for pid in self._processes.keys():
            if pid not in exit_pids and pid not in candidates:
                candidates.append(pid)

        if not candidates:
            self._evict_dead_processes()
            return

        if self._use_iouring and not self._iouring_disabled:
            ok = await self._batch_scan_via_iouring(candidates)
            if not ok:
                # Fall back for this cycle (and disable for future).
                for pid in candidates:
                    if not self._running:
                        break
                    await self._scan_process(pid)
        else:
            for pid in candidates:
                if not self._running:
                    break
                await self._scan_process(pid)

        self._evict_dead_processes()
        self._stats["scans_completed"] += 1
        self._stats["last_scan_time"] = time.time()
        self._stats["processes_tracked"] = len(self._processes)

    @staticmethod
    def _is_pe_candidate(pid: int) -> bool:
        """Fast check whether a PID is worth a full maps scan.

        Mirrors the first-pass filter in ``_find_pe_processes`` so we
        don't rescan every single exec() (a shell script could fire 100s
        per second during a build).
        """
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except (OSError, PermissionError):
            return False
        if "peloader" in exe or "pe-loader" in exe:
            return True
        if exe.endswith(".exe") or "pe-compat" in exe:
            return True
        # Fallback: peek at maps for pe-compat markers.  Bounded read
        # so a giant process map doesn't spike CPU.
        try:
            with open(f"/proc/{pid}/maps", "r") as f:
                head = f.read(8192)
            return "pe-compat" in head or "libpe_" in head
        except (OSError, PermissionError):
            return False

    async def _scan_all_processes(self):
        """Discover and scan all PE-related processes.

        Uses io_uring batch reads when enabled (R32): all maps files go
        out in one SQ + CQ cycle instead of N sequential open/read/close.
        """
        loop = asyncio.get_running_loop()
        pe_pids = await loop.run_in_executor(None, _find_pe_processes)

        known_pids = set(self._processes.keys())
        all_pids = set(pe_pids) | known_pids

        # Respect max_processes cap for brand-new PIDs.
        to_scan: list[int] = []
        for pid in all_pids:
            if not self._running:
                break
            if len(self._processes) >= self._max_processes and pid not in self._processes:
                continue
            to_scan.append(pid)

        if not to_scan:
            self._stats["scans_completed"] += 1
            self._stats["last_scan_time"] = time.time()
            self._stats["processes_tracked"] = len(self._processes)
            return

        if self._use_iouring and not self._iouring_disabled:
            ok = await self._batch_scan_via_iouring(to_scan)
            if not ok:
                for pid in to_scan:
                    if not self._running:
                        break
                    await self._scan_process(pid)
        else:
            for pid in to_scan:
                if not self._running:
                    break
                await self._scan_process(pid)

        self._stats["scans_completed"] += 1
        self._stats["last_scan_time"] = time.time()
        self._stats["processes_tracked"] = len(self._processes)

    async def _batch_scan_via_iouring(self, pids: list[int]) -> bool:
        """Batch-read ``/proc/<pid>/maps`` for every PID via io_uring.

        Submits all reads in one ring cycle, then feeds the resulting
        text to the existing parser.  Returns True on success, False if
        io_uring failed in a way that warrants falling back (which
        flips ``_iouring_disabled`` so we don't retry every tick).

        The read buffer is 1 MiB per PID.  Maps files for typical
        processes are <64 KiB; a few huge pathological ones (e.g.
        Firefox with 3k entries) can reach 512 KiB but rarely more.
        Truncated reads just yield a partial maps parse, which still
        detects the DLLs/PE regions we care about.
        """
        if not _IOURING_IMPORT_OK or batch_read_proc_files is None:
            self._iouring_disabled = True
            return False

        loop = asyncio.get_running_loop()
        paths = [f"/proc/{pid}/maps" for pid in pids]
        depth = min(max(len(paths), 8), self._iouring_depth)

        def _do_batch():
            try:
                return batch_read_proc_files(
                    paths,
                    buf_size=1024 * 1024,
                    depth=depth,
                    sqpoll=self._iouring_sqpoll,
                    sq_cpu=self._iouring_sq_cpu,
                )
            except OSError as exc:
                logger.warning(
                    "io_uring batch read failed (%s); disabling for this daemon",
                    exc,
                )
                return None

        results = await loop.run_in_executor(None, _do_batch)
        if results is None:
            self._iouring_disabled = True
            return False

        now = time.time()
        for pid, path in zip(pids, paths):
            if not self._running:
                break
            raw = results.get(path)
            if raw is None:
                # PID raced away / EPERM -- drop any stale tracking.
                self._processes.pop(pid, None)
                continue
            text = raw.decode("utf-8", errors="replace")
            regions = _parse_maps_text(text)
            await self._update_process_from_regions(pid, regions, now)
        return True

    async def _update_process_from_regions(
        self, pid: int, raw_regions: list[dict], now: float,
    ) -> None:
        """Apply pre-parsed maps data to the in-memory process map.

        Mirrors the bookkeeping in :meth:`_scan_process` but takes
        already-parsed region dicts (saves re-opening /proc/PID/maps when
        the caller -- e.g. the io_uring batch path -- has the text
        already).
        """
        loop = asyncio.get_running_loop()

        if pid not in self._processes:
            if len(self._processes) >= self._max_processes:
                stale_pids = [p for p in self._processes
                              if not os.path.exists(f"/proc/{p}")]
                for p in stale_pids:
                    del self._processes[p]
                if len(self._processes) >= self._max_processes:
                    oldest_pid = min(
                        self._processes,
                        key=lambda p: self._processes[p].last_updated,
                    )
                    del self._processes[oldest_pid]

            exe_name = await loop.run_in_executor(None, _get_exe_name, pid)
            self._processes[pid] = ProcessMemoryMap(
                pid=pid,
                subject_id=0,
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
                va_start=r["va_start"], va_end=r["va_end"],
                size=r["size"], prot=r["prot"], tag=r["tag"],
                label=r["label"], dll_name=r["dll_name"],
                load_time=now,
            )
            new_regions[r["va_start"]] = region
            dll_name = r["dll_name"]
            if dll_name:
                if dll_name not in new_dlls:
                    new_dlls[dll_name] = {
                        "base": r["va_start"], "size": 0, "sections": [],
                        "pathname": r.get("pathname", ""),
                    }
                dll_info = new_dlls[dll_name]
                dll_info["size"] += r["size"]
                dll_info["sections"].append({
                    "va_start": r["va_start"], "va_end": r["va_end"],
                    "prot": r["prot"], "tag": r["tag"],
                })

        self._detect_anomalies(pid, old_regions, new_regions, pmap.exe_name)
        # S75 Agent B: fire DLL-load callbacks for names that are new in
        # this rescan. Computed before the dict swap so we diff old->new.
        newly_loaded = [n for n in new_dlls if n not in pmap.dlls_loaded]
        pmap.regions = new_regions
        pmap.dlls_loaded = new_dlls
        pmap.last_updated = now
        pmap.event_count += 1
        for dll_name in newly_loaded:
            self._fire_dll_load(pid, dll_name)

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

        # S75 Agent B: diff old/new dlls_loaded for the callback hook
        # BEFORE we overwrite the map.
        newly_loaded = [n for n in new_dlls if n not in pmap.dlls_loaded]

        # Update the process map
        pmap.regions = new_regions
        pmap.dlls_loaded = new_dlls
        pmap.last_updated = now
        pmap.event_count += 1
        for dll_name in newly_loaded:
            self._fire_dll_load(pid, dll_name)

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
                # S75 Agent B: notify census / sub-observers of the new
                # DLL. The hook is a no-op when no consumer registered.
                self._fire_dll_load(pid, dll_name)

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

        With io_uring enabled (R32) we overlap scan-of-region-N with
        read-of-region-N+1: regions are submitted via the SQ ring in
        pipeline-depth batches, so the CPU can search already-arrived
        buffers while the kernel fetches the next ones.  This typically
        halves wall-clock time on pattern scans of 100+ MB processes.
        """
        if pid not in self._processes:
            return []

        pmap = self._processes[pid]
        matches: list[dict] = []
        mem_path = f"/proc/{pid}/mem"

        try:
            fd = os.open(mem_path, os.O_RDONLY)
        except (OSError, PermissionError):
            return []

        # Enumerate scanable regions once so both paths share logic.
        scanable = [
            (va, region)
            for va, region in sorted(pmap.regions.items())
            if "r" in region.prot and region.size <= 64 * 1024 * 1024
        ]

        try:
            if (
                self._use_iouring
                and not self._iouring_disabled
                and _IOURING_IMPORT_OK
                and IOUring is not None
                and IOUring.available()
                and len(scanable) > 1
            ):
                ok = await self._search_pattern_iouring(
                    fd, scanable, pattern, matches
                )
                if not ok:
                    self._search_pattern_sync(fd, scanable, pattern, matches)
            else:
                self._search_pattern_sync(fd, scanable, pattern, matches)
        finally:
            os.close(fd)

        self._stats["scans_completed"] += 1
        return matches

    @staticmethod
    def _search_pattern_sync(
        fd: int,
        scanable: list,
        pattern: bytes,
        matches: list[dict],
    ) -> None:
        """Synchronous /proc/PID/mem scan -- the portable fallback path."""
        for va, region in scanable:
            try:
                os.lseek(fd, va, os.SEEK_SET)
                data = os.read(fd, region.size)
            except OSError:
                continue
            MemoryObserver._collect_pattern_hits(
                data, va, region, pattern, matches
            )
            if len(matches) >= 1000:
                break

    async def _search_pattern_iouring(
        self,
        fd: int,
        scanable: list,
        pattern: bytes,
        matches: list[dict],
    ) -> bool:
        """Overlap pattern scanning with io_uring-driven region reads.

        Uses a sliding pipeline of submit_read -> scan -> drop to keep
        the kernel busy fetching the next region while Python does the
        substring search on the previous one.  Returns False if
        io_uring hit an error mid-pipeline (caller retries sync).
        """
        loop = asyncio.get_running_loop()

        def _do_scan() -> bool:
            try:
                ring = IOUring(
                    depth=self._iouring_depth,
                    sqpoll=self._iouring_sqpoll,
                    sq_cpu=self._iouring_sq_cpu,
                )
                ring._setup()
            except OSError:
                return False
            try:
                # Pipeline up to ``depth`` reads at a time.
                depth = max(2, min(self._iouring_depth, 16))
                in_flight: dict[int, tuple[int, object, bytearray]] = {}
                idx = 0
                total = len(scanable)
                while idx < total or in_flight:
                    # Fill the pipeline.
                    while idx < total and len(in_flight) < depth:
                        va, region = scanable[idx]
                        buf = bytearray(region.size)
                        ud = ring.submit_read(fd, buf, offset=va)
                        if ud is None:
                            break
                        in_flight[ud] = (va, region, buf)
                        idx += 1
                    if not in_flight:
                        break
                    # Drain as many as have landed (wait for at least 1).
                    completions = ring.drain(min_complete=1)
                    for c in completions:
                        meta = in_flight.pop(c.user_data, None)
                        if meta is None:
                            continue
                        va, region, buf = meta
                        if not c.ok:
                            continue
                        data = bytes(buf[:c.res]) if c.res != len(buf) else bytes(buf)
                        MemoryObserver._collect_pattern_hits(
                            data, va, region, pattern, matches
                        )
                        if len(matches) >= 1000:
                            return True
                return True
            except OSError:
                return False
            finally:
                ring.close()

        try:
            return await loop.run_in_executor(None, _do_scan)
        except Exception:
            logger.exception("io_uring pattern scan failed")
            self._iouring_disabled = True
            return False

    @staticmethod
    def _collect_pattern_hits(
        data: bytes,
        va: int,
        region,
        pattern: bytes,
        matches: list[dict],
    ) -> None:
        """Scan ``data`` for ``pattern`` and append hits to ``matches``."""
        offset = 0
        while True:
            i = data.find(pattern, offset)
            if i == -1:
                break
            match_va = va + i
            matches.append({
                "va": f"0x{match_va:x}",
                "va_int": match_va,
                "region_label": region.label,
                "region_tag": region.tag,
                "offset_in_region": i,
            })
            offset = i + 1
            if len(matches) >= 1000:
                break

    # ── Introspection ──

    def get_stats(self) -> dict:
        """Return observer statistics."""
        stats = {
            **self._stats,
            "mode": self._mode,
            "processes_tracked": len(self._processes),
            "anomalies_total": len(self._anomalies),
            "running": self._running,
            "cnproc_active": self._cnproc_active,
            "iouring_enabled": bool(self._use_iouring and not self._iouring_disabled),
            "iouring_sqpoll": bool(self._iouring_sqpoll),
        }
        if self._cnproc is not None:
            stats["cnproc_events"] = self._cnproc.event_count
        return stats


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
