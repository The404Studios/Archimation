"""
Syscall Monitor -- Live syscall tracing and behavioral analysis for PE processes.

Receives raw syscall events from the kernel Trust Syscall Tracer (TSC)
via netlink, uses the existing SyscallTranslator for Windows API mapping,
and maintains per-process traces, statistics, and behavioral analysis.

In simulation mode (default until TSC is built into the kernel), it
monitors PE processes via /proc/PID/syscall and strace-like parsing.

Complements the static syscall_translator.py with live monitoring,
per-PID ring buffers, behavioral classification, and cortex integration.
"""

import asyncio
import collections
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

# io_uring batch /proc reader -- gated by config, see daemon/config.py.
# Import is safe on non-Linux (module returns available() == False).
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

logger = logging.getLogger("ai-control.syscall_monitor")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Netlink family for TSC events (matches trust kernel module)
NETLINK_TSC = 31

# Syscall categories (match kernel TSC_CAT_* values)
TSC_CAT_FILE = 0x01
TSC_CAT_MEMORY = 0x02
TSC_CAT_PROCESS = 0x04
TSC_CAT_NETWORK = 0x08
TSC_CAT_SIGNAL = 0x10
TSC_CAT_IPC = 0x20
TSC_CAT_ALL = 0x3F

# Maximum entries per trace
MAX_TRACE_ENTRIES = 4096

# Maximum tracked processes
MAX_TRACKED_PROCESSES = 512

# Process TTL: evict tracking data after this many seconds of no events
PROCESS_TTL = 300.0

# Simulation poll interval
SIMULATION_POLL_INTERVAL = 2.0

# TSC netlink event format: seq(u32) subject_id(u32) pid(i32) syscall_nr(u16)
#   category(u8) pad(u8) arg0(u64) arg1(u64) arg2(u64) retval(i64) ts(u64)
TSC_EVENT_FORMAT = "<IIiHBxQQQqQ"
TSC_EVENT_SIZE = struct.calcsize(TSC_EVENT_FORMAT)

# ---------------------------------------------------------------------------
# Translator bridge: delegate to the full syscall_translator module
# ---------------------------------------------------------------------------

_translator_instance = None


def _get_translator():
    """Lazily import and cache the existing SyscallTranslator."""
    global _translator_instance
    if _translator_instance is not None:
        return _translator_instance
    try:
        from syscall_translator import SyscallTranslator as FullTranslator
        _translator_instance = FullTranslator()
        return _translator_instance
    except ImportError:
        logger.warning("syscall_translator module not available; using fallback tables")
        return None


def _translate_syscall(syscall_nr: int, args: Optional[list] = None) -> tuple[str, str]:
    """Translate a Linux syscall number to (WindowsAPI, category) using the full translator."""
    t = _get_translator()
    if t:
        result = t.translate(syscall_nr, args)
        return (result.get("win_api", f"unknown_syscall_{syscall_nr}"),
                result.get("category", "unknown"))
    return (f"unknown_syscall_{syscall_nr}", "unknown")


def _translate_ioctl(ioctl_cmd: int) -> str:
    """Translate an ioctl command to a Windows DeviceIoControl string."""
    t = _get_translator()
    if t:
        result = t.decode_ioctl(ioctl_cmd)
        name = result.get("known_name")
        if name:
            return name
        return result.get("description", f"ioctl_0x{ioctl_cmd:08x}")
    return f"unknown_ioctl_0x{ioctl_cmd:08x}"


# Socket family/type fallback tables (used if full translator is unavailable)
_SOCKET_FAMILY_MAP: dict[int, str] = {
    1:  "AF_UNIX (named pipe equivalent)",
    2:  "AF_INET (Winsock TCP/IPv4)",
    10: "AF_INET6 (Winsock TCP/IPv6)",
    16: "AF_NETLINK (DeviceIoControl equivalent)",
    17: "AF_PACKET (raw socket / WinPcap)",
}

_SOCKET_TYPE_MAP: dict[int, str] = {
    1: "SOCK_STREAM (TCP)",
    2: "SOCK_DGRAM (UDP)",
    3: "SOCK_RAW (raw socket)",
    5: "SOCK_SEQPACKET (reliable datagram)",
}


def _translate_socket(family: int, sock_type: int) -> str:
    """Translate socket family/type to Windows equivalent."""
    fam_str = _SOCKET_FAMILY_MAP.get(family, f"family_{family}")
    typ_str = _SOCKET_TYPE_MAP.get(sock_type & 0xF, f"type_{sock_type}")
    return f"{fam_str} / {typ_str}"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SyscallEvent:
    """A single translated syscall event."""
    timestamp: float
    pid: int
    subject_id: int
    syscall_nr: int
    linux_name: str
    windows_api: str
    category: str
    arg0: int
    arg1: int
    arg2: int
    return_value: int
    details: str = ""  # Human-readable extra info

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "pid": self.pid,
            "subject_id": self.subject_id,
            "syscall_nr": self.syscall_nr,
            "linux_name": self.linux_name,
            "windows_api": self.windows_api,
            "category": self.category,
            "arg0": self.arg0,
            "arg1": self.arg1,
            "arg2": self.arg2,
            "return_value": self.return_value,
            "details": self.details,
        }


_CATEGORY_LOG_CAP = 1024


@dataclass
class ProcessSyscallProfile:
    """Per-process syscall behavioral profile."""
    pid: int
    subject_id: int = 0
    events: collections.deque = field(
        default_factory=lambda: collections.deque(maxlen=MAX_TRACE_ENTRIES))
    stats: dict = field(default_factory=lambda: collections.defaultdict(int))
    ioctl_log: collections.deque = field(
        default_factory=lambda: collections.deque(maxlen=_CATEGORY_LOG_CAP))
    file_access_log: collections.deque = field(
        default_factory=lambda: collections.deque(maxlen=_CATEGORY_LOG_CAP))
    network_log: collections.deque = field(
        default_factory=lambda: collections.deque(maxlen=_CATEGORY_LOG_CAP))
    last_event_time: float = 0.0
    start_time: float = field(default_factory=time.time)

    def add_event(self, event: SyscallEvent) -> None:
        """Add a syscall event to this profile."""
        self.events.append(event)

        self.stats[event.syscall_nr] += 1
        self.last_event_time = event.timestamp

        # Categorize into specialized logs (bounded deques auto-evict)
        if event.syscall_nr == 16:  # ioctl
            self.ioctl_log.append({
                "timestamp": event.timestamp,
                "fd": event.arg0,
                "cmd": event.arg1,
                "cmd_name": _translate_ioctl(event.arg1),
                "arg": event.arg2,
                "return_value": event.return_value,
            })

        elif event.category == "file_io":
            entry = {
                "timestamp": event.timestamp,
                "syscall": event.linux_name,
                "windows_api": event.windows_api,
                "return_value": event.return_value,
            }
            if event.syscall_nr in (2, 257):  # open/openat
                entry["fd_or_path_ptr"] = event.arg1
                entry["flags"] = event.arg2
            else:
                entry["fd"] = event.arg0
                entry["size"] = event.arg2

            self.file_access_log.append(entry)

        elif event.category == "network":
            entry = {
                "timestamp": event.timestamp,
                "syscall": event.linux_name,
                "windows_api": event.windows_api,
                "return_value": event.return_value,
            }
            if event.syscall_nr == 41:  # socket
                entry["family"] = event.arg0
                entry["type"] = event.arg1
                entry["protocol"] = event.arg2
                entry["socket_desc"] = _translate_socket(
                    event.arg0, event.arg1
                )
            elif event.syscall_nr in (42, 49):  # connect/bind
                entry["fd"] = event.arg0
                entry["addr_ptr"] = event.arg1
                entry["addrlen"] = event.arg2
            else:
                entry["fd"] = event.arg0
                entry["size"] = event.arg2

            self.network_log.append(entry)

    def get_behavioral_summary(self) -> dict:
        """Produce a behavioral summary for the cortex decision engine."""
        total_calls = sum(self.stats.values())
        if total_calls == 0:
            return {"classification": "idle", "risk_score": 0}

        ioctl_count = self.stats.get(16, 0)
        network_count = sum(self.stats.get(nr, 0) for nr in (41, 42, 43, 44, 45, 49))
        file_count = sum(self.stats.get(nr, 0) for nr in (0, 1, 2, 3, 257))
        process_count = sum(self.stats.get(nr, 0) for nr in (56, 57, 59, 435))

        # Classify behavior
        classifications = []
        risk_score = 0

        if ioctl_count > total_calls * 0.3:
            classifications.append("driver_heavy")
            risk_score += 20
        if network_count > total_calls * 0.3:
            classifications.append("network_heavy")
            risk_score += 15
        if file_count > total_calls * 0.5:
            classifications.append("file_heavy")
            risk_score += 5
        if process_count > 10:
            classifications.append("process_spawner")
            risk_score += 25

        # Suspicious patterns
        if self.stats.get(59, 0) > 5:  # many execve calls
            classifications.append("suspicious_exec_pattern")
            risk_score += 40
        if ioctl_count > 100:
            classifications.append("high_ioctl_frequency")
            risk_score += 15
        if network_count > 0 and ioctl_count > 50:
            classifications.append("possible_c2_or_drm")
            risk_score += 30

        # Unique ioctl commands (driver fingerprinting)
        unique_ioctls = set()
        for entry in self.ioctl_log:
            unique_ioctls.add(entry["cmd"])

        return {
            "classification": "+".join(classifications) if classifications else "normal",
            "risk_score": min(risk_score, 100),
            "total_syscalls": total_calls,
            "ioctl_count": ioctl_count,
            "network_count": network_count,
            "file_count": file_count,
            "process_count": process_count,
            "unique_ioctl_commands": len(unique_ioctls),
            "duration_seconds": time.time() - self.start_time,
        }


# ---------------------------------------------------------------------------
# Linux syscall name table (x86_64)
# ---------------------------------------------------------------------------

SYSCALL_NAMES: dict[int, str] = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat",
    5: "fstat", 6: "lstat", 7: "lseek", 8: "mmap", 9: "mmap",
    10: "mprotect", 11: "munmap", 12: "brk", 16: "ioctl",
    20: "writev", 32: "dup", 33: "dup2", 41: "socket", 42: "connect",
    43: "accept", 44: "sendto", 45: "recvfrom", 46: "sendmsg",
    47: "recvmsg", 49: "bind", 50: "listen", 51: "getsockname",
    52: "getpeername", 53: "socketpair", 54: "setsockopt",
    55: "getsockopt", 56: "clone", 57: "fork", 59: "execve",
    60: "exit", 61: "wait4", 62: "kill", 72: "fcntl",
    78: "gettimeofday", 87: "unlink", 88: "rename", 89: "mkdir",
    90: "rmdir", 96: "gettimeofday", 102: "getuid",
    228: "clock_gettime", 257: "openat", 262: "newfstatat",
    263: "unlinkat", 268: "fchmodat", 288: "accept4", 293: "pipe2",
    302: "prlimit64", 318: "getrandom", 435: "clone3",
}


# ---------------------------------------------------------------------------
# Syscall Monitor
# ---------------------------------------------------------------------------

class SyscallMonitor:
    """
    Monitors syscalls from PE processes and translates them into
    Windows API semantics.

    Operates in two modes:
      - Kernel mode: receives events via netlink from trust_syscall.c
      - Simulation mode: polls /proc/PID/syscall for tracked processes
    """

    def __init__(self, poll_interval: float = SIMULATION_POLL_INTERVAL,
                 process_ttl: float = PROCESS_TTL,
                 max_processes: int = MAX_TRACKED_PROCESSES,
                 use_iouring: bool = False,
                 iouring_sqpoll: bool = False,
                 iouring_sq_cpu: Optional[int] = None,
                 iouring_depth: int = 32):
        self._profiles: dict[int, ProcessSyscallProfile] = {}
        self._poll_interval = poll_interval
        self._process_ttl = process_ttl
        self._max_processes = max_processes
        self._mode = "simulation"  # or "kernel"
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._nl_sock: Optional[socket.socket] = None
        # Translation delegated to module-level functions wrapping syscall_translator
        # io_uring feature flag (R32).  Gated by config.py so old-HW
        # boxes stay on /proc text reads.  _iouring_disabled flips to
        # True if a call fails at runtime, preventing log spam.
        self._use_iouring = bool(use_iouring and _IOURING_IMPORT_OK)
        self._iouring_sqpoll = bool(iouring_sqpoll)
        self._iouring_sq_cpu = iouring_sq_cpu
        self._iouring_depth = max(8, int(iouring_depth))
        self._iouring_disabled: bool = False

    # --- Lifecycle ---

    async def start(self) -> None:
        """Start the syscall monitor."""
        if self._running:
            return

        self._running = True

        # Try kernel netlink mode first
        if self._try_kernel_mode():
            self._mode = "kernel"
            self._task = asyncio.get_event_loop().create_task(
                self._kernel_event_loop()
            )
            logger.info("Syscall monitor started in kernel mode (netlink)")
        else:
            self._mode = "simulation"
            self._task = asyncio.get_event_loop().create_task(
                self._simulation_loop()
            )
            logger.info("Syscall monitor started in simulation mode")

    async def stop(self) -> None:
        """Stop the syscall monitor."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._nl_sock:
            self._nl_sock.close()
            self._nl_sock = None
        logger.info("Syscall monitor stopped")

    def _try_kernel_mode(self) -> bool:
        """Try to open a netlink socket to the TSC kernel module."""
        sock = None
        try:
            sock = socket.socket(
                socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_TSC
            )
            sock.bind((os.getpid(), 1))  # group 1
            sock.setblocking(False)
            self._nl_sock = sock
            return True
        except (OSError, PermissionError) as e:
            # Close the socket if bind/setblocking failed so we don't leak
            # an FD on every retry over the daemon's uptime.
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            logger.debug("Kernel netlink unavailable: %s (falling back to simulation)", e)
            return False

    # --- Kernel mode event loop ---

    async def _kernel_event_loop(self) -> None:
        """Read syscall events from kernel via netlink."""
        loop = asyncio.get_event_loop()
        last_evict = time.monotonic()
        evict_interval = max(self._poll_interval, 5.0)

        while self._running:
            try:
                data = await loop.sock_recv(self._nl_sock, 65536)
                if not data:
                    await asyncio.sleep(0.01)
                    continue
                self._parse_netlink_events(data)
            except BlockingIOError:
                await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Netlink receive error: %s", e)
                await asyncio.sleep(1.0)

            # Throttled cleanup (avoid O(N) walk on every packet)
            now = time.monotonic()
            if now - last_evict >= evict_interval:
                self._evict_stale_processes()
                last_evict = now

    def _parse_netlink_events(self, data: bytes) -> None:
        """Parse raw netlink messages containing TSC events."""
        offset = 0
        while offset + 16 <= len(data):  # nlmsghdr is 16 bytes
            # Parse nlmsghdr
            nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = \
                struct.unpack_from("<IHHII", data, offset)

            if nlmsg_len < 16:
                break

            # Payload starts after nlmsghdr
            payload_offset = offset + 16
            payload_end = offset + nlmsg_len

            if payload_end > len(data):
                break

            # Parse TSC event from payload
            if payload_end - payload_offset >= TSC_EVENT_SIZE:
                self._process_kernel_event(data[payload_offset:payload_offset + TSC_EVENT_SIZE])

            # Align to 4-byte boundary
            offset = (payload_end + 3) & ~3

    def _process_kernel_event(self, raw: bytes) -> None:
        """Process a single TSC event from the kernel."""
        seq, subject_id, pid, syscall_nr, category, arg0, arg1, arg2, retval, ts = \
            struct.unpack(TSC_EVENT_FORMAT, raw)

        linux_name = SYSCALL_NAMES.get(syscall_nr, f"syscall_{syscall_nr}")
        win_api, win_cat = _translate_syscall(syscall_nr)

        event = SyscallEvent(
            timestamp=ts / 1e9,  # ns -> seconds
            pid=pid,
            subject_id=subject_id,
            syscall_nr=syscall_nr,
            linux_name=linux_name,
            windows_api=win_api,
            category=win_cat,
            arg0=arg0,
            arg1=arg1,
            arg2=arg2,
            return_value=retval,
        )

        # Add extra details for specific syscalls
        if syscall_nr == 16:  # ioctl
            event.details = f"DeviceIoControl cmd={_translate_ioctl(arg1)}"
        elif syscall_nr == 41:  # socket
            event.details = _translate_socket(arg0, arg1)
        elif syscall_nr == 56 or syscall_nr == 435:  # clone/clone3
            event.details = f"flags=0x{arg0:x}"

        # Record in profile
        profile = self._get_or_create_profile(pid, subject_id)
        profile.add_event(event)

    # --- Simulation mode event loop ---

    async def _simulation_loop(self) -> None:
        """Poll /proc for PE process syscall info in simulation mode."""
        while self._running:
            try:
                await self._poll_pe_processes()
                self._evict_stale_processes()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Simulation poll error: %s", e)

            await asyncio.sleep(self._poll_interval)

    async def _poll_pe_processes(self) -> None:
        """Find PE processes and poll their current syscall state.

        With io_uring enabled (R32) we:

        1. Walk /proc once to collect PE-PID candidates (cheap dirent).
        2. Submit one batch ``read()`` per PID's ``/proc/<pid>/syscall``
           via io_uring.  N PIDs -> 1 submit + 1 drain, instead of N
           blocking syscalls on the main thread.

        On old HW / kernels <5.1 we fall through to the classic
        per-PID loop.  The PE-detection step (``_is_pe_process``) still
        does one readlink + small /proc read per candidate; optimising
        that is Round 33 territory (needs an io_uring OPENAT, 5.6+).
        """
        loop = asyncio.get_event_loop()
        try:
            pids = await loop.run_in_executor(
                None,
                lambda: [int(d) for d in os.listdir("/proc") if d.isdigit()],
            )
        except OSError:
            return

        # Filter to PE-loader processes + already-tracked ones.
        pe_pids = [pid for pid in pids if self._is_pe_process(pid)]
        if not pe_pids:
            return

        # Fast path: batch-read /proc/<pid>/syscall via io_uring.
        use_uring = (
            self._use_iouring
            and not self._iouring_disabled
            and batch_read_proc_files is not None
        )
        if use_uring:
            syscall_paths = [f"/proc/{pid}/syscall" for pid in pe_pids]
            depth = min(max(len(pe_pids), 8), self._iouring_depth)

            def _do_batch():
                try:
                    return batch_read_proc_files(
                        syscall_paths,
                        buf_size=512,      # /proc/PID/syscall is ~80 bytes
                        depth=depth,
                        sqpoll=self._iouring_sqpoll,
                        sq_cpu=self._iouring_sq_cpu,
                    )
                except OSError as exc:
                    logger.warning(
                        "syscall_monitor: io_uring batch failed (%s); "
                        "disabling for this daemon", exc,
                    )
                    return None

            batch = await loop.run_in_executor(None, _do_batch)
            if batch is None:
                self._iouring_disabled = True
                # Degrade to per-PID sync reads below.
            else:
                for pid, path in zip(pe_pids, syscall_paths):
                    raw = batch.get(path)
                    if raw is None:
                        continue
                    try:
                        line = raw.decode("ascii", errors="replace").strip()
                    except Exception:
                        continue
                    self._record_syscall_line(pid, line)
                return

        # Classic fallback path.
        for pid in pe_pids:
            try:
                with open(f"/proc/{pid}/syscall", "r") as f:
                    line = f.read().strip()
            except (OSError, PermissionError):
                continue
            self._record_syscall_line(pid, line)

    def _record_syscall_line(self, pid: int, line: str) -> None:
        """Parse one ``/proc/<pid>/syscall`` line and log the event.

        Split out of :meth:`_poll_pe_processes` so both the io_uring
        batch path and the fallback sync path share the bookkeeping.
        """
        if line == "running" or line == "-1":
            return

        parts = line.split()
        if len(parts) < 7:
            return

        try:
            syscall_nr = int(parts[0])
            arg0 = int(parts[1], 16) if len(parts) > 1 else 0
            arg1 = int(parts[2], 16) if len(parts) > 2 else 0
            arg2 = int(parts[3], 16) if len(parts) > 3 else 0
        except (ValueError, IndexError):
            return

        linux_name = SYSCALL_NAMES.get(syscall_nr, f"syscall_{syscall_nr}")
        win_api, win_cat = _translate_syscall(syscall_nr)

        event = SyscallEvent(
            timestamp=time.time(),
            pid=pid,
            subject_id=0,
            syscall_nr=syscall_nr,
            linux_name=linux_name,
            windows_api=win_api,
            category=win_cat,
            arg0=arg0,
            arg1=arg1,
            arg2=arg2,
            return_value=0,
        )

        if syscall_nr == 16:
            event.details = f"DeviceIoControl cmd={_translate_ioctl(arg1)}"
        elif syscall_nr == 41:
            event.details = _translate_socket(arg0, arg1)

        profile = self._get_or_create_profile(pid, 0)
        profile.add_event(event)

    def _is_pe_process(self, pid: int) -> bool:
        """Check if a PID is a PE process (running under pe-loader)."""
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
            if "pe-loader" in exe or "pe_loader" in exe:
                return True
            # Check cmdline for .exe
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().decode("utf-8", errors="replace")
            if ".exe" in cmdline.lower():
                return True
        except (OSError, PermissionError):
            pass

        # Check if already tracked
        return pid in self._profiles

    # --- Profile management ---

    def _get_or_create_profile(self, pid: int, subject_id: int) -> ProcessSyscallProfile:
        """Get or create a profile for a PID.

        Uses dict-insertion-order as an LRU proxy for O(1) eviction
        (previously min() scanned every profile — O(n) per create, which
        matters under syscall-heavy workloads where new PIDs appear often).
        """
        if pid not in self._profiles:
            if len(self._profiles) >= self._max_processes:
                try:
                    oldest_pid = next(iter(self._profiles))
                    del self._profiles[oldest_pid]
                except StopIteration:
                    pass

            self._profiles[pid] = ProcessSyscallProfile(
                pid=pid,
                subject_id=subject_id,
            )

        profile = self._profiles[pid]
        if subject_id and not profile.subject_id:
            profile.subject_id = subject_id
        return profile

    def _evict_stale_processes(self) -> None:
        """Remove profiles for processes that haven't had events recently.

        Uses start_time as a fallback when last_event_time is still 0 so that
        profiles created via start_tracking() but which never receive events
        don't accumulate forever for dead PIDs.
        """
        now = time.time()
        stale = []
        for pid, profile in self._profiles.items():
            ref_time = profile.last_event_time or profile.start_time
            if now - ref_time > self._process_ttl:
                stale.append(pid)
            elif not os.path.exists(f"/proc/{pid}"):
                stale.append(pid)
        for pid in stale:
            del self._profiles[pid]

    # --- Public query API ---

    async def get_trace(self, pid: int, limit: int = 100) -> Optional[list[dict]]:
        """Get the syscall trace for a PID."""
        profile = self._profiles.get(pid)
        if profile is None:
            return None
        # deque doesn't support slice; get last `limit` via list+islice
        total = len(profile.events)
        if limit >= total:
            return [ev.to_dict() for ev in profile.events]
        import itertools
        events = itertools.islice(profile.events, total - limit, total)
        return [ev.to_dict() for ev in events]

    async def get_stats(self, pid: int) -> Optional[dict]:
        """Get syscall frequency statistics for a PID."""
        profile = self._profiles.get(pid)
        if profile is None:
            return None

        # Convert numeric keys to named entries
        stats = {}
        for nr, count in sorted(profile.stats.items(), key=lambda x: -x[1]):
            linux_name = SYSCALL_NAMES.get(nr, f"syscall_{nr}")
            win_api, win_cat = _translate_syscall(nr)
            stats[linux_name] = {
                "count": count,
                "syscall_nr": nr,
                "windows_api": win_api,
                "category": win_cat,
            }
        return {
            "pid": pid,
            "subject_id": profile.subject_id,
            "total_syscalls": sum(profile.stats.values()),
            "unique_syscalls": len(profile.stats),
            "tracking_duration": time.time() - profile.start_time,
            "syscalls": stats,
        }

    async def get_ioctl_analysis(self, pid: int) -> Optional[list[dict]]:
        """Get ioctl analysis for a PID -- what drivers is it talking to?"""
        profile = self._profiles.get(pid)
        if profile is None:
            return None
        return list(profile.ioctl_log)

    async def get_file_access(self, pid: int) -> Optional[list[dict]]:
        """Get file access log for a PID."""
        profile = self._profiles.get(pid)
        if profile is None:
            return None
        return list(profile.file_access_log)

    async def get_network_activity(self, pid: int) -> Optional[list[dict]]:
        """Get network activity log for a PID."""
        profile = self._profiles.get(pid)
        if profile is None:
            return None
        return list(profile.network_log)

    async def get_behavioral_summary(self, pid: int) -> Optional[dict]:
        """Get behavioral classification for the cortex decision engine."""
        profile = self._profiles.get(pid)
        if profile is None:
            return None
        return profile.get_behavioral_summary()

    async def get_all_tracked(self) -> list[dict]:
        """Get summary of all tracked processes."""
        result = []
        for pid, profile in self._profiles.items():
            summary = profile.get_behavioral_summary()
            result.append({
                "pid": pid,
                "subject_id": profile.subject_id,
                "total_syscalls": sum(profile.stats.values()),
                "classification": summary["classification"],
                "risk_score": summary["risk_score"],
                "tracking_since": profile.start_time,
                "last_event": profile.last_event_time,
            })
        return result

    def get_global_stats(self) -> dict:
        """Get global monitor statistics."""
        total_events = sum(
            sum(p.stats.values()) for p in self._profiles.values()
        )
        return {
            "mode": self._mode,
            "tracked_processes": len(self._profiles),
            "total_events": total_events,
            "max_processes": self._max_processes,
            "poll_interval": self._poll_interval,
            "iouring_enabled": bool(
                self._use_iouring and not self._iouring_disabled
            ),
            "iouring_sqpoll": bool(self._iouring_sqpoll),
        }

    # --- Manual tracking ---

    async def start_tracking(self, pid: int, subject_id: int = 0) -> bool:
        """Manually start tracking a PID."""
        if pid in self._profiles:
            return False  # Already tracked
        self._get_or_create_profile(pid, subject_id)
        return True

    async def stop_tracking(self, pid: int) -> bool:
        """Manually stop tracking a PID."""
        if pid not in self._profiles:
            return False
        del self._profiles[pid]
        return True
