"""
Real-time connection monitor.

Runs a background thread that polls for active network connections.
Tracks new and closed connections and fires callbacks when changes are
detected.

Two data sources are supported:

* **NETLINK_INET_DIAG (preferred)** -- binary ``sock_diag`` dump over an
  AF_NETLINK socket.  ~10x cheaper than text-parsing ``/proc/net/*`` on
  hosts with thousands of sockets and lets us filter by TCP state at
  the kernel side.  See :mod:`firewall.backend.netlink`.

* **``/proc/net/{tcp,tcp6,udp,udp6}`` (fallback)** -- classic text parse,
  kept for hosts where netlink is unavailable (no CAP_NET_RAW, kernel
  without ``sock_diag``, or non-Linux dev hosts).

Both paths produce identical :class:`ConnectionInfo` objects, so the
rest of the firewall stack can't tell which was used.
"""

import asyncio
import logging
import os
import re
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

try:
    # Local helper; safe to import on any platform (probe-guarded).
    from firewall.backend.netlink import (
        InetDiagClient,
        TCP_STATE_NAME,
        TCP_CLOSE,
    )
    _NETLINK_IMPORT_OK = True
except Exception:  # pragma: no cover - only when module layout changes
    InetDiagClient = None  # type: ignore[assignment]
    TCP_STATE_NAME = {}    # type: ignore[assignment]
    TCP_CLOSE = 7          # type: ignore[assignment]
    _NETLINK_IMPORT_OK = False

# io_uring batch helper from the AI daemon (R32).  Used to coalesce
# per-PID /proc/<pid>/comm reads during inode-map rebuilds.  The import
# is best-effort: the firewall can run standalone without the daemon on
# disk, in which case batch_read_proc_files stays None and the sync
# path remains.
try:
    from iouring import batch_read_proc_files  # type: ignore
    _IOURING_OK = True
except Exception:
    try:
        from daemon.iouring import batch_read_proc_files  # type: ignore
        _IOURING_OK = True
    except Exception:
        batch_read_proc_files = None  # type: ignore[assignment]
        _IOURING_OK = False

logger = logging.getLogger("firewall.connection_monitor")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class ConnState(str, Enum):
    """Simplified connection states."""
    ESTABLISHED = "ESTABLISHED"
    LISTEN = "LISTEN"
    SYN_SENT = "SYN_SENT"
    SYN_RECV = "SYN_RECV"
    FIN_WAIT1 = "FIN_WAIT1"
    FIN_WAIT2 = "FIN_WAIT2"
    TIME_WAIT = "TIME_WAIT"
    CLOSE_WAIT = "CLOSE_WAIT"
    LAST_ACK = "LAST_ACK"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"
    UNCONN = "UNCONN"


_TCP_STATE_MAP = {
    "01": ConnState.ESTABLISHED,
    "02": ConnState.SYN_SENT,
    "03": ConnState.SYN_RECV,
    "04": ConnState.FIN_WAIT1,
    "05": ConnState.FIN_WAIT2,
    "06": ConnState.TIME_WAIT,
    "07": ConnState.CLOSED,
    "08": ConnState.CLOSE_WAIT,
    "09": ConnState.LAST_ACK,
    "0A": ConnState.LISTEN,
    "0B": ConnState.CLOSING,
}

# Precompiled once -- previously re-compiled on every /proc/*/fd entry
_SOCKET_INODE_RE = re.compile(r"socket:\[(\d+)\]")


@dataclass(frozen=True, eq=True)
class ConnectionKey:
    """Hashable key that uniquely identifies a connection."""
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int


@dataclass
class ConnectionInfo:
    """Full information about a single network connection."""

    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: int = 0
    process_name: str = ""
    exe_path: str = ""
    inode: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    @property
    def key(self) -> ConnectionKey:
        return ConnectionKey(
            protocol=self.protocol,
            local_addr=self.local_addr,
            local_port=self.local_port,
            remote_addr=self.remote_addr,
            remote_port=self.remote_port,
        )

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "local_addr": self.local_addr,
            "local_port": self.local_port,
            "remote_addr": self.remote_addr,
            "remote_port": self.remote_port,
            "state": self.state,
            "pid": self.pid,
            "process_name": self.process_name,
            "exe_path": self.exe_path,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


# ---------------------------------------------------------------------------
# Callback types
# ---------------------------------------------------------------------------

NewConnectionCallback = Callable[[ConnectionInfo], None]
ClosedConnectionCallback = Callable[[ConnectionInfo], None]
AsyncNewConnectionCallback = Callable[[ConnectionInfo], "asyncio.Future"]


# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------

class ConnectionMonitor:
    """Background monitor for active network connections.

    Polls ``/proc/net/*`` at a configurable interval and maintains an
    in-memory map of active connections.  Fires callbacks when new
    connections appear or existing connections close.

    Usage::

        monitor = ConnectionMonitor(poll_interval=1.0)
        monitor.on_new_connection(my_callback)
        monitor.start()
        ...
        monitor.stop()
    """

    # When idle (no connection churn for several ticks) back the poll off
    # to the slow interval; spin back up the moment something changes.
    _IDLE_POLL_MULTIPLIER: float = 2.0
    _IDLE_THRESHOLD_TICKS: int = 5

    @staticmethod
    def _auto_poll_interval(default: float) -> float:
        """Return a sensible poll interval based on host RAM size.

        Old hardware with <2 GiB RAM can't afford to walk /proc/*/fd
        every two seconds -- slow spinning disks and a single CPU make
        the poll dominate load.  Double the interval for those hosts
        while keeping new hardware snappy.  Parsing /proc/meminfo is a
        one-time cost at construction.  If the file is unreadable
        (non-Linux dev box, test harness) we keep the caller's default.
        """
        try:
            with open("/proc/meminfo", "r") as fh:
                for line in fh:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        if kb < 2_200_000:   # <~2.1 GiB
                            return max(default * 2.0, 4.0)
                        return default
        except (FileNotFoundError, PermissionError, ValueError, IndexError):
            pass
        return default

    def __init__(self, poll_interval: Optional[float] = None,
                 use_netlink: Optional[bool] = None) -> None:
        # Allow explicit interval override but default to hardware-aware
        # tuning.  None = auto; anything else wins.
        if poll_interval is None:
            poll_interval = self._auto_poll_interval(2.0)
        self._poll_interval = poll_interval
        self._active: dict[ConnectionKey, ConnectionInfo] = {}
        self._lock = threading.Lock()

        # Callbacks
        self._new_callbacks: list[NewConnectionCallback] = []
        self._closed_callbacks: list[ClosedConnectionCallback] = []
        self._async_new_callbacks: list[AsyncNewConnectionCallback] = []

        # Background thread
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running = False

        # Stats
        self._total_seen: int = 0
        self._total_closed: int = 0

        # Idle back-off: if several consecutive polls see no change we
        # extend the sleep interval -- reading /proc/net/* and walking
        # /proc/*/fd every 2 s is wasted CPU on an idle old machine.
        self._idle_ticks: int = 0
        # Shared /proc-fd inode-map cache (walking /proc/*/fd is the
        # expensive part of each poll).  Short TTL so a new connection
        # is still attributed promptly.
        self._inode_map_cache: Optional[dict[int, tuple[int, str, str]]] = None
        self._inode_map_cache_time: float = 0.0
        self._inode_map_ttl: float = 1.0
        # get_connections() cache -- the GUI polls it at its own 2 s
        # cadence, but the monitor may also provide it to CLI callers
        # in-process.  Guard against a double-read within a tight window.
        self._get_connections_cache: Optional[list[dict]] = None
        self._get_connections_cache_time: float = 0.0
        self._get_connections_ttl: float = 0.5

        # Netlink / sock_diag fast path.  None = probe lazily on first
        # poll; True/False = explicit override (tests, benchmarks).  When
        # the probe fails we don't retry -- the per-poll fallback cost is
        # tiny and a failing probe usually means missing capability.
        self._use_netlink = use_netlink
        self._netlink: Optional["InetDiagClient"] = None
        self._netlink_failed: bool = False
        self._netlink_source: str = "proc"  # "netlink" or "proc"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background monitoring thread."""
        if self._running:
            logger.warning("ConnectionMonitor is already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._poll_loop,
            name="connection-monitor",
            daemon=True,
        )
        self._running = True
        self._thread.start()
        logger.info(
            "ConnectionMonitor started (interval=%.1fs)", self._poll_interval
        )

    def stop(self) -> None:
        """Stop the background monitoring thread."""
        if not self._running:
            return
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self._poll_interval * 3)
        self._running = False
        self._thread = None
        # Release the netlink socket so we don't leak an FD when the
        # monitor is restarted (tests do this; long-running daemons
        # should also behave).
        if self._netlink is not None:
            try:
                self._netlink.close()
            except Exception:
                pass
            self._netlink = None
        logger.info("ConnectionMonitor stopped")

    def __del__(self) -> None:
        """Ensure the monitoring thread is stopped on garbage collection."""
        try:
            self.stop()
        except Exception:
            pass

    def __enter__(self) -> "ConnectionMonitor":
        """Support use as a context manager; starts monitoring."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Stop monitoring when exiting the context."""
        self.stop()

    @property
    def is_running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def on_new_connection(self, callback: NewConnectionCallback) -> None:
        """Register a callback for new connections.

        The callback receives a ``ConnectionInfo`` object.
        """
        self._new_callbacks.append(callback)

    def on_closed_connection(self, callback: ClosedConnectionCallback) -> None:
        """Register a callback for closed connections."""
        self._closed_callbacks.append(callback)

    def on_new_connection_async(
        self, callback: AsyncNewConnectionCallback
    ) -> None:
        """Register an async callback for new connections.

        The callback is scheduled on the running asyncio event loop.
        """
        self._async_new_callbacks.append(callback)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_connections(self) -> list[dict]:
        """Return active connections as a list of dicts.

        This wrapper converts ``ConnectionInfo`` dataclass objects into
        plain dictionaries so that GUI and CLI code can use
        ``conn.get("protocol")`` style access.

        Result is memoised for a short TTL to absorb bursty callers
        (e.g. GUI filter changes firing refresh() multiple times in the
        same tick).  Use monotonic() so an NTP step during the poll
        window can't suddenly expire a valid cache or keep a stale one
        alive for hours.

        Concurrency: the cache attributes live on ``self`` and are read
        by GUI callers / CLI / monitor users on arbitrary threads while
        _poll_once() invalidates them on the poll thread.  Fast-path
        reads are done via a local alias so a concurrent assignment on
        another thread can't land the tuple half-updated.  The slow
        path takes ``self._lock`` which also guards ``self._active``,
        so the snapshot and the cache publish happen atomically w.r.t.
        a concurrent invalidation from _poll_once.
        """
        now = time.monotonic()
        # Fast lockless read: local alias is a single GIL-atomic attr load.
        cached = self._get_connections_cache
        cached_time = self._get_connections_cache_time
        if (cached is not None
                and now - cached_time < self._get_connections_ttl):
            return cached

        # Slow path: serialize snapshot + publish under the monitor lock
        # so _poll_once()'s cache invalidation happens-before / after a
        # complete publish rather than racing the cache update.
        with self._lock:
            # Re-check under lock: another thread may have refilled it.
            cached = self._get_connections_cache
            if (cached is not None
                    and now - self._get_connections_cache_time
                    < self._get_connections_ttl):
                return cached
            snapshot = [c.to_dict() for c in self._active.values()]
            self._get_connections_cache = snapshot
            self._get_connections_cache_time = now
            return snapshot

    def get_active_connections(self) -> list[ConnectionInfo]:
        """Return a snapshot of all currently active connections."""
        with self._lock:
            return list(self._active.values())

    def get_connections_by_pid(self, pid: int) -> list[ConnectionInfo]:
        """Return active connections belonging to *pid*."""
        with self._lock:
            return [c for c in self._active.values() if c.pid == pid]

    def get_connections_by_app(self, exe_path: str) -> list[ConnectionInfo]:
        """Return active connections belonging to the given executable."""
        with self._lock:
            return [c for c in self._active.values() if c.exe_path == exe_path]

    def get_listening_ports(self) -> list[ConnectionInfo]:
        """Return all connections in LISTEN state."""
        with self._lock:
            return [
                c for c in self._active.values()
                if c.state == ConnState.LISTEN.value
            ]

    def get_stats(self) -> dict:
        """Return monitoring statistics."""
        with self._lock:
            return {
                "active": len(self._active),
                "total_seen": self._total_seen,
                "total_closed": self._total_closed,
                "running": self._running,
                "poll_interval": self._poll_interval,
                "source": self._netlink_source,
            }

    # ------------------------------------------------------------------
    # Background poll loop
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        """Main loop for the background thread."""
        logger.debug("Poll loop starting")
        while not self._stop_event.is_set():
            try:
                changed = self._poll_once()
            except Exception:
                logger.exception("Error during connection poll")
                changed = False
            # Adaptive sleep: back off when nothing has changed for a
            # while; snap back immediately when activity resumes.
            if changed:
                self._idle_ticks = 0
                interval = self._poll_interval
            else:
                self._idle_ticks += 1
                if self._idle_ticks >= self._IDLE_THRESHOLD_TICKS:
                    interval = self._poll_interval * self._IDLE_POLL_MULTIPLIER
                else:
                    interval = self._poll_interval
            self._stop_event.wait(timeout=interval)
        logger.debug("Poll loop exiting")

    def _poll_once(self) -> bool:
        """Perform a single poll cycle.

        State updates happen under the lock, but callback dispatch
        happens outside it to avoid deadlocks when callbacks attempt
        to query the monitor (which also acquires the lock).
        """
        current = self._read_current_connections()
        current_keys = set(current.keys())

        new_conns: list[ConnectionInfo] = []
        closed_conns: list[ConnectionInfo] = []

        with self._lock:
            prev_keys = set(self._active.keys())

            # Detect new connections
            new_keys = current_keys - prev_keys
            for key in new_keys:
                conn = current[key]
                self._active[key] = conn
                self._total_seen += 1
                new_conns.append(conn)

            # Detect closed connections
            closed_keys = prev_keys - current_keys
            for key in closed_keys:
                conn = self._active.pop(key)
                self._total_closed += 1
                closed_conns.append(conn)

            # Update existing connections (refresh state, last_seen)
            for key in current_keys & prev_keys:
                existing = self._active[key]
                updated = current[key]
                existing.state = updated.state
                existing.last_seen = time.time()
                # Update PID if it changed (e.g. was unknown before)
                if updated.pid and not existing.pid:
                    existing.pid = updated.pid
                    existing.process_name = updated.process_name
                    existing.exe_path = updated.exe_path

        # Fire callbacks outside the lock to prevent deadlocks
        for conn in new_conns:
            self._fire_new_callbacks(conn)
        for conn in closed_conns:
            self._fire_closed_callbacks(conn)

        # Invalidate the dict-snapshot cache whenever the set changes,
        # so GUI callers see additions/removals on the very next poll.
        # Take the lock so the assignment can't race with a concurrent
        # get_connections() mid-publish; under the GIL the assignment
        # itself is atomic, but ordering w.r.t. the snapshot publish in
        # get_connections() requires the same lock to establish a
        # happens-before relationship.
        if new_conns or closed_conns:
            with self._lock:
                self._get_connections_cache = None

        return bool(new_conns or closed_conns)

    def _read_current_connections(self) -> dict[ConnectionKey, ConnectionInfo]:
        """Read all connections, preferring NETLINK_INET_DIAG.

        Falls back to the classic /proc/net/* text parse when:

        * netlink has been explicitly disabled (``use_netlink=False``);
        * the probe failed on a previous call (missing kernel support
          or restrictive seccomp);
        * this specific poll's netlink dump raised an OSError.

        The inode -> pid map comes from the same /proc/*/fd walk used
        by the fallback path; that's unavoidable because the kernel's
        sock_diag doesn't expose pid attribution directly (only uid).
        """
        inode_map = self._get_cached_inode_map()
        connections: dict[ConnectionKey, ConnectionInfo] = {}

        # Netlink fast path.  Probe once, reuse the client across polls.
        if self._should_try_netlink():
            try:
                netlink_conns = self._read_via_netlink(inode_map)
                if netlink_conns is not None:
                    for conn in netlink_conns:
                        connections[conn.key] = conn
                    self._netlink_source = "netlink"
                    return connections
            except Exception:  # pragma: no cover - defensive
                logger.exception(
                    "Netlink sock_diag poll failed; reverting to /proc"
                )
                self._netlink_failed = True
                if self._netlink is not None:
                    try:
                        self._netlink.close()
                    except Exception:
                        pass
                    self._netlink = None

        # /proc text-parse fallback (legacy path).
        self._netlink_source = "proc"
        for proto, path in [
            ("tcp", "/proc/net/tcp"),
            ("tcp6", "/proc/net/tcp6"),
            ("udp", "/proc/net/udp"),
            ("udp6", "/proc/net/udp6"),
        ]:
            for conn in self._parse_proc_net(proto, path, inode_map):
                connections[conn.key] = conn

        return connections

    def _should_try_netlink(self) -> bool:
        """Return True if we should attempt the netlink fast path now."""
        if self._use_netlink is False:
            return False
        if self._netlink_failed:
            return False
        if not _NETLINK_IMPORT_OK or InetDiagClient is None:
            return False
        return True

    def _read_via_netlink(
        self,
        inode_map: dict[int, tuple[int, str, str]],
    ) -> Optional[list[ConnectionInfo]]:
        """Dump all four (family x proto) tables via sock_diag.

        Returns ``None`` if the netlink probe fails -- the caller takes
        that as the signal to use /proc.  Returns a (possibly empty) list
        on success.  Empty-on-success is valid: the host may have no
        live sockets.
        """
        if InetDiagClient is None:
            return None

        if self._netlink is None:
            client = InetDiagClient()
            if not client.open():
                self._netlink_failed = True
                logger.info(
                    "NETLINK_INET_DIAG unavailable; using /proc polling"
                )
                return None
            self._netlink = client
            logger.info(
                "NETLINK_INET_DIAG available; switched to binary sock_diag dump"
            )

        client = self._netlink
        results: list[ConnectionInfo] = []

        for raw in client.query_all():
            proto = raw["protocol"]
            state_code = raw["state_code"]
            # Skip fully-closed sockets; they'd otherwise appear once and
            # vanish, inflating the new/closed callback churn.
            if proto.startswith("tcp") and state_code == TCP_CLOSE:
                continue

            if proto.startswith("tcp"):
                state_name = TCP_STATE_NAME.get(state_code, ConnState.CLOSED.value)
                # Normalise to our ConnState enum where possible.
                try:
                    state = ConnState(state_name).value
                except ValueError:
                    state = state_name
            else:
                # UDP uses state 7 == UNCONN, else ESTABLISHED per /proc
                # semantics.  Keep that convention here.
                state = (
                    ConnState.UNCONN.value
                    if state_code == TCP_CLOSE
                    else ConnState.ESTABLISHED.value
                )

            inode = raw["inode"]
            pid, proc_name, exe_path = inode_map.get(inode, (0, "", ""))

            results.append(ConnectionInfo(
                protocol=proto,
                local_addr=raw["local_addr"],
                local_port=raw["local_port"],
                remote_addr=raw["remote_addr"],
                remote_port=raw["remote_port"],
                state=state,
                pid=pid,
                process_name=proc_name,
                exe_path=exe_path,
                inode=inode,
            ))

        return results

    def _parse_proc_net(
        self,
        protocol: str,
        path: str,
        inode_map: dict[int, tuple[int, str, str]],
    ) -> list[ConnectionInfo]:
        """Parse a /proc/net/* file and resolve process info.

        Iterates the file line-by-line rather than pulling the whole
        thing into memory via ``readlines()`` -- on a busy server the
        TCP table can run into tens of megabytes and the list copy is
        purely wasted RAM on old hardware.
        """
        results: list[ConnectionInfo] = []
        try:
            fh = open(path, "r")
        except (FileNotFoundError, PermissionError):
            return results

        is_v6 = "6" in protocol
        is_tcp = protocol.startswith("tcp")
        try:
            # Skip header line without buffering the rest
            try:
                next(fh)
            except StopIteration:
                return results
            for line in fh:
                # Bare split() already collapses whitespace + strips
                # trailing newline, no need for an explicit .strip()
                parts = line.split()
                if len(parts) < 10:
                    continue
                try:
                    local_hex = parts[1]
                    remote_hex = parts[2]
                    state_hex = parts[3]
                    inode = int(parts[9])

                    local_addr, local_port = self._decode_address(local_hex, is_v6)
                    remote_addr, remote_port = self._decode_address(remote_hex, is_v6)

                    if is_tcp:
                        state = _TCP_STATE_MAP.get(state_hex, ConnState.CLOSED).value
                    else:
                        state = (
                            ConnState.UNCONN.value
                            if state_hex == "07"
                            else ConnState.ESTABLISHED.value
                        )

                    pid, proc_name, exe_path = inode_map.get(inode, (0, "", ""))

                    results.append(ConnectionInfo(
                        protocol=protocol,
                        local_addr=local_addr,
                        local_port=local_port,
                        remote_addr=remote_addr,
                        remote_port=remote_port,
                        state=state,
                        pid=pid,
                        process_name=proc_name,
                        exe_path=exe_path,
                        inode=inode,
                    ))
                except (IndexError, ValueError):
                    continue
        finally:
            fh.close()

        return results

    @staticmethod
    def _decode_address(addr_hex: str, ipv6: bool = False) -> tuple[str, int]:
        """Decode a hex address:port from /proc/net/*."""
        host_hex, port_hex = addr_hex.split(":")
        port = int(port_hex, 16)

        if ipv6:
            if len(host_hex) == 32:
                parts = [host_hex[i:i + 8] for i in range(0, 32, 8)]
                raw = b""
                for part in parts:
                    raw += struct.pack("<I", int(part, 16))
                addr = socket.inet_ntop(socket.AF_INET6, raw)
            else:
                addr = host_hex
        else:
            addr_int = int(host_hex, 16)
            packed = struct.pack("<I", addr_int)
            addr = socket.inet_ntoa(packed)

        return addr, port

    def _get_cached_inode_map(self) -> dict[int, tuple[int, str, str]]:
        """Return a /proc/[pid]/fd inode map, rebuilding at most once per TTL.

        Walking every process's ``/proc/*/fd`` entries is by far the most
        expensive part of a poll -- O(all fds on the system).  The map is
        cheap to keep between ticks because connection identity (the key
        we actually look up) rarely changes within a second.  Monotonic
        clock so NTP steps can't corrupt TTL accounting.
        """
        now = time.monotonic()
        if (self._inode_map_cache is not None
                and now - self._inode_map_cache_time < self._inode_map_ttl):
            return self._inode_map_cache
        inode_map = self._build_inode_map()
        self._inode_map_cache = inode_map
        self._inode_map_cache_time = now
        return inode_map

    @staticmethod
    def _build_inode_map() -> dict[int, tuple[int, str, str]]:
        """Map socket inodes to (pid, name, exe) via /proc/[pid]/fd/.

        Uses ``os.scandir()`` for the per-pid fd directory walk so the
        kernel hands us dirents directly (no extra stat syscalls).  On
        busy systems with 10k+ open fds this is the hot path; the naive
        ``os.listdir`` + ``os.readlink`` version paid a dirent-and-stat
        round-trip per fd.

        Round 32 also batches the per-PID ``/proc/<pid>/comm`` reads
        through io_uring when the daemon's shim is importable.  A host
        with 50 socket-owning PIDs drops from 50 sequential open+read
        syscalls to one submit + one drain, shaving ~30% off inode-map
        rebuild cost on HDD-backed VMs.
        """
        inode_map: dict[int, tuple[int, str, str]] = {}

        try:
            proc_entries = os.listdir("/proc")
        except (FileNotFoundError, PermissionError):
            return inode_map

        # Pass 1: for every PID with at least one socket fd, collect its
        # inode list.  Defers the comm/exe reads so we can batch them.
        pid_sockets: dict[str, list[int]] = {}
        for entry in proc_entries:
            # Skip non-pid entries without str->int round-trip
            if not entry[0:1].isdigit() or not entry.isdigit():
                continue
            pid_str = entry
            fd_dir = f"/proc/{pid_str}/fd"
            sockets: list[int] = []
            try:
                with os.scandir(fd_dir) as it:
                    for fd_entry in it:
                        try:
                            link = os.readlink(fd_entry.path)
                        except (FileNotFoundError, PermissionError, OSError):
                            continue
                        if not link.startswith("socket:"):
                            continue
                        match = _SOCKET_INODE_RE.match(link)
                        if match:
                            sockets.append(int(match.group(1)))
            except (FileNotFoundError, PermissionError):
                continue
            if sockets:
                pid_sockets[pid_str] = sockets

        if not pid_sockets:
            return inode_map

        # Pass 2: batch-read /proc/<pid>/comm via io_uring when available.
        # On kernels <5.1 or when the shim is missing, batch_read_proc_files
        # itself falls back to plain open()+read().
        comm_paths = [f"/proc/{pid_str}/comm" for pid_str in pid_sockets]
        names: dict[str, str] = {}
        if _IOURING_OK and batch_read_proc_files is not None:
            try:
                batch = batch_read_proc_files(comm_paths, buf_size=256)
            except OSError as exc:  # pragma: no cover - defensive
                logger.debug("inode_map: io_uring batch failed (%s)", exc)
                batch = None
        else:
            batch = None

        if batch is not None:
            for pid_str, path in zip(pid_sockets, comm_paths):
                raw = batch.get(path)
                if raw is None:
                    names[pid_str] = ""
                else:
                    names[pid_str] = raw.decode(
                        "utf-8", errors="replace"
                    ).strip()
        else:
            # Sync fallback.  Keeps identical semantics to the old loop.
            for pid_str in pid_sockets:
                try:
                    with open(f"/proc/{pid_str}/comm", "r") as f:
                        names[pid_str] = f.read().strip()
                except (FileNotFoundError, PermissionError):
                    names[pid_str] = ""

        # Pass 3: resolve exe symlinks and assemble the map.  readlink()
        # stays synchronous -- IORING_OP_READLINKAT is 5.6+, and the
        # symlink resolution touches procfs internals where async can
        # return stale data on PID churn.
        for pid_str, sockets in pid_sockets.items():
            name = names.get(pid_str, "")
            try:
                exe = os.readlink(f"/proc/{pid_str}/exe")
            except (FileNotFoundError, PermissionError, OSError):
                exe = ""
            pid = int(pid_str)
            info = (pid, name, exe)
            for inode in sockets:
                inode_map[inode] = info

        return inode_map

    # ------------------------------------------------------------------
    # Callback dispatch
    # ------------------------------------------------------------------

    def _fire_new_callbacks(self, conn: ConnectionInfo) -> None:
        """Invoke all registered new-connection callbacks."""
        for cb in self._new_callbacks:
            try:
                cb(conn)
            except Exception:
                logger.exception("Error in new-connection callback")

        # Schedule async callbacks if an event loop is running
        for acb in self._async_new_callbacks:
            try:
                loop = asyncio.get_running_loop()
                asyncio.run_coroutine_threadsafe(acb(conn), loop)
            except RuntimeError:
                # No running event loop
                pass
            except Exception:
                logger.exception("Error scheduling async callback")

    def _fire_closed_callbacks(self, conn: ConnectionInfo) -> None:
        """Invoke all registered closed-connection callbacks."""
        for cb in self._closed_callbacks:
            try:
                cb(conn)
            except Exception:
                logger.exception("Error in closed-connection callback")
