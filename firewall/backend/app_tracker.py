"""
Per-application network tracking.

Monitors which applications make network connections by reading
``/proc/net/tcp``, ``/proc/net/tcp6``, and mapping socket inodes to
processes via ``/proc/[pid]/fd/``.  This is the Linux equivalent of
the Windows Firewall's per-application allow/block feature.
"""

import logging
import os
import re
import struct
import socket
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    # Local import avoided at module top-level so import failures don't
    # block app_tracker use on systems without cgroup v2 support.
    from . import cgroup_manager as _cgroup_manager  # type: ignore
except ImportError:  # pragma: no cover - fallback for non-package loading
    try:
        import cgroup_manager as _cgroup_manager  # type: ignore
    except ImportError:
        _cgroup_manager = None  # type: ignore

logger = logging.getLogger("firewall.app_tracker")

# ---------------------------------------------------------------------------
# TCP states (from include/net/tcp_states.h)
# ---------------------------------------------------------------------------

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

# Precompiled -- was re-compiled on every /proc/*/fd entry (thousands of times
# per refresh on busy systems).
_SOCKET_INODE_RE = re.compile(r"socket:\[(\d+)\]")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SocketInfo:
    """Parsed entry from /proc/net/tcp or /proc/net/tcp6."""

    protocol: str           # "tcp", "tcp6", "udp", "udp6"
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    inode: int


@dataclass
class AppConnection:
    """A network connection mapped to its owning process."""

    pid: int
    process_name: str
    exe_path: str
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class AppHistory:
    """Connection history for a single application."""

    app_path: str
    total_connections: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    connections: list[AppConnection] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------

class AppTracker:
    """Tracks which applications are making network connections.

    Reads the Linux ``/proc`` filesystem to correlate socket inodes
    with process file descriptors, providing Windows-style per-app
    network visibility.
    """

    # Maximum number of historical connections to keep per app
    MAX_HISTORY_PER_APP = 500
    # Maximum number of distinct applications to track
    MAX_TRACKED_APPS = 2000
    # inode_map TTL -- walking /proc/*/fd is expensive; callers that refresh
    # rapidly (GUI 2s timer + connection_monitor 2s poll) share the result.
    _INODE_MAP_TTL: float = 1.0

    def __init__(self) -> None:
        # app_path -> AppHistory
        self._history: dict[str, AppHistory] = defaultdict(
            lambda: AppHistory(app_path="")
        )
        # Set of app paths that are explicitly allowed
        self._allowed_apps: set[str] = set()
        # Set of app paths that are explicitly blocked
        self._blocked_apps: set[str] = set()
        # Cached inode -> (pid, name, exe) map
        self._inode_map_cache: Optional[dict[int, tuple[int, str, str]]] = None
        self._inode_map_cache_time: float = 0.0
        # Memoise (pid, app_name) pairs we've already cgrouped so we
        # don't hammer cgroup.procs on every 2-second refresh.  The
        # cgroup membership is sticky for the lifetime of the process
        # unless something external moves it, so one successful move
        # per (pid,app) is enough.
        self._cgrouped_pids: set[tuple[int, str]] = set()
        # Set of app path prefixes we want to auto-scope.  The firewall
        # frontend populates this via register_rule_target() when a
        # per-app rule is added.  Empty set == no scoping attempted.
        self._rule_target_apps: set[str] = set()
        # Lock serializing mutations to the shared caches and tracking
        # sets above.  GUI threads (2s refresh) and ConnectionMonitor's
        # poll thread (2s poll) both call get_connections() → which
        # walks _history and _cgrouped_pids.  Under GIL each individual
        # dict/set op is atomic, but compound patterns like "check then
        # evict then insert" in _record_history() and _maybe_scope_pid()
        # are not: without a lock, two racing callers can double-evict
        # or double-add (burning cgroup.procs writes).  threading.Lock
        # because the critical sections are short; RLock not needed
        # since no method here calls another locked method recursively.
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_connections(self) -> list[AppConnection]:
        """Return all current network connections with process info.

        Reads ``/proc/net/tcp``, ``/proc/net/tcp6``, ``/proc/net/udp``,
        ``/proc/net/udp6`` and maps each socket to its owning process.
        """
        sockets = self._read_all_sockets()
        inode_map = self._get_inode_map()
        connections: list[AppConnection] = []

        for sock in sockets:
            pid_info = inode_map.get(sock.inode)
            if pid_info is None:
                continue
            pid, name, exe = pid_info
            conn = AppConnection(
                pid=pid,
                process_name=name,
                exe_path=exe,
                protocol=sock.protocol,
                local_addr=sock.local_addr,
                local_port=sock.local_port,
                remote_addr=sock.remote_addr,
                remote_port=sock.remote_port,
                state=sock.state,
            )
            connections.append(conn)
            self._record_history(conn)
            # If this PID belongs to an app we have rules for, ensure
            # it lives in the correct cgroup so nft `socket cgroupv2`
            # predicates actually match.  Cheap no-op after first call
            # per (pid, app_name) thanks to _cgrouped_pids memoisation.
            self._maybe_scope_pid(pid, exe)

        return connections

    def get_app_connections(self, app_path: str) -> list[AppConnection]:
        """Return current connections belonging to *app_path*."""
        return [c for c in self.get_connections() if c.exe_path == app_path]

    def get_app_history(self, app_path: str) -> Optional[AppHistory]:
        """Return the accumulated connection history for *app_path*."""
        hist = self._history.get(app_path)
        if hist and hist.total_connections > 0:
            return hist
        return None

    def get_all_tracked_apps(self) -> list[str]:
        """Return a list of all application paths that have been seen."""
        return [
            path for path, hist in self._history.items()
            if hist.total_connections > 0
        ]

    def is_app_allowed(self, app_path: str) -> Optional[bool]:
        """Check whether an application is allowed to make connections.

        Returns:
            True  - explicitly allowed
            False - explicitly blocked
            None  - no explicit rule (use default policy)
        """
        if app_path in self._allowed_apps:
            return True
        if app_path in self._blocked_apps:
            return False
        return None

    def allow_app(self, app_path: str) -> None:
        """Explicitly allow an application."""
        self._allowed_apps.add(app_path)
        self._blocked_apps.discard(app_path)
        self.register_rule_target(app_path)
        logger.info("App allowed: %s", app_path)

    def block_app(self, app_path: str) -> None:
        """Explicitly block an application."""
        self._blocked_apps.add(app_path)
        self._allowed_apps.discard(app_path)
        self.register_rule_target(app_path)
        logger.info("App blocked: %s", app_path)

    def register_rule_target(self, app_path: str) -> None:
        """Tell the tracker that a firewall rule targets *app_path*.

        When a tracked connection's exe matches, the owning PID is moved
        into ``pe-compat.slice/<appname>.scope`` so the nft
        ``socket cgroupv2`` predicate will match.  Idempotent.
        """
        if not app_path:
            return
        # Lock: the set-comprehension rebuild of _cgrouped_pids below is
        # a read-then-write sequence that a concurrent _maybe_scope_pid()
        # on another thread could interleave with, losing the just-added
        # entry or (worse) overwriting it with a stale snapshot.
        with self._lock:
            self._rule_target_apps.add(app_path)
            # Invalidate memoisation for this app so any already-running
            # processes get re-checked on the next enumeration pass.
            prefix = None
            if _cgroup_manager is not None:
                prefix = _cgroup_manager.app_name_from_path(app_path)
            if prefix is not None:
                self._cgrouped_pids = {
                    (pid, app) for pid, app in self._cgrouped_pids if app != prefix
                }

    def unregister_rule_target(self, app_path: str) -> None:
        """Stop auto-scoping *app_path*'s processes.  Idempotent."""
        self._rule_target_apps.discard(app_path)

    def on_rule_changed(self, app_path: str, added: bool) -> None:
        """Callback suitable for :meth:`NftManager.add_app_rule_listener`.

        Wires the nft rule lifecycle to the tracker's scoping set: when
        the firewall starts matching on a new ``rule.application``, we
        begin auto-scoping that app's PIDs; when the last rule for an
        app is removed, we stop.  Multiple rules per app are OK -- the
        tracker's set is idempotent, and we only drop the target on the
        dedicated ``added=False`` path from load_rules() which already
        computes set differences.
        """
        if not app_path:
            return
        if added:
            self.register_rule_target(app_path)
        else:
            self.unregister_rule_target(app_path)

    def attach_to_nft_manager(self, nft_manager) -> None:
        """Register this tracker's :meth:`on_rule_changed` with *nft_manager*.

        Convenience wrapper so the firewall orchestrator (daemon or GUI)
        can hook tracker → nft in a single line without importing the
        listener callable directly.  Also eagerly syncs the tracker's
        target set with any rules already present in the NftManager so
        a reload-after-attach path still works.
        """
        if nft_manager is None:
            return
        add_listener = getattr(nft_manager, "add_app_rule_listener", None)
        if callable(add_listener):
            add_listener(self.on_rule_changed)
        # Prime the target set with existing rules.  Guard against the
        # list_rules API changing shape; we only need .application here.
        try:
            rules = nft_manager.list_rules(enabled_only=False)
        except Exception:  # pragma: no cover - defensive
            rules = []
        for r in rules:
            app = getattr(r, "application", None)
            if app:
                self.register_rule_target(app)

    def _maybe_scope_pid(self, pid: int, exe_path: str) -> None:
        """Place *pid* in its app's cgroup scope if a rule targets it.

        Silent no-op when:
          * cgroup_manager module missing
          * exe_path empty or not in registered targets
          * cgroup v2 unavailable / daemon not root
          * we already moved this (pid, app) pair in this run
        """
        if _cgroup_manager is None:
            return
        if not exe_path or not self._rule_target_apps:
            return

        # Match exe by exact path OR by basename.  Rules may store
        # either "firefox" or "/usr/bin/firefox"; normalise.
        matched_target: Optional[str] = None
        exe_basename = os.path.basename(exe_path)
        for target in self._rule_target_apps:
            if target == exe_path or os.path.basename(target) == exe_basename:
                matched_target = target
                break
        if matched_target is None:
            return

        app_name = _cgroup_manager.app_name_from_path(matched_target)
        if app_name is None:
            return

        key = (pid, app_name)
        # Lock so the "check+add" to the memoisation set is atomic.
        # Two threads racing without the lock can both observe the key
        # missing and both schedule a cgroup move (a wasted write into
        # cgroup.procs that can also log a noisy warning for each).
        with self._lock:
            if key in self._cgrouped_pids:
                return
            # Mark as attempted BEFORE the call so a persistent failure
            # (e.g. kernel thread, permission denied) doesn't spam logs
            # on every poll cycle.
            self._cgrouped_pids.add(key)

        if _cgroup_manager.ensure_app_scoped(pid, app_name):
            logger.debug(
                "Scoped pid %d (%s) -> pe-compat.slice/%s.scope",
                pid, exe_path, app_name,
            )

    def clear_app_rule(self, app_path: str) -> None:
        """Remove explicit allow/block for an application."""
        self._allowed_apps.discard(app_path)
        self._blocked_apps.discard(app_path)

    def get_allowed_apps(self) -> set[str]:
        """Return the set of explicitly allowed application paths."""
        return set(self._allowed_apps)

    def get_blocked_apps(self) -> set[str]:
        """Return the set of explicitly blocked application paths."""
        return set(self._blocked_apps)

    # ------------------------------------------------------------------
    # /proc/net readers
    # ------------------------------------------------------------------

    def _read_all_sockets(self) -> list[SocketInfo]:
        """Read all IPv4 and IPv6 TCP/UDP sockets from /proc/net."""
        sockets: list[SocketInfo] = []
        for proto, path in [
            ("tcp",  "/proc/net/tcp"),
            ("tcp6", "/proc/net/tcp6"),
            ("udp",  "/proc/net/udp"),
            ("udp6", "/proc/net/udp6"),
        ]:
            sockets.extend(self._parse_proc_net(proto, path))
        return sockets

    def _parse_proc_net(self, protocol: str, path: str) -> list[SocketInfo]:
        """Parse a ``/proc/net/tcp``-style file.

        Streams the file line-by-line rather than loading it entirely
        with ``readlines()`` -- the TCP table can be large on busy
        systems, and the transient list doubled memory use for no gain.
        """
        sockets: list[SocketInfo] = []
        try:
            fh = open(path, "r")
        except (FileNotFoundError, PermissionError) as exc:
            logger.debug("Cannot read %s: %s", path, exc)
            return sockets

        is_v6 = "6" in protocol
        is_udp = protocol.startswith("udp")
        try:
            # Skip header line
            try:
                next(fh)
            except StopIteration:
                return sockets
            for line in fh:
                parts = line.split()
                if len(parts) < 10:
                    continue
                try:
                    local_addr_hex = parts[1]
                    remote_addr_hex = parts[2]
                    state_hex = parts[3]
                    inode = int(parts[9])

                    local_addr, local_port = self._decode_address(
                        local_addr_hex, ipv6=is_v6
                    )
                    remote_addr, remote_port = self._decode_address(
                        remote_addr_hex, ipv6=is_v6
                    )

                    if is_udp:
                        state = "UNCONN" if state_hex == "07" else "ESTABLISHED"
                    else:
                        state = TCP_STATES.get(state_hex, state_hex)

                    sockets.append(SocketInfo(
                        protocol=protocol,
                        local_addr=local_addr,
                        local_port=local_port,
                        remote_addr=remote_addr,
                        remote_port=remote_port,
                        state=state,
                        inode=inode,
                    ))
                except (IndexError, ValueError) as exc:
                    logger.debug("Skipping malformed line in %s: %s", path, exc)
                    continue
        finally:
            fh.close()

        return sockets

    @staticmethod
    def _decode_address(addr_hex: str, ipv6: bool = False) -> tuple[str, int]:
        """Decode a hex-encoded address:port from /proc/net/*.

        Returns ``(ip_string, port)`` tuple.
        """
        host_hex, port_hex = addr_hex.split(":")
        port = int(port_hex, 16)

        if ipv6:
            # IPv6 addresses are 32 hex chars (16 bytes) in network order
            if len(host_hex) == 32:
                # Stored as four 32-bit words in host byte order
                parts = [host_hex[i:i+8] for i in range(0, 32, 8)]
                bytes_addr = b""
                for part in parts:
                    bytes_addr += struct.pack("<I", int(part, 16))
                addr = socket.inet_ntop(socket.AF_INET6, bytes_addr)
            else:
                addr = host_hex
        else:
            # IPv4 in little-endian hex
            addr_int = int(host_hex, 16)
            packed = struct.pack("<I", addr_int)
            addr = socket.inet_ntoa(packed)

        return addr, port

    # ------------------------------------------------------------------
    # inode -> process mapper
    # ------------------------------------------------------------------

    def _get_inode_map(self) -> dict[int, tuple[int, str, str]]:
        """Return the inode map, rebuilding at most once per _INODE_MAP_TTL.

        Monotonic clock so the cache can't be invalidated early (or held
        forever) by a wall-clock adjustment while the firewall is running
        -- common on laptops coming out of suspend.
        """
        now = time.monotonic()
        # Fast lockless check: attribute reads are GIL-atomic.  If the
        # cache is fresh, return it without paying for the lock; this
        # is the 99% case across bursty callers on an idle system.
        cached = self._inode_map_cache
        if (cached is not None
                and now - self._inode_map_cache_time < self._INODE_MAP_TTL):
            return cached
        # Slow path: serialize the /proc walk so two concurrent callers
        # don't each spend ~50-200 ms walking /proc/*/fd simultaneously.
        with self._lock:
            cached = self._inode_map_cache
            if (cached is not None
                    and now - self._inode_map_cache_time < self._INODE_MAP_TTL):
                return cached
            self._inode_map_cache = self._build_inode_map()
            self._inode_map_cache_time = now
            return self._inode_map_cache

    def _build_inode_map(self) -> dict[int, tuple[int, str, str]]:
        """Build a mapping of socket inode -> (pid, process_name, exe_path).

        Scans ``/proc/[pid]/fd/`` for symlinks to ``socket:[inode]``.
        Optimised variant: collect sockets first with
        :func:`os.scandir`, then only open ``comm``/``exe`` for PIDs
        that actually hold a socket fd.  Most PIDs (kernel workers,
        long-lived session daemons) never do, which saves two opens
        per uninteresting PID -- on a typical laptop with ~500 PIDs
        this halves the per-poll syscall count.
        """
        inode_map: dict[int, tuple[int, str, str]] = {}

        try:
            proc_entries = os.listdir("/proc")
        except (FileNotFoundError, PermissionError):
            return inode_map

        for pid_str in proc_entries:
            if not pid_str[0:1].isdigit() or not pid_str.isdigit():
                continue
            fd_dir = f"/proc/{pid_str}/fd"

            sockets: list[int] = []
            try:
                with os.scandir(fd_dir) as it:
                    for fd_entry in it:
                        try:
                            link = os.readlink(fd_entry.path)
                        except (FileNotFoundError, PermissionError, OSError):
                            continue
                        # Cheap prefix filter before regex.
                        if not link.startswith("socket:"):
                            continue
                        match = _SOCKET_INODE_RE.match(link)
                        if match:
                            sockets.append(int(match.group(1)))
            except (FileNotFoundError, PermissionError):
                continue

            if not sockets:
                continue

            try:
                with open(f"/proc/{pid_str}/comm", "r") as f:
                    proc_name = f.read().strip()
            except (FileNotFoundError, PermissionError):
                proc_name = ""
            try:
                exe_path = os.readlink(f"/proc/{pid_str}/exe")
            except (FileNotFoundError, PermissionError, OSError):
                exe_path = ""

            pid = int(pid_str)
            info = (pid, proc_name, exe_path)
            for inode in sockets:
                inode_map[inode] = info

        return inode_map

    # ------------------------------------------------------------------
    # History tracking
    # ------------------------------------------------------------------

    def _record_history(self, conn: AppConnection) -> None:
        """Record a connection in the per-application history.

        Runs under ``self._lock`` because the check-then-evict-then-insert
        sequence below is not GIL-atomic: two threads racing this method
        could both observe ``len(_history) >= MAX_TRACKED_APPS``, both
        call _evict_stale_apps(), and then both insert, leaving the map
        over-full by one entry.  Likewise, the AppHistory inner list
        mutations (``hist.connections = hist.connections[drop:]`` + the
        subsequent ``.append``) are compound ops that need serialization.
        """
        if not conn.exe_path:
            return

        with self._lock:
            # Evict stale apps if we're at the limit and this is a new app
            if (conn.exe_path not in self._history
                    and len(self._history) >= self.MAX_TRACKED_APPS):
                self._evict_stale_apps()

            hist = self._history[conn.exe_path]
            if hist.app_path == "":
                hist.app_path = conn.exe_path

            now = time.time()
            if hist.first_seen == 0.0:
                hist.first_seen = now
            hist.last_seen = now
            hist.total_connections += 1

            # Keep bounded history
            if len(hist.connections) >= self.MAX_HISTORY_PER_APP:
                # Drop the oldest quarter
                drop = self.MAX_HISTORY_PER_APP // 4
                hist.connections = hist.connections[drop:]

            hist.connections.append(conn)

    def _evict_stale_apps(self) -> None:
        """Evict the oldest quarter of tracked apps when at capacity."""
        if len(self._history) < self.MAX_TRACKED_APPS:
            return
        # Sort by last_seen, evict the oldest quarter
        evict_count = max(1, self.MAX_TRACKED_APPS // 4)
        by_age = sorted(self._history.items(), key=lambda kv: kv[1].last_seen)
        for key, _ in by_age[:evict_count]:
            del self._history[key]
        logger.info(
            "Evicted %d stale app entries, %d remaining",
            evict_count, len(self._history),
        )
