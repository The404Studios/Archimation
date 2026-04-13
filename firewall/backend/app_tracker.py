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
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

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

    def __init__(self) -> None:
        # app_path -> AppHistory
        self._history: dict[str, AppHistory] = defaultdict(
            lambda: AppHistory(app_path="")
        )
        # Set of app paths that are explicitly allowed
        self._allowed_apps: set[str] = set()
        # Set of app paths that are explicitly blocked
        self._blocked_apps: set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_connections(self) -> list[AppConnection]:
        """Return all current network connections with process info.

        Reads ``/proc/net/tcp``, ``/proc/net/tcp6``, ``/proc/net/udp``,
        ``/proc/net/udp6`` and maps each socket to its owning process.
        """
        sockets = self._read_all_sockets()
        inode_map = self._build_inode_map()
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
        logger.info("App allowed: %s", app_path)

    def block_app(self, app_path: str) -> None:
        """Explicitly block an application."""
        self._blocked_apps.add(app_path)
        self._allowed_apps.discard(app_path)
        logger.info("App blocked: %s", app_path)

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
        """Parse a ``/proc/net/tcp``-style file."""
        sockets: list[SocketInfo] = []
        try:
            with open(path, "r") as fh:
                lines = fh.readlines()
        except (FileNotFoundError, PermissionError) as exc:
            logger.debug("Cannot read %s: %s", path, exc)
            return sockets

        # Skip header line
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            try:
                parts = line.split()
                # Columns: sl  local_address  rem_address  st  ...  inode
                local_addr_hex = parts[1]
                remote_addr_hex = parts[2]
                state_hex = parts[3]
                inode = int(parts[9])

                is_v6 = "6" in protocol
                local_addr, local_port = self._decode_address(
                    local_addr_hex, ipv6=is_v6
                )
                remote_addr, remote_port = self._decode_address(
                    remote_addr_hex, ipv6=is_v6
                )

                state = TCP_STATES.get(state_hex, state_hex)
                if protocol.startswith("udp"):
                    state = "UNCONN" if state_hex == "07" else "ESTABLISHED"

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

    def _build_inode_map(self) -> dict[int, tuple[int, str, str]]:
        """Build a mapping of socket inode -> (pid, process_name, exe_path).

        Scans ``/proc/[pid]/fd/`` for symlinks to ``socket:[inode]``.
        """
        inode_map: dict[int, tuple[int, str, str]] = {}

        try:
            pids = [
                entry for entry in os.listdir("/proc")
                if entry.isdigit()
            ]
        except (FileNotFoundError, PermissionError):
            return inode_map

        for pid_str in pids:
            pid = int(pid_str)
            fd_dir = f"/proc/{pid}/fd"

            # Read process name and exe path
            try:
                with open(f"/proc/{pid}/comm", "r") as f:
                    proc_name = f.read().strip()
            except (FileNotFoundError, PermissionError):
                proc_name = ""

            try:
                exe_path = os.readlink(f"/proc/{pid}/exe")
            except (FileNotFoundError, PermissionError, OSError):
                exe_path = ""

            # Scan file descriptors for socket inodes
            try:
                fds = os.listdir(fd_dir)
            except (FileNotFoundError, PermissionError):
                continue

            for fd in fds:
                try:
                    link = os.readlink(os.path.join(fd_dir, fd))
                except (FileNotFoundError, PermissionError, OSError):
                    continue

                match = re.match(r"socket:\[(\d+)\]", link)
                if match:
                    inode = int(match.group(1))
                    inode_map[inode] = (pid, proc_name, exe_path)

        return inode_map

    # ------------------------------------------------------------------
    # History tracking
    # ------------------------------------------------------------------

    def _record_history(self, conn: AppConnection) -> None:
        """Record a connection in the per-application history."""
        if not conn.exe_path:
            return

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
