"""
Real-time connection monitor.

Runs a background thread that polls ``/proc/net/tcp``, ``/proc/net/tcp6``,
and ``/proc/net/udp`` for active network connections.  Tracks new and
closed connections and fires callbacks when changes are detected.
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

    def __init__(self, poll_interval: float = 2.0) -> None:
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
        """
        with self._lock:
            return [c.to_dict() for c in self._active.values()]

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
            }

    # ------------------------------------------------------------------
    # Background poll loop
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        """Main loop for the background thread."""
        logger.debug("Poll loop starting")
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception:
                logger.exception("Error during connection poll")
            self._stop_event.wait(timeout=self._poll_interval)
        logger.debug("Poll loop exiting")

    def _poll_once(self) -> None:
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

    def _read_current_connections(self) -> dict[ConnectionKey, ConnectionInfo]:
        """Read all connections from /proc/net/* and map to processes."""
        inode_map = self._build_inode_map()
        connections: dict[ConnectionKey, ConnectionInfo] = {}

        for proto, path in [
            ("tcp", "/proc/net/tcp"),
            ("tcp6", "/proc/net/tcp6"),
            ("udp", "/proc/net/udp"),
            ("udp6", "/proc/net/udp6"),
        ]:
            for conn in self._parse_proc_net(proto, path, inode_map):
                connections[conn.key] = conn

        return connections

    def _parse_proc_net(
        self,
        protocol: str,
        path: str,
        inode_map: dict[int, tuple[int, str, str]],
    ) -> list[ConnectionInfo]:
        """Parse a /proc/net/* file and resolve process info."""
        results: list[ConnectionInfo] = []
        try:
            with open(path, "r") as fh:
                lines = fh.readlines()
        except (FileNotFoundError, PermissionError):
            return results

        is_v6 = "6" in protocol
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            try:
                parts = line.split()
                local_hex = parts[1]
                remote_hex = parts[2]
                state_hex = parts[3]
                inode = int(parts[9])

                local_addr, local_port = self._decode_address(local_hex, is_v6)
                remote_addr, remote_port = self._decode_address(remote_hex, is_v6)

                if protocol.startswith("tcp"):
                    state = _TCP_STATE_MAP.get(state_hex, ConnState.CLOSED).value
                else:
                    state = (
                        ConnState.UNCONN.value
                        if state_hex == "07"
                        else ConnState.ESTABLISHED.value
                    )

                pid, proc_name, exe_path = inode_map.get(inode, (0, "", ""))

                conn = ConnectionInfo(
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
                )
                results.append(conn)
            except (IndexError, ValueError):
                continue

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

    @staticmethod
    def _build_inode_map() -> dict[int, tuple[int, str, str]]:
        """Map socket inodes to (pid, name, exe) via /proc/[pid]/fd/."""
        inode_map: dict[int, tuple[int, str, str]] = {}

        try:
            entries = os.listdir("/proc")
        except (FileNotFoundError, PermissionError):
            return inode_map

        for entry in entries:
            if not entry.isdigit():
                continue
            pid = int(entry)
            fd_dir = f"/proc/{pid}/fd"

            try:
                with open(f"/proc/{pid}/comm", "r") as f:
                    name = f.read().strip()
            except (FileNotFoundError, PermissionError):
                name = ""

            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except (FileNotFoundError, PermissionError, OSError):
                exe = ""

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
                    inode_map[int(match.group(1))] = (pid, name, exe)

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
