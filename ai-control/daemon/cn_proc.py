"""
PROC_EVENT / cn_proc netlink subscriber -- event-driven process tracking.

The kernel ``connector`` driver publishes process lifecycle events
(fork/exec/exit/uid/coredump) to AF_NETLINK NETLINK_CONNECTOR multicast
group CN_IDX_PROC.  Subscribing to it replaces the usual "walk /proc
every N seconds" polling with a push-model feed: we only do work when
something actually happens.

This is the single biggest idle-CPU win on the memory observer.  A box
with 400 processes but zero fork/exec traffic drops from O(400) per
poll to O(0) until something changes.

Requires CAP_NET_ADMIN to bind to the multicast group.  If that fails
we return a sentinel and the caller can stay on its /proc polling path.

Pure stdlib: ``socket`` + ``struct`` + ``os``.  Safe to import on
Windows (probe returns False, nothing binds).
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os
import socket
import struct
import sys
from dataclasses import dataclass
from enum import IntEnum
from typing import Awaitable, Callable, Optional

logger = logging.getLogger("ai-control.cn_proc")

# ---------------------------------------------------------------------------
# Netlink / connector constants (see linux/connector.h, linux/cn_proc.h).
# ---------------------------------------------------------------------------

NETLINK_CONNECTOR = 11
CN_IDX_PROC = 1
CN_VAL_PROC = 1

NLMSG_DONE = 3
NLMSG_ERROR = 2

NLM_F_REQUEST = 0x01

# PROC_CN_MCAST_OP values
PROC_CN_MCAST_LISTEN = 1
PROC_CN_MCAST_IGNORE = 2


class ProcEvent(IntEnum):
    """proc_event ``what`` values from linux/cn_proc.h."""
    NONE = 0
    FORK = 0x00000001
    EXEC = 0x00000002
    UID = 0x00000004
    GID = 0x00000040
    SID = 0x00000080
    PTRACE = 0x00000100
    COMM = 0x00000200
    COREDUMP = 0x40000000
    EXIT = 0x80000000


# Struct layouts
#
# struct nlmsghdr {
#     __u32 len; __u16 type; __u16 flags; __u32 seq; __u32 pid;
# };  -- 16 bytes
_NLMSGHDR = struct.Struct("=IHHII")
NLMSGHDR_LEN = _NLMSGHDR.size

# struct cn_msg {
#     struct cb_id { __u32 idx; __u32 val; } id;
#     __u32 seq;
#     __u32 ack;
#     __u16 len;
#     __u16 flags;
#     __u8 data[0];
# };
# 4 + 4 + 4 + 4 + 2 + 2 = 20 bytes header
_CN_MSG = struct.Struct("=IIIIHH")
CN_MSG_LEN = _CN_MSG.size

# struct proc_event {
#     __u32 what;
#     __u32 cpu;
#     __u64 timestamp_ns;
#     union { ... } event_data;
# };
# Header = 4 + 4 + 8 = 16, union is variable (biggest is 40 for exit).
_PROC_EVENT_HEAD = struct.Struct("=IIQ")
PROC_EVENT_HEAD_LEN = _PROC_EVENT_HEAD.size

# Event payloads we actually care about.
# struct { __kernel_pid_t parent_pid; parent_tgid; child_pid; child_tgid; };
#   -- four __u32 on Linux -> 16 bytes
_EV_FORK = struct.Struct("=IIII")
# struct { __kernel_pid_t process_pid; process_tgid; };
_EV_EXEC = struct.Struct("=II")
# struct { pid; tgid; exit_code; exit_signal; parent_pid; parent_tgid; };
_EV_EXIT = struct.Struct("=IIIIII")
# struct { pid; tgid; r/e uid; r/e gid; ... } -- we only read pid/tgid
_EV_IDS = struct.Struct("=II")


# ---------------------------------------------------------------------------
# Event dataclass
# ---------------------------------------------------------------------------

@dataclass
class CnProcEvent:
    """Decoded cn_proc event."""
    what: int               # ProcEvent
    cpu: int
    timestamp_ns: int
    pid: int                # Process-group leader (tgid) for user-space
    tgid: int
    # Event-specific
    parent_pid: int = 0
    parent_tgid: int = 0
    exit_code: int = 0

    @property
    def kind(self) -> str:
        """String form of the event type."""
        try:
            return ProcEvent(self.what).name
        except ValueError:
            return f"UNKNOWN(0x{self.what:x})"


EventCallback = Callable[[CnProcEvent], None]
AsyncEventCallback = Callable[[CnProcEvent], Awaitable[None]]


# ---------------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------------

class CnProcListener:
    """Subscribe to PROC_CN_MCAST_LISTEN and feed events to callbacks.

    Designed to plug into an existing asyncio loop via ``loop.add_reader``
    so the main thread stays fully idle until the kernel wakes us.

    Usage::

        listener = CnProcListener()
        if await listener.start(loop):
            listener.on_exec(lambda ev: ...)
            listener.on_exit(lambda ev: ...)
        else:
            # Fall back to /proc polling
            ...
    """

    _RECV_BUF = 64 * 1024

    def __init__(self) -> None:
        self._sock: Optional[socket.socket] = None
        self._port: int = 0
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._started: bool = False
        self._exec_cbs: list[EventCallback] = []
        self._exit_cbs: list[EventCallback] = []
        self._fork_cbs: list[EventCallback] = []
        self._any_cbs: list[EventCallback] = []
        self._async_any_cbs: list[AsyncEventCallback] = []
        self._event_count: int = 0
        self._reader_registered: bool = False

    # ------------------------------------------------------------------
    # Probe + lifecycle
    # ------------------------------------------------------------------

    @staticmethod
    def probe() -> bool:
        """Cheap static check: can we even create a NETLINK_CONNECTOR socket?

        Does not bind to the multicast group (which needs CAP_NET_ADMIN)
        and does not send a subscription -- returning True just means
        ``start()`` has a chance.  The authoritative check is ``start()``
        itself.
        """
        if sys.platform != "linux":
            return False
        if not hasattr(socket, "AF_NETLINK"):
            return False
        sock = None
        try:
            sock = socket.socket(
                socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR
            )
            return True
        except OSError:
            return False
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    async def start(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> bool:
        """Bind, subscribe, and hook into the event loop.

        Returns True on success.  False means the caller should stay on
        its polling fallback (EPERM on bind, old kernel, non-Linux host).
        """
        if self._started:
            return True
        if sys.platform != "linux" or not hasattr(socket, "AF_NETLINK"):
            return False
        if loop is None:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                logger.debug("cn_proc.start() requires a running event loop")
                return False
        self._loop = loop

        sock = None
        try:
            sock = socket.socket(
                socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR
            )
            # Non-blocking so the loop can reap events without stalling.
            sock.setblocking(False)
            # Bind to our pid with group bit set.  Kernel requires
            # CAP_NET_ADMIN to subscribe to CN_IDX_PROC -- EPERM here is
            # the expected non-root path.
            sock.bind((os.getpid(), CN_IDX_PROC))
            self._port = sock.getsockname()[0]

            # Generous rx buffer: a fork-storm (make -j64) can produce
            # hundreds of events per second.
            try:
                sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024
                )
            except OSError:
                pass

            self._sock = sock
            self._send_subscribe(PROC_CN_MCAST_LISTEN)
        except OSError as e:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            self._sock = None
            if e.errno == errno.EPERM:
                logger.info(
                    "cn_proc subscription requires CAP_NET_ADMIN; "
                    "falling back to /proc polling"
                )
            else:
                logger.info("cn_proc unavailable (%s); /proc fallback", e)
            return False

        try:
            loop.add_reader(self._sock.fileno(), self._on_readable)
            self._reader_registered = True
        except (NotImplementedError, RuntimeError) as e:
            # ProactorEventLoop on Windows would land here, but we've
            # already returned False for sys.platform != "linux", so
            # this mostly catches unusual selector implementations.
            logger.warning("cn_proc: loop.add_reader failed: %s", e)
            self._cleanup_socket()
            return False

        self._started = True
        logger.info("cn_proc subscribed (event-driven process tracking)")
        return True

    def stop(self) -> None:
        """Unsubscribe and close.  Safe to call multiple times."""
        if not self._started and self._sock is None:
            return
        if self._loop is not None and self._sock is not None and self._reader_registered:
            try:
                self._loop.remove_reader(self._sock.fileno())
            except (ValueError, RuntimeError, OSError):
                pass
            self._reader_registered = False
        if self._sock is not None:
            # Best-effort unsubscribe so we stop taking up a kernel slot.
            try:
                self._send_subscribe(PROC_CN_MCAST_IGNORE)
            except OSError:
                pass
        self._cleanup_socket()
        self._started = False
        logger.debug("cn_proc listener stopped (events=%d)", self._event_count)

    def _cleanup_socket(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # ------------------------------------------------------------------
    # Subscriptions
    # ------------------------------------------------------------------

    def on_exec(self, cb: EventCallback) -> None:
        self._exec_cbs.append(cb)

    def on_exit(self, cb: EventCallback) -> None:
        self._exit_cbs.append(cb)

    def on_fork(self, cb: EventCallback) -> None:
        self._fork_cbs.append(cb)

    def on_any(self, cb: EventCallback) -> None:
        self._any_cbs.append(cb)

    def on_any_async(self, cb: AsyncEventCallback) -> None:
        self._async_any_cbs.append(cb)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def started(self) -> bool:
        return self._started

    @property
    def event_count(self) -> int:
        return self._event_count

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _send_subscribe(self, op: int) -> None:
        """Send a PROC_CN_MCAST_{LISTEN,IGNORE} control message."""
        if self._sock is None:
            return
        # Payload: 4-byte enum value (PROC_CN_MCAST_LISTEN/IGNORE).
        payload = struct.pack("=I", op)

        cn = _CN_MSG.pack(
            CN_IDX_PROC,
            CN_VAL_PROC,
            0,                 # seq
            0,                 # ack
            len(payload),      # len
            0,                 # flags
        ) + payload

        total_len = NLMSGHDR_LEN + len(cn)
        hdr = _NLMSGHDR.pack(
            total_len,
            NLMSG_DONE,        # NETLINK_CONNECTOR uses NLMSG_DONE as the
                               # type for plain messages.
            0,                 # flags (no REQUEST flag; matches libnl users)
            0,                 # seq
            self._port,
        )
        self._sock.send(hdr + cn)

    def _on_readable(self) -> None:
        """Drain the socket non-blocking; dispatch every event we parse."""
        if self._sock is None:
            return
        while True:
            try:
                chunk = self._sock.recv(self._RECV_BUF)
            except BlockingIOError:
                return
            except OSError as e:
                if e.errno == errno.EINTR:
                    continue
                logger.debug("cn_proc recv error: %s", e)
                return
            if not chunk:
                return
            self._dispatch_chunk(chunk)

    def _dispatch_chunk(self, buf: bytes) -> None:
        off = 0
        blen = len(buf)

        while off + NLMSGHDR_LEN <= blen:
            nlmsg_len, nlmsg_type, _flags, _seq, _pid = _NLMSGHDR.unpack_from(buf, off)
            if nlmsg_len < NLMSGHDR_LEN or off + nlmsg_len > blen:
                break  # truncation

            if nlmsg_type == NLMSG_ERROR:
                # Log once and keep going -- an error here usually means
                # we dropped a burst (ENOBUFS); the stream recovers.
                logger.debug("cn_proc NLMSG_ERROR seen")
                off += _align4(nlmsg_len)
                continue

            # The kernel sends these with nlmsg_type = NLMSG_DONE for
            # each message; treat that as a regular payload carrier.
            payload_off = off + NLMSGHDR_LEN
            payload_end = off + nlmsg_len
            if payload_end - payload_off < CN_MSG_LEN + PROC_EVENT_HEAD_LEN:
                off += _align4(nlmsg_len)
                continue

            (idx, val, _cseq, _ack, cmlen, _cflags) = _CN_MSG.unpack_from(
                buf, payload_off
            )
            if idx != CN_IDX_PROC or val != CN_VAL_PROC:
                off += _align4(nlmsg_len)
                continue

            ev_off = payload_off + CN_MSG_LEN
            if ev_off + PROC_EVENT_HEAD_LEN > payload_end:
                off += _align4(nlmsg_len)
                continue

            what, cpu, ts = _PROC_EVENT_HEAD.unpack_from(buf, ev_off)
            data_off = ev_off + PROC_EVENT_HEAD_LEN
            remaining = payload_end - data_off

            ev = self._decode_event(what, cpu, ts, buf, data_off, remaining)
            off += _align4(nlmsg_len)
            if ev is None:
                continue

            self._event_count += 1
            self._fire(ev)

    @staticmethod
    def _decode_event(what: int, cpu: int, ts: int,
                      buf: bytes, off: int, remaining: int) -> Optional[CnProcEvent]:
        """Decode the per-event union based on ``what``.

        We only bother with FORK / EXEC / EXIT -- other events are
        mostly uid/gid changes the observer doesn't care about.  For
        unknown events we still return a CnProcEvent so ``on_any``
        subscribers see them.
        """
        try:
            if what == ProcEvent.FORK and remaining >= _EV_FORK.size:
                p_pid, p_tgid, c_pid, c_tgid = _EV_FORK.unpack_from(buf, off)
                return CnProcEvent(
                    what=what, cpu=cpu, timestamp_ns=ts,
                    pid=c_tgid, tgid=c_tgid,
                    parent_pid=p_pid, parent_tgid=p_tgid,
                )
            if what == ProcEvent.EXEC and remaining >= _EV_EXEC.size:
                pid, tgid = _EV_EXEC.unpack_from(buf, off)
                return CnProcEvent(
                    what=what, cpu=cpu, timestamp_ns=ts,
                    pid=tgid, tgid=tgid,
                )
            if what == ProcEvent.EXIT and remaining >= _EV_EXIT.size:
                pid, tgid, exit_code, _sig, p_pid, p_tgid = _EV_EXIT.unpack_from(buf, off)
                return CnProcEvent(
                    what=what, cpu=cpu, timestamp_ns=ts,
                    pid=tgid, tgid=tgid,
                    parent_pid=p_pid, parent_tgid=p_tgid,
                    exit_code=exit_code,
                )
            # Less-useful events: UID/GID/SID/PTRACE/COMM/COREDUMP
            if remaining >= _EV_IDS.size:
                pid, tgid = _EV_IDS.unpack_from(buf, off)
                return CnProcEvent(
                    what=what, cpu=cpu, timestamp_ns=ts,
                    pid=tgid, tgid=tgid,
                )
        except struct.error:
            return None
        return None

    def _fire(self, ev: CnProcEvent) -> None:
        # Specific-kind callbacks first, then wildcards.
        cbs: list[EventCallback]
        if ev.what == ProcEvent.EXEC:
            cbs = self._exec_cbs
        elif ev.what == ProcEvent.EXIT:
            cbs = self._exit_cbs
        elif ev.what == ProcEvent.FORK:
            cbs = self._fork_cbs
        else:
            cbs = []

        for cb in cbs:
            try:
                cb(ev)
            except Exception:
                logger.exception("cn_proc callback raised")

        for cb in self._any_cbs:
            try:
                cb(ev)
            except Exception:
                logger.exception("cn_proc on_any callback raised")

        if self._async_any_cbs and self._loop is not None:
            for acb in self._async_any_cbs:
                try:
                    self._loop.create_task(acb(ev))
                except RuntimeError:
                    pass


def _align4(n: int) -> int:
    """Netlink alignment."""
    return (n + 3) & ~3


__all__ = [
    "CnProcListener",
    "CnProcEvent",
    "ProcEvent",
]
