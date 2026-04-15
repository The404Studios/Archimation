"""
NETLINK_INET_DIAG client -- binary replacement for /proc/net/{tcp,tcp6,udp,udp6}.

Parsing text tables out of /proc grows with the connection count and pays
a (re-read + tokenise) cost every poll cycle.  The kernel's ``sock_diag``
module exposes the same data as a compact binary stream we can pull over
a netlink socket, filter server-side (by state), and decode with a pair
of ``struct.unpack`` calls.

This is still request/response (netlink ``NLM_F_DUMP``), not event push --
for true events you need BPF/NFLOG -- but in practice it cuts per-poll
CPU by ~10x on busy hosts and removes an O(N) string parse.

The module is pure stdlib: ``socket`` + ``struct`` + ``os``.  On non-Linux
hosts it imports cleanly but ``InetDiagClient.probe()`` returns False so
callers degrade to their existing /proc path.
"""

from __future__ import annotations

import errno
import logging
import os
import socket
import struct
import sys
from typing import Iterable, Optional

logger = logging.getLogger("firewall.netlink")

# ---------------------------------------------------------------------------
# Netlink / sock_diag constants (see linux/inet_diag.h, linux/sock_diag.h).
# ---------------------------------------------------------------------------

NETLINK_INET_DIAG = 4
NETLINK_SOCK_DIAG = NETLINK_INET_DIAG  # alias in older headers

# nlmsg types
SOCK_DIAG_BY_FAMILY = 20

# nlmsg flags
NLM_F_REQUEST = 0x01
NLM_F_ROOT = 0x100
NLM_F_MATCH = 0x200
NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH

# nlmsg terminators
NLMSG_DONE = 3
NLMSG_ERROR = 2

# TCP states (matches Linux ``TCP_*`` constants)
TCP_ESTABLISHED = 1
TCP_SYN_SENT = 2
TCP_SYN_RECV = 3
TCP_FIN_WAIT1 = 4
TCP_FIN_WAIT2 = 5
TCP_TIME_WAIT = 6
TCP_CLOSE = 7
TCP_CLOSE_WAIT = 8
TCP_LAST_ACK = 9
TCP_LISTEN = 10
TCP_CLOSING = 11

TCP_STATE_NAME = {
    TCP_ESTABLISHED: "ESTABLISHED",
    TCP_SYN_SENT: "SYN_SENT",
    TCP_SYN_RECV: "SYN_RECV",
    TCP_FIN_WAIT1: "FIN_WAIT1",
    TCP_FIN_WAIT2: "FIN_WAIT2",
    TCP_TIME_WAIT: "TIME_WAIT",
    TCP_CLOSE: "CLOSED",
    TCP_CLOSE_WAIT: "CLOSE_WAIT",
    TCP_LAST_ACK: "LAST_ACK",
    TCP_LISTEN: "LISTEN",
    TCP_CLOSING: "CLOSING",
}

# Default states bitmap: everything except TIME_WAIT (churn) + CLOSE (dead).
# Caller may override.  Bit N set means "dump state N".
_ALL_TCP_STATES = (
    (1 << TCP_ESTABLISHED)
    | (1 << TCP_SYN_SENT)
    | (1 << TCP_SYN_RECV)
    | (1 << TCP_FIN_WAIT1)
    | (1 << TCP_FIN_WAIT2)
    | (1 << TCP_CLOSE_WAIT)
    | (1 << TCP_LAST_ACK)
    | (1 << TCP_LISTEN)
    | (1 << TCP_CLOSING)
)

# UDP has a single "listening" state -> state 7 in the /proc dump, but for
# sock_diag we ask for all states (the kernel ignores the bitmap for UDP
# in recent kernels but we send a sane mask anyway).
_ALL_UDP_STATES = 0xFFFFFFFF

# Structs.  Numbers come straight from the kernel header layouts.
#
# struct nlmsghdr {
#     __u32 nlmsg_len;
#     __u16 nlmsg_type;
#     __u16 nlmsg_flags;
#     __u32 nlmsg_seq;
#     __u32 nlmsg_pid;
# };
_NLMSGHDR = struct.Struct("=IHHII")
NLMSGHDR_LEN = _NLMSGHDR.size  # 16

# struct inet_diag_sockid { __be16 sport; __be16 dport;
#     __be32 src[4]; __be32 dst[4]; __u32 if; __u32 cookie[2]; };
# 2 + 2 + 16 + 16 + 4 + 8 = 48
_INET_DIAG_SOCKID = struct.Struct("!HH16s16sI2I")  # ports net-order, rest native after
# We pack the sockid portion by hand (mixed endian) below.

# struct inet_diag_req_v2 {
#     __u8  sdiag_family;
#     __u8  sdiag_protocol;
#     __u8  idiag_ext;
#     __u8  pad;
#     __u32 idiag_states;
#     struct inet_diag_sockid id;  // 48 bytes, zeroed
# };
# 1 + 1 + 1 + 1 + 4 + 48 = 56
_INET_DIAG_REQ_V2 = struct.Struct("=BBBBI48s")

# struct inet_diag_msg {
#     __u8  idiag_family;
#     __u8  idiag_state;
#     __u8  idiag_timer;
#     __u8  idiag_retrans;
#     struct inet_diag_sockid id;     // 48 bytes
#     __u32 idiag_expires;
#     __u32 idiag_rqueue;
#     __u32 idiag_wqueue;
#     __u32 idiag_uid;
#     __u32 idiag_inode;
# };
# 4 + 48 + 20 = 72
_INET_DIAG_MSG = struct.Struct("=BBBB48sIIIII")
INET_DIAG_MSG_LEN = _INET_DIAG_MSG.size  # 72


def _align4(n: int) -> int:
    """Netlink message lengths are 4-byte aligned."""
    return (n + 3) & ~3


def _build_sockid() -> bytes:
    """Zero-filled sockid (we don't prefilter by endpoint)."""
    return b"\x00" * 48


def _build_request(family: int, protocol: int, states: int, seq: int, port: int) -> bytes:
    """Assemble a full NLM_F_DUMP request for SOCK_DIAG_BY_FAMILY."""
    req = _INET_DIAG_REQ_V2.pack(
        family,
        protocol,
        0,            # idiag_ext -- we don't need extensions
        0,            # pad
        states,
        _build_sockid(),
    )
    total_len = NLMSGHDR_LEN + len(req)
    hdr = _NLMSGHDR.pack(
        total_len,
        SOCK_DIAG_BY_FAMILY,
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
        port,
    )
    return hdr + req


def _decode_addr(raw: bytes, family: int) -> str:
    """Decode a 16-byte address buffer given the socket family.

    IPv4 lives in the first 4 bytes (network byte order); IPv6 takes the
    full 16.  ``inet_ntop`` does the heavy lifting so we stay correct for
    IPv4-mapped addresses.
    """
    if family == socket.AF_INET:
        return socket.inet_ntop(socket.AF_INET, raw[:4])
    return socket.inet_ntop(socket.AF_INET6, raw)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class InetDiagClient:
    """Stateless(ish) sock_diag client.

    Open once, reuse the socket across polls.  Each ``query_tcp`` /
    ``query_udp`` call sends a DUMP request, reads multipart responses
    until ``NLMSG_DONE``, and returns a list of connection dicts.

    Dict shape matches what the existing /proc parser produces so
    callers can swap implementations transparently.
    """

    # Empirically 128 KiB covers a few thousand sockets per chunk;
    # multipart responses mean we'll loop regardless.
    _RECV_BUF = 128 * 1024

    def __init__(self) -> None:
        self._sock: Optional[socket.socket] = None
        self._seq: int = 0
        self._port: int = 0
        self._available: Optional[bool] = None

    # ------------------------------------------------------------------
    # Availability probe
    # ------------------------------------------------------------------

    @staticmethod
    def probe() -> bool:
        """Return True iff this host can open a NETLINK_SOCK_DIAG socket.

        Checks only that socket creation + bind succeed -- doesn't send
        a real query.  On Windows / macOS this is an import-time short
        circuit; on Linux we still verify because older kernels or
        restrictive seccomp profiles can reject AF_NETLINK.
        """
        if sys.platform != "linux":
            return False
        if not hasattr(socket, "AF_NETLINK"):
            return False
        sock = None
        try:
            sock = socket.socket(
                socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_INET_DIAG
            )
            sock.bind((0, 0))
            return True
        except (OSError, AttributeError):
            return False
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def open(self) -> bool:
        """Open the netlink socket.  Returns False if not supported."""
        if self._sock is not None:
            return True
        if sys.platform != "linux" or not hasattr(socket, "AF_NETLINK"):
            self._available = False
            return False
        try:
            sock = socket.socket(
                socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_INET_DIAG
            )
            sock.bind((0, 0))
            # getsockname returns (pid, groups); kernel assigns the pid/port.
            self._port = sock.getsockname()[0]
            # Generous rx buffer so a full TCP dump on a busy host doesn't
            # tail-drop between recv() calls.
            try:
                sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024
                )
            except OSError:
                pass  # Not fatal; kernel default is ~200 KiB
            self._sock = sock
            self._available = True
            return True
        except OSError as e:
            logger.info(
                "NETLINK_INET_DIAG unavailable (%s); /proc fallback will be used",
                e,
            )
            self._available = False
            return False

    def close(self) -> None:
        if self._sock is not None:
            try:
                # shutdown on a datagram netlink socket is a no-op but
                # keeping it symmetrical simplifies future changes.
                try:
                    self._sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            self._available = None

    def __enter__(self) -> "InetDiagClient":
        self.open()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @property
    def available(self) -> Optional[bool]:
        """``True`` if ``open()`` succeeded, ``False`` if it failed, ``None``
        if no attempt has been made yet."""
        return self._available

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def query_tcp(self, ipv6: bool = False,
                  states: int = _ALL_TCP_STATES) -> list[dict]:
        """Dump TCP sockets for the chosen family."""
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        return self._query(family, socket.IPPROTO_TCP, states, "tcp6" if ipv6 else "tcp")

    def query_udp(self, ipv6: bool = False) -> list[dict]:
        """Dump UDP sockets for the chosen family."""
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        return self._query(family, socket.IPPROTO_UDP, _ALL_UDP_STATES, "udp6" if ipv6 else "udp")

    def query_all(self) -> Iterable[dict]:
        """Yield sockets from all four (family x protocol) pairs.

        Isolated try/except per pair so a single failing family (e.g. IPv6
        disabled at boot) doesn't blank the whole table.
        """
        for call in (
            lambda: self.query_tcp(ipv6=False),
            lambda: self.query_tcp(ipv6=True),
            lambda: self.query_udp(ipv6=False),
            lambda: self.query_udp(ipv6=True),
        ):
            try:
                yield from call()
            except OSError as e:
                logger.debug("sock_diag query failed: %s", e)
                continue

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _query(self, family: int, protocol: int, states: int,
               label: str) -> list[dict]:
        if not self.open():
            return []
        assert self._sock is not None

        self._seq = (self._seq + 1) & 0xFFFFFFFF
        req = _build_request(family, protocol, states, self._seq, self._port)
        try:
            self._sock.send(req)
        except OSError as e:
            logger.debug("sock_diag send failed (%s): %s", label, e)
            # Reset the socket so the next call can retry cleanly.
            self.close()
            return []

        results: list[dict] = []
        # Multipart response: keep reading until we see NLMSG_DONE or
        # NLMSG_ERROR.  Hard-cap the iteration count as a belt-and-braces
        # against a kernel bug that never sends DONE; 100k messages is
        # vastly more than any realistic socket table.
        for _ in range(100_000):
            try:
                chunk = self._sock.recv(self._RECV_BUF)
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR):
                    continue
                logger.debug("sock_diag recv failed (%s): %s", label, e)
                self.close()
                return results

            if not chunk:
                break

            done, msgs = self._parse_chunk(chunk, family, label)
            results.extend(msgs)
            if done:
                break
        else:
            logger.warning(
                "sock_diag dump for %s exceeded safety cap", label
            )

        return results

    @staticmethod
    def _parse_chunk(buf: bytes, family: int, label: str) -> tuple[bool, list[dict]]:
        """Walk a netlink chunk and return (done, [conn dicts])."""
        results: list[dict] = []
        done = False
        off = 0
        blen = len(buf)

        while off + NLMSGHDR_LEN <= blen:
            nlmsg_len, nlmsg_type, _flags, _seq, _pid = _NLMSGHDR.unpack_from(buf, off)

            if nlmsg_len < NLMSGHDR_LEN or off + nlmsg_len > blen:
                # Truncated / malformed -- bail on this chunk.
                break

            if nlmsg_type == NLMSG_DONE:
                done = True
                break
            if nlmsg_type == NLMSG_ERROR:
                # First 4 bytes after header are the errno (int32, negative).
                payload_off = off + NLMSGHDR_LEN
                if payload_off + 4 <= blen:
                    err = struct.unpack_from("=i", buf, payload_off)[0]
                    logger.debug("sock_diag NLMSG_ERROR for %s: %d", label, err)
                done = True
                break
            if nlmsg_type != SOCK_DIAG_BY_FAMILY:
                # Unknown message in our stream; skip it rather than abort.
                off += _align4(nlmsg_len)
                continue

            payload_off = off + NLMSGHDR_LEN
            payload_end = off + nlmsg_len
            if payload_end - payload_off < INET_DIAG_MSG_LEN:
                off += _align4(nlmsg_len)
                continue

            (fam, state, _timer, _retrans,
             sockid, _expires, _rqueue, _wqueue,
             uid, inode) = _INET_DIAG_MSG.unpack_from(buf, payload_off)

            # sockid layout: sport(2) dport(2) src(16) dst(16) if(4) cookie(8)
            # sport/dport are __be16; addresses are "__be32[4]" so also BE.
            sport, dport = struct.unpack("!HH", sockid[0:4])
            src_raw = sockid[4:20]
            dst_raw = sockid[20:36]

            try:
                laddr = _decode_addr(src_raw, fam)
                raddr = _decode_addr(dst_raw, fam)
            except (OSError, ValueError):
                off += _align4(nlmsg_len)
                continue

            results.append({
                "protocol": label,
                "family": fam,
                "state_code": state,
                "local_addr": laddr,
                "local_port": sport,
                "remote_addr": raddr,
                "remote_port": dport,
                "uid": uid,
                "inode": inode,
            })

            off += _align4(nlmsg_len)

        return done, results


__all__ = [
    "InetDiagClient",
    "TCP_STATE_NAME",
    "TCP_ESTABLISHED",
    "TCP_LISTEN",
    "TCP_CLOSE",
]
