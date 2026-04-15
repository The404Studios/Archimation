"""
io_uring batch-async /proc reader (Round 32).

Pure-stdlib ctypes shim that drives the kernel io_uring ABI directly
via ``syscall()``.  No dependency on ``liburing``, no pip package.

Why this module exists
----------------------
The memory / syscall / pattern observers in the AI daemon each walk
``/proc/<pid>/...`` on every tick.  On a host with 400 PIDs that's
1,200+ blocking file I/O syscalls per scan just to open, read and
close the relevant pseudo-files.  On HDD-backed VMs or under contention
each of those opens can stall for milliseconds.

io_uring lets us:

1. ``openat()`` every PID's pseudo-file (they're cheap in the page
   cache, but still N syscalls -- we keep them synchronous and let the
   kernel batch in the scheduler).
2. Submit **N read() operations in one shot** via the submission queue
   (SQ) ring -- the kernel does the reads asynchronously while we
   prepare the next cycle.
3. Drain the completion queue (CQ) with a single ``io_uring_enter()``
   waiting for all N completions.

On new hardware we additionally enable ``IORING_SETUP_SQPOLL``, which
gives the kernel a dedicated poll thread and eliminates the
submission-side syscall entirely.  That's ~30-50% less CPU for the
observer tick at the cost of one pinned core, which is fine on 4+ core
boxes but undesirable on an old 2-core netbook -- hence the hardware
class gating in :mod:`daemon.config`.

Compatibility matrix
--------------------
* Kernel 5.1 (May 2019): basic io_uring + READ/WRITE ops.  Minimum bar.
* Kernel 5.5           : ``IORING_SETUP_SQPOLL`` usable without root.
* Kernel 5.6           : multishot operations and ``IORING_FEAT_NODROP``.
* Non-Linux / old kernel: :meth:`IOUring.available` returns False, the
  observer sticks to its existing sync ``/proc`` text reads.

Interface
---------
``IOUring(depth=32, sqpoll=False, sq_cpu=None)``
    Context-managed ring.  ``depth`` is the SQ depth (also CQ size).

``ring.submit_read(fd, buf, offset=0) -> int``
    Queue a READ SQE; returns a user_data handle to correlate the
    completion.  ``buf`` must be a writable ``bytearray`` (or anything
    that yields a stable address via ``ctypes.addressof``).

``ring.submit_readv(fd, iov, offset=0) -> int``
    Queue a READV SQE (scatter-gather).

``ring.drain(min_complete=None, timeout=None) -> list[Completion]``
    Submit pending SQEs, wait until at least ``min_complete`` CQEs land
    (defaults to "all queued"), return list of (user_data, res, flags).

``ring.close()``
    Unmap rings and close the ring fd.  Idempotent.

Safe on Windows: module imports cleanly, ``available()`` returns False,
no ctypes calls run.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import logging
import mmap
import os
import struct
import sys
import threading
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("ai-control.iouring")

# ---------------------------------------------------------------------------
# Kernel ABI constants (from <linux/io_uring.h>).  Never change these.
# ---------------------------------------------------------------------------

# Syscall numbers (x86_64; aarch64 etc. use the same numbers on modern
# kernels because io_uring was added after the generic syscall table
# unification).
_NR_io_uring_setup = 425
_NR_io_uring_enter = 426
_NR_io_uring_register = 427  # reserved for future fixed-buffer work

# Setup flags
IORING_SETUP_SQPOLL = 1 << 1
IORING_SETUP_SQ_AFF = 1 << 2
IORING_SETUP_CQSIZE = 1 << 3

# Enter flags
IORING_ENTER_GETEVENTS = 1 << 0
IORING_ENTER_SQ_WAKEUP = 1 << 1

# Feature flags (in io_uring_params.features)
IORING_FEAT_SINGLE_MMAP = 1 << 0
IORING_FEAT_NODROP = 1 << 1
IORING_FEAT_SUBMIT_STABLE = 1 << 2
IORING_FEAT_SQPOLL_NONFIXED = 1 << 7  # 5.11

# Operation codes (partial -- we only use a handful)
IORING_OP_NOP = 0
IORING_OP_READV = 1
IORING_OP_WRITEV = 2
IORING_OP_READ = 22
IORING_OP_WRITE = 23

# SQ ring offsets into the mapped region
_SQ_RING_OFFSETS = "IIIIIIII"   # head, tail, ring_mask, ring_entries, flags,
                                # dropped, array, resv1 (+ reserved padding)
# CQ ring offsets layout
_CQ_RING_OFFSETS = "IIIIIIII"   # head, tail, ring_mask, ring_entries,
                                # overflow, cqes, flags, resv1

# mmap ring offsets (from io_uring_enter/mmap docs)
IORING_OFF_SQ_RING = 0
IORING_OFF_CQ_RING = 0x8000000
IORING_OFF_SQES = 0x10000000

# struct io_sqring_offsets {
#   __u32 head; tail; ring_mask; ring_entries; flags; dropped;
#   __u32 array; resv1; __u64 resv2; };
_SQRING_OFFSETS_LAYOUT = struct.Struct("=IIIIIIIIQ")

# struct io_cqring_offsets {
#   __u32 head; tail; ring_mask; ring_entries; overflow; cqes;
#   __u32 flags; resv1; __u64 resv2; };
_CQRING_OFFSETS_LAYOUT = struct.Struct("=IIIIIIIIQ")

# struct io_uring_params, 120 bytes:
#   __u32 sq_entries;
#   __u32 cq_entries;
#   __u32 flags;
#   __u32 sq_thread_cpu;
#   __u32 sq_thread_idle;
#   __u32 features;
#   __u32 wq_fd;
#   __u32 resv[3];
#   struct io_sqring_offsets sq_off;   (40 bytes: 9 * u32 but 8-byte align -> 40)
#   struct io_cqring_offsets cq_off;   (40 bytes)
#
# Total: 7*4 + 3*4 + 40 + 40 = 28 + 12 + 40 + 40 = 120 bytes
_IO_URING_PARAMS_LAYOUT = struct.Struct(
    "=IIIIIII"      # sq_entries, cq_entries, flags, sq_thread_cpu,
                     # sq_thread_idle, features, wq_fd
    "III"            # resv[3]
    "IIIIIIIIQ"      # sq_off  (9 * u32 + 1 * u64 but struct packs to 40 bytes)
    "IIIIIIIIQ"      # cq_off
)
_IO_URING_PARAMS_SIZE = _IO_URING_PARAMS_LAYOUT.size  # 120

# SQE layout (64 bytes).  Only the fields we actually set are named here.
#   __u8 opcode; __u8 flags; __u16 ioprio; __s32 fd;
#   union { __u64 off; __u64 addr2; };
#   union { __u64 addr; __u64 splice_off_in; };
#   __u32 len;
#   union { __u32 rw_flags; ... };       (various per-op)
#   __u64 user_data;
#   union { __u16 buf_index; ... };       (+ padding out to 64)
_SQE_LAYOUT = struct.Struct("=BBHiQQIIQHHI")
# Python struct sizes: 1 + 1 + 2 + 4 + 8 + 8 + 4 + 4 + 8 + 2 + 2 + 4 = 48
# but io_uring_sqe is 64 bytes.  We pad to 64 manually with zeros when writing.
_SQE_SIZE = 64
# struct.Struct for zeroing an SQE slot before repacking (mmap slice
# assignment requires equal-length writes, which makes a naive b'\0'*64
# assignment fragile).  Using 16 u32s keeps the pack alignment sane.
_ZERO_SQE = struct.Struct("=IIIIIIIIIIIIIIII")  # 16 * u32 = 64 bytes

# CQE layout (16 bytes):
#   __u64 user_data; __s32 res; __u32 flags;
_CQE_LAYOUT = struct.Struct("=QiI")
_CQE_SIZE = 16


# ---------------------------------------------------------------------------
# libc.syscall gateway
# ---------------------------------------------------------------------------

_LIBC: Optional[ctypes.CDLL] = None


def _libc() -> Optional[ctypes.CDLL]:
    """Lazy-load libc with its ``syscall`` symbol configured.

    We never raise here -- probe callers expect a None return on
    unsupported platforms.
    """
    global _LIBC
    if _LIBC is not None:
        return _LIBC
    if sys.platform != "linux":
        return None
    name = ctypes.util.find_library("c") or "libc.so.6"
    try:
        libc = ctypes.CDLL(name, use_errno=True)
    except OSError:
        return None
    # syscall(long number, ...) returns long.  We pass up to 6 args.
    libc.syscall.restype = ctypes.c_long
    _LIBC = libc
    return libc


def _syscall(number: int, *args: int) -> int:
    """Thin ``syscall(2)`` wrapper that raises OSError on failure."""
    lib = _libc()
    if lib is None:
        raise OSError(errno.ENOSYS, "syscall() not available on this platform")
    # Coerce all args to c_long so ctypes picks the correct sign handling.
    c_args = [ctypes.c_long(a) for a in args]
    ret = lib.syscall(ctypes.c_long(number), *c_args)
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return int(ret)


# ---------------------------------------------------------------------------
# Public completion type
# ---------------------------------------------------------------------------

@dataclass
class Completion:
    """A drained CQE."""
    user_data: int
    res: int           # >= 0: bytes transferred / file descriptor.  < 0: -errno
    flags: int

    @property
    def ok(self) -> bool:
        return self.res >= 0

    @property
    def err(self) -> int:
        return -self.res if self.res < 0 else 0


# ---------------------------------------------------------------------------
# Ring
# ---------------------------------------------------------------------------

class IOUring:
    """Submission/Completion ring owner.

    Not intrinsically thread-safe.  Callers are expected to submit from a
    single thread (the asyncio loop or a dedicated worker).  We guard the
    tail pointer with a local lock just in case callers queue from the
    executor pool.
    """

    # Cache the result of available() so repeated observer constructors
    # don't trip the probe syscall on every start.
    _availability: Optional[tuple[bool, dict]] = None

    def __init__(
        self,
        depth: int = 32,
        sqpoll: bool = False,
        sq_cpu: Optional[int] = None,
        sq_thread_idle_ms: int = 2000,
    ) -> None:
        if depth <= 0 or depth & (depth - 1):
            # io_uring requires a power-of-two queue depth.  Round up.
            nd = 1
            while nd < depth:
                nd *= 2
            depth = nd
        self._depth = depth
        self._sqpoll = bool(sqpoll)
        self._sq_cpu = sq_cpu
        self._sq_thread_idle_ms = sq_thread_idle_ms

        self._ring_fd: int = -1
        self._sq_ring: Optional[mmap.mmap] = None
        self._cq_ring: Optional[mmap.mmap] = None
        self._sqes: Optional[mmap.mmap] = None
        self._sq_ring_size: int = 0
        self._cq_ring_size: int = 0
        self._sqes_size: int = 0

        # Parsed ring offsets (populated by _setup).
        self._sq_off = {}
        self._cq_off = {}

        # Pre-bound struct accessors for the volatile head/tail pointers.
        # We always read them fresh from the mmap'd ring (no caching).
        self._pending_sqes: int = 0        # SQEs prepared but not yet submitted
        self._unseen_completions: dict[int, Completion] = {}  # drained but not yet consumed
        self._next_user_data: int = 1
        self._lock = threading.Lock()

        # Keep write-buffers alive for the duration of the call -- the
        # kernel needs their memory to stay resident until the CQE lands.
        self._pinned: dict[int, object] = {}

        self._features: int = 0

    # ------------------------------------------------------------------
    # Probe
    # ------------------------------------------------------------------

    @classmethod
    def available(cls, probe_sqpoll: bool = False) -> bool:
        """Return True iff io_uring is usable on this host.

        Caches the result for the life of the process.  The probe creates
        a tiny ring (depth 2) and immediately tears it down; on success
        we cache the kernel feature bitmap for :meth:`features`.
        """
        if cls._availability is not None:
            return cls._availability[0]
        ok, info = False, {}
        if sys.platform != "linux":
            cls._availability = (False, {})
            return False
        if _libc() is None:
            cls._availability = (False, {})
            return False
        try:
            ring = cls(depth=2, sqpoll=False)
            ring._setup()
            ok = True
            info = {
                "features": ring._features,
                "sqpoll_nonfixed": bool(
                    ring._features & IORING_FEAT_SQPOLL_NONFIXED
                ),
                "nodrop": bool(ring._features & IORING_FEAT_NODROP),
                "single_mmap": bool(ring._features & IORING_FEAT_SINGLE_MMAP),
                "sq_entries": ring._depth,
            }
            ring.close()
        except (OSError, ValueError) as e:
            logger.debug("io_uring probe failed: %s", e)
            ok = False
        cls._availability = (ok, info)
        return ok

    @classmethod
    def features(cls) -> dict:
        """Return the kernel feature bitmap (populated by available())."""
        if cls._availability is None:
            cls.available()
        return dict(cls._availability[1]) if cls._availability else {}

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "IOUring":
        self._setup()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Setup / teardown
    # ------------------------------------------------------------------

    def _setup(self) -> None:
        """Call io_uring_setup(2) and mmap the 3 rings.

        Raises OSError on any kernel-side failure; callers in ``available``
        swallow it and mark the ring unavailable.
        """
        if self._ring_fd >= 0:
            return  # already set up

        params = bytearray(_IO_URING_PARAMS_SIZE)
        flags = 0
        sq_cpu = 0
        if self._sqpoll:
            flags |= IORING_SETUP_SQPOLL
            if self._sq_cpu is not None:
                flags |= IORING_SETUP_SQ_AFF
                sq_cpu = int(self._sq_cpu)

        # Pack only the fields we want to *request*.  The kernel fills in
        # the rest (sq_entries, cq_entries, features, sq_off, cq_off).
        struct.pack_into(
            "=IIIIIII",
            params, 0,
            0,              # sq_entries  -- kernel computes from depth
            0,              # cq_entries  -- kernel computes (2*depth default)
            flags,
            sq_cpu,
            self._sq_thread_idle_ms,
            0,              # features (kernel fills)
            0,              # wq_fd
        )

        p_params = (ctypes.c_char * len(params)).from_buffer(params)
        ring_fd = _syscall(
            _NR_io_uring_setup,
            self._depth,
            ctypes.addressof(p_params),
        )

        # Unpack the full params out.
        sq_entries, cq_entries, _flg, _cpu, _idle, features, _wq, \
            _r0, _r1, _r2, \
            sq_head, sq_tail, sq_mask, sq_ents, sq_flags, sq_dropped, \
            sq_array, sq_resv1, _sq_resv2, \
            cq_head, cq_tail, cq_mask, cq_ents, cq_ovfl, cq_cqes, \
            cq_flags, cq_resv1, _cq_resv2 = _IO_URING_PARAMS_LAYOUT.unpack(
                bytes(params)
            )

        self._ring_fd = ring_fd
        self._features = features

        self._sq_off = {
            "head": sq_head, "tail": sq_tail, "ring_mask": sq_mask,
            "ring_entries": sq_ents, "flags": sq_flags, "dropped": sq_dropped,
            "array": sq_array,
        }
        self._cq_off = {
            "head": cq_head, "tail": cq_tail, "ring_mask": cq_mask,
            "ring_entries": cq_ents, "overflow": cq_ovfl, "cqes": cq_cqes,
            "flags": cq_flags,
        }

        # Sizes reported by kernel
        self._depth = sq_entries or self._depth

        # mmap the three regions.  On kernels with IORING_FEAT_SINGLE_MMAP
        # the SQ and CQ rings share the same mapping, but mmap'ing them
        # separately works on all kernels.
        sq_size = sq_array + sq_entries * 4
        cq_size = cq_cqes + cq_entries * _CQE_SIZE
        sqes_size = sq_entries * _SQE_SIZE

        self._sq_ring_size = sq_size
        self._cq_ring_size = cq_size
        self._sqes_size = sqes_size

        # mmap.mmap accepts offset only if page-aligned; io_uring offsets
        # are already page-aligned by definition.
        try:
            self._sq_ring = mmap.mmap(
                ring_fd, sq_size,
                mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE,
                offset=IORING_OFF_SQ_RING,
            )
        except (OSError, ValueError):
            os.close(ring_fd)
            self._ring_fd = -1
            raise

        try:
            self._cq_ring = mmap.mmap(
                ring_fd, cq_size,
                mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE,
                offset=IORING_OFF_CQ_RING,
            )
        except (OSError, ValueError):
            self._sq_ring.close(); self._sq_ring = None
            os.close(ring_fd); self._ring_fd = -1
            raise

        try:
            self._sqes = mmap.mmap(
                ring_fd, sqes_size,
                mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE,
                offset=IORING_OFF_SQES,
            )
        except (OSError, ValueError):
            self._sq_ring.close(); self._sq_ring = None
            self._cq_ring.close(); self._cq_ring = None
            os.close(ring_fd); self._ring_fd = -1
            raise

    def close(self) -> None:
        """Tear down the ring.  Idempotent."""
        with self._lock:
            if self._sqes is not None:
                try:
                    self._sqes.close()
                except (OSError, BufferError):
                    pass
                self._sqes = None
            if self._cq_ring is not None:
                try:
                    self._cq_ring.close()
                except (OSError, BufferError):
                    pass
                self._cq_ring = None
            if self._sq_ring is not None:
                try:
                    self._sq_ring.close()
                except (OSError, BufferError):
                    pass
                self._sq_ring = None
            if self._ring_fd >= 0:
                try:
                    os.close(self._ring_fd)
                except OSError:
                    pass
                self._ring_fd = -1
            self._pending_sqes = 0
            self._pinned.clear()
            self._unseen_completions.clear()

    # ------------------------------------------------------------------
    # Ring pointer helpers (all u32, native-endian, volatile reads/writes)
    # ------------------------------------------------------------------

    def _read_u32(self, ring: mmap.mmap, off: int) -> int:
        return struct.unpack_from("=I", ring, off)[0]

    def _write_u32(self, ring: mmap.mmap, off: int, val: int) -> None:
        struct.pack_into("=I", ring, off, val & 0xFFFFFFFF)

    # ------------------------------------------------------------------
    # SQE preparation
    # ------------------------------------------------------------------

    def _next_sqe_slot(self) -> Optional[int]:
        """Return the tail index (slot counter), or None if the ring is full.

        The ``ring_mask`` / ``ring_entries`` fields in ``self._sq_off``
        are byte offsets *into* the mapped SQ ring at which the kernel
        stores the actual values.  Callers that need ``mask`` must
        re-read via :meth:`_sq_mask` -- don't confuse the offset with
        the value.
        """
        assert self._sq_ring is not None
        head = self._read_u32(self._sq_ring, self._sq_off["head"])
        tail = self._read_u32(self._sq_ring, self._sq_off["tail"])
        if tail - head >= self._depth:
            return None
        return tail

    def _sq_mask(self) -> int:
        """Read the SQ ring mask from its dedicated slot in the mapping."""
        assert self._sq_ring is not None
        return self._read_u32(self._sq_ring, self._sq_off["ring_mask"])

    def _cq_mask(self) -> int:
        assert self._cq_ring is not None
        return self._read_u32(self._cq_ring, self._cq_off["ring_mask"])

    def _prep_rw(
        self,
        opcode: int,
        fd: int,
        addr: int,
        length: int,
        offset: int,
        user_data: int,
    ) -> bool:
        assert self._sqes is not None and self._sq_ring is not None
        with self._lock:
            tail = self._next_sqe_slot()
            if tail is None:
                return False
            idx = tail & self._sq_mask()
            sqe_off = idx * _SQE_SIZE
            # Zero the full 64 bytes so stale fields don't confuse the
            # kernel.  mmap.__setitem__ requires equal-length slice
            # assignment, so we use struct.pack_into with 16 zero u32s.
            _ZERO_SQE.pack_into(
                self._sqes, sqe_off,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            )
            _SQE_LAYOUT.pack_into(
                self._sqes, sqe_off,
                opcode & 0xFF,      # opcode
                0,                   # flags
                0,                   # ioprio
                fd,                  # fd
                offset,              # off
                addr,                # addr
                length,              # len
                0,                   # rw_flags / op-specific
                user_data,           # user_data
                0,                   # buf_index
                0,                   # personality
                0,                   # splice_fd_in (pad)
            )
            # Point array[tail] at this SQE index (identity mapping for simple cases).
            arr_base = self._sq_off["array"]
            self._write_u32(self._sq_ring, arr_base + idx * 4, idx)
            # Publish the new tail so the kernel (or SQPOLL thread) can see it.
            self._write_u32(self._sq_ring, self._sq_off["tail"], tail + 1)
            self._pending_sqes += 1
        return True

    # ------------------------------------------------------------------
    # Public submit helpers
    # ------------------------------------------------------------------

    def _alloc_user_data(self) -> int:
        with self._lock:
            ud = self._next_user_data
            self._next_user_data = (ud + 1) & 0xFFFFFFFFFFFFFFFF
            if self._next_user_data == 0:
                self._next_user_data = 1
            return ud

    def submit_read(
        self,
        fd: int,
        buf: bytearray,
        offset: int = 0,
        user_data: Optional[int] = None,
    ) -> Optional[int]:
        """Queue IORING_OP_READ.

        ``buf`` must be a bytearray (or ctypes array) whose storage stays
        alive until the CQE lands.  We keep a reference in
        ``self._pinned`` to prevent premature GC.

        Returns the user_data handle, or None if the ring is full (caller
        should :meth:`drain` and retry).
        """
        if self._ring_fd < 0:
            return None
        if not isinstance(buf, (bytearray, memoryview)):
            raise TypeError("buf must be bytearray or memoryview")
        if user_data is None:
            user_data = self._alloc_user_data()
        # Get a stable address for the buffer.  ctypes.addressof needs a
        # c_char array view.
        try:
            view = (ctypes.c_char * len(buf)).from_buffer(buf)
            addr = ctypes.addressof(view)
        except TypeError:
            # memoryview path -- use buffer protocol via ctypes
            ba = bytearray(buf) if not isinstance(buf, bytearray) else buf
            view = (ctypes.c_char * len(ba)).from_buffer(ba)
            addr = ctypes.addressof(view)
            buf = ba
        if not self._prep_rw(IORING_OP_READ, fd, addr, len(buf), offset, user_data):
            return None
        # Pin both the buffer and the ctypes view so neither is GC'd
        # before the kernel finishes the DMA/copy.
        self._pinned[user_data] = (buf, view)
        return user_data

    def submit_nop(self, user_data: Optional[int] = None) -> Optional[int]:
        """Queue a NOP (useful for timeout / wake probes)."""
        if self._ring_fd < 0:
            return None
        if user_data is None:
            user_data = self._alloc_user_data()
        if not self._prep_rw(IORING_OP_NOP, -1, 0, 0, 0, user_data):
            return None
        return user_data

    # ------------------------------------------------------------------
    # Submit + drain
    # ------------------------------------------------------------------

    def submit(self, to_submit: Optional[int] = None, wait_for: int = 0) -> int:
        """Call io_uring_enter(2) to push prepared SQEs.

        Returns the kernel's reported ``submitted`` count.  With SQPOLL
        the kernel may already have picked them up; we still call enter
        when the SQ thread was idle (IORING_ENTER_SQ_WAKEUP).
        """
        if self._ring_fd < 0:
            return 0
        n = to_submit if to_submit is not None else self._pending_sqes
        flags = 0
        if wait_for > 0:
            flags |= IORING_ENTER_GETEVENTS
        if self._sqpoll:
            # Wake SQPOLL if it's asleep.  The kernel ignores this flag
            # when the thread is already running.
            flags |= IORING_ENTER_SQ_WAKEUP
        try:
            submitted = _syscall(
                _NR_io_uring_enter,
                self._ring_fd,
                n,
                wait_for,
                flags,
                0,  # sigmask
                0,  # sigmask_size
            )
        except OSError as e:
            # EAGAIN on full CQ when wait_for == 0 is fine -- drain later.
            if e.errno in (errno.EAGAIN, errno.EBUSY):
                return 0
            raise
        self._pending_sqes = max(0, self._pending_sqes - submitted)
        return submitted

    def drain(
        self,
        min_complete: Optional[int] = None,
        max_complete: Optional[int] = None,
    ) -> list[Completion]:
        """Submit pending SQEs then harvest completed CQEs.

        ``min_complete`` defaults to the number of in-flight SQEs (so
        "drain everything we queued").  ``max_complete`` caps the return
        size; anything beyond is left on the CQ for a subsequent drain.
        """
        if self._ring_fd < 0 or self._cq_ring is None:
            return []

        in_flight = self._pending_sqes + len(self._pinned)
        if min_complete is None:
            min_complete = in_flight
        # Belt-and-braces: can't wait for more than we queued.
        min_complete = min(min_complete, in_flight)

        # Push SQEs to the kernel and wait for `min_complete` CQEs.
        self.submit(wait_for=min_complete)

        completions: list[Completion] = []
        head = self._read_u32(self._cq_ring, self._cq_off["head"])
        cqes_base = self._cq_off["cqes"]
        mask = self._cq_mask()

        while True:
            tail = self._read_u32(self._cq_ring, self._cq_off["tail"])
            if head == tail:
                break
            idx = head & mask
            off = cqes_base + idx * _CQE_SIZE
            ud, res, flags = _CQE_LAYOUT.unpack_from(self._cq_ring, off)
            completions.append(Completion(user_data=ud, res=res, flags=flags))
            head += 1
            if max_complete is not None and len(completions) >= max_complete:
                break

        # Publish the new head so the kernel can reuse those CQE slots.
        self._write_u32(self._cq_ring, self._cq_off["head"], head)

        # Release pinned buffers for completed user_data.
        with self._lock:
            for c in completions:
                self._pinned.pop(c.user_data, None)

        return completions


# ---------------------------------------------------------------------------
# Batch helper: open + read a set of /proc files in one ring cycle
# ---------------------------------------------------------------------------

@dataclass
class _BatchEntry:
    path: str
    buf: bytearray
    fd: int
    user_data: int
    result: Optional[bytes] = None
    error: Optional[int] = None


def batch_read_proc_files(
    paths: list[str],
    buf_size: int = 8192,
    depth: int = 0,
    sqpoll: bool = False,
    sq_cpu: Optional[int] = None,
) -> dict[str, Optional[bytes]]:
    """Open + read each path via io_uring, return {path: content-or-None}.

    Designed for procfs: file size is unknown but bounded (``buf_size``
    default is 8 KiB, enough for ``/proc/<pid>/status`` and the head of
    most maps files).  Callers needing the full maps text should call
    this twice or use :class:`IOUring` directly.

    * ``None`` in the result dict means open-or-read failed (e.g. PID
      raced away -- common and not an error condition).
    * Short reads are returned truncated, same as synchronous ``read()``.

    The opens are still synchronous because io_uring's OP_OPENAT landed
    in 5.6 and its semantics w.r.t. to path lookup make portability
    painful.  procfs opens are fast (no disk I/O), so this is fine.

    On kernels that don't support io_uring, falls back to classic
    ``open().read()``.
    """
    if not paths:
        return {}

    # Fallback on hosts without io_uring.
    if not IOUring.available():
        result: dict[str, Optional[bytes]] = {}
        for p in paths:
            try:
                with open(p, "rb") as fh:
                    result[p] = fh.read(buf_size)
            except (OSError, PermissionError):
                result[p] = None
        return result

    if depth <= 0:
        # Size the ring to match the batch, up to a sane cap.
        depth = min(max(len(paths), 8), 256)
        # round up to power of two
        nd = 1
        while nd < depth:
            nd *= 2
        depth = nd

    entries: list[_BatchEntry] = []
    # Pre-open all fds.  Non-blocking on procfs.
    for p in paths:
        try:
            fd = os.open(p, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        except (OSError, PermissionError):
            entries.append(_BatchEntry(path=p, buf=bytearray(0), fd=-1,
                                       user_data=0, error=errno.ENOENT))
            continue
        entries.append(_BatchEntry(
            path=p, buf=bytearray(buf_size), fd=fd, user_data=0,
        ))

    result = {}
    try:
        ring = IOUring(depth=depth, sqpoll=sqpoll, sq_cpu=sq_cpu)
        ring._setup()
    except OSError as e:
        logger.debug("io_uring unavailable, synchronous fallback: %s", e)
        for e_ in entries:
            if e_.fd >= 0:
                try:
                    data = os.read(e_.fd, buf_size)
                except OSError:
                    data = None
                finally:
                    try:
                        os.close(e_.fd)
                    except OSError:
                        pass
                result[e_.path] = data
            else:
                result[e_.path] = None
        return result

    try:
        # Queue READ SQEs in batches of ``depth``, draining between
        # batches so a >depth input list still works.
        index = 0
        total = len(entries)
        while index < total:
            batch_start = index
            in_batch: list[_BatchEntry] = []
            while index < total and len(in_batch) < depth:
                ent = entries[index]
                index += 1
                if ent.fd < 0:
                    result[ent.path] = None
                    continue
                ud = ring.submit_read(ent.fd, ent.buf, offset=0)
                if ud is None:
                    # Ring full mid-batch -- drain and retry this entry.
                    index -= 1
                    break
                ent.user_data = ud
                in_batch.append(ent)

            if not in_batch:
                # All entries in this window errored; continue.
                continue

            # Drain this batch.  Map user_data -> entry for O(1) lookup.
            by_ud = {e.user_data: e for e in in_batch}
            completions = ring.drain(min_complete=len(in_batch))
            for c in completions:
                ent = by_ud.pop(c.user_data, None)
                if ent is None:
                    # Shouldn't happen -- stray CQE from a prior drain?
                    continue
                if c.ok:
                    # res == bytes read.  Truncate buf to actual length.
                    ent.result = bytes(ent.buf[:c.res])
                    result[ent.path] = ent.result
                else:
                    ent.error = c.err
                    result[ent.path] = None

            # Mop up any SQE that was submitted but not drained (very
            # unusual -- drain() waits for min_complete).
            for ud, ent in by_ud.items():
                result.setdefault(ent.path, None)

    finally:
        ring.close()
        for e_ in entries:
            if e_.fd >= 0:
                try:
                    os.close(e_.fd)
                except OSError:
                    pass

    return result


__all__ = [
    "IOUring",
    "Completion",
    "batch_read_proc_files",
    "IORING_SETUP_SQPOLL",
    "IORING_SETUP_SQ_AFF",
    "IORING_OP_READ",
    "IORING_OP_READV",
]
