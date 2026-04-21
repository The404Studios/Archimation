"""
Entropy observer — S74 Agent 7 (Cluster 3: Shannon + Kolmogorov + Bennett).

Periodically walks /proc/<pid>/maps for trust-tagged subjects (or the full
process table as a fallback), samples each executable / anonymous region, and
publishes three information-theoretic scalars to the cortex:

  * Shannon entropy (bits/byte) of the sampled bytes
  * zlib level-1 compressibility ratio — a Kolmogorov-proxy à la Bennett
  * Normalised Compression Distance (NCD) vs. a per-path cached baseline —
    the first sighting of a given realpath *is* the baseline; subsequent
    samples are compared against it

Emitted event (dict; agent 10 routes it to the event bus):

    {
        "source":         "entropy",
        "pid":            int,
        "region":         str,           # /proc/<pid>/maps address range
        "path":           str,           # backing file or "[anon]"
        "entropy_bits":   float,         # 0.0 – 8.0
        "compressibility": float,        # 0.0 – ~1.0
        "ncd_baseline":   float | None,  # None on first sighting
        "ts":             float,         # time.time()
    }

Deliberately read-only, fail-soft, and cheap: one 4 KiB read per region,
one zlib pass, one Counter pass.  Budget: <30 ms per subject on commodity HW.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import time
import zlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger("aicontrol.entropy_observer")

SAMPLE_BYTES = 4096
DEFAULT_INTERVAL = 30.0  # seconds
MAX_BASELINES = 1024
MAX_SUBJECTS_PER_TICK = 64


@dataclass
class _Baseline:
    """Cached first-sighting sample used as the NCD reference for a path."""
    sample: bytes
    comp_len: int
    ts: float


@dataclass
class EntropyStats:
    ticks: int = 0
    events_emitted: int = 0
    read_errors: int = 0
    regions_scanned: int = 0
    baselines: int = 0


def shannon_entropy_bits(data: bytes) -> float:
    """Shannon entropy in bits/byte.  Zero for empty input."""
    n = len(data)
    if n == 0:
        return 0.0
    counts = Counter(data)
    # H = -sum(p * log2(p)) over observed bytes (0 * log 0 convention)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def compressibility(data: bytes) -> float:
    """zlib level-1 ratio: compressed / raw.  Lower = more redundant."""
    if not data:
        return 0.0
    return len(zlib.compress(data, 1)) / len(data)


def ncd(x: bytes, y: bytes) -> float:
    """
    Normalised Compression Distance (Cilibrasi & Vitanyi 2005):

        NCD(x,y) = (C(xy) - min(C(x),C(y))) / max(C(x),C(y))

    Returns 0.0 for identical inputs, ~1.0 for uncorrelated.
    """
    if not x or not y:
        return 1.0
    cx = len(zlib.compress(x, 1))
    cy = len(zlib.compress(y, 1))
    cxy = len(zlib.compress(x + y, 1))
    denom = max(cx, cy)
    if denom == 0:
        return 0.0
    return (cxy - min(cx, cy)) / denom


def _iter_maps(pid: int):
    """
    Yield (addr_range, perms, path) for each line of /proc/<pid>/maps.

    Silent on permission / disappearance errors — a subject may exit between
    enumeration and read.
    """
    try:
        with open(f"/proc/{pid}/maps", "r") as fh:
            for line in fh:
                parts = line.rstrip("\n").split(None, 5)
                if len(parts) < 5:
                    continue
                addr_range, perms = parts[0], parts[1]
                path = parts[5] if len(parts) == 6 else "[anon]"
                yield addr_range, perms, path
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return


def _read_region(pid: int, addr_range: str, nbytes: int = SAMPLE_BYTES) -> bytes:
    """
    Read up to *nbytes* from /proc/<pid>/mem at the region's base address.

    Requires CAP_SYS_PTRACE (or same-uid + ptrace_scope permissive) — falls
    back to empty bytes on EPERM / EIO, which is common for kernel-only or
    VVAR regions.
    """
    try:
        lo = int(addr_range.split("-", 1)[0], 16)
    except (ValueError, IndexError):
        return b""
    path = f"/proc/{pid}/mem"
    try:
        fd = os.open(path, os.O_RDONLY)
    except (OSError, PermissionError):
        return b""
    try:
        try:
            os.lseek(fd, lo, os.SEEK_SET)
            return os.read(fd, nbytes)
        except OSError:
            return b""
    finally:
        os.close(fd)


def _list_pids() -> list[int]:
    """All numeric /proc/<pid> entries.  Deterministic order."""
    out = []
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            out.append(int(entry))
    out.sort()
    return out


class EntropyObserver:
    """
    Async task that samples process memory and publishes entropy deltas.

    Observe-only; publishes via a callback list (agent 10 routes that list
    to the cortex event bus in api_server.py).
    """

    def __init__(
        self,
        interval: Optional[float] = None,
        trust_observer: Any = None,
        max_subjects: int = MAX_SUBJECTS_PER_TICK,
    ):
        env_iv = os.environ.get("AICONTROL_ENTROPY_INTERVAL")
        try:
            self._interval = float(env_iv) if env_iv else (interval or DEFAULT_INTERVAL)
        except ValueError:
            self._interval = DEFAULT_INTERVAL
        self._trust_observer = trust_observer
        self._max_subjects = max_subjects

        self._baselines: dict[str, _Baseline] = {}
        self._callbacks: list[Callable[[dict], None]] = []
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self.stats = EntropyStats()

    # ── Lifecycle ──

    def add_callback(self, cb: Callable[[dict], None]) -> None:
        """Register an async-or-sync callback invoked for each emitted event."""
        self._callbacks.append(cb)

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("EntropyObserver started (interval=%.1fs)", self._interval)

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info(
            "EntropyObserver stopped: ticks=%d emitted=%d errors=%d baselines=%d",
            self.stats.ticks, self.stats.events_emitted,
            self.stats.read_errors, self.stats.baselines,
        )

    # ── Sampling ──

    def _subject_pids(self) -> list[int]:
        """Prefer trust-tagged subjects; fall back to /proc scan."""
        if self._trust_observer is not None:
            try:
                subs = self._trust_observer.get_all_subjects()
                pids = [s["subject_id"] for s in subs if s.get("subject_id")]
                if pids:
                    return pids[: self._max_subjects]
            except Exception:
                logger.debug("trust_observer.get_all_subjects() failed — falling back")
        return _list_pids()[: self._max_subjects]

    def _sample_one(self, pid: int) -> list[dict]:
        """Return list of event dicts for a single pid."""
        out: list[dict] = []
        for addr_range, perms, path in _iter_maps(pid):
            # Only interesting regions: executable OR anonymous (heap/stack/JIT)
            is_exec = "x" in perms
            is_anon = path in ("[anon]", "[heap]", "[stack]") or path.startswith("[anon")
            if not (is_exec or is_anon):
                continue

            sample = _read_region(pid, addr_range, SAMPLE_BYTES)
            self.stats.regions_scanned += 1
            if not sample:
                self.stats.read_errors += 1
                continue

            h = shannon_entropy_bits(sample)
            c = compressibility(sample)

            key = os.path.realpath(path) if path not in ("[anon]", "[heap]", "[stack]") else f"{pid}:{path}"
            ncd_val: Optional[float] = None
            base = self._baselines.get(key)
            if base is None:
                # First sighting — *is* the baseline
                if len(self._baselines) < MAX_BASELINES:
                    self._baselines[key] = _Baseline(
                        sample=sample, comp_len=len(zlib.compress(sample, 1)),
                        ts=time.time(),
                    )
                    self.stats.baselines += 1
            else:
                ncd_val = ncd(base.sample, sample)

            out.append({
                "source": "entropy",
                "pid": pid,
                "region": addr_range,
                "path": path,
                "entropy_bits": round(h, 4),
                "compressibility": round(c, 4),
                "ncd_baseline": None if ncd_val is None else round(ncd_val, 4),
                "ts": time.time(),
            })
        return out

    def _emit(self, event: dict) -> None:
        self.stats.events_emitted += 1
        for cb in self._callbacks:
            try:
                r = cb(event)
                if asyncio.iscoroutine(r):
                    asyncio.create_task(r)  # fire-and-forget async callbacks
            except Exception:
                logger.exception("entropy observer callback error")

    async def _loop(self) -> None:
        loop = asyncio.get_running_loop()
        while self._running:
            try:
                self.stats.ticks += 1
                pids = self._subject_pids()
                for pid in pids:
                    # Offload the syscall-heavy sampling to a thread so we
                    # don't stall the event loop for slow /proc reads.
                    events = await loop.run_in_executor(None, self._sample_one, pid)
                    for ev in events:
                        self._emit(ev)
                await asyncio.sleep(self._interval)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("entropy observer tick error")
                await asyncio.sleep(self._interval)

    # ── REST-facing snapshot ──

    async def entropy_snapshot(self) -> dict:
        """
        One-shot snapshot used by the api_server GET handler.

        Returns current stats plus the most recent per-path entropy summary
        derived from the baseline cache (no fresh sampling — keep this cheap).
        """
        return {
            "interval_s": self._interval,
            "stats": {
                "ticks": self.stats.ticks,
                "events_emitted": self.stats.events_emitted,
                "read_errors": self.stats.read_errors,
                "regions_scanned": self.stats.regions_scanned,
                "baselines": self.stats.baselines,
            },
            "baselines": [
                {
                    "path": p,
                    "baseline_entropy_bits": round(shannon_entropy_bits(b.sample), 4),
                    "baseline_comp_ratio": round(b.comp_len / max(len(b.sample), 1), 4),
                    "ts": b.ts,
                }
                for p, b in list(self._baselines.items())[:64]
            ],
            "ts": time.time(),
        }


# ── Wire-up helper (called by agent 10 from api_server.py) ──

def register_with_daemon(app, event_bus, trust_observer=None) -> EntropyObserver:
    """
    Construct an EntropyObserver, wire its emissions to *event_bus* (if the
    bus exposes a ``publish``-style fan-out), register the REST handler on
    *app*, and return the observer.  Caller owns ``start()`` / ``stop()``.

    *event_bus* may be an EventBus instance or any object with a callable
    attribute named ``publish``, ``emit``, or ``on_all`` — we fail soft if
    none exist and simply log the event at debug level.
    """
    obs = EntropyObserver(trust_observer=trust_observer)

    def _fanout(event: dict) -> None:
        for name in ("publish", "emit"):
            fn = getattr(event_bus, name, None)
            if callable(fn):
                try:
                    fn(event)
                    return
                except Exception:
                    logger.debug("event_bus.%s failed", name)
        logger.debug("entropy event (no bus sink): %s", event)

    obs.add_callback(_fanout)

    if app is not None:
        try:
            app.add_api_route(
                "/cortex/entropy/snapshot", obs.entropy_snapshot, methods=["GET"],
            )
        except Exception:
            logger.debug("FastAPI route registration skipped")
    return obs


__all__ = [
    "EntropyObserver",
    "register_with_daemon",
    "shannon_entropy_bits",
    "compressibility",
    "ncd",
]
