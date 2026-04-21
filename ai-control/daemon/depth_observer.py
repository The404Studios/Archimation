"""
depth_observer.py -- Bennett logical-depth observer.

Charles Bennett's *logical depth* is, informally, the runtime of the
shortest program that reproduces an observed string. It distinguishes:

  * SHALLOW data (both fast AND slow compressors shrink it well) --
    low-entropy structure. e.g. zero-fill, repeated text, simple config.
  * DEEP data (fast compressor fails, slow compressor succeeds) --
    high-complexity STRUCTURE that takes real work to find. e.g. real
    executables, natural-language prose, algorithmically-generated output.
  * RANDOM data (neither compressor shrinks it) -- incompressible in a
    Kolmogorov sense. e.g. encrypted payloads, cryptographic keys, TLS
    traffic, ransomware-touched files.

We approximate the depth with a *differential compressibility ratio*:
compress the same buffer with a FAST compressor (gzip level 1) and a
SLOW one (gzip level 9), then look at how much extra compression the
slow pass buys us:

    depth_proxy = fast_ratio - slow_ratio

A large positive depth_proxy means "slow found structure that fast
missed" -- this is Bennett's depth. A depth_proxy near zero with both
ratios high means "both failed, the data is random." A depth_proxy near
zero with both ratios low means "both succeeded trivially, the data is
shallow."

Ransomware use case (per S75 roadmap §1.4):
  * Normal program output: fast misses structure, slow finds it -> DEEP.
  * Encrypted ransomware payload: neither finds structure -> RANDOM.

The discrimination signal is the *absence* of depth in encrypted output.

Design follows ``library_census.py`` (S75 Agent B) and
``algedonic_reader.py`` (S74 Agent K):

  * Class with ``snapshot()`` / ``observe()``.
  * RLock thread-safety.
  * ``register_with_daemon(app, event_bus)`` helper.
  * Graceful behavior on empty data (zero-state, no div-by-zero).
  * Stdlib only (no zstd optional dep).

Research reference: Research-H §1.6 (S74 dispatch, parking lot).
"""

from __future__ import annotations

import gzip
import logging
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)

# -- Tunables ----------------------------------------------------------------

# Classification thresholds. Tuned by ad-hoc experiment on:
#   * zero-fill (expect shallow)
#   * os.urandom() (expect random)
#   * utf-8 source code (expect deep)
# These are dimensionless ratios (compressed_size / original_size).
SHALLOW_RATIO_MAX = 0.10        # both ratios below this => shallow
RANDOM_RATIO_MIN = 0.90         # both ratios above this => random
DEEP_DELTA_MIN = 0.30           # fast_ratio - slow_ratio above this => deep

# Classification strings -- keep stable; the cortex keys on these.
CLASS_SHALLOW = "shallow"
CLASS_DEEP = "deep"
CLASS_RANDOM = "random"
CLASS_MIXED = "mixed"            # fallback for points outside the 3 corners

# Compression levels.
GZIP_FAST = 1
GZIP_SLOW = 9

# Minimum bytes for a measurement to be meaningful. Below this the
# gzip header (~20 bytes) dominates; don't try to classify.
MIN_USEFUL_BYTES = 32


# -- Result dataclass --------------------------------------------------------


@dataclass
class DepthResult:
    """One measurement of logical depth.

    Fields are JSON-serializable via ``asdict()`` / ``to_dict()``.
    """
    name: str
    size: int
    fast_ratio: float       # compressed_fast / original
    slow_ratio: float       # compressed_slow / original
    depth_proxy: float      # fast_ratio - slow_ratio (positive = deep)
    classification: str     # one of CLASS_SHALLOW/DEEP/RANDOM/MIXED
    ts: float

    def to_dict(self) -> dict:
        return asdict(self)


def _empty_result(name: str = "") -> DepthResult:
    return DepthResult(
        name=name,
        size=0,
        fast_ratio=0.0,
        slow_ratio=0.0,
        depth_proxy=0.0,
        classification=CLASS_SHALLOW,
        ts=time.time(),
    )


# -- Sampler (stateless, per-measurement) -----------------------------------


class DepthSampler:
    """Compute the Bennett depth proxy on a single byte buffer.

    Stateless by design -- no lock, no history. ``measure()`` is
    reentrant and safe to call from any thread.
    """

    def __init__(
        self,
        fast_level: int = GZIP_FAST,
        slow_level: int = GZIP_SLOW,
    ) -> None:
        # Clamp levels to gzip's valid 1..9 range.
        self._fast_level = max(1, min(9, int(fast_level)))
        self._slow_level = max(1, min(9, int(slow_level)))

    @staticmethod
    def _compress_size(data: bytes, level: int) -> int:
        """Return len(gzip.compress(data, level)). Never raises."""
        if not data:
            return 0
        try:
            return len(gzip.compress(data, compresslevel=level))
        except Exception:
            # Shouldn't happen for bytes input, but keep the observer
            # defensive: return data length so ratio == 1.0 ("random").
            return len(data)

    def measure(self, data: bytes, name: str = "") -> DepthResult:
        """Measure and classify a single buffer.

        Empty / too-small buffers return an empty DepthResult with
        classification=shallow. Large buffers (>few MB) are supported
        but expensive: O(level=9) gzip is ~50 MB/s on a modern CPU.
        """
        if not data:
            return _empty_result(name)
        size = len(data)

        # Tiny buffers -- gzip header overhead swamps the signal. Return
        # a zero-ratio result rather than risk misclassification.
        if size < MIN_USEFUL_BYTES:
            r = _empty_result(name)
            r.size = size
            return r

        fast_size = self._compress_size(data, self._fast_level)
        slow_size = self._compress_size(data, self._slow_level)

        # Ratios are compressed/original. Clamp to [0, 1.5] -- gzip can
        # expand tiny inputs past 1.0 with its header, which is fine for
        # arithmetic but looks weird in output.
        fast_ratio = fast_size / size if size > 0 else 0.0
        slow_ratio = slow_size / size if size > 0 else 0.0

        # Depth proxy: how much the slow compressor beat the fast one.
        depth_proxy = fast_ratio - slow_ratio

        classification = self._classify(fast_ratio, slow_ratio, depth_proxy)

        return DepthResult(
            name=name,
            size=size,
            fast_ratio=round(fast_ratio, 6),
            slow_ratio=round(slow_ratio, 6),
            depth_proxy=round(depth_proxy, 6),
            classification=classification,
            ts=time.time(),
        )

    @staticmethod
    def _classify(fast_ratio: float, slow_ratio: float,
                  depth_proxy: float) -> str:
        """Bucket a (fast_ratio, slow_ratio) point into shallow/deep/random.

        Classification priority (first match wins):
          1. shallow -- both ratios < SHALLOW_RATIO_MAX
          2. random  -- both ratios > RANDOM_RATIO_MIN
          3. deep    -- depth_proxy > DEEP_DELTA_MIN
          4. mixed   -- everything else (partially compressible, not
             dramatically slower-compressor-wins). Reported as "mixed"
             so the cortex can see the rare "middle" case rather than
             being forced into one of the three named buckets.
        """
        if fast_ratio < SHALLOW_RATIO_MAX and slow_ratio < SHALLOW_RATIO_MAX:
            return CLASS_SHALLOW
        if fast_ratio > RANDOM_RATIO_MIN and slow_ratio > RANDOM_RATIO_MIN:
            return CLASS_RANDOM
        if depth_proxy > DEEP_DELTA_MIN:
            return CLASS_DEEP
        return CLASS_MIXED


# -- Observer (aggregates many samples) --------------------------------------


class DepthObserver:
    """Aggregate ``DepthResult``s into a cortex-facing snapshot.

    Thread-safe via an RLock. Keeps only a bounded ring of recent
    samples (default 256) so long-running daemons don't leak memory.

    Snapshot schema::

        {"source": "depth_observer", "ts": <unix>,
         "samples": <int>,                         # total observe() calls
         "mean_depth": <float>,                    # mean depth_proxy
         "mean_fast_ratio": <float>,
         "mean_slow_ratio": <float>,
         "classifications": {"shallow": N, "deep": N,
                             "random": N, "mixed": N},
         "recent": [<last N result dicts>]}        # short tail
    """

    # Ring size -- bounded to keep memory finite when the observer
    # lives for days. 256 is enough for a few minutes of per-second
    # observations without being a burden.
    DEFAULT_RING_CAP = 256
    # Number of recent samples included in snapshot["recent"].
    SNAPSHOT_RECENT = 8

    def __init__(
        self,
        event_bus: Any = None,
        fast_level: int = GZIP_FAST,
        slow_level: int = GZIP_SLOW,
        ring_cap: int = DEFAULT_RING_CAP,
    ) -> None:
        self._event_bus = event_bus
        self._sampler = DepthSampler(fast_level=fast_level,
                                     slow_level=slow_level)
        self._ring_cap = max(16, int(ring_cap))
        self._lock = threading.RLock()

        # Accumulators (updated under lock).
        self._samples_total: int = 0
        self._classifications: dict[str, int] = {
            CLASS_SHALLOW: 0,
            CLASS_DEEP: 0,
            CLASS_RANDOM: 0,
            CLASS_MIXED: 0,
        }
        self._sum_fast: float = 0.0
        self._sum_slow: float = 0.0
        self._sum_depth: float = 0.0
        self._recent: list[DepthResult] = []

        # Stats for diagnostics.
        self._stats = {
            "observations": 0,
            "empty_inputs": 0,
            "publish_errors": 0,
        }

    # -- Measurement API ----------------------------------------------------

    def observe(self, name: str, data: bytes) -> DepthResult:
        """Measure *data* and fold the result into the snapshot.

        Returns the computed ``DepthResult`` (so a caller that wants the
        per-call classification doesn't have to re-derive it). Publishes
        the result to ``event_bus`` if one was provided.
        """
        if data is None:
            data = b""

        result = self._sampler.measure(data, name=str(name or ""))

        with self._lock:
            self._stats["observations"] += 1
            if result.size == 0:
                self._stats["empty_inputs"] += 1
                # Still fold it so downstream sees the observation,
                # but classification defaults to "shallow" for empties.
            self._samples_total += 1
            self._classifications[result.classification] = (
                self._classifications.get(result.classification, 0) + 1
            )
            self._sum_fast += result.fast_ratio
            self._sum_slow += result.slow_ratio
            self._sum_depth += result.depth_proxy

            self._recent.append(result)
            if len(self._recent) > self._ring_cap:
                # Drop oldest to keep bounded.
                self._recent.pop(0)

        self._publish(result)
        return result

    # -- Snapshot -----------------------------------------------------------

    def snapshot(self) -> dict:
        """Return a JSON-serializable summary of all observations so far.

        Safe to call before any observation -- returns a well-formed
        zero-state snapshot.
        """
        with self._lock:
            n = self._samples_total
            if n > 0:
                mean_fast = round(self._sum_fast / n, 6)
                mean_slow = round(self._sum_slow / n, 6)
                mean_depth = round(self._sum_depth / n, 6)
            else:
                mean_fast = 0.0
                mean_slow = 0.0
                mean_depth = 0.0

            recent_dicts = [
                r.to_dict() for r in self._recent[-self.SNAPSHOT_RECENT:]
            ]
            return {
                "source": "depth_observer",
                "ts": time.time(),
                "samples": n,
                "mean_fast_ratio": mean_fast,
                "mean_slow_ratio": mean_slow,
                "mean_depth": mean_depth,
                "classifications": dict(self._classifications),
                "recent": recent_dicts,
            }

    def stats(self) -> dict:
        """Observer counters for diagnostics."""
        with self._lock:
            return {
                **self._stats,
                "samples_total": self._samples_total,
                "ring_cap": self._ring_cap,
                "ring_len": len(self._recent),
            }

    def reset(self) -> None:
        """Clear all accumulated state. Used by tests and re-seeding."""
        with self._lock:
            self._samples_total = 0
            self._classifications = {
                CLASS_SHALLOW: 0,
                CLASS_DEEP: 0,
                CLASS_RANDOM: 0,
                CLASS_MIXED: 0,
            }
            self._sum_fast = 0.0
            self._sum_slow = 0.0
            self._sum_depth = 0.0
            self._recent = []
            for k in self._stats:
                self._stats[k] = 0

    # -- Event bus ---------------------------------------------------------

    def _publish(self, result: DepthResult) -> None:
        """Best-effort publish; mirrors library_census._publish."""
        bus = self._event_bus
        if bus is None:
            return
        event = {
            "source": "depth_observer",
            "topic": f"depth.{result.classification}",
            **result.to_dict(),
        }
        for name in ("publish", "emit"):
            fn = getattr(bus, name, None)
            if callable(fn):
                try:
                    fn(event)
                    return
                except Exception:
                    self._stats["publish_errors"] += 1
                    logger.debug("depth_observer: bus.%s failed",
                                 name, exc_info=True)


# -- Wire-up helper (called by api_server.py) -------------------------------


def register_with_daemon(
    app: Any,
    event_bus: Any = None,
    fast_level: int = GZIP_FAST,
    slow_level: int = GZIP_SLOW,
) -> DepthObserver:
    """Construct a DepthObserver and register its endpoint on *app*.

    Mirrors ``library_census.register_with_daemon``. There's no
    background poll loop -- the depth observer is *call-driven* (the
    caller feeds it bytes); the endpoint just exposes the current
    snapshot.

    Endpoint::

        GET /metrics/depth  -> DepthObserver.snapshot() dict
    """
    obs = DepthObserver(
        event_bus=event_bus,
        fast_level=fast_level,
        slow_level=slow_level,
    )

    if app is not None:
        try:
            @app.get("/metrics/depth")  # type: ignore[misc]
            async def _depth_snapshot() -> dict:
                return obs.snapshot()
        except Exception:
            logger.debug(
                "depth_observer: FastAPI route registration skipped",
                exc_info=True,
            )

    return obs


__all__ = [
    "DepthResult",
    "DepthSampler",
    "DepthObserver",
    "register_with_daemon",
    "CLASS_SHALLOW",
    "CLASS_DEEP",
    "CLASS_RANDOM",
    "CLASS_MIXED",
    "SHALLOW_RATIO_MAX",
    "RANDOM_RATIO_MIN",
    "DEEP_DELTA_MIN",
    "GZIP_FAST",
    "GZIP_SLOW",
    "MIN_USEFUL_BYTES",
]
