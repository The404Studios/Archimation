"""
Behavioral Markov n-gram Module -- Sequence-anomaly detection for PE processes.

Per-PID Markov n-gram (default n=3) over syscall sequences. Static binary
signatures recognise *what* a binary is; this module recognises *what it's
doing* by modeling syscall transition probabilities and flagging large
divergences from the per-PID baseline.

The model is self-calibrating: it learns from the same stream it scores
against, then anomaly_score() compares the recent log-likelihood to the
running mean+stdev of the PID's own past log-likelihoods. No global
"normal" prior is assumed -- a process that always fork/execs is normal
*for that PID*.

Memory bounded:
  - per-PID n-gram table capped at ``max_ngrams`` keys (oldest evicted)
  - per-key successor counter capped at 256 distinct successors
  - per-PID rolling syscall window capped at 512 entries
  - global PID table capped via gc(max_pids=256) (LRU on last-touch)

Pure stdlib (no scipy/numpy). Thread-safety: a single re-entrant lock
guards all mutation; reads of the singleton are consistent under the
GIL for primitive ops.

Hook surface for syscall_monitor.py:
    attach_to_observer(observer)
    -> wraps observer's per-event callsite with `model.observe(pid, name)`.

If the observer doesn't expose a hook, the singleton remains usable;
callers can poke it directly via ``get_model().observe(pid, syscall)``.
"""

from __future__ import annotations

import collections
import logging
import math
import threading
import time
from typing import Callable, Deque, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("ai-control.behavioral_markov")

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

DEFAULT_N = 3
DEFAULT_MAX_NGRAMS = 4096
DEFAULT_MAX_SUCCESSORS = 256
DEFAULT_WINDOW_LEN = 512
DEFAULT_SCORE_HISTORY = 64
DEFAULT_MAX_PIDS = 256
DEFAULT_SMOOTHING = 0.01     # Laplace-style alpha for unseen transitions

# Syscall names we expect from syscall_monitor.SYSCALL_NAMES; the model
# is name-agnostic so anything hashable works (strings or ints).
NGramKey = Tuple[str, ...]


# ---------------------------------------------------------------------------
# Per-PID state
# ---------------------------------------------------------------------------


class _PerPIDState:
    """All learning + scoring state for one PID. Kept out of the public API."""

    __slots__ = (
        "window", "ngram_counts", "ngram_totals", "ngram_order",
        "score_history", "total_observations", "last_touch",
    )

    def __init__(self, window_len: int):
        # Most-recent syscalls; deque maxlen does the eviction.
        self.window: Deque[str] = collections.deque(maxlen=window_len)
        # n-gram prefix -> Counter of next-syscall counts
        self.ngram_counts: Dict[NGramKey, collections.Counter] = {}
        # Cached prefix totals for fast P() denominators
        self.ngram_totals: Dict[NGramKey, int] = {}
        # FIFO of insertion order, for cap-and-evict on n-gram explosion
        self.ngram_order: Deque[NGramKey] = collections.deque()
        # Recent log-likelihoods, for anomaly z-score normalisation
        self.score_history: Deque[float] = collections.deque(maxlen=DEFAULT_SCORE_HISTORY)
        self.total_observations: int = 0
        self.last_touch: float = time.monotonic()


# ---------------------------------------------------------------------------
# Public model
# ---------------------------------------------------------------------------


class SyscallNGramModel:
    """Per-PID Markov n-gram model over syscall sequences.

    See module docstring for the algorithm. Public API:
        observe(pid, syscall) -> None
        log_likelihood(pid, window=32) -> float
        anomaly_score(pid) -> float in [0, 1]
        export(pid) -> dict (telemetry-friendly summary)
        gc(max_pids=256) -> int (PIDs evicted)
    """

    def __init__(
        self,
        n: int = DEFAULT_N,
        max_ngrams: int = DEFAULT_MAX_NGRAMS,
        smoothing: float = DEFAULT_SMOOTHING,
        max_successors: int = DEFAULT_MAX_SUCCESSORS,
        window_len: int = DEFAULT_WINDOW_LEN,
    ):
        if n < 2:
            raise ValueError("n must be >= 2 (need at least one prefix syscall)")
        if smoothing <= 0.0:
            raise ValueError("smoothing must be > 0 to keep log() finite")
        self.n = int(n)
        self.max_ngrams = int(max_ngrams)
        self.max_successors = int(max_successors)
        self.window_len = int(window_len)
        self.smoothing = float(smoothing)
        self._states: Dict[int, _PerPIDState] = {}
        # Re-entrant: anomaly_score() calls log_likelihood() under the same lock.
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Observation
    # ------------------------------------------------------------------

    def observe(self, pid: int, syscall: str) -> None:
        """Record one syscall event for ``pid``.

        Updates the rolling window and n-gram transition counts. Cheap:
        O(1) amortised plus an occasional eviction sweep when n-gram
        cardinality exceeds ``max_ngrams``.
        """
        if syscall is None:
            return
        # Coerce to a hashable string -- accept ints (raw syscall_nr) too.
        key = syscall if isinstance(syscall, str) else str(syscall)
        with self._lock:
            st = self._states.get(pid)
            if st is None:
                st = _PerPIDState(self.window_len)
                self._states[pid] = st

            st.window.append(key)
            st.total_observations += 1
            st.last_touch = time.monotonic()

            # Need at least n syscalls in the window to form an n-gram.
            if len(st.window) < self.n:
                return

            # Build (n-1)-prefix and observed successor.
            tail = list(st.window)[-self.n:]
            prefix: NGramKey = tuple(tail[:-1])
            succ = tail[-1]

            counter = st.ngram_counts.get(prefix)
            if counter is None:
                counter = collections.Counter()
                st.ngram_counts[prefix] = counter
                st.ngram_order.append(prefix)
                # Cap n-gram cardinality to bound memory.
                while len(st.ngram_counts) > self.max_ngrams and st.ngram_order:
                    victim = st.ngram_order.popleft()
                    victim_ctr = st.ngram_counts.pop(victim, None)
                    if victim_ctr is not None:
                        st.ngram_totals.pop(victim, None)

            # Cap successor cardinality per prefix.
            if succ not in counter and len(counter) >= self.max_successors:
                # Drop the rarest successor to make room.
                rarest, _ = min(counter.items(), key=lambda kv: kv[1])
                old = counter.pop(rarest, 0)
                st.ngram_totals[prefix] = st.ngram_totals.get(prefix, 0) - old

            counter[succ] += 1
            st.ngram_totals[prefix] = st.ngram_totals.get(prefix, 0) + 1

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def log_likelihood(self, pid: int, window: int = 32) -> float:
        """Mean log P(syscall_t | prefix) over the last ``window`` syscalls.

        Returns 0.0 if the PID is unknown or has fewer than n syscalls.
        Smoothing keeps every log() finite even for unseen transitions.
        """
        with self._lock:
            st = self._states.get(pid)
            if st is None or len(st.window) < self.n:
                return 0.0
            # Slice the trailing window; we need at least n entries to score one
            # transition, so widen the slice by (n-1) prefix syscalls.
            cap = max(self.n, int(window) + (self.n - 1))
            recent = list(st.window)[-cap:]
            if len(recent) < self.n:
                return 0.0

            total_lp = 0.0
            count = 0
            alpha = self.smoothing
            # Vocabulary size for smoothing denominator. We approximate it as
            # the count of *distinct successors ever seen* across all prefixes;
            # this is a conservative upper bound that keeps probabilities valid.
            vocab = self._approx_vocab_size(st)
            if vocab <= 0:
                vocab = 1

            for i in range(self.n - 1, len(recent)):
                prefix = tuple(recent[i - (self.n - 1):i])
                succ = recent[i]
                counter = st.ngram_counts.get(prefix)
                if counter is None:
                    # Totally novel prefix -> uniform smoothed prior
                    p = alpha / (alpha * vocab)
                else:
                    seen = counter.get(succ, 0)
                    denom = st.ngram_totals.get(prefix, sum(counter.values())) + alpha * vocab
                    p = (seen + alpha) / denom
                # log(p) is well-defined: alpha > 0 and vocab >= 1.
                total_lp += math.log(p)
                count += 1

            if count == 0:
                return 0.0
            mean_lp = total_lp / count
            # Track for anomaly normalisation.
            st.score_history.append(mean_lp)
            return mean_lp

    def anomaly_score(self, pid: int) -> float:
        """Normalised anomaly score in [0, 1]: 0=baseline, 1=highly anomalous.

        Compares the *current* log-likelihood against the running
        mean+stdev of this PID's own past log-likelihoods. Z-score is
        squashed via tanh on the absolute value of the negative side
        (only "less likely than usual" counts as anomalous; better-than-
        usual is still 0).
        """
        with self._lock:
            st = self._states.get(pid)
            if st is None:
                return 0.0
            current = self.log_likelihood(pid)
            history = list(st.score_history)
            # Need a few historical points before the score is meaningful.
            if len(history) < 4:
                return 0.0
            mean = sum(history) / len(history)
            var = sum((x - mean) ** 2 for x in history) / len(history)
            stdev = math.sqrt(var) if var > 0 else 0.0
            if stdev < 1e-9:
                # No variance yet -> any deviation is undefined; report 0.
                return 0.0
            # Negative z = current more negative than baseline = anomalous.
            z = (current - mean) / stdev
            if z >= 0:
                return 0.0
            # tanh squash gives a smooth 0..1 mapping; |z|=1 -> 0.46, |z|=2 -> 0.76.
            return float(math.tanh(abs(z) / 2.0))

    # ------------------------------------------------------------------
    # Telemetry
    # ------------------------------------------------------------------

    def export(self, pid: int) -> Dict:
        """Serializable summary for telemetry and behavioral_model integration."""
        with self._lock:
            st = self._states.get(pid)
            if st is None:
                return {
                    "pid": pid,
                    "n": self.n,
                    "total_observations": 0,
                    "unique_ngrams": 0,
                    "recent_anomaly_score": 0.0,
                    "top_5_transitions": [],
                }
            # Compute top transitions by frequency across the whole table.
            flat: List[Tuple[NGramKey, str, int]] = []
            for prefix, ctr in st.ngram_counts.items():
                for succ, cnt in ctr.items():
                    flat.append((prefix, succ, cnt))
            flat.sort(key=lambda t: t[2], reverse=True)
            top5 = [
                {
                    "prefix": list(prefix),
                    "next": succ,
                    "count": cnt,
                }
                for prefix, succ, cnt in flat[:5]
            ]
            return {
                "pid": pid,
                "n": self.n,
                "total_observations": st.total_observations,
                "unique_ngrams": len(st.ngram_counts),
                "recent_anomaly_score": round(self.anomaly_score(pid), 4),
                "top_5_transitions": top5,
            }

    # ------------------------------------------------------------------
    # Eviction / GC
    # ------------------------------------------------------------------

    def gc(self, max_pids: int = DEFAULT_MAX_PIDS) -> int:
        """Bound memory by LRU-evicting cold PIDs. Returns count evicted."""
        evicted = 0
        with self._lock:
            if len(self._states) <= max_pids:
                return 0
            # Sort PIDs by last_touch ascending; oldest first.
            ranked = sorted(
                self._states.items(),
                key=lambda kv: kv[1].last_touch,
            )
            to_drop = len(self._states) - max_pids
            for pid, _ in ranked[:to_drop]:
                self._states.pop(pid, None)
                evicted += 1
        if evicted:
            logger.debug("Markov GC evicted %d cold PIDs", evicted)
        return evicted

    def forget(self, pid: int) -> bool:
        """Drop all state for a PID (e.g., on process exit)."""
        with self._lock:
            return self._states.pop(pid, None) is not None

    def tracked_pids(self) -> List[int]:
        with self._lock:
            return list(self._states.keys())

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _approx_vocab_size(st: _PerPIDState) -> int:
        """Distinct successor symbols across all n-gram prefixes."""
        seen = set()
        for ctr in st.ngram_counts.values():
            seen.update(ctr.keys())
        return len(seen)


# ---------------------------------------------------------------------------
# Process-wide singleton
# ---------------------------------------------------------------------------

_singleton_lock = threading.Lock()
_singleton: Optional[SyscallNGramModel] = None


def get_model() -> SyscallNGramModel:
    """Return the process-wide SyscallNGramModel singleton (lazy-init)."""
    global _singleton
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                _singleton = SyscallNGramModel()
    return _singleton


def reset_singleton() -> None:
    """Test-only: drop the singleton so a fresh one is created next call."""
    global _singleton
    with _singleton_lock:
        _singleton = None


# ---------------------------------------------------------------------------
# Observer attachment
# ---------------------------------------------------------------------------


def attach_to_observer(observer) -> bool:
    """Register the singleton as a syscall sink on ``observer``.

    The syscall monitor in this codebase doesn't currently expose a
    formal "subscribe" hook; it appends events to per-PID profiles via
    ``ProcessSyscallProfile.add_event``. We support three integration
    modes, in order of preference:

        1. ``observer.add_syscall_callback(callable)`` if it exists.
        2. ``observer.on_syscall_event = callable`` attribute slot.
        3. Monkey-patch ``ProcessSyscallProfile.add_event`` to also feed us.

    Returns True if attachment succeeded, False otherwise. Safe to call
    multiple times -- attaches at most one feeder.
    """
    model = get_model()

    # Mode 1: explicit callback registration API.
    add_cb = getattr(observer, "add_syscall_callback", None)
    if callable(add_cb):
        try:
            add_cb(_make_event_callback(model))
            logger.info("behavioral_markov attached via add_syscall_callback()")
            return True
        except Exception as e:
            logger.warning("add_syscall_callback failed: %s", e)

    # Mode 2: single callback attribute.
    if hasattr(observer, "on_syscall_event"):
        try:
            observer.on_syscall_event = _make_event_callback(model)
            logger.info("behavioral_markov attached via on_syscall_event")
            return True
        except Exception as e:
            logger.warning("on_syscall_event assign failed: %s", e)

    # Mode 3: monkey-patch ProcessSyscallProfile.add_event. Idempotent.
    try:
        from syscall_monitor import ProcessSyscallProfile  # type: ignore
    except Exception:
        try:
            from daemon.syscall_monitor import ProcessSyscallProfile  # type: ignore
        except Exception:
            ProcessSyscallProfile = None  # type: ignore[assignment]

    if ProcessSyscallProfile is not None:
        if getattr(ProcessSyscallProfile.add_event, "_markov_wrapped", False):
            return True  # already wrapped
        original = ProcessSyscallProfile.add_event

        def add_event_wrapped(self, event):  # type: ignore[no-redef]
            try:
                model.observe(event.pid, event.linux_name)
            except Exception:
                # Never let the markov sink break the syscall monitor.
                logger.exception("markov observe() raised; swallowing")
            return original(self, event)

        add_event_wrapped._markov_wrapped = True  # type: ignore[attr-defined]
        ProcessSyscallProfile.add_event = add_event_wrapped  # type: ignore[assignment]
        logger.info("behavioral_markov attached via ProcessSyscallProfile patch")
        return True

    logger.warning("behavioral_markov: no observer hook available; "
                   "callers must invoke get_model().observe() directly")
    return False


def _make_event_callback(model: SyscallNGramModel) -> Callable:
    """Build a callback that accepts either (pid, name) or a SyscallEvent."""
    def _cb(*args, **kwargs):
        try:
            if len(args) == 1 and hasattr(args[0], "pid") and hasattr(args[0], "linux_name"):
                ev = args[0]
                model.observe(ev.pid, ev.linux_name)
            elif len(args) >= 2:
                model.observe(args[0], args[1])
            elif "pid" in kwargs and "syscall" in kwargs:
                model.observe(kwargs["pid"], kwargs["syscall"])
        except Exception:
            logger.exception("markov callback failed; swallowing")
    return _cb


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------


def _smoke_train_normal(model: SyscallNGramModel, pid: int, count: int = 100) -> None:
    """Inject a normal open/read/close-style sequence."""
    pattern = ["openat", "read", "read", "read", "close",
               "openat", "fstat", "read", "close",
               "openat", "read", "lseek", "read", "close"]
    for i in range(count):
        model.observe(pid, pattern[i % len(pattern)])


def _smoke_train_anomaly(model: SyscallNGramModel, pid: int, count: int = 10) -> None:
    """Inject an anomalous mmap/exec/fork sequence."""
    pattern = ["mmap", "mprotect", "execve", "fork", "clone",
               "ptrace", "kill", "mprotect", "execve", "clone"]
    for i in range(count):
        model.observe(pid, pattern[i % len(pattern)])


def _smoke_test() -> None:
    print("=== behavioral_markov smoke test ===")
    reset_singleton()
    model = get_model()

    pids = [1001, 1002, 1003]
    print(f"Training {len(pids)} PIDs on 100 normal syscalls each...")
    for pid in pids:
        _smoke_train_normal(model, pid, count=100)

    print("\n[BASELINE] After 100 normal syscalls:")
    baseline_scores = {}
    for pid in pids:
        ll = model.log_likelihood(pid)
        # Need to populate score_history for anomaly_score to be meaningful.
        for _ in range(8):
            model.log_likelihood(pid)
        score = model.anomaly_score(pid)
        baseline_scores[pid] = score
        print(f"  PID {pid}: log_likelihood={ll:+.4f}  anomaly_score={score:.4f}")

    print(f"\nInjecting 10 anomalous syscalls (mmap/exec/fork pattern) on PID {pids[0]}...")
    _smoke_train_anomaly(model, pids[0], count=10)

    print("\n[AFTER] Anomaly injection:")
    after_scores = {}
    for pid in pids:
        ll = model.log_likelihood(pid)
        score = model.anomaly_score(pid)
        after_scores[pid] = score
        delta = score - baseline_scores[pid]
        flag = " <-- INJECTED" if pid == pids[0] else ""
        print(f"  PID {pid}: log_likelihood={ll:+.4f}  anomaly_score={score:.4f}  "
              f"(delta {delta:+.4f}){flag}")

    print("\n[EXPORT] Telemetry summary for injected PID:")
    summary = model.export(pids[0])
    print(f"  total_observations: {summary['total_observations']}")
    print(f"  unique_ngrams:      {summary['unique_ngrams']}")
    print(f"  recent_anomaly:     {summary['recent_anomaly_score']}")
    print(f"  top_5_transitions:")
    for t in summary["top_5_transitions"]:
        print(f"    {t['prefix']} -> {t['next']}  (count={t['count']})")

    print("\n[GC] Adding 300 cold PIDs and running gc(max_pids=256)...")
    for fake_pid in range(2000, 2300):
        model.observe(fake_pid, "read")
    evicted = model.gc(max_pids=256)
    print(f"  evicted: {evicted}  remaining: {len(model.tracked_pids())}")

    rose = after_scores[pids[0]] > baseline_scores[pids[0]]
    print(f"\nResult: anomaly_score rose on injected PID? {rose}")
    print("=== smoke test done ===")


if __name__ == "__main__":
    _smoke_test()
