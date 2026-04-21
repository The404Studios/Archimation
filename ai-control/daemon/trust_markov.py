"""Discrete Markov chain over trust bands.

States: 5 named bands { USER=100, INTERACT=200, OPERATOR=400, ADMIN=600,
KERNEL=800 } plus an absorbing APOPTOSIS state at band-index 0 (below USER).

Used by the cortex / daemon to forecast a subject's expected time to
apoptosis from its observed band-transition history.  Pure stdlib; all
math implemented directly (6x6 matrices, hand-rolled power iteration
and (I-Q)^-1 for hitting times).

NOTE on KERNEL band value:
    The canonical band ladder in auth.py defines TRUST_KERNEL=900, but for
    the purposes of THIS Markov model we collapse it to 800 because the
    [800, 1000] kernel-only region is operationally a single absorbing
    "system" state -- subjects in [600, 1000] all map to the ADMIN/KERNEL
    bucket here.  See docstring of ``score_to_band_idx`` for thresholds.

Public API used by cortex / daemon:
    observe_score(subject_id, prev_score, next_score)
    forecast(subject_id, current_score)         -> dict for telemetry
    get_chain(subject_id)                        -> TrustMarkovChain
"""

from __future__ import annotations

import math
import threading
from collections import OrderedDict, defaultdict
from typing import Dict, List, Optional, Tuple

# ----- Band layout (mirrored from auth.py; KERNEL collapsed to 800) -----
TRUST_BANDS: List[int] = [0, 100, 200, 400, 600, 800]
BAND_NAMES: List[str] = ["APOPTOSIS", "USER", "INTERACT", "OPERATOR",
                         "ADMIN", "KERNEL"]
N_STATES: int = 6
ABSORBING_STATE: int = 0  # APOPTOSIS index

# In-memory cap for per-subject chains.  Beyond this, LRU evict.
_MAX_CHAINS: int = 1024

INF: float = float("inf")


def score_to_band_idx(score: float) -> int:
    """Map a continuous trust score to a band index 0..5.

    score < 100        -> 0 (APOPTOSIS)
    100 <= score < 200 -> 1 (USER)
    200 <= score < 400 -> 2 (INTERACT)
    400 <= score < 600 -> 3 (OPERATOR)
    600 <= score < 800 -> 4 (ADMIN)
    score >= 800       -> 5 (KERNEL)

    NaN / non-finite is treated as APOPTOSIS (worst-case).
    """
    if not isinstance(score, (int, float)) or math.isnan(score) or math.isinf(score):
        # Treat NaN as apoptosis; +inf as KERNEL (the only finite-overflow
        # path that might reasonably mean "max trust").
        if isinstance(score, float) and math.isinf(score) and score > 0:
            return N_STATES - 1
        return ABSORBING_STATE
    if score < 100:
        return 0
    if score < 200:
        return 1
    if score < 400:
        return 2
    if score < 600:
        return 3
    if score < 800:
        return 4
    return 5


# ---------------------------------------------------------------------------
# Linear algebra (stdlib-only) for the (I - Q)^-1 fundamental matrix.
# ---------------------------------------------------------------------------

def _identity(n: int) -> List[List[float]]:
    return [[1.0 if i == j else 0.0 for j in range(n)] for i in range(n)]


def _matsub(a: List[List[float]], b: List[List[float]]) -> List[List[float]]:
    n = len(a)
    return [[a[i][j] - b[i][j] for j in range(n)] for i in range(n)]


def _invert(m: List[List[float]]) -> Optional[List[List[float]]]:
    """Gauss-Jordan inversion of an n x n matrix.  Returns None if singular."""
    n = len(m)
    # Build augmented [m | I]
    aug = [row[:] + [1.0 if i == j else 0.0 for j in range(n)]
           for i, row in enumerate(m)]
    for col in range(n):
        # Partial pivot
        pivot_row = max(range(col, n), key=lambda r: abs(aug[r][col]))
        if abs(aug[pivot_row][col]) < 1e-12:
            return None  # Singular
        aug[col], aug[pivot_row] = aug[pivot_row], aug[col]
        pivot = aug[col][col]
        # Normalize pivot row
        inv_pivot = 1.0 / pivot
        for k in range(2 * n):
            aug[col][k] *= inv_pivot
        # Eliminate other rows
        for r in range(n):
            if r == col:
                continue
            factor = aug[r][col]
            if factor == 0.0:
                continue
            for k in range(2 * n):
                aug[r][k] -= factor * aug[col][k]
    return [row[n:] for row in aug]


# ---------------------------------------------------------------------------
# Markov chain over trust bands
# ---------------------------------------------------------------------------

class TrustMarkovChain:
    """Per-subject Markov chain over the 6 trust bands.

    Counts every observed (prev_band, next_band) transition.  Estimates a
    row-normalized transition matrix; rows with no observations remain at
    the identity (state stays put), reflecting "no evidence yet".

    The APOPTOSIS state (index 0) is absorbing in the model: any subject
    that hits it stays there.  Even if observations show transitions OUT
    of APOPTOSIS, those are zeroed during matrix construction.
    """

    __slots__ = ("_counts", "_observations", "_band_visits", "_lock",
                 "_last_touch")

    def __init__(self) -> None:
        self._counts: Dict[Tuple[int, int], int] = defaultdict(int)
        self._observations: int = 0
        self._band_visits: List[int] = [0] * N_STATES
        self._lock = threading.Lock()
        self._last_touch: float = 0.0  # set by the registry on access

    # ----- Observation -----
    def observe_transition(self, prev_score: float, next_score: float) -> None:
        i = score_to_band_idx(prev_score)
        j = score_to_band_idx(next_score)
        with self._lock:
            self._counts[(i, j)] += 1
            self._observations += 1
            # Count BOTH endpoints toward the visit histogram so that a
            # short trajectory still has a meaningful stationary fallback.
            self._band_visits[i] += 1
            self._band_visits[j] += 1

    @property
    def n_observations(self) -> int:
        return self._observations

    # ----- Transition matrix -----
    def transition_matrix(self) -> List[List[float]]:
        """Return a 6x6 row-stochastic matrix.

        - APOPTOSIS row is forced to absorbing (1.0 self-loop) regardless of
          observed counts.
        - Rows with zero observed outgoing transitions become identity rows
          (state stays put -- "no evidence to move").
        """
        with self._lock:
            row_sums = [0] * N_STATES
            for (i, j), c in self._counts.items():
                row_sums[i] += c
            mat: List[List[float]] = [[0.0] * N_STATES for _ in range(N_STATES)]
            # APOPTOSIS absorbing
            mat[0][0] = 1.0
            for i in range(1, N_STATES):
                if row_sums[i] == 0:
                    mat[i][i] = 1.0
                    continue
                inv = 1.0 / row_sums[i]
                for j in range(N_STATES):
                    c = self._counts.get((i, j), 0)
                    if c:
                        mat[i][j] = c * inv
        return mat

    # ----- Hitting time to APOPTOSIS -----
    def expected_time_to_apoptosis(self, current_band_idx: int) -> float:
        """E[T_0 | start = current_band_idx] using the absorbing-chain
        fundamental matrix N = (I - Q)^-1 where Q is the *reachable*
        transient block (we restrict to states that can actually reach
        APOPTOSIS, so a globally singular (I-Q) -- caused by an unrelated
        absorbing-but-not-APOPTOSIS state like KERNEL with no observed
        downward transitions -- doesn't poison the inversion).

        Returns:
            0.0      if already in APOPTOSIS
            +inf     if APOPTOSIS is unreachable from this state OR the
                     reachable-subset matrix is singular.
            float    expected number of observation-steps otherwise.
        """
        if current_band_idx == ABSORBING_STATE:
            return 0.0
        if not (0 <= current_band_idx < N_STATES):
            return INF
        P = self.transition_matrix()

        # Reverse-BFS from APOPTOSIS over the support of P to find the set
        # of states that CAN reach APOPTOSIS (excluding APOPTOSIS itself).
        reachable: set = set()
        frontier: List[int] = [ABSORBING_STATE]
        while frontier:
            nxt: List[int] = []
            for tgt in frontier:
                for src in range(N_STATES):
                    if src == ABSORBING_STATE or src in reachable:
                        continue
                    if P[src][tgt] > 0.0:
                        reachable.add(src)
                        nxt.append(src)
            frontier = nxt

        if current_band_idx not in reachable:
            return INF

        # Build the reduced transient block over `reachable` (sorted for
        # determinism).  Map global idx -> local idx.
        order = sorted(reachable)
        local_of: Dict[int, int] = {g: l for l, g in enumerate(order)}
        m = len(order)
        Q = [[P[order[i]][order[j]] for j in range(m)] for i in range(m)]
        I = _identity(m)
        IQ = _matsub(I, Q)
        N_mat = _invert(IQ)
        if N_mat is None:
            return INF
        row = N_mat[local_of[current_band_idx]]
        total = 0.0
        for v in row:
            if v < -1e-9:
                return INF
            total += max(0.0, v)
        if total > 1e15 or not math.isfinite(total):
            return INF
        return total

    # ----- Stationary distribution -----
    def stationary(self, iters: int = 64) -> List[float]:
        """Power iteration for pi P = pi.

        Starts from uniform over the 5 non-APOPTOSIS bands.  This is a
        soft estimate -- the true stationary of an absorbing chain is just
        a delta on APOPTOSIS, so we INSTEAD compute the stationary of the
        observed sub-stochastic transient kernel re-normalized row-wise
        (i.e., conditional on not absorbing this step).
        """
        P = self.transition_matrix()
        # Build a "conditional" transition matrix: zero out the APOPTOSIS
        # column then row-renormalize.
        Pc: List[List[float]] = [[0.0] * N_STATES for _ in range(N_STATES)]
        for i in range(N_STATES):
            row_sum = sum(P[i][j] for j in range(1, N_STATES))
            if row_sum <= 0.0:
                Pc[i][i] = 1.0
                continue
            for j in range(1, N_STATES):
                Pc[i][j] = P[i][j] / row_sum
        # Start uniform over the 5 non-APOPTOSIS bands.
        pi = [0.0] + [1.0 / (N_STATES - 1)] * (N_STATES - 1)
        for _ in range(max(1, iters)):
            new_pi = [0.0] * N_STATES
            for j in range(N_STATES):
                s = 0.0
                for i in range(N_STATES):
                    s += pi[i] * Pc[i][j]
                new_pi[j] = s
            # L1 renormalize (paranoia against drift)
            total = sum(new_pi) or 1.0
            pi = [v / total for v in new_pi]
        return pi

    def likelihood_in_band(self, band_idx: int) -> float:
        """Historical fraction of time spent in this band (visit count /
        total visits).  Returns 0.0 if no observations."""
        if not (0 <= band_idx < N_STATES):
            return 0.0
        with self._lock:
            total = sum(self._band_visits)
            if total == 0:
                return 0.0
            return self._band_visits[band_idx] / total

    # ----- Serialization -----
    def to_dict(self) -> Dict:
        with self._lock:
            return {
                "counts": {f"{i},{j}": c
                           for (i, j), c in self._counts.items()},
                "observations": self._observations,
                "band_visits": list(self._band_visits),
            }

    @classmethod
    def from_dict(cls, d: Dict) -> "TrustMarkovChain":
        chain = cls()
        for key, c in d.get("counts", {}).items():
            try:
                i_str, j_str = key.split(",", 1)
                i = int(i_str); j = int(j_str)
            except (ValueError, AttributeError):
                continue
            if 0 <= i < N_STATES and 0 <= j < N_STATES and c > 0:
                chain._counts[(i, j)] = int(c)
        chain._observations = int(d.get("observations", 0))
        bv = d.get("band_visits", [])
        if isinstance(bv, list) and len(bv) == N_STATES:
            chain._band_visits = [max(0, int(v)) for v in bv]
        return chain


# ---------------------------------------------------------------------------
# Process-wide registry of per-subject chains (LRU-bounded)
# ---------------------------------------------------------------------------

_chains: "OrderedDict[int, TrustMarkovChain]" = OrderedDict()
_chains_lock = threading.Lock()
_clock = 0  # logical access counter for LRU


def _touch(subject_id: int) -> None:
    """Move subject to MRU end; called under _chains_lock."""
    global _clock
    _clock += 1
    if subject_id in _chains:
        _chains.move_to_end(subject_id, last=True)
        _chains[subject_id]._last_touch = float(_clock)


def get_chain(subject_id: int) -> TrustMarkovChain:
    """Get-or-create the per-subject markov chain.  LRU-evicts when over cap."""
    with _chains_lock:
        if subject_id in _chains:
            _touch(subject_id)
            return _chains[subject_id]
        chain = TrustMarkovChain()
        _chains[subject_id] = chain
        _touch(subject_id)
        # Evict from LRU end (front) until we are within cap.
        while len(_chains) > _MAX_CHAINS:
            _chains.popitem(last=False)
        return chain


def reset_chain(subject_id: int) -> None:
    """Drop a subject's chain (testing / explicit revoke)."""
    with _chains_lock:
        _chains.pop(subject_id, None)


def reset_all() -> None:
    """Drop every chain.  Test-helper; safe in production but expensive."""
    with _chains_lock:
        _chains.clear()


def observe_score(subject_id: int, prev_score: float, next_score: float) -> None:
    get_chain(subject_id).observe_transition(prev_score, next_score)


def forecast(subject_id: int, current_score: float) -> Dict:
    """Returns telemetry-ready forecast for a subject.

    {
      "subject_id":               int,
      "current_score":            float,
      "current_band":             str   (BAND_NAMES[idx]),
      "current_band_idx":         int,
      "n_observations":           int,
      "expected_steps_to_apoptosis": float (may be +inf),
      "top_3_likely_next_bands":  [{"band": str, "p": float}, ...]
                                  (sorted desc; APOPTOSIS included if non-zero),
      "stationary_distribution":  {band_name: prob, ...}
                                  (over the 5 non-APOPTOSIS bands),
      "historical_band_likelihood": {band_name: fraction, ...},
    }
    """
    chain = get_chain(subject_id)
    band_idx = score_to_band_idx(current_score)
    P = chain.transition_matrix()
    eta = chain.expected_time_to_apoptosis(band_idx)

    # Top-3 likely next bands from CURRENT band's row.
    row = list(enumerate(P[band_idx]))
    row.sort(key=lambda kv: kv[1], reverse=True)
    top3 = [{"band": BAND_NAMES[i], "p": p} for i, p in row[:3] if p > 0.0]

    stat = chain.stationary()
    stationary_named = {BAND_NAMES[i]: stat[i] for i in range(N_STATES)}
    hist_named = {BAND_NAMES[i]: chain.likelihood_in_band(i)
                  for i in range(N_STATES)}

    # JSON cannot hold +inf; emit a sentinel string AND keep the float
    # under a separate key so callers can branch cleanly.
    eta_serializable = eta if math.isfinite(eta) else None

    return {
        "subject_id": subject_id,
        "current_score": float(current_score),
        "current_band": BAND_NAMES[band_idx],
        "current_band_idx": band_idx,
        "n_observations": chain.n_observations,
        "expected_steps_to_apoptosis": eta_serializable,
        "expected_steps_to_apoptosis_is_infinite": not math.isfinite(eta),
        "top_3_likely_next_bands": top3,
        "stationary_distribution": stationary_named,
        "historical_band_likelihood": hist_named,
    }


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

def _print_matrix(P: List[List[float]]) -> None:
    header = "        " + "  ".join(f"{n[:5]:>7}" for n in BAND_NAMES)
    print(header)
    for i, row in enumerate(P):
        cells = "  ".join(f"{v:>7.3f}" for v in row)
        print(f"{BAND_NAMES[i][:7]:>7} {cells}")


def _smoke() -> None:
    print("=== TrustMarkovChain smoke test ===")

    # ---- Trajectory 1: decay 600 -> ... -> 50 ----
    sid = 1234
    reset_chain(sid)
    traj = [600, 600, 600, 400, 600, 400, 200, 100, 50]
    for prev, nxt in zip(traj, traj[1:]):
        observe_score(sid, prev, nxt)
    chain = get_chain(sid)
    print(f"\n[traj1] subject {sid}, sequence: {traj}")
    print(f"[traj1] observations: {chain.n_observations}")
    print("[traj1] transition matrix:")
    _print_matrix(chain.transition_matrix())
    cur_score = traj[-1]
    cur_idx = score_to_band_idx(cur_score)
    eta = chain.expected_time_to_apoptosis(cur_idx)
    print(f"[traj1] current score={cur_score} -> band={BAND_NAMES[cur_idx]} "
          f"(idx {cur_idx})")
    print(f"[traj1] E[steps to APOPTOSIS] = {eta}  "
          f"(expected 0.0 since already absorbed)")

    # Forecast from a healthy starting point on the same chain
    # (use band INTERACT idx 2 as the hypothetical present)
    eta_interact = chain.expected_time_to_apoptosis(2)
    print(f"[traj1] hypothetical E[steps to APOPTOSIS | start=INTERACT] = "
          f"{eta_interact}")

    # ---- Trajectory 2: 10x stay at ADMIN (600), no downward observed ----
    sid2 = 5678
    reset_chain(sid2)
    for _ in range(10):
        observe_score(sid2, 600, 600)
    chain2 = get_chain(sid2)
    print(f"\n[traj2] subject {sid2}, 10x stay at ADMIN (600)")
    print(f"[traj2] observations: {chain2.n_observations}")
    print("[traj2] transition matrix:")
    _print_matrix(chain2.transition_matrix())
    cur_idx2 = score_to_band_idx(600)
    eta2 = chain2.expected_time_to_apoptosis(cur_idx2)
    print(f"[traj2] current band={BAND_NAMES[cur_idx2]}")
    print(f"[traj2] E[steps to APOPTOSIS] = {eta2}  "
          f"(expected +inf -- no observed downward transitions)")

    # ---- Forecast envelopes for each trajectory ----
    print("\n[forecast traj1, score=400]:")
    f1 = forecast(sid, 400)
    print(f"  current_band={f1['current_band']}, "
          f"E_steps={f1['expected_steps_to_apoptosis']}, "
          f"is_inf={f1['expected_steps_to_apoptosis_is_infinite']}")
    print(f"  top3={f1['top_3_likely_next_bands']}")

    print("\n[forecast traj2, score=600]:")
    f2 = forecast(sid2, 600)
    print(f"  current_band={f2['current_band']}, "
          f"E_steps={f2['expected_steps_to_apoptosis']}, "
          f"is_inf={f2['expected_steps_to_apoptosis_is_infinite']}")
    print(f"  top3={f2['top_3_likely_next_bands']}")

    # Round-trip serialization check
    blob = chain.to_dict()
    rebuilt = TrustMarkovChain.from_dict(blob)
    assert rebuilt.n_observations == chain.n_observations, \
        "to_dict/from_dict round-trip lost observations"
    print("\n[serialization] to_dict/from_dict round-trip OK "
          f"({rebuilt.n_observations} observations preserved)")
    print("=== smoke test done ===")


if __name__ == "__main__":  # pragma: no cover
    _smoke()
