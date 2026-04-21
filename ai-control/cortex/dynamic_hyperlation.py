"""
Dynamic Hyperlation -- observable view of "continuously metabolized,
self-consuming, behaviorally-driven trust flows" from the AI cortex.

Surfaces the foundational hypotheses of:
    Roberts, Eli, Leelee. "Root of Authority" (Zenodo 18710335),
    Section: Dynamic Hyperlation.

The paper models authority as a metabolism: each subject continuously burns
its credit (C_t) and score (S_t), spends to act, and is killed when those
flows go anomalous. Three hypotheses are testable in real time:

    Hypothesis 1 (Containment):
        If an entity cannot afford its next action -- C_t/C_starter < 0.1
        AND dC/dt is negative -- the anomaly is *contained by physics*: the
        entity literally runs out of fuel before it can spread. We surface
        this as METABOLIC_STARVATION.

    Hypothesis 2 (Behavioral Divergence):
        A subject's score collapsing faster than -0.1/s over a 5s window is
        the paper's compromise signal: behavior diverges from the trust
        baseline, regardless of what the entity *says* it is doing. Surfaced
        as BEHAVIORAL_DIVERGENCE.

    Theorem 1 (No software-accessible reusable secret):
        Authority cannot be re-derived from a stored credential. The
        snapshot here exposes only metabolic state -- never a token, key,
        or seed -- so consumers cannot, by reading the API, reconstruct
        anything reusable.

    Healthy default: STEADY_FLOW.

This module is read-only against /sys/kernel/trust/ (or libtrust if
importable). It never writes to the kernel; consumers (DecisionEngine
policy slot, /cortex/hyperlation/* API endpoints) decide what to do.

Graceful degradation: when the trust kernel module is not loaded (WSL/dev),
poll() yields a synthetic snapshot so the API and self-test still work.

============================================================================
SCHEMA: GET /system/state aggregator (Session 49)
============================================================================
Canonical envelope returned by the new aggregator endpoint:

    {
      "kernel": {
        "cancer_detections":    int   | null,
        "meiosis_count":        int   | null,
        "meiosis_active_bonds": int   | null,
        "theorem1_violations":  int   | null,
        "theorem2_violations":  int   | null,
        "theorem4_violations":  int   | null,
        "theorem5_violations":  int   | null,
        "theorem6_violations":  int   | null,
        "token_ledger":         str   | null,   # raw text, may be large
      },
      "cortex": {
        "subject_count":        int,
        "states":               { "STEADY_FLOW": int,
                                   "METABOLIC_STARVATION": int,
                                   "BEHAVIORAL_DIVERGENCE": int },
        "total_metabolism":     float,
        "source":               str,     # "sysfs" | "libtrust" | "synthetic"
      },
      "coherence": {
        "game_active":          str | null,
        "vrr_target":           str | null,
        "present_mode":         str | null,
      },
      "aggregated_at":          str,     # ISO8601 UTC
      "schema_version":         1
    }

Per-view fields degrade to null on missing/error -- never raise. The
aggregator NEVER reads anything that isn't already accessible to a
TRUST_INTERACT-banded caller; the kernel ledger view is the reason
the endpoint requires INTERACT rather than USER.
"""

from __future__ import annotations

import logging
import math
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger("cortex.hyperlation")


# Sysfs paths owned by sibling agents (Agents 8/3/4 in Session 48):
_SYSFS_ROOT = "/sys/kernel/trust"
# Kernel paths consumed by readers in this module (read-only).
# Theorem violation counters live under trust_invariants (NOT trust/),
# exposed by trust/kernel/trust_invariants.c via DEFINE_TI_SHOW_U64.
# All theorem reads -- both per-tick (theorem_violations) and the
# /system/state aggregator -- MUST use this root or they silently
# return 0 and mask live invariant breaches.
_TRUST_INVARIANTS_ROOT = "/sys/kernel/trust_invariants"
_TRUST_AUTHZ_TOKEN_LEDGER = "/sys/kernel/trust_authz/token_ledger"

_THEOREMS = (1, 2, 4, 5, 6)
_THEOREM_NODES = {
    n: f"{_TRUST_INVARIANTS_ROOT}/theorem{n}_violations" for n in _THEOREMS
}
_CANCER_NODE = f"{_SYSFS_ROOT}/cancer_detections"
_MEIOSIS_NODE = f"{_SYSFS_ROOT}/meiosis_active_bonds"
_MEIOSIS_COUNT_NODE = f"{_SYSFS_ROOT}/meiosis_count"
_SUBJECTS_DIR = f"{_SYSFS_ROOT}/subjects"

# Coherence runtime state files:
_COHERENCE_RUN = "/var/run/coherence"
_COHERENCE_FILES = {
    "game_active": f"{_COHERENCE_RUN}/game-active",
    "vrr_target": f"{_COHERENCE_RUN}/vrr-target",
    "present_mode": f"{_COHERENCE_RUN}/present-mode",
}

# Sex encoding (paper §Reproductive Asymmetry):
SEX_XX = 0
SEX_XY = 1

# Valid filter vocab. Bad values -> ValueError so the API can 400 cleanly.
VALID_CLASSES: frozenset = frozenset({
    "kernel_driver", "system_service", "user_app", "game", "unknown",
})
VALID_STATES: frozenset = frozenset({
    "STEADY_FLOW", "METABOLIC_STARVATION", "BEHAVIORAL_DIVERGENCE",
})

# Aggregator schema version -- bump on any envelope change.
SYSTEM_STATE_SCHEMA_VERSION = 1

# ----------------------------------------------------------------------------
# Markov transition matrix (Session 58, Agent 2)
# ----------------------------------------------------------------------------
# Per-subject empirical Markov chain over 4 named states. Indexed as:
#   0 STEADY_FLOW
#   1 METABOLIC_STARVATION
#   2 BEHAVIORAL_DIVERGENCE
#   3 APOPTOSIS  (absorbing)
#
# We ALSO accept (but never produce in `state` field) APOPTOSIS as a
# tracker-internal terminal label. The string is published only inside
# `markov.last_seen_state_name` -- the canonical `state` field stays in
# VALID_STATES so existing GUI filters and aggregator code paths are
# unchanged.
MARKOV_STATES: Tuple[str, ...] = (
    "STEADY_FLOW",
    "METABOLIC_STARVATION",
    "BEHAVIORAL_DIVERGENCE",
    "APOPTOSIS",
)
MARKOV_STATE_INDEX: Dict[str, int] = {s: i for i, s in enumerate(MARKOV_STATES)}
MARKOV_N_STATES: int = len(MARKOV_STATES)
MARKOV_APOPTOSIS_IDX: int = 3

# Anomaly thresholds for classify_markov_anomaly()
MARKOV_KL_DRIFT_THRESHOLD: float = 0.5
MARKOV_HITTING_TIME_DANGER: float = 5.0


def _state_name_to_idx(state: Optional[str]) -> Optional[int]:
    """Map a state-name string into the Markov state index, or None."""
    if state is None:
        return None
    return MARKOV_STATE_INDEX.get(state)


@dataclass
class MarkovTransitionMatrix:
    """4-state empirical Markov chain over hyperlation states.

    States indexed 0..3:
      0 STEADY_FLOW
      1 METABOLIC_STARVATION
      2 BEHAVIORAL_DIVERGENCE
      3 APOPTOSIS  (absorbing -- once reached, transitions all stay at 3)

    Storage is O(1): a 4x4 integer count matrix plus a small bounded
    deque of recent state indices for KL-divergence anomaly detection.
    `update()` is O(1) per call; matrix/stationary/hitting_time are O(1)
    in the sample count (bounded by the 4x4 size).
    """

    counts: List[List[int]] = field(
        default_factory=lambda: [[0] * MARKOV_N_STATES for _ in range(MARKOV_N_STATES)]
    )
    last_seen_state: Optional[int] = None
    history_len: int = 0
    # Recent-window ring for KL drift detection. Bounded so memory is O(1).
    recent_window_max: int = 32
    recent: Deque[int] = field(
        default_factory=lambda: deque(maxlen=32)
    )

    def __post_init__(self) -> None:
        # Ensure the ring buffer's capacity honours `recent_window_max` for
        # direct constructor calls. Without this, `MarkovTransitionMatrix(
        # recent_window_max=64)` would silently keep the factory-default
        # maxlen=32 deque, diverging from `from_dict({"recent_window_max": 64})`
        # which correctly sizes the ring. (S78 Dev G)
        if self.recent_window_max is None or self.recent_window_max <= 0:
            self.recent_window_max = 32
        if self.recent.maxlen != self.recent_window_max:
            # Preserve any pre-existing recent entries (factory default is
            # empty, but a caller could have supplied `recent=deque(...)`).
            self.recent = deque(self.recent, maxlen=self.recent_window_max)

    # ---- Mutators -------------------------------------------------------

    def update(self, new_state_idx: int) -> None:
        """Record that we just observed state `new_state_idx`.

        Idempotent against bad indices: out-of-range values are silently
        ignored so a misclassification upstream cannot poison the matrix.
        Rejects bool (which is an int subclass in Python but would
        confuse downstream `MARKOV_STATES[last]` indexing and type
        contracts; S78 Dev G).
        """
        # isinstance(True, int) is True; exclude bool explicitly so the
        # last_seen_state stays a proper int (or None).
        if isinstance(new_state_idx, bool) or not isinstance(new_state_idx, int):
            return
        if new_state_idx < 0 or new_state_idx >= MARKOV_N_STATES:
            return
        # APOPTOSIS is absorbing: once we reached 3, every "next state" we
        # might be told about is forced to 3 in the count. This keeps the
        # math correct even if the caller forgets the absorbing rule.
        if self.last_seen_state == MARKOV_APOPTOSIS_IDX:
            new_state_idx = MARKOV_APOPTOSIS_IDX
        prev = self.last_seen_state
        if prev is not None:
            self.counts[prev][new_state_idx] += 1
        self.last_seen_state = new_state_idx
        self.history_len += 1
        self.recent.append(new_state_idx)

    # ---- Read-only views ------------------------------------------------

    def matrix(self) -> List[List[float]]:
        """Row-normalized P[i][j] = counts[i][j] / sum(counts[i]).

        Rows with zero observations return an identity row (i->i with
        probability 1.0) so downstream math never divides by zero. This
        is the documented contract from the public API.

        WARNING for math consumers: identity rows for unobserved sources
        create phantom absorbing classes that pollute the stationary
        distribution and hitting-time computation. `stationary()` and
        `expected_hitting_time_to_apoptosis()` therefore use
        `_matrix_for_dynamics()` (uniform fallback for unobserved rows),
        which represents "we don't know" rather than "stays put forever."
        """
        out: List[List[float]] = [[0.0] * MARKOV_N_STATES for _ in range(MARKOV_N_STATES)]
        for i in range(MARKOV_N_STATES):
            row_sum = sum(self.counts[i])
            if row_sum <= 0:
                out[i][i] = 1.0
                continue
            inv = 1.0 / float(row_sum)
            for j in range(MARKOV_N_STATES):
                out[i][j] = self.counts[i][j] * inv
        return out

    def _matrix_for_dynamics(self) -> List[List[float]]:
        """Row-stochastic matrix used for stationary / hitting-time math.

        Differs from `matrix()` only in the unobserved-row treatment: an
        unobserved transient row (0,1,2) becomes UNIFORM over all 4 states
        (1/4 each) so it doesn't act as an absorbing class. The
        APOPTOSIS row stays absorbing-by-construction (P[3][3]=1.0)
        regardless of observation count, since the kernel guarantees it.
        """
        out: List[List[float]] = [[0.0] * MARKOV_N_STATES for _ in range(MARKOV_N_STATES)]
        for i in range(MARKOV_N_STATES):
            row_sum = sum(self.counts[i])
            if i == MARKOV_APOPTOSIS_IDX:
                # Absorbing-by-construction even with zero observations.
                out[i] = [0.0] * MARKOV_N_STATES
                out[i][MARKOV_APOPTOSIS_IDX] = 1.0
                continue
            if row_sum <= 0:
                # True ignorance prior: uniform over all 4 successors.
                u = 1.0 / float(MARKOV_N_STATES)
                out[i] = [u] * MARKOV_N_STATES
                continue
            inv = 1.0 / float(row_sum)
            for j in range(MARKOV_N_STATES):
                out[i][j] = self.counts[i][j] * inv
        return out

    def stationary(self, iters: int = 64) -> List[float]:
        """Equilibrium distribution via power iteration: pi @ P = pi.

        Starts from the empirical marginal of observed states (so a
        chain that's mostly self-looped in STEADY converges to a
        stationary that's mostly STEADY, not uniform across phantom
        absorbing classes from unobserved rows).

        Falls back to uniform if there is no observation history. Uses
        the public `matrix()` (identity rows for unobserved) -- a
        never-visited row is allowed to be a self-loop in the equilibrium
        sense ("if we never went there, the chain doesn't push us out").
        Default 64 iterations covers convergence with a wide margin for
        a 4x4 chain.
        """
        P = self.matrix()
        # Start from empirical marginal: count how many times each state
        # appeared as a destination across all rows. This ensures that
        # for a chain with multiple absorbing classes (e.g., observed
        # self-loops in STEADY plus the absorbing APOPTOSIS row), the
        # equilibrium is pulled toward where the mass actually sits,
        # not split uniformly between the absorbing classes.
        col_mass = [0.0] * MARKOV_N_STATES
        total_mass = 0.0
        for i in range(MARKOV_N_STATES):
            for j in range(MARKOV_N_STATES):
                col_mass[j] += float(self.counts[i][j])
                total_mass += float(self.counts[i][j])
        if total_mass > 0.0:
            pi = [v / total_mass for v in col_mass]
        else:
            pi = [1.0 / MARKOV_N_STATES] * MARKOV_N_STATES
        for _ in range(max(1, iters)):
            new_pi = [0.0] * MARKOV_N_STATES
            for j in range(MARKOV_N_STATES):
                acc = 0.0
                for i in range(MARKOV_N_STATES):
                    acc += pi[i] * P[i][j]
                new_pi[j] = acc
            s = sum(new_pi)
            if s <= 0.0:
                return [1.0 / MARKOV_N_STATES] * MARKOV_N_STATES
            new_pi = [v / s for v in new_pi]
            # Cheap convergence early-out
            delta = sum(abs(new_pi[k] - pi[k]) for k in range(MARKOV_N_STATES))
            pi = new_pi
            if delta < 1e-9:
                break
        return pi

    def expected_hitting_time_to_apoptosis(self) -> float:
        """E[T_3 | start = last_seen_state], the absorbing-chain hitting time.

        Implementation: with 3 transient states (0,1,2) and APOPTOSIS=3
        absorbing, partition P into transient block Q (3x3) and absorption
        column R (3x1, unused for hitting time). The fundamental matrix
        N = (I - Q)^-1; row-sums of N are the expected hitting times from
        each transient start state. We invert the 3x3 in closed form.

        Returns:
          0.0   if last_seen_state is APOPTOSIS or unset (already absorbed
                / no information)
          inf   if absorption is unreachable from the current state
                (e.g., chain has no 3-column entries yet); callers can
                treat this as "very safe / no apoptosis pressure"
        """
        # No history yet, or already absorbed
        if self.last_seen_state is None:
            return 0.0
        if self.last_seen_state == MARKOV_APOPTOSIS_IDX:
            return 0.0

        P = self._matrix_for_dynamics()
        # Transient block Q (states 0..2 -> 0..2)
        Q = [[P[i][j] for j in range(3)] for i in range(3)]
        # Build (I - Q)
        IQ = [[(1.0 if i == j else 0.0) - Q[i][j] for j in range(3)] for i in range(3)]
        N = _invert_3x3(IQ)
        if N is None:
            # Singular; means at least one transient row sums to ~1 in Q
            # (no probability of leaving the transient set), i.e.,
            # apoptosis unreachable from somewhere -- treat as infinite.
            return float("inf")
        row = self.last_seen_state  # 0, 1, or 2
        # Hitting time from `row` = sum of N[row][k] for k in transient
        return float(N[row][0] + N[row][1] + N[row][2])

    def kl_divergence_recent_vs_steady(self, recent_window: int = 10) -> float:
        """KL(recent || historical_visit_marginal).

        Anomaly detection semantics: "did the recent window of states
        diverge from how the chain has historically spent its time?"

        We compare against the historical VISIT marginal (how often each
        state appeared as a destination in the count matrix), NOT the
        dynamics-stationary returned by `stationary()`. Reason: with
        sparse data, a single observed self-loop creates an absorbing
        class that pulls the dynamics-stationary toward it, masking
        anomalies. Visit-marginal is purely empirical and reflects what
        the operator considers "normal historical behavior."

        Built from the most recent `recent_window` observations (capped
        at the bounded ring length). Returns 0.0 when not enough samples
        to make a meaningful estimate (avoids "every cold-start subject
        looks anomalous"). Uses a tiny epsilon smoothing so a state
        that's never been seen historically doesn't blow the divergence
        to infinity on first observation.
        """
        if recent_window <= 0:
            return 0.0
        if not self.recent:
            return 0.0
        take = min(recent_window, len(self.recent))
        recent_slice = list(self.recent)[-take:]
        if len(recent_slice) < 2:
            return 0.0
        # Empirical recent distribution
        emp = [0.0] * MARKOV_N_STATES
        for s in recent_slice:
            emp[s] += 1.0
        total = float(len(recent_slice))
        emp = [v / total for v in emp]
        # Historical visit marginal: column sums of the count matrix
        # (every transition recorded contributed one destination-vote).
        hist = [0.0] * MARKOV_N_STATES
        hist_total = 0.0
        for i in range(MARKOV_N_STATES):
            for j in range(MARKOV_N_STATES):
                v = float(self.counts[i][j])
                hist[j] += v
                hist_total += v
        if hist_total <= 0.0:
            # No transitions yet -- can't say anything meaningful.
            return 0.0
        hist = [v / hist_total for v in hist]
        # KL(emp || hist) with epsilon smoothing on the historical side.
        eps = 1e-9
        kl = 0.0
        for i in range(MARKOV_N_STATES):
            p = emp[i]
            q = hist[i]
            if p <= 0.0:
                continue
            q_safe = q if q > eps else eps
            kl += p * math.log(p / q_safe)
        if kl < 0.0:
            return 0.0
        return kl

    # ---- Serialization --------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "counts": [row[:] for row in self.counts],
            "last_seen_state": self.last_seen_state,
            "history_len": self.history_len,
            "recent": list(self.recent),
            "recent_window_max": self.recent_window_max,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "MarkovTransitionMatrix":
        counts = d.get("counts") or [[0] * MARKOV_N_STATES for _ in range(MARKOV_N_STATES)]
        # Defensive shape coercion in case persistence drifted.
        normed_counts: List[List[int]] = []
        for i in range(MARKOV_N_STATES):
            row = counts[i] if i < len(counts) else []
            normed_row = []
            for j in range(MARKOV_N_STATES):
                try:
                    normed_row.append(int(row[j]) if j < len(row) else 0)
                except (TypeError, ValueError):
                    normed_row.append(0)
            normed_counts.append(normed_row)
        rwm = int(d.get("recent_window_max", 32) or 32)
        if rwm <= 0:
            rwm = 32
        recent_dq: Deque[int] = deque(maxlen=rwm)
        for v in (d.get("recent") or []):
            try:
                vi = int(v)
                if 0 <= vi < MARKOV_N_STATES:
                    recent_dq.append(vi)
            except (TypeError, ValueError):
                continue
        last = d.get("last_seen_state")
        if last is not None:
            try:
                last_i = int(last)
                if not (0 <= last_i < MARKOV_N_STATES):
                    last_i = None
            except (TypeError, ValueError):
                last_i = None
            last = last_i
        try:
            hist_len = int(d.get("history_len", 0) or 0)
        except (TypeError, ValueError):
            hist_len = 0
        return cls(
            counts=normed_counts,
            last_seen_state=last,
            history_len=hist_len,
            recent_window_max=rwm,
            recent=recent_dq,
        )


def _invert_3x3(M: List[List[float]]) -> Optional[List[List[float]]]:
    """Closed-form 3x3 inverse via cofactor expansion. Returns None if singular.

    Pure stdlib; we only need this for the Markov hitting-time computation
    so a 3x3 closed-form is faster and simpler than a generic Gauss elim.
    """
    a, b, c = M[0][0], M[0][1], M[0][2]
    d, e, f = M[1][0], M[1][1], M[1][2]
    g, h, i = M[2][0], M[2][1], M[2][2]
    det = (a * (e * i - f * h)
           - b * (d * i - f * g)
           + c * (d * h - e * g))
    if abs(det) < 1e-15:
        return None
    inv_det = 1.0 / det
    inv = [
        [(e * i - f * h) * inv_det,
         -(b * i - c * h) * inv_det,
         (b * f - c * e) * inv_det],
        [-(d * i - f * g) * inv_det,
         (a * i - c * g) * inv_det,
         -(a * f - c * d) * inv_det],
        [(d * h - e * g) * inv_det,
         -(a * h - b * g) * inv_det,
         (a * e - b * d) * inv_det],
    ]
    return inv


class HypothesisSlot(Enum):
    """Foundational hypotheses surfaced by Dynamic Hyperlation.

    Anchored in Roberts, Eli, Leelee. "Root of Authority" (Zenodo 18710335),
    section: Foundational Hypotheses. Each slot names an empirically
    falsifiable claim the kernel + cortex co-enforce, and each maps to a
    classifier rule in `classify_hypothesis_violation()` so a single
    subject_state dict can be tested against all three at once.

    Slot semantics (paper-aligned):

        HYP_DYNAMIC_AUTHORITY (Hypothesis 1, Metabolic Trust):
            Authority is continuously metabolized -- it is *spent*, not
            *held*. An entity burning credit faster than 2x its baseline
            metabolism rate is exhibiting the anomalous-burn pattern that
            forced the metabolism axiom in the first place.

        HYP_BIOLOGICAL_TRUST (Hypothesis 2, Behavioral Divergence):
            Trust is observed from behavior, not declaration. A score
            collapse of dS/dt < -0.1/s sustained over 5s is the paper's
            canonical compromise signal -- already surfaced by the state
            classifier as the BEHAVIORAL_DIVERGENCE state.

        HYP_APOPTOTIC_SAFETY (Hypothesis 3, Architectural Self-Authentication):
            Compromised entities self-destruct (apoptosis) before they can
            propagate. Triggered when the kernel reports a subject has
            entered apoptosis (apoptosis_event flag in the per-subject
            record, or kernel-emitted apoptosis_count delta).
    """
    HYP_DYNAMIC_AUTHORITY = "dynamic_authority"
    HYP_BIOLOGICAL_TRUST = "biological_trust"
    HYP_APOPTOTIC_SAFETY = "apoptotic_safety"


# Module-level aliases so test_roa_conformance.py and other consumers can
# `from dynamic_hyperlation import HYP_DYNAMIC_AUTHORITY` directly.
HYP_DYNAMIC_AUTHORITY = HypothesisSlot.HYP_DYNAMIC_AUTHORITY
HYP_BIOLOGICAL_TRUST = HypothesisSlot.HYP_BIOLOGICAL_TRUST
HYP_APOPTOTIC_SAFETY = HypothesisSlot.HYP_APOPTOTIC_SAFETY
HYPOTHESIS_SLOTS: List[HypothesisSlot] = list(HypothesisSlot)

__all__ = [
    "HyperlationStateTracker",
    "HyperlationFilter",
    "HypothesisSlot",
    "HYP_DYNAMIC_AUTHORITY",
    "HYP_BIOLOGICAL_TRUST",
    "HYP_APOPTOTIC_SAFETY",
    "HYPOTHESIS_SLOTS",
    "SYSTEM_STATE_SCHEMA_VERSION",
    "VALID_CLASSES",
    "VALID_STATES",
    "SEX_XX",
    "SEX_XY",
    "MarkovTransitionMatrix",
    "MARKOV_STATES",
    "MARKOV_STATE_INDEX",
    "MARKOV_N_STATES",
    "MARKOV_APOPTOSIS_IDX",
    "MARKOV_KL_DRIFT_THRESHOLD",
    "MARKOV_HITTING_TIME_DANGER",
]


@dataclass
class _SubjectHistory:
    """Per-subject rolling window for dC/dt and dS/dt derivation.

    We keep ~6s of (timestamp, C_t, S_t) so the 5s divergence window has
    margin. maxlen=64 covers up to ~10Hz sampling without unbounded growth
    on a long-lived subject.
    """
    samples: Deque[Tuple[float, float, float]] = field(
        default_factory=lambda: deque(maxlen=64)
    )
    C_starter: Optional[float] = None  # First-seen C, for Hypothesis 1 ratio.

    def add(self, ts: float, C_t: float, S_t: float) -> None:
        if self.C_starter is None and C_t > 0:
            self.C_starter = float(C_t)
        self.samples.append((ts, float(C_t), float(S_t)))

    def derivatives(self, now: float) -> Tuple[float, float, float]:
        """Return (dC/dt, dS/dt, tokens_burned_in_last_1s).

        Uses the oldest sample within [now-1s, now] as the lower bound for
        token-burn (positive = consumption), and the oldest sample within
        [now-5s, now] as the divergence window for dS/dt. dC/dt uses a 1s
        window. All zeros if there isn't enough history yet.
        """
        if len(self.samples) < 2:
            return (0.0, 0.0, 0.0)
        # Snapshot to avoid mutation during iteration
        samples = list(self.samples)
        last_ts, last_C, last_S = samples[-1]

        # Find oldest sample within 1s for credit derivative + burn
        c_old_ts, c_old_C = last_ts, last_C
        for ts, C, _S in samples:
            if last_ts - ts <= 1.0 and last_ts - ts > 0:
                c_old_ts, c_old_C = ts, C
                break
        dC_dt = 0.0
        dt_c = max(1e-6, last_ts - c_old_ts)
        if dt_c > 0:
            dC_dt = (last_C - c_old_C) / dt_c
        # Tokens burned = positive consumption in the last 1s.
        burned = max(0.0, c_old_C - last_C)

        # 5s window for behavioral divergence
        s_old_ts, s_old_S = last_ts, last_S
        for ts, _C, S in samples:
            if last_ts - ts <= 5.0 and last_ts - ts > 0:
                s_old_ts, s_old_S = ts, S
                break
        dS_dt = 0.0
        dt_s = max(1e-6, last_ts - s_old_ts)
        if dt_s > 0:
            dS_dt = (last_S - s_old_S) / dt_s

        return (dC_dt, dS_dt, burned)


def _classify_subject_kind(rec: dict) -> str:
    """Return a coarse class tag from a per-subject record.

    Uses the `kind` field if the kernel reports one, else falls back to
    heuristics (sex_int + score band) so the filter is always usable. The
    classification vocab matches VALID_CLASSES.
    """
    raw = str(rec.get("kind") or rec.get("class") or "").strip().lower()
    if raw in VALID_CLASSES:
        return raw
    # Heuristic fallback: high-score XY subjects are typically privileged
    # services; low-score XY are user apps; XX with G_t >= 1 are kernel
    # drivers (the immune system). Anything else is "unknown" so callers
    # can filter it out without false positives leaking through.
    try:
        S_t = float(rec.get("S_t", 0.0))
        sex = int(rec.get("sex", SEX_XX))
        G_t = int(rec.get("G_t", 0))
    except (TypeError, ValueError):
        return "unknown"
    if sex == SEX_XX and G_t >= 1 and S_t >= 80:
        return "kernel_driver"
    if sex == SEX_XY and S_t >= 70:
        return "system_service"
    if sex == SEX_XY and 30 <= S_t < 70:
        return "user_app"
    if sex == SEX_XY and S_t < 30:
        return "game"
    return "unknown"


@dataclass
class HyperlationFilter:
    """View-only filter applied to snapshots / endpoint responses.

    Construction is cheap; pass to `snapshot(filter=...)` or
    `get_subject(id, filter=...)`. None / empty fields are no-ops; non-empty
    ones intersect with AND. The filter NEVER mutates tracker state.
    """
    class_filter: Optional[Set[str]] = None     # classes to include
    state_filter: Optional[Set[str]] = None     # states to include
    subject_ids: Optional[Set[int]] = None      # if non-empty, only these

    def matches(self, subject: dict) -> bool:
        if self.subject_ids:
            try:
                if int(subject.get("id", -1)) not in self.subject_ids:
                    return False
            except (TypeError, ValueError):
                return False
        if self.state_filter:
            if subject.get("state") not in self.state_filter:
                return False
        if self.class_filter:
            cls = subject.get("class") or _classify_subject_kind(subject)
            if cls not in self.class_filter:
                return False
        return True

    @classmethod
    def parse_query(
        cls,
        class_csv: Optional[str] = None,
        state_csv: Optional[str] = None,
        pid_csv: Optional[str] = None,
    ) -> "HyperlationFilter":
        """Parse comma-separated query params into a HyperlationFilter.

        Raises ValueError on any unknown class/state token or non-int pid
        so the FastAPI layer can return a clean 400 instead of crashing
        on the snapshot read.
        """
        classes: Optional[Set[str]] = None
        if class_csv:
            classes = set()
            for raw in class_csv.split(","):
                tok = raw.strip().lower()
                if not tok:
                    continue
                if tok not in VALID_CLASSES:
                    raise ValueError(
                        f"unknown class {tok!r}; valid: {sorted(VALID_CLASSES)}"
                    )
                classes.add(tok)
        states: Optional[Set[str]] = None
        if state_csv:
            states = set()
            for raw in state_csv.split(","):
                tok = raw.strip().upper()
                if not tok:
                    continue
                if tok not in VALID_STATES:
                    raise ValueError(
                        f"unknown state {tok!r}; valid: {sorted(VALID_STATES)}"
                    )
                states.add(tok)
        pids: Optional[Set[int]] = None
        if pid_csv:
            pids = set()
            for raw in pid_csv.split(","):
                tok = raw.strip()
                if not tok:
                    continue
                try:
                    pids.add(int(tok))
                except ValueError:
                    raise ValueError(f"non-integer subject_id {tok!r}")
        return cls(
            class_filter=classes if classes else None,
            state_filter=states if states else None,
            subject_ids=pids if pids else None,
        )


class HyperlationStateTracker:
    """Process-wide singleton: 1Hz poller of trust kernel state.

    Polling is wrapped in try/except at every I/O boundary -- if the kernel
    module isn't loaded (WSL/dev) the tracker still returns a synthetic
    snapshot so callers (API, decision engine) degrade gracefully.

    Threading model: a single daemon thread polls every 1s; reads from
    other threads use a snapshot dict published under a lock. The lock is
    only held to swap pointers, not during sysfs I/O.
    """

    POLL_INTERVAL_S = 1.0
    # Hypothesis 1 thresholds (paper §Containment):
    STARVATION_RATIO = 0.1
    # Hypothesis 2 thresholds (paper §Behavioral Divergence):
    DIVERGENCE_DSDT = -0.1  # score / second over 5s
    # Foundational hypothesis thresholds (paper §Foundational Hypotheses):
    #   HYP_DYNAMIC_AUTHORITY: anomalous burn = > 2x baseline metabolism rate.
    #   The baseline is the per-class steady-state burn-per-S-second; below
    #   this floor we don't have enough signal to call it anomalous.
    METABOLISM_BASELINE = 0.05      # tokens / score-second, steady-state floor
    METABOLISM_BURN_MULT = 2.0      # multiplier above baseline = anomalous

    _instance: Optional["HyperlationStateTracker"] = None
    _instance_lock = threading.Lock()

    @classmethod
    def get(cls) -> "HyperlationStateTracker":
        """Return the process-wide singleton, lazily constructed."""
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self) -> None:
        self._history: Dict[int, _SubjectHistory] = {}
        self._history_lock = threading.Lock()
        self._snapshot: dict = self._empty_snapshot()
        self._snapshot_lock = threading.Lock()
        self._poll_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._libtrust = self._try_import_libtrust()
        # Per-subject empirical Markov chain over the 4 named states
        # (STEADY_FLOW, METABOLIC_STARVATION, BEHAVIORAL_DIVERGENCE,
        # APOPTOSIS). Updated O(1) per subject per poll cycle. Lives
        # under _history_lock since it's mutated alongside _SubjectHistory
        # in poll_once().
        self._markov_per_subject: Dict[int, MarkovTransitionMatrix] = {}

    @staticmethod
    def _try_import_libtrust():
        """Best-effort import of the userspace libtrust binding.

        Returns the module on success or None when running on a host without
        the kernel module / .so installed.
        """
        try:
            import libtrust  # type: ignore
            return libtrust
        except Exception:
            return None

    @staticmethod
    def _empty_snapshot() -> dict:
        return {
            "subjects": [],
            "global": {
                "theorems_violated": [],
                "total_metabolism": 0.0,
                "active_meiotic_bonds": 0,
                "cancer_detections": 0,
            },
            "timestamp": time.time(),
            "source": "uninitialized",
        }

    # -- Public API ----------------------------------------------------------

    def start(self) -> None:
        """Spawn the 1Hz poller thread (idempotent)."""
        if self._poll_thread is not None and self._poll_thread.is_alive():
            return
        self._stop.clear()
        t = threading.Thread(
            target=self._poll_loop,
            name="hyperlation-poller",
            daemon=True,
        )
        self._poll_thread = t
        t.start()
        logger.info("HyperlationStateTracker poller started")

    def stop(self) -> None:
        """Signal the poller to exit (best-effort; daemon thread anyway)."""
        self._stop.set()

    def snapshot(
        self,
        filter: Optional[HyperlationFilter] = None,
    ) -> dict:
        """Return the most recently published snapshot dict (shallow copy).

        If `filter` is provided, the returned dict's `subjects` list is
        narrowed to just the matching records. The tracker's internal
        snapshot is NOT mutated -- this is purely a view filter, so other
        callers (and the next poll cycle) see the unfiltered state.

        The returned dict (including the `subjects` list and `global` dict)
        is shallow-copied from the internal snapshot so that callers who
        mutate the returned structure (e.g., add annotation fields or
        reorder the list) cannot corrupt the tracker's internal state
        observed by other concurrent readers. Each per-subject record is
        also copied one level deep. (S78 Dev G fix for snapshot aliasing.)
        """
        with self._snapshot_lock:
            snap = dict(self._snapshot)
            # Copy mutable containers under the lock so concurrent poller
            # writers can't race with the copy pass.
            inner_subjects = list(snap.get("subjects") or [])
            inner_global = dict(snap.get("global") or {})
        snap["subjects"] = [dict(s) for s in inner_subjects]
        snap["global"] = inner_global
        if filter is None:
            return snap
        subjects = snap["subjects"]
        snap["subjects"] = [s for s in subjects if filter.matches(s)]
        # Annotate the response so the caller sees the filter applied
        # (helps with debugging "why is my list empty?" GUI tickets).
        snap["filter_applied"] = {
            "class_filter": sorted(filter.class_filter) if filter.class_filter else None,
            "state_filter": sorted(filter.state_filter) if filter.state_filter else None,
            "subject_ids": sorted(filter.subject_ids) if filter.subject_ids else None,
            "matched": len(snap["subjects"]),
            "total_before_filter": len(subjects),
        }
        return snap

    def get_subject(
        self,
        subject_id: int,
        filter: Optional[HyperlationFilter] = None,
    ) -> Optional[dict]:
        """Return per-subject record from the latest snapshot, or None.

        `filter` here is mostly used to enforce a class_filter check
        (e.g., GUI is browsing only games -- don't surface a kernel driver
        even if asked by ID). Matches the same AND-composition rules.
        """
        snap = self.snapshot()  # unfiltered inner read
        for s in snap.get("subjects", []):
            if s.get("id") == subject_id:
                if filter is not None and not filter.matches(s):
                    return None
                return s
        return None

    def state_for(self, subject_id: int) -> str:
        """Return the named state for `subject_id`, or empty string on miss.

        Returning "" (not "STEADY_FLOW") on miss lets callers distinguish
        "I have no data" from "data says steady". The
        `DecisionEngine.consult_hyperlation` wrapper applies the
        Session-49 fail-CLOSED policy on the empty case (see its docstring).

        Normalises a None `state` field to "" so the empty-on-miss
        contract holds even when a producer placed an explicit None
        rather than omitting the key. (S78 Dev G.)
        """
        rec = self.get_subject(subject_id)
        if rec is None:
            return ""
        state = rec.get("state", "")
        if state is None:
            return ""
        return state

    def markov_summary(self, subject_id: int) -> Dict[str, Any]:
        """Return the full per-subject Markov summary dict.

        Shape:
            {
              "matrix":                  list[list[float]],  # 4x4 row-stochastic
              "stationary":              list[float],        # length 4
              "expected_hitting_time":   float | None,       # None if unreachable
              "kl_anomaly_score":        float,
              "history_len":             int,
              "last_seen_state":         int | None,
              "last_seen_state_name":    str | None,         # MARKOV_STATES[i]
              "subject_id":              int,
            }

        Returns an empty-skeleton dict (history_len=0, all-zero matrix)
        if the subject has never been observed -- callers should treat
        this as "no Markov data yet" rather than as an error condition.
        """
        # Hold _history_lock for the entire summary build. The poll loop
        # (see _poll_loop around line 1139) mutates `markov` non-atomically
        # via markov.update() -- counts[i][j], recent.append(), history_len,
        # last_seen_state all change outside any internal matrix lock. If
        # we release the lock between `get()` and the matrix/stationary/KL
        # reads, the poller can race in and produce torn reads.
        # The lock-held body does only pure-Python math -- no I/O, no LLM
        # calls -- so holding it across the summary build is safe.
        with self._history_lock:
            markov = self._markov_per_subject.get(subject_id)
            if markov is None:
                empty = MarkovTransitionMatrix()
                mtx = empty.matrix()
                stat = empty.stationary()
                return {
                    "matrix": mtx,
                    "stationary": stat,
                    "expected_hitting_time": None,
                    "kl_anomaly_score": 0.0,
                    "history_len": 0,
                    "last_seen_state": None,
                    "last_seen_state_name": None,
                    "subject_id": subject_id,
                }
            mtx = markov.matrix()
            stat = markov.stationary()
            hit = markov.expected_hitting_time_to_apoptosis()
            hit_out: Optional[float] = (
                None if (math.isinf(hit) or math.isnan(hit)) else hit
            )
            last = markov.last_seen_state
            last_name = (MARKOV_STATES[last]
                         if (last is not None and 0 <= last < MARKOV_N_STATES)
                         else None)
            return {
                "matrix": mtx,
                "stationary": stat,
                "expected_hitting_time": hit_out,
                "kl_anomaly_score": markov.kl_divergence_recent_vs_steady(),
                "history_len": markov.history_len,
                "last_seen_state": last,
                "last_seen_state_name": last_name,
                "subject_id": subject_id,
            }

    def classify_markov_anomaly(self, subject_id: int) -> Optional[str]:
        """Return a Markov-anomaly tag for `subject_id`, or None.

        Tags (priority: hitting-time first, since approaching apoptosis is
        the harder failure mode and should not be masked by KL drift):
          "approaching_apoptosis" -- expected hitting time < 5 steps
          "transition_drift"      -- KL(recent || stationary) > 0.5
          None                    -- subject is in equilibrium
        """
        with self._history_lock:
            markov = self._markov_per_subject.get(subject_id)
        if markov is None or markov.history_len == 0:
            return None
        # Hitting time check (only meaningful if some 3-column transitions
        # have been observed; an inf result means "no path observed",
        # which is NOT a danger signal).
        hit = markov.expected_hitting_time_to_apoptosis()
        if (not math.isinf(hit)
                and not math.isnan(hit)
                and 0.0 < hit < MARKOV_HITTING_TIME_DANGER):
            return "approaching_apoptosis"
        # KL drift check
        kl = markov.kl_divergence_recent_vs_steady()
        if kl > MARKOV_KL_DRIFT_THRESHOLD:
            return "transition_drift"
        return None

    def theorem_violations(self) -> Dict[str, int]:
        """Return {theorem_N: violation_count} for N in (1, 2, 4, 5, 6)."""
        out: Dict[str, int] = {}
        for n in _THEOREMS:
            out[f"theorem_{n}"] = self._read_int(_THEOREM_NODES[n])
        return out

    # -- Aggregator support: /system/state -----------------------------------

    @classmethod
    def aggregate_system_state(cls) -> dict:
        """Build the canonical /system/state envelope.

        Reads kernel + cortex (snapshot summary) + coherence views, each
        view degrading per-field to None on missing path. NEVER raises --
        endpoint authors can return the dict directly.

        Schema documented at the top of this module.
        """
        # Kernel view: graceful degrade per-field.
        kernel_view: Dict[str, Optional[object]] = {
            "cancer_detections": cls._read_int_or_none(_CANCER_NODE),
            "meiosis_count": cls._read_int_or_none(_MEIOSIS_COUNT_NODE),
            "meiosis_active_bonds": cls._read_int_or_none(_MEIOSIS_NODE),
        }
        for n in _THEOREMS:
            # _THEOREM_NODES is the single source of truth for theorem path.
            kernel_view[f"theorem{n}_violations"] = cls._read_int_or_none(
                _THEOREM_NODES[n]
            )
        kernel_view["token_ledger"] = cls._read_text_or_none(
            _TRUST_AUTHZ_TOKEN_LEDGER, max_bytes=8192,
        )

        # Cortex view: summarize the current snapshot (do NOT poll inline;
        # the poller already runs at 1Hz and we don't want /system/state
        # latency to spike on a slow sysfs read).
        try:
            tracker = cls.get()
            snap = tracker.snapshot()
        except Exception as exc:
            logger.debug("aggregate_system_state snapshot failed: %s", exc)
            snap = cls._empty_snapshot()
        states_count: Dict[str, int] = {s: 0 for s in VALID_STATES}
        subjects = snap.get("subjects", [])
        for s in subjects:
            st = s.get("state")
            if st in states_count:
                states_count[st] += 1
        cortex_view = {
            "subject_count": len(subjects),
            "states": states_count,
            "total_metabolism": float(
                snap.get("global", {}).get("total_metabolism", 0.0) or 0.0
            ),
            "source": str(snap.get("source", "unknown")),
        }

        # Coherence view: tiny text files, all read-only.
        coherence_view: Dict[str, Optional[str]] = {}
        for key, path in _COHERENCE_FILES.items():
            coherence_view[key] = cls._read_text_or_none(path, max_bytes=256)
            if coherence_view[key] is not None:
                # Strip trailing newline from typical /var/run state files.
                coherence_view[key] = coherence_view[key].strip()

        return {
            "kernel": kernel_view,
            "cortex": cortex_view,
            "coherence": coherence_view,
            "aggregated_at": datetime.now(timezone.utc).isoformat(),
            "schema_version": SYSTEM_STATE_SCHEMA_VERSION,
        }

    # -- Polling -------------------------------------------------------------

    def _poll_loop(self) -> None:
        # Tight outer try/except so a single broken poll doesn't kill the
        # poller thread; we just log and continue at the next interval.
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as exc:
                logger.debug("hyperlation poll iteration failed: %s", exc)
            self._stop.wait(self.POLL_INTERVAL_S)

    def poll_once(self) -> dict:
        """Run a single polling pass and publish a fresh snapshot.

        Returns the snapshot for callers that want a synchronous read
        (smoke test, /cortex/hyperlation/state without waiting for the
        next tick).
        """
        now = time.time()
        raw = self._read_subjects()
        source = "sysfs" if raw.get("_source") == "sysfs" else (
            "libtrust" if raw.get("_source") == "libtrust" else "synthetic"
        )

        subjects_out: List[dict] = []
        total_metabolism = 0.0

        with self._history_lock:
            for entry in raw.get("subjects", []):
                sid = int(entry.get("id", 0))
                C_t = float(entry.get("C_t", 0.0))
                S_t = float(entry.get("S_t", 0.0))
                G_t = int(entry.get("G_t", 0))
                sex_int = int(entry.get("sex", SEX_XX))
                sex_label = "XY" if sex_int == SEX_XY else "XX"

                hist = self._history.get(sid)
                if hist is None:
                    hist = _SubjectHistory()
                    self._history[sid] = hist
                hist.add(now, C_t, S_t)
                dC_dt, dS_dt, burned = hist.derivatives(now)

                # Metabolism rate per paper §Dynamic Hyperlation:
                #   tokens_burned_in_last_1s / (S_t * 1.0)
                # Guard against S_t == 0 (apoptotic / never-bootstrapped).
                if S_t > 0:
                    metabolism_rate = burned / (S_t * 1.0)
                else:
                    metabolism_rate = 0.0
                total_metabolism += metabolism_rate

                state = self._classify(C_t, hist.C_starter, dC_dt, dS_dt)

                # Markov state index. APOPTOSIS is detected from the
                # canonical kernel signal (both S and C collapsed to <=0,
                # OR an explicit apoptosis flag in the raw entry); the
                # transient state classifier never emits it.
                apoptosis_now = bool(
                    entry.get("apoptosis_event")
                    or entry.get("apoptosis")
                    or entry.get("dead")
                    or (S_t <= 0.0 and C_t <= 0.0)
                )
                state_idx = (MARKOV_APOPTOSIS_IDX
                             if apoptosis_now else _state_name_to_idx(state))
                markov = self._markov_per_subject.get(sid)
                if markov is None:
                    markov = MarkovTransitionMatrix()
                    self._markov_per_subject[sid] = markov
                if state_idx is not None:
                    markov.update(state_idx)

                rec = {
                    "id": sid,
                    "C_t": C_t,
                    "S_t": S_t,
                    "G_t": G_t,
                    "L_t": sex_label,
                    "metabolism_rate": metabolism_rate,
                    "state": state,
                    "flow_vector": [dC_dt, dS_dt, G_t, sex_int],
                }
                # Pre-classify the kind so filters don't pay the heuristic
                # cost on every endpoint call.
                rec["class"] = _classify_subject_kind({**entry, "S_t": S_t})
                # Compact Markov summary in the published snapshot. Full
                # matrix / stationary live behind markov_summary(sid) so
                # we don't pay 4x4 of dicts on every snapshot read.
                kl_score = markov.kl_divergence_recent_vs_steady()
                hit_time = markov.expected_hitting_time_to_apoptosis()
                # JSON-safe: replace inf with None so consumers don't choke.
                hit_time_out: Optional[float] = (
                    None if (math.isinf(hit_time) or math.isnan(hit_time))
                    else hit_time
                )
                rec["markov"] = {
                    "kl_anomaly_score": kl_score,
                    "expected_hitting_time_steps": hit_time_out,
                }
                subjects_out.append(rec)

            # GC: drop history for subjects not seen in this pass for >120s.
            seen_now = {int(e.get("id", 0)) for e in raw.get("subjects", [])}
            stale = []
            for sid, hist in self._history.items():
                if sid in seen_now:
                    continue
                if not hist.samples:
                    stale.append(sid)
                    continue
                last_ts = hist.samples[-1][0]
                if now - last_ts > 120.0:
                    stale.append(sid)
            for sid in stale:
                self._history.pop(sid, None)
                # Drop Markov state for stale subjects too -- the GC TTL
                # is identical so the two maps stay in lockstep.
                self._markov_per_subject.pop(sid, None)

        theorems = self.theorem_violations()
        violated = [k for k, v in theorems.items() if v > 0]
        snapshot = {
            "subjects": subjects_out,
            "global": {
                "theorems_violated": violated,
                "theorem_counts": theorems,
                "total_metabolism": total_metabolism,
                "active_meiotic_bonds": self._read_int(_MEIOSIS_NODE),
                "cancer_detections": self._read_int(_CANCER_NODE),
            },
            "timestamp": now,
            "source": source,
        }
        with self._snapshot_lock:
            self._snapshot = snapshot
        return snapshot

    # -- Classification ------------------------------------------------------

    @classmethod
    def _classify(
        cls,
        C_t: float,
        C_starter: Optional[float],
        dC_dt: float,
        dS_dt: float,
    ) -> str:
        """Map the 4-tuple to one of the paper's three named states."""
        # Hypothesis 1: Containment via metabolic starvation.
        if C_starter and C_starter > 0:
            if (C_t / C_starter) < cls.STARVATION_RATIO and dC_dt < 0:
                return "METABOLIC_STARVATION"
        # Hypothesis 2: Behavioral divergence (score collapse).
        if dS_dt < cls.DIVERGENCE_DSDT:
            return "BEHAVIORAL_DIVERGENCE"
        return "STEADY_FLOW"

    @classmethod
    def classify_hypothesis_violation(
        cls,
        subject_state: dict,
    ) -> List[HypothesisSlot]:
        """Return the foundational hypotheses whose anomaly pattern is present.

        See `HypothesisSlot` for the per-slot semantics. The classifier is
        pure (no I/O), accepts the same per-subject record shape that
        `snapshot()["subjects"][i]` returns, and is empty-list-on-noise: a
        STEADY_FLOW subject with normal metabolism returns `[]`.

        Inputs read from `subject_state` (all optional, missing -> skip slot):
            metabolism_rate (float): tokens-burned-per-second-per-S, set
                by poll_once(). Compared against METABOLISM_BASELINE *
                METABOLISM_BURN_MULT for HYP_DYNAMIC_AUTHORITY.
            state (str): one of VALID_STATES. BEHAVIORAL_DIVERGENCE flips
                HYP_BIOLOGICAL_TRUST.
            apoptosis_event (bool) | apoptosis (bool) | dead (bool):
                Any-true triggers HYP_APOPTOTIC_SAFETY. Falls back to
                S_t <= 0 + dead-flag-from-kernel if the explicit field
                isn't present (kernel reports apoptosis as score zeroing).
        """
        violated: List[HypothesisSlot] = []

        # HYP_DYNAMIC_AUTHORITY: metabolism > 2x baseline.
        try:
            metab = float(subject_state.get("metabolism_rate", 0.0) or 0.0)
        except (TypeError, ValueError):
            metab = 0.0
        if metab > (cls.METABOLISM_BASELINE * cls.METABOLISM_BURN_MULT):
            violated.append(HYP_DYNAMIC_AUTHORITY)

        # HYP_BIOLOGICAL_TRUST: divergence already detected by state classifier.
        if subject_state.get("state") == "BEHAVIORAL_DIVERGENCE":
            violated.append(HYP_BIOLOGICAL_TRUST)

        # HYP_APOPTOTIC_SAFETY: explicit kernel apoptosis flag, or S_t collapsed
        # to zero with no credit (the kernel signals apoptosis by zeroing
        # both score and credit before the subject is reaped).
        apoptosis = bool(
            subject_state.get("apoptosis_event")
            or subject_state.get("apoptosis")
            or subject_state.get("dead")
        )
        if not apoptosis:
            try:
                S_t = float(subject_state.get("S_t", 1.0))
                C_t = float(subject_state.get("C_t", 1.0))
                if S_t <= 0.0 and C_t <= 0.0:
                    apoptosis = True
            except (TypeError, ValueError):
                pass
        if apoptosis:
            violated.append(HYP_APOPTOTIC_SAFETY)

        return violated

    # -- Sysfs / libtrust I/O (every call wrapped) ---------------------------

    @staticmethod
    def _read_int(path: str) -> int:
        try:
            with open(path, "r") as f:
                raw = f.read().strip()
            return int(raw, 0) if raw else 0
        except (OSError, ValueError):
            return 0

    @staticmethod
    def _read_int_or_none(path: str) -> Optional[int]:
        """Like _read_int but returns None on missing path / parse fail.

        Used by the /system/state aggregator so the response can show
        operators which kernel facets are present vs degraded, instead of
        coercing every miss to 0 (which would silently lie).
        """
        try:
            with open(path, "r") as f:
                raw = f.read().strip()
            if not raw:
                return None
            return int(raw, 0)
        except (OSError, ValueError):
            return None

    @staticmethod
    def _read_text_or_none(path: str, max_bytes: int = 4096) -> Optional[str]:
        """Read up to `max_bytes` of text or None on miss."""
        try:
            with open(path, "r") as f:
                return f.read(max_bytes)
        except OSError:
            return None

    def _read_subjects(self) -> dict:
        """Try libtrust, then sysfs, then synthetic. Always returns a dict."""
        # Path 1: libtrust binding (preferred -- bulk ioctl, no path walk).
        if self._libtrust is not None:
            try:
                fn = getattr(self._libtrust, "list_subjects", None)
                if callable(fn):
                    rows = fn() or []
                    out = []
                    for r in rows:
                        # Accept either dict or attribute-style records.
                        if isinstance(r, dict):
                            out.append({
                                "id": r.get("id", 0),
                                "C_t": r.get("C_t", r.get("credit", 0.0)),
                                "S_t": r.get("S_t", r.get("score", 0.0)),
                                "G_t": r.get("G_t", r.get("generation", 0)),
                                "sex": r.get("sex", SEX_XX),
                                "kind": r.get("kind") or r.get("class"),
                            })
                        else:
                            out.append({
                                "id": getattr(r, "id", 0),
                                "C_t": getattr(r, "C_t", 0.0),
                                "S_t": getattr(r, "S_t", 0.0),
                                "G_t": getattr(r, "G_t", 0),
                                "sex": getattr(r, "sex", SEX_XX),
                                "kind": getattr(r, "kind", None),
                            })
                    return {"subjects": out, "_source": "libtrust"}
            except Exception as exc:
                logger.debug("libtrust list_subjects failed: %s", exc)

        # Path 2: sysfs walk under /sys/kernel/trust/subjects/<id>/.
        try:
            if os.path.isdir(_SUBJECTS_DIR):
                out = []
                for name in os.listdir(_SUBJECTS_DIR):
                    if not name.isdigit():
                        continue
                    sid = int(name)
                    base = os.path.join(_SUBJECTS_DIR, name)
                    rec = {
                        "id": sid,
                        "C_t": self._read_float(os.path.join(base, "credit")),
                        "S_t": self._read_float(os.path.join(base, "score")),
                        "G_t": self._read_int(os.path.join(base, "generation")),
                        "sex": self._read_int(os.path.join(base, "sex")),
                        "kind": self._read_text_or_none(
                            os.path.join(base, "kind"), 64,
                        ),
                    }
                    out.append(rec)
                return {"subjects": out, "_source": "sysfs"}
        except OSError as exc:
            logger.debug("sysfs subjects walk failed: %s", exc)

        # Path 3: synthetic placeholder for WSL/dev.
        return {"subjects": [], "_source": "synthetic"}

    @staticmethod
    def _read_float(path: str) -> float:
        try:
            with open(path, "r") as f:
                raw = f.read().strip()
            return float(raw) if raw else 0.0
        except (OSError, ValueError):
            return 0.0


# -- Smoke test ---------------------------------------------------------------

if __name__ == "__main__":
    """Exercise every Session-49 deliverable: filters, aggregator, fail-closed."""
    import json as _json

    logging.basicConfig(level=logging.INFO)
    tracker = HyperlationStateTracker.get()

    passed = 0
    failed = 0

    def _check(label: str, cond: bool, detail: str = "") -> None:
        global passed, failed
        if cond:
            passed += 1
            print(f"  PASS  {label}")
        else:
            failed += 1
            print(f"  FAIL  {label}{('  -- ' + detail) if detail else ''}")

    # If /sys isn't there (WSL/dev), inject a few synthetic subjects through
    # the history layer so callers can see the classifier in action.
    if not os.path.isdir(_SUBJECTS_DIR):
        print("[hyperlation] /sys/kernel/trust/subjects absent -- using fake data")
        now = time.time()
        with tracker._history_lock:
            # Subject 1001: STEADY_FLOW system_service (XY, S high)
            h1 = _SubjectHistory()
            h1.add(now - 5.0, 1000.0, 70.0)
            h1.add(now - 1.0, 990.0, 70.5)
            h1.add(now, 985.0, 70.5)
            tracker._history[1001] = h1
            # Subject 1002: METABOLIC_STARVATION user_app
            h2 = _SubjectHistory()
            h2.C_starter = 1000.0
            h2.add(now - 5.0, 200.0, 50.0)
            h2.add(now - 1.0, 90.0, 49.0)
            h2.add(now, 50.0, 48.5)
            tracker._history[1002] = h2
            # Subject 1003: BEHAVIORAL_DIVERGENCE game (XY, low S)
            h3 = _SubjectHistory()
            h3.add(now - 5.0, 1000.0, 80.0)
            h3.add(now - 2.0, 998.0, 60.0)
            h3.add(now, 996.0, 25.0)
            tracker._history[1003] = h3

        # Build a snapshot from the injected history and seed the tracker.
        subjects_out = []
        for sid, hist in tracker._history.items():
            ts, C, S = hist.samples[-1]
            dC, dS, burned = hist.derivatives(now)
            metab = burned / (S * 1.0) if S > 0 else 0.0
            state = HyperlationStateTracker._classify(
                C, hist.C_starter, dC, dS,
            )
            kind_input = {
                "S_t": S, "sex": SEX_XY, "G_t": 0,
            }
            if sid == 1003:
                kind_input["S_t"] = 25
            cls = _classify_subject_kind(kind_input)
            subjects_out.append({
                "id": sid, "C_t": C, "S_t": S, "G_t": 1, "L_t": "XY",
                "metabolism_rate": metab, "state": state,
                "flow_vector": [dC, dS, 1, SEX_XY],
                "class": cls,
            })
        snap = {
            "subjects": subjects_out,
            "global": {
                "theorems_violated": [], "theorem_counts": {},
                "total_metabolism": sum(s["metabolism_rate"] for s in subjects_out),
                "active_meiotic_bonds": 0, "cancer_detections": 0,
            },
            "timestamp": now, "source": "synthetic-smoke",
        }
        with tracker._snapshot_lock:
            tracker._snapshot = snap

    # ---- Filter tests --------------------------------------------------
    print("\n[smoke] Filter tests:")
    snap_all = tracker.snapshot()
    _check("unfiltered snapshot returns subjects",
           len(snap_all.get("subjects", [])) >= 3,
           f"got {len(snap_all.get('subjects', []))}")

    f_state_div = HyperlationFilter(state_filter={"BEHAVIORAL_DIVERGENCE"})
    snap_div = tracker.snapshot(filter=f_state_div)
    _check("state_filter=BEHAVIORAL_DIVERGENCE narrows the list",
           all(s["state"] == "BEHAVIORAL_DIVERGENCE"
               for s in snap_div["subjects"]) and len(snap_div["subjects"]) >= 1,
           f"got {[s['state'] for s in snap_div['subjects']]}")

    f_pid = HyperlationFilter(subject_ids={1001, 1003})
    snap_pid = tracker.snapshot(filter=f_pid)
    ids_seen = {s["id"] for s in snap_pid["subjects"]}
    _check("subject_ids filter matches IDs", ids_seen == {1001, 1003},
           f"got {ids_seen}")

    f_combo = HyperlationFilter(
        subject_ids={1001, 1002, 1003},
        state_filter={"METABOLIC_STARVATION"},
    )
    snap_combo = tracker.snapshot(filter=f_combo)
    _check("AND-composition: pid+state",
           [s["id"] for s in snap_combo["subjects"]] == [1002],
           f"got {[s['id'] for s in snap_combo['subjects']]}")

    # Filter does NOT mutate underlying snapshot
    snap_after = tracker.snapshot()
    _check("filter is a view -- tracker snapshot unaffected",
           len(snap_after.get("subjects", [])) == len(snap_all.get("subjects", [])))

    # parse_query: valid + invalid
    try:
        f_parsed = HyperlationFilter.parse_query(
            class_csv="game,user_app",
            state_csv="BEHAVIORAL_DIVERGENCE",
            pid_csv="1001,1003",
        )
        _check("parse_query accepts well-formed CSVs",
               f_parsed.subject_ids == {1001, 1003}
               and f_parsed.state_filter == {"BEHAVIORAL_DIVERGENCE"}
               and f_parsed.class_filter == {"game", "user_app"})
    except Exception as exc:
        _check("parse_query accepts well-formed CSVs", False, str(exc))

    bad_inputs = [
        {"class_csv": "weapon"},
        {"state_csv": "PANIC"},
        {"pid_csv": "abc"},
    ]
    for bad in bad_inputs:
        try:
            HyperlationFilter.parse_query(**bad)
            _check(f"parse_query rejects {bad}", False, "no exception raised")
        except ValueError:
            _check(f"parse_query rejects {bad}", True)

    # ---- Aggregator -----------------------------------------------------
    print("\n[smoke] Aggregator tests:")
    agg = HyperlationStateTracker.aggregate_system_state()
    _check("aggregator has all three views",
           {"kernel", "cortex", "coherence"}.issubset(agg.keys()))
    _check("schema_version == 1", agg.get("schema_version") == 1)
    _check("aggregated_at is ISO8601", isinstance(agg.get("aggregated_at"), str)
           and "T" in agg["aggregated_at"])
    _check("cortex view has subject_count",
           isinstance(agg["cortex"].get("subject_count"), int)
           and agg["cortex"]["subject_count"] >= 3)
    # Kernel view fields all present (value may be None on WSL).
    expected_kernel_keys = {
        "cancer_detections", "meiosis_count", "meiosis_active_bonds",
        "theorem1_violations", "theorem2_violations", "theorem4_violations",
        "theorem5_violations", "theorem6_violations", "token_ledger",
    }
    _check("kernel view exposes every documented field",
           expected_kernel_keys.issubset(agg["kernel"].keys()),
           f"missing: {expected_kernel_keys - set(agg['kernel'].keys())}")
    _check("coherence view has 3 documented fields",
           {"game_active", "vrr_target", "present_mode"}.issubset(
               agg["coherence"].keys()))

    # ---- Fail-CLOSED default --------------------------------------------
    # state_for() now returns "" on miss (not "STEADY_FLOW"); the
    # DecisionEngine.consult_hyperlation wrapper turns the empty into
    # BEHAVIORAL_DIVERGENCE. We can verify state_for() here directly;
    # decision_engine import is exercised in its own test suite.
    print("\n[smoke] Fail-closed default tests:")
    miss = tracker.state_for(99999999)
    _check("state_for(unknown) returns empty (not STEADY_FLOW)", miss == "",
           f"got {miss!r}")
    hit = tracker.state_for(1003)
    _check("state_for(known) returns the actual classified state",
           hit == "BEHAVIORAL_DIVERGENCE", f"got {hit!r}")

    # ---- Foundational hypothesis slots ---------------------------------
    print("\n[smoke] HypothesisSlot tests:")
    _check("HypothesisSlot enum has 3 members", len(list(HypothesisSlot)) == 3)
    _check("HYPOTHESIS_SLOTS exports all 3",
           set(HYPOTHESIS_SLOTS) == {
               HYP_DYNAMIC_AUTHORITY,
               HYP_BIOLOGICAL_TRUST,
               HYP_APOPTOTIC_SAFETY,
           })
    _check("HYP_DYNAMIC_AUTHORITY is a HypothesisSlot",
           isinstance(HYP_DYNAMIC_AUTHORITY, HypothesisSlot))
    _check("HYP_BIOLOGICAL_TRUST is a HypothesisSlot",
           isinstance(HYP_BIOLOGICAL_TRUST, HypothesisSlot))
    _check("HYP_APOPTOTIC_SAFETY is a HypothesisSlot",
           isinstance(HYP_APOPTOTIC_SAFETY, HypothesisSlot))

    # Three fixtures for classify_hypothesis_violation -- one per state.
    fixture_starvation = {
        "id": 1002, "C_t": 50.0, "S_t": 48.5, "G_t": 1, "L_t": "XY",
        "metabolism_rate": 0.30,           # > 2x baseline (0.05*2=0.1)
        "state": "METABOLIC_STARVATION",
        "flow_vector": [-30.0, -0.1, 1, SEX_XY],
        "class": "user_app",
    }
    fixture_divergence = {
        "id": 1003, "C_t": 996.0, "S_t": 25.0, "G_t": 1, "L_t": "XY",
        "metabolism_rate": 0.02,           # below baseline -- only state slot
        "state": "BEHAVIORAL_DIVERGENCE",
        "flow_vector": [-1.0, -10.0, 1, SEX_XY],
        "class": "game",
    }
    fixture_steady = {
        "id": 1001, "C_t": 985.0, "S_t": 70.5, "G_t": 1, "L_t": "XY",
        "metabolism_rate": 0.01,           # below baseline
        "state": "STEADY_FLOW",
        "flow_vector": [-3.0, 0.0, 1, SEX_XY],
        "class": "system_service",
    }
    cls_starv = HyperlationStateTracker.classify_hypothesis_violation(
        fixture_starvation)
    cls_div = HyperlationStateTracker.classify_hypothesis_violation(
        fixture_divergence)
    cls_steady = HyperlationStateTracker.classify_hypothesis_violation(
        fixture_steady)
    _check("METABOLIC_STARVATION fixture flags HYP_DYNAMIC_AUTHORITY",
           HYP_DYNAMIC_AUTHORITY in cls_starv,
           f"got {[s.name for s in cls_starv]}")
    _check("BEHAVIORAL_DIVERGENCE fixture flags HYP_BIOLOGICAL_TRUST",
           HYP_BIOLOGICAL_TRUST in cls_div,
           f"got {[s.name for s in cls_div]}")
    _check("STEADY_FLOW fixture flags zero hypotheses",
           cls_steady == [],
           f"got {[s.name for s in cls_steady]}")

    # Apoptosis fixture: explicit kernel apoptosis_event flag.
    fixture_apop = {
        "id": 1004, "C_t": 0.0, "S_t": 0.0, "G_t": 1, "L_t": "XY",
        "metabolism_rate": 0.0,
        "state": "STEADY_FLOW",
        "apoptosis_event": True,
        "class": "user_app",
    }
    cls_apop = HyperlationStateTracker.classify_hypothesis_violation(
        fixture_apop)
    _check("apoptosis fixture flags HYP_APOPTOTIC_SAFETY",
           HYP_APOPTOTIC_SAFETY in cls_apop,
           f"got {[s.name for s in cls_apop]}")

    # ---- Sysfs path correctness (tempdir mock) -------------------------
    # Verify EVERY theorem reader lands at /sys/kernel/trust_invariants/...
    # not the legacy /sys/kernel/trust/... path. We do this by mocking the
    # filesystem via tempdir + monkeypatching the module-level _THEOREM_NODES.
    print("\n[smoke] Sysfs path tests:")
    import tempfile
    import sys as _sys
    # Use the running module object directly -- works whether we were
    # imported by name or invoked as __main__ by `python3 dynamic_hyperlation.py`.
    _self_mod = _sys.modules[__name__]

    # 1. Static check: every entry in _THEOREM_NODES is under trust_invariants.
    bad_paths = [p for p in _THEOREM_NODES.values()
                 if not p.startswith(_TRUST_INVARIANTS_ROOT + "/")]
    _check("_THEOREM_NODES all under /sys/kernel/trust_invariants/",
           bad_paths == [], f"bad: {bad_paths}")

    # 2. Static check: NO path in this module hard-codes the legacy
    #    /sys/kernel/trust/theorem* shape.
    import re as _re
    src_path = os.path.abspath(__file__)
    with open(src_path, "r", encoding="utf-8") as _f:
        _src = _f.read()
    legacy_hits = _re.findall(r"/sys/kernel/trust/theorem\d", _src)
    _check("no legacy /sys/kernel/trust/theorem* references in source",
           legacy_hits == [], f"found: {legacy_hits}")

    # 3. Live mock: write fake counters into a tempdir, monkeypatch the
    #    theorem path map, confirm theorem_violations() picks them up.
    with tempfile.TemporaryDirectory() as _td:
        fake_root = os.path.join(_td, "trust_invariants")
        os.makedirs(fake_root, exist_ok=True)
        for n, real in _THEOREM_NODES.items():
            fname = os.path.basename(real)  # theoremN_violations
            with open(os.path.join(fake_root, fname), "w") as _f:
                _f.write(str(n * 7))        # theorem1=7, theorem2=14, ...
        saved = dict(_THEOREM_NODES)
        try:
            for n in _THEOREMS:
                _self_mod._THEOREM_NODES[n] = os.path.join(
                    fake_root, f"theorem{n}_violations")
            tv = tracker.theorem_violations()
            expected = {f"theorem_{n}": n * 7 for n in _THEOREMS}
            _check("theorem_violations reads mocked tempdir paths",
                   tv == expected, f"got {tv}")
        finally:
            for n in _THEOREMS:
                _self_mod._THEOREM_NODES[n] = saved[n]

    # 4. Aggregator should also use the corrected paths -- verify by
    #    monkeypatching again and checking aggregate_system_state.
    with tempfile.TemporaryDirectory() as _td:
        fake_root = os.path.join(_td, "trust_invariants")
        os.makedirs(fake_root, exist_ok=True)
        for n in _THEOREMS:
            fname = f"theorem{n}_violations"
            with open(os.path.join(fake_root, fname), "w") as _f:
                _f.write(str(n * 11))
        saved = dict(_THEOREM_NODES)
        try:
            for n in _THEOREMS:
                _self_mod._THEOREM_NODES[n] = os.path.join(
                    fake_root, f"theorem{n}_violations")
            agg2 = HyperlationStateTracker.aggregate_system_state()
            expected_agg = {f"theorem{n}_violations": n * 11 for n in _THEOREMS}
            got_agg = {k: agg2["kernel"].get(k) for k in expected_agg}
            _check("aggregate_system_state reads mocked tempdir paths",
                   got_agg == expected_agg,
                   f"got {got_agg}, expected {expected_agg}")
        finally:
            for n in _THEOREMS:
                _self_mod._THEOREM_NODES[n] = saved[n]

    # ---- Markov transition matrix (Session 58, Agent 2) ----------------
    print("\n[smoke] MarkovTransitionMatrix tests:")

    # Build a chain that should look stable: 50 STEADY_FLOW transitions,
    # then 5 BEHAVIORAL_DIVERGENCE in a row -> KL spike on a small recent
    # window, expected_hitting_time should remain inf (we never showed a
    # transition into APOPTOSIS).
    mk = MarkovTransitionMatrix()
    for _ in range(50):
        mk.update(MARKOV_STATE_INDEX["STEADY_FLOW"])
    kl_before = mk.kl_divergence_recent_vs_steady(recent_window=10)
    print(f"  KL(recent || steady) after 50x STEADY_FLOW = {kl_before:.6f}")
    _check("KL near zero in pure STEADY_FLOW regime", kl_before < 0.05,
           f"got {kl_before}")

    # Inject 5 BEHAVIORAL_DIVERGENCE
    for _ in range(5):
        mk.update(MARKOV_STATE_INDEX["BEHAVIORAL_DIVERGENCE"])
    kl_after = mk.kl_divergence_recent_vs_steady(recent_window=10)
    print(f"  KL(recent || steady) after 5x DIVERGENCE injection = {kl_after:.6f}")
    _check("KL spikes when recent window diverges from history",
           kl_after > kl_before + 0.5,
           f"got before={kl_before} after={kl_after}")

    # Build a separate chain that ENDS in APOPTOSIS so hitting time -> 0.
    mk2 = MarkovTransitionMatrix()
    for _ in range(20):
        mk2.update(MARKOV_STATE_INDEX["STEADY_FLOW"])
    for _ in range(7):
        mk2.update(MARKOV_STATE_INDEX["METABOLIC_STARVATION"])
    for _ in range(3):
        mk2.update(MARKOV_STATE_INDEX["APOPTOSIS"])
    hit_at_apop = mk2.expected_hitting_time_to_apoptosis()
    print(f"  hitting_time when last_seen=APOPTOSIS = {hit_at_apop}")
    _check("expected hitting time is 0 when already absorbed",
           hit_at_apop == 0.0, f"got {hit_at_apop}")

    # Reachable-but-not-yet-there: build chain with rare 1->3 transitions
    # so the hitting time is finite and >0 from a transient state.
    mk3 = MarkovTransitionMatrix()
    # 30 STEADY (state 0) self-transitions, then bounce 0->1->3->...
    for _ in range(30):
        mk3.update(MARKOV_STATE_INDEX["STEADY_FLOW"])
    mk3.update(MARKOV_STATE_INDEX["METABOLIC_STARVATION"])
    mk3.update(MARKOV_STATE_INDEX["APOPTOSIS"])
    # Reset last_seen back into a transient state to ask the question:
    # "from STEADY_FLOW today, how long until apoptosis on average?"
    mk3.last_seen_state = MARKOV_STATE_INDEX["STEADY_FLOW"]
    hit_from_steady = mk3.expected_hitting_time_to_apoptosis()
    print(f"  hitting_time from STEADY (with 0->1->3 path) = {hit_from_steady}")
    _check("hitting time finite when path to APOPTOSIS exists",
           not math.isinf(hit_from_steady) and hit_from_steady > 0.0,
           f"got {hit_from_steady}")

    # Print the resulting transition matrix from mk2 so an operator can
    # eyeball the absorbing-row structure.
    print("  mk2 transition matrix (rows = from, cols = to):")
    P = mk2.matrix()
    header = "    " + "  ".join(f"{s[:8]:>8}" for s in MARKOV_STATES)
    print(header)
    for i, row in enumerate(P):
        print(f"    {MARKOV_STATES[i][:8]:>8}  "
              + "  ".join(f"{p:8.4f}" for p in row))
    # Absorbing-row sanity: row 3 must be [0, 0, 0, 1.0]
    _check("APOPTOSIS row is absorbing (P[3] == [0,0,0,1])",
           P[3] == [0.0, 0.0, 0.0, 1.0],
           f"got {P[3]}")

    # to_dict / from_dict round trip
    rt = MarkovTransitionMatrix.from_dict(mk2.to_dict())
    _check("to_dict/from_dict round trip preserves counts",
           rt.counts == mk2.counts, "counts mismatch")
    _check("to_dict/from_dict round trip preserves history_len",
           rt.history_len == mk2.history_len, "history_len mismatch")

    # Tracker integration: directly seed a Markov chain for a synthetic
    # subject (synthetic-mode poll_once produces no subjects on WSL/dev),
    # then verify markov_summary returns the documented schema.
    with tracker._history_lock:
        tracker._markov_per_subject[1003] = MarkovTransitionMatrix()
        for _ in range(5):
            tracker._markov_per_subject[1003].update(
                MARKOV_STATE_INDEX["BEHAVIORAL_DIVERGENCE"])
    summary_1003 = tracker.markov_summary(1003)
    _check("markov_summary returns the documented schema",
           {"matrix", "stationary", "expected_hitting_time",
            "kl_anomaly_score", "history_len"}.issubset(summary_1003.keys()))
    _check("markov_summary reflects observed history_len",
           summary_1003["history_len"] == 5,
           f"got history_len={summary_1003['history_len']}")
    # Snapshot enrichment: explicit "subject through poll_once would carry
    # a markov dict" check via the same code path the production poller
    # uses. We exercise this by injecting a fake _read_subjects result.
    saved_read = tracker._read_subjects
    try:
        tracker._read_subjects = lambda: {
            "subjects": [{"id": 9999, "C_t": 1000.0, "S_t": 70.0,
                          "G_t": 1, "sex": SEX_XY, "kind": "system_service"}],
            "_source": "synthetic",
        }
        tracker.poll_once()
        snap_now = tracker.snapshot()
        match = [s for s in snap_now["subjects"] if s["id"] == 9999]
        _check("poll_once attaches compact markov dict to subject record",
               len(match) == 1
               and isinstance(match[0].get("markov"), dict)
               and "kl_anomaly_score" in match[0]["markov"]
               and "expected_hitting_time_steps" in match[0]["markov"],
               f"got {match[0].get('markov') if match else 'no subject'}")
    finally:
        tracker._read_subjects = saved_read

    # classify_markov_anomaly: exercise both tags.
    # Force a synthetic subject into "approaching_apoptosis" by directly
    # constructing a Markov chain with a strong path to APOPTOSIS and
    # parking last_seen at a transient state.
    with tracker._history_lock:
        forced = MarkovTransitionMatrix()
        # 5x STEADY->STEADY, then STEADY->APOPTOSIS: P(0->3) = 1/6 ~ 0.167
        # Hitting time from state 0 ~= 1 / 0.167 = 6 steps; tighten:
        # 1x STEADY->STEADY, then STEADY->APOPTOSIS: P(0->3)=0.5, hit~2.
        forced.update(0)  # prime
        forced.update(0)  # 0->0
        forced.update(MARKOV_APOPTOSIS_IDX)  # 0->3
        forced.last_seen_state = 0  # ask "from STEADY" again
        tracker._markov_per_subject[424242] = forced
    tag = tracker.classify_markov_anomaly(424242)
    print(f"  classify_markov_anomaly(forced near-apoptosis subject) = {tag!r}")
    _check("classify_markov_anomaly tags approaching_apoptosis",
           tag == "approaching_apoptosis",
           f"got {tag!r}")

    # transition_drift: chain in pure STEADY plus recent burst of DIVERGENCE
    with tracker._history_lock:
        drifty = MarkovTransitionMatrix()
        for _ in range(40):
            drifty.update(MARKOV_STATE_INDEX["STEADY_FLOW"])
        for _ in range(8):
            drifty.update(MARKOV_STATE_INDEX["BEHAVIORAL_DIVERGENCE"])
        tracker._markov_per_subject[424243] = drifty
    tag2 = tracker.classify_markov_anomaly(424243)
    print(f"  classify_markov_anomaly(drifty subject) = {tag2!r}")
    _check("classify_markov_anomaly tags transition_drift on KL spike",
           tag2 == "transition_drift",
           f"got {tag2!r}")

    # Equilibrium: pure STEADY chain returns None.
    with tracker._history_lock:
        calm = MarkovTransitionMatrix()
        for _ in range(40):
            calm.update(MARKOV_STATE_INDEX["STEADY_FLOW"])
        tracker._markov_per_subject[424244] = calm
    _check("classify_markov_anomaly returns None in equilibrium",
           tracker.classify_markov_anomaly(424244) is None,
           f"got {tracker.classify_markov_anomaly(424244)!r}")

    # ---- Final tally ----------------------------------------------------
    print(f"\n[smoke] Result: {passed} pass / {failed} fail")
    if failed == 0:
        print("[smoke] OK")
    print("\n[smoke] Sample aggregator envelope:")
    print(_json.dumps(agg, indent=2, default=str)[:1500])
