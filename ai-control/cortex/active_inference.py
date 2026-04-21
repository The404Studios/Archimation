"""
Active-Inference Cortex (Friston FEP) -- S74 Cluster 2 (meta-exploit).

Replaces the passive-Markov-on-cortex-events loop of decision_engine.py with
a generative agent that:

  1. Subscribes to TrustObserver + MemoryObserver events.
  2. Compresses current ecosystem state into a small discrete *belief* token
     (10-20 bucketed dimensions -> a single joined state string).
  3. Maintains a learned transition model  P(s' | s, a)  as Dirichlet counts.
  4. Each cycle computes *expected free energy*  G(a)  for each candidate
     action and selects argmin.  Free-energy minimisation = Friston FEP.
  5. Publishes the selected action + the posterior back onto the cortex
     EventBus so the existing decision_engine (Markov) can either consume
     or coexist.

This layer does NOT touch decision_engine.py (separate sibling layer).
It lives alongside dynamic_hyperlation.py and trust_translate.py.

Reference:  Friston KJ. "The free-energy principle: a unified brain theory?"
Nature Reviews Neuroscience 11, 127-138 (2010).  Parr T, Pezzulo G, Friston KJ.
"Active Inference: The Free Energy Principle in Mind, Brain, and Behavior"
(MIT Press 2022).

S73 Cluster 2 converged on this gap from three independent frameworks:
  E  Maturana & Varela autopoiesis   (close the perception->action loop)
  I  Friston FEP                      (variational free-energy cortex)
  B  Beer VSM algedonic               (sub-ms kernel->cortex bypass)

~400 LOC target.  No numpy dep -- uses math + collections.defaultdict so the
module imports cleanly on any base Python 3.10+.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

logger = logging.getLogger("cortex.active_inference")

# --------------------------------------------------------------------------
# Design constants
# --------------------------------------------------------------------------

# Dirichlet concentration prior.  alpha = 1.0 is the uniform Laplace smoother
# ("add-one") which gives max-entropy over s' for unseen (s, a) pairs -- this
# is the correct prior for an agent that starts *ignorant* and should explore.
# A smaller alpha (e.g. 0.1) biases toward sparse / deterministic transitions;
# a larger alpha (e.g. 10) over-smooths and delays learning.  Friston's own
# examples typically use alpha in [0.5, 2]; we pick 1.0 for the uniform prior.
DIRICHLET_ALPHA = 1.0

# Number of observations to absorb before the agent is allowed to SELECT an
# action.  Below this the model is too sparse for expected-free-energy to be
# anything other than noise; the agent emits a no-op action and just learns.
BOOTSTRAP_OBSERVATIONS = 20

# Upper bound on (prev_s, a) pairs kept in the model, to keep memory bounded
# under a long-running daemon.  LRU eviction on insertion order.
MAX_MODEL_ENTRIES = 4096

# Candidate action vocabulary.  These must map onto trust kernel actions the
# decision_engine / autonomy controller already understand.  Kept small
# deliberately -- G(a) scales linearly in len(candidates), and FEP is
# meaningful only when each action is semantically distinct.
DEFAULT_ACTION_CANDIDATES: tuple[str, ...] = (
    "noop",
    "tighten_thresholds",
    "relax_thresholds",
    "freeze_cancerous",
    "request_quorum",
    "trigger_algedonic",
    "promote_healthy",
    "demote_divergent",
)


# --------------------------------------------------------------------------
# Generative model:  P(s' | s, a)  with Dirichlet-alpha=1 priors
# --------------------------------------------------------------------------

class GenerativeModel:
    """
    Sparse transition model over discrete state tokens.

    Internally:  counts[(s, a)][s'] = integer count, plus Dirichlet-alpha
    smoother for posteriors.  Lock-free reads; writes serialised through a
    simple RLock because observer callbacks can fire from multiple executor
    threads inside the daemon lifespan block.
    """

    def __init__(self, alpha: float = DIRICHLET_ALPHA,
                 max_entries: int = MAX_MODEL_ENTRIES) -> None:
        self.alpha = float(alpha)
        self.max_entries = int(max_entries)
        # dict-of-dict, not full defaultdict, so we can do LRU eviction.
        self._counts: dict[tuple[str, str], dict[str, int]] = {}
        # Outcome vocabulary -- grows monotonically; used as the support of
        # s' for unseen (s, a) pairs.
        self._outcomes: set[str] = set()
        self._lock = threading.RLock()
        self._total_updates: int = 0

    # ---- learning ----------------------------------------------------------

    def update(self, prev_s: str, action: str, new_s: str) -> None:
        """Increment count for P(new_s | prev_s, action)."""
        if not prev_s or not action or not new_s:
            return
        with self._lock:
            key = (prev_s, action)
            bucket = self._counts.get(key)
            if bucket is None:
                if len(self._counts) >= self.max_entries:
                    # LRU eviction: dict iteration is insertion order.
                    oldest = next(iter(self._counts))
                    self._counts.pop(oldest, None)
                bucket = {}
                self._counts[key] = bucket
            bucket[new_s] = bucket.get(new_s, 0) + 1
            self._outcomes.add(new_s)
            self._total_updates += 1

    # ---- inference ---------------------------------------------------------

    def predict(self, s: str, a: str) -> dict[str, float]:
        """
        Return normalized posterior P(s' | s, a) with Dirichlet smoothing.

        For unseen (s, a) pairs returns uniform distribution over the full
        outcome vocabulary (max-entropy ignorance prior).
        """
        with self._lock:
            bucket = self._counts.get((s, a))
            outcomes = set(self._outcomes)
            if bucket is not None:
                outcomes.update(bucket.keys())
            if not outcomes:
                # Total ignorance -- caller should treat as no-info.
                return {}

            alpha = self.alpha
            counts = {o: (bucket[o] if bucket and o in bucket else 0) + alpha
                      for o in outcomes}
            total = sum(counts.values())
            if total <= 0.0:
                return {}
            return {o: c / total for o, c in counts.items()}

    def entropy(self, s: str, a: str) -> float:
        """Shannon entropy H[P(s'|s,a)] in nats."""
        dist = self.predict(s, a)
        if not dist:
            return 0.0
        h = 0.0
        for p in dist.values():
            if p > 0.0:
                h -= p * math.log(p)
        return h

    def state_entropy(self, s: str) -> float:
        """Average H over all actions conditioned on s (diagnostic)."""
        with self._lock:
            actions = {k[1] for k in self._counts if k[0] == s}
        if not actions:
            return 0.0
        return sum(self.entropy(s, a) for a in actions) / len(actions)

    # ---- introspection -----------------------------------------------------

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "entries": len(self._counts),
                "outcome_vocab": len(self._outcomes),
                "total_updates": self._total_updates,
                "alpha": self.alpha,
                "max_entries": self.max_entries,
            }


# --------------------------------------------------------------------------
# Belief state -- compressed ecosystem summary
# --------------------------------------------------------------------------

# Bucket boundaries for the 10-ish dimensions of the belief token.  Each
# function maps a raw ecosystem metric onto a small finite label.  A full
# belief state is a deterministic join of these labels, so the state token
# lives in a space of  product(|buckets_i|)  possible states -- in practice
# <2000 states, keeping (s, a) count density useful.

def _bucket_tracked(n: int) -> str:
    if n <= 0: return "empty"
    if n < 8: return "few"
    if n < 64: return "some"
    if n < 512: return "many"
    return "flood"


def _bucket_frac(x: float) -> str:
    # x in [0, 1]
    if x <= 0.05: return "none"
    if x <= 0.25: return "low"
    if x <= 0.60: return "mid"
    if x <= 0.90: return "high"
    return "all"


def _bucket_count(n: int) -> str:
    if n <= 0: return "zero"
    if n < 3: return "one"
    if n < 10: return "few"
    if n < 50: return "many"
    return "storm"


@dataclass
class BeliefState:
    """
    Compressed belief token.  The 10 dimensions are chosen from TrustObserver
    + MemoryObserver shape (see ai-control/daemon/trust_observer.py
    get_anomaly_status + memory_observer.py get_stats).

    Joined token example:
      "tr:some|hc:mid|ca:zero|qr:none|fr:zero|os:zero|an:zero|ps:low|me:some|mo:zero"
    """

    # Trust-side (TrustObserver.get_anomaly_status())
    tracked_bucket: str = "empty"        # # subjects tracked
    healthy_frac: str = "none"           # healthy / total
    cancerous_count: str = "zero"        # #CANCEROUS immune
    quarantined_frac: str = "none"       # QUARANTINED / total
    frozen_count: str = "zero"           # #frozen subjects
    oscillating_count: str = "zero"      # #approaching-oscillation
    anomaly_severity: str = "zero"       # total_anomalies bucket
    critical_frac: str = "none"          # CRITICAL tier / total

    # Memory-side (MemoryObserver.get_stats())
    memory_tracked: str = "empty"        # # processes tracked
    memory_anomaly: str = "zero"         # #memory anomalies

    def token(self) -> str:
        """Deterministic short string.  Order is load-bearing."""
        return (
            f"tr:{self.tracked_bucket}"
            f"|hc:{self.healthy_frac}"
            f"|ca:{self.cancerous_count}"
            f"|qr:{self.quarantined_frac}"
            f"|fr:{self.frozen_count}"
            f"|os:{self.oscillating_count}"
            f"|an:{self.anomaly_severity}"
            f"|cr:{self.critical_frac}"
            f"|me:{self.memory_tracked}"
            f"|mo:{self.memory_anomaly}"
        )

    # ---- builders ----------------------------------------------------------

    @classmethod
    def from_observers(cls, trust_observer: Any = None,
                       memory_observer: Any = None) -> "BeliefState":
        """Snapshot current ecosystem state.  Missing observers => defaults."""
        b = cls()
        if trust_observer is not None:
            try:
                status = trust_observer.get_anomaly_status()
                total = max(1, int(status.get("total_tracked", 0)))
                b.tracked_bucket = _bucket_tracked(total)
                imm = status.get("immune_distribution", {})
                b.healthy_frac = _bucket_frac(imm.get("HEALTHY", 0) / total)
                b.cancerous_count = _bucket_count(imm.get("CANCEROUS", 0))
                b.quarantined_frac = _bucket_frac(imm.get("QUARANTINED", 0) / total)
                b.frozen_count = _bucket_count(status.get("frozen_count", 0))
                b.oscillating_count = _bucket_count(
                    len(status.get("oscillating_subjects", [])))
                b.anomaly_severity = _bucket_count(status.get("total_anomalies", 0))
                risk = status.get("risk_distribution", {})
                b.critical_frac = _bucket_frac(risk.get("CRITICAL", 0) / total)
            except Exception:
                logger.debug("BeliefState: trust_observer introspection failed",
                             exc_info=True)
        if memory_observer is not None:
            try:
                mstats = memory_observer.get_stats() or {}
                b.memory_tracked = _bucket_tracked(
                    int(mstats.get("processes_tracked", 0)))
                b.memory_anomaly = _bucket_count(
                    int(mstats.get("anomalies_total", 0)))
            except Exception:
                logger.debug("BeliefState: memory_observer introspection failed",
                             exc_info=True)
        return b


# --------------------------------------------------------------------------
# Active-inference agent
# --------------------------------------------------------------------------

# Per-action preference prior C(a) -- log-preference over *outcomes* an action
# is believed to cause.  Higher = more preferred = lower free energy.  These
# are design-time priors; they encode "the cortex wants a healthy ecosystem".
# Keys are outcome-belief-tokens partial-matched via `in` (substring), so we
# don't need every enumerated state.
PREFERENCE_PRIORS: tuple[tuple[str, float], ...] = (
    ("hc:all", +2.0),           # all subjects healthy = strong preference
    ("hc:high", +1.0),
    ("ca:zero", +1.5),          # no cancerous = preferred
    ("ca:storm", -2.0),
    ("cr:none", +1.0),
    ("cr:high", -1.5),
    ("cr:all", -2.0),
    ("fr:storm", -1.0),
    ("mo:storm", -1.0),
    ("an:storm", -1.5),
)


def _log_preference(outcome_token: str) -> float:
    """log C(o) -- design-time preference over ecosystem outcomes."""
    score = 0.0
    for frag, w in PREFERENCE_PRIORS:
        if frag in outcome_token:
            score += w
    return score


@dataclass
class ActionSelection:
    action: str
    expected_free_energy: float
    posterior: dict[str, float] = field(default_factory=dict)
    reason: str = ""


class ActiveInferenceAgent:
    """
    Closes the observer->cortex loop with a Friston-style FEP agent.

    Typical lifecycle (wired by agent 10 in api_server.lifespan):

        agent = ActiveInferenceAgent(event_bus, trust_observer=..., memory_observer=...)
        agent.start()                               # registers callbacks
        ...
        sel = agent.select_action()                 # periodic tick
        agent.stop()
    """

    def __init__(self,
                 event_bus: Any = None,
                 trust_observer: Any = None,
                 memory_observer: Any = None,
                 observer_handles: Optional[dict[str, Any]] = None,
                 action_candidates: Optional[Iterable[str]] = None,
                 bootstrap: int = BOOTSTRAP_OBSERVATIONS) -> None:
        # Support both explicit kwargs and a bundle dict (api_server pattern).
        if observer_handles:
            trust_observer = trust_observer or observer_handles.get("trust_observer")
            memory_observer = memory_observer or observer_handles.get("memory_observer")
            event_bus = event_bus or observer_handles.get("event_bus")

        self.event_bus = event_bus
        self.trust_observer = trust_observer
        self.memory_observer = memory_observer
        self.model = GenerativeModel()
        self.candidates: tuple[str, ...] = tuple(
            action_candidates or DEFAULT_ACTION_CANDIDATES)
        self.bootstrap = int(bootstrap)

        self._prev_state: Optional[str] = None
        self._last_action: str = "noop"
        self._last_selection: Optional[ActionSelection] = None
        self._n_observations: int = 0
        self._n_selections: int = 0
        self._started: bool = False
        self._event_log: deque = deque(maxlen=64)
        self._lock = threading.RLock()

    # ---- wiring ------------------------------------------------------------

    def start(self) -> None:
        """Register callbacks on observers.  Idempotent."""
        if self._started:
            return
        self._started = True
        if self.trust_observer is not None and hasattr(
                self.trust_observer, "add_event_callback"):
            try:
                self.trust_observer.add_event_callback(self.on_trust_event)
                logger.info("ActiveInferenceAgent: subscribed to trust_observer")
            except Exception:
                logger.warning("Cannot subscribe to trust_observer",
                               exc_info=True)
        # Seed prev_state from a snapshot so the first real event has a valid
        # (s, a, s') triple to update on.
        self._prev_state = BeliefState.from_observers(
            self.trust_observer, self.memory_observer).token()
        logger.info("ActiveInferenceAgent started (bootstrap=%d, |A|=%d)",
                    self.bootstrap, len(self.candidates))

    def stop(self) -> None:
        self._started = False
        logger.info(
            "ActiveInferenceAgent stopped (obs=%d, selections=%d, entries=%d)",
            self._n_observations, self._n_selections,
            self.model.stats()["entries"],
        )

    # ---- event intake ------------------------------------------------------

    def on_trust_event(self, evt: dict) -> None:
        """Callback for TrustObserver._emit_event dicts."""
        try:
            self._ingest_observation(evt)
        except Exception:
            logger.exception("on_trust_event failed")

    def on_event(self, evt: Any) -> None:
        """
        Generic cortex EventBus handler (accepts either a dict or an Event
        dataclass from event_bus.py).
        """
        try:
            if hasattr(evt, "type_name"):
                record = {
                    "type": evt.type_name(),
                    "subject_id": getattr(evt, "subject_id", 0),
                    "source": getattr(evt, "source_name", ""),
                }
            elif isinstance(evt, dict):
                record = evt
            else:
                return
            self._ingest_observation(record)
        except Exception:
            logger.exception("on_event failed")

    def _ingest_observation(self, evt: dict) -> None:
        with self._lock:
            self._n_observations += 1
            self._event_log.append((time.time(), evt.get("type", "?")))

            new_state = BeliefState.from_observers(
                self.trust_observer, self.memory_observer).token()

            prev = self._prev_state or new_state
            # Update only on actual state transitions; self-loops are fine
            # and informative (they tell the model the action had no effect).
            self.model.update(prev, self._last_action, new_state)
            self._prev_state = new_state

    # ---- action selection (expected free energy) ---------------------------

    def select_action(
        self,
        candidates: Optional[Iterable[str]] = None,
    ) -> ActionSelection:
        """
        Select argmin_a G(a) where

            G(a) = -<log C(o)>_q  +  KL[q(s') || prior(s')]
                 = accuracy_term  +  complexity_term

        Here  q(s'|s,a) = Dirichlet-smoothed count posterior,  C(o) is the
        design-time preference (PREFERENCE_PRIORS), and the prior used for
        the KL term is the uniform distribution over the current outcome
        vocabulary -- this is the standard implementation choice for a
        discrete FEP agent lacking an external prior signal.

        Bootstrap: during the first K observations, always return "noop".
        """
        with self._lock:
            cand = tuple(candidates or self.candidates)
            n_obs = self._n_observations

        if n_obs < self.bootstrap:
            sel = ActionSelection(
                action="noop",
                expected_free_energy=0.0,
                reason=f"bootstrap: seeding model, {n_obs}/{self.bootstrap} observations",
            )
            with self._lock:
                self._last_selection = sel
                self._n_selections += 1
            logger.debug("active_inference bootstrap %d/%d -> noop",
                         n_obs, self.bootstrap)
            return sel

        with self._lock:
            state = self._prev_state or BeliefState.from_observers(
                self.trust_observer, self.memory_observer).token()

        best: Optional[ActionSelection] = None
        for a in cand:
            dist = self.model.predict(state, a)
            if not dist:
                # No outcome vocab yet; treat as no-info, skip but keep noop.
                continue
            g = self._expected_free_energy(dist)
            if best is None or g < best.expected_free_energy:
                best = ActionSelection(
                    action=a,
                    expected_free_energy=g,
                    posterior=dist,
                    reason="argmin_G",
                )

        if best is None:
            best = ActionSelection(
                action="noop",
                expected_free_energy=0.0,
                reason="no outcome vocabulary yet",
            )

        with self._lock:
            self._last_action = best.action
            self._last_selection = best
            self._n_selections += 1

        # Publish back onto cortex event_bus if available -- decision_engine
        # can consume as an additional signal.
        self._publish_selection(best)
        return best

    @staticmethod
    def _expected_free_energy(dist: dict[str, float]) -> float:
        """
        G = -sum_o q(o) log C(o)   (accuracy / pragmatic value)
            + sum_o q(o) log q(o) / p(o)   (epistemic / complexity, KL vs uniform)

        Lower G is better.  A uniform prior p(o) drops to log(N) constant
        across actions, so the KL reduces to -H[q] + log(N); the relative
        ranking is unaffected by log(N) so we omit it.
        """
        if not dist:
            return 0.0
        acc = 0.0
        neg_ent = 0.0
        for o, p in dist.items():
            if p <= 0.0:
                continue
            acc -= p * _log_preference(o)   # pragmatic value
            neg_ent += p * math.log(p)       # -H[q]
        # G = pragmatic + complexity.  complexity without log(N) ~= -H[q].
        return acc + neg_ent

    # ---- publishing --------------------------------------------------------

    def _publish_selection(self, sel: ActionSelection) -> None:
        if self.event_bus is None:
            return
        # EventBus from cortex/event_bus.py has on_all / on / start / stop --
        # no direct publish method.  Most daemons use the bus as input-only.
        # If a `publish` method exists (custom extension) use it; otherwise
        # just log.
        publish = getattr(self.event_bus, "publish", None)
        if callable(publish):
            try:
                publish({
                    "type": "active_inference.decision",
                    "action": sel.action,
                    "expected_free_energy": sel.expected_free_energy,
                    "reason": sel.reason,
                    "timestamp": time.time(),
                })
            except Exception:
                logger.debug("event_bus publish failed", exc_info=True)

    # ---- metrics -----------------------------------------------------------

    def metrics(self) -> dict[str, Any]:
        """Expose at /metrics/active_inference."""
        with self._lock:
            sel = self._last_selection
            state = self._prev_state or ""
            return {
                "free_energy": (sel.expected_free_energy if sel else None),
                "selected_action": (sel.action if sel else None),
                "selection_reason": (sel.reason if sel else None),
                "model_entropy": self.model.state_entropy(state),
                "n_observations": self._n_observations,
                "n_selections": self._n_selections,
                "bootstrap_threshold": self.bootstrap,
                "bootstrap_complete": self._n_observations >= self.bootstrap,
                "current_state_token": state,
                "candidate_actions": list(self.candidates),
                "model": self.model.stats(),
                "recent_events": list(self._event_log)[-8:],
            }


# --------------------------------------------------------------------------
# Daemon wiring helper (called by agent 10 from api_server lifespan)
# --------------------------------------------------------------------------

# Module-level singleton so the /metrics endpoint can reach the live agent.
_active_agent: Optional[ActiveInferenceAgent] = None


def get_agent() -> Optional[ActiveInferenceAgent]:
    """Return the process-wide active-inference agent, if registered."""
    return _active_agent


def register_with_daemon(app: Any, observer_bundle: dict[str, Any]) -> ActiveInferenceAgent:
    """
    Wire the active-inference agent into the FastAPI app + observer bundle.

    Agent 10 calls this from ai-control/daemon/api_server.lifespan after the
    trust_observer and memory_observer are started.

    Parameters
    ----------
    app : FastAPI
        The daemon's FastAPI instance.  A GET /metrics/active_inference
        endpoint and a POST /cortex/active_inference/select endpoint are
        registered on it.
    observer_bundle : dict
        Must contain at least:
          - "trust_observer"  : TrustObserver | None
          - "memory_observer" : MemoryObserver | None
          - "event_bus"       : EventBus | None   (optional, for publish)

    Returns
    -------
    ActiveInferenceAgent
        The started agent.  Caller should hold onto it for .stop() in the
        lifespan shutdown half.
    """
    global _active_agent
    agent = ActiveInferenceAgent(
        event_bus=observer_bundle.get("event_bus"),
        trust_observer=observer_bundle.get("trust_observer"),
        memory_observer=observer_bundle.get("memory_observer"),
    )
    agent.start()
    _active_agent = agent

    # Endpoint registration is best-effort so unit tests that pass a stub
    # app (no .get decorator) don't explode.
    try:
        @app.get("/metrics/active_inference")
        async def _ai_metrics():   # type: ignore[unused-ignore]
            return agent.metrics()

        @app.post("/cortex/active_inference/select")
        async def _ai_select():    # type: ignore[unused-ignore]
            sel = agent.select_action()
            return {
                "action": sel.action,
                "expected_free_energy": sel.expected_free_energy,
                "reason": sel.reason,
                "posterior": sel.posterior,
            }
    except AttributeError:
        logger.debug("register_with_daemon: app is not a FastAPI instance; "
                     "skipping endpoint registration")

    logger.info("active_inference agent registered with daemon")
    return agent


__all__ = [
    "ActiveInferenceAgent",
    "ActionSelection",
    "BeliefState",
    "GenerativeModel",
    "DIRICHLET_ALPHA",
    "BOOTSTRAP_OBSERVATIONS",
    "DEFAULT_ACTION_CANDIDATES",
    "PREFERENCE_PRIORS",
    "register_with_daemon",
    "get_agent",
]
