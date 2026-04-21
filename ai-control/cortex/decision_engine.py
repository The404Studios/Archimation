"""
Decision Engine -- evaluates events and produces decisions.

Three-tier evaluation (from spec Section 6.1 DECIDE):
1. Policy rules (instant): static allow/deny based on configuration
2. Heuristics (fast): behavioral patterns and thresholds
3. LLM reasoning (slow, optional): for ambiguous cases via local GGUF model
"""
import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Callable, Any, Deque
from enum import IntEnum

logger = logging.getLogger("cortex.decision")


# ---------------------------------------------------------------------------
# Module-level default-engine singleton (S76 Agent E wiring)
#
# The AI daemon's api_server.py lifespan tries to attach a Monte-Carlo
# confidence sampler by doing::
#
#     import decision_engine as _de_mod
#     eng = getattr(_de_mod, "_default_engine", None)
#     if eng is not None and hasattr(eng, "set_confidence_sampler"):
#         eng.set_confidence_sampler(cs)
#
# Prior to S76 the attribute did not exist, so the Monte-Carlo sampler
# auto-attachment silently fell through its try/except and never ran.
# Exposing ``_default_engine`` here (populated on first DecisionEngine
# instantiation) closes that wire without requiring the daemon to know
# the engine's construction path.
#
# Semantics: FIRST INSTANCE WINS. Subsequent DecisionEngine() calls do
# NOT overwrite the default, because the daemon may have already handed
# the sampler to the first instance. Callers that explicitly want a new
# default can use ``set_default_engine()`` below.
# ---------------------------------------------------------------------------
_default_engine: Optional["DecisionEngine"] = None


def get_default_engine() -> Optional["DecisionEngine"]:
    """Return the first DecisionEngine constructed in this process, or None.

    Safe to call before any DecisionEngine has been instantiated."""
    return _default_engine


def set_default_engine(engine: Optional["DecisionEngine"]) -> None:
    """Explicitly override the module-level default engine.

    Intended for tests + long-running daemons that want to rebind the
    singleton after a hot reload. Passing None clears the binding."""
    global _default_engine
    _default_engine = engine


def _is_old_hw() -> bool:
    """Tight heuristic: <=2 cores or <2GB RAM => scale buffers down."""
    try:
        cpus = os.cpu_count() or 1
    except Exception:
        cpus = 1
    mem_gb = 1.0
    try:
        mem_gb = (os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")) / (1024 ** 3)
    except (ValueError, OSError, AttributeError):
        pass
    return cpus <= 2 or mem_gb < 2.0


class Verdict(IntEnum):
    ALLOW = 0
    DENY = 1
    QUARANTINE = 2
    ESCALATE = 3    # Ask human
    MODIFY = 4      # Allow with modifications (e.g., reduced token budget)


@dataclass
class EvalResult:
    """Result of evaluating an event through the decision pipeline."""
    verdict: Verdict
    reason: str
    tier: str       # "policy", "heuristic", "llm", "default"
    confidence: float  # 0.0 - 1.0
    modifications: Optional[dict] = None  # For MODIFY verdict
    timestamp: float = field(default_factory=time.time)


# -- Event protocol (matches spec Section 7.1 header fields) --
#
# NOTE: This Event class shadows event_bus.Event.  DecisionEngine.evaluate()
# accepts any object with source_layer, event_type, and pid attributes (duck
# typing), so callers may pass either this Event or event_bus.Event directly.

@dataclass
class Event:
    """
    Minimal event representation matching the spec event bus protocol.

    source_layer: 0=kernel, 1=broker, 2=pe_runtime, 3=scm, 4=cortex
    event_type:   per-source enum value
    pid:          source process ID
    subject_id:   trust subject
    payload:      event-specific data dict

    This class duplicates some fields from event_bus.Event for standalone use
    within the decision engine.  DecisionEngine.evaluate() uses duck typing and
    accepts any object with the required attributes.
    """
    source_layer: int
    event_type: int
    pid: int = 0
    tid: int = 0
    subject_id: int = 0
    timestamp_ns: int = 0
    sequence: int = 0
    flags: int = 0
    payload: dict = field(default_factory=dict)


# -- Event type constants (per-source enums) --

# Layer 0 (kernel / trust.ko)
EVT_SCORE_CHANGE = 0x01
EVT_TOKEN_STARVE = 0x02
EVT_IMMUNE_ALERT = 0x03
EVT_QUARANTINE = 0x04
EVT_APOPTOSIS = 0x05

# Layer 2 (PE runtime)
EVT_PE_LOAD = 0x01
EVT_PE_DLL_LOAD = 0x02
EVT_PE_UNIMPL_API = 0x03
EVT_PE_EXCEPTION = 0x04
EVT_PE_EXIT = 0x05
EVT_PE_TRUST_DENY = 0x06

# Layer 3 (SCM / services) -- must match event_bus.SvcEventType
EVT_SVC_INSTALL = 0x01
EVT_SVC_START = 0x02
EVT_SVC_STOP = 0x03
EVT_SVC_CRASH = 0x04
EVT_SVC_RESTART = 0x05
EVT_SVC_DEPENDENCY_FAIL = 0x06

# Layer 2 (PE runtime -- memory subsystem, must match event_bus.PeEventType)
EVT_MEMORY_MAP = 0x10
EVT_MEMORY_UNMAP = 0x11
EVT_MEMORY_PROTECT = 0x12
EVT_MEMORY_PATTERN = 0x13
EVT_MEMORY_ANOMALY = 0x14
EVT_STUB_CALLED = 0x15

# Layer 4 (cortex self-events)
EVT_CORTEX_DECISION = 0x01
EVT_CORTEX_ESCALATION = 0x02


# -- Policy Rules --

@dataclass
class PolicyRule:
    """A static policy rule evaluated against incoming events."""
    name: str
    source_layer: int
    event_type: int
    condition: Callable[[Event], bool]
    verdict: Verdict
    reason: str
    priority: int = 0  # Higher = checked first


class DecisionEngine:
    """
    Three-tier decision engine: policy rules -> heuristics -> LLM.

    The engine evaluates events top-to-bottom through the tiers. The first
    tier that produces a result wins. If nothing matches, a low-confidence
    ALLOW is returned (default-open with logging).
    """

    def __init__(self) -> None:
        self._policy_rules: List[PolicyRule] = []
        # Secondary index: (source_layer, event_type) -> list of rules.
        # Rebuilt on add/remove; eliminates linear scan of ALL rules per event.
        self._rule_index: Dict[tuple, List[PolicyRule]] = {}
        self._heuristic_state: Dict[str, Any] = {}
        self._llm: Any = None  # Optional llama-cpp-python backend
        self._eval_count: int = 0
        # HW-tier aware buffer sizes.  Old hardware gets a smaller timing
        # window (less memory) and a tighter state hard cap so a pathological
        # event storm cannot chew through RAM on a 1-core 1GB box.
        old_hw = _is_old_hw()
        self._eval_times: Deque[float] = deque(maxlen=250 if old_hw else 1000)
        self._state_hard_cap: int = 2000 if old_hw else 10000
        self._state_trim_to: int = 1000 if old_hw else 5000
        self._verdict_counts: Dict[str, int] = {v.name: 0 for v in Verdict}
        # Cached p99 (recomputed only every N evaluations) to avoid sorting
        # the full timing deque on every /status API call.
        self._stats_cache: Optional[dict] = None
        self._stats_cache_eval_count: int = -1
        # Last verdict emitted, used to feed the bigram DecisionMarkovModel.
        # None until the first decision is finalized.
        self._last_verdict_name: Optional[str] = None

        # S75 Agent C: optional Monte-Carlo confidence sampler. When set,
        # EvalResult.confidence is re-drawn from a beta posterior on
        # _finalize (surgical stochasticity injection). When left as None,
        # confidence is the original deterministic value from the tier
        # (ALL existing behaviour unchanged).
        #
        # Wire contract (from set_confidence_sampler below):
        #   sampler.deterministic_mean == True  -> behaviour identical to
        #     the pre-S75 deterministic path (posterior mean ~= base conf).
        #   sampler.deterministic_mean == False -> confidence becomes a
        #     beta-distributed random variable with E[x] ~= base conf.
        self._confidence_sampler: Any = None

        self._load_default_policies()

        # S76 Agent E: register as the module-level default engine on
        # first instantiation so api_server.py can discover + attach the
        # Monte-Carlo confidence sampler without shared wiring. First
        # instance wins; subsequent constructions do NOT rebind (the
        # daemon may have already handed the sampler to the first one).
        global _default_engine
        if _default_engine is None:
            _default_engine = self

    # -- Policy management --

    def _load_default_policies(self) -> None:
        """Built-in policy rules matching spec Section 6.1 examples."""

        # Trust / kernel policies
        self.add_rule(PolicyRule(
            name="auto_quarantine_cancerous",
            source_layer=0, event_type=EVT_IMMUNE_ALERT,
            condition=lambda e: True,  # Always quarantine on immune alert
            verdict=Verdict.QUARANTINE,
            reason="Immune system flagged process as cancerous",
            priority=100,
        ))

        self.add_rule(PolicyRule(
            name="escalate_token_starve",
            source_layer=0, event_type=EVT_TOKEN_STARVE,
            condition=lambda e: True,
            verdict=Verdict.ESCALATE,
            reason="Process exhausted trust tokens -- requires human review",
            priority=50,
        ))

        self.add_rule(PolicyRule(
            name="deny_apoptotic_load",
            source_layer=2, event_type=EVT_PE_LOAD,
            condition=lambda e: e.payload.get("apoptotic", False),
            verdict=Verdict.DENY,
            reason="PE load denied: subject is in apoptotic state",
            priority=90,
        ))

        # Service policies
        #
        # NOTE: We deliberately do NOT install an always-true
        # "auto_restart_crashed" tier-1 ALLOW rule here.  The previous
        # version of this file did, and because tier-1 policy wins over
        # tier-2 heuristics the crash-loop detection heuristic in
        # _eval_heuristics() (5+ crashes in 60s -> DENY) was DEAD CODE --
        # the policy rule matched first and short-circuited the pipeline
        # on every crash, so restart-storms were never caught.
        # Leaving no rule means:
        #   * normal crash  -> heuristic returns None -> default-ALLOW
        #                      (handler runs normal autonomy flow -> restart)
        #   * crash loop    -> heuristic DENY -> handler skips restart
        # which is the intended three-tier behavior.

        self.add_rule(PolicyRule(
            name="escalate_dependency_failure",
            source_layer=3, event_type=EVT_SVC_DEPENDENCY_FAIL,
            condition=lambda e: True,
            verdict=Verdict.ESCALATE,
            reason="Service dependency failed -- human intervention may be needed",
            priority=40,
        ))

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a policy rule. Rules are kept sorted by descending priority."""
        self._policy_rules.append(rule)
        self._policy_rules.sort(key=lambda r: -r.priority)
        self._rebuild_rule_index()

    def remove_rule(self, name: str) -> bool:
        """Remove a policy rule by name. Returns True if found."""
        before = len(self._policy_rules)
        self._policy_rules = [r for r in self._policy_rules if r.name != name]
        if len(self._policy_rules) < before:
            self._rebuild_rule_index()
            return True
        return False

    def _rebuild_rule_index(self) -> None:
        """Rebuild the (layer, type) -> rules index from _policy_rules.
        Preserves priority order (policy_rules is already sorted)."""
        idx: Dict[tuple, List[PolicyRule]] = {}
        for rule in self._policy_rules:
            key = (rule.source_layer, rule.event_type)
            idx.setdefault(key, []).append(rule)
        self._rule_index = idx

    # -- Main evaluation pipeline --

    def evaluate(self, event: Event) -> EvalResult:
        """
        Evaluate an event through the three-tier pipeline.

        Accepts any object with source_layer, event_type, and pid attributes
        (duck typing).  Both decision_engine.Event and event_bus.Event work.

        Returns the first result found, or a low-confidence default ALLOW.
        """
        self._eval_count += 1
        start = time.monotonic()

        # Tier 1: Policy rules (instant)
        result = self._eval_policy(event)
        if result is not None:
            self._finalize(result, start)
            return result

        # Tier 2: Heuristics (fast)
        result = self._eval_heuristics(event)
        if result is not None:
            self._finalize(result, start)
            return result

        # Tier 3: LLM (slow, optional)
        if self._llm is not None:
            result = self._eval_llm(event)
            if result is not None:
                self._finalize(result, start)
                return result

        # Default: allow with low confidence
        result = EvalResult(
            verdict=Verdict.ALLOW,
            reason="No matching policy or heuristic -- default allow",
            tier="default",
            confidence=0.3,
        )
        self._finalize(result, start)
        return result

    def set_confidence_sampler(self, sampler: Any) -> None:
        """Attach a ConfidenceSampler (S75 Agent C, roadmap §1.2.4).

        When attached, EvalResult.confidence is re-drawn on _finalize from
        a beta posterior centred on the tier's original confidence. Pass
        a ConfidenceSampler constructed with ``deterministic_mean=True``
        to preserve pre-S75 behaviour (posterior mean) while keeping the
        wiring validated end-to-end. Pass ``None`` to detach.

        This is additive, opt-in wiring: default engine construction does
        not invoke the sampler so existing tests and callers are
        unchanged.
        """
        self._confidence_sampler = sampler

    def _finalize(self, result: EvalResult, start: float) -> None:
        """Record timing and verdict statistics.

        Also feeds the process-wide ``DecisionMarkovModel`` singleton so
        the /cortex/markov/decisions endpoint sees real bigram data. Wrap
        in try/except so a singleton failure never poisons decision flow.
        """
        elapsed = time.monotonic() - start
        self._eval_times.append(elapsed)

        # S75 Agent C: optional Monte-Carlo confidence calibration. When a
        # sampler is attached, redraw the confidence from a beta posterior
        # centred on the tier's original deterministic confidence; when
        # the sampler is in ``deterministic_mean`` mode the returned
        # value is the posterior mean, so behaviour is numerically
        # indistinguishable from the pre-S75 path.  Guarded by try/except
        # so a sampler malfunction cannot poison decision flow.
        sampler = self._confidence_sampler
        if sampler is not None:
            try:
                base = float(max(0.0, min(1.0, result.confidence)))
                new_conf = float(sampler.calibrated(base))
                if 0.0 <= new_conf <= 1.0:
                    result.confidence = new_conf
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("ConfidenceSampler failed: %s", exc)

        verdict_name = result.verdict.name
        self._verdict_counts[verdict_name] = (
            self._verdict_counts.get(verdict_name, 0) + 1
        )

        # Feed the decision-bigram chain. Always pass through
        # observe_decision() so the model's internal stream stays
        # consistent (single source of truth for the (prev, next) pair).
        try:
            get_default_model().observe_decision(verdict_name)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("DecisionMarkovModel observe failed: %s", exc)
        self._last_verdict_name = verdict_name

    # -- Tier 1: Policy rules --

    def _eval_policy(self, event: Event) -> Optional[EvalResult]:
        """Check static policy rules in priority order.

        Uses the (source_layer, event_type) index for O(matching-rules) lookup
        instead of scanning all rules.  Order within the bucket preserves the
        original priority-descending sort.
        """
        rules = self._rule_index.get((event.source_layer, event.event_type))
        if not rules:
            return None
        for rule in rules:
            try:
                if rule.condition(event):
                    logger.debug(
                        "Policy rule '%s' matched event (layer=%d, type=0x%02x)",
                        rule.name, event.source_layer, event.event_type,
                    )
                    return EvalResult(
                        verdict=rule.verdict,
                        reason=rule.reason,
                        tier="policy",
                        confidence=1.0,
                    )
            except Exception as exc:
                logger.error(
                    "Policy rule '%s' raised exception: %s", rule.name, exc,
                )
        return None

    # -- Tier 2: Heuristics --

    def _sliding_window_add(
        self, key: str, now: float, window_s: float, max_entries: int = 4096,
    ) -> int:
        """Append `now` to a sliding time window and return its length.

        Uses a deque per key for O(1) append + popleft; the previous
        implementation rebuilt the list via list-comprehension on every
        event, which was O(N) *per event* on hot PIDs.  The deque-based
        approach is amortized O(1) per event, a 10-100x win under heavy
        event rates.

        `max_entries` caps deque size so a pathological sender cannot grow
        the window past its natural ceiling (redundant with the window
        expiry, but defends against clock skew / time jumps).
        """
        history = self._heuristic_state.get(key)
        if history is None:
            history = deque(maxlen=max_entries)
            self._heuristic_state[key] = history
        # Expire old entries from the left of the window -- O(1) per pop.
        cutoff = now - window_s
        while history and history[0] < cutoff:
            history.popleft()
        history.append(now)
        return len(history)

    def _eval_heuristics(self, event: Event) -> Optional[EvalResult]:
        """Behavioral pattern detection."""

        # Heuristic: rapid PE spawning (fork bomb detection)
        # Spec: "Process spawning >20 children in 5s = suspicious"
        if event.source_layer == 2 and event.event_type == EVT_PE_LOAD:
            now = time.monotonic()
            n = self._sliding_window_add(f"spawn_rate_{event.pid}", now, 5.0)
            if n > 20:
                logger.warning(
                    "Fork bomb heuristic: pid %d spawned %d PE loads in 5s",
                    event.pid, n,
                )
                return EvalResult(
                    verdict=Verdict.QUARANTINE,
                    reason=f"Rapid PE spawning: {n} loads in 5s (fork bomb?)",
                    tier="heuristic",
                    confidence=0.85,
                )

        # Heuristic: repeated trust denials (privilege escalation probing)
        if event.source_layer == 2 and event.event_type == EVT_PE_TRUST_DENY:
            now = time.monotonic()
            n = self._sliding_window_add(f"deny_rate_{event.pid}", now, 10.0)
            if n > 50:
                logger.warning(
                    "Privilege probe heuristic: pid %d got %d trust denials in 10s",
                    event.pid, n,
                )
                return EvalResult(
                    verdict=Verdict.QUARANTINE,
                    reason=f"Excessive trust denials: {n} in 10s "
                           f"(privilege escalation attempt?)",
                    tier="heuristic",
                    confidence=0.75,
                )

        # Heuristic: service crash loop
        if event.source_layer == 3 and event.event_type == EVT_SVC_CRASH:
            # payload may arrive as raw bytes if no struct parser is registered
            # for the SCM event type -- guard the .get() call defensively.
            payload = getattr(event, "payload", None)
            if isinstance(payload, dict):
                svc_name = payload.get("service_name", str(event.pid))
            else:
                svc_name = str(event.pid)
            now = time.monotonic()
            n = self._sliding_window_add(f"crash_rate_{svc_name}", now, 60.0)
            if n > 5:
                logger.warning(
                    "Crash loop heuristic: service '%s' crashed %d times in 60s",
                    svc_name, n,
                )
                return EvalResult(
                    verdict=Verdict.DENY,
                    reason=f"Service crash loop: {n} crashes in 60s "
                           f"-- stopping restarts",
                    tier="heuristic",
                    confidence=0.9,
                )

        # Heuristic: PE exception storm
        if event.source_layer == 2 and event.event_type == EVT_PE_EXCEPTION:
            now = time.monotonic()
            n = self._sliding_window_add(f"exception_rate_{event.pid}", now, 10.0)
            if n > 100:
                return EvalResult(
                    verdict=Verdict.QUARANTINE,
                    reason=f"Exception storm: {n} exceptions in 10s "
                           f"-- process unstable",
                    tier="heuristic",
                    confidence=0.8,
                )

        # Heuristic: executable heap (possible shellcode injection)
        if event.source_layer == 2 and event.event_type == EVT_MEMORY_PROTECT:
            payload = getattr(event, "payload", None)
            if isinstance(payload, dict) and payload.get("new_prot") == "rwx":
                region_tag = payload.get("tag", "")
                if region_tag in ("heap", "unknown"):
                    now = time.monotonic()
                    n = self._sliding_window_add(
                        f"rwx_heap_{event.pid}", now, 10.0,
                    )
                    if n > 5:
                        return EvalResult(
                            verdict=Verdict.QUARANTINE,
                            reason="Excessive RWX heap allocations "
                                   "-- possible shellcode injection",
                            tier="heuristic",
                            confidence=0.9,
                        )

        # Heuristic: IAT modification detection
        if event.source_layer == 2 and event.event_type == EVT_MEMORY_PROTECT:
            payload = getattr(event, "payload", None)
            if isinstance(payload, dict) and payload.get("tag") == "iat":
                if "w" in payload.get("new_prot", ""):
                    return EvalResult(
                        verdict=Verdict.ESCALATE,
                        reason=f"IAT section made writable -- possible import "
                               f"hooking (PID {event.pid})",
                        tier="heuristic",
                        confidence=0.8,
                    )

        # Heuristic: stub call frequency -- detect programs that are mostly broken
        if event.source_layer == 2 and event.event_type == EVT_STUB_CALLED:
            now = time.monotonic()
            n = self._sliding_window_add(f"stub_freq_{event.pid}", now, 5.0)
            if n > 100:
                return EvalResult(
                    verdict=Verdict.ESCALATE,
                    reason=f"Process {event.pid} hitting >100 stubs/5s "
                           f"-- likely non-functional",
                    tier="heuristic",
                    confidence=0.6,
                )

        # Heuristic: DLL injection -- unknown executable region mapped not from a
        # known .so or PE DLL path.  Legitimate memory maps originate from the
        # loader itself (tag="loader" or source_path ending in .so/.dll).
        if event.source_layer == 2 and event.event_type == EVT_MEMORY_MAP:
            payload = getattr(event, "payload", None)
            if isinstance(payload, dict):
                prot = payload.get("prot_flags", 0)
                source = payload.get("source_path", "")
                tag = payload.get("tag", "")
                # Check if the region is executable (PROT_EXEC = 0x4)
                is_exec = bool(prot & 0x4)
                # Known legitimate sources end in .so, .dll, or come from
                # the loader (tag starts with "loader" or "pe_map")
                known_source = (
                    source.endswith(".so")
                    or source.endswith(".dll")
                    or source.endswith(".exe")
                    or tag.startswith("loader")
                    or tag.startswith("pe_map")
                    or tag == "stack"
                    or tag == "heap"
                    or tag == "tls"
                )
                if is_exec and not known_source and source:
                    logger.warning(
                        "DLL injection heuristic: PID %d mapped executable "
                        "region from unknown source '%s' (tag=%s)",
                        event.pid, source, tag,
                    )
                    return EvalResult(
                        verdict=Verdict.ESCALATE,
                        reason=f"Possible DLL injection: executable region "
                               f"mapped from unknown source '{source}' "
                               f"(PID {event.pid})",
                        tier="heuristic",
                        confidence=0.7,
                    )

        # Prune stale heuristic state entries periodically.  Skip the walk
        # entirely when the state dict is small -- no risk of unbounded growth
        # and nothing to reclaim.
        if self._eval_count % 100 == 0 and len(self._heuristic_state) > 128:
            self._prune_heuristic_state()

        return None

    def _prune_heuristic_state(self) -> None:
        """Remove heuristic state entries with no recent activity (idle > 30s).

        Also enforces a hard cap to prevent unbounded growth from many
        short-lived PIDs generating unique heuristic keys.  On old HW the
        cap is tighter to keep memory footprint small.

        Accepts both list and deque values (legacy pickled state might
        still be list-based; live state is deque-based).
        """
        now = time.monotonic()
        stale_keys = []
        for key, history in self._heuristic_state.items():
            # `history` is either a list or deque of floats.  Both support
            # len(), indexing via history[-1], and truthiness.
            if history:
                try:
                    last = history[-1]
                except (IndexError, TypeError):
                    stale_keys.append(key)
                    continue
                if now - last > 30.0:
                    stale_keys.append(key)
            else:
                stale_keys.append(key)
        for key in stale_keys:
            del self._heuristic_state[key]

        # Hard cap: if still too many keys, evict oldest.  Cap is soft-tied
        # to HW tier via an override attribute so tests/constrained hosts
        # can tune it without editing the class.
        hard_cap = getattr(self, "_state_hard_cap", 10000)
        trim_to = getattr(self, "_state_trim_to", 5000)
        if len(self._heuristic_state) > hard_cap:
            entries = []
            for key, history in self._heuristic_state.items():
                try:
                    last = history[-1] if history else 0
                except (IndexError, TypeError):
                    last = 0
                entries.append((key, last))
            entries.sort(key=lambda x: x[1])
            to_remove = len(self._heuristic_state) - trim_to
            for key, _ in entries[:to_remove]:
                del self._heuristic_state[key]

    # -- Tier 3: LLM reasoning --

    def _eval_llm(self, event: Event) -> Optional[EvalResult]:
        """
        LLM reasoning for ambiguous cases. Optional.

        Uses local GGUF model via llama-cpp-python when available.
        Only invoked when policy and heuristics are both insufficient.
        """
        # TODO: integrate with llama-cpp-python when model available.
        # The prompt should describe the event context and ask for a
        # verdict (allow/deny/quarantine/escalate) with reasoning.
        return None

    def set_llm_backend(self, llm: Any) -> None:
        """Attach an LLM backend for tier-3 reasoning."""
        self._llm = llm
        logger.info("LLM backend attached to decision engine")

    # -- Bulk evaluation --

    def evaluate_batch(self, events: List[Event]) -> List[EvalResult]:
        """Evaluate a batch of events. Returns results in same order."""
        return [self.evaluate(e) for e in events]

    # -- Statistics --

    @property
    def stats(self) -> dict:
        """Engine performance and evaluation statistics.

        The avg/p99 timing calculation is O(N log N) over the 1000-entry
        deque (full sort).  Cache the result for ~100 evaluations so the
        /status API endpoint doesn't pay that cost on every poll.
        """
        if (
            self._stats_cache is not None
            and self._eval_count - self._stats_cache_eval_count < 100
        ):
            # Refresh only the live counters; timing stats remain cached.
            cached = dict(self._stats_cache)
            cached["evaluations"] = self._eval_count
            cached["heuristic_state_keys"] = len(self._heuristic_state)
            cached["verdict_counts"] = dict(self._verdict_counts)
            return cached

        avg_time = (
            sum(self._eval_times) / len(self._eval_times)
            if self._eval_times else 0.0
        )
        p99_time = (
            sorted(self._eval_times)[int(len(self._eval_times) * 0.99)]
            if len(self._eval_times) >= 100 else avg_time
        )
        result = {
            "evaluations": self._eval_count,
            "policy_rules": len(self._policy_rules),
            "avg_eval_time_ms": round(avg_time * 1000, 3),
            "p99_eval_time_ms": round(p99_time * 1000, 3),
            "heuristic_state_keys": len(self._heuristic_state),
            "verdict_counts": dict(self._verdict_counts),
            "llm_available": self._llm is not None,
        }
        self._stats_cache = result
        self._stats_cache_eval_count = self._eval_count
        return result

    @property
    def rules(self) -> List[dict]:
        """List all policy rules for inspection."""
        return [
            {
                "name": r.name,
                "source_layer": r.source_layer,
                "event_type": r.event_type,
                "verdict": r.verdict.name,
                "reason": r.reason,
                "priority": r.priority,
            }
            for r in self._policy_rules
        ]


# ---------------------------------------------------------------------------
# DecisionMarkovModel -- bigram Markov chain over decision verdicts.
#
# Session 68 (Agent F): operationalizes the "Decisions" row of the eight-chain
# table in docs/markov-chains.md. States are the existing `Verdict` enum
# names (ALLOW / DENY / QUARANTINE / ESCALATE / MODIFY) -- we do NOT invent
# new verdict tokens; the model only accepts strings that round-trip through
# the enum.
#
# Design constraints:
#   * Bounded memory: collections.deque(maxlen=1024) for the full observation
#     stream; transition count matrix is O(|Verdict|^2) = 25 entries max.
#   * Thread-safe: one Lock protecting every mutation and every derived-read
#     that walks the counts dict.
#   * Duck-typed API for cortex/api.py::_markov_decision_snapshot:
#       state_count / transition_count / last_action / last_timestamp /
#       observations / top_transitions(k) / snapshot() / next_decision_distribution()
#   * Test-compat API (tests/integration/test_markov_chains.py:293):
#       observe_decision(action) -- single-arg append-to-stream variant that
#         derives the (prev, next) transition from the previous observation.
#       predict_next(after_action, k) -- returns a sorted list of
#         (action, prob) tuples; empty list for unknown origin.
#
# Hook: DecisionEngine._finalize() now calls into the module-level singleton
# via get_default_model().observe(prev_verdict_name, result.verdict.name) so
# that the live decision stream populates the chain without callers needing
# to know it exists. The wiring is isolated to one line and tolerant of
# singleton-init failure (wrapped in try/except at call site).
# ---------------------------------------------------------------------------


class DecisionMarkovModel:
    """Bigram Markov chain over decision verdicts (stateful stream observer).

    States are the names of the ``Verdict`` enum; any other state label is
    accepted but recorded literally (for forward-compat if the enum grows).
    The model counts (prev, next) transitions rather than raw emissions so
    that predict_next() can answer "given I just saw X, what's most likely
    to come next?" -- which is the question both the test suite and the
    /cortex/markov/decisions endpoint want answered.

    Memory is bounded in two ways:
      * ``_observations`` is a bounded deque (maxlen=1024) of the full
        observation stream, so memory is O(1024) regardless of uptime.
      * ``_transitions`` is dense-keyed by (prev, next) string tuples.
        With |Verdict|=5 and the small set of externally-injected labels
        we'll ever see, the dict has at most a few dozen entries.

    Thread-safety: a single ``threading.Lock`` guards every mutation and
    every derived-read that walks the internal dicts. Readers of simple
    attributes (``state_count``, ``observations``) do not take the lock;
    they rely on the GIL for atomic int/len reads.
    """

    __slots__ = (
        "_lock", "_transitions", "_state_counts", "_stream",
        "_last_action", "_last_timestamp", "_total_observations",
    )

    # Canonical state set. We expose Verdict names rather than ints so the
    # snapshot JSON is self-describing.
    STATES: List[str] = [v.name for v in Verdict]

    # Max length of the observation stream (the prompt calls for 1024).
    _MAX_OBSERVATIONS: int = 1024

    def __init__(self) -> None:
        import threading as _threading
        self._lock = _threading.Lock()
        # (prev_state, next_state) -> count
        self._transitions: Dict[tuple, int] = {}
        # per-state visit counts (counts BOTH prev and next endpoints)
        self._state_counts: Dict[str, int] = {}
        # bounded stream of raw actions for observe_decision() chaining
        self._stream: Deque[str] = deque(maxlen=self._MAX_OBSERVATIONS)
        self._last_action: Optional[str] = None
        self._last_timestamp: Optional[float] = None
        self._total_observations: int = 0

    # --- Observation API (two variants: pair + single) ---------------------

    def observe(self, prev_decision: str, next_decision: str) -> None:
        """Increment the (prev -> next) transition count.

        Either argument may be any hashable string; we do not reject
        unknown state names (forward-compat), but known names are matched
        against ``Verdict`` for the state-count tally.
        """
        if not isinstance(prev_decision, str) or not isinstance(next_decision, str):
            return
        with self._lock:
            key = (prev_decision, next_decision)
            self._transitions[key] = self._transitions.get(key, 0) + 1
            self._state_counts[prev_decision] = self._state_counts.get(prev_decision, 0) + 1
            self._state_counts[next_decision] = self._state_counts.get(next_decision, 0) + 1
            self._last_action = next_decision
            self._last_timestamp = time.time()
            self._total_observations += 1

    def observe_decision(self, action: str) -> None:
        """Append ``action`` to the stream; derive (prev, action) if stream non-empty.

        This matches the test-suite contract -- feeding a sequence of raw
        actions produces the bigram chain implicitly. First call is a
        no-op for transitions (no predecessor) but still records the state
        for state_counts tracking.
        """
        if not isinstance(action, str):
            return
        prev: Optional[str]
        with self._lock:
            prev = self._stream[-1] if self._stream else None
            self._stream.append(action)
        if prev is None:
            # First observation: just record the state visit.
            with self._lock:
                self._state_counts[action] = self._state_counts.get(action, 0) + 1
                self._last_action = action
                self._last_timestamp = time.time()
                self._total_observations += 1
            return
        self.observe(prev, action)

    # --- Read-only derived quantities --------------------------------------

    def next_decision_distribution(self, current: str) -> Dict[str, float]:
        """Normalized P(next | current) over observed transitions out of ``current``.

        Returns an empty dict if ``current`` has never been observed as a
        predecessor. Probabilities sum to 1.0 modulo float error when the
        dict is non-empty.
        """
        with self._lock:
            out_counts: Dict[str, int] = {}
            for (prev, nxt), c in self._transitions.items():
                if prev == current and c > 0:
                    out_counts[nxt] = out_counts.get(nxt, 0) + c
        total = sum(out_counts.values())
        if total == 0:
            return {}
        return {k: v / total for k, v in out_counts.items()}

    def predict_next(self, after_action: str, k: int = 3) -> List[tuple]:
        """Top-k (next_state, probability) tuples sorted by descending probability.

        Empty list for unknown origin (matches the defensive contract in
        test_decision_markov_observation_records).
        """
        dist = self.next_decision_distribution(after_action)
        if not dist:
            return []
        ranked = sorted(dist.items(), key=lambda kv: kv[1], reverse=True)
        return ranked[: max(1, int(k))]

    def top_transitions(self, k: int = 10) -> List[dict]:
        """Top-k highest-count (prev -> next) transitions, for telemetry.

        Returns a list of dicts shaped for JSON so the /cortex/markov/decisions
        endpoint can emit them directly.
        """
        with self._lock:
            items = sorted(
                self._transitions.items(),
                key=lambda kv: kv[1],
                reverse=True,
            )[: max(1, int(k))]
        return [
            {"from": prev, "to": nxt, "count": c}
            for (prev, nxt), c in items
        ]

    def snapshot(self) -> dict:
        """JSON-safe telemetry snapshot.

        Keys documented for /cortex/markov/decisions callers:
          * states:              full Verdict name list (stable enumeration)
          * state_counts:        state -> visit count
          * transitions:         "prev->next" -> count
          * top_transitions:     top-10 list of {from, to, count}
          * total_observations:  integer, monotonically increasing
        """
        with self._lock:
            transitions_str = {
                f"{prev}->{nxt}": c
                for (prev, nxt), c in self._transitions.items()
            }
            state_counts = dict(self._state_counts)
            total = self._total_observations
            last_action = self._last_action
            last_ts = self._last_timestamp
        return {
            "states": list(self.STATES),
            "state_counts": state_counts,
            "transitions": transitions_str,
            "top_transitions": self.top_transitions(k=10),
            "total_observations": total,
            "last_action": last_action,
            "last_timestamp": last_ts,
        }

    # --- Duck-typed attributes for cortex/api.py snapshot ------------------

    @property
    def state_count(self) -> int:
        """Number of distinct states observed (INCLUDING non-Verdict strings)."""
        return len(self._state_counts)

    @property
    def transition_count(self) -> int:
        """Number of distinct (prev, next) transitions observed."""
        return len(self._transitions)

    @property
    def last_action(self) -> Optional[str]:
        return self._last_action

    @property
    def last_timestamp(self) -> Optional[float]:
        return self._last_timestamp

    @property
    def observations(self) -> int:
        """Total number of observe()/observe_decision() calls that recorded state."""
        return self._total_observations

    def reset(self) -> None:
        """Drop all observations. Test-only; safe in production."""
        with self._lock:
            self._transitions.clear()
            self._state_counts.clear()
            self._stream.clear()
            self._last_action = None
            self._last_timestamp = None
            self._total_observations = 0


# Module-level lazy singleton -- mirrors markov_nlp.get_default_model() pattern.
_default_decision_model: Optional[DecisionMarkovModel] = None
_default_decision_lock = None  # lazily created to avoid import-time threading cost


def get_default_model() -> DecisionMarkovModel:
    """Return the process-wide DecisionMarkovModel singleton (lazy-init).

    The same pattern markov_nlp / behavioral_markov / trust_markov use. The
    singleton can be reset via reset_default_model() for deterministic tests.
    """
    global _default_decision_model, _default_decision_lock
    if _default_decision_model is not None:
        return _default_decision_model
    if _default_decision_lock is None:
        import threading as _threading
        _default_decision_lock = _threading.Lock()
    with _default_decision_lock:
        if _default_decision_model is None:
            _default_decision_model = DecisionMarkovModel()
    return _default_decision_model


def reset_default_model() -> None:
    """Drop the process-wide singleton (test helper)."""
    global _default_decision_model
    _default_decision_model = None
