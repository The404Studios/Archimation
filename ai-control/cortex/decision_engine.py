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

        self._load_default_policies()

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
        self.add_rule(PolicyRule(
            name="auto_restart_crashed",
            source_layer=3, event_type=EVT_SVC_CRASH,
            condition=lambda e: True,
            verdict=Verdict.ALLOW,
            reason="Service crashed -- auto-restart per policy",
            priority=30,
        ))

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

    def _finalize(self, result: EvalResult, start: float) -> None:
        """Record timing and verdict statistics."""
        elapsed = time.monotonic() - start
        self._eval_times.append(elapsed)

        self._verdict_counts[result.verdict.name] = (
            self._verdict_counts.get(result.verdict.name, 0) + 1
        )

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
