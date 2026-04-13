"""
Autonomy Controller -- governs how much independent action the cortex can take.

The cortex's autonomy is itself governed by the Root of Authority trust system.
Higher trust score = more autonomous. Mistakes reduce autonomy.
"""
import logging
import time
from enum import IntEnum
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("cortex.autonomy")


class AutonomyLevel(IntEnum):
    OBSERVE = 0      # Log only
    ADVISE = 1       # Suggest, human approves
    ACT_REPORT = 2   # Act, then notify human
    AUTONOMOUS = 3   # Full control, log only
    # Level 4 (SOVEREIGN) removed -- no code path should allow self-modification
    # of trust parameters without human confirmation.


# Hard ceiling: no domain may EVER exceed this level autonomously.
# AUTONOMOUS (3) is the maximum; SOVEREIGN was removed as a safety measure.
MAX_AUTONOMY_LEVEL = AutonomyLevel.AUTONOMOUS


class Domain:
    """Autonomy domain constants."""
    PROCESS = "process_management"
    NETWORK = "network_access"
    TRUST = "trust_modification"
    HARDWARE = "hardware_control"
    PE_EXECUTION = "pe_execution"
    SERVICE = "service_management"
    SECURITY = "security_response"
    SYSTEM_CONFIG = "system_configuration"


ALL_DOMAINS: List[str] = [
    Domain.PROCESS,
    Domain.NETWORK,
    Domain.TRUST,
    Domain.HARDWARE,
    Domain.PE_EXECUTION,
    Domain.SERVICE,
    Domain.SECURITY,
    Domain.SYSTEM_CONFIG,
]

# Spec default per-domain levels (Section 6.2)
DEFAULT_DOMAIN_LEVELS: Dict[str, int] = {
    Domain.PROCESS: 2,        # act + report
    Domain.NETWORK: 1,        # advise
    Domain.TRUST: 0,          # observe only
    Domain.HARDWARE: 1,       # advise
    Domain.PE_EXECUTION: 2,   # act + report
    Domain.SERVICE: 2,        # act + report
    Domain.SECURITY: 2,       # act + report
    Domain.SYSTEM_CONFIG: 1,  # advise
}


@dataclass
class Decision:
    """A decision made by the cortex."""
    domain: str
    action: str
    description: str
    autonomy_level: int
    timestamp: float = field(default_factory=time.time)
    approved: Optional[bool] = None  # None = pending, True = approved, False = denied
    human_override: bool = False


class AutonomyController:
    """
    Manages per-domain autonomy levels governed by the cortex's own trust score.

    MAX_PENDING limits the pending decision list to prevent unbounded growth.

    Score-based ceiling (from spec Section 6.2, SOVEREIGN removed):
        score >= 70  ->  max Level 3 (AUTONOMOUS) -- hard cap
        score >= 50  ->  max Level 2 (ACT_REPORT)
        score >= 30  ->  max Level 1 (ADVISE)
        score <  30  ->  forced Level 0 (OBSERVE)

    Score dynamics:
        +1   correct decision (human confirms or no incident after 24h)
        -5   false positive (human overrides a quarantine/deny)
        -10  missed threat (incident occurs after cortex allowed an action)
        -20  human explicitly lowers autonomy

    Safety mechanisms:
        - Hard ceiling at AUTONOMOUS (3); SOVEREIGN (4) removed entirely
        - Dead-man switch: forces OBSERVE after 4h without human interaction
        - Emergency stop: POST /emergency-stop zeros score + all levels
        - Dangerous commands (rm, mkfs, dd, iptables, etc.) are blocked in orchestrator
    """

    # Dead-man switch: force OBSERVE if no human interaction for this long.
    DEAD_MAN_TIMEOUT_S: int = 4 * 3600  # 4 hours

    # Maximum pending decisions before oldest entries are evicted.
    MAX_PENDING: int = 500

    def __init__(
        self,
        config_levels: Optional[Dict[str, int]] = None,
        initial_score: int = 50,
    ):
        if config_levels is None:
            config_levels = {}

        self._configured_levels: Dict[str, int] = {}
        for domain in ALL_DOMAINS:
            raw = config_levels.get(domain, DEFAULT_DOMAIN_LEVELS.get(domain, 2))
            # Enforce hard ceiling: no domain may be configured above MAX_AUTONOMY_LEVEL
            self._configured_levels[domain] = min(raw, MAX_AUTONOMY_LEVEL)

        self._score: int = max(0, min(100, initial_score))
        self._decisions: List[Decision] = []
        self._pending: List[Decision] = []
        self._score_history: List[dict] = []

        # Dead-man switch state
        self._init_time: float = time.time()
        self._last_human_interaction: float = time.time()
        self._dead_man_tripped: bool = False
        self._emergency_stopped: bool = False

        logger.info(
            "Autonomy controller initialized. Score: %d, Ceiling: Level %d",
            self._score, self._score_to_ceiling(self._score),
        )

    # -- Score-to-ceiling mapping --

    @staticmethod
    def _score_to_ceiling(score: int) -> int:
        """Map cortex trust score to maximum autonomy level.

        Hard-capped at AUTONOMOUS (3).  SOVEREIGN (4) was removed;
        self-modification of trust parameters requires explicit human action.
        """
        if score >= 70:
            return AutonomyLevel.AUTONOMOUS
        if score >= 50:
            return AutonomyLevel.ACT_REPORT
        if score >= 30:
            return AutonomyLevel.ADVISE
        return AutonomyLevel.OBSERVE

    # -- Properties --

    @property
    def score(self) -> int:
        return self._score

    @property
    def ceiling(self) -> int:
        return self._score_to_ceiling(self._score)

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    # -- Level queries --

    def effective_level(self, domain: str) -> int:
        """Effective autonomy level: min(configured, ceiling)."""
        configured = self._configured_levels.get(domain, 0)
        return min(configured, self.ceiling)

    def can_act(self, domain: str) -> bool:
        """Can the cortex take action in this domain without human approval?"""
        return self.effective_level(domain) >= AutonomyLevel.ACT_REPORT

    def needs_approval(self, domain: str) -> bool:
        """Does the cortex need human approval for this domain?"""
        return self.effective_level(domain) == AutonomyLevel.ADVISE

    def is_observe_only(self, domain: str) -> bool:
        """Is the cortex limited to observation in this domain?"""
        return self.effective_level(domain) == AutonomyLevel.OBSERVE

    # -- Dead-man switch & emergency stop --

    def check_dead_man_switch(self) -> bool:
        """Check if a human has interacted recently.

        If no human interaction (approve, deny, or set_autonomy) has occurred
        within DEAD_MAN_TIMEOUT_S seconds, force all domains to OBSERVE.
        Returns True if the switch tripped.
        """
        elapsed = time.time() - self._last_human_interaction
        if elapsed > self.DEAD_MAN_TIMEOUT_S:
            if not self._dead_man_tripped:
                logger.warning(
                    "DEAD-MAN SWITCH: no human interaction for %.0fs "
                    "(limit=%ds). Forcing all domains to OBSERVE.",
                    elapsed, self.DEAD_MAN_TIMEOUT_S,
                )
                self.emergency_stop("dead-man switch (no human interaction)")
                self._dead_man_tripped = True
            return True
        self._dead_man_tripped = False
        return False

    def record_human_interaction(self) -> None:
        """Record that a human interacted (resets dead-man timer)."""
        self._last_human_interaction = time.time()
        self._dead_man_tripped = False

    def emergency_stop(self, reason: str = "emergency stop") -> None:
        """Immediately drop ALL domains to OBSERVE (level 0).

        This is the panic button. Score is set to 0 so the ceiling stays
        at OBSERVE until a human explicitly raises it.
        """
        logger.critical("EMERGENCY STOP: %s", reason)
        for domain in ALL_DOMAINS:
            self._configured_levels[domain] = AutonomyLevel.OBSERVE
        old_score = self._score
        self._score = 0
        self._score_history.append({
            "timestamp": time.time(),
            "old_score": old_score,
            "new_score": 0,
            "delta": -old_score,
            "reason": f"EMERGENCY STOP: {reason}",
        })
        self._emergency_stopped = True
        self._pending.clear()

    @property
    def is_emergency_stopped(self) -> bool:
        return self._emergency_stopped

    # -- Score adjustments --

    def record_correct(self) -> None:
        """Record a correct decision. +1 score."""
        self._adjust_score(1, "correct decision")

    def record_false_positive(self) -> None:
        """Human overrode a cortex action. -5 score."""
        self._adjust_score(-5, "false positive (human override)")

    def record_missed_threat(self) -> None:
        """Incident occurred after cortex allowed. -10 score."""
        self._adjust_score(-10, "missed threat")

    def record_manual_lower(self) -> None:
        """Human explicitly lowered autonomy. -20 score."""
        self._adjust_score(-20, "manual autonomy reduction")

    def _adjust_score(self, delta: int, reason: str) -> None:
        old = self._score
        self._score = max(0, min(100, self._score + delta))
        old_ceil = self._score_to_ceiling(old)
        new_ceil = self._score_to_ceiling(self._score)

        entry = {
            "timestamp": time.time(),
            "old_score": old,
            "new_score": self._score,
            "delta": delta,
            "reason": reason,
        }
        self._score_history.append(entry)

        # Keep history bounded
        if len(self._score_history) > 1000:
            self._score_history = self._score_history[-500:]

        if old_ceil != new_ceil:
            logger.warning(
                "Autonomy ceiling changed: Level %d -> Level %d "
                "(score: %d -> %d, reason: %s)",
                old_ceil, new_ceil, old, self._score, reason,
            )
        else:
            logger.info(
                "Score: %d -> %d (%s)", old, self._score, reason,
            )

    # -- Decision creation --

    def create_decision(
        self, domain: str, action: str, description: str,
    ) -> Decision:
        """
        Create a decision record for the given domain.

        Returns a Decision with:
        - approved=True   if level >= ACT_REPORT (auto-approved)
        - approved=None   if level == ADVISE (pending human approval)
        - approved=False  if level == OBSERVE (no action taken)
        """
        level = self.effective_level(domain)
        decision = Decision(
            domain=domain,
            action=action,
            description=description,
            autonomy_level=level,
        )

        if level >= AutonomyLevel.ACT_REPORT:
            decision.approved = True
        elif level == AutonomyLevel.ADVISE:
            decision.approved = None  # Pending human approval
            self._pending.append(decision)
        else:
            decision.approved = False  # Observe only -- no action

        # Cap pending list to prevent unbounded growth
        self._pending = [d for d in self._pending if d.approved is None]
        if len(self._pending) > self.MAX_PENDING:
            self._pending = self._pending[-self.MAX_PENDING:]

        self._decisions.append(decision)

        # Keep decisions bounded
        if len(self._decisions) > 5000:
            self._decisions = self._decisions[-2500:]

        return decision

    # -- Pending decision management --

    def get_pending(self) -> List[Decision]:
        """Return list of decisions awaiting human approval."""
        return list(self._pending)

    def approve_pending(self, index: int) -> bool:
        """Approve a pending decision by index. Returns True on success."""
        if 0 <= index < len(self._pending):
            self._pending[index].approved = True
            self._pending.pop(index)
            self.record_human_interaction()
            return True
        return False

    def deny_pending(self, index: int) -> bool:
        """Deny a pending decision and record false positive. Returns True on success."""
        if 0 <= index < len(self._pending):
            decision = self._pending[index]
            decision.approved = False
            decision.human_override = True
            self._pending.pop(index)
            self.record_false_positive()
            self.record_human_interaction()
            return True
        return False

    def clear_resolved_pending(self) -> int:
        """Remove pending decisions that have been resolved. Returns count removed."""
        before = len(self._pending)
        self._pending = [d for d in self._pending if d.approved is None]
        return before - len(self._pending)

    # -- State export --

    @staticmethod
    def _level_name(level: int) -> str:
        """Safe level-to-name conversion (handles removed SOVEREIGN)."""
        try:
            return AutonomyLevel(level).name
        except ValueError:
            return f"LEVEL_{level}"

    @property
    def state(self) -> dict:
        """Export full controller state for API/dashboard."""
        return {
            "score": self._score,
            "ceiling": self.ceiling,
            "ceiling_name": self._level_name(self.ceiling),
            "max_autonomy_level": int(MAX_AUTONOMY_LEVEL),
            "configured_levels": dict(self._configured_levels),
            "effective_levels": {
                d: self.effective_level(d) for d in ALL_DOMAINS
            },
            "effective_level_names": {
                d: self._level_name(self.effective_level(d))
                for d in ALL_DOMAINS
            },
            "pending_decisions": len(self._pending),
            "total_decisions": len(self._decisions),
            "score_history_len": len(self._score_history),
            "recent_score_history": self._score_history[-10:],
            "emergency_stopped": self._emergency_stopped,
            "dead_man_tripped": self._dead_man_tripped,
            "dead_man_timeout_s": self.DEAD_MAN_TIMEOUT_S,
            "seconds_since_human_interaction": (
                round(time.time() - self._last_human_interaction, 1)
                if self._last_human_interaction > 0 else None
            ),
        }
