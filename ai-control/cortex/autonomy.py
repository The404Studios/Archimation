"""
Autonomy Controller -- governs how much independent action the cortex can take.

The cortex's autonomy is itself governed by the Root of Authority trust system.
Higher trust score = more autonomous. Mistakes reduce autonomy.
"""
import logging
import os
import time
from collections import deque
from enum import IntEnum
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Optional

logger = logging.getLogger("cortex.autonomy")


def _is_old_hw() -> bool:
    """Lightweight old-HW probe (<=2 cores or <2GB RAM)."""
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
    """A decision made by the cortex.

    Fields added for Session 25 approval follow-through wiring:
      pid            -- process ID associated with this gate (if any).  Set
                        when a handler freezes a process while awaiting
                        approval so the resolution path can resume/kill it.
      resume_action  -- optional zero-arg callable invoked on approve().
                        Typical use: resume a SIGSTOP'd PE process.
      reject_action  -- optional zero-arg callable invoked on deny/expire.
                        Typical use: SIGKILL a frozen PE process.
      expires_at     -- absolute time (seconds, time.time()) after which a
                        pending decision should auto-resolve to its default
                        (deny).  None = never expire.
      resolved_by    -- one of "human", "auto-expire", "" (still pending).
                        Informational only; never affects gate behavior.
    """
    domain: str
    action: str
    description: str
    autonomy_level: int
    timestamp: float = field(default_factory=time.time)
    approved: Optional[bool] = None  # None = pending, True = approved, False = denied
    human_override: bool = False
    pid: Optional[int] = None
    resume_action: Optional[Callable[[], None]] = None
    reject_action: Optional[Callable[[], None]] = None
    expires_at: Optional[float] = None
    resolved_by: str = ""


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
        # HW-tier aware history caps -- old HW keeps less history to limit
        # Python heap growth under hours of uptime; new HW keeps more for
        # richer /scores history windows.
        old_hw = _is_old_hw()
        decisions_cap = 2000 if old_hw else 5000
        score_history_cap = 500 if old_hw else 2000
        # deque(maxlen) gives O(1) bounded append; the list-based approach
        # copied the tail every N inserts.
        self._decisions: Deque[Decision] = deque(maxlen=decisions_cap)
        self._pending: List[Decision] = []
        self._score_history: Deque[dict] = deque(maxlen=score_history_cap)

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

        Reject callbacks are fired OUTSIDE the pending-list mutation so a
        misbehaving callback cannot leave the autonomy controller in a
        half-emergency state (pending still populated but domains at OBSERVE).
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
        # Swap the pending list atomically before iterating so any callback
        # that calls back into create_decision() sees an empty pending list
        # and doesn't get its new decision dropped in a recursive sweep.
        leftover = self._pending
        self._pending = []
        for d in leftover:
            d.approved = False
            d.resolved_by = "emergency-stop"
            self._safe_call(d.reject_action, "reject (emergency-stop)")

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

        # deque(maxlen=...) bounds automatically -- no slice-rebuild cost.
        self._score_history.append({
            "timestamp": time.time(),
            "old_score": old,
            "new_score": self._score,
            "delta": delta,
            "reason": reason,
        })

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
        pid: Optional[int] = None,
        resume_action: Optional[Callable[[], None]] = None,
        reject_action: Optional[Callable[[], None]] = None,
        pending_ttl_s: Optional[float] = None,
    ) -> Decision:
        """
        Create a decision record for the given domain.

        Returns a Decision with:
        - approved=True   if level >= ACT_REPORT (auto-approved)
        - approved=None   if level == ADVISE (pending human approval)
        - approved=False  if level == OBSERVE (no action taken)

        Optional follow-through wiring (used when the caller freezes a
        process while awaiting approval):
          pid            -- process ID this decision gates.
          resume_action  -- invoked on approve_pending() (e.g. SIGCONT the pid).
          reject_action  -- invoked on deny_pending() or auto-expiry (e.g. SIGKILL).
          pending_ttl_s  -- seconds until auto-deny (default DEFAULT_PENDING_TTL_S).
                            Only applies if the decision ends up pending.
        """
        level = self.effective_level(domain)
        decision = Decision(
            domain=domain,
            action=action,
            description=description,
            autonomy_level=level,
            pid=pid,
            resume_action=resume_action,
            reject_action=reject_action,
        )

        if level >= AutonomyLevel.ACT_REPORT:
            decision.approved = True
        elif level == AutonomyLevel.ADVISE:
            decision.approved = None  # Pending human approval
            ttl = self.DEFAULT_PENDING_TTL_S if pending_ttl_s is None else pending_ttl_s
            if ttl is not None and ttl > 0:
                decision.expires_at = decision.timestamp + ttl
            self._pending.append(decision)
        else:
            decision.approved = False  # Observe only -- no action

        # Cap pending list to prevent unbounded growth.  When we trim the
        # oldest entries we MUST fire their reject callbacks -- otherwise
        # any frozen PE process gated by an evicted decision leaks as a
        # SIGSTOP'd ghost forever.  (This was a latent Session 25-class bug.)
        if len(self._pending) > self.MAX_PENDING:
            overflow = len(self._pending) - self.MAX_PENDING
            evicted = self._pending[:overflow]
            self._pending = self._pending[overflow:]
            for d in evicted:
                if d.approved is None:
                    d.approved = False
                    d.resolved_by = "pending-overflow"
                    self._safe_call(d.reject_action, "reject (pending-overflow)")

        # deque(maxlen=decisions_cap) handles the bound automatically; no
        # manual slice-resize needed (and slicing a deque would blow up).
        self._decisions.append(decision)

        return decision

    # -- Pending decision management --

    # Default TTL for pending decisions if the caller doesn't set expires_at.
    # 300s = 5 minutes.  If a human doesn't approve within this window,
    # expire_overdue_pending() auto-applies the reject_action (e.g. SIGKILL
    # a frozen PE process) so we don't leak SIGSTOP'd zombies.
    DEFAULT_PENDING_TTL_S: float = 300.0

    def get_pending(self) -> List[Decision]:
        """Return list of decisions awaiting human approval."""
        return list(self._pending)

    @staticmethod
    def _safe_call(cb: Optional[Callable[[], None]], label: str) -> None:
        """Run a callback swallowing all exceptions so a bad callback can't
        break the autonomy flow (or the API request)."""
        if cb is None:
            return
        try:
            cb()
        except Exception:
            # Log but don't propagate -- the caller (API or expiry loop)
            # must never crash because a resume/reject callback misbehaved.
            logger.exception("Decision %s callback raised", label)

    def approve_pending(self, index: int) -> bool:
        """Approve a pending decision by index. Returns True on success.

        If the decision was gating a frozen PID, its resume_action callback
        (registered by the handler that froze the process) is invoked here
        so the PE process can actually run.  Without this, a SIGSTOP'd
        process stays frozen forever.
        """
        if 0 <= index < len(self._pending):
            decision = self._pending[index]
            decision.approved = True
            decision.resolved_by = "human"
            self._pending.pop(index)
            self.record_human_interaction()
            # Fire the resume callback OUTSIDE the list mutation so any
            # exception it throws doesn't corrupt pending list state.
            self._safe_call(decision.resume_action, "resume")
            return True
        return False

    def deny_pending(self, index: int) -> bool:
        """Deny a pending decision and record false positive. Returns True on success.

        If the decision was gating a frozen PID, its reject_action callback
        (registered by the handler that froze the process) is invoked here
        so the PE process is killed rather than left as a SIGSTOP'd ghost.
        """
        if 0 <= index < len(self._pending):
            decision = self._pending[index]
            decision.approved = False
            decision.human_override = True
            decision.resolved_by = "human"
            self._pending.pop(index)
            self.record_false_positive()
            self.record_human_interaction()
            self._safe_call(decision.reject_action, "reject")
            return True
        return False

    def expire_overdue_pending(self, now: Optional[float] = None) -> int:
        """Auto-expire any pending decisions past their expires_at deadline.

        Expired decisions are treated as DENIED (reject_action fires).
        This prevents frozen PE processes from leaking forever if the
        human never clicks approve/deny.

        Returns the number of decisions that were expired.
        """
        if now is None:
            now = time.time()
        if not self._pending:
            return 0

        expired: List[Decision] = []
        kept: List[Decision] = []
        for d in self._pending:
            if d.expires_at is not None and now >= d.expires_at:
                expired.append(d)
            else:
                kept.append(d)

        if not expired:
            return 0

        self._pending = kept
        for d in expired:
            d.approved = False
            d.resolved_by = "auto-expire"
            # Expiry defaults to DENY.  Fire reject callback so the
            # frozen process doesn't leak.  No human_override flag
            # (this wasn't a human decision) -- don't penalize the
            # cortex score for its own inaction.
            logger.warning(
                "Pending decision auto-expired: %s (%s) -- applying reject action",
                d.action, d.description,
            )
            self._safe_call(d.reject_action, "reject (auto-expire)")
        return len(expired)

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
        # deque doesn't support slice, so take the last 10 via itertools.islice.
        from itertools import islice
        hist_len = len(self._score_history)
        start = max(0, hist_len - 10)
        recent_history = list(islice(self._score_history, start, hist_len))
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
            "score_history_len": hist_len,
            "recent_score_history": recent_history,
            "emergency_stopped": self._emergency_stopped,
            "dead_man_tripped": self._dead_man_tripped,
            "dead_man_timeout_s": self.DEAD_MAN_TIMEOUT_S,
            "seconds_since_human_interaction": (
                round(time.time() - self._last_human_interaction, 1)
                if self._last_human_interaction > 0 else None
            ),
        }
