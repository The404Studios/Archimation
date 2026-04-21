"""
AI Cortex -- Main Entry Point

The central nervous system of the AI Arch Linux OS.
Event-driven, autonomous, trust-governed.

Usage:
  python -m cortex                    # Run the cortex
  python -m cortex --config /path     # Custom config
  python -m cortex --log-level DEBUG  # Verbose
  python -m cortex --api-port 8421    # Custom API port (daemon uses 8420)
"""

import asyncio
import argparse
import logging
import os
import signal
import struct
import sys
import time
from collections import deque
from pathlib import Path
from typing import Optional

from .config import CortexConfig
from .event_bus import (
    EventBus, Event, SourceLayer,
    PeEventType, TrustEventType, SvcEventType,
)
from .autonomy import AutonomyController, ALL_DOMAINS, AutonomyLevel, Domain
from .decision_engine import DecisionEngine, Verdict, EvalResult
from .orchestrator import Orchestrator
from .trust_history import TrustHistoryStore

logger = logging.getLogger("cortex")


# ---------------------------------------------------------------------------
# Hardware capability detection: scales buffers/limits up on beefy machines,
# down on constrained ones.  Old HW (1 core or <=1GB RAM) gets tight buffers,
# new HW (4+ cores with plenty of RAM) gets richer history windows.
# ---------------------------------------------------------------------------

def _detect_hw_tier() -> str:
    """Return 'old' for constrained hosts, 'new' for richer ones.

    Heuristic only -- we never fail on detection errors, we just default to
    'old' (safer, tighter buffers) when probes fail.
    """
    try:
        cpu_count = os.cpu_count() or 1
    except Exception:
        cpu_count = 1
    mem_gb = 1.0
    try:
        # sysconf is POSIX; Windows/WSL tooling may not expose it.
        page_size = os.sysconf("SC_PAGE_SIZE")
        phys_pages = os.sysconf("SC_PHYS_PAGES")
        mem_gb = (page_size * phys_pages) / (1024 ** 3)
    except (ValueError, OSError, AttributeError):
        pass
    if cpu_count >= 4 and mem_gb >= 4.0:
        return "new"
    return "old"


_HW_TIER = _detect_hw_tier()
# Recent-event buffer size -- on old hardware we keep less history to cap
# memory growth; on new hardware we keep more for richer /events/recent output.
_RECENT_EVENTS_MAX = 500 if _HW_TIER == "new" else 150

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

__version__ = "0.1.0"


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(level_name: str, log_file: Optional[str] = None) -> None:
    """Configure root logging for the cortex."""
    level = getattr(logging, level_name.upper(), logging.INFO)
    fmt = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]

    if log_file:
        try:
            fh = logging.FileHandler(log_file)
            fh.setLevel(level)
            fh.setFormatter(logging.Formatter(fmt))
            handlers.append(fh)
        except OSError as exc:
            print(f"Warning: cannot open log file {log_file}: {exc}", file=sys.stderr)

    logging.basicConfig(level=level, format=fmt, handlers=handlers)


# ---------------------------------------------------------------------------
# Event handler wiring: SENSE -> DECIDE -> ACT
# ---------------------------------------------------------------------------

class CortexHandlers:
    """
    Wires the three-phase loop: events arrive from the bus (SENSE),
    the autonomy controller decides (DECIDE), and the orchestrator
    executes (ACT).
    """

    def __init__(
        self,
        autonomy: AutonomyController,
        orchestrator: Orchestrator,
        trust_history: Optional[TrustHistoryStore] = None,
        decision_engine: Optional[DecisionEngine] = None,
    ):
        self._autonomy = autonomy
        self._orchestrator = orchestrator
        self._trust_history = trust_history
        self._decision_engine = decision_engine
        self._events_processed: int = 0
        self._start_time: float = time.time()
        # deque(maxlen) gives O(1) bounded append; the previous list-and-slice
        # copied the tail every 200 events, and burned CPU on busy systems.
        self._recent_events: "deque[dict]" = deque(maxlen=_RECENT_EVENTS_MAX)
        self._pending_tasks: set[asyncio.Task] = set()
        # Running counters over recorded action tags -- /status API previously
        # walked the recent_events list four times per request to tally
        # memory_events / anomalies / patterns / stubs / maps, which is O(N)
        # per poll.  Now we tally at record-time for O(1) reads.
        self._action_counts: dict[str, int] = {
            "memory_anomaly": 0,
            "memory_pattern": 0,
            "memory_stub": 0,
            "memory_map": 0,
            "memory_protect": 0,
        }

    # -- Helpers --------------------------------------------------------------

    def _track_task(self, coro) -> asyncio.Task:
        """Create an asyncio task and track it so it isn't lost on shutdown."""
        task = asyncio.get_running_loop().create_task(coro)
        self._pending_tasks.add(task)
        task.add_done_callback(self._pending_tasks.discard)
        return task

    def _record_event(self, event: Event, action_taken: str) -> None:
        """Keep a bounded buffer of recent events for the API."""
        self._events_processed += 1
        entry = {
            "timestamp": time.time(),
            "source": event.source_name,
            "type": event.type_name(),
            "pid": event.pid,
            "subject_id": event.subject_id,
            "action": action_taken,
        }
        self._recent_events.append(entry)
        # Fast-path: tally categories at record time so /status doesn't have
        # to rescan the whole ring buffer and run substring checks on every
        # poll.  Uses startswith because record-tag format is stable.
        if action_taken:
            if "memory anomaly" in action_taken:
                self._action_counts["memory_anomaly"] += 1
            elif action_taken.startswith("pattern:"):
                self._action_counts["memory_pattern"] += 1
            elif action_taken.startswith("stub:"):
                self._action_counts["memory_stub"] += 1
            elif action_taken.startswith("map:"):
                self._action_counts["memory_map"] += 1
            elif action_taken.startswith("protect:"):
                self._action_counts["memory_protect"] += 1

    @property
    def recent_events(self) -> list[dict]:
        # deque supports slicing via list()+indexing; return at most 100 for
        # the API without copying the whole buffer.
        n = len(self._recent_events)
        if n <= 100:
            return list(self._recent_events)
        # Skip to the 100-from-end point.  Deque supports negative indexing
        # but not slicing, so we use islice from collections-like logic.
        return list(self._recent_events)[-100:]

    @property
    def action_counts(self) -> dict[str, int]:
        """O(1) snapshot of running action-category counters."""
        return dict(self._action_counts)

    @property
    def events_processed(self) -> int:
        return self._events_processed

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self._start_time

    # -- Helpers --------------------------------------------------------------

    def _get_payload_dict(self, event: Event) -> dict:
        """Return event.payload as a dict, or empty dict if still raw bytes."""
        if isinstance(event.payload, dict):
            return event.payload
        return {}

    def _check_decision_engine(self, event: Event) -> Optional[EvalResult]:
        """Run the event through the DecisionEngine (if available).

        Returns the EvalResult, or None if no engine is configured.
        The caller decides how to handle DENY / QUARANTINE / ESCALATE verdicts.
        """
        if self._decision_engine is None:
            return None
        try:
            return self._decision_engine.evaluate(event)
        except Exception as exc:
            logger.error("DecisionEngine.evaluate() failed: %s", exc)
            return None

    def _apply_engine_verdict(self, event: Event, result: EvalResult) -> bool:
        """Act on a DecisionEngine verdict that overrides normal flow.

        Returns True if the caller should short-circuit (deny/quarantine/escalate
        already handled here), False if normal handler flow should continue.
        """
        if result.verdict == Verdict.DENY:
            logger.warning(
                "DecisionEngine DENY: pid=%d reason=%s (tier=%s, conf=%.2f)",
                event.pid, result.reason, result.tier, result.confidence,
            )
            self._record_event(event, f"denied by {result.tier}: {result.reason}")
            return True

        if result.verdict == Verdict.QUARANTINE:
            logger.warning(
                "DecisionEngine QUARANTINE: pid=%d reason=%s (tier=%s, conf=%.2f)",
                event.pid, result.reason, result.tier, result.confidence,
            )
            self._orchestrator.freeze_process(event.pid, force=True)
            self._orchestrator.trust_quarantine(event.pid)
            self._track_task(
                self._orchestrator.notify(
                    "DecisionEngine Quarantine",
                    f"pid={event.pid}: {result.reason}",
                    "critical",
                )
            )
            self._record_event(event, f"quarantined by {result.tier}: {result.reason}")
            return True

        if result.verdict == Verdict.ESCALATE:
            logger.info(
                "DecisionEngine ESCALATE: pid=%d reason=%s (tier=%s, conf=%.2f)",
                event.pid, result.reason, result.tier, result.confidence,
            )
            self._track_task(
                self._orchestrator.notify(
                    "DecisionEngine Escalation",
                    f"pid={event.pid}: {result.reason}",
                    "normal",
                )
            )
            # Escalation does NOT short-circuit -- fall through to autonomy
            # controller which may further evaluate (e.g. pending human approval).
            return False

        # ALLOW / MODIFY -- let normal handler flow continue
        return False

    # -- PE Runtime handlers --------------------------------------------------

    def handle_pe_load(self, event: Event) -> None:
        """PE binary wants to load. Evaluate and act."""
        # Decision engine pre-check (heuristics: fork bomb, policy: apoptotic deny)
        engine_result = self._check_decision_engine(event)
        if engine_result is not None and self._apply_engine_verdict(event, engine_result):
            return  # Engine already handled (deny/quarantine)

        # Session 25 follow-through: capture pid so the gated decision can
        # fire resume/reject callbacks when the human approves or denies.
        # Binding pid into closures here (not into orchestrator refs) means
        # api.py can call the callback without any cortex-side reference.
        gated_pid = event.pid
        orchestrator = self._orchestrator

        def _resume_cb() -> None:
            orchestrator.resume_after_approval(gated_pid)

        def _reject_cb() -> None:
            orchestrator.kill_after_rejection(gated_pid)

        decision = self._autonomy.create_decision(
            Domain.PE_EXECUTION, "pe_load",
            f"PE load: pid={gated_pid} subject={event.subject_id}",
            pid=gated_pid,
            resume_action=_resume_cb,
            reject_action=_reject_cb,
        )

        payload = self._get_payload_dict(event)

        # Record the start in trust history and get suggested budget
        exe_path = payload.get("exe_path", "")
        history_record = None
        suggested_budget = None
        if self._trust_history and exe_path:
            history_record = self._trust_history.record_start(exe_path)
            suggested_budget = history_record.suggested_token_budget
            logger.info(
                "PE load pid=%d: trust history reliability=%.2f budget=%d runs=%d",
                event.pid, history_record.reliability, suggested_budget,
                history_record.total_runs,
            )

        action = "observed"
        if decision.approved:
            # At ACT_REPORT level or above, we permit the load.
            # Check kernel trust score first, then fall back to history-suggested budget.
            score_result = self._orchestrator.trust_get_score(event.pid)
            if score_result.get("success") and score_result.get("score", 50) < 30:
                # Low-trust binary: use history budget or tight default
                budget = suggested_budget if suggested_budget is not None else 100
                self._orchestrator.trust_get_balance(event.pid)
                action = f"approved with restricted budget ({budget} tokens)"
                logger.info("PE load pid=%d: low trust score, restricted budget=%d", event.pid, budget)
            elif suggested_budget is not None:
                # Apply history-suggested budget even for normal binaries
                self._orchestrator.trust_get_balance(event.pid)
                action = f"approved (history budget={suggested_budget})"
                logger.info("PE load pid=%d: approved, history budget=%d", event.pid, suggested_budget)
            else:
                action = "approved"
                logger.info("PE load pid=%d: approved", event.pid)
        elif decision.approved is None:
            # Pending human approval -- freeze the process while waiting.
            # The resume/reject callbacks attached to `decision` above will
            # fire when the human calls /decisions/{index}/approve or /deny,
            # or when the decision auto-expires (default 300s).
            self._orchestrator.freeze_process(event.pid)
            self._track_task(
                self._orchestrator.notify_decision(decision)
            )
            action = "pending (frozen)"
        else:
            action = "observe only"

        self._record_event(event, action)

    def handle_pe_exit(self, event: Event) -> None:
        """PE process exited. Record for statistics and trust history."""
        payload = self._get_payload_dict(event)
        exe_path = payload.get("exe_path", "")
        exit_code = payload.get("exit_code", -1)
        runtime_ms = payload.get("runtime_ms", 0)
        stubs_called = payload.get("stubs_called", 0)
        trust_denials = payload.get("trust_denials", 0)
        exceptions = payload.get("exceptions", 0)

        if self._trust_history and exe_path:
            self._trust_history.record_exit(
                exe_path=exe_path,
                exit_code=exit_code,
                runtime_ms=runtime_ms,
                stubs_called=stubs_called,
                trust_denials=trust_denials,
                exceptions=exceptions,
            )
            logger.debug(
                "PE exit pid=%d: recorded in trust history (exit_code=%d, runtime=%dms)",
                event.pid, exit_code, runtime_ms,
            )

        # Free the score-cache slot for this now-dead pid so the cache
        # doesn't accumulate stale entries across process churn.
        try:
            self._orchestrator.invalidate_score_cache(event.pid)
        except Exception:
            logger.debug("invalidate_score_cache failed", exc_info=True)

        self._record_event(event, "recorded")
        logger.debug("PE exit: pid=%d", event.pid)

    def handle_pe_exception(self, event: Event) -> None:
        """PE process hit an exception."""
        # Decision engine pre-check (heuristic: exception storm detection)
        engine_result = self._check_decision_engine(event)
        if engine_result is not None and self._apply_engine_verdict(event, engine_result):
            return  # Engine already handled (quarantine on exception storm)

        self._record_event(event, "recorded")
        logger.warning("PE exception: pid=%d subject=%d", event.pid, event.subject_id)

    def handle_pe_trust_escalate(self, event: Event) -> None:
        """PE process is requesting an authority escalation through a trust gate.

        S75 follow-up: closes the producer-without-consumer gap on
        PE_EVT_TRUST_ESCALATE (declared at pe-loader/include/eventbus/pe_event.h:50,
        previously orphaned). Semantics: this is the *opposite* of trust_deny —
        the runtime is asking the cortex to evaluate whether the requested
        elevation should be granted. Decision-engine-first; if no engine verdict,
        fall back to autonomy.create_decision so a human can rubber-stamp."""
        engine_result = self._check_decision_engine(event)
        if engine_result is not None and self._apply_engine_verdict(event, engine_result):
            return

        decision = self._autonomy.create_decision(
            Domain.SECURITY, "trust_escalate_request",
            f"Trust escalate request for pid={event.pid}",
        )

        action = "observed"
        if decision.approved:
            # Granted: log as approved escalation; the kernel side will
            # consult the granted authority via its own ioctl path.
            payload = getattr(event, "payload", {}) or {}
            api = payload.get("api_name", "?")
            from_s = payload.get("from_score", -1)
            to_s = payload.get("to_score", -1)
            logger.info(
                "Trust escalate APPROVED: pid=%d api=%s score %d->%d",
                event.pid, api, from_s, to_s,
            )
            action = "escalation_approved"
        else:
            # Refused: leave the requesting process at its current authority
            # band. No quarantine — refusal is the safe default and not punitive.
            action = "escalation_refused"
        self._record_event(event, action)

    def handle_pe_trust_deny(self, event: Event) -> None:
        """PE process was denied a trust-gated operation."""
        # Decision engine pre-check (heuristic: privilege escalation probe detection)
        engine_result = self._check_decision_engine(event)
        if engine_result is not None and self._apply_engine_verdict(event, engine_result):
            return  # Engine already handled (quarantine on excessive denials)

        decision = self._autonomy.create_decision(
            Domain.SECURITY, "trust_deny_response",
            f"Trust deny for pid={event.pid}",
        )

        action = "observed"
        if decision.approved:
            # Repeated denials might warrant quarantine -- check score
            score_result = self._orchestrator.trust_get_score(event.pid)
            if score_result.get("success") and score_result.get("score", 50) < 10:
                self._orchestrator.freeze_process(event.pid, force=True)
                self._orchestrator.trust_quarantine(event.pid)
                action = "quarantined (score < 10)"
                logger.warning("Trust deny cascade: pid=%d quarantined", event.pid)
            else:
                action = "logged"
        self._record_event(event, action)

    # -- Trust kernel module handlers -----------------------------------------

    def handle_trust_alert(self, event: Event) -> None:
        """Trust system raised an immune alert."""
        # Decision engine pre-check (policy: auto-quarantine on immune alert)
        engine_result = self._check_decision_engine(event)
        if engine_result is not None and self._apply_engine_verdict(event, engine_result):
            return  # Engine already handled (quarantine)

        # Session 25 follow-through: wire pid + resume/reject callbacks so
        # a human approval/denial on the pending decision unfreezes or
        # kills the alert subject instead of leaving it SIGSTOP'd forever.
        #
        # Semantics differ from pe_load: an APPROVED immune alert means
        # "yes, quarantine it" -- which we've ALREADY done at freeze time.
        # So "approve" here keeps the process frozen+quarantined (no-op
        # callback) while "reject" releases and resumes it (false alert).
        gated_pid = event.pid
        orchestrator = self._orchestrator

        def _resume_cb() -> None:
            # Approved: the human confirms the immune alert was legitimate.
            # Process stays frozen+quarantined; nothing to do here.  The
            # quarantine_release pathway is a separate admin action.
            return

        def _reject_cb() -> None:
            # Rejected: the human says this was a false alarm.  Release
            # the quarantine (if it was applied) AND resume the process,
            # otherwise it leaks as a SIGSTOP'd ghost.
            orchestrator.trust_release(gated_pid)
            orchestrator.resume_after_approval(gated_pid)

        decision = self._autonomy.create_decision(
            Domain.SECURITY, "trust_alert",
            f"Trust immune alert: pid={gated_pid} subject={event.subject_id}",
            pid=gated_pid,
            resume_action=_resume_cb,
            reject_action=_reject_cb,
        )

        action = "observed"
        if decision.approved:
            self._orchestrator.freeze_process(event.pid, force=True)
            self._orchestrator.trust_quarantine(event.pid)

            # Record quarantine in trust history
            payload = self._get_payload_dict(event)
            exe_path = payload.get("exe_path", "")
            if self._trust_history and exe_path:
                self._trust_history.record_quarantine(exe_path)

            self._track_task(
                self._orchestrator.notify(
                    "Security Alert",
                    f"Process {event.pid} quarantined: immune alert triggered",
                    "critical",
                )
            )
            action = "quarantined + notified"
            logger.warning("Immune alert: pid=%d quarantined", event.pid)
        elif decision.approved is None:
            self._orchestrator.freeze_process(event.pid, force=True)
            self._track_task(
                self._orchestrator.notify_decision(decision)
            )
            action = "frozen, pending approval"

        self._record_event(event, action)

    def handle_trust_quarantine(self, event: Event) -> None:
        """Trust system quarantined a subject (kernel-initiated)."""
        # Quarantine usually clamps trust score -- invalidate cached reading.
        try:
            self._orchestrator.invalidate_score_cache(event.pid)
        except Exception:
            logger.debug("invalidate_score_cache failed", exc_info=True)
        self._record_event(event, "kernel quarantine")
        self._track_task(
            self._orchestrator.notify(
                "Quarantine",
                f"Kernel quarantined pid={event.pid} (subject={event.subject_id})",
                "critical",
            )
        )

    def handle_trust_token_starve(self, event: Event) -> None:
        """A process exhausted its trust tokens."""
        # Decision engine pre-check (policy: escalate token starvation)
        engine_result = self._check_decision_engine(event)
        if engine_result is not None and self._apply_engine_verdict(event, engine_result):
            return

        self._record_event(event, "token starvation")
        logger.warning("Token starvation: pid=%d subject=%d", event.pid, event.subject_id)

    def handle_trust_score_change(self, event: Event) -> None:
        """Trust score changed for a subject."""
        # Drop any cached trust-score reading for this pid -- the decision
        # engine + policy evaluator will re-query through the ioctl next
        # time, ensuring we don't act on stale score data.
        try:
            self._orchestrator.invalidate_score_cache(event.pid)
        except Exception:
            logger.debug("invalidate_score_cache failed", exc_info=True)
        self._record_event(event, "score change")

    # -- Service fabric handlers ----------------------------------------------

    def handle_service_crash(self, event: Event) -> None:
        """A service crashed. Decide whether to restart."""
        # Decision engine pre-check (heuristic: crash loop detection)
        engine_result = self._check_decision_engine(event)
        if engine_result is not None and self._apply_engine_verdict(event, engine_result):
            return  # Engine says stop restarts (crash loop detected)

        decision = self._autonomy.create_decision(
            Domain.SERVICE, "svc_restart",
            f"Service crash: pid={event.pid}",
        )

        action = "observed"
        if decision.approved:
            # Attempt restart via SCM
            self._track_task(
                self._orchestrator.scm_start_service(f"pid_{event.pid}")
            )
            action = "restart requested"
            logger.info("Service crash pid=%d: auto-restart requested", event.pid)
        elif decision.approved is None:
            self._track_task(
                self._orchestrator.notify_decision(decision)
            )
            action = "pending restart approval"

        self._record_event(event, action)

    def handle_service_dependency_fail(self, event: Event) -> None:
        """A service dependency failed."""
        # Decision engine pre-check (policy: escalate dependency failures)
        engine_result = self._check_decision_engine(event)
        if engine_result is not None and self._apply_engine_verdict(event, engine_result):
            return

        self._record_event(event, "dependency failure")
        self._track_task(
            self._orchestrator.notify(
                "Service Dependency Failure",
                f"Service pid={event.pid} has a failed dependency",
                "normal",
            )
        )

    # -- Memory subsystem handlers ----------------------------------------------

    async def handle_memory_map(self, event: Event) -> None:
        """Handle memory map events -- detect DLL injection via decision engine."""
        if self._decision_engine:
            result = self._check_decision_engine(event)
            if result and self._apply_engine_verdict(event, result):
                return

        payload = self._get_payload_dict(event)
        source_path = payload.get("source_path", "")
        logger.debug(
            "Memory map PID %d: VA %#x size=%d source=%s",
            event.pid, payload.get("va", 0),
            payload.get("size", 0), source_path,
        )
        self._record_event(event, f"map:{source_path or 'anon'}")

    async def handle_memory_anomaly(self, event: Event) -> None:
        """Handle memory anomaly events from the TMS / memory scanner."""
        if self._decision_engine:
            result = self._check_decision_engine(event)
            if result and self._apply_engine_verdict(event, result):
                return

        payload = self._get_payload_dict(event)

        # Log the anomaly
        logger.warning(
            "Memory anomaly PID %d: %s at VA %#x",
            event.pid,
            payload.get("description", "unknown"),
            payload.get("va", 0),
        )

        # Negative trust impact via quarantine-grade notification
        self._track_task(
            self._orchestrator.notify(
                "Memory Anomaly",
                f"PID {event.pid}: {payload.get('description', 'unknown')} "
                f"at VA {payload.get('va', 0):#x}",
                "critical",
            )
        )
        self._record_event(event, "memory anomaly detected")

    async def handle_memory_pattern(self, event: Event) -> None:
        """Handle pattern match events from the memory scanner."""
        if self._decision_engine:
            result = self._check_decision_engine(event)
            if result and self._apply_engine_verdict(event, result):
                return

        payload = self._get_payload_dict(event)
        category = payload.get("category", "unknown")
        pattern_id = payload.get("pattern_id", "?")

        logger.info(
            "Memory pattern match PID %d: %s (%s) at VA %#x",
            event.pid, pattern_id, category, payload.get("va", 0),
        )

        # Anti-debug and anti-cheat patterns warrant notification
        if category in ("anti_debug", "anti_cheat", "drm"):
            self._track_task(
                self._orchestrator.notify(
                    "Memory Pattern Alert",
                    f"PID {event.pid}: {category} pattern '{pattern_id}' detected",
                    "normal",
                )
            )

        self._record_event(event, f"pattern:{pattern_id}")

    async def handle_memory_protect(self, event: Event) -> None:
        """Handle memory-protection-change events from the TMS.

        The DecisionEngine carries two heuristics keyed on MEMORY_PROTECT --
        RWX-heap injection (QUARANTINE) and IAT-write hook (ESCALATE).
        Before this handler was added, no subscriber was registered for
        MEMORY_PROTECT, so the dispatcher never routed it to
        _check_decision_engine() and those heuristics were dead code
        (handle_all() fired, but it only logs -- it never consults the
        engine).  This closes that observability gap.
        """
        if self._decision_engine:
            result = self._check_decision_engine(event)
            if result and self._apply_engine_verdict(event, result):
                return

        payload = self._get_payload_dict(event)
        logger.debug(
            "Memory protect PID %d: VA %#x new_prot=%s tag=%s",
            event.pid, payload.get("va", 0),
            payload.get("new_prot", ""), payload.get("tag", ""),
        )
        self._record_event(event, f"protect:{payload.get('new_prot', '?')}")

    async def handle_stub_called(self, event: Event) -> None:
        """Handle stub call events -- an unimplemented function was called."""
        payload = self._get_payload_dict(event)
        dll = payload.get("dll", "?")
        func = payload.get("function", "?")

        logger.debug("Stub call: %s!%s (PID %d)", dll, func, event.pid)

        # Check decision engine for stub flood
        if self._decision_engine:
            result = self._check_decision_engine(event)
            if result and self._apply_engine_verdict(event, result):
                return

        self._record_event(event, f"stub:{dll}!{func}")

    # -- Global handler (audit log) -------------------------------------------

    def handle_all(self, event: Event) -> None:
        """Global handler for audit logging. Receives every event."""
        logger.debug(
            "EVENT seq=%d src=%s type=%s pid=%d flags=0x%04x",
            event.sequence,
            event.source_name,
            event.type_name(),
            event.pid,
            event.flags,
        )

    # -- Command channel: PE load approval ------------------------------------

    async def handle_cmd_pe_load(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a PE_LOAD_REQUEST on the command socket.

        Protocol (binary, packed):
          Request:  magic(4) cmd_type(1) pad(3) pid(4) uid(4)
                    exe_path(512) subsystem(4) import_count(4)  = 536 bytes
          Response: magic(4) cmd_type(1) verdict(1) pad(2)
                    token_budget(4) capabilities(4) priority(4,signed)
                    deny_reason(256)                            = 276 bytes
        """
        REQUEST_SIZE = 536
        RESPONSE_FMT = "<IBBxxIIi256s"   # 276 bytes
        REQUEST_FMT = "<IB3xII512sII"    # 536 bytes
        CMD_MAGIC = 0x43545843
        CMD_PE_LOAD_REQUEST = 0x01
        CMD_PE_LOAD_RESPONSE = 0x02
        VERDICT_ALLOW = 0
        VERDICT_DENY = 1
        VERDICT_MODIFY = 2

        try:
            data = await asyncio.wait_for(reader.readexactly(REQUEST_SIZE), timeout=2.0)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            writer.close()
            await writer.wait_closed()
            return

        # Parse the request
        try:
            (magic, cmd_type, pid, uid, exe_path_raw,
             subsystem, import_count) = struct.unpack(REQUEST_FMT, data)
        except struct.error:
            writer.close()
            await writer.wait_closed()
            return

        if magic != CMD_MAGIC or cmd_type != CMD_PE_LOAD_REQUEST:
            writer.close()
            await writer.wait_closed()
            return

        # Decode exe path (null-terminated within 512-byte field)
        exe_path = exe_path_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

        logger.info(
            "CMD pe_load_request: pid=%d uid=%d exe=%s subsystem=%d imports=%d",
            pid, uid, exe_path, subsystem, import_count,
        )

        # -- Decision engine (3-tier: policy -> heuristic -> LLM) ---------------

        verdict = VERDICT_ALLOW
        token_budget = 1000
        capabilities = 0xFFFFFFFF
        priority = 0
        deny_reason = b""

        # Build a lightweight event for the DecisionEngine (duck-typed)
        if self._decision_engine is not None:
            from .event_bus import SourceLayer as _SL, PeEventType as _PE
            _cmd_event = type("_CmdEvent", (), {
                "source_layer": int(_SL.RUNTIME),
                "event_type": int(_PE.LOAD),
                "pid": pid,
                "subject_id": 0,
                "payload": {"exe_path": exe_path, "subsystem": subsystem},
            })()
            try:
                engine_result = self._decision_engine.evaluate(_cmd_event)
                if engine_result.verdict == Verdict.DENY:
                    verdict = VERDICT_DENY
                    deny_reason = engine_result.reason.encode("utf-8")[:255]
                    logger.warning(
                        "CMD DecisionEngine DENY: pid=%d reason=%s",
                        pid, engine_result.reason,
                    )
                elif engine_result.verdict == Verdict.QUARANTINE:
                    verdict = VERDICT_DENY
                    deny_reason = engine_result.reason.encode("utf-8")[:255]
                    self._orchestrator.freeze_process(pid, force=True)
                    logger.warning(
                        "CMD DecisionEngine QUARANTINE: pid=%d reason=%s",
                        pid, engine_result.reason,
                    )
                elif engine_result.verdict == Verdict.MODIFY and engine_result.modifications:
                    verdict = VERDICT_MODIFY
                    token_budget = engine_result.modifications.get(
                        "token_budget", token_budget,
                    )
                    capabilities = engine_result.modifications.get(
                        "capabilities", capabilities,
                    )
            except Exception as exc:
                logger.error("CMD DecisionEngine error: %s", exc)

        # Consult autonomy controller (only if engine did not already deny)
        if verdict != VERDICT_DENY:
            decision = self._autonomy.create_decision(
                Domain.PE_EXECUTION, "pe_load_cmd",
                f"PE load request: pid={pid} exe={exe_path}",
            )

            if decision.approved is False:
                # Autonomy says no (only at FULL_MANUAL level with explicit deny)
                verdict = VERDICT_DENY
                deny_reason = b"Autonomy controller denied PE execution"
            elif decision.approved is None:
                # Pending -- we cannot block indefinitely, allow with tight budget
                verdict = VERDICT_MODIFY
                token_budget = 200
                capabilities = 0x0000FFFF  # Restricted capabilities
            else:
                # Approved -- check trust history for budget suggestion
                if self._trust_history and exe_path:
                    history = self._trust_history.record_start(exe_path)
                    if history.suggested_token_budget is not None:
                        token_budget = history.suggested_token_budget
                    if history.quarantines > 0:
                        # Previously quarantined: deny
                        verdict = VERDICT_DENY
                        deny_reason = (
                            f"Previously quarantined ({history.quarantines} times)"
                        ).encode("utf-8")[:255]
                    elif history.reliability < 0.3 and history.total_runs >= 3:
                        # Unreliable binary: allow but restrict
                        verdict = VERDICT_MODIFY
                        token_budget = min(token_budget, 300)
                        capabilities = 0x0000FFFF

                # Check kernel trust score if available
                score_result = self._orchestrator.trust_get_score(pid)
                if score_result.get("success") and score_result.get("score", 50) < 10:
                    verdict = VERDICT_DENY
                    deny_reason = b"Trust score critically low"

                # Native subsystem (driver) gets restricted by default
                if subsystem == 1 and verdict == VERDICT_ALLOW:
                    decision_drv = self._autonomy.create_decision(
                        Domain.SECURITY, "driver_load_cmd",
                        f"Native/driver PE: pid={pid} exe={exe_path}",
                    )
                    if not decision_drv.approved:
                        verdict = VERDICT_DENY
                        deny_reason = b"Driver loading requires explicit approval"

        # -- Build and send response ------------------------------------------

        deny_reason_padded = deny_reason[:255].ljust(256, b"\x00")
        response = struct.pack(
            RESPONSE_FMT,
            CMD_MAGIC,
            CMD_PE_LOAD_RESPONSE,
            verdict,
            token_budget,
            capabilities,
            priority,
            deny_reason_padded,
        )

        verdict_names = {VERDICT_ALLOW: "ALLOW", VERDICT_DENY: "DENY", VERDICT_MODIFY: "MODIFY"}
        logger.info(
            "CMD pe_load_response: pid=%d verdict=%s budget=%d caps=0x%08x",
            pid, verdict_names.get(verdict, "?"), token_budget, capabilities,
        )

        try:
            writer.write(response)
            await writer.drain()
        except ConnectionError:
            pass
        finally:
            writer.close()
            await writer.wait_closed()


# ---------------------------------------------------------------------------
# Wire handlers to the event bus
# ---------------------------------------------------------------------------

def register_handlers(bus: EventBus, handlers: CortexHandlers) -> None:
    """Register all event handlers on the bus."""

    # PE Runtime events
    bus.on(SourceLayer.RUNTIME, PeEventType.LOAD, handlers.handle_pe_load)
    bus.on(SourceLayer.RUNTIME, PeEventType.EXIT, handlers.handle_pe_exit)
    bus.on(SourceLayer.RUNTIME, PeEventType.EXCEPTION, handlers.handle_pe_exception)
    bus.on(SourceLayer.RUNTIME, PeEventType.TRUST_DENY, handlers.handle_pe_trust_deny)
    bus.on(SourceLayer.RUNTIME, PeEventType.TRUST_ESCALATE, handlers.handle_pe_trust_escalate)

    # Trust kernel events
    bus.on(SourceLayer.KERNEL, TrustEventType.IMMUNE_ALERT, handlers.handle_trust_alert)
    bus.on(SourceLayer.KERNEL, TrustEventType.QUARANTINE, handlers.handle_trust_quarantine)
    bus.on(SourceLayer.KERNEL, TrustEventType.TOKEN_STARVE, handlers.handle_trust_token_starve)
    bus.on(SourceLayer.KERNEL, TrustEventType.SCORE_CHANGE, handlers.handle_trust_score_change)

    # Service events
    bus.on(SourceLayer.SCM, SvcEventType.CRASH, handlers.handle_service_crash)
    bus.on(SourceLayer.SCM, SvcEventType.DEPENDENCY_FAIL, handlers.handle_service_dependency_fail)

    # Memory subsystem events (from TMS / pattern scanner)
    bus.on(SourceLayer.RUNTIME, PeEventType.MEMORY_MAP, handlers.handle_memory_map)
    bus.on(SourceLayer.RUNTIME, PeEventType.MEMORY_ANOMALY, handlers.handle_memory_anomaly)
    bus.on(SourceLayer.RUNTIME, PeEventType.MEMORY_PATTERN, handlers.handle_memory_pattern)
    bus.on(SourceLayer.RUNTIME, PeEventType.MEMORY_PROTECT, handlers.handle_memory_protect)
    bus.on(SourceLayer.RUNTIME, PeEventType.STUB_CALLED, handlers.handle_stub_called)

    # Global audit handler
    bus.on_all(handlers.handle_all)

    logger.info("Registered %d event handlers", bus.stats["handlers_registered"])


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cortex",
        description="AI Cortex -- autonomous brain for AI Arch Linux",
    )
    parser.add_argument(
        "--config", "-c",
        default="/etc/pe-compat/cortex.toml",
        help="Path to cortex configuration (default: /etc/pe-compat/cortex.toml)",
    )
    parser.add_argument(
        "--log-level", "-l",
        default=None,
        help="Override log level (DEBUG, INFO, WARNING, ERROR)",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Log to file in addition to stdout",
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=None,
        help="Override REST API port (default: 8421)",
    )
    parser.add_argument(
        "--no-api",
        action="store_true",
        help="Disable the REST API server",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Command socket server (PE load approval handshake)
# ---------------------------------------------------------------------------

CORTEX_CMD_SOCK = "/run/pe-compat/cortex-cmd.sock"


async def _run_cmd_server(handlers: CortexHandlers) -> asyncio.AbstractServer:
    """Start the command socket server for PE load approval requests.

    Returns the asyncio server object (caller must close on shutdown).
    Creates /run/pe-compat/ if needed and removes stale socket files.
    """
    sock_path = Path(CORTEX_CMD_SOCK)

    # Ensure parent directory exists
    sock_path.parent.mkdir(parents=True, exist_ok=True)

    # Remove stale socket
    if sock_path.exists():
        sock_path.unlink()

    async def _on_connect(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await handlers.handle_cmd_pe_load(reader, writer)
        except Exception:
            logger.exception("Command socket handler error")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_unix_server(_on_connect, path=str(sock_path))

    # Make the socket group-writable so PE loaders in the same group can connect
    try:
        os.chmod(str(sock_path), 0o660)
    except OSError:
        pass

    logger.info("Command socket listening on %s", CORTEX_CMD_SOCK)
    return server


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main(argv: Optional[list[str]] = None) -> None:
    """Cortex main entry point."""
    args = parse_args(argv)

    # Load configuration
    config = CortexConfig.load(args.config)

    # Apply CLI overrides
    log_level = args.log_level or config.log_level
    setup_logging(log_level, args.log_file)

    logger.info("AI Cortex %s starting...", __version__)
    logger.info("Config: %s", args.config)

    # Check root
    if os.geteuid() != 0:
        logger.warning(
            "Cortex should run as root for full control. "
            "Trust device and process signals may not work."
        )

    # -- Create components ---------------------------------------------------

    # Autonomy controller (uses config defaults)
    autonomy_levels = {
        domain: getattr(config.autonomy, domain, 2)
        for domain in ALL_DOMAINS
        if hasattr(config.autonomy, domain)
    }
    autonomy = AutonomyController(
        config_levels=autonomy_levels,
        initial_score=config.initial_trust_score,
    )

    # Orchestrator (ACT layer)
    orchestrator = Orchestrator(
        autonomy=autonomy,
        trust_device=config.trust_device,
        scm_socket=config.scm_socket,
    )

    # Trust history store (persistent per-executable trust records)
    trust_history = TrustHistoryStore()
    logger.info("Trust history: %s", trust_history.stats)

    # Decision engine (DECIDE layer -- policy rules + heuristics + optional LLM)
    decision_engine = DecisionEngine()
    logger.info(
        "Decision engine: %d policy rules, LLM=%s",
        len(decision_engine._policy_rules),
        decision_engine._llm is not None,
    )

    # Event bus (SENSE layer)
    bus = EventBus(socket_path=config.event_socket)

    # Handlers (wire SENSE -> DECIDE -> ACT)
    handlers = CortexHandlers(
        autonomy=autonomy,
        orchestrator=orchestrator,
        trust_history=trust_history,
        decision_engine=decision_engine,
    )
    register_handlers(bus, handlers)

    # Register cortex as trust subject 0
    orchestrator.trust_register_cortex()

    # -- Signal handling ------------------------------------------------------

    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def handle_signal(signum: int) -> None:
        sig_name = signal.Signals(signum).name
        logger.info("Received %s, initiating shutdown...", sig_name)
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, handle_signal, sig)

    # -- Start event bus ------------------------------------------------------

    bus_task = asyncio.create_task(bus.start())
    logger.info("Event bus started on %s", config.event_socket)

    # -- Start command socket (PE load approval) ------------------------------

    cmd_server: Optional[asyncio.AbstractServer] = None
    try:
        cmd_server = await _run_cmd_server(handlers)
    except Exception as exc:
        logger.warning("Command socket failed to start: %s", exc)

    # -- Optional REST API ----------------------------------------------------
    #
    # Bind-before-ready (Session 34):  the cortex REST API must be *actually
    # listening* before we tell systemd READY=1 and before ai-control's
    # cortex-proxy aiohttp session starts issuing requests.  Previously we
    # fired the uvicorn task with `asyncio.create_task(...)` and logged
    # "REST API listening..." immediately -- but uvicorn hadn't yet called
    # `server.started = True` (lifespan.startup + socket bind happens inside
    # `server.serve()` after a few ticks).  On slow hardware (QEMU TCG,
    # cold-boot with a lot of imports) that window is hundreds of ms, which
    # is plenty for the ai-control daemon's startup fanout (dashboard +
    # health checks) to hit ECONNREFUSED and mark cortex as unavailable.
    #
    # Fix mirrors the pattern ai-control/daemon/main.py uses for uvicorn:
    # an asyncio.Event set by _run_api_server() when server.started flips,
    # awaited here with a bounded timeout before we progress to "ready".

    api_task: Optional[asyncio.Task] = None
    api_ready: asyncio.Event = asyncio.Event()
    api_port: int = args.api_port or 8421
    if not args.no_api:
        try:
            from .api import create_cortex_api

            app = create_cortex_api(
                autonomy, orchestrator, handlers, bus, trust_history,
                decision_engine=decision_engine,
            )

            # Start uvicorn in a background task.  The task sets `api_ready`
            # once `server.started` flips to True, i.e. the TCP socket is
            # open and accepting -- not merely "the task was scheduled".
            logger.info("REST API startup: binding 127.0.0.1:%d ...", api_port)
            api_task = asyncio.create_task(
                _run_api_server(app, port=api_port, ready_event=api_ready),
            )
        except ImportError as exc:
            logger.warning("REST API unavailable (missing dependency): %s", exc)
        except Exception as exc:
            logger.warning("REST API failed to start: %s", exc)

    # Gate the READY signal on actual uvicorn bind.  60s is generous --
    # typical cold-boot on a beefy host is <300ms; QEMU TCG + Pentium 4
    # class hardware has been observed at ~3-5s.  If the task already
    # failed (no api_task set), skip the wait entirely and proceed to
    # the degraded-but-running state.  Do NOT sys.exit(): cortex's
    # command socket + event bus are independently useful without the
    # REST surface, and the ai-control daemon treats cortex-proxy failures
    # as degraded JSON rather than fatal.
    if api_task is not None:
        try:
            await asyncio.wait_for(api_ready.wait(), timeout=60.0)
            logger.info("REST API listening on 127.0.0.1:%d (bound)", api_port)
        except asyncio.TimeoutError:
            logger.error(
                "REST API did not bind within 60s on 127.0.0.1:%d; "
                "continuing in degraded mode (cortex-proxy calls from "
                "ai-control will return connection errors until uvicorn "
                "finishes startup).", api_port,
            )
            # Leave api_task running -- uvicorn may still come up late;
            # we just don't block the rest of the cortex startup on it.

    # -- Notify systemd -------------------------------------------------------
    #
    # ai-cortex.service is currently Type=simple (per packages/ai-control-
    # daemon/PKGBUILD).  Under Type=simple, READY=1 is a no-op: systemd
    # considers the service active the moment exec() succeeds.  We still
    # send the notification in case the unit ever gets upgraded to
    # Type=notify -- and to be idempotent with ai-control/daemon/main.py
    # which writes to NOTIFY_SOCKET directly via stdlib sockets.
    #
    # Critical ordering: READY=1 comes AFTER `api_ready.wait()` above so the
    # systemd-visible "active" state (when/if Type=notify) truly means
    # "REST surface is accepting HTTP".

    # Stdlib helper: send any state string to NOTIFY_SOCKET. Mirrors
    # ai-control/daemon/main.py._notify_systemd so cortex has no AUR-only
    # sdnotify dependency for the watchdog path.
    def _notify_systemd(state: str) -> bool:
        notify_sock = os.environ.get("NOTIFY_SOCKET")
        if not notify_sock:
            return False
        try:
            import socket as _sock_mod
            addr = (
                "\x00" + notify_sock[1:]
                if notify_sock.startswith("@") else notify_sock
            )
            _s = _sock_mod.socket(_sock_mod.AF_UNIX, _sock_mod.SOCK_DGRAM)
            try:
                _s.settimeout(2.0)
                _s.connect(addr)
                _s.sendall(state.encode("utf-8"))
                return True
            finally:
                _s.close()
        except OSError as _exc:
            logger.debug("NOTIFY_SOCKET send (%r) failed: %s", state, _exc)
            return False

    try:
        import sdnotify  # type: ignore[import-untyped]
        n = sdnotify.SystemdNotifier()
        n.notify("READY=1")
        logger.info("Sent READY=1 to systemd (Type=notify if configured)")
    except ImportError:
        if _notify_systemd("READY=1"):
            logger.info("Sent READY=1 to systemd via stdlib fallback")

    logger.info(
        "AI Cortex ready. Autonomy ceiling: Level %d (%s). "
        "Trust score: %d. Domains: %s",
        autonomy.ceiling,
        AutonomyLevel(autonomy.ceiling).name,
        autonomy.score,
        ", ".join(
            f"{d}={AutonomyLevel(autonomy.effective_level(d)).name}"
            for d in ALL_DOMAINS
        ),
    )

    # Send startup notification (tracked so it completes before shutdown)
    handlers._track_task(
        orchestrator.notify(
            "AI Cortex Online",
            f"Version {__version__}, autonomy ceiling Level {autonomy.ceiling}",
            "normal",
        )
    )

    # -- Dead-man switch periodic check ----------------------------------------

    async def _interruptible_sleep(seconds: float) -> bool:
        """Sleep that wakes immediately on shutdown.  Returns True if the
        sleep completed (no shutdown), False if shutdown was signalled."""
        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            return True
        return False

    async def _dead_man_check_loop() -> None:
        """Periodically check dead-man switch and prune heuristic state."""
        # Old HW polls less often (cheaper) than new HW.
        interval = 300 if _HW_TIER == "new" else 600
        while not shutdown_event.is_set():
            try:
                # Interruptible sleep -- exits fast on shutdown instead of
                # hanging the tasks.cancel() path for up to 300s.
                if not await _interruptible_sleep(interval):
                    return
                autonomy.check_dead_man_switch()
                # Prune stale heuristic state in the decision engine so it
                # doesn't accumulate entries for long-gone processes.
                decision_engine._prune_heuristic_state()
            except asyncio.CancelledError:
                return
            except Exception:
                logger.exception("Dead-man check failed")

    async def _pending_expiry_loop() -> None:
        """Session 25 follow-through: auto-expire pending decisions that
        have passed their TTL.  Runs every 30s so a 300s TTL results in
        at most ~330s of actual lag before SIGKILL lands on a rejected
        frozen PE process.  Without this, SIGSTOP'd processes would leak
        forever when a human never clicks approve/deny.
        """
        while not shutdown_event.is_set():
            try:
                if not await _interruptible_sleep(30):
                    return
                expired = autonomy.expire_overdue_pending()
                if expired:
                    logger.warning(
                        "Expired %d overdue pending decision(s); reject "
                        "callbacks fired", expired,
                    )
            except asyncio.CancelledError:
                return
            except Exception:
                logger.exception("Pending expiry sweep failed")

    async def _watchdog_heartbeat_loop() -> None:
        """Session 36: periodic WATCHDOG=1 ping.

        Unit file declares WatchdogSec=60, so we ping every 30s (half-interval,
        systemd-recommended). No-op if NOTIFY_SOCKET is unset (non-systemd run
        or Type=simple). Exits on shutdown_event.
        """
        if "NOTIFY_SOCKET" not in os.environ:
            return
        logger.info("Watchdog heartbeat task started (interval=30s)")
        while not shutdown_event.is_set():
            try:
                if not await _interruptible_sleep(30):
                    return
                _notify_systemd("WATCHDOG=1")
            except asyncio.CancelledError:
                return
            except Exception:
                logger.exception("Watchdog heartbeat failed")

    dead_man_task = asyncio.create_task(_dead_man_check_loop())
    expiry_task = asyncio.create_task(_pending_expiry_loop())
    watchdog_task = asyncio.create_task(_watchdog_heartbeat_loop())

    # -- Run until shutdown ---------------------------------------------------

    try:
        await shutdown_event.wait()
    except asyncio.CancelledError:
        pass

    # Notify systemd we're stopping so it stops enforcing WatchdogSec during
    # the graceful shutdown window.
    _notify_systemd("STOPPING=1")

    dead_man_task.cancel()
    try:
        await dead_man_task
    except asyncio.CancelledError:
        pass

    expiry_task.cancel()
    try:
        await expiry_task
    except asyncio.CancelledError:
        pass

    watchdog_task.cancel()
    try:
        await watchdog_task
    except asyncio.CancelledError:
        pass

    # -- Clean shutdown -------------------------------------------------------

    logger.info("Shutting down...")

    # Stop command socket server
    if cmd_server is not None:
        cmd_server.close()
        await cmd_server.wait_closed()
        # Clean up socket file
        try:
            Path(CORTEX_CMD_SOCK).unlink(missing_ok=True)
        except OSError:
            pass
        logger.info("Command socket closed")

    # Stop event bus
    await bus.stop()
    bus_task.cancel()
    try:
        await bus_task
    except asyncio.CancelledError:
        pass

    # Stop API server.  Bound the join-wait so a stuck uvicorn doesn't
    # block shutdown forever (e.g. a request handler hung in a blocking
    # call that ignored the cancel).  Mirrors the pattern ai-control's
    # shutdown uses for its uvicorn task.
    if api_task is not None:
        api_task.cancel()
        try:
            await asyncio.wait_for(api_task, timeout=5.0)
        except asyncio.CancelledError:
            pass
        except asyncio.TimeoutError:
            logger.warning(
                "REST API task did not exit within 5s of cancel; "
                "proceeding with shutdown anyway",
            )

    # Drain pending handler tasks so nothing is lost on shutdown.
    # Snapshot the set BEFORE awaiting so new tasks arriving during the drain
    # don't race the wait() call (done_callback_discard also mutates the set).
    if handlers._pending_tasks:
        pending_snapshot = set(handlers._pending_tasks)
        logger.info("Waiting for %d pending tasks...", len(pending_snapshot))
        done, still_pending = await asyncio.wait(pending_snapshot, timeout=5.0)
        for t in still_pending:
            t.cancel()
        # Give cancelled tasks one tick to process cancellation cleanly so
        # they don't log CancelledError traceback at interpreter exit.
        if still_pending:
            try:
                await asyncio.wait(still_pending, timeout=1.0)
            except Exception:
                logger.debug("Cleanup wait for cancelled tasks failed", exc_info=True)

    # Release trust device
    orchestrator.close()

    logger.info(
        "AI Cortex stopped. Events processed: %d, Actions executed: %d, "
        "DecisionEngine evaluations: %d (verdicts: %s)",
        handlers.events_processed,
        orchestrator.stats["actions_executed"],
        decision_engine.stats["evaluations"],
        decision_engine.stats["verdict_counts"],
    )


async def _run_api_server(
    app: object,
    host: str = "127.0.0.1",
    port: int = 8421,
    ready_event: Optional[asyncio.Event] = None,
) -> None:
    """Run the FastAPI app via uvicorn.

    Args:
        app:         The FastAPI application (from create_cortex_api).
        host:        Bind host. Default 127.0.0.1 (cortex is internal-only --
                     ai-control proxies external access).
        port:        Bind port. Default 8421 (daemon uses 8420).
        ready_event: If provided, is set() once uvicorn.Server.started flips
                     to True, i.e. the socket is bound and lifespan.startup
                     completed.  Callers use this to gate systemd READY=1
                     and to log truthful bind state.  If uvicorn import or
                     startup fails, the event is left unset so callers can
                     time out and proceed in degraded mode.
    """
    try:
        import uvicorn  # type: ignore[import-untyped]

        server_config = uvicorn.Config(
            app,
            host=host,
            port=port,
            log_level="warning",
            access_log=False,
        )
        server = uvicorn.Server(server_config)

        # Signal the ready event when uvicorn has finished startup.  Poll
        # `server.started` (an internal bool flipped after socket bind +
        # lifespan.startup complete).  Typical wait is <500ms on warm
        # disk; in QEMU TCG or heavily loaded hosts it can stretch to
        # several seconds.  The polling interval is deliberately tight
        # (50ms) to minimize the window between "really listening" and
        # "ready_event observed by main()".  This mirrors the pattern
        # ai-control/daemon/api_server.start_server() uses for the
        # outer ai-control REST surface.
        if ready_event is not None:
            async def _signal_when_started() -> None:
                try:
                    # Guard with a wall-clock budget in case server.started
                    # never flips (e.g. lifespan.startup stalls on a bad
                    # route handler). 90s matches uvicorn's own startup
                    # timeout ceiling.
                    deadline = time.time() + 90.0
                    while not getattr(server, "started", False):
                        if time.time() > deadline:
                            logger.error(
                                "uvicorn.Server.started never flipped to True "
                                "within 90s; ready_event will remain unset",
                            )
                            return
                        await asyncio.sleep(0.05)
                    ready_event.set()
                except asyncio.CancelledError:
                    # On shutdown we intentionally don't set the event --
                    # avoids a late-arriving ready signal racing a stop.
                    raise

            # Strong reference — otherwise the GC can collect this task
            # mid-flight (CPython issues a "Task was destroyed but it is
            # pending!" warning, and the ready_event is silently never set,
            # leaving systemd waiting on READY=1 until watchdog timeout).
            _ready_signal_task = asyncio.create_task(_signal_when_started())
        else:
            _ready_signal_task = None

        try:
            await server.serve()
        finally:
            if _ready_signal_task is not None and not _ready_signal_task.done():
                _ready_signal_task.cancel()
                try:
                    await _ready_signal_task
                except (asyncio.CancelledError, Exception):
                    pass
    except ImportError:
        logger.warning("uvicorn not installed -- REST API disabled")
    except asyncio.CancelledError:
        # Cooperative shutdown -- propagate so asyncio.wait() observes it.
        raise
    except Exception:
        # Any other error: log with traceback so startup failures surface
        # in journalctl instead of being silently swallowed by the task.
        logger.exception("REST API server crashed")
