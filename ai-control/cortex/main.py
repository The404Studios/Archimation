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
        self._recent_events: list[dict] = []
        self._pending_tasks: set[asyncio.Task] = set()

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
        if len(self._recent_events) > 200:
            self._recent_events = self._recent_events[-100:]

    @property
    def recent_events(self) -> list[dict]:
        return list(self._recent_events[-100:])

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

        decision = self._autonomy.create_decision(
            Domain.PE_EXECUTION, "pe_load",
            f"PE load: pid={event.pid} subject={event.subject_id}",
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
            # Pending human approval -- freeze the process while waiting
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

        decision = self._autonomy.create_decision(
            Domain.SECURITY, "trust_alert",
            f"Trust immune alert: pid={event.pid} subject={event.subject_id}",
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

    api_task: Optional[asyncio.Task] = None
    if not args.no_api:
        try:
            from .api import create_cortex_api

            api_port = args.api_port or 8421
            app = create_cortex_api(
                autonomy, orchestrator, handlers, bus, trust_history,
                decision_engine=decision_engine,
            )

            # Start uvicorn in a background task
            api_task = asyncio.create_task(
                _run_api_server(app, port=api_port)
            )
            logger.info("REST API listening on 127.0.0.1:%d", api_port)
        except ImportError as exc:
            logger.warning("REST API unavailable (missing dependency): %s", exc)
        except Exception as exc:
            logger.warning("REST API failed to start: %s", exc)

    # -- Notify systemd -------------------------------------------------------

    try:
        import sdnotify  # type: ignore[import-untyped]
        n = sdnotify.SystemdNotifier()
        n.notify("READY=1")
    except ImportError:
        pass

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

    async def _dead_man_check_loop() -> None:
        """Periodically check dead-man switch and prune heuristic state."""
        while not shutdown_event.is_set():
            try:
                await asyncio.sleep(300)  # Check every 5 minutes
                autonomy.check_dead_man_switch()
                # Prune stale heuristic state in the decision engine so it
                # doesn't accumulate entries for long-gone processes.
                decision_engine._prune_heuristic_state()
            except Exception:
                logger.exception("Dead-man check failed")

    dead_man_task = asyncio.create_task(_dead_man_check_loop())

    # -- Run until shutdown ---------------------------------------------------

    try:
        await shutdown_event.wait()
    except asyncio.CancelledError:
        pass

    dead_man_task.cancel()
    try:
        await dead_man_task
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

    # Stop API server
    if api_task is not None:
        api_task.cancel()
        try:
            await api_task
        except asyncio.CancelledError:
            pass

    # Drain pending handler tasks so nothing is lost on shutdown
    if handlers._pending_tasks:
        logger.info("Waiting for %d pending tasks...", len(handlers._pending_tasks))
        done, _ = await asyncio.wait(handlers._pending_tasks, timeout=5.0)
        for t in handlers._pending_tasks - done:
            t.cancel()

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


async def _run_api_server(app: object, host: str = "127.0.0.1", port: int = 8421) -> None:
    """Run the FastAPI app via uvicorn."""
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
        await server.serve()
    except ImportError:
        logger.warning("uvicorn not installed -- REST API disabled")
    except asyncio.CancelledError:
        pass
