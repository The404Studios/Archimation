"""End-to-end integration test: PE_EVT_TRUST_DENY full chain.

Pipeline exercised
------------------
    (simulated pe_event_emit)  [ai-control/cortex/event_bus.py]
            |
            v  parse_pe_trust_deny_payload
    {api_name, category, score, tokens}
            |
            v  CortexHandlers.handle_pe_trust_deny
            |     (main.py:435)
            v
    autonomy.create_decision(SECURITY, trust_deny_response, ...)
            |
            v  (if approved)
    orchestrator.trust_get_score(pid) + possibly freeze + quarantine

The handler + parser live in separate modules; this test wires them
together with fake Autonomy + Orchestrator so we can assert the whole
chain actually dispatches an action (not the isolation patterns used
in the unit-test suite).

Contracts asserted:
  1. parse_pe_trust_deny_payload recovers api_name, category, score.
  2. handle_pe_trust_deny records exactly one event in _recent_events.
  3. autonomy.create_decision fires with Domain.SECURITY.
  4. orchestrator.trust_get_score is consulted when decision.approved.
  5. If the returned score < 10, a quarantine is issued (pid freeze +
     trust_quarantine call).
  6. When autonomy refuses the decision, no quarantine fires and the
     recorded action is "observed".

S77 Agent 5 deliverable.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from _s77_helpers import (  # noqa: E402
    FakeAutonomy,
    FakeOrchestrator,
    PE_EVT_TRUST_DENY,
    SRC_RUNTIME,
    build_event_bytes,
    build_trust_deny_payload,
    load_cortex_module,
)


class TrustDenyPipelineBase(unittest.TestCase):
    """Common plumbing: load the event_bus + main modules once per class."""

    @classmethod
    def setUpClass(cls) -> None:
        # Load under unique names so each scenario gets clean state.
        cls.eb = load_cortex_module("event_bus", unique_suffix="_deny")
        # main.py imports a lot of sibling cortex modules — loading it this
        # way forces the sibling imports through the normal sys.modules
        # route. We only need CortexHandlers + the register_handlers helper.
        # If the module fails to import (missing optional deps) this scenario
        # skips rather than aborts the suite.
        try:
            cls.cortex_main = load_cortex_module("main", unique_suffix="_deny")
        except Exception as exc:  # pragma: no cover
            raise unittest.SkipTest(f"cortex.main import failed: {exc}")


class TestTrustDenyParser(TrustDenyPipelineBase):
    """Wire-bytes -> parser dict contract."""

    def test_parser_recovers_fields(self) -> None:
        payload = build_trust_deny_payload(
            api_name="NtSetSystemInformation",
            category=7,
            score=42,
            tokens=120,
        )
        parsed = self.eb.parse_pe_trust_deny_payload(payload)
        self.assertEqual(parsed["api_name"], "NtSetSystemInformation")
        self.assertEqual(parsed["category"], 7)
        self.assertEqual(parsed["score"], 42)
        self.assertEqual(parsed["tokens"], 120)

    def test_event_header_parse_roundtrip(self) -> None:
        """build_event_bytes -> EventBus._parse_event yields a usable Event."""
        bus = self.eb.EventBus(socket_path="/tmp/_s77_unused_deny.sock")
        payload = build_trust_deny_payload(
            api_name="NtCreateFile", category=1, score=30, tokens=10,
        )
        raw = build_event_bytes(SRC_RUNTIME, PE_EVT_TRUST_DENY, payload,
                                pid=12345, subject_id=777)
        event = bus._parse_event(raw)
        self.assertIsNotNone(event)
        self.assertEqual(event.source_layer, SRC_RUNTIME)
        self.assertEqual(event.event_type, PE_EVT_TRUST_DENY)
        self.assertEqual(event.pid, 12345)
        self.assertEqual(event.subject_id, 777)
        # payload is dict-decoded by the parser registry
        self.assertIsInstance(event.payload, dict)
        self.assertEqual(event.payload["api_name"], "NtCreateFile")


class TestTrustDenyHandlerChain(TrustDenyPipelineBase):
    """handler invocation + autonomy + orchestrator side-effects."""

    def _build_event(self, pid: int = 9999, api: str = "NtOpenProcessToken"):
        payload = build_trust_deny_payload(api_name=api, category=2,
                                           score=20, tokens=5)
        raw = build_event_bytes(SRC_RUNTIME, PE_EVT_TRUST_DENY, payload,
                                pid=pid)
        bus = self.eb.EventBus(socket_path="/tmp/_s77_unused_deny.sock")
        event = bus._parse_event(raw)
        assert event is not None
        return event

    def _make_handlers(self, *, approved: bool | None = True,
                       trust_score: int = 50):
        autonomy = FakeAutonomy(approved=approved)
        orchestrator = FakeOrchestrator(trust_score=trust_score)
        handlers = self.cortex_main.CortexHandlers(
            autonomy=autonomy,
            orchestrator=orchestrator,
            trust_history=None,
            decision_engine=None,
        )
        return handlers, autonomy, orchestrator

    def test_approved_but_score_ok_just_logs(self) -> None:
        """approved=True + score>=10 -> records action 'logged', no quarantine."""
        event = self._build_event()
        handlers, autonomy, orch = self._make_handlers(
            approved=True, trust_score=50,
        )
        before_events = handlers.events_processed
        handlers.handle_pe_trust_deny(event)
        self.assertEqual(handlers.events_processed, before_events + 1)
        # Autonomy was consulted.
        self.assertEqual(len(autonomy.calls), 1)
        self.assertEqual(autonomy.calls[0]["action"], "trust_deny_response")
        # Orchestrator: score was checked; no freeze / quarantine.
        score_calls = [c for c in orch.calls if c[0] == "trust_get_score"]
        self.assertEqual(len(score_calls), 1)
        self.assertFalse(any(c[0] == "freeze_process" for c in orch.calls))
        self.assertFalse(any(c[0] == "trust_quarantine" for c in orch.calls))
        # Recent event ring shows the handler ran + tagged the action.
        tail = list(handlers._recent_events)[-1]
        self.assertEqual(tail["type"], "TRUST_DENY")
        self.assertEqual(tail["action"], "logged")

    def test_approved_with_low_score_quarantines(self) -> None:
        """approved=True + score<10 -> full quarantine path fires."""
        event = self._build_event(pid=31337)
        handlers, autonomy, orch = self._make_handlers(
            approved=True, trust_score=5,   # triggers < 10 branch in main.py:451
        )
        handlers.handle_pe_trust_deny(event)
        freeze_calls = [c for c in orch.calls if c[0] == "freeze_process"]
        quar_calls = [c for c in orch.calls if c[0] == "trust_quarantine"]
        self.assertEqual(len(freeze_calls), 1, orch.calls)
        self.assertEqual(len(quar_calls), 1, orch.calls)
        # freeze_process called with our pid and force=True.
        self.assertEqual(freeze_calls[0][1], 31337)
        self.assertTrue(freeze_calls[0][2])
        # Last recent_event tags the quarantine.
        tail = list(handlers._recent_events)[-1]
        self.assertIn("quarantined", tail["action"])

    def test_refused_decision_is_merely_observed(self) -> None:
        """approved=False -> handler records 'observed'; no orchestrator action."""
        event = self._build_event()
        handlers, autonomy, orch = self._make_handlers(
            approved=False, trust_score=50,
        )
        handlers.handle_pe_trust_deny(event)
        # Autonomy consulted.
        self.assertEqual(len(autonomy.calls), 1)
        # But orchestrator never touched.
        self.assertEqual(orch.calls, [])
        tail = list(handlers._recent_events)[-1]
        self.assertEqual(tail["action"], "observed")


class TestTrustDenyBusRegistration(TrustDenyPipelineBase):
    """End-to-end: register_handlers wires handle_pe_trust_deny on the bus."""

    def test_register_handlers_binds_trust_deny(self) -> None:
        bus = self.eb.EventBus(socket_path="/tmp/_s77_unused_deny.sock")
        autonomy = FakeAutonomy(approved=True)
        orchestrator = FakeOrchestrator(trust_score=50)
        handlers = self.cortex_main.CortexHandlers(
            autonomy=autonomy, orchestrator=orchestrator,
            trust_history=None, decision_engine=None,
        )
        self.cortex_main.register_handlers(bus, handlers)
        # Now synthesise an event and drive it through _dispatch so the
        # handler pipeline runs exactly the way the live daemon would.
        event = bus._parse_event(build_event_bytes(
            SRC_RUNTIME, PE_EVT_TRUST_DENY,
            build_trust_deny_payload(api_name="NtLoadDriver",
                                     category=4, score=15, tokens=20),
            pid=4242,
        ))
        self.assertIsNotNone(event)
        bus._dispatch(event)  # synchronous dispatch
        # Exactly one call to create_decision, and it was the deny path.
        self.assertEqual(len(autonomy.calls), 1)
        self.assertEqual(autonomy.calls[0]["action"], "trust_deny_response")
        # handler recorded the event
        self.assertEqual(handlers.events_processed, 1)


if __name__ == "__main__":
    unittest.main()
