"""S79 Test Agent 4 — PE event -> cortex parser -> handler -> orchestrator.

Pipeline exercised (multi-step, cross-component)
-------------------------------------------------
    build_*_payload  (pe-loader wire bytes, _s79_helpers)
          |
          v  EventBus._parse_event (cortex/event_bus.py:504)
    Event dataclass with parsed dict payload
          |
          v  EventBus._dispatch (event_bus.py:552)  --or-- direct handler call
    CortexHandlers.handle_pe_*  (cortex/main.py)
          |
          +--> autonomy.create_decision      (FakeAutonomy)
          +--> orchestrator.*                (FakeOrchestrator)
          +--> _record_event ring            (asserted via _recent_events)

This file extends the S77 suite (test_pe_trust_deny_e2e /
test_pe_trust_escalate_e2e) with the OTHER PeEventType values that
register_handlers wires on the bus (main.py:929-934, :946-950):

  * PE_EVT_LOAD           -> handle_pe_load
  * PE_EVT_DLL_LOAD       -> NO HANDLER (silent skip verified)
  * PE_EVT_EXCEPTION      -> handle_pe_exception (records event)
  * PE_EVT_TRUST_DENY     -> covered by S77, re-asserted with reason_name flow
  * PE_EVT_TRUST_ESCALATE with reason_name=privilege_adjust

Mock boundaries (documented per test):
  * No /run/pe-compat/events.sock — we build bytes and call _parse_event
    directly, skipping the recvfrom() path entirely.
  * FakeAutonomy + FakeOrchestrator from _s77_helpers mock the DECIDE/ACT
    sides. Real AutonomyController needs a shared-secret file + score
    bookkeeping; real Orchestrator opens /dev/trust.
  * _trust_history=None and _decision_engine=None on CortexHandlers mean
    _check_decision_engine early-returns None (main.py:217-218) and the
    autonomy branch exercises uncontested.
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
    PE_EVT_TRUST_ESCALATE,
    SRC_RUNTIME,
    build_event_bytes,
    build_trust_deny_payload,
    build_trust_escalate_payload,
    load_cortex_module,
)
from _s79_helpers import (  # noqa: E402
    PE_EVT_DLL_LOAD,
    PE_EVT_EXCEPTION,
    PE_EVT_LOAD,
    build_pe_dll_load_payload,
    build_pe_exception_payload,
    build_pe_load_payload,
)


class PeFullLoopBase(unittest.TestCase):
    """Shared module loads + handler builder."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.eb = load_cortex_module("event_bus", unique_suffix="_s79_pe")
        try:
            cls.cortex_main = load_cortex_module(
                "main", unique_suffix="_s79_pe",
            )
        except Exception as exc:  # pragma: no cover
            raise unittest.SkipTest(f"cortex.main import failed: {exc}")

    def _make_bus(self, tag: str):
        return self.eb.EventBus(socket_path=f"/tmp/_s79_{tag}.sock")

    def _make_handlers(self, *, approved: bool | None = True,
                       trust_score: int = 50):
        autonomy = FakeAutonomy(approved=approved)
        orchestrator = FakeOrchestrator(trust_score=trust_score)
        handlers = self.cortex_main.CortexHandlers(
            autonomy=autonomy, orchestrator=orchestrator,
            trust_history=None, decision_engine=None,
        )
        return handlers, autonomy, orchestrator


class TestPeLoadFullLoop(PeFullLoopBase):
    """PE_EVT_LOAD -> parse -> handle_pe_load -> autonomy + score check."""

    def test_pe_load_parses_and_invokes_autonomy(self) -> None:
        """Wire bytes for PE_EVT_LOAD get parsed into {exe_path, trust_score,
        token_budget, ...} and the handler calls autonomy.create_decision
        with Domain.PE_EXECUTION + "pe_load" action (main.py:297)."""
        bus = self._make_bus("load_parse")
        payload = build_pe_load_payload(
            exe_path="C:\\Program Files\\Demo\\app.exe",
            imports_resolved=42, imports_unresolved=0,
            trust_score=50, token_budget=1000,
        )
        raw = build_event_bytes(SRC_RUNTIME, PE_EVT_LOAD, payload, pid=4242)
        event = bus._parse_event(raw)
        self.assertIsNotNone(event)
        # Parser routed through dispatch table.
        self.assertIsInstance(event.payload, dict)
        self.assertEqual(event.payload["exe_path"],
                         "C:\\Program Files\\Demo\\app.exe")
        self.assertEqual(event.payload["imports_resolved"], 42)
        self.assertEqual(event.payload["trust_score"], 50)

        handlers, autonomy, orch = self._make_handlers(
            approved=True, trust_score=50,
        )
        handlers.handle_pe_load(event)
        # Autonomy was consulted with PE_EXECUTION domain.
        self.assertEqual(len(autonomy.calls), 1)
        self.assertEqual(autonomy.calls[0]["action"], "pe_load")
        # Orchestrator.trust_get_score was consulted (main.py:324).
        self.assertTrue(any(c[0] == "trust_get_score" for c in orch.calls))
        # Ring shows the handler ran.
        self.assertEqual(handlers.events_processed, 1)

    def test_pe_load_approved_low_score_restricts_budget(self) -> None:
        """approved=True + kernel score<30 -> action contains "restricted
        budget" (main.py:325-330). Pins the low-trust branch in isolation.

        Mock boundary: ``handle_pe_load`` calls
        ``orchestrator.trust_get_balance(pid)`` which FakeOrchestrator does
        not implement (it's in _s77_helpers and covered the deny/escalate
        codepaths only). We stitch a no-op onto the fake at test time so
        the codepath survives."""
        bus = self._make_bus("load_lowscore")
        payload = build_pe_load_payload(exe_path="suspicious.exe",
                                        trust_score=20)
        raw = build_event_bytes(SRC_RUNTIME, PE_EVT_LOAD, payload, pid=777)
        event = bus._parse_event(raw)
        handlers, _autonomy, orch = self._make_handlers(
            approved=True, trust_score=5,  # very low, triggers <30 branch
        )
        # Stitch trust_get_balance onto the fake (not in _s77_helpers).
        def _fake_get_balance(pid):
            orch.calls.append(("trust_get_balance", pid))
            return {"success": True, "tokens": 100}
        orch.trust_get_balance = _fake_get_balance

        handlers.handle_pe_load(event)
        tail = list(handlers._recent_events)[-1]
        self.assertIn("restricted budget", tail["action"])

    def test_pe_load_pending_freezes_process(self) -> None:
        """approved=None (pending) -> orchestrator.freeze_process called
        and notify_decision scheduled (main.py:343-347). Mock boundary:
        no async loop, so notify_decision call is captured as a
        pre-await coroutine; FakeOrchestrator surfaces it as a pending
        task. Because CortexHandlers._track_task needs a running loop,
        we wrap in asyncio.run to make the test self-contained."""
        import asyncio

        bus = self._make_bus("load_pending")
        payload = build_pe_load_payload(exe_path="pending.exe")
        raw = build_event_bytes(SRC_RUNTIME, PE_EVT_LOAD, payload, pid=888)
        event = bus._parse_event(raw)
        handlers, _a, orch = self._make_handlers(approved=None)

        async def _drive() -> None:
            handlers.handle_pe_load(event)
            # Give the scheduled notify_decision task a tick to complete.
            await asyncio.sleep(0)

        asyncio.run(_drive())
        # freeze_process was called while pending.
        freeze_calls = [c for c in orch.calls if c[0] == "freeze_process"]
        self.assertEqual(len(freeze_calls), 1, orch.calls)


class TestPeDllLoadNoHandler(PeFullLoopBase):
    """PE_EVT_DLL_LOAD currently has NO cortex-side handler registered
    (main.py:929-934 binds LOAD/EXIT/EXCEPTION/TRUST_DENY/TRUST_ESCALATE but
    not DLL_LOAD). This is a REPORT-only finding: the event type emits from
    pe-loader but cortex drops it on the floor (silently; global on_all
    handler still logs at DEBUG).

    We pin the current behavior so a future maintainer who adds a handler
    will see this test need updating — at which point the behavior has
    changed in a way worth knowing about."""

    def test_dll_load_parses_but_no_handler_bound(self) -> None:
        """bus._parse_event routes through parse_pe_dll_load_payload; the
        dict is populated. But register_handlers never calls bus.on(...) for
        DLL_LOAD — so the type_handlers list at event_bus.py:568 is empty.
        bus._dispatch thus runs global handlers only and returns without
        raising."""
        bus = self._make_bus("dll_load_nohandler")
        payload = build_pe_dll_load_payload(dll_name="user32.dll",
                                            resolved=20, unresolved=2)
        raw = build_event_bytes(SRC_RUNTIME, PE_EVT_DLL_LOAD, payload,
                                pid=1234)
        event = bus._parse_event(raw)
        self.assertIsNotNone(event)
        self.assertEqual(event.payload["dll_name"], "user32.dll")
        self.assertEqual(event.payload["resolved"], 20)

        # Register handlers; DLL_LOAD is intentionally absent.
        handlers, autonomy, orch = self._make_handlers()
        self.cortex_main.register_handlers(bus, handlers)

        # Dispatch is silent: no handler, no autonomy consult, no crash.
        bus._dispatch(event)
        self.assertEqual(len(autonomy.calls), 0,
                         "DLL_LOAD must not invoke autonomy (no handler)")
        # Global on_all still runs -> handle_all is a pure logger, makes no
        # changes to events_processed (it doesn't call _record_event).
        self.assertEqual(handlers.events_processed, 0)


class TestPeTrustDenyQuarantineFlow(PeFullLoopBase):
    """PE_EVT_TRUST_DENY with score<10 -> full quarantine flow.

    This cross-component scenario fires:
        1. parse_pe_trust_deny_payload
        2. handle_pe_trust_deny (main.py:435)
        3. autonomy.create_decision (SECURITY domain)
        4. orchestrator.trust_get_score
        5. [branch] score<10 -> freeze_process + trust_quarantine
    """

    def test_deny_cascade_low_score_triggers_quarantine(self) -> None:
        bus = self._make_bus("deny_quar")
        payload = build_trust_deny_payload(
            api_name="NtLoadDriver", category=4, score=5, tokens=1,
        )
        raw = build_event_bytes(SRC_RUNTIME, PE_EVT_TRUST_DENY, payload,
                                pid=31337)
        event = bus._parse_event(raw)
        handlers, autonomy, orch = self._make_handlers(
            approved=True, trust_score=5,  # pushes <10 branch
        )
        handlers.handle_pe_trust_deny(event)
        # Full quarantine flow: trust_get_score, freeze_process, trust_quarantine.
        names = [c[0] for c in orch.calls]
        self.assertIn("trust_get_score", names)
        self.assertIn("freeze_process", names)
        self.assertIn("trust_quarantine", names)
        tail = list(handlers._recent_events)[-1]
        self.assertEqual(tail["type"], "TRUST_DENY")
        self.assertIn("quarantined", tail["action"])


class TestPeTrustEscalateReasonFlow(PeFullLoopBase):
    """PE_EVT_TRUST_ESCALATE with reason=4 (privilege_adjust) goes through
    full parser -> handler chain, and the handler logs the reason name so
    downstream routing can discriminate on cause (S78 Dev C)."""

    def test_escalate_privilege_adjust_approved(self) -> None:
        bus = self._make_bus("esc_priv")
        payload = build_trust_escalate_payload(
            api_name="NtAdjustPrivilegesToken",
            from_score=50, to_score=80, reason=4,  # privilege_adjust
        )
        raw = build_event_bytes(SRC_RUNTIME, PE_EVT_TRUST_ESCALATE, payload,
                                pid=5555)
        event = bus._parse_event(raw)
        self.assertIsNotNone(event)
        # S78 Dev C reason_name field present.
        self.assertEqual(event.payload["reason_name"], "privilege_adjust")

        handlers, autonomy, orch = self._make_handlers(approved=True)
        handlers.handle_pe_trust_escalate(event)
        # Autonomy invoked with the trust_escalate_request action.
        self.assertEqual(len(autonomy.calls), 1)
        self.assertEqual(autonomy.calls[0]["action"],
                         "trust_escalate_request")
        tail = list(handlers._recent_events)[-1]
        self.assertEqual(tail["action"], "escalation_approved")


class TestPeExceptionHandler(PeFullLoopBase):
    """PE_EVT_EXCEPTION -> handle_pe_exception records + warns (no
    autonomy call). The handler is minimal but its presence closes a
    Layer-2 -> Layer-4 observability gap.

    Mock boundary: parse_payload has NO registered parser for EXCEPTION
    so event.payload stays as raw bytes. The handler does not introspect
    the payload; it just records + logs.
    """

    def test_exception_records_event(self) -> None:
        bus = self._make_bus("excp")
        raw = build_event_bytes(SRC_RUNTIME, PE_EVT_EXCEPTION,
                                build_pe_exception_payload(), pid=9999)
        event = bus._parse_event(raw)
        self.assertIsNotNone(event)
        handlers, autonomy, orch = self._make_handlers()
        handlers.handle_pe_exception(event)
        # Autonomy NOT consulted (exception is not a decision event).
        self.assertEqual(len(autonomy.calls), 0)
        # Event got recorded with "recorded" action (main.py:395).
        self.assertEqual(handlers.events_processed, 1)
        tail = list(handlers._recent_events)[-1]
        self.assertEqual(tail["type"], "EXCEPTION")
        self.assertEqual(tail["action"], "recorded")


class TestBusRegistrationAllPe(PeFullLoopBase):
    """register_handlers binds all five PE event types on the bus."""

    def test_register_handlers_binds_all_pe_types(self) -> None:
        """Spot-check that the handler dict in EventBus has entries for
        LOAD, EXIT, EXCEPTION, TRUST_DENY, TRUST_ESCALATE. Not DLL_LOAD —
        see TestPeDllLoadNoHandler."""
        bus = self._make_bus("binding_check")
        handlers, _a, _o = self._make_handlers()
        self.cortex_main.register_handlers(bus, handlers)
        runtime_handlers = bus._handlers.get(SRC_RUNTIME, {})
        # Expect all five PE handlers + 4 memory handlers + STUB_CALLED.
        PE_EVT_EXIT = 0x05
        expected_types = {
            PE_EVT_LOAD, PE_EVT_EXCEPTION, PE_EVT_EXIT,
            PE_EVT_TRUST_DENY, PE_EVT_TRUST_ESCALATE,
        }
        for t in expected_types:
            self.assertIn(t, runtime_handlers,
                          f"type 0x{t:02x} not registered on RUNTIME")
            self.assertTrue(runtime_handlers[t],
                            f"type 0x{t:02x} registered but empty handler list")
        # And DLL_LOAD is INTENTIONALLY unregistered today.
        self.assertNotIn(PE_EVT_DLL_LOAD, runtime_handlers,
                         "DLL_LOAD unexpectedly acquired a handler — "
                         "update TestPeDllLoadNoHandler accordingly")


if __name__ == "__main__":
    unittest.main()
