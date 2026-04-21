"""S79 Test Agent 4 — TrustEventType -> CortexHandlers dispatch chain.

Pipeline exercised (kernel-layer -> cortex):
  TrustEventType wire (source=SRC_KERNEL=0)
      -> EventBus.on(KERNEL, <TrustEventType>, handler)     [main.py:935-939]
      -> bus._dispatch(event)
      -> CortexHandlers.handle_trust_*

Four trust event types have handlers today:
  * IMMUNE_ALERT (0x03)  -> handle_trust_alert
  * QUARANTINE   (0x04)  -> handle_trust_quarantine
  * TOKEN_STARVE (0x02)  -> handle_trust_token_starve
  * SCORE_CHANGE (0x01)  -> handle_trust_score_change
APOPTOSIS (0x05) and TRC_CHANGE (0x06) are declared in the enum but have
NO handler registered (main.py:935-939) — REPORT-only producer-without-
consumer gap.

Mock boundaries:
  * No trust.ko / /dev/trust: we build synthetic 64-byte headers with
    empty payload bytes (trust events don't have payload parsers, so
    event.payload stays as raw bytes and the handlers read event.pid /
    event.subject_id only).
  * FakeAutonomy/FakeOrchestrator from _s77_helpers.
  * handle_trust_alert has an async notify_decision path when
    approved=None — we wrap in asyncio.run to exercise it.
"""

from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from _s77_helpers import (  # noqa: E402
    FakeAutonomy,
    FakeOrchestrator,
    SRC_KERNEL,
    build_event_bytes,
    load_cortex_module,
)
from _s79_helpers import (  # noqa: E402
    TRUST_EVT_APOPTOSIS,
    TRUST_EVT_IMMUNE_ALERT,
    TRUST_EVT_QUARANTINE,
    TRUST_EVT_SCORE_CHANGE,
    TRUST_EVT_TOKEN_STARVE,
)


def _empty_payload() -> bytes:
    """Trust events have no registered parser in event_bus.py, so any
    non-empty byte buffer survives as raw_payload. 16 bytes is enough."""
    return b"\x00" * 16


class TrustDispatchBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.eb = load_cortex_module("event_bus", unique_suffix="_s79_trust")
        try:
            cls.cortex_main = load_cortex_module(
                "main", unique_suffix="_s79_trust",
            )
        except Exception as exc:  # pragma: no cover
            raise unittest.SkipTest(f"cortex.main import failed: {exc}")

    def _make_event(self, event_type: int, *, pid: int = 4242,
                    subject_id: int = 55):
        bus = self.eb.EventBus(socket_path="/tmp/_s79_trust.sock")
        raw = build_event_bytes(SRC_KERNEL, event_type, _empty_payload(),
                                pid=pid, subject_id=subject_id)
        event = bus._parse_event(raw)
        assert event is not None
        return event

    def _make_handlers(self, *, approved: bool | None = True):
        autonomy = FakeAutonomy(approved=approved)
        orchestrator = FakeOrchestrator(trust_score=50)
        handlers = self.cortex_main.CortexHandlers(
            autonomy=autonomy, orchestrator=orchestrator,
            trust_history=None, decision_engine=None,
        )
        return handlers, autonomy, orchestrator


class TestImmuneAlertDispatch(TrustDispatchBase):
    """TrustEventType.IMMUNE_ALERT -> handle_trust_alert full chain."""

    def test_alert_approved_quarantines_and_notifies(self) -> None:
        """approved=True -> freeze_process(force=True) + trust_quarantine
        + notify (main.py:502-519). The notify call is async, so we
        drive through asyncio.run."""
        event = self._make_event(TRUST_EVT_IMMUNE_ALERT, pid=31337)
        handlers, autonomy, orch = self._make_handlers(approved=True)

        async def _drive() -> None:
            handlers.handle_trust_alert(event)
            # Allow any notify task a tick to complete.
            await asyncio.sleep(0)

        asyncio.run(_drive())

        self.assertEqual(len(autonomy.calls), 1)
        self.assertEqual(autonomy.calls[0]["action"], "trust_alert")
        freezes = [c for c in orch.calls if c[0] == "freeze_process"]
        quars = [c for c in orch.calls if c[0] == "trust_quarantine"]
        self.assertEqual(len(freezes), 1)
        self.assertEqual(len(quars), 1)
        self.assertTrue(freezes[0][2])  # force=True
        tail = list(handlers._recent_events)[-1]
        self.assertIn("quarantined", tail["action"])

    def test_alert_refused_is_observed(self) -> None:
        """approved=False -> action="observed"; no orchestrator calls
        (main.py:528). Note: decision is REJECTED here, not just
        pending — different from pe_load semantics."""
        event = self._make_event(TRUST_EVT_IMMUNE_ALERT)
        handlers, autonomy, orch = self._make_handlers(approved=False)

        async def _drive() -> None:
            handlers.handle_trust_alert(event)
            await asyncio.sleep(0)

        asyncio.run(_drive())
        tail = list(handlers._recent_events)[-1]
        self.assertEqual(tail["action"], "observed")


class TestQuarantineDispatch(TrustDispatchBase):
    """TrustEventType.QUARANTINE -> handle_trust_quarantine.
    This is the kernel-INITIATED quarantine path, not cortex-initiated."""

    def test_quarantine_invalidates_score_cache(self) -> None:
        """Kernel quarantined a subject; cortex invalidates its score
        cache (main.py:534) and schedules a critical notification."""
        event = self._make_event(TRUST_EVT_QUARANTINE, pid=777)
        handlers, _autonomy, orch = self._make_handlers()

        async def _drive() -> None:
            handlers.handle_trust_quarantine(event)
            await asyncio.sleep(0)

        asyncio.run(_drive())
        names = [c[0] for c in orch.calls]
        self.assertIn("invalidate_score_cache", names)
        # Notify was scheduled with a "critical" level.
        notif = [c for c in orch.calls if c[0] == "notify"]
        self.assertTrue(notif, orch.calls)
        self.assertEqual(notif[0][3], "critical")
        tail = list(handlers._recent_events)[-1]
        self.assertEqual(tail["action"], "kernel quarantine")


class TestTokenStarveDispatch(TrustDispatchBase):
    """TrustEventType.TOKEN_STARVE -> handle_trust_token_starve.
    Logs + records; no autonomy call today."""

    def test_token_starve_records_event(self) -> None:
        event = self._make_event(TRUST_EVT_TOKEN_STARVE, pid=555)
        handlers, autonomy, _orch = self._make_handlers()
        handlers.handle_trust_token_starve(event)
        self.assertEqual(handlers.events_processed, 1)
        tail = list(handlers._recent_events)[-1]
        self.assertEqual(tail["action"], "token starvation")
        # No autonomy consultation for token starve.
        self.assertEqual(len(autonomy.calls), 0)


class TestScoreChangeDispatch(TrustDispatchBase):
    """TrustEventType.SCORE_CHANGE -> handle_trust_score_change.
    Invalidates cached score reading for the pid (main.py:561)."""

    def test_score_change_invalidates_cache(self) -> None:
        event = self._make_event(TRUST_EVT_SCORE_CHANGE, pid=909)
        handlers, _autonomy, orch = self._make_handlers()
        handlers.handle_trust_score_change(event)
        calls = [c for c in orch.calls if c[0] == "invalidate_score_cache"]
        self.assertEqual(len(calls), 1, orch.calls)
        self.assertEqual(calls[0][1], 909)
        tail = list(handlers._recent_events)[-1]
        self.assertEqual(tail["action"], "score change")


class TestTrustEventBusRegistration(TrustDispatchBase):
    """register_handlers binds all 4 trust event types on the bus;
    APOPTOSIS (0x05) is intentionally NOT bound today (gap)."""

    def test_all_four_types_bound(self) -> None:
        bus = self.eb.EventBus(socket_path="/tmp/_s79_trust_reg.sock")
        handlers, _a, _o = self._make_handlers()
        self.cortex_main.register_handlers(bus, handlers)
        kernel_handlers = bus._handlers.get(SRC_KERNEL, {})
        for t in (TRUST_EVT_IMMUNE_ALERT, TRUST_EVT_QUARANTINE,
                  TRUST_EVT_TOKEN_STARVE, TRUST_EVT_SCORE_CHANGE):
            self.assertIn(t, kernel_handlers,
                          f"Trust event 0x{t:02x} not bound")

    def test_apoptosis_is_unbound_report_only(self) -> None:
        """REPORT: TrustEventType.APOPTOSIS (0x05) is declared in the
        enum (event_bus.py:90) but register_handlers binds only 4 of 6
        trust types (main.py:936-939 misses APOPTOSIS and TRC_CHANGE).

        Pin current behavior so the gap is visible; once wired, this
        test should break and prompt a follow-up."""
        bus = self.eb.EventBus(socket_path="/tmp/_s79_apop.sock")
        handlers, _a, _o = self._make_handlers()
        self.cortex_main.register_handlers(bus, handlers)
        kernel_handlers = bus._handlers.get(SRC_KERNEL, {})
        self.assertNotIn(TRUST_EVT_APOPTOSIS, kernel_handlers,
                         "APOPTOSIS acquired a handler; consumer wired — "
                         "update this test")

    def test_end_to_end_dispatch_score_change_via_bus(self) -> None:
        """Drive a SCORE_CHANGE wire-bytes event through bus._dispatch."""
        bus = self.eb.EventBus(socket_path="/tmp/_s79_sc_e2e.sock")
        handlers, _autonomy, orch = self._make_handlers()
        self.cortex_main.register_handlers(bus, handlers)
        raw = build_event_bytes(SRC_KERNEL, TRUST_EVT_SCORE_CHANGE,
                                _empty_payload(), pid=123456)
        event = bus._parse_event(raw)
        self.assertIsNotNone(event)
        bus._dispatch(event)
        invalidate = [c for c in orch.calls
                      if c[0] == "invalidate_score_cache"]
        self.assertEqual(len(invalidate), 1)
        self.assertEqual(invalidate[0][1], 123456)


if __name__ == "__main__":
    unittest.main()
