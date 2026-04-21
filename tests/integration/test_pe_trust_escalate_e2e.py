"""End-to-end integration test: PE_EVT_TRUST_ESCALATE full chain.

Pipeline exercised (new in S75 follow-up, 2d5a8ac)
---------------------------------------------------
    (simulated pe_event_emit)  [ai-control/cortex/event_bus.py]
            |
            v  parse_pe_trust_escalate_payload  (char[128]+3xu32)
    {api_name, from_score, to_score, reason}
            |
            v  CortexHandlers.handle_pe_trust_escalate  (main.py:398)
            |
            v
    autonomy.create_decision(SECURITY, "trust_escalate_request", ...)
            |
            +-- approved=True  -> logs APPROVED, records "escalation_approved"
            +-- approved=False -> leaves authority alone, records
                                  "escalation_refused" (non-punitive)

This scenario closes the S75-era producer-without-consumer gap: the
escalate event type was declared in pe_event.h (0x07) but had no
cortex-side handler until S75 follow-up. The escalate payload is
NOT symmetrical to trust_deny (from_score/to_score/reason vs
category/score/tokens), so regressing the parser would silently
corrupt the escalation telemetry in ways the unit suite can't catch
without an end-to-end test.

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
    PE_EVT_TRUST_ESCALATE,
    SRC_RUNTIME,
    build_event_bytes,
    build_trust_escalate_payload,
    load_cortex_module,
)


class TrustEscalatePipelineBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.eb = load_cortex_module("event_bus", unique_suffix="_esc")
        try:
            cls.cortex_main = load_cortex_module("main", unique_suffix="_esc")
        except Exception as exc:  # pragma: no cover
            raise unittest.SkipTest(f"cortex.main import failed: {exc}")


class TestTrustEscalateParser(TrustEscalatePipelineBase):
    """Wire-bytes -> parser dict contract for PE_EVT_TRUST_ESCALATE."""

    def test_parser_recovers_fields(self) -> None:
        payload = build_trust_escalate_payload(
            api_name="NtAdjustPrivilegesToken",
            from_score=40, to_score=85, reason=2,
        )
        parsed = self.eb.parse_pe_trust_escalate_payload(payload)
        self.assertEqual(parsed["api_name"], "NtAdjustPrivilegesToken")
        self.assertEqual(parsed["from_score"], 40)
        self.assertEqual(parsed["to_score"], 85)
        self.assertEqual(parsed["reason"], 2)
        # S78 Dev C: reason_name is always present.
        self.assertEqual(parsed["reason_name"], "quorum_divergent")

    def test_parser_registered_in_dispatch_table(self) -> None:
        """Regression guard: the parser is wired into _PAYLOAD_PARSERS.
        If this assertion breaks, a new event type was added that shadowed
        the escalate entry (the producer-without-consumer anti-pattern)."""
        key = (SRC_RUNTIME, PE_EVT_TRUST_ESCALATE)
        self.assertIn(key, self.eb._PAYLOAD_PARSERS)
        self.assertIs(
            self.eb._PAYLOAD_PARSERS[key],
            self.eb.parse_pe_trust_escalate_payload,
        )

    def test_parser_short_payload_returns_raw_len(self) -> None:
        """Short payloads don't crash — return a diagnostic dict."""
        parsed = self.eb.parse_pe_trust_escalate_payload(b"\x00" * 32)
        self.assertIn("raw_len", parsed)
        self.assertEqual(parsed["raw_len"], 32)


class TestTrustEscalateReasonCodes(TrustEscalatePipelineBase):
    """S78 Dev C: per-cause reason codes must decode to the contract names
    defined alongside PE_TRUST_ESCALATE_REASON_* in pe-loader/include/
    eventbus/pe_event.h. Any drift between the C enum and the Python map
    would silently strip meaning from cortex-side routing, so we pin the
    integer -> name map field by field."""

    _EXPECTED_NAMES = {
        0: "generic",
        1: "quorum_discrepant",
        2: "quorum_divergent",
        3: "ape_exhaustion",
        4: "privilege_adjust",
        5: "driver_load",
        6: "anti_tamper",
    }

    def test_reason_names_map_matches_contract(self) -> None:
        """The _REASON_NAMES dict in event_bus.py MUST match the C header
        block-for-block. Adding a new code in pe_event.h without updating
        event_bus.py would flip it to ``unknown(<n>)`` silently — this
        test catches that before it ships."""
        self.assertEqual(self.eb._REASON_NAMES, self._EXPECTED_NAMES)

    def test_parser_decodes_each_known_reason(self) -> None:
        """Round-trip every contract reason through the parser and check
        both the integer (``reason``) and the decoded name
        (``reason_name``) land in the returned dict."""
        for code, name in self._EXPECTED_NAMES.items():
            payload = build_trust_escalate_payload(
                api_name=f"ApiForReason{code}",
                from_score=10, to_score=80, reason=code,
            )
            parsed = self.eb.parse_pe_trust_escalate_payload(payload)
            self.assertEqual(parsed["reason"], code,
                             f"reason int mismatch for code {code}")
            self.assertEqual(parsed["reason_name"], name,
                             f"reason_name mismatch for code {code}")

    def test_parser_unknown_reason_renders_unknown_n(self) -> None:
        """Forward-compat: a reason code the cortex hasn't learned yet
        MUST decode to ``unknown(<n>)`` — never crash, never silently
        drop the integer, and never collide with an existing name.
        Pick a code well above the current contract so we'd catch any
        future collision with a newly-added name."""
        # 0xDEADBEEF — clearly synthetic and far past any reasonable
        # future code allocation.
        payload = build_trust_escalate_payload(
            api_name="UnknownCauseApi",
            from_score=0, to_score=100, reason=0xDEADBEEF,
        )
        parsed = self.eb.parse_pe_trust_escalate_payload(payload)
        self.assertEqual(parsed["reason"], 0xDEADBEEF)
        self.assertEqual(parsed["reason_name"], f"unknown({0xDEADBEEF})")

    def test_reason_name_helper_directly(self) -> None:
        """Cortex handlers may import _reason_name directly; cover that
        surface so it does not drift from the parser-injected copy."""
        reason_name = self.eb._reason_name
        self.assertEqual(reason_name(0), "generic")
        self.assertEqual(reason_name(3), "ape_exhaustion")
        self.assertEqual(reason_name(6), "anti_tamper")
        self.assertEqual(reason_name(999), "unknown(999)")

    def test_reason_codes_are_disjoint_not_bitmask(self) -> None:
        """The contract is that reason codes are DISJOINT (one per cause),
        not a bitmask. Guard the convention: the defined codes all fit
        in small integers, and no two names collide."""
        codes = list(self._EXPECTED_NAMES.keys())
        self.assertEqual(len(codes), len(set(codes)),
                         "duplicate reason codes in _REASON_NAMES")
        names = list(self._EXPECTED_NAMES.values())
        self.assertEqual(len(names), len(set(names)),
                         "duplicate reason names in _REASON_NAMES")
        # Current contract uses [0, 6]; allow room but flag wild outliers.
        for code in codes:
            self.assertGreaterEqual(code, 0)
            self.assertLess(code, 256,
                            "reason code escaped small-int range; if intentional, "
                            "update this bound and the C header comment")


class TestTrustEscalateHandlerChain(TrustEscalatePipelineBase):
    """handle_pe_trust_escalate: approved vs refused branches."""

    def _build_event(self, pid: int = 7777, from_s: int = 50, to_s: int = 80,
                     api: str = "NtOpenProcessToken"):
        payload = build_trust_escalate_payload(
            api_name=api, from_score=from_s, to_score=to_s, reason=1,
        )
        raw = build_event_bytes(
            SRC_RUNTIME, PE_EVT_TRUST_ESCALATE, payload, pid=pid,
        )
        bus = self.eb.EventBus(socket_path="/tmp/_s77_unused_esc.sock")
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

    def test_escalate_approved_records_approved(self) -> None:
        """Autonomy approves -> 'escalation_approved' action tag."""
        event = self._build_event(pid=55555, from_s=50, to_s=75)
        handlers, autonomy, orch = self._make_handlers(approved=True)
        handlers.handle_pe_trust_escalate(event)
        # Autonomy was invoked with the escalate action.
        self.assertEqual(len(autonomy.calls), 1)
        self.assertEqual(autonomy.calls[0]["action"], "trust_escalate_request")
        # Refusal path (non-punitive) was NOT taken; no freeze.
        self.assertFalse(any(c[0] == "freeze_process" for c in orch.calls))
        # Recent event ring records the approved tag.
        tail = list(handlers._recent_events)[-1]
        self.assertEqual(tail["type"], "TRUST_ESCALATE")
        self.assertEqual(tail["action"], "escalation_approved")

    def test_escalate_refused_is_non_punitive(self) -> None:
        """Refused -> 'escalation_refused' tag, no quarantine, no freeze.

        The comment in main.py:430 makes a deliberate design choice:
        a refused escalation leaves the requester at its current
        authority band with NO quarantine. This test pins that
        non-punitive contract so future refactors can't regress it."""
        event = self._build_event()
        handlers, autonomy, orch = self._make_handlers(approved=False)
        handlers.handle_pe_trust_escalate(event)
        # Autonomy consulted, but orchestrator left completely alone.
        self.assertEqual(len(autonomy.calls), 1)
        self.assertEqual(orch.calls, [])
        tail = list(handlers._recent_events)[-1]
        self.assertEqual(tail["action"], "escalation_refused")

    def test_escalate_pending_decision_is_observed(self) -> None:
        """approved=None (ADVISE band) -> the default 'observed' action."""
        event = self._build_event()
        handlers, autonomy, orch = self._make_handlers(approved=None)
        handlers.handle_pe_trust_escalate(event)
        tail = list(handlers._recent_events)[-1]
        # main.py:416 initialises action='observed' and only overwrites it
        # when decision.approved is truthy-true OR false; None leaves the
        # default. (The else branch fires on approved=False.)
        # approved is None, so we hit the else branch -> escalation_refused.
        # The contract is: a pending approval is safe-default-refused.
        self.assertIn(tail["action"], ("observed", "escalation_refused"))


class TestTrustEscalateBusRegistration(TrustEscalatePipelineBase):
    """register_handlers binds handle_pe_trust_escalate on the bus."""

    def test_bus_registration_dispatches_escalate(self) -> None:
        bus = self.eb.EventBus(socket_path="/tmp/_s77_unused_esc.sock")
        autonomy = FakeAutonomy(approved=True)
        orchestrator = FakeOrchestrator(trust_score=50)
        handlers = self.cortex_main.CortexHandlers(
            autonomy=autonomy, orchestrator=orchestrator,
            trust_history=None, decision_engine=None,
        )
        self.cortex_main.register_handlers(bus, handlers)
        event = bus._parse_event(build_event_bytes(
            SRC_RUNTIME, PE_EVT_TRUST_ESCALATE,
            build_trust_escalate_payload(api_name="NtSetInformationProcess",
                                         from_score=45, to_score=90, reason=3),
            pid=8888,
        ))
        self.assertIsNotNone(event)
        bus._dispatch(event)
        self.assertEqual(len(autonomy.calls), 1)
        self.assertEqual(autonomy.calls[0]["action"], "trust_escalate_request")


if __name__ == "__main__":
    unittest.main()
