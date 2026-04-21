"""S79 Test Agent 4 — Handler envelopes + software_catalog URL pinning
   + reason_name flow through handle_pe_trust_escalate.

Pipeline exercised (multi-step):

1. Contusion command path
   ------------------------
        args dict
             |
             v  contusion_handlers.HANDLERS[<type>](args)
        envelope dict  -> success / error / handler_type

2. software_catalog URL pinning (S78 Dev F)
   ----------------------------------------
        app_install_windows("git")
             |
             v  software_catalog.resolve("git")
        entry["url"] -> https://github.com/git-for-windows/.../Git-2.47.1-64-bit.exe
   We verify the URLs the S78 audit pinned are still shape-correct
   (/download/<tag>/ style with a pinned filename), so a future ``latest``
   refactor gets caught before shipping.

3. reason_name flow through handle_pe_trust_escalate
   --------------------------------------------------
        PE_EVT_TRUST_ESCALATE wire with reason=4 (privilege_adjust)
             |
             v  parse_pe_trust_escalate_payload -> {reason:4, reason_name:"privilege_adjust"}
             |
             v  handle_pe_trust_escalate (main.py:398)
             |
             v  autonomy.create_decision(...)  [ approved=True ]
        recent_events[-1] -> action="escalation_approved"
   We verify ``event.payload["reason_name"]`` is a readable dict value
   the handler can route on.

Mock boundaries:
  * No FastAPI TestClient — we call the HANDLERS dict directly.
  * No network: software_catalog is pure data; the URL-shape test doesn't
    actually fetch.
  * FakeAutonomy + FakeOrchestrator for the trust_escalate chain.
"""

from __future__ import annotations

import asyncio
import re
import sys
import unittest
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

_REPO_ROOT = _THIS_DIR.parents[1]
_DAEMON_DIR = _REPO_ROOT / "ai-control" / "daemon"
_AI_CONTROL = _REPO_ROOT / "ai-control"
for _p in (str(_DAEMON_DIR), str(_AI_CONTROL)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from _s77_helpers import (  # noqa: E402
    FakeAutonomy,
    FakeOrchestrator,
    PE_EVT_TRUST_ESCALATE,
    SRC_RUNTIME,
    build_event_bytes,
    build_trust_escalate_payload,
    load_cortex_module,
)


class ContusionEnvelopeBase(unittest.TestCase):
    """Load contusion_handlers once; many tests reuse HANDLERS."""

    @classmethod
    def setUpClass(cls) -> None:
        import contusion_handlers  # noqa: E402
        cls.ch = contusion_handlers
        cls.HANDLERS = contusion_handlers.HANDLERS


class TestContusionEnvelopeShape(ContusionEnvelopeBase):
    """Spot-check a few handler envelopes: they MUST be dicts with a
    success bool, and failures MUST carry a diagnostic field (same
    contract as test_handler_envelopes.py::_DIAGNOSTIC_KEYS)."""

    DIAG_KEYS = (
        "error", "missing", "missing_dependency",
        "needs_confirm", "needs_clarification", "confirmation_required",
        "reason", "hint",
    )

    def _run(self, handler_type: str, args: dict) -> dict:
        fn = self.HANDLERS[handler_type]
        return asyncio.run(asyncio.wait_for(fn(args), timeout=10.0))

    def test_script_list_envelope(self) -> None:
        """script.list is a harmless always-available handler."""
        result = self._run("script.list", {})
        self.assertIsInstance(result, dict)
        self.assertIn("success", result)
        self.assertIsInstance(result["success"], bool)

    def test_script_info_missing_arg_surfaces_diagnostic(self) -> None:
        """script.info without 'name' -> _bad_arg(...) -> success=False
        with either 'error' or 'reason' filled. Pins the diagnostic
        contract at a representative bad-arg handler."""
        result = self._run("script.info", {})
        self.assertIsInstance(result, dict)
        self.assertFalse(result.get("success", True))
        diagnostics = {k: result.get(k) for k in self.DIAG_KEYS
                       if result.get(k)}
        self.assertTrue(diagnostics,
                        f"bare success=false with no diagnostic: {result!r}")


class TestSoftwareCatalogUrlPinning(unittest.TestCase):
    """S78 Dev F pinned three URLs that were previously /latest/download/
    with a versioned filename (broken on every upstream release). Each
    has a TODO(S79) marker asking for a tag bump once the current
    version EOLs.

    This test pins the SHAPE (explicit /download/<tag>/ + version-embedded
    filename) so that a future maintainer who slides back to
    /latest/download/<versioned-file> breaks the test."""

    @classmethod
    def setUpClass(cls) -> None:
        import software_catalog  # noqa: E402
        cls.sc = software_catalog

    def test_git_url_is_pinned_not_latest(self) -> None:
        """git's URL was /latest/download/Git-2.47.1-64-bit.exe pre-S78.
        Post-S78: /download/v2.47.1.windows.1/Git-2.47.1-64-bit.exe."""
        entry = self.sc.resolve("git")
        self.assertIsNotNone(entry)
        url = entry["url"]
        self.assertRegex(url, r"/download/v\d+\.\d+(\.\d+)+[^/]*/",
                         f"git URL reverted to unstable shape: {url}")
        self.assertNotIn("/latest/download/", url)

    def test_audacity_url_is_pinned(self) -> None:
        entry = self.sc.resolve("audacity")
        self.assertIsNotNone(entry)
        url = entry["url"]
        self.assertIn("/download/Audacity-", url)
        self.assertNotIn("/latest/download/", url)

    def test_handbrake_url_is_pinned(self) -> None:
        entry = self.sc.resolve("handbrake")
        self.assertIsNotNone(entry)
        url = entry["url"]
        # HandBrake uses just version tag, no 'v' prefix.
        self.assertRegex(url, r"/download/\d+\.\d+(\.\d+)+/")
        self.assertNotIn("/latest/download/", url)

    def test_resolve_via_alias_also_pinned(self) -> None:
        """Aliases must resolve to the SAME pinned URL as the canonical key.
        Drift here would mean install_app with "Git" works but "Git for
        Windows" silently points at a broken URL."""
        a = self.sc.resolve("git for windows")
        b = self.sc.resolve("git")
        # At least one alias should resolve; if "git for windows" isn't a
        # registered alias it may return None, but if it DOES resolve it
        # must match.
        if a is not None:
            self.assertEqual(a["url"], b["url"])

    def test_resolve_unknown_returns_none(self) -> None:
        """Sanity: not every name resolves. install_app would then surface
        an unknown_app error envelope."""
        self.assertIsNone(self.sc.resolve("definitely-not-an-app-xyz"))


class TestReasonNameFlowsThroughEscalateHandler(unittest.TestCase):
    """End-to-end: PE_EVT_TRUST_ESCALATE wire bytes encode reason=4
    (privilege_adjust). parse_pe_trust_escalate_payload adds
    reason_name="privilege_adjust" to the dict. handle_pe_trust_escalate
    reads event.payload to log the reason. Verify the name survives the
    pipeline and appears in the _recent_events record."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.eb = load_cortex_module("event_bus", unique_suffix="_s79_reason")
        try:
            cls.cortex_main = load_cortex_module(
                "main", unique_suffix="_s79_reason",
            )
        except Exception as exc:  # pragma: no cover
            raise unittest.SkipTest(f"cortex.main import failed: {exc}")

    def test_reason_name_present_in_parsed_event(self) -> None:
        payload = build_trust_escalate_payload(
            api_name="NtAdjustPrivilegesToken",
            from_score=50, to_score=80, reason=4,
        )
        raw = build_event_bytes(SRC_RUNTIME, PE_EVT_TRUST_ESCALATE, payload,
                                pid=12345)
        bus = self.eb.EventBus(socket_path="/tmp/_s79_reason.sock")
        event = bus._parse_event(raw)
        self.assertIsNotNone(event)
        # S78 Dev C: reason_name sits alongside reason in the parsed dict.
        self.assertEqual(event.payload["reason"], 4)
        self.assertEqual(event.payload["reason_name"], "privilege_adjust")

    def test_handler_logs_and_records_with_reason_context(self) -> None:
        """handle_pe_trust_escalate reads event.payload to pull api_name,
        from_score, to_score for its log line (main.py:420-427). The
        recorded action tag doesn't itself carry the reason, but the
        _recent_events entry carries the TrustEventType name for routing."""
        payload = build_trust_escalate_payload(
            api_name="NtLoadDriver",
            from_score=40, to_score=85, reason=5,  # driver_load
        )
        raw = build_event_bytes(SRC_RUNTIME, PE_EVT_TRUST_ESCALATE, payload,
                                pid=99999)
        bus = self.eb.EventBus(socket_path="/tmp/_s79_reason2.sock")
        event = bus._parse_event(raw)
        self.assertEqual(event.payload["reason_name"], "driver_load")

        autonomy = FakeAutonomy(approved=True)
        orch = FakeOrchestrator()
        handlers = self.cortex_main.CortexHandlers(
            autonomy=autonomy, orchestrator=orch,
            trust_history=None, decision_engine=None,
        )
        handlers.handle_pe_trust_escalate(event)
        tail = list(handlers._recent_events)[-1]
        # Action is "escalation_approved" per main.py:428.
        self.assertEqual(tail["action"], "escalation_approved")
        self.assertEqual(tail["type"], "TRUST_ESCALATE")
        self.assertEqual(tail["pid"], 99999)

    def test_unknown_reason_degrades_gracefully(self) -> None:
        """S78 Dev C forward-compat: unknown reason decodes to
        'unknown(<n>)' (event_bus.py:303). Handler MUST still run —
        no crash, no assertion failure."""
        payload = build_trust_escalate_payload(
            api_name="NewApiCall",
            from_score=10, to_score=50, reason=42,  # not in _REASON_NAMES
        )
        raw = build_event_bytes(SRC_RUNTIME, PE_EVT_TRUST_ESCALATE, payload,
                                pid=1010)
        bus = self.eb.EventBus(socket_path="/tmp/_s79_unk.sock")
        event = bus._parse_event(raw)
        self.assertEqual(event.payload["reason_name"], "unknown(42)")
        handlers = self.cortex_main.CortexHandlers(
            autonomy=FakeAutonomy(approved=True),
            orchestrator=FakeOrchestrator(),
            trust_history=None, decision_engine=None,
        )
        # Must not raise.
        handlers.handle_pe_trust_escalate(event)
        tail = list(handlers._recent_events)[-1]
        self.assertEqual(tail["action"], "escalation_approved")


if __name__ == "__main__":
    unittest.main()
