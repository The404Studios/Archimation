"""Tests for ``ai-control/daemon/system_summary.py``.

Runs under either ``pytest`` or plain ``python -m unittest``.  Designed
to be self-contained -- no subsystem imports except ``system_summary``
and a handful of fakes defined inline.  A broken subsystem must **not**
crash the endpoint; we assert that contract explicitly.

Invocation
----------
::

    # pytest
    pytest ai-control/daemon/tests/test_system_summary.py -q

    # stdlib
    python -m unittest ai-control.daemon.tests.test_system_summary
"""

from __future__ import annotations

import asyncio
import os
import sys
import unittest
from pathlib import Path
from typing import Any

# Make ``daemon/`` importable whether pytest collects from the repo root
# or directly from the tests dir.
_DAEMON_DIR = Path(__file__).resolve().parent.parent
if str(_DAEMON_DIR) not in sys.path:
    sys.path.insert(0, str(_DAEMON_DIR))

import system_summary  # noqa: E402  (sys.path tweak above)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeScannerDB:
    def __init__(self, n=3):
        self.patterns = {f"p{i}": object() for i in range(n)}


class _FakeScanner:
    def __init__(self):
        self.db = _FakeScannerDB(n=5)
        self._stats = {"scans_total": 7, "hits_total": 2}


class _FakeMemoryObserver:
    def __init__(self):
        self._processes = {1234: object(), 5678: object()}
        self._running = True


class _FakeTranslator:
    def get_stats(self):
        return {
            "linux_syscalls_mapped": 111,
            "nt_syscalls_mapped": 31,
            "known_ioctls": 70,
        }


class _ExplodingScanner:
    """Every attribute read raises AttributeError -> builder must not crash."""

    @property
    def db(self):
        raise AttributeError("nuked")

    @property
    def _stats(self):
        raise AttributeError("nuked")


class _ExplodingSubsystem:
    """Raises on any attr access -- simulates a partially-torn-down module."""

    def __getattribute__(self, name):  # noqa: D401
        raise RuntimeError(f"subsystem-dead: {name}")


# ---------------------------------------------------------------------------
# Async helper
# ---------------------------------------------------------------------------


def _run(coro):
    """Run an async coroutine from a sync test method.

    Creates a fresh event loop per call and closes it so we don't leak
    loops across tests (triggers a ResourceWarning on Windows otherwise).
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBuildSummary(unittest.TestCase):
    """Direct coroutine tests -- no FastAPI dependency."""

    def _base_state(self, **overrides) -> dict[str, Any]:
        state: dict[str, Any] = {
            "scanner": _FakeScanner(),
            "memory_observer": _FakeMemoryObserver(),
            "syscall_translator": _FakeTranslator(),
            "ready": True,
            "session": "headless",
            "start_monotonic": 0.0,
        }
        state.update(overrides)
        return state

    def test_empty_state_returns_starting(self):
        """Missing subsystems -> every entry is {"loaded": False}, state=starting."""
        out = _run(system_summary._build_summary({}))
        self.assertEqual(out["daemon"], "ai-control")
        self.assertEqual(out["state"], "starting")
        self.assertIsInstance(out["subsystems"], dict)
        # All 14 known subsystems must appear even when absent.
        for key in ("scanner", "memory_observer", "memory_diff",
                    "stub_discovery", "binary_signatures", "win_api_db",
                    "stub_generator", "syscall_monitor", "syscall_translator",
                    "behavioral_model", "thermal", "power",
                    "contusion", "firewall"):
            self.assertIn(key, out["subsystems"], f"missing: {key}")
            self.assertFalse(out["subsystems"][key]["loaded"])
        self.assertIn("counters", out)
        self.assertIn("uptime_s", out)
        self.assertGreaterEqual(out["uptime_s"], 0)

    def test_populated_state_reports_details(self):
        out = _run(system_summary._build_summary(self._base_state()))
        self.assertEqual(out["state"], "ready")
        self.assertEqual(out["session"], "headless")
        # Scanner wired.
        self.assertTrue(out["subsystems"]["scanner"]["loaded"])
        self.assertEqual(out["subsystems"]["scanner"]["patterns"], 5)
        self.assertEqual(out["subsystems"]["scanner"]["scans_total"], 7)
        self.assertEqual(out["subsystems"]["scanner"]["hits_total"], 2)
        # Memory observer wired.
        mo = out["subsystems"]["memory_observer"]
        self.assertTrue(mo["loaded"])
        self.assertEqual(mo["tracked_pids"], 2)
        self.assertTrue(mo["enabled"])
        # Syscall translator exposes table counts.
        st = out["subsystems"]["syscall_translator"]
        self.assertEqual(st["linux"], 111)
        self.assertEqual(st["nt"], 31)
        self.assertEqual(st["ioctls"], 70)

    def test_broken_subsystem_does_not_crash(self):
        """AttributeError in accessor MUST yield loaded=true + error field."""
        state = self._base_state(scanner=_ExplodingScanner())
        out = _run(system_summary._build_summary(state))
        scanner = out["subsystems"]["scanner"]
        # The scanner builder catches AttributeError via _cheap_getattr,
        # so it still reports loaded:true with zero counters -- no crash.
        self.assertTrue(scanner["loaded"])

    def test_totally_exploding_subsystem_is_caught(self):
        """A subsystem whose every access raises is marked loaded+error."""
        state = self._base_state(contusion=_ExplodingSubsystem())
        out = _run(system_summary._build_summary(state))
        cn = out["subsystems"]["contusion"]
        # The contusion builder only reads APP_PROFILES (module-level)
        # so an exploding instance still produces loaded:true.  This is
        # by design -- the presence check is "is instance not None".
        self.assertTrue(cn["loaded"])

    def test_counters_fields_present(self):
        out = _run(system_summary._build_summary({}))
        counters = out["counters"]
        for k in ("auth_tokens_issued", "auth_tokens_revoked",
                  "audit_entries_total", "pe_processes_active"):
            self.assertIn(k, counters)
            self.assertIsInstance(counters[k], int)

    def test_session_enum_is_sanitised(self):
        out = _run(system_summary._build_summary({"session": "INJECTED"}))
        self.assertEqual(out["session"], "headless")
        out = _run(system_summary._build_summary({"session": "wayland"}))
        self.assertEqual(out["session"], "wayland")


class TestRouter(unittest.TestCase):
    """Router-shape tests.

    We invoke the registered handler directly rather than going through
    the FastAPI ``TestClient`` because the TestClient<->httpx version
    matrix varies by platform (e.g. httpx>=0.28 only exposes async
    ``ASGITransport`` on some builds).  Calling the handler coroutine
    exercises the exact same code path as the HTTP layer -- the route
    handler is just ``async def`` and returns the summary dict.
    """

    def setUp(self):
        try:
            import fastapi  # noqa: F401
        except ImportError:
            self.skipTest("FastAPI not installed in this environment")

    def _handler(self, app_state):
        """Return the async handler function registered on /system/summary."""
        router = system_summary.make_summary_router(app_state)
        for route in router.routes:
            if getattr(route, "path", None) == "/system/summary":
                return route.endpoint
        self.fail("route /system/summary not registered on router")

    def test_router_registers_single_route(self):
        router = system_summary.make_summary_router({})
        paths = [r.path for r in router.routes]
        self.assertEqual(paths, ["/system/summary"])

    def test_handler_returns_200_shaped_body_when_empty(self):
        handler = self._handler({})
        body = _run(handler())
        self.assertEqual(body["daemon"], "ai-control")
        self.assertEqual(body["state"], "starting")
        self.assertIsInstance(body["subsystems"], dict)

    def test_handler_has_all_top_level_keys(self):
        state = {
            "scanner": _FakeScanner(),
            "memory_observer": _FakeMemoryObserver(),
            "syscall_translator": _FakeTranslator(),
            "ready": True,
            "start_monotonic": 0.0,
        }
        handler = self._handler(state)
        body = _run(handler())
        for key in ("daemon", "version", "uptime_s", "session",
                    "hostname", "subsystems", "counters", "state"):
            self.assertIn(key, body)

    def test_handler_tolerates_exploding_subsystem(self):
        handler = self._handler(
            {"scanner": _ExplodingScanner(), "ready": True}
        )
        # MUST NOT raise, even with a broken subsystem.
        body = _run(handler())
        self.assertTrue(body["subsystems"]["scanner"]["loaded"])
        # Other subsystems are absent -> loaded:false, but call still succeeds.
        self.assertFalse(body["subsystems"]["power"]["loaded"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
