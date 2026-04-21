"""Unit tests for ``ai-control/daemon/library_census.py`` (S75 Item 2).

Covers the cross-PID library histogram, rare-library identification,
snapshot JSON-serializability, drift policy firing, and graceful
behavior when the memory_observer is empty or absent.

No live memory_observer / /proc walk is required -- tests inject a
stub observer whose ``_processes`` attribute matches the real shape
(``dict[int, ProcessMemoryMap]`` where ProcessMemoryMap has a
``dlls_loaded: dict[str, dict]`` attribute).

S75 Agent B deliverable.
"""

from __future__ import annotations

import importlib
import json
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DAEMON_DIR = _REPO_ROOT / "ai-control" / "daemon"

if str(_DAEMON_DIR) not in sys.path:
    sys.path.insert(0, str(_DAEMON_DIR))


def _load_module():
    sys.modules.pop("library_census", None)
    return importlib.import_module("library_census")


# -- Fakes -----------------------------------------------------------------


def _fake_pmap(pid: int, dll_names) -> SimpleNamespace:
    """Build a minimal ProcessMemoryMap-shaped stand-in.

    The census reads only ``pmap.dlls_loaded.keys()``; values are dicts
    in the real code so we mirror that, but the census never reads the
    values so they can be empty.
    """
    return SimpleNamespace(
        pid=pid,
        dlls_loaded={name: {} for name in dll_names},
    )


class _FakeMemoryObserver:
    """Just enough memory_observer API for the census to read.

    Matches the public surface used by
    ``LibraryCensus._collect_pid_maps()``: a ``_processes`` dict keyed
    by PID whose values expose ``.dlls_loaded``.
    """

    def __init__(self, pid_to_dlls: dict = None) -> None:
        self._processes: dict = {}
        if pid_to_dlls:
            for pid, names in pid_to_dlls.items():
                self._processes[pid] = _fake_pmap(pid, names)


class _FakeBus:
    def __init__(self) -> None:
        self.received: list = []

    def publish(self, event: dict) -> None:
        self.received.append(event)


# -- Tests ------------------------------------------------------------------


class TestEmptyMemoryObserver(unittest.TestCase):
    """Empty and absent memory_observer must yield a zero-state snapshot."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_no_observer_returns_empty_snapshot(self) -> None:
        census = self.mod.LibraryCensus(memory_observer=None)
        snap = census.snapshot()
        self.assertEqual(snap["source"], "library_census")
        self.assertEqual(snap["total_subjects"], 0)
        self.assertEqual(snap["total_libraries"], 0)
        self.assertEqual(snap["library_counts"], {})
        self.assertEqual(snap["rare_libraries"], [])
        self.assertEqual(snap["unique_library_ratio"], 0.0)

    def test_empty_observer_returns_empty_snapshot(self) -> None:
        mo = _FakeMemoryObserver({})
        census = self.mod.LibraryCensus(memory_observer=mo)
        snap = census.snapshot()
        self.assertEqual(snap["total_subjects"], 0)
        self.assertEqual(snap["total_libraries"], 0)

    def test_observer_missing_processes_attr_is_safe(self) -> None:
        # If an alternative observer implementation (e.g. a mock) has
        # no _processes attribute, the census must not crash.
        class _WeirdObserver:
            pass

        census = self.mod.LibraryCensus(memory_observer=_WeirdObserver())
        snap = census.snapshot()
        self.assertEqual(snap["total_subjects"], 0)


class TestDisjointDllSets(unittest.TestCase):
    """5 PIDs with disjoint DLLs -> 5 subjects, all DLLs rare."""

    def setUp(self) -> None:
        self.mod = _load_module()
        # Each PID loads 3 unique DLLs.  5 * 3 = 15 DLLs, all unique.
        self.pid_dlls = {
            1001: ["a1.dll", "a2.dll", "a3.dll"],
            1002: ["b1.dll", "b2.dll", "b3.dll"],
            1003: ["c1.dll", "c2.dll", "c3.dll"],
            1004: ["d1.dll", "d2.dll", "d3.dll"],
            1005: ["e1.dll", "e2.dll", "e3.dll"],
        }
        self.mo = _FakeMemoryObserver(self.pid_dlls)
        self.census = self.mod.LibraryCensus(memory_observer=self.mo)

    def test_subject_and_library_counts(self) -> None:
        snap = self.census.snapshot()
        self.assertEqual(snap["total_subjects"], 5)
        self.assertEqual(snap["total_libraries"], 15)
        self.assertGreaterEqual(snap["total_libraries"], 10,
                                "acceptance test: >=10 unique libraries")

    def test_every_library_is_rare(self) -> None:
        snap = self.census.snapshot()
        # Threshold default is 2; every DLL appears in exactly 1 subject.
        self.assertEqual(len(snap["rare_libraries"]), 15)
        # Must be lowercase + sorted for stable output.
        self.assertEqual(snap["rare_libraries"],
                         sorted(snap["rare_libraries"]))

    def test_unique_library_ratio_is_one(self) -> None:
        snap = self.census.snapshot()
        # All singletons -> ratio = 1.0.
        self.assertEqual(snap["unique_library_ratio"], 1.0)

    def test_each_library_count_is_one(self) -> None:
        snap = self.census.snapshot()
        for name, count in snap["library_counts"].items():
            self.assertEqual(count, 1, msg=f"{name} should be 1")


class TestOverlappingDllSets(unittest.TestCase):
    """Cross-PID overlap -- counts aggregate correctly."""

    def setUp(self) -> None:
        self.mod = _load_module()
        # 10 PIDs all share kernel32+ntdll; half add user32; two have
        # a rare "exotic.dll"; one has a unique "singleton.dll".
        pid_dlls = {}
        for pid in range(2001, 2011):   # 10 PIDs
            dlls = ["kernel32.dll", "ntdll.dll"]
            if pid % 2 == 0:
                dlls.append("user32.dll")
            pid_dlls[pid] = dlls
        pid_dlls[2001].append("exotic.dll")
        pid_dlls[2002].append("exotic.dll")
        pid_dlls[2003].append("singleton.dll")
        self.mo = _FakeMemoryObserver(pid_dlls)
        self.census = self.mod.LibraryCensus(memory_observer=self.mo)

    def test_popular_library_counts_aggregate(self) -> None:
        snap = self.census.snapshot()
        self.assertEqual(snap["total_subjects"], 10)
        self.assertEqual(snap["library_counts"]["kernel32.dll"], 10)
        self.assertEqual(snap["library_counts"]["ntdll.dll"], 10)
        self.assertEqual(snap["library_counts"]["user32.dll"], 5)

    def test_rare_libraries_include_exotic_and_singleton(self) -> None:
        # Default rare_threshold = 2: exotic (in 2) and singleton (in 1)
        # both qualify; user32 (in 5) and kernel32 (in 10) do not.
        snap = self.census.snapshot()
        self.assertIn("exotic.dll", snap["rare_libraries"])
        self.assertIn("singleton.dll", snap["rare_libraries"])
        self.assertNotIn("user32.dll", snap["rare_libraries"])
        self.assertNotIn("kernel32.dll", snap["rare_libraries"])

    def test_unique_library_ratio_is_singletons_over_total(self) -> None:
        snap = self.census.snapshot()
        # 4 unique DLLs: kernel32, ntdll, user32, exotic, singleton = 5
        # Of those, only "singleton.dll" has count==1 -> 1/5 = 0.2
        self.assertEqual(snap["total_libraries"], 5)
        self.assertAlmostEqual(snap["unique_library_ratio"], 0.2, places=4)


class TestJsonSerializable(unittest.TestCase):
    """Snapshots must round-trip through json.dumps/loads cleanly."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_snapshot_is_json_serializable(self) -> None:
        mo = _FakeMemoryObserver({
            42: ["kernel32.dll", "ntdll.dll"],
            43: ["kernel32.dll", "vulkan-1.dll"],
        })
        census = self.mod.LibraryCensus(memory_observer=mo)
        snap = census.snapshot()
        text = json.dumps(snap)
        recovered = json.loads(text)
        self.assertEqual(recovered["total_subjects"], 2)
        self.assertIn("kernel32.dll", recovered["library_counts"])


class TestPolicyEvaluate(unittest.TestCase):
    """Drift policy fires on a subject loading rare DLLs."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_policy_does_not_fire_on_common_dlls(self) -> None:
        # 20 PIDs all load the same 2 DLLs. No drift expected on any PID.
        pid_dlls = {
            3000 + i: ["kernel32.dll", "ntdll.dll"] for i in range(20)
        }
        mo = _FakeMemoryObserver(pid_dlls)
        census = self.mod.LibraryCensus(memory_observer=mo)
        event = census.policy_evaluate(3000)
        self.assertIsNone(event, "no drift expected on shared DLLs")

    def test_policy_fires_on_unusual_dll_set(self) -> None:
        # 20 PIDs share kernel32+ntdll; only PID 4999 adds an exotic DLL.
        pid_dlls = {
            4000 + i: ["kernel32.dll", "ntdll.dll"] for i in range(20)
        }
        pid_dlls[4999] = ["kernel32.dll", "ntdll.dll", "exotic_injector.dll"]
        mo = _FakeMemoryObserver(pid_dlls)
        bus = _FakeBus()
        census = self.mod.LibraryCensus(memory_observer=mo, event_bus=bus)
        event = census.policy_evaluate(4999)
        self.assertIsNotNone(event, "drift should fire for PID 4999")
        self.assertEqual(event["source"], "library_census.policy")
        self.assertEqual(event["subject_pid"], 4999)
        self.assertIn("exotic_injector.dll", event["rare_loaded"])
        # Common DLLs must NOT be flagged.
        self.assertNotIn("kernel32.dll", event["rare_loaded"])
        # And the event must have been published to the bus.
        self.assertTrue(any(
            e.get("source") == "library_census.policy" for e in bus.received
        ))

    def test_policy_safe_on_unknown_pid(self) -> None:
        mo = _FakeMemoryObserver({5000: ["a.dll"], 5001: ["b.dll"]})
        census = self.mod.LibraryCensus(memory_observer=mo)
        self.assertIsNone(census.policy_evaluate(pid_pid := 99999))

    def test_policy_safe_on_tiny_population(self) -> None:
        # Population too small for ratios to be meaningful; expect None.
        mo = _FakeMemoryObserver({6000: ["a.dll", "unique.dll"]})
        census = self.mod.LibraryCensus(memory_observer=mo)
        self.assertIsNone(census.policy_evaluate(6000))


class TestDllLoadHook(unittest.TestCase):
    """on_dll_load invalidates cached snapshot ts without crashing."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_hook_invalidates_cache_ts(self) -> None:
        mo = _FakeMemoryObserver({1: ["a.dll"]})
        census = self.mod.LibraryCensus(memory_observer=mo)
        # Prime the cache.
        snap = census.snapshot()
        original_ts = snap["ts"]
        self.assertGreater(original_ts, 0.0)
        # Fire the hook -- cache ts should go to 0.
        census.on_dll_load(1, "new.dll")
        self.assertEqual(census._last_snapshot["ts"], 0.0)

    def test_hook_empty_name_is_noop(self) -> None:
        census = self.mod.LibraryCensus(memory_observer=None)
        census.on_dll_load(1, "")  # must not raise


class TestWireUpHelper(unittest.TestCase):
    """register_with_daemon builds a census and registers hooks."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_register_returns_census_with_none_app(self) -> None:
        census = self.mod.register_with_daemon(None, event_bus=_FakeBus())
        self.assertIsInstance(census, self.mod.LibraryCensus)

    def test_register_installs_dll_load_callback(self) -> None:
        """If the memory_observer exposes register_dll_load_callback, we wire."""
        calls = []

        class _ObserverWithHook:
            def __init__(self) -> None:
                self._processes = {}

            def register_dll_load_callback(self, cb) -> None:
                calls.append(cb)

        mo = _ObserverWithHook()
        census = self.mod.register_with_daemon(
            None, event_bus=None, memory_observer=mo,
        )
        # The census's on_dll_load should have been registered as a cb.
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], census.on_dll_load)

    def test_register_safe_when_observer_lacks_hook(self) -> None:
        """Observer without register_dll_load_callback must still work."""
        class _LegacyObserver:
            def __init__(self) -> None:
                self._processes = {}

        mo = _LegacyObserver()
        census = self.mod.register_with_daemon(
            None, event_bus=None, memory_observer=mo,
        )
        self.assertIsInstance(census, self.mod.LibraryCensus)


class TestPollingLifecycle(unittest.TestCase):
    """Background poll thread starts, publishes, and stops cleanly."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_polling_publishes_snapshots(self) -> None:
        mo = _FakeMemoryObserver({1: ["kernel32.dll"]})
        bus = _FakeBus()
        census = self.mod.LibraryCensus(memory_observer=mo, event_bus=bus)
        census.start_polling(interval_seconds=0.5)
        # Wait briefly for at least one tick.
        time.sleep(0.3)
        census.stop_polling()
        # At least one snapshot published (the first tick runs immediately).
        self.assertGreaterEqual(len(bus.received), 1)
        self.assertEqual(bus.received[0]["source"], "library_census")

    def test_stop_polling_is_idempotent(self) -> None:
        census = self.mod.LibraryCensus()
        census.stop_polling()  # never started
        census.stop_polling()  # called twice

    def test_double_start_is_noop(self) -> None:
        mo = _FakeMemoryObserver({})
        census = self.mod.LibraryCensus(memory_observer=mo)
        census.start_polling(interval_seconds=0.5)
        t1 = census._poll_thread
        census.start_polling(interval_seconds=0.5)
        t2 = census._poll_thread
        self.assertIs(t1, t2, "second start() must be a no-op")
        census.stop_polling()


if __name__ == "__main__":
    unittest.main()
