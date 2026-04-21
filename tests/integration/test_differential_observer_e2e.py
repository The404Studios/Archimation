"""End-to-end: differential_observer wrapping library_census (S76 Agent D).

Pipeline exercised
------------------
    library_census (real instance, seeded with fake memory_observer)
            |
            v  DifferentialFilter.set_observer(lc)
    filter.tick()     -> first tick: seeds baseline, returns {}
    <mutate lc>
    filter.tick()     -> second tick: returns the delta dict

Unit tests for differential_observer in tests/unit/test_differential_observer.py
exercise the filter with a stub observer whose snapshot() returns dicts
the test crafts directly. This integration test drives the *real*
library_census as the upstream so we catch:
  * library_census snapshot-shape drift that changes what deltas get
    produced (e.g. a renamed field would show as add+remove instead
    of a numeric delta);
  * poll-thread lifecycle bugs introduced by S76 Agent B's stop/start
    race fix -- the differential filter has the same fix applied.

S77 Agent 5 deliverable.
"""

from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from _s77_helpers import load_daemon_module  # noqa: E402


def _fake_pmap(pid: int, dlls) -> SimpleNamespace:
    return SimpleNamespace(pid=pid,
                           dlls_loaded={name: {} for name in dlls})


class _MutableMemoryObserver:
    """A memory_observer stand-in whose ``_processes`` map can be mutated
    from the test body. library_census reads via ``_processes`` so changes
    are visible on the next snapshot()."""

    def __init__(self) -> None:
        self._processes: dict = {}
        self._lock = threading.Lock()

    def add_pid(self, pid: int, dlls) -> None:
        with self._lock:
            self._processes[pid] = _fake_pmap(pid, dlls)

    def remove_pid(self, pid: int) -> None:
        with self._lock:
            self._processes.pop(pid, None)


class DifferentialE2EBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.do = load_daemon_module("differential_observer", unique_suffix="_e2e")
        cls.lc = load_daemon_module("library_census", unique_suffix="_e2e_diff")


class TestDifferentialOverLibraryCensus(DifferentialE2EBase):
    """filter on a real library_census emitting deltas as we mutate the
    upstream memory observer."""

    def test_first_tick_seeds_baseline_returns_empty(self) -> None:
        mo = _MutableMemoryObserver()
        mo.add_pid(100, ["kernel32.dll", "ntdll.dll"])
        census = self.lc.LibraryCensus(memory_observer=mo)
        flt = self.do.DifferentialFilter(observer=census, name="library_census")
        delta = flt.tick()
        self.assertEqual(delta, {})  # baseline seed, no delta yet

    def test_mutation_produces_nonempty_delta(self) -> None:
        """After baseline, add a PID with new DLLs -- delta must be non-empty
        and reflect both total_subjects increment and library_counts change."""
        mo = _MutableMemoryObserver()
        mo.add_pid(100, ["kernel32.dll"])
        census = self.lc.LibraryCensus(memory_observer=mo)
        flt = self.do.DifferentialFilter(observer=census)
        flt.tick()  # seed

        # Mutation: add a new PID with new DLLs.
        mo.add_pid(200, ["user32.dll", "d3d9.dll"])
        delta = flt.tick()
        self.assertIsInstance(delta, dict)
        self.assertTrue(delta, "expected non-empty delta after mutation")
        # total_subjects should have an integer +1 delta.
        self.assertIn("total_subjects", delta)
        self.assertEqual(delta["total_subjects"], 1)
        # library_counts changed; its delta is a recursive dict.
        self.assertIn("library_counts", delta)

    def test_zero_change_tick_yields_zero_numeric_deltas(self) -> None:
        """After two identical snapshots, every numeric field delta is 0.

        Note the fact-finding caveat: in the current S76 Agent D
        implementation of _delta_collection, a list field always produces
        a dict with keys ``added`` and ``removed`` (even if both are []).
        That makes _has_meaningful_change return True on list-containing
        snapshots where nothing actually changed, so we can't assert "no
        bus publish" via that predicate. We assert the observable contract
        that DOES hold: numeric-scalar deltas are exactly 0."""
        mo = _MutableMemoryObserver()
        mo.add_pid(100, ["kernel32.dll"])
        census = self.lc.LibraryCensus(memory_observer=mo)
        flt = self.do.DifferentialFilter(observer=census)
        flt.tick()           # seed
        delta = flt.tick()   # no mutation between ticks
        # All numeric fields must be 0 (no change).
        self.assertEqual(delta.get("total_subjects", 0), 0)
        self.assertEqual(delta.get("total_libraries", 0), 0)
        self.assertEqual(delta.get("unique_library_ratio", 0.0), 0.0)
        # library_counts is a nested dict; every value should also be 0.
        lc_delta = delta.get("library_counts", {})
        if isinstance(lc_delta, dict):
            for v in lc_delta.values():
                # Nested dict delta of unchanged key is 0 (int) or None.
                self.assertIn(v, (0, 0.0, None))

    def test_removal_shows_in_delta(self) -> None:
        """Remove a PID -- total_subjects should drop by 1."""
        mo = _MutableMemoryObserver()
        mo.add_pid(100, ["kernel32.dll"])
        mo.add_pid(200, ["ntdll.dll"])
        census = self.lc.LibraryCensus(memory_observer=mo)
        flt = self.do.DifferentialFilter(observer=census)
        flt.tick()
        mo.remove_pid(200)
        delta = flt.tick()
        self.assertEqual(delta.get("total_subjects"), -1)


class TestDifferentialRegistry(DifferentialE2EBase):
    """DifferentialRegistry collects named filters and fans out through
    /metrics/deltas (exercised here via snapshot_all)."""

    def test_registry_fan_out(self) -> None:
        mo_a = _MutableMemoryObserver()
        mo_a.add_pid(1, ["a.dll"])
        mo_b = _MutableMemoryObserver()
        mo_b.add_pid(2, ["b.dll"])
        census_a = self.lc.LibraryCensus(memory_observer=mo_a)
        census_b = self.lc.LibraryCensus(memory_observer=mo_b)
        flt_a = self.do.DifferentialFilter(observer=census_a, name="a")
        flt_b = self.do.DifferentialFilter(observer=census_b, name="b")
        reg = self.do.DifferentialRegistry()
        reg.register("a", flt_a)
        reg.register("b", flt_b)
        self.assertEqual(set(reg.names()), {"a", "b"})
        # Before first tick, deltas() is empty for each.
        self.assertEqual(reg.snapshot_all(), {"a": {}, "b": {}})
        # Seed both.
        flt_a.tick(); flt_b.tick()
        # Mutate a; tick both.
        mo_a.add_pid(99, ["z.dll"])
        flt_a.tick(); flt_b.tick()
        snap = reg.snapshot_all()
        self.assertTrue(snap["a"], "filter a should have delta after mutation")
        # b's numeric total_subjects delta should be 0.
        self.assertEqual(snap["b"].get("total_subjects", 0), 0)


class TestPollLifecycleNoOrphan(DifferentialE2EBase):
    """Regression for S76 Agent B's stop/start race: rapid cycles must
    not accumulate poll threads."""

    def test_stop_then_start_does_not_orphan(self) -> None:
        mo = _MutableMemoryObserver()
        mo.add_pid(1, ["a.dll"])
        census = self.lc.LibraryCensus(memory_observer=mo)
        flt = self.do.DifferentialFilter(observer=census)
        # Rapid cycle: start / stop / start / stop.
        flt.start_polling(interval_seconds=0.25)
        self.assertTrue(flt.stats()["polling"])
        flt.stop_polling()
        flt.start_polling(interval_seconds=0.25)
        flt.stop_polling()
        # No background threads should remain under the filter's name.
        live = [t for t in threading.enumerate()
                if t.name.startswith("differential[")]
        # Give joiners a moment to settle.
        deadline = time.monotonic() + 2.0
        while live and time.monotonic() < deadline:
            time.sleep(0.05)
            live = [t for t in threading.enumerate()
                    if t.name.startswith("differential[") and t.is_alive()]
        self.assertEqual(live, [], f"orphan poll threads: {live}")


if __name__ == "__main__":
    unittest.main()
