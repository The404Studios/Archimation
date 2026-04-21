"""End-to-end: library_census -> BeliefState wire (S75 follow-up, 2d5a8ac).

Pipeline exercised
------------------
    memory_observer (fake: dict[pid, ProcessMemoryMap-shaped])
            |
            v
    library_census.snapshot()
            -> {"library_counts": {...}, "unique_library_ratio": <float>, ...}
            |
            v  bucketed into none/low/mid/high/saturated
    BeliefState.from_observers(library_census=...)
            |
            v
    BeliefState.token()  -> "...|lb:<bucket>"

This scenario is critical because the wire lives in TWO files:
  * ai-control/daemon/library_census.py    (producer)
  * ai-control/cortex/active_inference.py  (consumer, BeliefState.from_observers)
A unit test of either side in isolation cannot catch if the consumer's
bucketing thresholds drift from the producer's ratio semantics (the
|lb: segment would silently shift the behavioral token, breaking the
Markov chain keyed on it). Cross-module integration closes that gap.

S77 Agent 5 deliverable.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from _s77_helpers import load_cortex_module, load_daemon_module  # noqa: E402


def _fake_pmap(pid: int, dlls) -> SimpleNamespace:
    """Shape memory_observer._processes entries need: .dlls_loaded dict."""
    return SimpleNamespace(pid=pid,
                           dlls_loaded={name: {} for name in dlls})


class _FakeMemoryObserver:
    """Just the _processes attribute library_census reads."""

    def __init__(self, pid_to_dlls: dict) -> None:
        self._processes = {
            pid: _fake_pmap(pid, dlls) for pid, dlls in pid_to_dlls.items()
        }


class LibraryBeliefBase(unittest.TestCase):
    """Load both modules under a unique name so state doesn't bleed."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.lc = load_daemon_module("library_census", unique_suffix="_bel")
        cls.ai = load_cortex_module("active_inference", unique_suffix="_bel")


class TestLibraryCensusSeedsBeliefState(LibraryBeliefBase):
    """Seed a census, run BeliefState.from_observers, assert |lb: segment."""

    def test_empty_census_produces_none_bucket(self) -> None:
        """No observer -> library_distribution='none' -> |lb:none segment."""
        census = self.lc.LibraryCensus(memory_observer=None)
        bstate = self.ai.BeliefState.from_observers(library_census=census)
        self.assertEqual(bstate.library_distribution, "none")
        self.assertIn("|lb:none", bstate.token())

    def test_low_ratio_population_low_bucket(self) -> None:
        """Tight-ecosystem population (mostly shared, a few singletons).

        unique_library_ratio is singletons/total_libraries (library_census.py:191).
        Build 6 PIDs sharing 5 common DLLs + 1 unique DLL each.
        total_libraries = 5 shared + 6 unique = 11. singletons = 6. ratio = 6/11 ~= 0.54.
        That lands in 'high' bucket (0.5-0.7). Verify the round-trip."""
        shared = ["kernel32.dll", "ntdll.dll", "user32.dll",
                  "gdi32.dll", "advapi32.dll"]
        pids = {
            i: shared + [f"unique_{i}.dll"] for i in range(6)
        }
        mo = _FakeMemoryObserver(pids)
        census = self.lc.LibraryCensus(memory_observer=mo)
        snap = census.snapshot()
        # Pin the arithmetic so a future refactor that redefines the ratio
        # is caught here (rather than silently shifting the |lb: bucket).
        self.assertEqual(snap["total_subjects"], 6)
        self.assertEqual(snap["total_libraries"], 11)
        self.assertAlmostEqual(snap["unique_library_ratio"], 6.0 / 11.0,
                               delta=0.001)
        bstate = self.ai.BeliefState.from_observers(library_census=census)
        # 0.54 -> 'high' bucket per active_inference.py:351-353.
        self.assertEqual(bstate.library_distribution, "high")
        self.assertIn("|lb:high", bstate.token())

    def test_all_shared_population_is_none_bucket(self) -> None:
        """All-shared population: singletons=0 -> ratio=0 -> 'none' bucket."""
        shared = ["kernel32.dll", "ntdll.dll", "user32.dll"]
        pids = {i: shared for i in range(4)}
        mo = _FakeMemoryObserver(pids)
        census = self.lc.LibraryCensus(memory_observer=mo)
        snap = census.snapshot()
        self.assertEqual(snap["unique_library_ratio"], 0.0)
        bstate = self.ai.BeliefState.from_observers(library_census=census)
        self.assertEqual(bstate.library_distribution, "none")

    def test_high_diversity_population_tips_bucket_higher(self) -> None:
        """Every PID loads distinct DLLs -> high unique_library_ratio -> 'saturated'."""
        pids = {
            i: [f"unique_{i}_{k}.dll" for k in range(3)]
            for i in range(10)
        }
        mo = _FakeMemoryObserver(pids)
        census = self.lc.LibraryCensus(memory_observer=mo)
        snap = census.snapshot()
        self.assertEqual(snap["total_subjects"], 10)
        # Every DLL is unique to a single PID -> ratio == 1.0 -> 'saturated'.
        self.assertAlmostEqual(snap["unique_library_ratio"], 1.0, delta=0.01)
        bstate = self.ai.BeliefState.from_observers(library_census=census)
        self.assertEqual(bstate.library_distribution, "saturated")
        self.assertIn("|lb:saturated", bstate.token())

    def test_bucketing_threshold_boundaries(self) -> None:
        """Bucket thresholds in active_inference.py:346-355:
              <0.10 -> none
            0.10-0.30 -> low
            0.30-0.50 -> mid
            0.50-0.70 -> high
              >=0.70 -> saturated
        Build a stub census that returns a synthetic ratio to verify each
        threshold lands in the correct bucket."""
        class _StubCensus:
            def __init__(self, r: float) -> None:
                self._r = r

            def snapshot(self) -> dict:
                return {
                    "source": "library_census", "ts": 0,
                    "library_counts": {}, "total_subjects": 1,
                    "total_libraries": 0, "rare_libraries": [],
                    "unique_library_ratio": self._r,
                }

        cases = [
            (0.05, "none"),
            (0.15, "low"),
            (0.35, "mid"),
            (0.60, "high"),
            (0.85, "saturated"),
        ]
        for ratio, want in cases:
            with self.subTest(ratio=ratio):
                bstate = self.ai.BeliefState.from_observers(
                    library_census=_StubCensus(ratio),
                )
                self.assertEqual(bstate.library_distribution, want)


class TestBeliefStateTokenIsStable(LibraryBeliefBase):
    """Token-segment order + count are load-bearing; lock them down."""

    def test_token_ends_with_lb_segment(self) -> None:
        """The |lb: segment is the LAST segment per S75 follow-up contract."""
        bstate = self.ai.BeliefState()
        tok = bstate.token()
        self.assertTrue(tok.endswith(f"|lb:{bstate.library_distribution}"),
                        tok)

    def test_token_contains_11_segments(self) -> None:
        """Adding a new dimension without bumping the Markov feature index
        would silently invalidate every prior-built transition table."""
        bstate = self.ai.BeliefState()
        # token() separator is "|". Counting segments = split-length.
        segments = bstate.token().split("|")
        self.assertEqual(len(segments), 11, bstate.token())
        self.assertTrue(any(s.startswith("lb:") for s in segments))


if __name__ == "__main__":
    unittest.main()
