"""Boundary tests for ``ai-control/cortex/active_inference.py``.

S79 Test Agent 3 -- BeliefState bucketing boundaries from S75/S76.

The library_distribution bucket ladder (from active_inference.py
source around lines 346-355):

    ratio < 0.1   -> "none"
    ratio < 0.3   -> "low"
    ratio < 0.5   -> "mid"
    ratio < 0.7   -> "high"
    ratio >= 0.7  -> "saturated"

Every branch is strict-less, so the boundary VALUE goes to the NEXT
bucket. We probe each edge plus out-of-band negatives + >1.

Not gated. Must complete <5s.
"""

from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CORTEX_DIR = _REPO_ROOT / "ai-control" / "cortex"

if str(_CORTEX_DIR) not in sys.path:
    sys.path.insert(0, str(_CORTEX_DIR))


def _load():
    sys.modules.pop("active_inference", None)
    return importlib.import_module("active_inference")


class _FakeLibraryCensus:
    """Implements snapshot() with a caller-specified unique_library_ratio."""

    def __init__(self, ratio: float) -> None:
        self._ratio = ratio

    def snapshot(self) -> dict:
        return {"unique_library_ratio": self._ratio}


class BeliefStateLibraryDistributionBoundaries(unittest.TestCase):
    """Exhaustive sweep of ratio -> library_distribution bucket."""

    def setUp(self) -> None:
        self.mod = _load()

    def _bucket(self, ratio: float) -> str:
        b = self.mod.BeliefState.from_observers(
            library_census=_FakeLibraryCensus(ratio),
        )
        return b.library_distribution

    def test_exact_zero_is_none(self) -> None:
        """ratio=0.0 -> 'none' (in range [0, 0.1))."""
        self.assertEqual(self._bucket(0.0), "none")

    def test_just_below_one_tenth_is_none(self) -> None:
        """ratio=0.0999 -> 'none'."""
        self.assertEqual(self._bucket(0.0999), "none")

    def test_exactly_one_tenth_is_low(self) -> None:
        """ratio=0.1 -> 'low' (0.1 not <0.1).

        Source line 346: `if ratio < 0.1: "none"`, so 0.1 exact is NOT
        none; falls into the next branch `< 0.3` which makes it low."""
        self.assertEqual(self._bucket(0.1), "low")

    def test_just_below_three_tenths_is_low(self) -> None:
        """ratio=0.2999 -> 'low'."""
        self.assertEqual(self._bucket(0.2999), "low")

    def test_exactly_three_tenths_is_mid(self) -> None:
        """ratio=0.3 -> 'mid'."""
        self.assertEqual(self._bucket(0.3), "mid")

    def test_just_below_half_is_mid(self) -> None:
        """ratio=0.4999 -> 'mid'."""
        self.assertEqual(self._bucket(0.4999), "mid")

    def test_exactly_half_is_high(self) -> None:
        """ratio=0.5 -> 'high'."""
        self.assertEqual(self._bucket(0.5), "high")

    def test_just_below_seven_tenths_is_high(self) -> None:
        """ratio=0.6999 -> 'high'."""
        self.assertEqual(self._bucket(0.6999), "high")

    def test_exactly_seven_tenths_is_saturated(self) -> None:
        """ratio=0.7 -> 'saturated'."""
        self.assertEqual(self._bucket(0.7), "saturated")

    def test_one_is_saturated(self) -> None:
        """ratio=1.0 -> 'saturated'."""
        self.assertEqual(self._bucket(1.0), "saturated")

    def test_negative_ratio_documented(self) -> None:
        """ratio=-0.1 -> 'none' (negative < 0.1, so 'none' branch wins).

        Documented behavior: a negative ratio (which should never occur
        in production since it's a count proportion) falls through the
        <0.1 branch and gets bucketed as 'none'."""
        self.assertEqual(self._bucket(-0.1), "none")

    def test_above_one_ratio_documented(self) -> None:
        """ratio=1.1 -> 'saturated' (falls through to else branch).

        Documented behavior: ratios >1 (invalid per the
        unique_library_ratio contract) bucket as 'saturated'."""
        self.assertEqual(self._bucket(1.1), "saturated")

    def test_huge_ratio_saturated(self) -> None:
        """ratio=1e9 -> 'saturated'."""
        self.assertEqual(self._bucket(1e9), "saturated")

    def test_parametric_sweep(self) -> None:
        """Parametric sweep across the ladder boundaries via subTest."""
        cases = [
            (-1.0, "none"),
            (0.0, "none"),
            (0.09999, "none"),
            (0.1, "low"),
            (0.29999, "low"),
            (0.3, "mid"),
            (0.49999, "mid"),
            (0.5, "high"),
            (0.69999, "high"),
            (0.7, "saturated"),
            (0.99999, "saturated"),
            (1.0, "saturated"),
            (2.0, "saturated"),
        ]
        for ratio, expected in cases:
            with self.subTest(ratio=ratio):
                self.assertEqual(self._bucket(ratio), expected)


class BeliefStateMissingObservers(unittest.TestCase):
    """from_observers tolerates None observers and bad snapshots."""

    def setUp(self) -> None:
        self.mod = _load()

    def test_all_none_returns_default_buckets(self) -> None:
        """from_observers(None, None, None) -> all default labels."""
        b = self.mod.BeliefState.from_observers()
        # Defaults per source:
        self.assertEqual(b.tracked_bucket, "empty")
        self.assertEqual(b.library_distribution, "none")

    def test_census_returns_missing_ratio_key(self) -> None:
        """snapshot() without unique_library_ratio -> default 0.0 -> 'none'."""
        class _MissingKey:
            def snapshot(self):
                return {}
        b = self.mod.BeliefState.from_observers(library_census=_MissingKey())
        self.assertEqual(b.library_distribution, "none")

    def test_census_snapshot_raises_is_safe(self) -> None:
        """snapshot() raises -> library_distribution stays default."""
        class _Raiser:
            def snapshot(self):
                raise RuntimeError("boom")
        b = self.mod.BeliefState.from_observers(library_census=_Raiser())
        # exception caught; bucket remains default "none".
        self.assertEqual(b.library_distribution, "none")

    def test_census_returns_none_instead_of_dict(self) -> None:
        """snapshot() returning None -> handled via ``or {}`` fallback."""
        class _NullSnap:
            def snapshot(self):
                return None
        b = self.mod.BeliefState.from_observers(library_census=_NullSnap())
        self.assertEqual(b.library_distribution, "none")


class BucketHelperBoundaries(unittest.TestCase):
    """Edge cases in _bucket_tracked / _bucket_frac / _bucket_count."""

    def setUp(self) -> None:
        self.mod = _load()

    def test_bucket_tracked_boundaries(self) -> None:
        """Ladder: <=0 empty, <8 few, <64 some, <512 many, else flood."""
        cases = [
            (-1, "empty"),
            (0, "empty"),
            (1, "few"),
            (7, "few"),
            (8, "some"),
            (63, "some"),
            (64, "many"),
            (511, "many"),
            (512, "flood"),
            (10**9, "flood"),
        ]
        for n, expected in cases:
            with self.subTest(n=n):
                self.assertEqual(self.mod._bucket_tracked(n), expected)

    def test_bucket_frac_ladder(self) -> None:
        """Ladder: <=0.05 none, <=0.25 low, <=0.60 mid, <=0.90 high, else all."""
        cases = [
            (0.0, "none"),
            (0.05, "none"),
            (0.0500001, "low"),
            (0.25, "low"),
            (0.2500001, "mid"),
            (0.60, "mid"),
            (0.60001, "high"),
            (0.90, "high"),
            (0.90001, "all"),
            (1.0, "all"),
        ]
        for x, expected in cases:
            with self.subTest(x=x):
                self.assertEqual(self.mod._bucket_frac(x), expected)

    def test_bucket_count_ladder(self) -> None:
        """Ladder: <=0 zero, <3 one, <10 few, <50 many, else storm."""
        cases = [
            (-1, "zero"),
            (0, "zero"),
            (1, "one"),
            (2, "one"),
            (3, "few"),
            (9, "few"),
            (10, "many"),
            (49, "many"),
            (50, "storm"),
            (10**6, "storm"),
        ]
        for n, expected in cases:
            with self.subTest(n=n):
                self.assertEqual(self.mod._bucket_count(n), expected)


if __name__ == "__main__":
    unittest.main()
