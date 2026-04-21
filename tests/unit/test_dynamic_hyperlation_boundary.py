"""Boundary tests for ``ai-control/cortex/dynamic_hyperlation.py``.

S79 Test Agent 3 -- MarkovTransitionMatrix edges with S78 fixes:
  * recent_window_max <= 0 -> clamped to 32 (S78 Dev G fix)
  * recent_window_max=1 / 2**16
  * update(-1) / update(4) / update(bool) -> rejected
  * APOPTOSIS absorbing behavior post-update
  * snapshot() empty
  * to_dict / from_dict round-trip with boundary window sizes
  * kl_divergence_recent_vs_steady with no observations / 1 sample

Not gated. Must complete <2s.
"""

from __future__ import annotations

import importlib
import sys
import unittest
from collections import deque
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CORTEX_DIR = _REPO_ROOT / "ai-control" / "cortex"

if str(_CORTEX_DIR) not in sys.path:
    sys.path.insert(0, str(_CORTEX_DIR))


def _load_module():
    sys.modules.pop("dynamic_hyperlation", None)
    return importlib.import_module("dynamic_hyperlation")


class RecentWindowMaxBoundaries(unittest.TestCase):
    """recent_window_max construction edges (S78 Dev G fix)."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_window_max_zero_clamped_to_32(self) -> None:
        """recent_window_max=0 -> clamped to 32 (S78 fix, dynamic_hyperlation.py:208-209)."""
        m = self.mod.MarkovTransitionMatrix(recent_window_max=0)
        self.assertEqual(m.recent_window_max, 32)
        self.assertEqual(m.recent.maxlen, 32)

    def test_window_max_negative_clamped(self) -> None:
        """recent_window_max=-5 -> clamped to 32."""
        m = self.mod.MarkovTransitionMatrix(recent_window_max=-5)
        self.assertEqual(m.recent_window_max, 32)

    def test_window_max_one_preserved(self) -> None:
        """recent_window_max=1 -> ring of 1 (the smallest valid)."""
        m = self.mod.MarkovTransitionMatrix(recent_window_max=1)
        self.assertEqual(m.recent_window_max, 1)
        self.assertEqual(m.recent.maxlen, 1)
        # Observe 3 states -> ring holds only the newest.
        for i in range(3):
            m.update(0)
        self.assertEqual(len(m.recent), 1)

    def test_window_max_large_preserved(self) -> None:
        """recent_window_max=65536 -> preserved (no upper clamp)."""
        m = self.mod.MarkovTransitionMatrix(recent_window_max=65536)
        self.assertEqual(m.recent_window_max, 65536)
        self.assertEqual(m.recent.maxlen, 65536)

    def test_from_dict_zero_clamped(self) -> None:
        """from_dict with recent_window_max=0 also clamps to 32 (source line 473)."""
        m = self.mod.MarkovTransitionMatrix.from_dict({"recent_window_max": 0})
        self.assertEqual(m.recent_window_max, 32)

    def test_direct_constructor_honours_rwm(self) -> None:
        """Regression: direct construction resizes the default ring to recent_window_max."""
        m = self.mod.MarkovTransitionMatrix(recent_window_max=64)
        self.assertEqual(m.recent.maxlen, 64)


class UpdateIndexBoundaries(unittest.TestCase):
    """update(idx) with out-of-range / bool / negative."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_negative_index_rejected(self) -> None:
        """update(-1) -> silently ignored; state unchanged."""
        m = self.mod.MarkovTransitionMatrix()
        m.update(-1)
        self.assertIsNone(m.last_seen_state)
        self.assertEqual(m.history_len, 0)

    def test_out_of_range_index_rejected(self) -> None:
        """update(4) -> silently ignored (valid 0..3)."""
        m = self.mod.MarkovTransitionMatrix()
        m.update(4)
        self.assertIsNone(m.last_seen_state)

    def test_bool_rejected(self) -> None:
        """update(True) -> rejected (S78 Dev G; bool is int-subclass).

        Paper-conformance concern: last_seen_state must stay a pure int or
        None; passing bool would type-pollute downstream.
        """
        m = self.mod.MarkovTransitionMatrix()
        m.update(True)
        self.assertIsNone(m.last_seen_state)
        m.update(False)
        self.assertIsNone(m.last_seen_state)

    def test_non_int_rejected(self) -> None:
        """update(1.5) -> rejected; update('0') -> rejected."""
        m = self.mod.MarkovTransitionMatrix()
        m.update(1.5)  # type: ignore[arg-type]
        self.assertIsNone(m.last_seen_state)
        m.update("0")  # type: ignore[arg-type]
        self.assertIsNone(m.last_seen_state)

    def test_zero_valid(self) -> None:
        """update(0) -> STEADY_FLOW recorded."""
        m = self.mod.MarkovTransitionMatrix()
        m.update(0)
        self.assertEqual(m.last_seen_state, 0)
        self.assertEqual(m.history_len, 1)

    def test_boundary_index_three_valid(self) -> None:
        """update(3) (APOPTOSIS) at boundary -> recorded."""
        m = self.mod.MarkovTransitionMatrix()
        m.update(3)
        self.assertEqual(m.last_seen_state, self.mod.MARKOV_APOPTOSIS_IDX)


class ApoptosisAbsorbingBoundary(unittest.TestCase):
    """APOPTOSIS (idx 3) is absorbing post-update."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_apoptosis_absorbs_subsequent_updates(self) -> None:
        """Once in APOPTOSIS, any later update is forced to APOPTOSIS."""
        m = self.mod.MarkovTransitionMatrix()
        m.update(0)  # STEADY_FLOW
        m.update(3)  # APOPTOSIS
        # Subsequent update(0) should NOT move the state.
        m.update(0)
        self.assertEqual(m.last_seen_state, self.mod.MARKOV_APOPTOSIS_IDX)
        # The transition should be recorded as 3->3 per absorbing rule.
        self.assertEqual(m.counts[3][3], 1)

    def test_hitting_time_zero_when_absorbed(self) -> None:
        """expected_hitting_time_to_apoptosis -> 0.0 when already in APOPTOSIS."""
        m = self.mod.MarkovTransitionMatrix()
        m.update(3)
        self.assertEqual(m.expected_hitting_time_to_apoptosis(), 0.0)

    def test_hitting_time_zero_when_unset(self) -> None:
        """expected_hitting_time_to_apoptosis -> 0.0 with zero observations."""
        m = self.mod.MarkovTransitionMatrix()
        self.assertEqual(m.expected_hitting_time_to_apoptosis(), 0.0)


class SnapshotEmptyBoundary(unittest.TestCase):
    """matrix() / stationary() / to_dict boundaries on empty state."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_matrix_empty_is_identity(self) -> None:
        """Zero-observation matrix: rows are identity per the public contract."""
        m = self.mod.MarkovTransitionMatrix()
        P = m.matrix()
        for i in range(self.mod.MARKOV_N_STATES):
            for j in range(self.mod.MARKOV_N_STATES):
                expected = 1.0 if i == j else 0.0
                self.assertEqual(P[i][j], expected,
                                 f"row {i}, col {j}")

    def test_stationary_empty_is_uniform(self) -> None:
        """Empty chain -> uniform stationary distribution."""
        m = self.mod.MarkovTransitionMatrix()
        pi = m.stationary()
        n = self.mod.MARKOV_N_STATES
        for v in pi:
            self.assertAlmostEqual(v, 1.0 / n, places=4)

    def test_to_dict_empty(self) -> None:
        """to_dict on fresh matrix: zeros everywhere."""
        m = self.mod.MarkovTransitionMatrix()
        d = m.to_dict()
        self.assertEqual(d["history_len"], 0)
        self.assertIsNone(d["last_seen_state"])
        self.assertEqual(d["recent"], [])
        # All counts == 0.
        for row in d["counts"]:
            self.assertEqual(sum(row), 0)


class SnapshotIsolationBoundary(unittest.TestCase):
    """to_dict()/from_dict round-trip must yield independent copies (S78 Dev G)."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_to_dict_returns_isolated_copy(self) -> None:
        """Mutating the dict returned by to_dict must NOT affect the matrix."""
        m = self.mod.MarkovTransitionMatrix()
        m.update(0)
        m.update(1)
        d = m.to_dict()
        # Mutate the snapshot copy.
        d["counts"][0][1] = 99
        d["recent"].append(2)
        # Original matrix unchanged.
        self.assertNotEqual(m.counts[0][1], 99)
        self.assertNotIn(2, list(m.recent))

    def test_from_dict_round_trip_preserves_rwm(self) -> None:
        """from_dict(to_dict()) preserves recent_window_max (S78 fix)."""
        m = self.mod.MarkovTransitionMatrix(recent_window_max=64)
        m.update(0)
        d = m.to_dict()
        m2 = self.mod.MarkovTransitionMatrix.from_dict(d)
        self.assertEqual(m2.recent_window_max, 64)
        self.assertEqual(m2.recent.maxlen, 64)


class KlDivergenceBoundaries(unittest.TestCase):
    """kl_divergence_recent_vs_steady edge cases."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_no_observations(self) -> None:
        """Empty recent window -> 0.0 (avoid misleading anomaly)."""
        m = self.mod.MarkovTransitionMatrix()
        self.assertEqual(m.kl_divergence_recent_vs_steady(recent_window=10), 0.0)

    def test_single_observation(self) -> None:
        """1 sample < 2 minimum -> 0.0 per source line 412."""
        m = self.mod.MarkovTransitionMatrix()
        m.update(0)
        self.assertEqual(m.kl_divergence_recent_vs_steady(recent_window=10), 0.0)

    def test_zero_recent_window(self) -> None:
        """recent_window=0 -> 0.0 (early-out)."""
        m = self.mod.MarkovTransitionMatrix()
        m.update(0)
        m.update(1)
        self.assertEqual(m.kl_divergence_recent_vs_steady(recent_window=0), 0.0)

    def test_negative_recent_window(self) -> None:
        """recent_window=-1 -> 0.0 (early-out)."""
        m = self.mod.MarkovTransitionMatrix()
        m.update(0)
        m.update(1)
        self.assertEqual(m.kl_divergence_recent_vs_steady(recent_window=-1), 0.0)


if __name__ == "__main__":
    unittest.main()
