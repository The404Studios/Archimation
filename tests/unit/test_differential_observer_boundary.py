"""Boundary tests for ``ai-control/daemon/differential_observer.py``.

S79 Test Agent 3 -- edges in _delta_dict, _delta_collection,
_has_meaningful_change, DifferentialRegistry.

Boundaries probed:
  * _delta_dict({}, {}) / added-only / removed-only
  * nested dict: 0 / 1 / 20 / 100 levels deep
  * list with reordered elements -> set-difference correctness
  * mixed-type field (int -> str)
  * _has_meaningful_change with all-zero dict (S78 Dev G fix)
  * DifferentialRegistry with 0 / 1 / 100 registered filters

Not gated. Must complete <5s.
"""

from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DAEMON_DIR = _REPO_ROOT / "ai-control" / "daemon"

if str(_DAEMON_DIR) not in sys.path:
    sys.path.insert(0, str(_DAEMON_DIR))


def _load_module():
    sys.modules.pop("differential_observer", None)
    return importlib.import_module("differential_observer")


class DeltaDictBoundaries(unittest.TestCase):
    """_delta_dict empty / one-sided / mixed-type."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_both_empty_returns_empty_dict(self) -> None:
        """_delta_dict({}, {}) -> {}."""
        self.assertEqual(self.mod._delta_dict({}, {}), {})

    def test_only_old_has_key(self) -> None:
        """Key present only in old -> {"removed": val}."""
        delta = self.mod._delta_dict({"a": 1}, {})
        self.assertIn("a", delta)
        self.assertEqual(delta["a"], {"removed": 1})

    def test_only_new_has_key(self) -> None:
        """Key present only in new -> {"added": val}."""
        delta = self.mod._delta_dict({}, {"a": 2})
        self.assertIn("a", delta)
        self.assertEqual(delta["a"], {"added": 2})

    def test_mixed_type_int_to_str(self) -> None:
        """key: int on one side, str on the other -> {"changed": True, old, new}."""
        delta = self.mod._delta_dict({"x": 5}, {"x": "five"})
        self.assertEqual(delta["x"], {"changed": True, "old": 5, "new": "five"})

    def test_numeric_field_unchanged_is_zero(self) -> None:
        """Int field unchanged -> delta is 0."""
        delta = self.mod._delta_dict({"x": 5}, {"x": 5})
        self.assertEqual(delta["x"], 0)


class NestedDictDepthBoundaries(unittest.TestCase):
    """Recursion depth in _delta_dict."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_depth_zero(self) -> None:
        """Flat dict (depth=0) works."""
        delta = self.mod._delta_dict({"a": 1}, {"a": 2})
        self.assertEqual(delta["a"], 1)

    def test_depth_one(self) -> None:
        """One level of nesting."""
        delta = self.mod._delta_dict({"a": {"b": 1}}, {"a": {"b": 2}})
        self.assertEqual(delta["a"]["b"], 1)

    def test_depth_20(self) -> None:
        """20 levels deep -> still computable."""
        def build(depth, val):
            d = val
            for _ in range(depth):
                d = {"k": d}
            return d

        old = build(20, 1)
        new = build(20, 5)
        delta = self.mod._delta_dict(old, new)
        # Walk down.
        for _ in range(20):
            delta = delta["k"]
        self.assertEqual(delta, 4)

    def test_depth_100(self) -> None:
        """100 levels -> within Python recursion limit (default 1000)."""
        def build(depth, val):
            d = val
            for _ in range(depth):
                d = {"k": d}
            return d

        old = build(100, 1)
        new = build(100, 2)
        # Just verify it doesn't crash.
        delta = self.mod._delta_dict(old, new)
        self.assertIsNotNone(delta)


class ListSetDifferenceBoundaries(unittest.TestCase):
    """_delta_collection: reorder / same / disjoint."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_reorder_only_no_change_in_set(self) -> None:
        """[a,b,c] vs [c,b,a] -> empty added, empty removed (set-equal)."""
        delta = self.mod._delta_collection(["a", "b", "c"], ["c", "b", "a"])
        self.assertEqual(delta["added"], [])
        self.assertEqual(delta["removed"], [])

    def test_disjoint_lists(self) -> None:
        """[a] vs [b] -> added=[b], removed=[a]."""
        delta = self.mod._delta_collection(["a"], ["b"])
        self.assertEqual(delta["added"], ["b"])
        self.assertEqual(delta["removed"], ["a"])

    def test_unhashable_elements_fallback(self) -> None:
        """List-of-dicts (unhashable) -> summary fallback with old_len/new_len."""
        delta = self.mod._delta_collection([{"x": 1}], [{"x": 1}, {"y": 2}])
        self.assertIn("changed", delta)
        self.assertEqual(delta["old_len"], 1)
        self.assertEqual(delta["new_len"], 2)


class MeaningfulChangeBoundaries(unittest.TestCase):
    """_has_meaningful_change with zero / all-empty-lists / real changes (S78 Dev G)."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_empty_delta_not_meaningful(self) -> None:
        """Empty delta dict -> False."""
        self.assertFalse(
            self.mod.DifferentialFilter._has_meaningful_change({}),
        )

    def test_all_zero_numeric_not_meaningful(self) -> None:
        """All numeric fields zero -> False (S78 Dev G baseline)."""
        self.assertFalse(
            self.mod.DifferentialFilter._has_meaningful_change(
                {"a": 0, "b": 0, "c": 0},
            ),
        )

    def test_list_delta_both_empty_not_meaningful(self) -> None:
        """{"added": [], "removed": []} under a key -> NOT meaningful.

        S77 Agent 5 + S78 Dev G regression: ensure empty-list deltas for
        list-shaped keys do not trigger publish."""
        delta = {"k": {"added": [], "removed": []}}
        self.assertFalse(
            self.mod.DifferentialFilter._has_meaningful_change(delta),
        )

    def test_list_delta_added_non_empty_is_meaningful(self) -> None:
        """{"added": ["x"], "removed": []} -> True."""
        delta = {"k": {"added": ["x"], "removed": []}}
        self.assertTrue(
            self.mod.DifferentialFilter._has_meaningful_change(delta),
        )

    def test_single_nonzero_number_is_meaningful(self) -> None:
        """Any non-zero numeric -> True."""
        self.assertTrue(
            self.mod.DifferentialFilter._has_meaningful_change({"x": 1}),
        )

    def test_changed_true_is_meaningful(self) -> None:
        """{"changed": True, ...} -> True."""
        delta = {"s": {"changed": True, "old": "a", "new": "b"}}
        self.assertTrue(
            self.mod.DifferentialFilter._has_meaningful_change(delta),
        )


class RegistryUpstreamCountBoundaries(unittest.TestCase):
    """DifferentialRegistry with 0 / 1 / 100 filters."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_empty_registry(self) -> None:
        """0 filters -> names=[] snapshot_all={}."""
        reg = self.mod.DifferentialRegistry()
        self.assertEqual(reg.names(), [])
        self.assertEqual(reg.snapshot_all(), {})
        self.assertIsNone(reg.get("nonexistent"))

    def test_single_filter(self) -> None:
        """1 filter -> retrievable by name."""
        reg = self.mod.DifferentialRegistry()
        flt = self.mod.DifferentialFilter(observer=None, name="test")
        reg.register("test", flt)
        self.assertEqual(reg.names(), ["test"])
        self.assertIs(reg.get("test"), flt)

    def test_100_filters(self) -> None:
        """100 filters -> all retrievable, sorted names."""
        reg = self.mod.DifferentialRegistry()
        for i in range(100):
            flt = self.mod.DifferentialFilter(observer=None, name=f"obs{i:03d}")
            reg.register(f"obs{i:03d}", flt)
        self.assertEqual(len(reg.names()), 100)
        # names() returns sorted list.
        self.assertEqual(reg.names(), sorted(reg.names()))
        # stop_all without error.
        reg.stop_all()


class SentinelMissingSemantics(unittest.TestCase):
    """_delta_value missing-key sentinel handling."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_both_missing_returns_none(self) -> None:
        """Both sides missing -> None (no-change marker)."""
        sent = self.mod._SENTINEL_MISSING
        self.assertIsNone(self.mod._delta_value(sent, sent))

    def test_none_to_none_returns_none(self) -> None:
        """None -> None -> None."""
        self.assertIsNone(self.mod._delta_value(None, None))

    def test_none_to_value_is_added(self) -> None:
        """None -> 5 -> {"added": 5}."""
        self.assertEqual(self.mod._delta_value(None, 5), {"added": 5})


if __name__ == "__main__":
    unittest.main()
