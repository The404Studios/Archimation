"""Unit tests for ``ai-control/daemon/differential_observer.py`` (S76 Agent D).

Covers:
  * numeric int / float deltas
  * dict recursive deltas
  * list set-difference (added / removed)
  * string change detection
  * first tick returns {}
  * key appearance / disappearance handled
  * mixed-type fields (int + dict + list in one observer)
  * thread-safety (poller + reader concurrent)
  * JSON-serializable delta output

Pattern mirrors ``tests/unit/test_library_census.py`` (S75 Agent B).
"""

from __future__ import annotations

import importlib
import json
import sys
import threading
import time
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DAEMON_DIR = _REPO_ROOT / "ai-control" / "daemon"

if str(_DAEMON_DIR) not in sys.path:
    sys.path.insert(0, str(_DAEMON_DIR))


def _load_module():
    sys.modules.pop("differential_observer", None)
    return importlib.import_module("differential_observer")


# -- Fakes -----------------------------------------------------------------


class _StubObserver:
    """Minimal observer: a mutable snapshot buffer that we step through.

    Tests call ``set(dict)`` to change what the next snapshot() returns.
    """

    def __init__(self, initial: dict = None) -> None:
        self._snap = dict(initial or {})
        self._lock = threading.Lock()

    def set(self, snap: dict) -> None:
        with self._lock:
            self._snap = dict(snap)

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._snap)


class _FakeBus:
    def __init__(self) -> None:
        self.received: list = []
        self.lock = threading.Lock()

    def publish(self, event: dict) -> None:
        with self.lock:
            self.received.append(event)


# -- Tests ------------------------------------------------------------------


class TestDeltaPrimitives(unittest.TestCase):
    """_delta_value / _delta_dict on individual value types."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_numeric_int_delta(self) -> None:
        d = self.mod._delta_dict({"x": 5}, {"x": 8})
        self.assertEqual(d["x"], 3)

    def test_numeric_int_delta_decrease(self) -> None:
        d = self.mod._delta_dict({"x": 10}, {"x": 2})
        self.assertEqual(d["x"], -8)

    def test_numeric_float_delta(self) -> None:
        d = self.mod._delta_dict({"y": 1.5}, {"y": 2.0})
        self.assertAlmostEqual(d["y"], 0.5, places=6)

    def test_numeric_zero_delta(self) -> None:
        d = self.mod._delta_dict({"n": 42}, {"n": 42})
        self.assertEqual(d["n"], 0)

    def test_dict_recursive_delta(self) -> None:
        old = {"counts": {"a": 1, "b": 2}}
        new = {"counts": {"a": 3, "b": 2}}
        d = self.mod._delta_dict(old, new)
        self.assertEqual(d["counts"]["a"], 2)
        self.assertEqual(d["counts"]["b"], 0)

    def test_list_set_difference(self) -> None:
        old = {"items": ["a", "b", "c"]}
        new = {"items": ["b", "c", "d"]}
        d = self.mod._delta_dict(old, new)
        delta = d["items"]
        self.assertIn("d", delta["added"])
        self.assertIn("a", delta["removed"])
        self.assertNotIn("b", delta["added"])
        self.assertNotIn("b", delta["removed"])

    def test_list_unchanged(self) -> None:
        old = {"items": [1, 2, 3]}
        new = {"items": [3, 2, 1]}  # same set, different order
        d = self.mod._delta_dict(old, new)
        self.assertEqual(d["items"]["added"], [])
        self.assertEqual(d["items"]["removed"], [])

    def test_list_unhashable_fallback(self) -> None:
        """Lists of dicts can't be setted; fall back to summary."""
        old = {"rows": [{"id": 1}, {"id": 2}]}
        new = {"rows": [{"id": 1}, {"id": 2}, {"id": 3}]}
        d = self.mod._delta_dict(old, new)
        delta = d["rows"]
        # Fallback: changed + old_len + new_len
        self.assertIn("changed", delta)
        self.assertTrue(delta["changed"])
        self.assertEqual(delta["old_len"], 2)
        self.assertEqual(delta["new_len"], 3)

    def test_string_equality_flag(self) -> None:
        d = self.mod._delta_dict({"s": "foo"}, {"s": "bar"})
        self.assertTrue(d["s"]["changed"])
        self.assertEqual(d["s"]["old"], "foo")
        self.assertEqual(d["s"]["new"], "bar")

    def test_string_unchanged(self) -> None:
        d = self.mod._delta_dict({"s": "foo"}, {"s": "foo"})
        self.assertFalse(d["s"]["changed"])

    def test_key_disappearance(self) -> None:
        d = self.mod._delta_dict({"a": 1, "b": 2}, {"a": 1})
        self.assertEqual(d["a"], 0)
        # "b" removed from snapshot.
        self.assertIn("removed", d["b"])
        self.assertEqual(d["b"]["removed"], 2)

    def test_key_appearance(self) -> None:
        d = self.mod._delta_dict({"a": 1}, {"a": 1, "new_key": "hello"})
        self.assertIn("added", d["new_key"])
        self.assertEqual(d["new_key"]["added"], "hello")


class TestFilterLifecycle(unittest.TestCase):
    """First-tick semantics + baseline handling."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_first_tick_returns_empty(self) -> None:
        obs = _StubObserver({"n": 10})
        flt = self.mod.DifferentialFilter(observer=obs)
        delta = flt.tick()
        self.assertEqual(delta, {})

    def test_second_tick_returns_delta(self) -> None:
        obs = _StubObserver({"n": 10})
        flt = self.mod.DifferentialFilter(observer=obs)
        flt.tick()
        obs.set({"n": 15})
        delta = flt.tick()
        self.assertEqual(delta["n"], 5)

    def test_no_upstream_is_noop(self) -> None:
        flt = self.mod.DifferentialFilter(observer=None)
        self.assertEqual(flt.tick(), {})
        self.assertEqual(flt.deltas(), {})

    def test_upstream_raises_is_safe(self) -> None:
        class _BrokenObserver:
            def snapshot(self):
                raise RuntimeError("boom")

        flt = self.mod.DifferentialFilter(observer=_BrokenObserver())
        self.assertEqual(flt.tick(), {})
        self.assertGreaterEqual(flt.stats()["snapshot_errors"], 1)

    def test_set_observer_resets_baseline(self) -> None:
        obs_a = _StubObserver({"x": 1})
        obs_b = _StubObserver({"x": 999})
        flt = self.mod.DifferentialFilter(observer=obs_a)
        flt.tick()  # baseline x=1
        flt.set_observer(obs_b)
        # Baseline gone -> next tick returns {}
        self.assertEqual(flt.tick(), {})
        # Subsequent tick with no change -> zero-delta dict
        delta = flt.tick()
        self.assertEqual(delta["x"], 0)


class TestFilterMixedTypes(unittest.TestCase):
    """One snapshot carries int + dict + list + str."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_mixed_field_delta(self) -> None:
        obs = _StubObserver({
            "count": 5,
            "library_counts": {"kernel32.dll": 10, "user32.dll": 7},
            "rare_libraries": ["a.dll", "b.dll"],
            "label": "idle",
        })
        flt = self.mod.DifferentialFilter(observer=obs)
        flt.tick()  # baseline

        obs.set({
            "count": 12,
            "library_counts": {"kernel32.dll": 13, "gdi32.dll": 2},
            "rare_libraries": ["b.dll", "c.dll"],
            "label": "active",
        })
        d = flt.tick()

        # numeric
        self.assertEqual(d["count"], 7)
        # nested dict: kernel32 +3; user32 removed; gdi32 added
        lc = d["library_counts"]
        self.assertEqual(lc["kernel32.dll"], 3)
        self.assertIn("removed", lc["user32.dll"])
        self.assertEqual(lc["user32.dll"]["removed"], 7)
        self.assertIn("added", lc["gdi32.dll"])
        self.assertEqual(lc["gdi32.dll"]["added"], 2)
        # list set-diff
        rl = d["rare_libraries"]
        self.assertIn("c.dll", rl["added"])
        self.assertIn("a.dll", rl["removed"])
        # string change
        self.assertTrue(d["label"]["changed"])
        self.assertEqual(d["label"]["old"], "idle")
        self.assertEqual(d["label"]["new"], "active")


class TestHasMeaningfulChange(unittest.TestCase):
    """The 'is there a change worth publishing?' predicate."""

    def setUp(self) -> None:
        self.mod = _load_module()
        self.flt_cls = self.mod.DifferentialFilter

    def test_all_zero_delta_is_not_meaningful(self) -> None:
        delta = {"a": 0, "b": 0.0}
        self.assertFalse(self.flt_cls._has_meaningful_change(delta))

    def test_numeric_change_is_meaningful(self) -> None:
        delta = {"a": 0, "b": 5}
        self.assertTrue(self.flt_cls._has_meaningful_change(delta))

    def test_added_key_is_meaningful(self) -> None:
        delta = {"a": 0, "x": {"added": 42}}
        self.assertTrue(self.flt_cls._has_meaningful_change(delta))

    def test_string_change_is_meaningful(self) -> None:
        delta = {"s": {"changed": True, "old": "a", "new": "b"}}
        self.assertTrue(self.flt_cls._has_meaningful_change(delta))

    def test_string_unchanged_is_not_meaningful(self) -> None:
        delta = {"s": {"changed": False, "old": "a", "new": "a"}}
        self.assertFalse(self.flt_cls._has_meaningful_change(delta))


class TestFilterEventBus(unittest.TestCase):
    """Meaningful deltas are published; zero-deltas are not."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_meaningful_delta_publishes(self) -> None:
        obs = _StubObserver({"n": 1})
        bus = _FakeBus()
        flt = self.mod.DifferentialFilter(
            observer=obs, event_bus=bus, name="test"
        )
        flt.tick()  # baseline
        obs.set({"n": 5})
        flt.tick()
        self.assertEqual(len(bus.received), 1)
        event = bus.received[0]
        self.assertEqual(event["source"], "differential_observer")
        self.assertEqual(event["observer"], "test")
        self.assertEqual(event["delta"]["n"], 4)

    def test_zero_delta_does_not_publish(self) -> None:
        obs = _StubObserver({"n": 1})
        bus = _FakeBus()
        flt = self.mod.DifferentialFilter(observer=obs, event_bus=bus)
        flt.tick()    # baseline
        flt.tick()    # no change -> no publish
        self.assertEqual(len(bus.received), 0)


class TestThreadSafety(unittest.TestCase):
    """Poller running + concurrent deltas() reader."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_poller_and_reader_concurrent(self) -> None:
        obs = _StubObserver({"n": 0})
        flt = self.mod.DifferentialFilter(observer=obs)

        # Start poller at fast interval.
        flt.start_polling(interval_seconds=0.05)

        read_errors: list = []
        stop = threading.Event()

        def reader():
            while not stop.is_set():
                try:
                    d = flt.deltas()
                    # JSON-serializable even under churn.
                    json.dumps(d)
                except Exception as e:  # pragma: no cover
                    read_errors.append(e)

        def mutator():
            for i in range(20):
                obs.set({"n": i})
                time.sleep(0.02)

        t_r = threading.Thread(target=reader)
        t_m = threading.Thread(target=mutator)
        t_r.start()
        t_m.start()
        t_m.join(timeout=5.0)
        stop.set()
        t_r.join(timeout=2.0)

        flt.stop_polling()

        self.assertEqual(read_errors, [])
        # Some ticks should have happened.
        self.assertGreater(flt.stats()["ticks"], 1)

    def test_double_start_is_noop(self) -> None:
        obs = _StubObserver({"n": 0})
        flt = self.mod.DifferentialFilter(observer=obs)
        flt.start_polling(interval_seconds=0.5)
        t1 = flt._poll_thread
        flt.start_polling(interval_seconds=0.5)
        t2 = flt._poll_thread
        self.assertIs(t1, t2)
        flt.stop_polling()

    def test_stop_without_start_is_idempotent(self) -> None:
        flt = self.mod.DifferentialFilter()
        flt.stop_polling()
        flt.stop_polling()  # twice -- must not raise


class TestJsonSerializable(unittest.TestCase):
    """Delta output must round-trip through json cleanly."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_complex_delta_json(self) -> None:
        obs = _StubObserver({
            "n": 3,
            "dict_field": {"a": 1},
            "list_field": ["x"],
            "str_field": "hello",
        })
        flt = self.mod.DifferentialFilter(observer=obs)
        flt.tick()
        obs.set({
            "n": 7,
            "dict_field": {"a": 2, "b": 9},
            "list_field": ["y"],
            "str_field": "world",
        })
        delta = flt.tick()
        text = json.dumps(delta)
        recovered = json.loads(text)
        self.assertEqual(recovered["n"], 4)
        self.assertEqual(recovered["dict_field"]["a"], 1)


class TestRegistry(unittest.TestCase):
    """DifferentialRegistry aggregates multiple filters by name."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_register_and_get(self) -> None:
        reg = self.mod.DifferentialRegistry()
        flt = self.mod.DifferentialFilter(
            observer=_StubObserver({"n": 1}), name="alpha"
        )
        reg.register("alpha", flt)
        self.assertIs(reg.get("alpha"), flt)
        self.assertIsNone(reg.get("missing"))
        self.assertEqual(reg.names(), ["alpha"])

    def test_snapshot_all(self) -> None:
        reg = self.mod.DifferentialRegistry()
        obs_a = _StubObserver({"n": 1})
        obs_b = _StubObserver({"m": 10})
        flt_a = self.mod.DifferentialFilter(observer=obs_a, name="a")
        flt_b = self.mod.DifferentialFilter(observer=obs_b, name="b")
        flt_a.tick()
        obs_a.set({"n": 4})
        flt_a.tick()
        reg.register("a", flt_a)
        reg.register("b", flt_b)
        all_deltas = reg.snapshot_all()
        self.assertEqual(all_deltas["a"]["n"], 3)
        self.assertEqual(all_deltas["b"], {})  # b never ticked


class TestWireUpHelper(unittest.TestCase):
    """register_with_daemon builds a registry; tolerates app=None."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_register_with_none_app(self) -> None:
        reg = self.mod.register_with_daemon(None)
        self.assertIsInstance(reg, self.mod.DifferentialRegistry)
        self.assertEqual(reg.names(), [])

    def test_register_with_observers(self) -> None:
        obs = _StubObserver({"n": 0})
        reg = self.mod.register_with_daemon(
            None, observers={"alpha": obs},
        )
        self.assertEqual(reg.names(), ["alpha"])
        flt = reg.get("alpha")
        self.assertIsNotNone(flt)
        # Ticking the filter should now produce deltas.
        flt.tick()
        obs.set({"n": 3})
        flt.tick()
        self.assertEqual(flt.deltas()["n"], 3)


if __name__ == "__main__":
    unittest.main()
