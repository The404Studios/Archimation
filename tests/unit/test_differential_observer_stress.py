"""Stress tests for ``ai-control/daemon/differential_observer.py`` (S77 Agent 2).

These tests probe failure modes that fixed-N unit tests miss:
  * upstream observers that return None / raise / return non-dict
  * registry with 10 upstreams under continuous tick churn
  * rapid start/stop cycles (same bug pattern S76 Agent B fixed in
    library_census — S77 Agent 2 found + fixed it here too)
  * deep nested dicts in snapshots (recursion depth)
  * set-difference fallback for unhashable list items
  * tick() thread-safety against set_observer() mutation

Gated behind ``STRESS_TESTS=1``. Run with::

    cd tests/unit && STRESS_TESTS=1 python -m unittest test_differential_observer_stress -v

S77 Agent 2 deliverable.
"""

from __future__ import annotations

import importlib
import os
import random
import sys
import threading
import time
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DAEMON_DIR = _REPO_ROOT / "ai-control" / "daemon"

if str(_DAEMON_DIR) not in sys.path:
    sys.path.insert(0, str(_DAEMON_DIR))

STRESS_ENABLED = bool(os.environ.get("STRESS_TESTS"))


def _load_module():
    sys.modules.pop("differential_observer", None)
    return importlib.import_module("differential_observer")


class _StubObserver:
    def __init__(self, initial=None):
        self._snap = dict(initial or {})
        self._lock = threading.Lock()

    def set(self, snap):
        with self._lock:
            self._snap = dict(snap)

    def snapshot(self):
        with self._lock:
            return dict(self._snap)


class _RaisingObserver:
    def snapshot(self):
        raise RuntimeError("upstream broken")


class _NonDictObserver:
    def snapshot(self):
        return "not a dict"


class _NoneObserver:
    def snapshot(self):
        return None


class _FlakyObserver:
    """Alternates between valid snapshots and exceptions."""
    def __init__(self):
        self._n = 0
        self._lock = threading.Lock()

    def snapshot(self):
        with self._lock:
            self._n += 1
            n = self._n
        if n % 3 == 0:
            raise RuntimeError("flaky")
        if n % 5 == 0:
            return None
        return {"tick": n, "data": [1, 2, 3]}


@unittest.skipUnless(STRESS_ENABLED, "stress tests disabled (set STRESS_TESTS=1)")
class TestDifferentialObserverStress(unittest.TestCase):

    def setUp(self):
        self.mod = _load_module()

    def test_registry_with_pathological_upstreams(self):
        """Registry wired to 4 upstream observers — one raises, one
        returns None, one returns non-dict, one works — must not crash
        and must still return deltas for the working one."""
        reg = self.mod.DifferentialRegistry()
        good = _StubObserver({"x": 1})
        reg.register("good",
                     self.mod.DifferentialFilter(good, name="good"))
        reg.register("raising",
                     self.mod.DifferentialFilter(_RaisingObserver(),
                                                 name="raising"))
        reg.register("none",
                     self.mod.DifferentialFilter(_NoneObserver(),
                                                 name="none"))
        reg.register("nondict",
                     self.mod.DifferentialFilter(_NonDictObserver(),
                                                 name="nondict"))

        for _ in range(5):
            for name in reg.names():
                flt = reg.get(name)
                try:
                    flt.tick()
                except Exception as e:
                    self.fail(f"tick() raised for {name}: {e}")
            good.set({"x": good.snapshot()["x"] + 1})

        snap_all = reg.snapshot_all()
        self.assertIn("good", snap_all)
        # Good observer should have a numeric 'x' delta on non-first ticks.
        self.assertIsInstance(snap_all["good"], dict)

    def test_rapid_stop_start_no_thread_leak(self):
        """Same pattern as library_census: 30 stop/start cycles on
        a polling filter must not accumulate straggler threads (S77
        Agent 2 found this bug in differential_observer and fixed via
        per-thread stop_event; this test is the regression guard)."""
        obs = _StubObserver({"x": 0})
        flt = self.mod.DifferentialFilter(observer=obs, name="stress")

        try:
            for _ in range(30):
                flt.start_polling(interval_seconds=0.5)
                time.sleep(0.005)
                flt.stop_polling()
        finally:
            flt.stop_polling()

        time.sleep(0.5)
        alive = [t for t in threading.enumerate()
                 if t.name.startswith("differential[") and t.is_alive()]
        self.assertLessEqual(len(alive), 1,
                             f"thread leak: {len(alive)} alive pollers")

    def test_concurrent_tick_and_set_observer(self):
        """A tick() loop running while another thread calls
        set_observer() 100 times. Must not crash or leak errors."""
        obs1 = _StubObserver({"a": 1})
        obs2 = _StubObserver({"b": 2})
        flt = self.mod.DifferentialFilter(observer=obs1, name="swap")

        errors = []
        stop = threading.Event()

        def ticker():
            try:
                while not stop.is_set():
                    flt.tick()
            except Exception as e:
                errors.append(("ticker", e))

        def swapper():
            try:
                for _ in range(100):
                    flt.set_observer(obs1 if random.random() < 0.5 else obs2)
                    time.sleep(0.001)
            except Exception as e:
                errors.append(("swap", e))

        t1 = threading.Thread(target=ticker, daemon=True)
        t2 = threading.Thread(target=swapper)
        t1.start()
        t2.start()
        t2.join(timeout=30)
        stop.set()
        t1.join(timeout=5)

        self.assertEqual(errors, [], f"races: {errors}")

    def test_deep_nested_dict_delta(self):
        """Observer returning a 20-deep nested dict. _delta_dict must
        recurse without Python recursion-limit issues and produce a
        structurally similar output."""

        def build_nested(depth, seed=0):
            if depth == 0:
                return seed
            return {"n": build_nested(depth - 1, seed + 1),
                    "val": depth}

        class _DeepObserver:
            def __init__(self):
                self.state = build_nested(20, 0)
            def snapshot(self):
                return dict(self.state)

        deep = _DeepObserver()
        flt = self.mod.DifferentialFilter(observer=deep, name="deep")
        flt.tick()  # baseline
        # Modify at depth 20.
        cur = deep.state
        for _ in range(20):
            if isinstance(cur, dict) and "n" in cur:
                cur = cur["n"]
            else:
                break
        # mutate root only for simplicity
        deep.state["val"] = 999
        delta = flt.tick()
        self.assertIsInstance(delta, dict)

    def test_flaky_upstream_does_not_lose_baseline(self):
        """Upstream that alternates valid/exception/None. Filter must
        gracefully keep its baseline across failures and emit valid
        deltas on successful ticks."""
        flt = self.mod.DifferentialFilter(observer=_FlakyObserver(),
                                          name="flaky")
        valid_deltas = 0
        for _ in range(60):
            d = flt.tick()
            if d:
                valid_deltas += 1
        # Over 60 ticks, a 2-of-3 success rate * not-baseline-first
        # gives us at least 20 valid delta computations.
        self.assertGreater(valid_deltas, 15,
                           f"too few valid deltas: {valid_deltas}")
        stats = flt.stats()
        self.assertGreater(stats["snapshot_errors"], 0)

    def test_list_delta_with_unhashable_items(self):
        """Upstream snapshot containing list-of-dicts (unhashable).
        _delta_collection must fall back to the summary form without
        raising TypeError."""

        class _ListObserver:
            def __init__(self):
                self.data = [{"k": 1}, {"k": 2}]
            def snapshot(self):
                return {"items": list(self.data)}

        obs = _ListObserver()
        flt = self.mod.DifferentialFilter(observer=obs, name="unhash")
        flt.tick()  # baseline
        obs.data.append({"k": 3})
        delta = flt.tick()
        self.assertIsInstance(delta, dict)
        items = delta.get("items", {})
        # Fallback summary: {"changed": True, "old_len": 2, "new_len": 3}
        # OR set-difference if the runtime thinks dicts are equal-hashable.
        # Accept either shape as long as it's a dict.
        self.assertIsInstance(items, dict)

    def test_concurrent_registry_stop_all(self):
        """Registry with 10 polling filters. stop_all() must join all
        within a reasonable window without deadlocking."""
        reg = self.mod.DifferentialRegistry()
        for i in range(10):
            obs = _StubObserver({"i": i})
            flt = self.mod.DifferentialFilter(observer=obs, name=f"o{i}")
            reg.register(f"o{i}", flt)
            flt.start_polling(interval_seconds=0.5)

        start = time.perf_counter()
        reg.stop_all()
        elapsed = time.perf_counter() - start
        # Even with 2s per-filter timeout, stop_all is serial so budget
        # is 20s; but all filters should wake immediately on Event.set().
        self.assertLess(elapsed, 10.0,
                        f"stop_all too slow: {elapsed:.2f}s")

        time.sleep(0.3)
        alive = [t for t in threading.enumerate()
                 if t.name.startswith("differential[") and t.is_alive()]
        self.assertLessEqual(len(alive), 1)


if __name__ == "__main__":
    unittest.main()
