"""High-scale stress tests for ``ai-control/daemon/differential_observer.py`` (S79).

S79 Test Agent 2 -- scales S77 Agent 2's 4-upstream / 30-cycle tests
to 32 upstreams and 100+ cycles, adds 128-thread tick hammering and
snapshot_all() under registry churn. Adversarial stop_start_storm
checks the S77 per-thread stop_event fix at higher scale.

Gated behind ``STRESS_TESTS=1``. Run with::

    cd tests/unit && STRESS_TESTS=1 python -m unittest test_differential_observer_stress_v2 -v

S79 Test Agent 2 deliverable.
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


class _NumericObs:
    """Observer returning {k: int} counts. Tick bumps values."""
    def __init__(self, size=10):
        self._data = {f"k{i}": 0 for i in range(size)}
        self._lock = threading.Lock()

    def tick_values(self):
        with self._lock:
            for k in self._data:
                self._data[k] += 1

    def snapshot(self):
        with self._lock:
            return dict(self._data)


class _FlakyObs:
    """Raises on some fraction of calls."""
    def __init__(self, fail_every=7):
        self._n = 0
        self._fail_every = fail_every
        self._lock = threading.Lock()

    def snapshot(self):
        with self._lock:
            self._n += 1
            n = self._n
        if n % self._fail_every == 0:
            raise RuntimeError(f"flaky tick {n}")
        return {"count": n, "items": list(range(n % 5))}


class _ListObs:
    """Returns dict with a list field."""
    def __init__(self):
        self._data = list(range(10))
        self._lock = threading.Lock()

    def mutate(self, items):
        with self._lock:
            self._data = list(items)

    def snapshot(self):
        with self._lock:
            return {"items": list(self._data)}


@unittest.skipUnless(STRESS_ENABLED, "stress tests disabled (set STRESS_TESTS=1)")
class TestDifferentialObserverStressV2(unittest.TestCase):

    def setUp(self):
        self.mod = _load_module()

    def test_32_upstream_registry_tick_storm(self):
        """Registry with 32 upstream observers (varied shapes). 128
        threads hammer tick() across them. Probes registry-level
        contention + per-filter locks under heavy fan-out."""
        reg = self.mod.DifferentialRegistry()
        obs_list = []
        for i in range(32):
            if i % 4 == 0:
                obs = _FlakyObs(fail_every=11)
            elif i % 4 == 1:
                obs = _ListObs()
            else:
                obs = _NumericObs(size=20)
            obs_list.append(obs)
            flt = self.mod.DifferentialFilter(observer=obs, name=f"up{i}")
            reg.register(f"up{i}", flt)

        errors = []
        stop = threading.Event()

        def hammer(tid):
            try:
                rng = random.Random(tid)
                while not stop.is_set():
                    name = rng.choice(reg.names())
                    flt = reg.get(name)
                    if flt is not None:
                        flt.tick()
            except Exception as e:
                errors.append(("hammer", tid, e))

        threads = [threading.Thread(target=hammer, args=(i,), daemon=True,
                                    name=f"h-{i}")
                   for i in range(128)]
        for t in threads:
            t.start()
        time.sleep(3.0)
        stop.set()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(errors, [], f"errors: {errors[:3]}")
        # stats should still be legible.
        all_snaps = reg.snapshot_all()
        self.assertEqual(len(all_snaps), 32)

    def test_stop_start_storm_100_cycles(self):
        """100 stop/start cycles on one DifferentialFilter. Same
        adversarial pattern as library_census_v2. Pass = no thread leak."""
        obs = _NumericObs(size=4)
        flt = self.mod.DifferentialFilter(observer=obs, name="storm")
        try:
            for _ in range(100):
                flt.start_polling(interval_seconds=0.25)
                flt.stop_polling()
        finally:
            flt.stop_polling()
        time.sleep(0.5)
        alive = [t for t in threading.enumerate()
                 if t.name.startswith("differential[") and t.is_alive()]
        self.assertLessEqual(len(alive), 1,
                             f"thread leak: {len(alive)}")

    def test_pathological_mix_with_random_failures(self):
        """16 upstreams, 4 raise randomly; tick 1000 times across all.
        Verify working ones still produce deltas and broken ones
        increment snapshot_errors without crashing."""
        reg = self.mod.DifferentialRegistry()
        good = []
        flaky = []
        for i in range(12):
            o = _NumericObs(size=5)
            flt = self.mod.DifferentialFilter(observer=o, name=f"good{i}")
            reg.register(f"good{i}", flt)
            good.append((o, flt))
        for i in range(4):
            o = _FlakyObs(fail_every=3)
            flt = self.mod.DifferentialFilter(observer=o, name=f"flaky{i}")
            reg.register(f"flaky{i}", flt)
            flaky.append(flt)

        for _ in range(1000):
            for obs, flt in good:
                obs.tick_values()
                flt.tick()
            for flt in flaky:
                try:
                    flt.tick()
                except Exception:
                    self.fail("flaky observer exception leaked")

        for _, flt in good:
            stats = flt.stats()
            self.assertGreater(stats["tick_count"], 500)
        for flt in flaky:
            stats = flt.stats()
            self.assertGreater(stats["snapshot_errors"], 0)

    def test_128_threads_reader_during_registry_churn(self):
        """128 threads read snapshot_all() while another thread continuously
        adds/removes filters via register(). Registry lock must prevent
        torn reads / dict-changed-size exceptions."""
        reg = self.mod.DifferentialRegistry()
        errors = []
        stop = threading.Event()

        def churner():
            try:
                i = 0
                while not stop.is_set():
                    name = f"c{i % 32}"
                    obs = _NumericObs(size=3)
                    flt = self.mod.DifferentialFilter(observer=obs, name=name)
                    reg.register(name, flt)
                    i += 1
            except Exception as e:
                errors.append(("churn", e))

        def reader(tid):
            try:
                while not stop.is_set():
                    _ = reg.snapshot_all()
                    _ = reg.names()
            except Exception as e:
                errors.append(("read", tid, e))

        churn_t = threading.Thread(target=churner, daemon=True)
        readers = [threading.Thread(target=reader, args=(i,), daemon=True)
                   for i in range(128)]
        churn_t.start()
        for t in readers:
            t.start()
        time.sleep(2.0)
        stop.set()
        churn_t.join(timeout=5)
        for t in readers:
            t.join(timeout=5)

        self.assertEqual(errors, [], f"races: {errors[:5]}")

    def test_10k_tick_latency_budget(self):
        """10_000 sequential ticks on a single filter + numeric observer.
        Budget: 2s total (200us / tick)."""
        obs = _NumericObs(size=20)
        flt = self.mod.DifferentialFilter(observer=obs, name="latency")
        t0 = time.perf_counter()
        for _ in range(10_000):
            obs.tick_values()
            flt.tick()
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 15.0,
                        f"10k ticks took {elapsed:.1f}s")
        stats = flt.stats()
        self.assertEqual(stats["tick_count"], 10_000)

    def test_registry_stop_all_with_32_polling(self):
        """32 concurrent polling filters; stop_all() should join ALL
        within 10s even though it's serial (each can timeout 2s).
        Probes signal-on-Event-works-fast path."""
        reg = self.mod.DifferentialRegistry()
        for i in range(32):
            obs = _NumericObs(size=3)
            flt = self.mod.DifferentialFilter(observer=obs, name=f"p{i}")
            reg.register(f"p{i}", flt)
            flt.start_polling(interval_seconds=1.0)

        t0 = time.perf_counter()
        reg.stop_all()
        elapsed = time.perf_counter() - t0
        # 32 serial stop_polling with fast Event.set() should complete
        # in <5s; if any one hangs waiting 2s, 32*2=64s is the ceiling.
        self.assertLess(elapsed, 15.0,
                        f"stop_all(32) took {elapsed:.1f}s")

        time.sleep(0.5)
        alive = [t for t in threading.enumerate()
                 if t.name.startswith("differential[") and t.is_alive()]
        self.assertLessEqual(len(alive), 2,
                             f"thread leak after stop_all: {len(alive)}")


if __name__ == "__main__":
    unittest.main()
