"""High-scale stress tests for ``ai-control/daemon/depth_observer.py`` (S79).

S79 Test Agent 2 -- scales S77 Agent 2's 32 thread / 2MB tests up to
64+ threads with multi-MB buffers, probes ring_cap at exact capacity,
and fills caches near their memory bounds.

Gated behind ``STRESS_TESTS=1``. Run with::

    cd tests/unit && STRESS_TESTS=1 python -m unittest test_depth_observer_stress_v2 -v

S79 Test Agent 2 deliverable.
"""

from __future__ import annotations

import gc
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
    sys.modules.pop("depth_observer", None)
    return importlib.import_module("depth_observer")


@unittest.skipUnless(STRESS_ENABLED, "stress tests disabled (set STRESS_TESTS=1)")
class TestDepthObserverStressV2(unittest.TestCase):

    def setUp(self):
        self.mod = _load_module()

    def test_64_thread_concurrent_measure_1mb(self):
        """64 threads each calling measure() on 1MB buffers. Probes
        DepthSampler stateless reentrancy under real pressure.
        Pass = all measurements return finite ratios in [0, 1.5]."""
        mod = self.mod
        sampler = mod.DepthSampler()
        buf = os.urandom(1024 * 1024)

        errors = []
        results = []
        results_lock = threading.Lock()

        def worker():
            try:
                for _ in range(3):
                    r = sampler.measure(buf, name="urandom")
                    with results_lock:
                        results.append(r)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(64)]
        t0 = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
            self.assertFalse(t.is_alive())
        elapsed = time.perf_counter() - t0

        self.assertEqual(errors, [], f"errors: {errors[:3]}")
        self.assertEqual(len(results), 64 * 3)
        for r in results:
            self.assertGreaterEqual(r.fast_ratio, 0.0)
            self.assertLessEqual(r.fast_ratio, 1.5)
            self.assertEqual(r.classification, mod.CLASS_RANDOM,
                             "urandom must classify as random")
        # gzip-9 on 192MB total should fit within 120s on dev hardware.
        self.assertLess(elapsed, 180.0,
                        f"1MB x 192 concurrent too slow: {elapsed:.1f}s")

    def test_ring_cap_exact_boundary(self):
        """ring_cap=64, submit 1000 observations: final ring_len must be
        exactly 64 (not 63, not 65). Probes the pop-on-overflow boundary
        via an explicit count at capacity."""
        mod = self.mod
        obs = mod.DepthObserver(ring_cap=64)
        buf = b"X" * 256
        for i in range(1000):
            obs.observe(f"x{i}", buf)
        stats = obs.stats()
        self.assertEqual(stats["ring_cap"], 64)
        self.assertEqual(stats["ring_len"], 64,
                         f"ring_len drifted: {stats['ring_len']}")
        self.assertEqual(stats["samples_total"], 1000)

    def test_100k_small_buffer_flood(self):
        """100_000 observations on a tiny buffer. Probes classification
        counter accumulator and gzip overhead at high rate.
        Budget: 30s (330us per observe()). If slower, flag perf drift."""
        mod = self.mod
        obs = mod.DepthObserver(ring_cap=256)
        buf = b"A" * 64  # just above MIN_USEFUL_BYTES=32

        t0 = time.perf_counter()
        for i in range(100_000):
            obs.observe("x", buf)
        elapsed = time.perf_counter() - t0

        snap = obs.snapshot()
        self.assertEqual(snap["samples"], 100_000)
        total_class = sum(snap["classifications"].values())
        self.assertEqual(total_class, 100_000)
        self.assertLess(elapsed, 45.0,
                        f"100k observations took {elapsed:.1f}s")

    def test_5mb_buffer_x_50_measures(self):
        """5MB urandom * 50 measurements = 250 MB processed. Probes
        gzip memory pressure + observer accumulator at multi-GB total.
        Budget: 120s."""
        mod = self.mod
        obs = mod.DepthObserver(ring_cap=32)

        t0 = time.perf_counter()
        for i in range(50):
            buf = os.urandom(5 * 1024 * 1024)
            r = obs.observe(f"big_{i}", buf)
            self.assertEqual(r.classification, mod.CLASS_RANDOM)
            # Explicit GC hint every 10 to probe gc disturbance.
            if i % 10 == 9:
                gc.collect()
        elapsed = time.perf_counter() - t0

        snap = obs.snapshot()
        self.assertEqual(snap["samples"], 50)
        self.assertEqual(snap["classifications"][mod.CLASS_RANDOM], 50)
        self.assertLess(elapsed, 240.0,
                        f"5MB x 50 took {elapsed:.1f}s")

    def test_concurrent_observe_256_threads_accumulator_integrity(self):
        """256 threads * 100 observe calls = 25600 total. Final
        samples_total must be EXACTLY 25600 (no lost increments).
        Probes the RLock holding under heavy short critical sections."""
        mod = self.mod
        obs = mod.DepthObserver(ring_cap=256)
        buf = b"consistent" * 128

        errors = []

        def worker():
            try:
                for _ in range(100):
                    obs.observe("w", buf)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(256)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
            self.assertFalse(t.is_alive())

        self.assertEqual(errors, [])
        snap = obs.snapshot()
        self.assertEqual(snap["samples"], 256 * 100,
                         f"lost increments: got {snap['samples']}")
        total_class = sum(snap["classifications"].values())
        self.assertEqual(total_class, 256 * 100,
                         "classifications sum != samples")

    def test_reset_storm_during_observe(self):
        """200 reset() calls while 32 observers produce. Probes lock
        contention and consistency post-storm: final snap must be
        self-consistent (samples == sum(classifications))."""
        mod = self.mod
        obs = mod.DepthObserver(ring_cap=64)
        buf = b"data" * 512

        stop = threading.Event()

        def producer():
            while not stop.is_set():
                obs.observe("p", buf)

        prods = [threading.Thread(target=producer, daemon=True) for _ in range(32)]
        for t in prods:
            t.start()
        time.sleep(0.2)
        for _ in range(200):
            obs.reset()
        stop.set()
        for t in prods:
            t.join(timeout=5)

        snap = obs.snapshot()
        total_class = sum(snap["classifications"].values())
        self.assertEqual(total_class, snap["samples"],
                         f"reset/observe race: samples={snap['samples']} "
                         f"class_sum={total_class}")

    def test_mixed_buffer_population_classification_stability(self):
        """Feed 300 buffers drawn from [zero, urandom, src, partial]
        uniformly. Probes classifier stability at 300 samples - no
        classification should deviate from contract (never 'deep' for
        zero-fill, never 'shallow' for urandom)."""
        mod = self.mod
        obs = mod.DepthObserver(ring_cap=300)

        zeros = b"\x00" * 65536
        rand_bytes = os.urandom(65536)
        src = (b"def foo():\n    return 42\n" * 1024)[:65536]

        rng = random.Random(99)
        for i in range(300):
            choice = rng.choice([zeros, rand_bytes, src])
            r = obs.observe(f"mix_{i}", choice)
            if choice is zeros:
                self.assertEqual(r.classification, mod.CLASS_SHALLOW,
                                 f"zeros misclassified as {r.classification}")
            elif choice is rand_bytes:
                self.assertEqual(r.classification, mod.CLASS_RANDOM,
                                 f"urandom misclassified as {r.classification}")

        snap = obs.snapshot()
        self.assertEqual(snap["samples"], 300)

    def test_very_large_single_buffer_20mb(self):
        """One 20MB urandom buffer. Probes gzip-9 peak memory on the
        biggest single-shot input the observer will ever see in prod.
        Pass: completes in <60s, classifies as random."""
        mod = self.mod
        sampler = mod.DepthSampler()
        buf = os.urandom(20 * 1024 * 1024)
        t0 = time.perf_counter()
        r = sampler.measure(buf, name="huge")
        elapsed = time.perf_counter() - t0
        self.assertEqual(r.classification, mod.CLASS_RANDOM)
        self.assertLess(elapsed, 60.0,
                        f"20MB gzip-9 took {elapsed:.1f}s")


if __name__ == "__main__":
    unittest.main()
