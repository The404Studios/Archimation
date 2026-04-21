"""Stress tests for ``ai-control/daemon/depth_observer.py`` (S77 Agent 2).

These tests probe failure modes that fixed-N unit tests miss:
  * large-buffer compression (10MB random + 10MB zeros + 10MB source)
  * thousands of observe() calls from many threads without OOM
  * classification stability across pathological inputs
  * ring-cap invariants under floods
  * reset() correctness under concurrent observe()

Gated behind ``STRESS_TESTS=1`` so CI runs aren't slowed. Run with::

    cd tests/unit && STRESS_TESTS=1 python -m unittest test_depth_observer_stress -v

S77 Agent 2 deliverable.
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


class _FakeBus:
    def __init__(self):
        self.count = 0
        self.lock = threading.Lock()

    def publish(self, event):
        with self.lock:
            self.count += 1


@unittest.skipUnless(STRESS_ENABLED, "stress tests disabled (set STRESS_TESTS=1)")
class TestDepthObserverStress(unittest.TestCase):

    def setUp(self):
        self.mod = _load_module()

    def test_large_buffer_interleaved_classification(self):
        """Feed 2MB of zero-fill + 2MB of urandom + 2MB of repeated
        Python source to the observer interleaved. Classifications must
        stay in {shallow, deep, random, mixed} and the counts for
        shallow+random must each be >= 2 (we fed at least 2 batches of
        each). Uses 2MB rather than 10MB to keep the test under 30s."""
        obs = self.mod.DepthObserver(ring_cap=512)

        zeros = b"\x00" * (2 * 1024 * 1024)
        rand_bytes = os.urandom(2 * 1024 * 1024)
        src_chunk = (b"def hello():\n    return 'world'\n" * 32768)[:2 * 1024 * 1024]

        valid = {self.mod.CLASS_SHALLOW, self.mod.CLASS_DEEP,
                 self.mod.CLASS_RANDOM, self.mod.CLASS_MIXED}

        batches = [("zeros", zeros), ("rand", rand_bytes), ("src", src_chunk)] * 2
        random.Random(0).shuffle(batches)

        start = time.perf_counter()
        for name, data in batches:
            r = obs.observe(name, data)
            self.assertIn(r.classification, valid)
        elapsed = time.perf_counter() - start
        # gzip-9 on 12MB total should be well under 60s on any host.
        self.assertLess(elapsed, 120.0,
                        f"compression too slow: {elapsed:.1f}s")

        snap = obs.snapshot()
        self.assertEqual(snap["samples"], len(batches))
        shallow_cnt = snap["classifications"][self.mod.CLASS_SHALLOW]
        random_cnt = snap["classifications"][self.mod.CLASS_RANDOM]
        self.assertGreaterEqual(shallow_cnt, 2,
                                f"zeros not classified shallow: {snap}")
        self.assertGreaterEqual(random_cnt, 2,
                                f"urandom not classified random: {snap}")

    def test_ring_cap_invariant_under_flood(self):
        """10_000 observe() calls must never grow the ring beyond
        ring_cap. Also probes that the mean statistics stay finite."""
        obs = self.mod.DepthObserver(ring_cap=64)
        buf = b"A" * 256
        for i in range(10_000):
            obs.observe(f"x{i}", buf)
        snap = obs.snapshot()
        self.assertEqual(snap["samples"], 10_000)
        self.assertLessEqual(len(obs._recent), 64)
        for k in ("mean_fast_ratio", "mean_slow_ratio", "mean_depth"):
            self.assertTrue(isinstance(snap[k], float))
            self.assertFalse(snap[k] != snap[k],  # NaN check
                             f"{k} is NaN")

    def test_concurrent_observe_no_accumulator_tear(self):
        """32 threads each calling observe() 500 times. Final
        samples_total must equal 32*500 exactly (no lost increments)
        and per-classification counts must sum to that total."""
        obs = self.mod.DepthObserver(ring_cap=256)
        buf = b"deadbeef" * 1024  # 8KB compressible buffer

        def worker():
            for _ in range(500):
                obs.observe("w", buf)

        threads = [threading.Thread(target=worker) for _ in range(32)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
            self.assertFalse(t.is_alive())
        snap = obs.snapshot()
        self.assertEqual(snap["samples"], 32 * 500)
        total_class = sum(snap["classifications"].values())
        self.assertEqual(total_class, 32 * 500,
                         "classification counts don't sum to samples")

    def test_reset_during_concurrent_observe(self):
        """Reset() called mid-flight against 4 producer threads. After
        producers finish and a final snapshot taken, all counters must
        be self-consistent (samples >= classification-sum after the
        post-reset writes). Probes lock contention between reset/observe."""
        obs = self.mod.DepthObserver(ring_cap=64)
        buf = b"x" * 512

        stop = threading.Event()

        def producer():
            while not stop.is_set():
                obs.observe("p", buf)

        threads = [threading.Thread(target=producer, daemon=True) for _ in range(4)]
        for t in threads:
            t.start()
        time.sleep(0.2)
        for _ in range(20):
            obs.reset()
            time.sleep(0.01)
        stop.set()
        for t in threads:
            t.join(timeout=5)

        snap = obs.snapshot()
        total_class = sum(snap["classifications"].values())
        # After reset, samples and classifications should stay in sync;
        # the important invariant is no negative counts and no crash.
        self.assertGreaterEqual(snap["samples"], 0)
        self.assertEqual(total_class, snap["samples"],
                         f"reset/observe race: samples={snap['samples']} "
                         f"class_sum={total_class}")

    def test_malformed_input_types(self):
        """observe() must handle None, and non-bytes inputs raise (as
        documented by dataclass/gzip path). None -> zero-result."""
        obs = self.mod.DepthObserver()

        # None is documented as "treated as b''".
        r = obs.observe("none", None)
        self.assertEqual(r.size, 0)

        # Non-bytes -- gzip.compress will raise; observe() lets it
        # bubble up (or _compress_size returns len(data)). Just make
        # sure nothing corrupts internal state.
        try:
            obs.observe("bad", "a string not bytes")
        except Exception:
            pass
        snap = obs.snapshot()
        self.assertGreaterEqual(snap["samples"], 1)

    def test_publish_failure_backpressure(self):
        """Bus that always raises must increment publish_errors without
        losing observations."""

        class _BadBus:
            def publish(self, event):
                raise RuntimeError("bus full")

        obs = self.mod.DepthObserver(event_bus=_BadBus())
        for _ in range(1000):
            obs.observe("x", b"A" * 128)
        stats = obs.stats()
        self.assertEqual(stats["samples_total"], 1000)
        self.assertGreaterEqual(stats["publish_errors"], 1000)


if __name__ == "__main__":
    unittest.main()
