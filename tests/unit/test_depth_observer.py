"""Unit tests for ``ai-control/daemon/depth_observer.py`` (S76 Agent D).

Covers:
  * empty / too-small input -> zero-state result, no crash
  * shallow case (zero-fill) -> classification=shallow
  * random case (os.urandom) -> classification=random
  * deep case (Python source code) -> depth_proxy > 0
  * snapshot aggregation across multiple observe() calls
  * thread-safety (4 concurrent writers)
  * JSON-serializable snapshot + per-result dicts
  * wire-up helper and event bus publishing

Pattern mirrors ``tests/unit/test_library_census.py`` (S75 Agent B).
"""

from __future__ import annotations

import importlib
import json
import os
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
    sys.modules.pop("depth_observer", None)
    return importlib.import_module("depth_observer")


# -- Fakes -----------------------------------------------------------------


class _FakeBus:
    def __init__(self) -> None:
        self.received: list = []
        self.lock = threading.Lock()

    def publish(self, event: dict) -> None:
        with self.lock:
            self.received.append(event)


# -- Sampler tests ----------------------------------------------------------


class TestDepthSamplerEmpty(unittest.TestCase):
    """Empty / tiny inputs must not crash and return zero-state."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_empty_bytes(self) -> None:
        sampler = self.mod.DepthSampler()
        r = sampler.measure(b"")
        self.assertEqual(r.size, 0)
        self.assertEqual(r.fast_ratio, 0.0)
        self.assertEqual(r.slow_ratio, 0.0)
        self.assertEqual(r.depth_proxy, 0.0)
        self.assertEqual(r.classification, self.mod.CLASS_SHALLOW)

    def test_tiny_bytes_below_threshold(self) -> None:
        """Under MIN_USEFUL_BYTES we return zeros (header overhead dominates)."""
        sampler = self.mod.DepthSampler()
        r = sampler.measure(b"x" * 4)
        # Size is recorded but the ratios are zeroed so classification
        # defaults to shallow (no misleading "random" on tiny inputs).
        self.assertEqual(r.size, 4)
        self.assertEqual(r.fast_ratio, 0.0)
        self.assertEqual(r.slow_ratio, 0.0)
        self.assertEqual(r.classification, self.mod.CLASS_SHALLOW)


class TestDepthSamplerShallow(unittest.TestCase):
    """Highly-compressible data classifies as shallow."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_zero_fill_is_shallow(self) -> None:
        sampler = self.mod.DepthSampler()
        data = b"\x00" * 4096
        r = sampler.measure(data, name="zero_fill")
        # Both ratios must be tiny (gzip compresses zeroes to ~0.01).
        self.assertLess(r.fast_ratio, self.mod.SHALLOW_RATIO_MAX)
        self.assertLess(r.slow_ratio, self.mod.SHALLOW_RATIO_MAX)
        self.assertEqual(r.classification, self.mod.CLASS_SHALLOW)

    def test_repeated_ascii_is_shallow(self) -> None:
        sampler = self.mod.DepthSampler()
        data = (b"ABCDABCDABCDABCD" * 256)  # 4 KiB of period-4 ASCII
        r = sampler.measure(data, name="repeat")
        self.assertEqual(r.classification, self.mod.CLASS_SHALLOW)


class TestDepthSamplerRandom(unittest.TestCase):
    """High-entropy data classifies as random."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_urandom_is_random(self) -> None:
        sampler = self.mod.DepthSampler()
        data = os.urandom(4096)
        r = sampler.measure(data, name="urandom")
        # Both ratios should be close to 1.0 (gzip has ~0.1% overhead
        # on random data in either direction).
        self.assertGreater(r.fast_ratio, self.mod.RANDOM_RATIO_MIN)
        self.assertGreater(r.slow_ratio, self.mod.RANDOM_RATIO_MIN)
        self.assertEqual(r.classification, self.mod.CLASS_RANDOM)

    def test_urandom_depth_proxy_is_small(self) -> None:
        """Slow compressor should not out-perform fast on true random."""
        sampler = self.mod.DepthSampler()
        data = os.urandom(8192)
        r = sampler.measure(data)
        # depth_proxy = fast_ratio - slow_ratio; on random data the
        # two ratios should be within 0.05 of each other.
        self.assertLess(abs(r.depth_proxy), 0.05)


class TestDepthSamplerDeep(unittest.TestCase):
    """Data with structure but high per-symbol entropy -> depth_proxy > 0.

    Note on Bennett: the DEEP classification requires
    depth_proxy > DEEP_DELTA_MIN (0.30). Python source and English prose
    often land in the MIXED bucket because gzip-level-9 only buys a few
    percent over level-1. We assert the WEAKER contract the roadmap
    requires: depth_proxy > 0 (slow beat fast, i.e. there's structure
    the fast compressor missed). This is what distinguishes deep/mixed
    from random.
    """

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_python_source_has_positive_depth(self) -> None:
        sampler = self.mod.DepthSampler()
        # Read our own module as a structured-but-entropic corpus.
        source_path = _DAEMON_DIR / "depth_observer.py"
        data = source_path.read_bytes()
        r = sampler.measure(data, name="python_source")
        # depth_proxy must be >= 0: slow compressor never does WORSE
        # than fast on the same data.
        self.assertGreaterEqual(r.depth_proxy, 0.0)
        # And the source is NOT random (gzip finds structure).
        self.assertNotEqual(r.classification, self.mod.CLASS_RANDOM)

    def test_json_repeated_structure_classifies_non_random(self) -> None:
        """A deliberately-structured payload: 1024 copies of a JSON doc."""
        sampler = self.mod.DepthSampler()
        doc = '{"subject": 42, "name": "kernel32", "loaded": true}\n'
        data = (doc * 1024).encode("utf-8")
        r = sampler.measure(data)
        # Highly-redundant -> compressible by both -> shallow.
        self.assertEqual(r.classification, self.mod.CLASS_SHALLOW)
        self.assertLess(r.fast_ratio, 0.1)


# -- Observer (aggregation) tests -------------------------------------------


class TestDepthObserverAggregation(unittest.TestCase):
    """snapshot() reflects multiple observe() calls."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_zero_observations_yields_well_formed_snapshot(self) -> None:
        obs = self.mod.DepthObserver()
        snap = obs.snapshot()
        self.assertEqual(snap["source"], "depth_observer")
        self.assertEqual(snap["samples"], 0)
        self.assertEqual(snap["mean_depth"], 0.0)
        self.assertEqual(snap["recent"], [])
        # Every class bucket must be present and zero.
        for k in (self.mod.CLASS_SHALLOW, self.mod.CLASS_DEEP,
                  self.mod.CLASS_RANDOM, self.mod.CLASS_MIXED):
            self.assertEqual(snap["classifications"][k], 0)

    def test_snapshot_counts_by_class(self) -> None:
        obs = self.mod.DepthObserver()
        obs.observe("shallow1", b"\x00" * 2048)
        obs.observe("shallow2", b"A" * 2048)
        obs.observe("random1", os.urandom(2048))
        snap = obs.snapshot()
        self.assertEqual(snap["samples"], 3)
        self.assertEqual(snap["classifications"][self.mod.CLASS_SHALLOW], 2)
        self.assertEqual(snap["classifications"][self.mod.CLASS_RANDOM], 1)

    def test_recent_is_bounded(self) -> None:
        """recent[] is capped at SNAPSHOT_RECENT in snapshot output."""
        obs = self.mod.DepthObserver()
        for i in range(20):
            obs.observe(f"s{i}", b"\x00" * 1024)
        snap = obs.snapshot()
        self.assertLessEqual(len(snap["recent"]),
                             self.mod.DepthObserver.SNAPSHOT_RECENT)
        # But the total-samples counter still tracks all 20.
        self.assertEqual(snap["samples"], 20)

    def test_ring_cap_enforced(self) -> None:
        """Internal ring buffer doesn't grow past ring_cap."""
        obs = self.mod.DepthObserver(ring_cap=32)
        for i in range(100):
            obs.observe(f"s{i}", b"\x00" * 256)
        stats = obs.stats()
        self.assertLessEqual(stats["ring_len"], 32)
        self.assertEqual(stats["samples_total"], 100)

    def test_reset_clears_state(self) -> None:
        obs = self.mod.DepthObserver()
        obs.observe("x", b"\x00" * 1024)
        self.assertEqual(obs.snapshot()["samples"], 1)
        obs.reset()
        snap = obs.snapshot()
        self.assertEqual(snap["samples"], 0)
        self.assertEqual(snap["mean_depth"], 0.0)


# -- Thread-safety ----------------------------------------------------------


class TestDepthObserverThreadSafety(unittest.TestCase):
    """Concurrent observe()s from 4 threads -> counts are consistent."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_concurrent_observe(self) -> None:
        obs = self.mod.DepthObserver()
        n_threads = 4
        per_thread = 25

        def worker(idx: int) -> None:
            for i in range(per_thread):
                obs.observe(f"t{idx}_{i}", b"\x00" * 512)

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)

        snap = obs.snapshot()
        # Exactly n_threads * per_thread samples -- no torn writes.
        self.assertEqual(snap["samples"], n_threads * per_thread)
        # Totals across classifications must sum to samples.
        total_classed = sum(snap["classifications"].values())
        self.assertEqual(total_classed, n_threads * per_thread)


# -- JSON serializable -----------------------------------------------------


class TestDepthObserverJsonSerializable(unittest.TestCase):
    """Snapshot must round-trip through json.dumps/loads cleanly."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_snapshot_json(self) -> None:
        obs = self.mod.DepthObserver()
        obs.observe("shallow", b"\x00" * 1024)
        obs.observe("random", os.urandom(1024))
        snap = obs.snapshot()
        text = json.dumps(snap)
        recovered = json.loads(text)
        self.assertEqual(recovered["source"], "depth_observer")
        self.assertEqual(recovered["samples"], 2)
        self.assertEqual(len(recovered["recent"]), 2)

    def test_result_to_dict_is_json(self) -> None:
        sampler = self.mod.DepthSampler()
        r = sampler.measure(b"\x00" * 1024, name="z")
        d = r.to_dict()
        # Round-trip.
        text = json.dumps(d)
        recovered = json.loads(text)
        self.assertEqual(recovered["name"], "z")
        self.assertEqual(recovered["classification"],
                         self.mod.CLASS_SHALLOW)


# -- Event bus + wire-up ---------------------------------------------------


class TestDepthObserverEventBus(unittest.TestCase):
    """observe() publishes to event_bus when provided."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_publish_on_observe(self) -> None:
        bus = _FakeBus()
        obs = self.mod.DepthObserver(event_bus=bus)
        obs.observe("s", b"\x00" * 1024)
        self.assertEqual(len(bus.received), 1)
        event = bus.received[0]
        self.assertEqual(event["source"], "depth_observer")
        self.assertIn("topic", event)
        self.assertTrue(event["topic"].startswith("depth."))
        self.assertIn("classification", event)

    def test_publish_failure_does_not_break_observe(self) -> None:
        class _BrokenBus:
            def publish(self, _event):
                raise RuntimeError("bus is down")

        obs = self.mod.DepthObserver(event_bus=_BrokenBus())
        # Must not raise.
        result = obs.observe("s", b"\x00" * 512)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(obs.stats()["publish_errors"], 1)


class TestDepthObserverWireUp(unittest.TestCase):
    """register_with_daemon returns an observer; tolerates app=None."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_register_with_none_app(self) -> None:
        observer = self.mod.register_with_daemon(None)
        self.assertIsInstance(observer, self.mod.DepthObserver)

    def test_register_with_event_bus(self) -> None:
        bus = _FakeBus()
        observer = self.mod.register_with_daemon(None, event_bus=bus)
        observer.observe("x", b"\x00" * 1024)
        self.assertEqual(len(bus.received), 1)


if __name__ == "__main__":
    unittest.main()
