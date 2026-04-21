"""End-to-end: depth_observer classification + event bus publish (S76 Agent D).

Pipeline exercised
------------------
    caller-supplied bytes (4 KB)  [observer is call-driven, not poll]
            |
            v
    DepthObserver.observe(name, data)
            -> DepthSampler.measure (fast gzip + slow gzip ratios)
            -> classify: shallow / deep / random / mixed
            -> _publish(event) on the bus
            -> fold into snapshot aggregator
            |
            v
    DepthObserver.snapshot()  -> {classifications: {...}, mean_depth: ...}

This scenario is the one ransomware-discrimination case in the S76
roadmap: encrypted payloads classify as 'random', normal program
output classifies as 'deep' (slow compressor finds structure the fast
one missed), and zero-fill classifies as 'shallow'. The unit test
covers the classifier; the integration test verifies the classifier +
aggregator + event-bus publish all agree.

S77 Agent 5 deliverable.
"""

from __future__ import annotations

import os
import sys
import threading
import unittest
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from _s77_helpers import load_daemon_module  # noqa: E402


class _FakeBus:
    def __init__(self) -> None:
        self.events: list = []
        self.lock = threading.Lock()

    def publish(self, event: dict) -> None:
        with self.lock:
            self.events.append(event)


class DepthObserverE2EBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.do = load_daemon_module("depth_observer", unique_suffix="_e2e")


class TestDepthClassification(DepthObserverE2EBase):
    """Drive three distinct buffer types through the observer and assert
    each lands in its expected classification bucket."""

    def test_zero_fill_is_shallow(self) -> None:
        """4 KB of zeros -> both compressors shrink dramatically -> shallow."""
        obs = self.do.DepthObserver()
        result = obs.observe("zeros", b"\x00" * 4096)
        self.assertEqual(result.classification, self.do.CLASS_SHALLOW)
        self.assertLess(result.fast_ratio, 0.10)
        self.assertLess(result.slow_ratio, 0.10)

    def test_urandom_is_random(self) -> None:
        """4 KB of os.urandom -> neither compressor finds structure -> random."""
        obs = self.do.DepthObserver()
        result = obs.observe("random", os.urandom(4096))
        self.assertEqual(result.classification, self.do.CLASS_RANDOM)
        self.assertGreater(result.fast_ratio, 0.90)
        self.assertGreater(result.slow_ratio, 0.90)

    def test_repeated_structured_prose_is_compressible(self) -> None:
        """Highly-repetitive prose -> both compressors shrink well, but
        the structure is shallow (low-entropy). This catches cases where
        the classifier mis-buckets compressible text.

        We use a deliberately repetitive corpus so it lands firmly in
        'shallow' — testing 'deep' requires carefully-constructed data
        where the slow compressor beats the fast one by > DEEP_DELTA_MIN
        (0.30), which is NOT something we can guarantee for arbitrary
        code/prose without a calibrated corpus."""
        obs = self.do.DepthObserver()
        pattern = (b"The quick brown fox jumps over the lazy dog. " * 100)
        # Pad to 4 KB so size is comparable to other buffers.
        data = (pattern * 2)[:4096]
        result = obs.observe("prose", data)
        self.assertIn(result.classification,
                      (self.do.CLASS_SHALLOW, self.do.CLASS_DEEP,
                       self.do.CLASS_MIXED))
        # And critically: NOT random.
        self.assertNotEqual(result.classification, self.do.CLASS_RANDOM)

    def test_empty_buffer_returns_zero_state(self) -> None:
        """Empty input -> size=0 result; no crash."""
        obs = self.do.DepthObserver()
        result = obs.observe("empty", b"")
        self.assertEqual(result.size, 0)
        self.assertEqual(result.classification, self.do.CLASS_SHALLOW)


class TestDepthSnapshotAggregation(DepthObserverE2EBase):
    """Multiple observations fold into the snapshot counters."""

    def test_snapshot_aggregates_mixed_stream(self) -> None:
        obs = self.do.DepthObserver()
        # Pump 3 shallow + 3 random through.
        for i in range(3):
            obs.observe(f"shallow_{i}", b"\x00" * 4096)
        for i in range(3):
            obs.observe(f"random_{i}", os.urandom(4096))
        snap = obs.snapshot()
        self.assertEqual(snap["samples"], 6)
        self.assertEqual(snap["classifications"][self.do.CLASS_SHALLOW], 3)
        self.assertEqual(snap["classifications"][self.do.CLASS_RANDOM], 3)
        # Recent ring captures most recent observations.
        self.assertLessEqual(len(snap["recent"]), self.do.DepthObserver.SNAPSHOT_RECENT)

    def test_snapshot_pre_observation_is_zero_state(self) -> None:
        obs = self.do.DepthObserver()
        snap = obs.snapshot()
        self.assertEqual(snap["samples"], 0)
        self.assertEqual(snap["mean_depth"], 0.0)
        self.assertEqual(snap["classifications"][self.do.CLASS_SHALLOW], 0)


class TestDepthBusPublish(DepthObserverE2EBase):
    """Observer publishes each measurement to the event bus."""

    def test_bus_receives_classification_event(self) -> None:
        bus = _FakeBus()
        obs = self.do.DepthObserver(event_bus=bus)
        obs.observe("zeros", b"\x00" * 4096)
        obs.observe("random", os.urandom(4096))
        # Bus received one event per observation.
        self.assertEqual(len(bus.events), 2)
        for ev in bus.events:
            self.assertEqual(ev["source"], "depth_observer")
            self.assertIn(ev["classification"],
                          (self.do.CLASS_SHALLOW, self.do.CLASS_DEEP,
                           self.do.CLASS_RANDOM, self.do.CLASS_MIXED))
            # Topic encodes the classification -- used by bus filters.
            self.assertTrue(ev["topic"].startswith("depth."),
                            ev["topic"])

    def test_bus_failure_counted_not_raised(self) -> None:
        """_publish swallows bus exceptions to keep the observer alive."""

        class _BrokenBus:
            def publish(self, event):
                raise RuntimeError("bus offline")

        obs = self.do.DepthObserver(event_bus=_BrokenBus())
        # Must not raise.
        obs.observe("zeros", b"\x00" * 4096)
        self.assertEqual(obs.stats()["publish_errors"], 1)


class TestRansomwareDiscriminationScenario(DepthObserverE2EBase):
    """End-to-end of the ransomware-discrimination signal: a workflow
    where 'normal' output is mixed/shallow and 'encrypted' output is
    distinctively 'random'.

    The classifier's design intent is that encryption is the ONLY
    common producer of 'random' output, so a cortex policy that fires
    on runs-of-random-hits has ransomware as its foremost positive."""

    def test_random_blob_is_distinctive(self) -> None:
        """Encrypted-blob proxy classifies as random; a structured prose
        control does NOT. If the classifier's signal collapses (e.g. both
        end up 'mixed'), this test fails."""
        obs = self.do.DepthObserver()
        r_encrypted = obs.observe("ransom_proxy", os.urandom(4096))
        r_normal = obs.observe("normal_proxy",
                               b"import os\n" * 500)  # Python source proxy
        self.assertEqual(r_encrypted.classification, self.do.CLASS_RANDOM)
        self.assertNotEqual(r_normal.classification, self.do.CLASS_RANDOM,
                            f"normal data mis-classified as random: "
                            f"{r_normal}")


if __name__ == "__main__":
    unittest.main()
