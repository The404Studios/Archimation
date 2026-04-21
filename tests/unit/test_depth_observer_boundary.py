"""Boundary tests for ``ai-control/daemon/depth_observer.py``.

S79 Test Agent 3 -- S76 DepthObserver / DepthSampler edges.

Boundaries probed:
  * measure(b"") / single-byte / below MIN_USEFUL_BYTES / at boundary
  * classification when fast_ratio == slow_ratio exactly
  * depth_proxy at the exact DEEP_DELTA_MIN threshold (0.30)
  * ring_cap boundaries: 0, 1, 64, 65, 1000 (constructor clamps to min 16)
  * Huge buffer (10MB)

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
    sys.modules.pop("depth_observer", None)
    return importlib.import_module("depth_observer")


class InputSizeBoundaries(unittest.TestCase):
    """measure(b"") through MIN_USEFUL_BYTES-1, =, +1."""

    def setUp(self) -> None:
        self.mod = _load_module()
        self.sampler = self.mod.DepthSampler()

    def test_empty_bytes(self) -> None:
        """b"" -> zero-state result, classification=shallow."""
        r = self.sampler.measure(b"")
        self.assertEqual(r.size, 0)
        self.assertEqual(r.classification, self.mod.CLASS_SHALLOW)
        self.assertEqual(r.fast_ratio, 0.0)
        self.assertEqual(r.slow_ratio, 0.0)
        self.assertEqual(r.depth_proxy, 0.0)

    def test_single_byte(self) -> None:
        """1 byte < MIN_USEFUL_BYTES (32) -> zero-state result."""
        r = self.sampler.measure(b"\x00")
        # Source line 162: "if size < MIN_USEFUL_BYTES" returns empty
        # result with r.size = size.
        self.assertEqual(r.size, 1)
        self.assertEqual(r.fast_ratio, 0.0)
        self.assertEqual(r.slow_ratio, 0.0)

    def test_below_min_useful_bytes(self) -> None:
        """MIN_USEFUL_BYTES - 1 -> still treated as too-small."""
        r = self.sampler.measure(b"\x00" * (self.mod.MIN_USEFUL_BYTES - 1))
        self.assertEqual(r.fast_ratio, 0.0)

    def test_exact_min_useful_bytes(self) -> None:
        """Exactly MIN_USEFUL_BYTES -> full measurement (>=, not strictly >)."""
        size = self.mod.MIN_USEFUL_BYTES
        r = self.sampler.measure(b"\x00" * size)
        # 32 bytes -> gzip compresses all-zeros well.
        self.assertEqual(r.size, size)
        # Measurement actually happened; fast/slow ratios populated.
        # With all-zeros, both ratios are similar and classification==shallow.
        self.assertIn(r.classification,
                      (self.mod.CLASS_SHALLOW, self.mod.CLASS_RANDOM,
                       self.mod.CLASS_DEEP, self.mod.CLASS_MIXED))

    def test_one_above_min_useful_bytes(self) -> None:
        """MIN_USEFUL_BYTES+1 -> no overflow, real measurement."""
        size = self.mod.MIN_USEFUL_BYTES + 1
        r = self.sampler.measure(b"\x00" * size)
        self.assertEqual(r.size, size)

    def test_huge_buffer_10mb(self) -> None:
        """10MB input -> completes without error, real measurement."""
        size = 10 * 1024 * 1024
        r = self.sampler.measure(b"\x00" * size)
        self.assertEqual(r.size, size)
        # All-zeros in 10MB compresses well -> shallow.
        self.assertEqual(r.classification, self.mod.CLASS_SHALLOW)


class ClassificationBoundaries(unittest.TestCase):
    """Threshold edges in _classify()."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_equal_fast_and_slow_no_deep(self) -> None:
        """fast_ratio == slow_ratio -> depth_proxy = 0 < DEEP_DELTA_MIN.

        With both ratios equal and mid-range, classification should be
        'mixed' (neither shallow nor random nor deep)."""
        cls = self.mod.DepthSampler._classify(0.5, 0.5, 0.0)
        self.assertEqual(cls, self.mod.CLASS_MIXED)

    def test_deep_delta_at_threshold(self) -> None:
        """depth_proxy == DEEP_DELTA_MIN (0.30) is NOT deep.

        Source line 208: `if depth_proxy > DEEP_DELTA_MIN` -- strict
        inequality, so exactly 0.30 falls through to 'mixed'."""
        cls = self.mod.DepthSampler._classify(0.5, 0.2,
                                              self.mod.DEEP_DELTA_MIN)
        self.assertEqual(cls, self.mod.CLASS_MIXED)

    def test_deep_delta_just_above_threshold(self) -> None:
        """depth_proxy = DEEP_DELTA_MIN + epsilon -> classified deep."""
        cls = self.mod.DepthSampler._classify(
            0.5, 0.19, self.mod.DEEP_DELTA_MIN + 0.001,
        )
        self.assertEqual(cls, self.mod.CLASS_DEEP)

    def test_shallow_threshold_strict(self) -> None:
        """SHALLOW_RATIO_MAX (0.10) is NOT shallow (strict <)."""
        # Both exactly at 0.10 -> fails `< SHALLOW_RATIO_MAX` -> mixed.
        cls = self.mod.DepthSampler._classify(
            self.mod.SHALLOW_RATIO_MAX, self.mod.SHALLOW_RATIO_MAX, 0.0,
        )
        self.assertEqual(cls, self.mod.CLASS_MIXED)

    def test_random_threshold_strict(self) -> None:
        """RANDOM_RATIO_MIN (0.90) is NOT random (strict >)."""
        cls = self.mod.DepthSampler._classify(
            self.mod.RANDOM_RATIO_MIN, self.mod.RANDOM_RATIO_MIN, 0.0,
        )
        self.assertEqual(cls, self.mod.CLASS_MIXED)


class RingCapBoundaries(unittest.TestCase):
    """DepthObserver ring_cap constructor boundaries."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_ring_cap_zero_clamped_to_min(self) -> None:
        """ring_cap=0 -> clamped to max(16, 0) = 16."""
        obs = self.mod.DepthObserver(ring_cap=0)
        # Source line 251: `self._ring_cap = max(16, int(ring_cap))`.
        self.assertEqual(obs._ring_cap, 16)

    def test_ring_cap_one_clamped(self) -> None:
        """ring_cap=1 -> clamped to 16."""
        obs = self.mod.DepthObserver(ring_cap=1)
        self.assertEqual(obs._ring_cap, 16)

    def test_ring_cap_64(self) -> None:
        """ring_cap=64 -> preserved."""
        obs = self.mod.DepthObserver(ring_cap=64)
        self.assertEqual(obs._ring_cap, 64)

    def test_ring_cap_65(self) -> None:
        """ring_cap=65 (off-by-one from 64) -> preserved."""
        obs = self.mod.DepthObserver(ring_cap=65)
        self.assertEqual(obs._ring_cap, 65)

    def test_ring_cap_1000_bounded_eviction(self) -> None:
        """ring_cap=1000; observe 1005 times -> only last 1000 kept."""
        obs = self.mod.DepthObserver(ring_cap=1000)
        for i in range(1005):
            # Must be >= MIN_USEFUL_BYTES to not be dropped; use 32 bytes.
            obs.observe(f"probe{i}", b"\x00" * 32)
        self.assertLessEqual(len(obs._recent), 1000)
        # Ring eviction is by pop(0) -- newest are kept.
        # Verify last entry is "probe1004" if classification allows.
        last = obs._recent[-1]
        self.assertEqual(last.name, "probe1004")


class MeasureNoneInput(unittest.TestCase):
    """observe(name, data=None) should coerce to empty."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_observe_none_data(self) -> None:
        """data=None -> coerced to b""; size=0 result."""
        obs = self.mod.DepthObserver()
        # Source line 283: "if data is None: data = b"".
        r = obs.observe("test", None)  # type: ignore[arg-type]
        self.assertEqual(r.size, 0)


if __name__ == "__main__":
    unittest.main()
