"""Boundary tests for ``ai-control/cortex/monte_carlo.py``.

S79 Test Agent 3 -- edges in ConfidenceSampler, RolloutSearch,
StochasticRateLimiter.

Boundaries probed:
  * ConfidenceSampler.calibrated(0.0) / 1.0 / 0.5
  * calibrated(-0.0001) / 1.0001 -- out-of-band, should clip
  * calibrated(NaN) -- document behavior
  * RolloutSearch.recommend([]) -- no actions
  * RolloutSearch.recommend(["a"], n_rollouts=0) -- no rollouts
  * StochasticRateLimiter.consume(0)
  * StochasticRateLimiter.consume(-1) -- document (granted/denied?)
  * StochasticRateLimiter.consume(int_max) -- clamp or fail?

Not gated. Must complete <5s.
"""

from __future__ import annotations

import importlib.util
import math
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_MC_PATH = _REPO_ROOT / "ai-control" / "cortex" / "monte_carlo.py"


def _load_monte_carlo():
    name = "cortex_monte_carlo_boundary"
    spec = importlib.util.spec_from_file_location(name, _MC_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class ConfidenceSamplerCalibratedBoundaries(unittest.TestCase):
    """calibrated(base_confidence): input ranges and NaN handling."""

    def setUp(self) -> None:
        self.mod = _load_monte_carlo()
        # Use deterministic_mean so the returned value is the posterior
        # mean (deterministic): easier to reason about.
        self.cs = self.mod.ConfidenceSampler(
            seed=42, deterministic_mean=True,
        )

    def test_zero_confidence(self) -> None:
        """calibrated(0.0) -> alpha=1, beta=1+10=11 -> mean=1/12."""
        v = self.cs.calibrated(0.0)
        self.assertAlmostEqual(v, 1.0 / 12.0, places=5)

    def test_one_confidence(self) -> None:
        """calibrated(1.0) -> alpha=11, beta=1 -> mean=11/12."""
        v = self.cs.calibrated(1.0)
        self.assertAlmostEqual(v, 11.0 / 12.0, places=5)

    def test_half_confidence(self) -> None:
        """calibrated(0.5) -> alpha=6, beta=6 -> mean=0.5."""
        v = self.cs.calibrated(0.5)
        self.assertAlmostEqual(v, 0.5, places=5)

    def test_below_zero_is_clipped(self) -> None:
        """calibrated(-0.0001) -> base clipped to 0.0 -> mean=1/12.

        Source line 749: `base = max(0.0, min(1.0, float(base_confidence)))`."""
        v = self.cs.calibrated(-0.0001)
        self.assertAlmostEqual(v, 1.0 / 12.0, places=5)

    def test_above_one_is_clipped(self) -> None:
        """calibrated(1.0001) -> base clipped to 1.0 -> mean=11/12."""
        v = self.cs.calibrated(1.0001)
        self.assertAlmostEqual(v, 11.0 / 12.0, places=5)

    def test_nan_behavior_documented(self) -> None:
        """calibrated(NaN) -> silently clipped to 1.0 on CPython.

        Documented behavior: ``min(1.0, NaN)`` in CPython returns 1.0
        (because ``1.0 < NaN`` is False so min keeps its left arg). Then
        ``max(0.0, 1.0)`` returns 1.0, so base becomes 1.0, alpha=11,
        beta=1, posterior mean=11/12.

        This is a CONTRACT GAP: a NaN input silently becomes "confidence
        1.0" rather than raising. Source line 749 in monte_carlo.py
        should arguably guard against NaN explicitly. We lock in the
        current behavior so any future change surfaces as a failing
        boundary test."""
        v = self.cs.calibrated(float("nan"))
        # Confirmed behavior: NaN is silently treated as 1.0.
        self.assertAlmostEqual(v, 11.0 / 12.0, places=5,
                               msg=f"CPython NaN clip behavior changed: {v}")


class RolloutSearchBoundaries(unittest.TestCase):
    """RolloutSearch.recommend with empty actions / zero rollouts."""

    def setUp(self) -> None:
        self.mod = _load_monte_carlo()
        self.rs = self.mod.RolloutSearch(seed=42, n_rollouts=8)

    def test_empty_actions_list(self) -> None:
        """recommend([]) -> best_action=None, ranked=[]."""
        rec = self.rs.recommend([], reward_fn=lambda a, rng: rng.random())
        self.assertIsNone(rec["best_action"])
        self.assertEqual(rec["ranked"], [])

    def test_zero_rollouts(self) -> None:
        """recommend(["a"], n_rollouts=0) -> NaN reward mean.

        With 0 rollouts, rewards list is empty, below MIN_VALID_SAMPLES,
        so reward_mean=NaN. best_action=None because no valid rewards."""
        rec = self.rs.recommend(
            ["a"], reward_fn=lambda a, rng: rng.random(), n_rollouts=0,
        )
        self.assertIsNone(rec["best_action"])
        self.assertEqual(len(rec["ranked"]), 1)
        self.assertTrue(math.isnan(rec["ranked"][0]["reward_mean"]))
        self.assertEqual(rec["ranked"][0]["n_rollouts"], 0)

    def test_single_action_normal_rollouts(self) -> None:
        """recommend(["a"], n_rollouts=64) -> a wins (only action)."""
        rec = self.rs.recommend(
            ["a"], reward_fn=lambda a, rng: rng.random(), n_rollouts=64,
        )
        self.assertEqual(rec["best_action"], "a")
        self.assertEqual(len(rec["ranked"]), 1)


class StochasticRateLimiterBoundaries(unittest.TestCase):
    """consume(tokens): 0, negative, and integer-max."""

    def setUp(self) -> None:
        self.mod = _load_monte_carlo()
        # Fake time source so tests are deterministic.
        self._t = [0.0]

        def tick():
            return self._t[0]

        self.tick = tick
        self.rl = self.mod.StochasticRateLimiter(
            rate_per_sec=10.0, capacity=64.0, seed=7, time_fn=tick,
        )

    def test_consume_zero_tokens(self) -> None:
        """consume(0) -> always granted (current tokens >= 0).

        Documented behavior: zero-token consume is a no-op grant, because
        the check is ``self._tokens >= tokens`` which is True for any
        non-negative token count."""
        ok = self.rl.consume(0)
        self.assertTrue(ok)
        # Token bucket unchanged.
        self.assertEqual(self.rl.stats()["tokens"], 64.0)

    def test_consume_negative_tokens_documented(self) -> None:
        """consume(-1) -> granted; tokens INCREASES by 1.

        Documented behavior: consume doesn't guard against negative.
        ``self._tokens -= -1`` increases tokens by 1. This is NOT a bug
        per the contract but is a contract-gap: negative consumes should
        probably raise ValueError."""
        start_tokens = self.rl.stats()["tokens"]
        ok = self.rl.consume(-1)
        # current implementation: grants, and tokens go UP by 1.
        self.assertTrue(ok)
        # Token bucket incremented (capped at capacity if needed).
        final = self.rl.stats()["tokens"]
        self.assertGreaterEqual(final, start_tokens)

    def test_consume_integer_max(self) -> None:
        """consume(very large) -> denied, tokens unchanged."""
        # Python ints are unbounded; use a large enough value to exceed
        # the capacity ceiling of 64.
        ok = self.rl.consume(10**18)
        self.assertFalse(ok)
        self.assertEqual(self.rl.stats()["denied"], 1)

    def test_consume_one_token_granted(self) -> None:
        """Sanity: consume(1) at full bucket -> granted."""
        ok = self.rl.consume(1)
        self.assertTrue(ok)
        self.assertEqual(self.rl.stats()["tokens"], 63.0)


class MonteCarloSamplerEmptyPrior(unittest.TestCase):
    """sample_posterior with bad prior bounds."""

    def setUp(self) -> None:
        self.mod = _load_monte_carlo()
        self.s = self.mod.MonteCarloSampler(n_samples=10, seed=42)

    def test_equal_low_high_raises(self) -> None:
        """low == high -> ValueError ('must satisfy low < high')."""
        with self.assertRaises(ValueError):
            self.s.sample_posterior(
                {"low": 1.0, "high": 1.0},
                likelihood_fn=lambda x: 1.0,
            )

    def test_low_above_high_raises(self) -> None:
        """low > high -> ValueError."""
        with self.assertRaises(ValueError):
            self.s.sample_posterior(
                {"low": 5.0, "high": 1.0},
                likelihood_fn=lambda x: 1.0,
            )


class FaultInjectorProbabilityClamp(unittest.TestCase):
    """should_fire probability clamping."""

    def setUp(self) -> None:
        self.mod = _load_monte_carlo()
        self.fi = self.mod.FaultInjector(seed=42, default_probability=0.0)

    def test_probability_zero_never_fires(self) -> None:
        """p=0 -> should_fire returns False."""
        for _ in range(50):
            self.assertFalse(self.fi.should_fire(0.0))

    def test_probability_one_always_fires(self) -> None:
        """p=1 -> should_fire returns True."""
        for _ in range(50):
            self.assertTrue(self.fi.should_fire(1.0))

    def test_negative_probability_clamped_to_zero(self) -> None:
        """p=-0.5 -> clamped to 0 -> never fires.

        Source line 895: ``p = max(0.0, min(1.0, p))``."""
        for _ in range(50):
            self.assertFalse(self.fi.should_fire(-0.5))

    def test_above_one_probability_clamped(self) -> None:
        """p=1.5 -> clamped to 1.0 -> always fires."""
        for _ in range(50):
            self.assertTrue(self.fi.should_fire(1.5))


if __name__ == "__main__":
    unittest.main()
