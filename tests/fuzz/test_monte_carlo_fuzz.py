"""Fuzz tests for ``ai-control/cortex/monte_carlo.py``.

Targets:
  * MonteCarloSampler.sample_posterior  (rejection sampling)
  * MonteCarloSampler.estimate_expectation (importance sampling)
  * ConfidenceSampler.calibrated        (base confidence in [0,1] clip)
  * RolloutSearch.recommend             (ranked-action dict)
  * FaultInjector.should_fire           (Bernoulli gate)
  * StochasticRateLimiter.consume       (token-bucket)

Invariants hammered:

  1. All numeric outputs are finite (or NaN for documented edge cases).
  2. calibrated() returns a value in [0.0, 1.0] for every finite base.
  3. recommend() always returns a dict with ``best_action`` and ``ranked``
     keys, even on empty action list or on 50+ random ASCII actions.
  4. consume() returns a bool for any input (including negative, 0, huge).
  5. No sampler raises on pathological inputs we can predict.

S79 Test Agent 1 deliverable.
"""

from __future__ import annotations

import importlib.util
import json
import math
import os
import random
import string
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FUZZ_DIR = Path(__file__).resolve().parent
_MODULE_PATH = _REPO_ROOT / "ai-control" / "cortex" / "monte_carlo.py"

if str(_FUZZ_DIR) not in sys.path:
    sys.path.insert(0, str(_FUZZ_DIR))

from _fuzz_helpers import make_seed_logger, maybe_systemrandom  # noqa: E402

FUZZ_ENABLED = bool(os.environ.get("FUZZ_TESTS"))
FUZZ_ITERATIONS = int(os.environ.get("FUZZ_ITERATIONS", "1000"))
FUZZ_ROOT_SEED = 42


def _load_module():
    """Load monte_carlo.py by path (mirrors test_monte_carlo.py pattern)."""
    name = "cortex_monte_carlo_under_fuzz"
    spec = importlib.util.spec_from_file_location(name, _MODULE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _random_target_pdf(rng: random.Random):
    """Return a random nonneg target function bounded in [0, 1]."""
    mode = rng.randint(0, 4)
    if mode == 0:
        # Uniform mass
        return lambda x: 0.5
    if mode == 1:
        # Triangular peaked at mid
        return lambda x: max(0.0, 1.0 - abs(x - 0.5) * 2.0)
    if mode == 2:
        # Gaussian-ish
        mu = rng.uniform(0.1, 0.9)
        return lambda x: math.exp(-((x - mu) ** 2) * 10.0)
    if mode == 3:
        # Step
        cut = rng.uniform(0.1, 0.9)
        return lambda x: 1.0 if x > cut else 0.0
    # Noisy tiny weight
    return lambda x: rng.random() * 1e-6


@unittest.skipUnless(FUZZ_ENABLED, "fuzz tests disabled by default")
class MonteCarloSamplerFuzzTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_module()

    # ------------------------------------------------------------------
    # rejection sampler
    # ------------------------------------------------------------------

    def test_sample_posterior_over_random_targets(self) -> None:
        """1000 random target PDFs: sampler returns the expected dict shape
        without exception; all fields are the documented types."""
        log = make_seed_logger("sample_posterior")
        for i in range(FUZZ_ITERATIONS):
            seed = FUZZ_ROOT_SEED + i
            # Build a fresh deterministic sampler so seed pins the result.
            sampler = self.mod.MonteCarloSampler(seed=seed, n_samples=20)
            gen_rng = random.Random(seed)
            target = _random_target_pdf(gen_rng)
            # Random but valid prior low < high
            low = gen_rng.uniform(-5.0, 0.4)
            high = low + gen_rng.uniform(0.01, 10.0)
            try:
                res = sampler.sample_posterior(
                    prior={"low": low, "high": high},
                    likelihood_fn=target,
                    n=20,
                )
            except Exception as e:
                log(seed, (low, high))
                self.fail(f"sample_posterior raised: {e!r}")
            # Shape contract
            self.assertIsInstance(res, dict)
            self.assertIn("samples", res)
            self.assertIn("mean", res)
            self.assertIn("accepted", res)
            self.assertIn("proposed", res)
            self.assertIn("acceptance", res)
            self.assertIsInstance(res["samples"], list)
            self.assertIsInstance(res["accepted"], int)
            self.assertIsInstance(res["proposed"], int)
            self.assertIsInstance(res["acceptance"], float)
            # Acceptance rate is in [0, 1]
            self.assertGreaterEqual(res["acceptance"], 0.0)
            self.assertLessEqual(res["acceptance"], 1.0)
            # Accepted samples must be in the prior interval
            for x in res["samples"]:
                self.assertGreaterEqual(x, low)
                self.assertLessEqual(x, high)

    def test_sample_posterior_invalid_bounds_raises(self) -> None:
        """high <= low is documented to raise ValueError."""
        sampler = self.mod.MonteCarloSampler(seed=1)
        for (lo, hi) in [(0.0, 0.0), (1.0, 0.5), (5.0, -2.0)]:
            with self.assertRaises(ValueError):
                sampler.sample_posterior(
                    prior={"low": lo, "high": hi},
                    likelihood_fn=lambda x: 1.0,
                    n=5,
                )

    # ------------------------------------------------------------------
    # importance sampling / estimate_expectation
    # ------------------------------------------------------------------

    def test_estimate_expectation_random_fs(self) -> None:
        """Random f and proposal dists. Returns nan or finite float."""
        for i in range(FUZZ_ITERATIONS):
            seed = FUZZ_ROOT_SEED + 10000 + i
            sampler = self.mod.MonteCarloSampler(seed=seed, n_samples=50)
            gen = random.Random(seed)
            # Proposal: uniform(-a, a)
            a = gen.uniform(0.1, 10.0)
            proposal = lambda r, a=a: r.uniform(-a, a)
            # f is a simple poly / trig choice
            choice = gen.randint(0, 3)
            if choice == 0:
                f = lambda x: x
            elif choice == 1:
                f = lambda x: x * x
            elif choice == 2:
                f = lambda x: math.sin(x)
            else:
                # Misbehaving f: divides by zero sometimes
                f = lambda x: 1.0 / x if x != 0 else float("inf")
            try:
                est = sampler.estimate_expectation(f, proposal, n=50)
            except Exception as e:
                make_seed_logger("est_exp")(seed, "params")
                self.fail(f"estimate_expectation raised: {e!r}")
            self.assertIsInstance(est, float)
            # Returns finite OR nan
            self.assertTrue(math.isnan(est) or math.isfinite(est),
                            f"est is neither nan nor finite: {est}")


@unittest.skipUnless(FUZZ_ENABLED, "fuzz tests disabled by default")
class ConfidenceSamplerFuzzTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_module()

    def test_calibrated_clips_base_to_unit_interval(self) -> None:
        """calibrated(base) for base outside [0,1] still produces a
        valid Beta draw; output is a float in (0, 1)."""
        # Test fixed edge values from the brief
        edge_cases = [
            -1.0, -0.001, 0.0, 0.5, 1.0, 1.001, 2.0,
            math.nan, math.inf, -math.inf, 1e300, -1e300,
        ]
        sampler = self.mod.ConfidenceSampler(seed=FUZZ_ROOT_SEED)
        log = make_seed_logger("calibrated")
        for base in edge_cases:
            try:
                # NaN is handled internally via min/max clip; but math
                # ops on NaN may propagate, let's just verify no raise.
                v = sampler.calibrated(base, successes=0, failures=0)
            except Exception as e:
                log(FUZZ_ROOT_SEED, base)
                self.fail(f"calibrated({base}) raised: {e!r}")
            self.assertIsInstance(v, float)
            # NaN base may propagate; skip strict bounds check then
            if not math.isnan(base):
                # The output is a Beta draw -> should be in (0, 1)
                self.assertGreaterEqual(v, 0.0,
                                        f"base={base} -> v={v}")
                self.assertLessEqual(v, 1.0,
                                     f"base={base} -> v={v}")

    def test_calibrated_random_bases(self) -> None:
        """1000 random bases + successes + failures: output is float
        in [0, 1]."""
        sampler = self.mod.ConfidenceSampler(seed=FUZZ_ROOT_SEED + 1)
        rng = random.Random(FUZZ_ROOT_SEED + 1)
        log = make_seed_logger("calibrated_rand")
        for i in range(FUZZ_ITERATIONS):
            base = rng.uniform(-2.0, 2.0)
            s = rng.randint(0, 100)
            f = rng.randint(0, 100)
            try:
                v = sampler.calibrated(base, successes=s, failures=f)
            except Exception as e:
                log(FUZZ_ROOT_SEED + 1 + i, (base, s, f))
                self.fail(f"calibrated raised: {e!r}")
            self.assertIsInstance(v, float)
            self.assertTrue(math.isfinite(v))
            self.assertGreaterEqual(v, 0.0)
            self.assertLessEqual(v, 1.0)

    def test_deterministic_mean_path(self) -> None:
        """deterministic_mean=True returns exactly alpha/(alpha+beta)."""
        cs = self.mod.ConfidenceSampler(seed=0, deterministic_mean=True)
        for alpha, beta in [(1.0, 1.0), (10.0, 5.0), (0.5, 0.5),
                            (100.0, 1.0), (1.0, 1000.0)]:
            v = cs.sample(alpha, beta)
            expected = alpha / (alpha + beta)
            self.assertAlmostEqual(v, expected, places=9)


@unittest.skipUnless(FUZZ_ENABLED, "fuzz tests disabled by default")
class RolloutSearchFuzzTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_module()

    def _random_action_list(self, rng: random.Random) -> list:
        n = rng.randint(0, 50)
        out = []
        for _ in range(n):
            length = rng.randint(0, 20)
            s = "".join(
                rng.choices(string.ascii_letters + string.digits + "_",
                            k=length)
            )
            out.append(s)
        return out

    def _random_reward_profile_fn(self, rng: random.Random):
        """Pick a reward function compatible with RolloutSearch.search()."""
        mode = rng.randint(0, 4)
        if mode == 0:
            return lambda action, r: r.random()
        if mode == 1:
            # Prefer specific action
            fav = "noop"
            return lambda action, r, fav=fav: (
                r.gauss(0.0, 1.0) + (2.0 if action == fav else 0.0)
            )
        if mode == 2:
            # Deny-biased
            return lambda action, r: (
                r.gauss(0.0, 1.0) - (1.0 if action == "deny" else 0.0)
            )
        if mode == 3:
            # Random exceptions
            def _f(action, r):
                if r.random() < 0.05:
                    raise RuntimeError("synthetic fault")
                return r.random()
            return _f
        # Extreme values
        return lambda action, r: r.choice([
            float("inf"), float("-inf"), float("nan"), 0.0, 1e20,
        ])

    def test_recommend_random_actions(self) -> None:
        """Random action lists + profiles: dict shape holds."""
        log = make_seed_logger("recommend")
        for i in range(500):
            seed = FUZZ_ROOT_SEED + 20000 + i
            rs = self.mod.RolloutSearch(seed=seed, n_rollouts=16)
            gen = random.Random(seed)
            actions = self._random_action_list(gen)
            rfn = self._random_reward_profile_fn(gen)
            try:
                rec = rs.recommend(actions, rfn, n_rollouts=16)
            except Exception as e:
                log(seed, actions)
                self.fail(f"recommend raised: {e!r}")
            # Shape contract
            self.assertIsInstance(rec, dict)
            self.assertIn("best_action", rec)
            self.assertIn("ranked", rec)
            self.assertIsInstance(rec["ranked"], list)
            # best_action is None iff no valid rewards at all
            if rec["best_action"] is None:
                # Every ranked entry has either all-nan reward or no actions
                if actions:
                    for entry in rec["ranked"]:
                        self.assertTrue(
                            math.isnan(entry["reward_mean"]),
                            "best=None but finite reward seen")
            else:
                self.assertIsInstance(rec["best_action"], str)
            # Each entry has the documented fields
            for entry in rec["ranked"]:
                self.assertIn("action", entry)
                self.assertIn("reward_mean", entry)
                self.assertIn("reward_std", entry)
                self.assertIn("n_rollouts", entry)
                self.assertIn("probability", entry)
                self.assertIsInstance(entry["action"], str)
                self.assertIsInstance(entry["probability"], float)
                self.assertGreaterEqual(entry["probability"], 0.0)
            # Probability invariant: the sum over UNIQUE actions is 0 or 1.
            # (Duplicate action names in the input get the same probability
            # entry since the softmax dict is keyed by action name; summing
            # over rec["ranked"] entries can exceed 1 when duplicates exist.
            # We assert the unique-key sum, which is the intended contract.)
            unique_p = {e["action"]: e["probability"] for e in rec["ranked"]}
            total_p = sum(unique_p.values())
            self.assertTrue(
                total_p == 0.0 or abs(total_p - 1.0) < 1e-6,
                f"unique action prob sum = {total_p} (not 0 or 1); "
                f"actions={list(unique_p.keys())[:10]}")
            # JSON-serializable
            try:
                json.dumps(rec, allow_nan=True)
            except TypeError as e:
                self.fail(f"recommend result not JSON-safe: {e!r}")

    def test_recommend_unknown_reward_profile_falls_through(self) -> None:
        """_builtin_reward_fn('anything_weird') returns uniform fallback."""
        for profile in ["", "UNKNOWN", "UPPERCASE", "with space",
                        "deny_biased", "prefer_noop", None]:
            name = profile or "uniform"
            fn = self.mod._builtin_reward_fn(name)
            # Try a few draws; never raise
            rng = random.Random(1)
            for _ in range(100):
                v = fn("noop", rng)
                self.assertIsInstance(v, float)
                self.assertTrue(math.isfinite(v))

    def test_recommend_empty_action_list(self) -> None:
        """Empty actions: still returns dict with best_action None or a
        fallback name chosen internally."""
        # The rollout endpoint inserts defaults when body list is empty;
        # but RolloutSearch.recommend on empty list should degrade
        # gracefully too.
        rs = self.mod.RolloutSearch(seed=1, n_rollouts=10)
        rec = rs.recommend([], lambda a, r: r.random())
        self.assertIsInstance(rec, dict)
        self.assertIn("ranked", rec)
        self.assertEqual(rec["ranked"], [])


@unittest.skipUnless(FUZZ_ENABLED, "fuzz tests disabled by default")
class StochasticRateLimiterFuzzTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_module()

    def test_consume_any_tokens_returns_bool(self) -> None:
        """Consume with any numeric input: bool, no raise.

        Note: negative/zero tokens in a well-stocked bucket trivially
        succeed (any positive balance >= 0 >= negative). The contract
        is ``return bool``, not ``reject-non-positive``.
        """
        rl = self.mod.StochasticRateLimiter(
            rate_per_sec=1.0, capacity=10.0, seed=FUZZ_ROOT_SEED)
        log = make_seed_logger("consume")
        rng = random.Random(FUZZ_ROOT_SEED)
        for i in range(FUZZ_ITERATIONS):
            tokens = rng.choice([
                0.0, -1.0, -1e9, 0.5, 1.0, 2.0, 50.0, 1e6, 1e20,
            ])
            try:
                ok = rl.consume(tokens)
            except Exception as e:
                log(FUZZ_ROOT_SEED + i, tokens)
                self.fail(f"consume({tokens}) raised: {e!r}")
            self.assertIsInstance(ok, bool)

    def test_consume_huge_tokens_denied(self) -> None:
        """tokens > capacity always False (cannot overdraw)."""
        rl = self.mod.StochasticRateLimiter(
            rate_per_sec=0.0, capacity=10.0, seed=1)
        for _ in range(100):
            self.assertFalse(rl.consume(100.0))

    def test_stats_shape_stable(self) -> None:
        """stats() dict has all documented keys."""
        rl = self.mod.StochasticRateLimiter(
            rate_per_sec=5.0, capacity=10.0, seed=7)
        for _ in range(20):
            rl.consume(1.0)
        s = rl.stats()
        self.assertIn("tokens", s)
        self.assertIn("capacity", s)
        self.assertIn("rate_per_sec", s)
        self.assertIn("granted", s)
        self.assertIn("denied", s)


@unittest.skipUnless(FUZZ_ENABLED, "fuzz tests disabled by default")
class FaultInjectorFuzzTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_module()

    def test_should_fire_probability_clamped(self) -> None:
        """Probabilities outside [0,1] must not raise; output is bool."""
        fi = self.mod.FaultInjector(seed=FUZZ_ROOT_SEED)
        for p in [-1.0, -0.5, 0.0, 0.01, 0.5, 1.0, 1.5, 2.0,
                  math.inf, math.nan, 1e300]:
            for _ in range(50):
                try:
                    fired = fi.should_fire(p)
                except Exception as e:
                    make_seed_logger("should_fire")(FUZZ_ROOT_SEED, p)
                    self.fail(f"should_fire({p}) raised: {e!r}")
                self.assertIsInstance(fired, bool)

    def test_should_fire_extreme_ends(self) -> None:
        """p=0 -> never fires; p=1 -> always fires."""
        fi = self.mod.FaultInjector(seed=FUZZ_ROOT_SEED)
        fires_zero = sum(int(fi.should_fire(0.0)) for _ in range(1000))
        fires_one = sum(int(fi.should_fire(1.0)) for _ in range(1000))
        self.assertEqual(fires_zero, 0)
        self.assertEqual(fires_one, 1000)


@unittest.skipUnless(FUZZ_ENABLED, "fuzz tests disabled by default")
class MonteCarloSystemRandomCousinTest(unittest.TestCase):
    """A SystemRandom cousin pass over the four sampler classes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_module()

    def test_sysrand_confidence_rollout_fault_rate(self) -> None:
        rng = maybe_systemrandom()
        # ConfidenceSampler
        cs = self.mod.ConfidenceSampler()
        for _ in range(200):
            base = rng.uniform(-0.5, 1.5)
            v = cs.calibrated(base)
            self.assertGreaterEqual(v, 0.0)
            self.assertLessEqual(v, 1.0)
        # RolloutSearch
        rs = self.mod.RolloutSearch(n_rollouts=8)
        for _ in range(20):
            actions = [str(i) for i in range(rng.randint(0, 10))]
            rec = rs.recommend(actions, lambda a, r: r.random())
            self.assertIsInstance(rec, dict)
        # FaultInjector
        fi = self.mod.FaultInjector()
        for _ in range(200):
            p = rng.uniform(-1.0, 2.0)
            self.assertIsInstance(fi.should_fire(p), bool)
        # StochasticRateLimiter
        rl = self.mod.StochasticRateLimiter(
            rate_per_sec=rng.uniform(0.0, 100.0), capacity=16.0)
        for _ in range(100):
            self.assertIsInstance(rl.consume(rng.uniform(0.1, 2.0)), bool)


if __name__ == "__main__":
    unittest.main(verbosity=2)
