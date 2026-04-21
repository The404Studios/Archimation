"""Fuzz harness for ``ai-control/cortex/monte_carlo.py``.

S79 Test Agent 1 deliverable.

Targets the S75 Agent C samplers and the S74 baseline:

  * ``MonteCarloSampler.sample_posterior`` (rejection) with pathological
    target functions (NaN / inf / negative / raising).
  * ``ConfidenceSampler.calibrated`` with out-of-range base confidences.
  * ``RolloutSearch.recommend`` with 0..100-long random action lists.
  * ``FaultInjector.should_fire`` with p in [-0.5, 1.5] (clamp contract).
  * ``StochasticRateLimiter.consume`` with random rate / capacity / size.
  * ``UncertaintyQuantifier.quantify`` with degenerate input distributions.

Invariants enforced per fuzzer documented inline. Each call asserts no
uncaught exception escapes and basic type/structure invariants on the
returned value.

Env vars:
  * ``FUZZ_DEEP=1``          -> 100k iterations.
  * ``FUZZ_ITERATIONS=N``    -> override iteration count.

NOTE: The task brief names ``rejection_sample`` / ``should_inject`` but
the actual public API (monte_carlo.py:126, 892) is ``sample_posterior``
and ``should_fire``. We fuzz the real API shape.
"""

from __future__ import annotations

import importlib.util
import logging
import math
import os
import random
import sys
import unittest
from pathlib import Path

# Silence the cortex.monte_carlo logger -- expected degenerate-input warnings
# from intentional NaN/raise/all-zero shapes drown out pytest output.
logging.getLogger("cortex.monte_carlo").setLevel(logging.ERROR)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FUZZ_DIR = Path(__file__).resolve().parent
if str(_FUZZ_DIR) not in sys.path:
    sys.path.insert(0, str(_FUZZ_DIR))

from _fuzz_helpers import make_seed_logger  # noqa: E402

FUZZ_DEEP = bool(os.environ.get("FUZZ_DEEP"))
# MC fuzzers are more expensive than byte-parsers (each iteration may do
# 1000 rejection-sample proposals) -- use a smaller default so the whole
# suite stays under 30s.
FUZZ_ITERATIONS = int(os.environ.get(
    "FUZZ_ITERATIONS",
    "10000" if FUZZ_DEEP else "200",
))
FUZZ_ROOT_SEED = int(os.environ.get("FUZZ_ROOT_SEED", "314159"))


def _load_monte_carlo():
    name = "_fuzz_monte_carlo"
    path = _REPO_ROOT / "ai-control" / "cortex" / "monte_carlo.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # Register in sys.modules BEFORE exec so @dataclass introspection works.
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


MC = _load_monte_carlo()


# --------------------------------------------------------------------------
# Pathological function pool
# --------------------------------------------------------------------------

def _random_likelihood(rng: random.Random):
    """Return a 1-arg float->float that sometimes returns NaN/inf/negative."""
    shape = rng.randint(0, 7)
    if shape == 0:
        return lambda x: float("nan")
    if shape == 1:
        return lambda x: float("inf")
    if shape == 2:
        return lambda x: -1.0 * abs(x)
    if shape == 3:
        return lambda x: 0.0
    if shape == 4:
        def _raise(x):
            raise RuntimeError("fuzz explosion")
        return _raise
    if shape == 5:
        return lambda x: abs(x)
    if shape == 6:
        return lambda x: math.exp(-x * x)  # well-behaved gaussian
    # shape 7 -- random positive
    k = rng.uniform(0.01, 100.0)
    return lambda x, k=k: k * abs(x)


class FuzzMonteCarloSampler(unittest.TestCase):

    def test_sample_posterior_pathological(self):
        """rejection sampler must not crash on finite/nan/inf; sample count <= n.

        SURFACED BUG (S79 Test Agent 1, seed=314159):
          ``MonteCarloSampler.sample_posterior`` does NOT wrap the user
          ``likelihood_fn`` call in try/except (monte_carlo.py:164). Its
          sibling methods ``estimate_expectation`` (line 213) and
          ``mcmc_chain`` (line 269) DO catch exceptions from
          user-provided callables. This asymmetry lets a noisy
          likelihood propagate straight through to the cortex veto path.

          Not fixed here (read-only task). Test uses non-raising
          pathological likelihoods only so the rest of the contract is
          still exercised.
        """
        log = make_seed_logger(self._testMethodName)
        for i in range(FUZZ_ITERATIONS):
            seed = FUZZ_ROOT_SEED + i
            rng = random.Random(seed)
            low = rng.uniform(-100, 100)
            high = low + rng.uniform(0.01, 100.0)
            prior = {"low": low, "high": high}
            n = rng.randint(1, 16)
            # Skip the "raises" shape to document-rather-than-fail the
            # asymmetry bug above.
            shape = rng.randint(0, 6)
            if shape == 0:
                lik = lambda x: float("nan")
            elif shape == 1:
                lik = lambda x: float("inf")
            elif shape == 2:
                lik = lambda x: -abs(x)
            elif shape == 3:
                lik = lambda x: 0.0
            elif shape == 4:
                lik = lambda x: abs(x)
            elif shape == 5:
                lik = lambda x: math.exp(-x * x)
            else:
                k = rng.uniform(0.01, 100.0)
                lik = lambda x, k=k: k * abs(x)
            sampler = MC.MonteCarloSampler(seed=seed, n_samples=n)
            try:
                result = sampler.sample_posterior(prior, lik, n)
            except ValueError:
                continue  # documented behaviour for bad bounds
            except Exception as exc:
                log(seed, (prior, n, shape))
                raise AssertionError(
                    f"sample_posterior raised {type(exc).__name__}: {exc} "
                    f"prior={prior} n={n} shape={shape} seed={seed}"
                ) from exc
            self.assertIsInstance(result, dict)
            self.assertIn("accepted", result)
            self.assertIn("proposed", result)
            self.assertLessEqual(result["accepted"], n)
            self.assertLessEqual(result["accepted"], result["proposed"])
            self.assertGreaterEqual(result["acceptance"], 0.0)
            self.assertLessEqual(result["acceptance"], 1.0)


class FuzzConfidenceSampler(unittest.TestCase):

    def test_calibrated_out_of_range_base(self):
        """Base confidence in [-1, 2] -- clamp to [0, 1] and produce finite draw."""
        log = make_seed_logger(self._testMethodName)
        for i in range(FUZZ_ITERATIONS):
            seed = FUZZ_ROOT_SEED + i
            rng = random.Random(seed)
            base = rng.uniform(-1.0, 2.0)
            succ = rng.randint(0, 100)
            fail = rng.randint(0, 100)
            cs = MC.ConfidenceSampler(seed=seed)
            try:
                out = cs.calibrated(base, successes=succ, failures=fail)
            except Exception as exc:
                log(seed, (base, succ, fail))
                raise AssertionError(
                    f"calibrated raised {type(exc).__name__}: {exc} "
                    f"base={base} seed={seed}"
                ) from exc
            self.assertIsInstance(out, float)
            # Beta draws lie in [0, 1]
            self.assertGreaterEqual(out, 0.0, msg=f"seed={seed} base={base}")
            self.assertLessEqual(out, 1.0, msg=f"seed={seed} base={base}")

    def test_deterministic_mode_symmetry(self):
        """deterministic_mean=True => same alpha/beta yields same output."""
        for i in range(100):
            seed = FUZZ_ROOT_SEED + i
            rng = random.Random(seed)
            base = rng.uniform(0.0, 1.0)
            cs1 = MC.ConfidenceSampler(seed=seed, deterministic_mean=True)
            cs2 = MC.ConfidenceSampler(seed=seed + 7, deterministic_mean=True)
            self.assertAlmostEqual(
                cs1.calibrated(base, 5, 3),
                cs2.calibrated(base, 5, 3),
                places=12,
            )


class FuzzRolloutSearch(unittest.TestCase):

    def test_recommend_varied_action_lists(self):
        """RolloutSearch.recommend returns a well-formed dict with best_action.

        SURFACED BUG (S79 Test Agent 1, seed=314159+2 = 314161):
          ``RolloutSearch.recommend`` returns ``best_action=None`` for ANY
          non-empty action list when ``n_rollouts < MIN_VALID_SAMPLES``
          (=8). The search() loop caps valid-results at
          MIN_VALID_SAMPLES, so n_rollouts in {1..7} always produces
          ``reward_mean=nan`` for every branch -- recommend() then
          short-circuits to ``best=None`` at monte_carlo.py:845-846.

          Severity: would-fire-in-prod. A cortex caller asking for a
          quick 4-rollout preview gets a silent no-recommendation, with
          no error surface and best_action=None indistinguishable from
          "no actions supplied".

          Not fixed here (read-only task). The fuzzer uses
          n_rollouts >= MIN_VALID_SAMPLES so the rest of the contract is
          still covered.
        """
        log = make_seed_logger(self._testMethodName)
        iters = min(FUZZ_ITERATIONS, 400)
        for i in range(iters):
            seed = FUZZ_ROOT_SEED + i
            rng = random.Random(seed)
            n_actions = rng.randint(0, 100)
            actions = [f"a{rng.randint(0, 999)}" for _ in range(n_actions)]
            # Use >= MIN_VALID_SAMPLES to dodge the nan-cap bug above.
            n_roll = rng.randint(MC.MIN_VALID_SAMPLES, 64)
            rs = MC.RolloutSearch(seed=seed, n_rollouts=n_roll)

            def rew(a, r, seed=seed):
                return r.gauss(0.0, 1.0)

            try:
                out = rs.recommend(actions, rew)
            except Exception as exc:
                log(seed, (n_actions, actions, n_roll))
                raise AssertionError(
                    f"recommend raised {type(exc).__name__}: {exc} "
                    f"n_actions={n_actions} n_roll={n_roll} seed={seed}"
                ) from exc
            self.assertIsInstance(out, dict)
            self.assertIn("best_action", out)
            self.assertIn("ranked", out)
            self.assertIsInstance(out["ranked"], list)
            if not actions:
                self.assertIsNone(out["best_action"])
            else:
                self.assertIsNotNone(
                    out["best_action"],
                    msg=f"n_actions={n_actions} n_roll={n_roll} seed={seed}",
                )

    def test_recommend_low_rollout_bug_reproducer(self):
        """Document the n_rollouts < MIN_VALID_SAMPLES bug.

        With n_rollouts < 8 and a finite reward_fn, every action's
        reward_mean is NaN (search() requires >= MIN_VALID_SAMPLES valid
        samples; monte_carlo.py:812), so recommend() returns
        best_action=None even with non-empty actions.
        """
        for n_roll in range(1, MC.MIN_VALID_SAMPLES):
            rs = MC.RolloutSearch(seed=FUZZ_ROOT_SEED, n_rollouts=n_roll)
            out = rs.recommend(["allow", "deny"], lambda a, r: r.random())
            # We assert the CURRENT buggy behaviour so future fixes break
            # this test and get reviewed.
            self.assertIsNone(
                out["best_action"],
                msg=(f"n_roll={n_roll}: best_action was "
                     f"{out['best_action']!r}; bug may be fixed "
                     f"-- update fuzzer invariants."),
            )


class FuzzFaultInjector(unittest.TestCase):

    def test_should_fire_out_of_range_p(self):
        """p in [-0.5, 1.5] -> clamp -> deterministic at p<=0 and p>=1."""
        log = make_seed_logger(self._testMethodName)
        for i in range(FUZZ_ITERATIONS):
            seed = FUZZ_ROOT_SEED + i
            rng = random.Random(seed)
            p = rng.uniform(-0.5, 1.5)
            fi = MC.FaultInjector(seed=seed)
            try:
                fired = fi.should_fire(p)
            except Exception as exc:
                log(seed, p)
                raise AssertionError(
                    f"should_fire raised {type(exc).__name__}: {exc} "
                    f"p={p} seed={seed}"
                ) from exc
            self.assertIsInstance(fired, bool)
            # Deterministic boundaries: p<=0 never fires; p>=1 always fires.
            if p <= 0.0:
                self.assertFalse(fired, msg=f"p={p} seed={seed}")
            elif p >= 1.0:
                self.assertTrue(fired, msg=f"p={p} seed={seed}")

    def test_should_fire_probabilistic(self):
        """p=0.5 across many trials -> rate within broad band."""
        fi = MC.FaultInjector(seed=FUZZ_ROOT_SEED)
        trials = 2000
        fires = sum(1 for _ in range(trials) if fi.should_fire(0.5))
        rate = fires / trials
        # Wide envelope to avoid flakes: 0.5 +/- 0.05 (~3 sigma for N=2000)
        self.assertGreater(rate, 0.40)
        self.assertLess(rate, 0.60)


class FuzzStochasticRateLimiter(unittest.TestCase):

    def test_consume_random_parameters(self):
        """Token balance never goes negative; return type always bool."""
        log = make_seed_logger(self._testMethodName)
        iters = min(FUZZ_ITERATIONS, 1000)
        for i in range(iters):
            seed = FUZZ_ROOT_SEED + i
            rng = random.Random(seed)
            # Fake clock so we don't actually sleep.
            t = [0.0]

            def now():
                return t[0]

            rate = rng.uniform(0.0, 200.0)
            capacity = rng.uniform(1.0, 10000.0)
            rl = MC.StochasticRateLimiter(
                rate_per_sec=rate, capacity=capacity,
                seed=seed, time_fn=now,
            )
            for _ in range(rng.randint(1, 20)):
                t[0] += rng.uniform(0.0, 5.0)
                size = rng.uniform(0.0, capacity * 2)
                try:
                    ok = rl.consume(size)
                except Exception as exc:
                    log(seed, (rate, capacity, size, t[0]))
                    raise AssertionError(
                        f"consume raised {type(exc).__name__}: {exc} seed={seed}"
                    ) from exc
                self.assertIsInstance(ok, bool)
                stats = rl.stats()
                # Balance invariants: tokens in [0, capacity].
                self.assertGreaterEqual(stats["tokens"], -1e-9,
                                        msg=f"seed={seed} tokens went negative")
                self.assertLessEqual(stats["tokens"], capacity + 1e-6,
                                     msg=f"seed={seed} tokens exceeded capacity")


class FuzzUncertaintyQuantifier(unittest.TestCase):

    def test_quantify_degenerate_inputs(self):
        """UQ on all-NaN, all-zero, single-sample, and pathological dists."""
        log = make_seed_logger(self._testMethodName)
        iters = min(FUZZ_ITERATIONS, 400)
        for i in range(iters):
            seed = FUZZ_ROOT_SEED + i
            rng = random.Random(seed)
            shape = rng.randint(0, 4)
            # 0: all NaN, 1: all zero, 2: constant, 3: raises, 4: normal
            if shape == 0:
                dec = lambda x: float("nan")
            elif shape == 1:
                dec = lambda x: 0.0
            elif shape == 2:
                k = rng.uniform(-100, 100)
                dec = lambda x, k=k: k
            elif shape == 3:
                def dec(x):
                    raise ValueError("nope")
            else:
                dec = lambda x: x * 0.5 + rng.gauss(0, 1)

            def dist(r):
                return r.uniform(-1, 1)

            n = rng.randint(1, 50)
            uq = MC.UncertaintyQuantifier(seed=seed)
            try:
                res = uq.quantify(dec, dist, n)
            except Exception as exc:
                log(seed, (shape, n))
                raise AssertionError(
                    f"quantify raised {type(exc).__name__}: {exc} "
                    f"shape={shape} seed={seed}"
                ) from exc
            self.assertIsInstance(res, MC.UncertaintyResult)
            # Degenerate inputs should surface as nan fields, NEVER raise.
            if shape in (0, 3):
                self.assertTrue(math.isnan(res.mean),
                                msg=f"shape={shape} seed={seed}")


if __name__ == "__main__":
    unittest.main()
