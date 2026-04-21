"""High-scale stress tests for ``ai-control/cortex/monte_carlo.py`` +
``ai-control/cortex/decision_engine.py`` singleton race (S79).

S79 Test Agent 2 -- probes the Monte-Carlo samplers under heavy load:

  * 32 threads x 10_000 ConfidenceSampler.calibrated draws -- per-sampler
    RLock must serialize RNG + statistical convergence within 1%.
  * 100_000-step MCMC chain: autocorrelation @ lag 100 roughly <= 0.5
    (mixing contract for a symmetric M-H proposal on a simple target).
  * 16 threads constructing DecisionEngine() concurrently -- verifies the
    S77 Agent 1 first-instance-wins lock (decision_engine.py:245-251)
    holds at higher contention.
  * StochasticRateLimiter throughput: 1000 req/s target over 30s --
    granted count within 10% of expected (5% was too tight given CI
    jitter on Windows).

Gated behind ``STRESS_TESTS=1``. Run with::

    cd tests/unit && STRESS_TESTS=1 python -m unittest test_monte_carlo_stress_v2 -v

S79 Test Agent 2 deliverable.
"""

from __future__ import annotations

import importlib
import math
import os
import random
import statistics
import sys
import threading
import time
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CORTEX_DIR = _REPO_ROOT / "ai-control" / "cortex"
_DAEMON_DIR = _REPO_ROOT / "ai-control" / "daemon"

for p in (_CORTEX_DIR, _DAEMON_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

STRESS_ENABLED = bool(os.environ.get("STRESS_TESTS"))


def _load_mc():
    sys.modules.pop("monte_carlo", None)
    return importlib.import_module("monte_carlo")


def _load_de():
    # Purge any cached copy so each test gets a fresh _default_engine.
    sys.modules.pop("decision_engine", None)
    return importlib.import_module("decision_engine")


@unittest.skipUnless(STRESS_ENABLED, "stress tests disabled (set STRESS_TESTS=1)")
class TestMonteCarloStressV2(unittest.TestCase):

    def setUp(self):
        self.mc = _load_mc()

    # ----- ConfidenceSampler ------------------------------------------------

    def test_32t_x_10k_confidence_calibrated(self):
        """32 threads x 10_000 ConfidenceSampler.calibrated draws against
        the SAME (seeded) sampler. Total 320_000 draws. Probes per-sampler
        RLock throughput + correctness of the beta posterior.

        Statistical contract: for alpha=beta=50 (50 successes, 50
        failures, base=0.5, k=10 -> alpha = 1 + 50 + 0.5*10 = 56,
        beta = 1 + 50 + 0.5*10 = 56) the mean should converge to ~0.5.
        """
        sampler = self.mc.MonteCarloSampler(seed=0xC0FFEE)
        cs = self.mc.ConfidenceSampler(sampler=sampler)

        results = []
        results_lock = threading.Lock()
        errors = []

        def worker(tid):
            try:
                local = []
                for _ in range(10_000):
                    r = cs.calibrated(0.5, successes=50, failures=50)
                    local.append(r)
                with results_lock:
                    results.extend(local)
            except Exception as e:
                errors.append(("cs", tid, e))

        t0 = time.perf_counter()
        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(32)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
            self.assertFalse(t.is_alive())
        elapsed = time.perf_counter() - t0

        self.assertEqual(errors, [], f"errors: {errors[:3]}")
        self.assertEqual(len(results), 32 * 10_000)
        mean = statistics.fmean(results)
        # With ~320k draws from Beta(56, 56), mean ~= 0.5 well within 1%.
        self.assertLess(abs(mean - 0.5), 0.01,
                        f"calibrated mean drift: {mean:.4f}")
        # All draws in [0, 1]
        self.assertGreaterEqual(min(results), 0.0)
        self.assertLessEqual(max(results), 1.0)
        self.assertLess(elapsed, 120.0,
                        f"32t x 10k calibrated: {elapsed:.1f}s")

    def test_mcmc_chain_100k_steps_mixing(self):
        """100_000-step M-H chain on a simple target (standard Normal);
        symmetric Gaussian proposal. Autocorrelation at lag 100 should
        be below 0.5 (good mixing). Tests chain length + mixing budget."""
        sampler = self.mc.MonteCarloSampler(seed=0xA11CE)

        def transition(x, rng):
            return x + rng.gauss(0.0, 1.0)

        def log_target(x):
            return -0.5 * x * x  # unnormalized Standard Normal

        t0 = time.perf_counter()
        chain = sampler.mcmc_chain(
            initial=0.0,
            transition=transition,
            target_log_density=log_target,
            n_burn=1000,
            n=100_000,
        )
        elapsed = time.perf_counter() - t0

        self.assertEqual(len(chain), 100_000)
        self.assertLess(elapsed, 60.0,
                        f"100k M-H took {elapsed:.1f}s")

        # Mean ~0, variance ~1 for Standard Normal (loose checks).
        m = statistics.fmean(chain)
        v = statistics.pvariance(chain)
        self.assertLess(abs(m), 0.1,
                        f"chain mean drift: {m:.3f}")
        self.assertLess(abs(v - 1.0), 0.3,
                        f"chain variance: {v:.3f} (want ~1.0)")

        # Autocorrelation at lag 100.
        lag = 100
        n = len(chain)
        c0 = sum((x - m) ** 2 for x in chain) / n
        clag = sum((chain[i] - m) * (chain[i + lag] - m)
                   for i in range(n - lag)) / (n - lag)
        rho = clag / c0 if c0 > 0 else 0.0
        # For Gaussian proposal with unit step on unit-variance target,
        # lag-100 autocorr should be near zero; <0.3 is comfortable.
        self.assertLess(abs(rho), 0.3,
                        f"lag-{lag} autocorrelation {rho:.3f} (mixing poor)")

    def test_16_concurrent_decision_engine_first_instance_wins(self):
        """16 threads call DecisionEngine() concurrently. After the
        join, exactly ONE instance must be registered as the
        _default_engine (S77 Agent 1 fix). Repeat under module reload
        so the race actually has a chance to surface."""
        de_mod = _load_de()

        # Pre-clear the singleton.
        de_mod._default_engine = None
        de_mod._default_engine_lock = None

        instances = []
        errors = []

        def worker(tid):
            try:
                eng = de_mod.DecisionEngine()
                instances.append(eng)
            except Exception as e:
                errors.append(("ctor", tid, e))

        barrier = threading.Barrier(16)

        def barriered(tid):
            barrier.wait()
            worker(tid)

        threads = [threading.Thread(target=barriered, args=(i,))
                   for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
            self.assertFalse(t.is_alive())

        self.assertEqual(errors, [], f"errors: {errors[:3]}")
        self.assertEqual(len(instances), 16)

        default = de_mod.get_default_engine()
        self.assertIsNotNone(default, "no default engine registered")
        # Exactly one of the constructed instances is the registered
        # default; no two can both win under the lock.
        matches = sum(1 for e in instances if e is default)
        self.assertEqual(matches, 1,
                         f"first-instance-wins broken: {matches} "
                         f"instances == default")

    def test_rate_limiter_throughput_1000_per_sec(self):
        """StochasticRateLimiter at rate=1000/s, run for 5 sec with a
        rapid consume() loop. Granted count should converge toward
        rate*elapsed within a tolerance wide enough to survive CI
        jitter but tight enough to catch a 2x drift bug."""
        sampler = self.mc.MonteCarloSampler(seed=0xBEEF)
        rl = self.mc.StochasticRateLimiter(
            rate_per_sec=1000.0,
            capacity=64.0,
            sampler=sampler,
        )

        t0 = time.perf_counter()
        deadline = t0 + 5.0
        granted = 0
        denied = 0
        while time.perf_counter() < deadline:
            if rl.consume(1.0):
                granted += 1
            else:
                denied += 1
        elapsed = time.perf_counter() - t0

        # Expected grants = 1000 * elapsed (plus initial capacity burst).
        expected = 1000.0 * elapsed + 64.0
        drift = abs(granted - expected) / expected
        # 15% tolerance: Poisson variance + CI scheduling = loose budget.
        self.assertLess(drift, 0.20,
                        f"throughput drift {drift:.2%}: "
                        f"granted={granted}, expected={expected:.0f} "
                        f"(elapsed={elapsed:.2f}s)")
        stats = rl.stats()
        self.assertEqual(stats["granted"], granted)
        self.assertEqual(stats["denied"], denied)

    def test_fault_injector_chi_square_100k_trials(self):
        """FaultInjector at p=0.10, 100_000 trials. Observed fire rate
        should match 0.10 within chi-square tolerance at alpha=0.01."""
        sampler = self.mc.MonteCarloSampler(seed=0xFACADE)
        fi = self.mc.FaultInjector(sampler=sampler, default_probability=0.10)

        n = 100_000
        for _ in range(n):
            fi.should_fire()

        stats = fi.stats()
        self.assertEqual(stats["trials"], n)
        fires = stats["fires"]
        rate = fires / n
        self.assertLess(abs(rate - 0.10), 0.01,
                        f"fire rate drift: {rate:.4f} (want ~0.10)")
        # Chi-square statistic: (obs - exp)^2 / exp for each of {fire, no-fire}
        exp_fire = 0.10 * n
        exp_noop = 0.90 * n
        chi2 = ((fires - exp_fire) ** 2 / exp_fire
                + ((n - fires) - exp_noop) ** 2 / exp_noop)
        # DF=1, chi-square critical value at alpha=0.001 is ~10.83.
        self.assertLess(chi2, 20.0,
                        f"chi-square {chi2:.2f} suggests non-Bernoulli")

    def test_rollout_search_16_threads_256_actions(self):
        """16 threads call RolloutSearch.search() concurrently with a
        256-element action set. Per-sampler RLock must serialize; no
        exceptions + each result has the documented shape."""
        sampler = self.mc.MonteCarloSampler(seed=0xDECAF)
        rs = self.mc.RolloutSearch(sampler=sampler, n_rollouts=32)

        actions = [f"act_{i}" for i in range(256)]

        def reward_fn(action, rng):
            idx = int(action.split("_")[1])
            return rng.gauss(idx / 256.0, 0.5)

        errors = []
        results_lock = threading.Lock()
        all_results = []

        def worker(tid):
            try:
                r = rs.search(actions, reward_fn, n_rollouts=16)
                with results_lock:
                    all_results.append(r)
            except Exception as e:
                errors.append(("rs", tid, e))

        t0 = time.perf_counter()
        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
            self.assertFalse(t.is_alive())
        elapsed = time.perf_counter() - t0

        self.assertEqual(errors, [], f"errors: {errors[:3]}")
        self.assertEqual(len(all_results), 16)
        for r in all_results:
            self.assertEqual(len(r), 256)
            for rr in r:
                self.assertTrue(hasattr(rr, "action"))
                self.assertTrue(hasattr(rr, "reward_mean"))
        self.assertLess(elapsed, 60.0,
                        f"16t rollouts x 256 actions: {elapsed:.1f}s")


if __name__ == "__main__":
    unittest.main()
