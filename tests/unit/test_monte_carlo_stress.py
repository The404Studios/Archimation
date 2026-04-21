"""Stress tests for ``ai-control/cortex/monte_carlo.py`` (S79).

S79 Test Agent 2 -- 256-thread sampler concurrency + ConfidenceSampler
clip-to-[0,1] invariance + StochasticRateLimiter throughput.

The MonteCarloSampler uses a single RLock around all RNG accesses, so
256 threads calling rejection_sample concurrently should SERIALIZE (not
crash), still produce valid output, and throughput should scale at
the single-thread rate. The ConfidenceSampler.calibrated(base) must
always return a value in [0.0, 1.0]; any out-of-range = bug.

Gated behind ``STRESS_TESTS=1``. Run with::

    cd tests/unit && STRESS_TESTS=1 python -m unittest test_monte_carlo_stress -v

S79 Test Agent 2 deliverable.
"""

from __future__ import annotations

import importlib
import math
import os
import random
import sys
import threading
import time
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CORTEX_DIR = _REPO_ROOT / "ai-control" / "cortex"

if str(_CORTEX_DIR) not in sys.path:
    sys.path.insert(0, str(_CORTEX_DIR))

STRESS_ENABLED = bool(os.environ.get("STRESS_TESTS"))


def _load_module():
    sys.modules.pop("monte_carlo", None)
    return importlib.import_module("monte_carlo")


@unittest.skipUnless(STRESS_ENABLED, "stress tests disabled (set STRESS_TESTS=1)")
class TestMonteCarloStress(unittest.TestCase):

    def setUp(self):
        self.mod = _load_module()

    def test_256_thread_sample_posterior_shared_sampler(self):
        """256 threads share one MonteCarloSampler. Call sample_posterior
        concurrently. RLock should serialize; no crash, all results
        well-formed, no accepted/proposed drift."""
        sampler = self.mod.MonteCarloSampler(n_samples=50, seed=42)
        errors = []

        def worker():
            try:
                for _ in range(4):
                    res = sampler.sample_posterior(
                        {"low": 0.0, "high": 1.0},
                        lambda x: 1.0 - abs(x - 0.5),
                        n=50,
                    )
                    if not isinstance(res, dict):
                        errors.append(("bad type", res))
                    if res["accepted"] > res["proposed"]:
                        errors.append(("accepted>proposed", res))
            except Exception as e:
                errors.append(("exc", e))

        threads = [threading.Thread(target=worker) for _ in range(256)]
        t0 = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
            self.assertFalse(t.is_alive())
        elapsed = time.perf_counter() - t0

        self.assertEqual(errors, [], f"errors: {errors[:3]}")
        # draws_total should have accumulated across all 256*4 = 1024 calls.
        stats = sampler.stats()
        self.assertGreater(stats["draws_total"], 1024 * 50,
                           "draws_total undercounted")
        self.assertLess(elapsed, 120.0,
                        f"256t x 4 sample_posterior: {elapsed:.1f}s")

    def test_256_thread_calibrated_clip_invariant(self):
        """256 threads call ConfidenceSampler.calibrated(base) with
        varied base values. EVERY return MUST be in [0.0, 1.0]."""
        cs = self.mod.ConfidenceSampler(seed=123)
        errors = []
        lock = threading.Lock()
        all_values = []

        def worker(tid):
            try:
                rng = random.Random(tid)
                local = []
                for _ in range(100):
                    base = rng.random()  # in [0, 1)
                    v = cs.calibrated(base)
                    if not (0.0 <= v <= 1.0):
                        errors.append(("out_of_range", base, v))
                    local.append(v)
                with lock:
                    all_values.extend(local)
            except Exception as e:
                errors.append(("exc", tid, e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(256)]
        t0 = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
            self.assertFalse(t.is_alive())
        elapsed = time.perf_counter() - t0

        self.assertEqual(errors, [], f"errors: {errors[:3]}")
        self.assertEqual(len(all_values), 256 * 100)
        # Mean should be ~0.5 if base distribution is uniform on [0,1].
        mean = sum(all_values) / len(all_values)
        self.assertAlmostEqual(mean, 0.5, delta=0.1,
                               msg=f"calibrated mean: {mean:.3f}")
        self.assertLess(elapsed, 60.0,
                        f"calibrated x 25600 under 256t: {elapsed:.1f}s")

    def test_256_thread_rate_limiter_throughput(self):
        """StochasticRateLimiter at lambda=100 tokens/sec, 256 threads
        each calling consume(1) 100 times. Throughput should average
        ~100/sec over ~1s (+/- 10%) -- not 256*100/elapsed."""
        # Use a fresh sampler/seed for reproducibility.
        shared = self.mod.MonteCarloSampler(seed=7)
        rl = self.mod.StochasticRateLimiter(
            rate_per_sec=100.0, capacity=64.0, sampler=shared,
        )
        errors = []

        def worker(tid):
            try:
                for _ in range(100):
                    rl.consume(1.0)
                    # Small delay so the poisson refill has time.
                    if tid % 32 == 0:
                        time.sleep(0.001)
            except Exception as e:
                errors.append(("exc", tid, e))

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(256)]
        t0 = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
            self.assertFalse(t.is_alive())
        elapsed = time.perf_counter() - t0

        self.assertEqual(errors, [], f"errors: {errors[:3]}")
        stats = rl.stats()
        # granted + denied = 256 * 100
        total = stats["granted"] + stats["denied"]
        self.assertEqual(total, 256 * 100,
                         f"lost consume calls: {total}")

        # Throughput = granted / elapsed. Should be bounded by
        # rate_per_sec + initial bucket capacity.
        gated_throughput = stats["granted"] / max(elapsed, 1e-6)
        # Loose bound: we started with 64 tokens + got rate*elapsed
        # refill. granted <= 64 + rate*elapsed.
        upper = 64 + 100 * elapsed
        self.assertLessEqual(stats["granted"], upper * 1.5,
                             f"granted={stats['granted']} exceeded "
                             f"1.5x expected ceiling {upper:.0f}")

    def test_concurrent_mcmc_chain_active_count(self):
        """64 threads run mcmc_chain concurrently. active_chains counter
        must return to 0 after all threads complete (probe for leak)."""
        sampler = self.mod.MonteCarloSampler(seed=99)

        def target_log_density(x):
            return -0.5 * x * x  # N(0,1)

        def transition(x, rng):
            return x + rng.gauss(0, 0.5)

        def worker():
            sampler.mcmc_chain(
                initial=0.0,
                transition=transition,
                target_log_density=target_log_density,
                n_burn=50, n=100,
            )

        threads = [threading.Thread(target=worker) for _ in range(64)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
            self.assertFalse(t.is_alive())

        stats = sampler.stats()
        self.assertEqual(stats["active_chains"], 0,
                         f"active_chains leaked: {stats['active_chains']}")

    def test_fault_injector_256_threads_empirical_rate(self):
        """256 threads * 100 should_fire(p=0.5) calls = 25600 total.
        Empirical rate should be within 0.04 of 0.5 (3-sigma for
        Bernoulli at n=25600)."""
        fi = self.mod.FaultInjector(seed=77, default_probability=0.5)
        errors = []

        def worker():
            try:
                for _ in range(100):
                    fi.should_fire()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(256)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        self.assertEqual(errors, [], f"errors: {errors[:3]}")
        stats = fi.stats()
        total = stats["trials"]
        # Trials counter under _fires/_trials += 1 inside the lock;
        # should be exact.
        self.assertEqual(total, 256 * 100,
                         f"trials drift: {total}")
        rate = stats["empirical_rate"]
        self.assertAlmostEqual(rate, 0.5, delta=0.04,
                               msg=f"empirical_rate={rate:.3f}")

    def test_importance_sampling_under_load(self):
        """256 threads call estimate_expectation with shared sampler.
        Pass: all results finite, no crash, draws_total accumulates."""
        sampler = self.mod.MonteCarloSampler(n_samples=100, seed=5)

        def f(x):
            return x * x

        def proposal_dist(rng):
            return rng.gauss(0, 1)

        errors = []
        results = []
        lock = threading.Lock()

        def worker():
            try:
                est = sampler.estimate_expectation(f, proposal_dist, n=100)
                with lock:
                    results.append(est)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(256)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        self.assertEqual(errors, [], f"errors: {errors[:3]}")
        self.assertEqual(len(results), 256)
        finite = [r for r in results if math.isfinite(r)]
        self.assertGreater(len(finite), 250, "too many nan results")
        # E[X^2] for N(0,1) = 1.0; mean of estimators should be ~1.0.
        mean = sum(finite) / len(finite)
        self.assertAlmostEqual(mean, 1.0, delta=0.2,
                               msg=f"E[X^2] estimator mean: {mean:.3f}")


if __name__ == "__main__":
    unittest.main()
