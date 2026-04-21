"""Unit tests for ``ai-control/cortex/monte_carlo.py`` -- S74 Agent T.

Covers:

* Rejection sampler converges to the known mean of a uniform target within
  three standard errors (~99.7 % under CLT).
* Importance sampler recovers a known expectation when proposal == target.
* Metropolis-Hastings chain drags a far off-mode starting point toward the
  target mean within burn-in.
* ``register_with_daemon`` tolerates ``event_bus=None`` and stub apps
  without raising.
"""

from __future__ import annotations

import importlib.util
import math
import random
import statistics
import sys
import threading
import unittest
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[2]
_MODULE_PATH = _REPO_ROOT / "ai-control" / "cortex" / "monte_carlo.py"


def _load():
    name = "cortex_monte_carlo_under_test"
    spec = importlib.util.spec_from_file_location(name, _MODULE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # Register BEFORE exec_module so @dataclass can resolve cls.__module__
    # via sys.modules (dataclasses looks this up during class construction).
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


mc = _load()


class RejectionSamplerTest(unittest.TestCase):
    """Uniform target on [0, 1]: known mean 0.5, variance 1/12."""

    def test_converges_to_uniform_mean(self) -> None:
        sampler = mc.MonteCarloSampler(seed=42)
        res = sampler.sample_posterior(
            prior={"low": 0.0, "high": 1.0},
            likelihood_fn=lambda x: 1.0,    # uniform
            n=1000,
        )
        self.assertEqual(res["accepted"], 1000)
        # std error of mean = sqrt(var/n) = sqrt(1/12/1000) ~= 0.00913
        # 3 stderr envelope ~= 0.0274 -- comfortable for a seeded RNG.
        self.assertAlmostEqual(res["mean"], 0.5, delta=0.04)
        self.assertGreater(res["acceptance"], 0.99)   # uniform -> ~1

    def test_short_sample_returns_nan_mean(self) -> None:
        sampler = mc.MonteCarloSampler(seed=1)
        res = sampler.sample_posterior(
            prior={"low": 0.0, "high": 1.0},
            likelihood_fn=lambda x: 1.0,
            n=mc.MIN_VALID_SAMPLES - 1,
        )
        self.assertTrue(math.isnan(res["mean"]))


class ImportanceSamplingTest(unittest.TestCase):
    """Uniform[0,1] proposal, f(x)=x has E[f]=0.5."""

    def test_known_proposal_recovers_mean(self) -> None:
        sampler = mc.MonteCarloSampler(seed=7)
        est = sampler.estimate_expectation(
            f=lambda x: x,
            proposal_dist=lambda rng: rng.random(),
            n=1000,
        )
        self.assertAlmostEqual(est, 0.5, delta=0.05)

    def test_reweighted_proposal(self) -> None:
        """Sanity: importance weights pull a biased proposal back to target.

        Proposal q = Uniform[0, 1]; pretend the target is also uniform but we
        supply weight_fn=lambda x: 1.0  -- result should match the unweighted
        estimate (weights cancel).  Primarily exercises the weighted code path.
        """
        sampler = mc.MonteCarloSampler(seed=13)
        est = sampler.estimate_expectation(
            f=lambda x: x * x,
            proposal_dist=lambda rng: rng.random(),
            n=2000,
            weight_fn=lambda x: 1.0,
        )
        # True E[X^2] for Uniform[0,1] is 1/3.
        self.assertAlmostEqual(est, 1.0 / 3.0, delta=0.05)


class MCMCTest(unittest.TestCase):
    """M-H chain on a zero-mean unit-variance target.

    Starts at x0 = +5 (five sigma off-mode) and walks back toward the mean.
    After 500 burn-in + 1000 samples the sample mean should be much closer
    to zero than the starting point.
    """

    def test_chain_drifts_toward_target_mean(self) -> None:
        sampler = mc.MonteCarloSampler(seed=2025)

        # log density of a standard normal (up to additive const).
        def log_pi(x: float) -> float:
            return -0.5 * x * x

        def propose(x: float, rng: random.Random) -> float:
            return x + rng.gauss(0.0, 0.7)   # symmetric random walk

        samples = sampler.mcmc_chain(
            initial=5.0,
            transition=propose,
            target_log_density=log_pi,
            n_burn=500,
            n=1000,
        )
        self.assertEqual(len(samples), 1000)
        sample_mean = statistics.fmean(samples)
        # Must have moved at least halfway from 5.0 toward 0.0.
        self.assertLess(abs(sample_mean), 2.5)
        # And should be closer to the true mean (0) than to the starting pt.
        self.assertLess(abs(sample_mean - 0.0), abs(sample_mean - 5.0))


class UncertaintyQuantifierTest(unittest.TestCase):

    def test_quantify_returns_tuple(self) -> None:
        uq = mc.UncertaintyQuantifier(seed=123)
        # decision_fn: constant 0.5 regardless of input.
        res = uq.quantify(
            decision_fn=lambda x: 0.5,
            input_distribution=lambda rng: rng.random(),
            n_samples=200,
        )
        mean, std, p05, p95 = res.as_tuple()
        self.assertAlmostEqual(mean, 0.5)
        self.assertAlmostEqual(std, 0.0)
        self.assertFalse(res.uncertain(0.01))

    def test_quantify_noisy_input(self) -> None:
        uq = mc.UncertaintyQuantifier(seed=99)
        # decision_fn is identity on a Uniform[0, 1] input.
        res = uq.quantify(
            decision_fn=lambda x: float(x),
            input_distribution=lambda rng: rng.random(),
            n_samples=1000,
        )
        # mean ~= 0.5, CI width ~= 0.9 (5%-95% of a uniform)
        self.assertAlmostEqual(res.mean, 0.5, delta=0.05)
        self.assertGreater(res.p95 - res.p05, 0.5)
        self.assertTrue(res.uncertain(threshold=0.1))
        self.assertEqual(res.n_valid, 1000)

    def test_quantify_degenerate_returns_nan(self) -> None:
        uq = mc.UncertaintyQuantifier(seed=5)
        # decision_fn always raises -> zero valid outputs.
        res = uq.quantify(
            decision_fn=lambda x: (_ for _ in ()).throw(RuntimeError("boom")),
            input_distribution=lambda rng: rng.random(),
            n_samples=20,
        )
        self.assertTrue(math.isnan(res.mean))
        self.assertEqual(res.n_valid, 0)
        self.assertTrue(res.uncertain(threshold=1e6))


class RegisterWithDaemonTest(unittest.TestCase):

    def test_event_bus_none_is_graceful(self) -> None:
        uq = mc.register_with_daemon(app=None, event_bus=None)
        self.assertIsInstance(uq, mc.UncertaintyQuantifier)
        self.assertIs(mc.get_quantifier(), uq)

    def test_stub_app_no_attrs(self) -> None:
        class _StubApp:
            pass
        uq = mc.register_with_daemon(app=_StubApp(), event_bus=None)
        self.assertIsInstance(uq, mc.UncertaintyQuantifier)

    def test_event_bus_publish_receives_metrics(self) -> None:
        class _Bus:
            def __init__(self) -> None:
                self.events: list[dict] = []
                self.subs: list = []

            def subscribe(self, topic, cb):
                self.subs.append((topic, cb))

            def publish(self, event):
                self.events.append(event)

        bus = _Bus()
        uq = mc.register_with_daemon(app=None, event_bus=bus)
        # Sanity: subscribe was called exactly once with the expected topic.
        self.assertEqual(len(bus.subs), 1)
        topic, cb = bus.subs[0]
        self.assertEqual(topic, "cortex.uncertainty.request")
        # Fire a request event.  Payload carries the callables.
        cb({
            "payload": {
                "decision_fn": lambda x: float(x),
                "input_distribution": lambda rng: rng.random(),
                "n_samples": 64,
                "request_id": "unit-test-1",
            }
        })
        self.assertEqual(len(bus.events), 1)
        evt = bus.events[0]
        self.assertEqual(evt["type"], "cortex.uncertainty.result")
        self.assertEqual(evt["request_id"], "unit-test-1")
        self.assertEqual(evt["n_valid"], 64)


if __name__ == "__main__":
    unittest.main()
