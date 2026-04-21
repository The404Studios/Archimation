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


# --------------------------------------------------------------------------
# S75 Agent C additions -- ConfidenceSampler / RolloutSearch / FaultInjector /
# StochasticRateLimiter + decision_engine regression test.
# --------------------------------------------------------------------------


class DeterminismTest(unittest.TestCase):
    """Two instances of any sampler with seed=42 must produce identical
    sample sequences (classical reproducibility contract)."""

    def test_confidence_sampler_repeatable(self) -> None:
        cs_a = mc.ConfidenceSampler(seed=42)
        cs_b = mc.ConfidenceSampler(seed=42)
        a_samples = cs_a.sample_many(2.0, 5.0, n=100)
        b_samples = cs_b.sample_many(2.0, 5.0, n=100)
        self.assertEqual(a_samples, b_samples)

    def test_rollout_search_repeatable(self) -> None:
        actions = ("x", "y", "z")
        def reward(a: str, rng: random.Random) -> float:
            return rng.random() + (0.1 if a == "x" else 0.0)
        rs_a = mc.RolloutSearch(seed=42, n_rollouts=32)
        rs_b = mc.RolloutSearch(seed=42, n_rollouts=32)
        r_a = rs_a.search(actions, reward)
        r_b = rs_b.search(actions, reward)
        self.assertEqual([x.action for x in r_a], [x.action for x in r_b])
        for a, b in zip(r_a, r_b):
            self.assertAlmostEqual(a.reward_mean, b.reward_mean)

    def test_fault_injector_repeatable(self) -> None:
        fi_a = mc.FaultInjector(seed=42, default_probability=0.5)
        fi_b = mc.FaultInjector(seed=42, default_probability=0.5)
        seq_a = [fi_a.should_fire() for _ in range(200)]
        seq_b = [fi_b.should_fire() for _ in range(200)]
        self.assertEqual(seq_a, seq_b)


class ConfidenceBetaPosteriorTest(unittest.TestCase):
    """Sampled distribution matches input beta posterior within 2% over
    N=10000 (docs/s75_roadmap.md §5 Item 4 acceptance test)."""

    def test_beta_posterior_mean_within_2pct(self) -> None:
        alpha, beta = 3.0, 7.0
        n = 10000
        cs = mc.ConfidenceSampler(seed=42)
        samples = cs.sample_many(alpha, beta, n=n)
        self.assertEqual(len(samples), n)
        sample_mean = statistics.fmean(samples)
        true_mean = alpha / (alpha + beta)   # 0.3
        # 2% absolute tolerance per roadmap acceptance test.
        deviation = abs(sample_mean - true_mean)
        self.assertLess(deviation, 0.02,
                        f"Beta sample mean {sample_mean:.4f} off true "
                        f"{true_mean:.4f} by {deviation:.4f} (>2%)")

        # Variance check: Beta(a, b) has variance = ab / [(a+b)^2 (a+b+1)].
        true_var = (alpha * beta) / ((alpha + beta) ** 2 * (alpha + beta + 1.0))
        sample_var = statistics.pvariance(samples)
        rel_var_dev = abs(sample_var - true_var) / true_var
        self.assertLess(rel_var_dev, 0.08,
                        f"Beta sample variance {sample_var:.5f} off "
                        f"true {true_var:.5f} by {rel_var_dev:.2%}")

    def test_deterministic_mean_matches_analytical_mean(self) -> None:
        cs = mc.ConfidenceSampler(seed=1, deterministic_mean=True)
        self.assertAlmostEqual(cs.sample(3.0, 7.0), 0.3, places=10)
        self.assertAlmostEqual(cs.sample(1.0, 1.0), 0.5, places=10)

    def test_calibrated_returns_in_unit_interval(self) -> None:
        cs = mc.ConfidenceSampler(seed=42)
        for base in (0.0, 0.25, 0.5, 0.75, 1.0):
            for _ in range(20):
                v = cs.calibrated(base, successes=3, failures=1)
                self.assertGreaterEqual(v, 0.0)
                self.assertLessEqual(v, 1.0)


class RolloutSearchTest(unittest.TestCase):
    """Returns finite results for a trivial action set."""

    def test_trivial_set_returns_finite_results(self) -> None:
        rs = mc.RolloutSearch(seed=42, n_rollouts=32)
        actions = ("a", "b", "c")
        # Reward favours "b" with a +0.5 bias.
        def reward(a: str, rng: random.Random) -> float:
            return rng.gauss(0.0, 1.0) + (0.5 if a == "b" else 0.0)
        results = rs.search(actions, reward)
        self.assertEqual(len(results), 3)
        for r in results:
            self.assertTrue(math.isfinite(r.reward_mean),
                            f"{r.action} reward_mean is not finite")
            self.assertTrue(math.isfinite(r.reward_std))
            self.assertEqual(r.n_rollouts, 32)
        # "b" should rank first with a favouring reward.
        self.assertEqual(results[0].action, "b")

    def test_recommend_returns_softmax_probs(self) -> None:
        rs = mc.RolloutSearch(seed=42, n_rollouts=16)
        def reward(a: str, rng: random.Random) -> float:
            return 1.0 if a == "good" else 0.0
        rec = rs.recommend(("good", "bad"), reward)
        self.assertEqual(rec["best_action"], "good")
        total_prob = sum(r["probability"] for r in rec["ranked"])
        self.assertAlmostEqual(total_prob, 1.0, places=6)
        # "good" should dominate the probability mass.
        good = next(r for r in rec["ranked"] if r["action"] == "good")
        self.assertGreater(good["probability"], 0.5)

    def test_empty_actions_returns_empty(self) -> None:
        rs = mc.RolloutSearch(seed=1, n_rollouts=8)
        results = rs.search((), lambda a, rng: 0.0)
        self.assertEqual(results, [])


class FaultInjectorChiSquareTest(unittest.TestCase):
    """Chi-square sanity: observed fires match Bernoulli(p) at p>=0.05."""

    def test_chi_square_p_value(self) -> None:
        p = 0.3
        n = 5000
        fi = mc.FaultInjector(seed=42, default_probability=p)
        fires = sum(1 for _ in range(n) if fi.should_fire())
        expected_fires = n * p
        expected_nonfires = n * (1.0 - p)
        nonfires = n - fires
        chi_square = (
            ((fires - expected_fires) ** 2) / expected_fires
            + ((nonfires - expected_nonfires) ** 2) / expected_nonfires
        )
        # Chi-square with df=1 at alpha=0.05 is 3.841. The test passes when
        # chi_square < 3.841 (fail to reject H0: rates match).
        self.assertLess(chi_square, 3.841,
                        f"chi_square={chi_square:.3f} exceeds 3.841 "
                        f"critical value (fires={fires}/{n}, expected "
                        f"{expected_fires:.0f})")
        # Also sanity-check FaultInjector.stats.
        st = fi.stats()
        self.assertEqual(st["trials"], n)
        self.assertEqual(st["fires"], fires)

    def test_probability_zero_never_fires(self) -> None:
        fi = mc.FaultInjector(seed=1, default_probability=0.0)
        self.assertFalse(any(fi.should_fire() for _ in range(1000)))

    def test_probability_one_always_fires(self) -> None:
        fi = mc.FaultInjector(seed=1, default_probability=1.0)
        self.assertTrue(all(fi.should_fire() for _ in range(1000)))

    def test_maybe_inject_runs_fault_fn(self) -> None:
        fi = mc.FaultInjector(seed=1, default_probability=1.0)
        counter = {"n": 0}
        fi.maybe_inject(lambda: counter.__setitem__("n", counter["n"] + 1))
        self.assertEqual(counter["n"], 1)


class StochasticRateLimiterTest(unittest.TestCase):
    """Throughput within 5% of configured lambda rate."""

    def test_throughput_within_5pct(self) -> None:
        # Use a fake clock so the test is fast + deterministic. Lambda=10/s,
        # simulate 100 seconds of wall time in 1-second ticks.
        rate = 10.0
        sim_seconds = 100.0
        clock = {"t": 0.0}
        rl = mc.StochasticRateLimiter(
            rate_per_sec=rate,
            capacity=1e9,   # effectively unlimited so no throttling drop
            seed=42,
            time_fn=lambda: clock["t"],
        )
        # Drain initial capacity so we measure arrivals, not starting tokens.
        rl._tokens = 0.0
        total_granted = 0
        ticks = 100
        dt = sim_seconds / ticks
        for _ in range(ticks):
            clock["t"] += dt
            # Try to consume as many as possible up to a generous ceiling.
            ceiling = int(rate * dt * 5)
            for _ in range(ceiling):
                if rl.consume(1.0):
                    total_granted += 1
                else:
                    break
        expected = rate * sim_seconds    # 1000 tokens
        relative_error = abs(total_granted - expected) / expected
        self.assertLess(relative_error, 0.05,
                        f"Throughput {total_granted} off expected {expected:.0f} "
                        f"by {relative_error:.2%} (>5%)")

    def test_consume_respects_capacity(self) -> None:
        clock = {"t": 0.0}
        rl = mc.StochasticRateLimiter(
            rate_per_sec=0.0,     # no replenishment
            capacity=5.0,
            seed=1,
            time_fn=lambda: clock["t"],
        )
        granted = sum(1 for _ in range(10) if rl.consume(1.0))
        self.assertEqual(granted, 5)


class DecisionEngineRegressionTest(unittest.TestCase):
    """Unwired path -> no behaviour change in decision_engine.

    The S75 wiring is opt-in: without calling set_confidence_sampler(),
    the confidence value must equal the tier's original deterministic
    confidence. This regression guards against accidental always-on
    sampling.
    """

    def _load_de(self):
        _cortex_dir = _REPO_ROOT / "ai-control" / "cortex"
        sys.path.insert(0, str(_cortex_dir))
        try:
            import importlib
            if "decision_engine" in sys.modules:
                del sys.modules["decision_engine"]
            de = importlib.import_module("decision_engine")
            return de
        finally:
            # Leave the path so downstream imports (monte_carlo etc.) still
            # work inside this suite.
            pass

    def test_unwired_confidence_is_deterministic(self) -> None:
        de = self._load_de()
        engine = de.DecisionEngine()
        # Default-ALLOW path (no matching rule / heuristic) -> confidence 0.3.
        evt = de.Event(source_layer=99, event_type=99, pid=1)
        r1 = engine.evaluate(evt)
        r2 = engine.evaluate(evt)
        r3 = engine.evaluate(evt)
        self.assertEqual(r1.confidence, 0.3)
        self.assertEqual(r2.confidence, 0.3)
        self.assertEqual(r3.confidence, 0.3)

    def test_wired_deterministic_mean_matches_unwired(self) -> None:
        """With ConfidenceSampler(deterministic_mean=True) attached, the
        confidence must equal the posterior mean, which is arithmetically
        ~= the base confidence for symmetric prior counts. This proves the
        wiring does not distort behaviour in the deterministic path."""
        de = self._load_de()
        engine = de.DecisionEngine()
        cs = mc.ConfidenceSampler(seed=42, deterministic_mean=True)
        engine.set_confidence_sampler(cs)
        # Run many times with an event that hits the default ALLOW path
        # (confidence=0.3). ConfidenceSampler.calibrated() with base=0.3,
        # successes=0, failures=0 yields alpha=1+0+3=4, beta=1+0+7=8,
        # mean=4/12 = 0.333... -- i.e. ~base confidence with a small shift
        # from the Laplace prior. Check the sample is close to that.
        evt = de.Event(source_layer=99, event_type=99, pid=1)
        r = engine.evaluate(evt)
        # calibrated() uses k=10 so alpha = 1 + 0 + 0.3*10 = 4.0,
        # beta = 1 + 0 + 0.7*10 = 8.0, mean = 4/12 = 0.3333...
        self.assertAlmostEqual(r.confidence, 4.0 / 12.0, places=6)

    def test_wired_stochastic_path_varies(self) -> None:
        """With a non-deterministic ConfidenceSampler attached, the
        confidence values across calls should vary (the whole point of MC)."""
        de = self._load_de()
        engine = de.DecisionEngine()
        cs = mc.ConfidenceSampler(seed=42, deterministic_mean=False)
        engine.set_confidence_sampler(cs)
        evt = de.Event(source_layer=99, event_type=99, pid=1)
        values = [engine.evaluate(evt).confidence for _ in range(20)]
        # At least some variation (probability of 20 identical draws ~ 0).
        self.assertGreater(len(set(values)), 1)
        for v in values:
            self.assertGreaterEqual(v, 0.0)
            self.assertLessEqual(v, 1.0)


class ActiveInferenceOptionalMCTest(unittest.TestCase):
    """Verify the active_inference MC posterior path is OFF by default and
    opt-in via the monte_carlo_posterior constructor kwarg."""

    def _load_ai(self):
        _cortex_dir = _REPO_ROOT / "ai-control" / "cortex"
        sys.path.insert(0, str(_cortex_dir))
        import importlib
        if "active_inference" in sys.modules:
            del sys.modules["active_inference"]
        return importlib.import_module("active_inference")

    def test_default_off_returns_dirichlet_mean(self) -> None:
        ai = self._load_ai()
        agent = ai.ActiveInferenceAgent()
        # Train the model with a known sparse posterior.
        for _ in range(10):
            agent.model.update("s0", "a0", "o_hit")
        # Under the Dirichlet mean, predict is the stable ratio with the
        # alpha smoother. Two consecutive calls must return identical dists.
        d1 = agent.model.predict("s0", "a0")
        d2 = agent.model.predict("s0", "a0")
        self.assertEqual(d1, d2)
        self.assertFalse(agent.monte_carlo_posterior)

    def test_mc_on_produces_stochastic_posterior(self) -> None:
        ai = self._load_ai()
        agent = ai.ActiveInferenceAgent(
            monte_carlo_posterior=True, mc_seed=42)
        # Populate the model with some spread so the Dirichlet has non-
        # trivial variance between draws.
        for _ in range(5):
            agent.model.update("s0", "a0", "o_hit")
            agent.model.update("s0", "a0", "o_miss")
        d1 = agent.model.predict("s0", "a0")
        d2 = agent.model.predict("s0", "a0")
        # At least one outcome differs across two draws.
        self.assertTrue(
            any(d1.get(k) != d2.get(k) for k in set(d1) | set(d2)),
            "Two MC draws must differ at least at one outcome",
        )


class RolloutEndpointBodyTest(unittest.TestCase):
    """Unit-test the endpoint body helper without a FastAPI context."""

    def test_default_actions_used_when_missing(self) -> None:
        samplers = mc.register_samplers(seed=42, rate_per_sec=1.0)
        rec = mc._run_rollout_endpoint({}, samplers)
        self.assertIn("ranked", rec)
        self.assertIn("best_action", rec)
        # Default profile "uniform" should be echoed.
        self.assertEqual(rec["profile"], "uniform")
        # Default actions length == 4 (noop / allow / deny / escalate).
        self.assertEqual(len(rec["ranked"]), 4)

    def test_prefer_noop_profile_picks_noop(self) -> None:
        samplers = mc.register_samplers(seed=42, rate_per_sec=1.0)
        rec = mc._run_rollout_endpoint(
            {"actions": ["noop", "deny"],
             "reward_profile": "prefer_noop",
             "n_rollouts": 128},
            samplers,
        )
        self.assertEqual(rec["best_action"], "noop")
        self.assertEqual(rec["profile"], "prefer_noop")


if __name__ == "__main__":
    unittest.main()
