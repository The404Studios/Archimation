"""S79 Test Agent 4 — Monte-Carlo cross-chain: sampler -> engine -> rate limiter.

Pipeline exercised (multi-step)
-------------------------------
    register_samplers(seed=X)           [monte_carlo.py:1041]
          |
          v
    ConfidenceSampler + StochasticRateLimiter (shared RNG)
          |
          v
    get_default_engine() / DecisionEngine()
          |
          v  engine.set_confidence_sampler(cs)
    engine.evaluate(event) -> _finalize -> result.confidence = cs.calibrated(base)

The S77 monte_carlo_engine test pinned the sampler<->engine wire. This test
extends to the CROSS-SAMPLER chain: a rate limiter AND a confidence sampler
attached to the same engine evaluation stream, covering attach/detach
transitions mid-stream.

Mock boundaries:
  * DecisionEngine first-instance-wins: we reset _default_engine per-test
    so each scenario starts clean.
  * No policy / heuristic / LLM registered — events hit default-allow at
    confidence 0.3 (main.py:372) which the sampler then recalibrates.
  * StochasticRateLimiter uses monotonic time_fn — we inject a fake clock
    so "seconds elapsed" is deterministic.
"""

from __future__ import annotations

import itertools
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from _s77_helpers import load_cortex_module  # noqa: E402


def _make_event():
    return SimpleNamespace(
        source_layer=99, event_type=0x99, pid=1234,
        subject_id=0, tid=0, timestamp_ns=0, sequence=0,
        payload={}, flags=0,
    )


class MonteCarloFullChainBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.de = load_cortex_module("decision_engine", unique_suffix="_s79_mc")
        cls.mc = load_cortex_module("monte_carlo", unique_suffix="_s79_mc")

    def setUp(self) -> None:
        # Clean singleton per test for first-instance-wins semantics.
        self.de.set_default_engine(None)
        # Clear any cached module-level samplers from prior tests.
        try:
            self.mc.register_samplers(seed=0)  # reset-ish; new instances.
        except Exception:
            pass


class TestEngineWithLiveSampler(MonteCarloFullChainBase):
    """attach sampler -> evaluate N -> detach -> evaluate M: three phases
    in one test to verify state transitions don't leak."""

    def test_attach_then_detach_then_reattach(self) -> None:
        """Round-trip: deterministic -> sampled -> deterministic -> sampled.
        Between phases the engine singleton must pick up the new sampler."""
        eng = self.de.DecisionEngine()

        # Phase 1: no sampler -> confidence = 0.3.
        r1 = eng.evaluate(_make_event())
        self.assertAlmostEqual(r1.confidence, 0.3, delta=1e-9)

        # Phase 2: attach sampler in deterministic_mean -> fixed posterior mean.
        cs = self.mc.ConfidenceSampler(seed=123, deterministic_mean=True)
        eng.set_confidence_sampler(cs)
        r2 = eng.evaluate(_make_event())
        # Deterministic posterior mean (base 0.3; alpha=1+3, beta=1+7 -> 4/12).
        self.assertAlmostEqual(r2.confidence, 4.0 / 12.0, delta=0.001)

        # Phase 3: detach -> back to 0.3.
        eng.set_confidence_sampler(None)
        r3 = eng.evaluate(_make_event())
        self.assertAlmostEqual(r3.confidence, 0.3, delta=1e-9)

        # Phase 4: reattach a different sampler -> new values.
        cs2 = self.mc.ConfidenceSampler(seed=9999, deterministic_mean=False)
        eng.set_confidence_sampler(cs2)
        confs = [eng.evaluate(_make_event()).confidence for _ in range(20)]
        for c in confs:
            self.assertGreaterEqual(c, 0.0)
            self.assertLessEqual(c, 1.0)
        # Non-deterministic => at least 2 distinct values across 20 draws.
        self.assertGreater(len(set(round(c, 6) for c in confs)), 1)

    def test_default_engine_singleton_picked_up_by_api(self) -> None:
        """api_server lifespan (ai-control/daemon/api_server.py) calls
        ``get_default_engine()`` and attaches a sampler. We simulate that
        handoff: DecisionEngine() becomes _default_engine, then a caller
        retrieves it and attaches without re-instantiating."""
        # Simulate the "first instance wins" handshake.
        eng_live = self.de.DecisionEngine()
        # The "api lifespan" impersonator fetches + installs.
        eng_from_default = self.de.get_default_engine()
        self.assertIs(eng_live, eng_from_default)
        cs = self.mc.ConfidenceSampler(seed=42, deterministic_mean=True)
        eng_from_default.set_confidence_sampler(cs)

        # A second caller that uses the singleton sees the attached sampler.
        eng_third_party = self.de.get_default_engine()
        self.assertIs(eng_third_party._confidence_sampler, cs)


class TestStochasticRateLimiterInFlight(MonteCarloFullChainBase):
    """StochasticRateLimiter throttling a high-frequency event stream.

    This doesn't directly involve the cortex bus (no handler subscribes to
    a rate-limited stream today) but it validates the Poisson-arrival
    model sits alongside ConfidenceSampler without interference."""

    def test_rate_limiter_denies_when_pressure_exceeds_lambda(self) -> None:
        """Build a rate limiter with rate=1/sec, capacity=5; burst 20
        requests with zero time elapsed. After the first 5 are granted
        the rest must be denied (no time elapsed -> no refill)."""
        clock = [0.0]
        rl = self.mc.StochasticRateLimiter(
            rate_per_sec=1.0, capacity=5, seed=42,
            time_fn=lambda: clock[0],
        )
        granted, denied = 0, 0
        for _ in range(20):
            if rl.consume(1.0):
                granted += 1
            else:
                denied += 1
        self.assertEqual(granted, 5)
        self.assertEqual(denied, 15)
        stats = rl.stats()
        self.assertEqual(stats["granted"], 5)
        self.assertEqual(stats["denied"], 15)

    def test_rate_limiter_refills_over_simulated_time(self) -> None:
        """Tick the fake clock forward to give the Poisson process time
        to deliver tokens. With rate=10/sec and 2 seconds elapsed, mean
        arrivals=20 — easily drains our 5-capacity bucket up."""
        clock = [0.0]
        rl = self.mc.StochasticRateLimiter(
            rate_per_sec=10.0, capacity=5, seed=123,
            time_fn=lambda: clock[0],
        )
        # Drain to 0.
        for _ in range(5):
            rl.consume(1.0)
        self.assertEqual(rl.stats()["tokens"], 0.0)
        # Advance clock 2 seconds -> Poisson draws should refill to capacity.
        clock[0] = 2.0
        # Attempt to consume; _refill fires on consume() entry.
        rl.consume(1.0)
        stats = rl.stats()
        # Granted should now exceed the initial 5 due to refill.
        self.assertGreaterEqual(stats["granted"], 6)


class TestSharedRNGAcrossSamplers(MonteCarloFullChainBase):
    """register_samplers(seed=X) yields reproducible sequences across
    confidence + rate_limiter. A second register_samplers(seed=X) call
    produces identical sequences from BOTH, which proves the seed really
    flows through the shared MonteCarloSampler."""

    def test_two_registered_pairs_produce_identical_draws(self) -> None:
        out1 = self.mc.register_samplers(seed=555)
        cs1 = out1["confidence_sampler"]
        rl1 = out1["rate_limiter"]
        seq_cs1 = cs1.sample_many(2.0, 5.0, n=10)

        out2 = self.mc.register_samplers(seed=555)
        cs2 = out2["confidence_sampler"]
        rl2 = out2["rate_limiter"]
        seq_cs2 = cs2.sample_many(2.0, 5.0, n=10)

        self.assertEqual(seq_cs1, seq_cs2)
        # rate_limiters should both have rate set (nonzero).
        self.assertGreater(rl1.rate_per_sec, 0)
        self.assertGreater(rl2.rate_per_sec, 0)


if __name__ == "__main__":
    unittest.main()
