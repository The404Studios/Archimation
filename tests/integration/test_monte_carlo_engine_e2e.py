"""End-to-end: ConfidenceSampler -> DecisionEngine._finalize (S76 Agent E).

Pipeline exercised
------------------
    DecisionEngine()  (registers as module-level _default_engine on first
                       instantiation — decision_engine.py:240-242)
            |
            v
    get_default_engine() -> our engine instance
            |
            v
    engine.set_confidence_sampler(ConfidenceSampler(seed=...))
            |
            v
    engine.evaluate(event) -> _finalize ->
        sampler.calibrated(base_confidence) is called (decision_engine.py:404)
        EvalResult.confidence is replaced by the beta draw.

The new wire is easy to regress: ``_default_engine`` was an attribute
that didn't exist pre-S76, and the api_server's getattr-based probe
fell through silently (any AttributeError on .set_confidence_sampler
would be swallowed). An end-to-end test exercising both ``first
instance wins'' and ``sampler override'' paths pins the contract.

S77 Agent 5 deliverable.
"""

from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from _s77_helpers import load_cortex_module  # noqa: E402


class EngineMonteCarloBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.de = load_cortex_module("decision_engine", unique_suffix="_mc")
        cls.mc = load_cortex_module("monte_carlo", unique_suffix="_mc")

    def setUp(self) -> None:
        # Start each test with a clean _default_engine singleton so
        # first-instance-wins semantics are testable in isolation.
        self.de.set_default_engine(None)


class TestDefaultEngineRegistration(EngineMonteCarloBase):
    """Covers the S76 first-instance-wins contract (decision_engine.py:240)."""

    def test_first_instance_becomes_default(self) -> None:
        self.assertIsNone(self.de.get_default_engine())
        eng1 = self.de.DecisionEngine()
        self.assertIs(self.de.get_default_engine(), eng1)

    def test_subsequent_instance_does_not_rebind(self) -> None:
        eng1 = self.de.DecisionEngine()
        eng2 = self.de.DecisionEngine()
        self.assertIsNot(eng1, eng2)
        # First instance is still the default.
        self.assertIs(self.de.get_default_engine(), eng1)

    def test_set_default_engine_overrides(self) -> None:
        eng1 = self.de.DecisionEngine()
        eng2 = self.de.DecisionEngine()
        self.de.set_default_engine(eng2)
        self.assertIs(self.de.get_default_engine(), eng2)
        self.de.set_default_engine(None)
        self.assertIsNone(self.de.get_default_engine())


class TestConfidenceSamplerAttachment(EngineMonteCarloBase):
    """Attach sampler, evaluate, assert confidence was redrawn."""

    def _make_event(self) -> object:
        """Build a minimal event-like object the engine will default-allow.

        source_layer=99 (no matching policy), event_type=0x99, empty payload
        -> _eval_policy and _eval_heuristics both miss -> default-allow path
        with confidence=0.3 from main.py:364.
        """
        from types import SimpleNamespace
        return SimpleNamespace(
            source_layer=99, event_type=0x99, pid=1234,
            subject_id=0, tid=0, timestamp_ns=0, sequence=0,
            payload={}, flags=0,
        )

    def test_no_sampler_keeps_deterministic_confidence(self) -> None:
        """Baseline: without a sampler, default-allow confidence is exactly 0.3."""
        eng = self.de.DecisionEngine()
        res = eng.evaluate(self._make_event())
        self.assertAlmostEqual(res.confidence, 0.3, delta=1e-9)

    def test_deterministic_mean_sampler_is_idempotent(self) -> None:
        """ConfidenceSampler(deterministic_mean=True) returns the posterior
        mean; calibrated(0.3) returns alpha/(alpha+beta) where
        alpha=1+0+0.3*10=4 and beta=1+0+0.7*10=8. Mean = 4/12 = 0.333
        (monte_carlo.py:742-749)."""
        eng = self.de.DecisionEngine()
        sampler = self.mc.ConfidenceSampler(seed=42, deterministic_mean=True)
        eng.set_confidence_sampler(sampler)
        res = eng.evaluate(self._make_event())
        self.assertAlmostEqual(res.confidence, 4.0 / 12.0, delta=0.001)

    def test_stochastic_sampler_bounds_and_varies(self) -> None:
        """A non-deterministic sampler produces values in [0, 1] that
        differ from the raw 0.3 across evaluations (stochasticity present
        on the wire)."""
        eng = self.de.DecisionEngine()
        sampler = self.mc.ConfidenceSampler(seed=2026, deterministic_mean=False)
        eng.set_confidence_sampler(sampler)
        confidences = []
        for _ in range(32):
            confidences.append(eng.evaluate(self._make_event()).confidence)
        for c in confidences:
            self.assertGreaterEqual(c, 0.0)
            self.assertLessEqual(c, 1.0)
        # At least some variation — seeded sampler produces a distribution.
        self.assertGreater(len(set(round(c, 6) for c in confidences)), 1,
                           "sampler produced a constant (did _finalize call it?)")

    def test_detach_sampler_restores_deterministic_path(self) -> None:
        """Setting sampler to None reverts confidence to deterministic 0.3."""
        eng = self.de.DecisionEngine()
        eng.set_confidence_sampler(
            self.mc.ConfidenceSampler(seed=7, deterministic_mean=False),
        )
        # Sanity: first eval uses sampler.
        r1 = eng.evaluate(self._make_event())
        eng.set_confidence_sampler(None)
        r2 = eng.evaluate(self._make_event())
        self.assertAlmostEqual(r2.confidence, 0.3, delta=1e-9)
        # r1 may or may not equal 0.3 depending on the RNG; pin only the
        # "detached returns deterministic" contract that matters.
        del r1


class TestRegisterSamplersProcessWide(EngineMonteCarloBase):
    """register_samplers installs ConfidenceSampler + RolloutSearch +
    FaultInjector + StochasticRateLimiter with a shared RNG (one seed
    pins all four). Verifies the S75 Agent C contract."""

    def test_register_samplers_wires_all_four_singletons(self) -> None:
        out = self.mc.register_samplers(seed=1234)
        self.assertIn("confidence_sampler", out)
        self.assertIn("rollout_search", out)
        self.assertIn("fault_injector", out)
        self.assertIn("rate_limiter", out)
        # Module-level getters return the same instances.
        self.assertIs(self.mc.get_confidence_sampler(), out["confidence_sampler"])
        self.assertIs(self.mc.get_rollout_search(), out["rollout_search"])
        self.assertIs(self.mc.get_fault_injector(), out["fault_injector"])
        self.assertIs(self.mc.get_rate_limiter(), out["rate_limiter"])

    def test_shared_rng_pinned_by_seed(self) -> None:
        """Two register_samplers(seed=X) calls should produce identical
        sequences from their confidence samplers -- proves the seed
        really flows through shared MonteCarloSampler."""
        out1 = self.mc.register_samplers(seed=9999)
        seq1 = out1["confidence_sampler"].sample_many(2.0, 5.0, n=32)
        out2 = self.mc.register_samplers(seed=9999)
        seq2 = out2["confidence_sampler"].sample_many(2.0, 5.0, n=32)
        self.assertEqual(seq1, seq2)


if __name__ == "__main__":
    unittest.main()
