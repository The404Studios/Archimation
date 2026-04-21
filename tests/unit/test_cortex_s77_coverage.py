"""S77 Agent 1 -- cortex coverage gap closure.

Covers recent S75/S76 additions that previously had no regression tests:

* ``DecisionMarkovModel.observe_decision`` thread-safety (S77 race fix).
* ``get_default_engine`` / ``set_default_engine`` / first-instance-wins
  (S76 Agent E wiring).
* ``BeliefState.from_observers(library_census=...)`` bucketing (S75
  follow-up).
* ``ActiveInferenceAgent(monte_carlo_posterior=True)`` end-to-end path
  (S75 Agent C MC posterior).
* ``event_bus.parse_pe_trust_escalate_payload`` signed-score schema
  (S77 Agent 1 fix).
* ``event_bus.parse_pe_trust_deny_payload`` packed-layout parse.
* ``decision_engine._finalize`` Monte-Carlo confidence integration
  exercised end-to-end via evaluate().
* ``CortexHandlers.handle_pe_trust_escalate`` consumer path (S75 follow-up).

Intentionally does NOT run QEMU or heavy builds; uses in-process stubs.
"""
from __future__ import annotations

import importlib.util
import sys
import threading
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CORTEX_DIR = _REPO_ROOT / "ai-control" / "cortex"
_MC_PATH = _CORTEX_DIR / "monte_carlo.py"


def _load_cortex_module(mod_name: str):
    """Load a cortex module fresh under an isolated sys.modules key.

    Cortex modules reference each other via relative imports; we insert
    the cortex directory at the front of sys.path so plain imports work.
    Each test class reloads the target modules to reset module-level
    singletons (``_default_engine`` / ``_default_decision_model``).
    """
    if str(_CORTEX_DIR) not in sys.path:
        sys.path.insert(0, str(_CORTEX_DIR))
    # Force a fresh import so module-level singletons reset between
    # test methods.
    for name in (mod_name,):
        sys.modules.pop(name, None)
    import importlib
    return importlib.import_module(mod_name)


def _load_monte_carlo():
    """Monte-Carlo has no siblings that import it at module load; load by path."""
    name = "cortex_monte_carlo_s77"
    spec = importlib.util.spec_from_file_location(name, _MC_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------
# DecisionMarkovModel.observe_decision thread safety (S77 race fix)
# --------------------------------------------------------------------------

class DecisionMarkovModelThreadSafetyTest(unittest.TestCase):
    """The S77 Agent 1 race-fix consolidates observe_decision into a single
    critical section. This test exercises the concurrent path and verifies
    the invariant ``total_observations == total stream appends`` holds."""

    def setUp(self) -> None:
        self.de = _load_cortex_module("decision_engine")

    def test_concurrent_observe_decision_invariant(self) -> None:
        model = self.de.DecisionMarkovModel()
        n_threads = 8
        n_per_thread = 200
        expected_total = n_threads * n_per_thread

        def worker(i: int) -> None:
            for j in range(n_per_thread):
                model.observe_decision(f"ALLOW_{i % 3}")

        threads = [
            threading.Thread(target=worker, args=(i,))
            for i in range(n_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Invariant 1: total_observations == total calls to observe_decision.
        # (_total_observations is incremented on EVERY observe_decision that
        # recorded state, which is every call in this test.)
        self.assertEqual(model.observations, expected_total)

        # Invariant 2: sum(transition counts) + 1 (for the very first
        # observation which has no predecessor) == total_observations.
        transition_total = sum(
            c for c in model._transitions.values()
        )
        self.assertEqual(transition_total + 1, expected_total)

    def test_observe_decision_first_call_records_no_transition(self) -> None:
        model = self.de.DecisionMarkovModel()
        model.observe_decision("ALLOW")
        # First observation never records a transition.
        self.assertEqual(model.transition_count, 0)
        # But state count for ALLOW should be 1.
        self.assertEqual(model._state_counts.get("ALLOW"), 1)
        self.assertEqual(model.observations, 1)
        self.assertEqual(model.last_action, "ALLOW")

    def test_observe_decision_ignores_non_string(self) -> None:
        model = self.de.DecisionMarkovModel()
        model.observe_decision(42)  # type: ignore[arg-type]
        model.observe_decision(None)  # type: ignore[arg-type]
        self.assertEqual(model.observations, 0)


# --------------------------------------------------------------------------
# _default_engine singleton (S76 Agent E wiring)
# --------------------------------------------------------------------------

class DefaultEngineSingletonTest(unittest.TestCase):
    """Cover get_default_engine / set_default_engine / first-instance-wins."""

    def setUp(self) -> None:
        self.de = _load_cortex_module("decision_engine")
        # Reset the module-level singleton before each test since the
        # fixture imports the module fresh but api_server or prior tests
        # may have bound an engine.
        self.de.set_default_engine(None)

    def test_get_default_engine_returns_none_initially(self) -> None:
        self.assertIsNone(self.de.get_default_engine())

    def test_first_engine_wins(self) -> None:
        e1 = self.de.DecisionEngine()
        e2 = self.de.DecisionEngine()
        self.assertIs(self.de.get_default_engine(), e1)
        self.assertIsNot(self.de.get_default_engine(), e2)

    def test_set_default_engine_overrides(self) -> None:
        e1 = self.de.DecisionEngine()
        e2 = self.de.DecisionEngine()
        self.assertIs(self.de.get_default_engine(), e1)
        self.de.set_default_engine(e2)
        self.assertIs(self.de.get_default_engine(), e2)

    def test_set_default_engine_none_clears(self) -> None:
        _ = self.de.DecisionEngine()
        self.assertIsNotNone(self.de.get_default_engine())
        self.de.set_default_engine(None)
        self.assertIsNone(self.de.get_default_engine())

    def test_concurrent_construction_single_winner(self) -> None:
        """Ten threads race to construct the first engine. Exactly one
        must become the default; the other nine get distinct instances
        that do NOT bind to the module-level slot."""
        engines: list = []
        barrier = threading.Barrier(10)

        def worker() -> None:
            barrier.wait()
            engines.append(self.de.DecisionEngine())

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(engines), 10)
        winner = self.de.get_default_engine()
        self.assertIsNotNone(winner)
        # Winner must be one of the constructed engines.
        self.assertIn(winner, engines)
        # Exactly one engine is the default (all other instances are not).
        non_winners = [e for e in engines if e is not winner]
        self.assertEqual(len(non_winners), 9)


# --------------------------------------------------------------------------
# BeliefState.from_observers library_census kwarg (S75 follow-up)
# --------------------------------------------------------------------------

class BeliefStateLibraryCensusTest(unittest.TestCase):
    """Covers the library_census bucketing in active_inference.BeliefState."""

    def setUp(self) -> None:
        self.ai = _load_cortex_module("active_inference")

    def _stub_census(self, ratio: float):
        """Return an object whose .snapshot() returns the supplied ratio."""
        class _S:
            def snapshot(inner_self) -> dict:
                return {"unique_library_ratio": ratio}
        return _S()

    def test_none_bucket_for_low_ratio(self) -> None:
        b = self.ai.BeliefState.from_observers(
            library_census=self._stub_census(0.05))
        self.assertEqual(b.library_distribution, "none")

    def test_low_bucket(self) -> None:
        b = self.ai.BeliefState.from_observers(
            library_census=self._stub_census(0.20))
        self.assertEqual(b.library_distribution, "low")

    def test_mid_bucket(self) -> None:
        b = self.ai.BeliefState.from_observers(
            library_census=self._stub_census(0.40))
        self.assertEqual(b.library_distribution, "mid")

    def test_high_bucket(self) -> None:
        b = self.ai.BeliefState.from_observers(
            library_census=self._stub_census(0.60))
        self.assertEqual(b.library_distribution, "high")

    def test_saturated_bucket(self) -> None:
        b = self.ai.BeliefState.from_observers(
            library_census=self._stub_census(0.95))
        self.assertEqual(b.library_distribution, "saturated")

    def test_missing_census_defaults_to_none(self) -> None:
        b = self.ai.BeliefState.from_observers(library_census=None)
        self.assertEqual(b.library_distribution, "none")

    def test_census_failure_is_survivable(self) -> None:
        class _BadCensus:
            def snapshot(inner_self):
                raise RuntimeError("census exploded")

        # Should NOT raise; defaults to "none".
        b = self.ai.BeliefState.from_observers(library_census=_BadCensus())
        self.assertEqual(b.library_distribution, "none")

    def test_token_includes_library_dimension(self) -> None:
        b = self.ai.BeliefState.from_observers(
            library_census=self._stub_census(0.45))
        self.assertIn("lb:mid", b.token())


# --------------------------------------------------------------------------
# ActiveInferenceAgent monte_carlo_posterior=True (S75 Agent C)
# --------------------------------------------------------------------------

class ActiveInferenceMCPosteriorTest(unittest.TestCase):
    """The ``monte_carlo_posterior=True`` path installs an RNG on the
    GenerativeModel and makes predict() return a Dirichlet sample rather
    than the Dirichlet mean. Exercise both code paths."""

    def setUp(self) -> None:
        self.ai = _load_cortex_module("active_inference")

    def test_default_is_false(self) -> None:
        agent = self.ai.ActiveInferenceAgent()
        self.assertFalse(agent.monte_carlo_posterior)
        self.assertIsNone(agent.model._mc_rng)

    def test_mc_seed_pins_rng(self) -> None:
        agent = self.ai.ActiveInferenceAgent(
            monte_carlo_posterior=True, mc_seed=123)
        self.assertTrue(agent.monte_carlo_posterior)
        self.assertIsNotNone(agent.model._mc_rng)
        # Two agents with the same seed + same model state produce the
        # same first sample.
        a2 = self.ai.ActiveInferenceAgent(
            monte_carlo_posterior=True, mc_seed=123)
        for _ in range(3):
            agent.model.update("s", "a", "o1")
            a2.model.update("s", "a", "o1")
        d1 = agent.model.predict("s", "a")
        d2 = a2.model.predict("s", "a")
        # Same-seed replay over same observations must produce identical
        # dirichlet draws.
        self.assertEqual(d1, d2)

    def test_explicit_sample_kwarg_overrides_default(self) -> None:
        agent = self.ai.ActiveInferenceAgent(
            monte_carlo_posterior=True, mc_seed=42)
        agent.model.update("s", "a", "o1")
        # With sample=False, even with MC enabled, we get the mean.
        d_mean_1 = agent.model.predict("s", "a", sample=False)
        d_mean_2 = agent.model.predict("s", "a", sample=False)
        self.assertEqual(d_mean_1, d_mean_2)

    def test_bootstrap_returns_noop(self) -> None:
        agent = self.ai.ActiveInferenceAgent(
            bootstrap=10, monte_carlo_posterior=False)
        # No observations yet -> bootstrap path -> noop.
        sel = agent.select_action()
        self.assertEqual(sel.action, "noop")
        self.assertIn("bootstrap", sel.reason.lower())


# --------------------------------------------------------------------------
# event_bus payload parsers (S75 follow-up TRUST_ESCALATE + S77 schema fix)
# --------------------------------------------------------------------------

class EventBusParsersTest(unittest.TestCase):
    def setUp(self) -> None:
        self.eb = _load_cortex_module("event_bus")

    def test_parse_pe_trust_escalate_short_returns_raw_len(self) -> None:
        """Short payloads are flagged but not dropped."""
        short = b"\x00" * 64
        result = self.eb.parse_pe_trust_escalate_payload(short)
        self.assertIn("raw_len", result)
        self.assertEqual(result["raw_len"], 64)

    def test_parse_pe_trust_escalate_roundtrip_positive(self) -> None:
        """Valid 140-byte payload with positive scores."""
        import struct as _s
        api = b"AdjustTokenPrivileges\x00" + b"\x00" * (128 - 22)
        tail = _s.pack("<iiI", 100, 600, 0x1)
        payload = api + tail
        self.assertEqual(len(payload), 140)
        result = self.eb.parse_pe_trust_escalate_payload(payload)
        self.assertEqual(result["api_name"], "AdjustTokenPrivileges")
        self.assertEqual(result["from_score"], 100)
        self.assertEqual(result["to_score"], 600)
        self.assertEqual(result["reason"], 0x1)

    def test_parse_pe_trust_escalate_signed_scores(self) -> None:
        """S77 Agent 1 fix: negative trust scores MUST round-trip as
        negative int32, not underflow to huge positive uint32."""
        import struct as _s
        api = b"CreateProcess\x00" + b"\x00" * (128 - 14)
        # -500 was the silent-bug case: under <I the unpack would have
        # returned 4294966796 (2^32 - 500).
        tail = _s.pack("<iiI", -500, 0, 0x2)
        payload = api + tail
        result = self.eb.parse_pe_trust_escalate_payload(payload)
        self.assertEqual(result["from_score"], -500)
        self.assertEqual(result["to_score"], 0)
        # reason stays unsigned
        self.assertEqual(result["reason"], 0x2)

    def test_parse_pe_trust_deny_packed_layout(self) -> None:
        """Exactly-137-byte packed layout (no struct padding)."""
        import struct as _s
        api = b"OpenProcess\x00" + b"\x00" * (128 - 12)
        tail = _s.pack("<BiI", 5, -100, 42)
        payload = api + tail
        self.assertEqual(len(payload), 137)
        result = self.eb.parse_pe_trust_deny_payload(payload)
        self.assertEqual(result["api_name"], "OpenProcess")
        self.assertEqual(result["category"], 5)
        self.assertEqual(result["score"], -100)
        self.assertEqual(result["tokens"], 42)

    def test_parse_pe_trust_deny_too_short_returns_empty(self) -> None:
        """Payloads shorter than 137 bytes return an empty dict."""
        result = self.eb.parse_pe_trust_deny_payload(b"\x00" * 100)
        self.assertEqual(result, {})


# --------------------------------------------------------------------------
# DecisionEngine._finalize MC confidence integration via evaluate()
# --------------------------------------------------------------------------

class DecisionEngineFinalizeMCTest(unittest.TestCase):
    """S75 Agent C wired the ConfidenceSampler into _finalize but the
    existing tests cover only the deterministic_mean variant. This
    exercises the stochastic path end-to-end through evaluate()."""

    def setUp(self) -> None:
        self.mc = _load_monte_carlo()
        self.de = _load_cortex_module("decision_engine")

    def test_evaluate_with_stochastic_sampler_stays_in_unit(self) -> None:
        engine = self.de.DecisionEngine()
        cs = self.mc.ConfidenceSampler(seed=42, deterministic_mean=False)
        engine.set_confidence_sampler(cs)
        # Use a matched policy-tier event (immune alert -> quarantine,
        # confidence 1.0) so we're calibrating a base=1.0 input.
        evt = self.de.Event(
            source_layer=0,
            event_type=self.de.EVT_IMMUNE_ALERT,
            pid=1, subject_id=1,
        )
        for _ in range(50):
            r = engine.evaluate(evt)
            self.assertGreaterEqual(r.confidence, 0.0)
            self.assertLessEqual(r.confidence, 1.0)
            self.assertEqual(r.verdict, self.de.Verdict.QUARANTINE)

    def test_evaluate_broken_sampler_does_not_crash(self) -> None:
        engine = self.de.DecisionEngine()

        class _BadSampler:
            def calibrated(self, base):
                raise RuntimeError("sampler on fire")

        engine.set_confidence_sampler(_BadSampler())
        evt = self.de.Event(source_layer=0, event_type=0x01, pid=1)
        # Must not raise; the sampler failure is swallowed.
        r = engine.evaluate(evt)
        self.assertIsNotNone(r)

    def test_evaluate_sampler_returning_out_of_range_is_ignored(self) -> None:
        """A sampler returning 1.5 should leave the base confidence alone."""
        engine = self.de.DecisionEngine()

        class _BogusSampler:
            def calibrated(self, base):
                return 1.5   # outside [0, 1]

        engine.set_confidence_sampler(_BogusSampler())
        # Use the IMMUNE_ALERT policy rule (tier=policy, confidence=1.0)
        # so we have a predictable base confidence to compare against.
        evt = self.de.Event(
            source_layer=0,
            event_type=self.de.EVT_IMMUNE_ALERT,
            pid=1, subject_id=1,
        )
        r = engine.evaluate(evt)
        # Out-of-range draws are rejected; base confidence (1.0 for
        # policy tier) is preserved.
        self.assertEqual(r.confidence, 1.0)


# --------------------------------------------------------------------------
# DecisionMarkovModel API (used by /cortex/markov/decisions endpoint)
# --------------------------------------------------------------------------

class DecisionMarkovAPIShapeTest(unittest.TestCase):
    """Covers the duck-typed properties and snapshot() shape expected by
    cortex/api.py::_markov_decision_snapshot."""

    def setUp(self) -> None:
        self.de = _load_cortex_module("decision_engine")

    def test_snapshot_has_expected_keys(self) -> None:
        model = self.de.DecisionMarkovModel()
        model.observe_decision("ALLOW")
        model.observe_decision("DENY")
        snap = model.snapshot()
        for key in (
            "states", "state_counts", "transitions",
            "top_transitions", "total_observations",
            "last_action", "last_timestamp",
        ):
            self.assertIn(key, snap, f"snapshot missing {key}")
        self.assertEqual(snap["last_action"], "DENY")
        self.assertEqual(snap["total_observations"], 2)
        self.assertIn("ALLOW->DENY", snap["transitions"])

    def test_predict_next_empty_for_unknown_origin(self) -> None:
        model = self.de.DecisionMarkovModel()
        self.assertEqual(model.predict_next("NEVER_SEEN"), [])

    def test_predict_next_sorted_by_probability(self) -> None:
        model = self.de.DecisionMarkovModel()
        for _ in range(10):
            model.observe_decision("A")
            model.observe_decision("B")   # A->B happens 10 times
        model.observe_decision("A")
        model.observe_decision("C")       # A->C happens once
        top = model.predict_next("A", k=2)
        self.assertEqual(len(top), 2)
        # B must rank first (10 transitions vs 1).
        self.assertEqual(top[0][0], "B")
        self.assertGreater(top[0][1], top[1][1])


# --------------------------------------------------------------------------
# CortexHandlers.handle_pe_trust_escalate (S75 follow-up consumer)
# --------------------------------------------------------------------------

class HandlePeTrustEscalateTest(unittest.TestCase):
    """Smoke-cover the S75 follow-up consumer handler. We can't bring up
    the full main.py stack here, so we instantiate CortexHandlers with
    minimal stubs and synthesize an Event."""

    def setUp(self) -> None:
        # main.py uses relative imports (``from .config import ...``) so
        # we need to import it as a sub-module of a ``cortex`` package.
        # We alias ai-control/cortex as package ``cortex_pkg77`` for this.
        try:
            ai_ctrl = _REPO_ROOT / "ai-control"
            if str(ai_ctrl) not in sys.path:
                sys.path.insert(0, str(ai_ctrl))
            # Importing the real ``cortex`` package (dir already on path)
            # pulls in __init__.py which is empty; main.py relative-imports
            # its siblings.
            import importlib
            sys.modules.pop("cortex.main", None)
            sys.modules.pop("cortex.event_bus", None)
            self.main_mod = importlib.import_module("cortex.main")
            self.event_bus_mod = importlib.import_module("cortex.event_bus")
            self.de = importlib.import_module("cortex.decision_engine")
        except ImportError as exc:
            self.skipTest(f"main.py deps unavailable: {exc}")

    def _make_handlers(self):
        # Minimal stubs that match the attributes the handler touches.
        class _Autonomy:
            def create_decision(self, domain, kind, reason, **kwargs):
                from types import SimpleNamespace
                return SimpleNamespace(approved=True)

        class _Orchestrator:
            def notify(self, *a, **kw):
                # Must return an awaitable for _track_task.
                import asyncio
                async def _noop():
                    return None
                return _noop()

            def freeze_process(self, pid, force=False):
                pass

            def trust_quarantine(self, pid):
                pass

        return self.main_mod.CortexHandlers(
            autonomy=_Autonomy(),
            orchestrator=_Orchestrator(),
            decision_engine=None,   # no engine -> fall through to autonomy
        )

    def _synth_event(self):
        return self.event_bus_mod.Event(
            magic=0, version=1,
            source_layer=int(self.event_bus_mod.SourceLayer.RUNTIME),
            event_type=int(self.event_bus_mod.PeEventType.TRUST_ESCALATE),
            timestamp_ns=0, pid=1234, tid=1234, subject_id=1,
            sequence=0, payload_len=140, flags=0,
            payload={
                "api_name": "AdjustPriv",
                "from_score": -100,
                "to_score": 500,
                "reason": 0x1,
            },
            raw_payload=b"",
        )

    def test_handler_approved_path_records_event(self) -> None:
        handlers = self._make_handlers()
        event = self._synth_event()
        handlers.handle_pe_trust_escalate(event)
        # One record was appended with "escalation_approved".
        recent = handlers.recent_events
        self.assertTrue(recent)
        self.assertEqual(recent[-1]["action"], "escalation_approved")
        self.assertEqual(recent[-1]["pid"], 1234)


if __name__ == "__main__":
    unittest.main()
