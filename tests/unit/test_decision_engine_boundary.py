"""Boundary tests for ``ai-control/cortex/decision_engine.py``.

S79 Test Agent 3 -- edges in DecisionEngine module-level singleton
plumbing + evaluate() on edge-case events.

Boundaries probed:
  * DecisionEngine() default construction
  * get_default_engine() before any construction -> None
  * After 1 / 2 / 3 DecisionEngine() -> first-instance-wins (S76 Agent E)
  * set_default_engine(None) -- clear
  * evaluate() empty event / all-None fields / oversized event

Not gated. Must complete <5s.
"""

from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CORTEX_DIR = _REPO_ROOT / "ai-control" / "cortex"

if str(_CORTEX_DIR) not in sys.path:
    sys.path.insert(0, str(_CORTEX_DIR))


def _load_fresh():
    """Reload decision_engine so module-level ``_default_engine`` is None."""
    for name in ("decision_engine",):
        sys.modules.pop(name, None)
    return importlib.import_module("decision_engine")


class DefaultEngineSingletonBoundaries(unittest.TestCase):
    """First-instance-wins semantics of _default_engine."""

    def test_get_default_before_any_construction(self) -> None:
        """Fresh module -> get_default_engine() is None."""
        de = _load_fresh()
        self.assertIsNone(de.get_default_engine())

    def test_first_instance_wins(self) -> None:
        """After 1 construction -> _default_engine is that instance."""
        de = _load_fresh()
        e1 = de.DecisionEngine()
        self.assertIs(de.get_default_engine(), e1)

    def test_second_instance_does_not_rebind(self) -> None:
        """After 2 constructions -> default remains e1."""
        de = _load_fresh()
        e1 = de.DecisionEngine()
        e2 = de.DecisionEngine()
        self.assertIsNot(e1, e2)
        self.assertIs(de.get_default_engine(), e1)

    def test_third_instance_same_behavior(self) -> None:
        """After N=3 -> still e1."""
        de = _load_fresh()
        e1 = de.DecisionEngine()
        de.DecisionEngine()
        de.DecisionEngine()
        self.assertIs(de.get_default_engine(), e1)

    def test_set_default_engine_overrides(self) -> None:
        """set_default_engine(e2) -> default becomes e2."""
        de = _load_fresh()
        e1 = de.DecisionEngine()
        e2 = de.DecisionEngine()
        de.set_default_engine(e2)
        self.assertIs(de.get_default_engine(), e2)
        # Follow-up: now back to None.
        de.set_default_engine(None)
        self.assertIsNone(de.get_default_engine())

    def test_set_default_engine_none_clears(self) -> None:
        """set_default_engine(None) -> cleared."""
        de = _load_fresh()
        de.DecisionEngine()
        self.assertIsNotNone(de.get_default_engine())
        de.set_default_engine(None)
        self.assertIsNone(de.get_default_engine())


class EvaluateEventShapeBoundaries(unittest.TestCase):
    """evaluate() with minimal / None-field / oversized events."""

    def setUp(self) -> None:
        self.de = _load_fresh()
        self.engine = self.de.DecisionEngine()

    def test_default_event_returns_default_allow(self) -> None:
        """Event with default (zero) fields -> default ALLOW verdict."""
        evt = self.de.Event(source_layer=0, event_type=0)
        r = self.engine.evaluate(evt)
        # No policy matches (source=0 type=0 has no rule); no heuristic
        # fires. Default = ALLOW with tier="default" + confidence=0.3.
        self.assertEqual(r.verdict, self.de.Verdict.ALLOW)
        self.assertEqual(r.tier, "default")

    def test_event_with_empty_payload_dict(self) -> None:
        """payload={} -> safe, same result as default."""
        evt = self.de.Event(source_layer=2, event_type=0x99, payload={})
        r = self.engine.evaluate(evt)
        # No matching rule/heuristic for event_type 0x99 -> default ALLOW.
        self.assertEqual(r.verdict, self.de.Verdict.ALLOW)

    def test_event_with_huge_payload(self) -> None:
        """Very large payload dict (1000 keys) -> still evaluates."""
        big = {f"k{i}": i for i in range(1000)}
        evt = self.de.Event(source_layer=2, event_type=0xAA, payload=big)
        r = self.engine.evaluate(evt)
        self.assertEqual(r.verdict, self.de.Verdict.ALLOW)

    def test_event_with_negative_pid(self) -> None:
        """pid=-1 -> no crash, sliding window keyed on pid=-1."""
        evt = self.de.Event(
            source_layer=2,
            event_type=self.de.EVT_PE_LOAD,
            pid=-1,
            payload={},
        )
        r = self.engine.evaluate(evt)
        self.assertIsNotNone(r)

    def test_event_with_huge_pid(self) -> None:
        """pid=2**31-1 -> no overflow in dict key formation."""
        evt = self.de.Event(
            source_layer=2,
            event_type=self.de.EVT_PE_LOAD,
            pid=(1 << 31) - 1,
            payload={},
        )
        r = self.engine.evaluate(evt)
        self.assertIsNotNone(r)


class EvaluateMultipleInvocations(unittest.TestCase):
    """Repeated evaluate() increments counters correctly."""

    def setUp(self) -> None:
        self.de = _load_fresh()
        self.engine = self.de.DecisionEngine()

    def test_zero_evaluations_counter(self) -> None:
        """Fresh engine -> 0 evals."""
        self.assertEqual(self.engine._eval_count, 0)

    def test_one_eval_increments_counter(self) -> None:
        """After 1 evaluate -> _eval_count == 1."""
        evt = self.de.Event(source_layer=0, event_type=0)
        self.engine.evaluate(evt)
        self.assertEqual(self.engine._eval_count, 1)

    def test_many_evals_all_counted(self) -> None:
        """100 evaluates -> _eval_count == 100."""
        evt = self.de.Event(source_layer=0, event_type=0)
        for _ in range(100):
            self.engine.evaluate(evt)
        self.assertEqual(self.engine._eval_count, 100)


class DecisionMarkovModelBoundaries(unittest.TestCase):
    """DecisionMarkovModel edge cases."""

    def setUp(self) -> None:
        self.de = _load_fresh()
        self.de.reset_default_model()

    def test_fresh_model_empty_state(self) -> None:
        """Fresh model -> no observations, no transitions."""
        m = self.de.get_default_model()
        self.assertEqual(m.observations, 0)
        self.assertEqual(m.state_count, 0)
        self.assertEqual(m.transition_count, 0)
        self.assertEqual(m.last_action, None)

    def test_single_observation_no_transition(self) -> None:
        """1 observe_decision -> 1 state, 0 transitions."""
        m = self.de.get_default_model()
        m.observe_decision("ALLOW")
        # No predecessor -> no transitions.
        self.assertEqual(m.transition_count, 0)
        self.assertEqual(m.state_count, 1)

    def test_two_observations_one_transition(self) -> None:
        """2 observe_decision -> 1 transition (a -> b)."""
        m = self.de.get_default_model()
        m.observe_decision("ALLOW")
        m.observe_decision("DENY")
        self.assertEqual(m.transition_count, 1)

    def test_predict_unknown_origin_returns_empty(self) -> None:
        """predict_next('UNSEEN') -> []."""
        m = self.de.get_default_model()
        self.assertEqual(m.predict_next("UNSEEN"), [])

    def test_non_string_input_ignored(self) -> None:
        """observe_decision(123) -> silently no-op (source early-return)."""
        m = self.de.get_default_model()
        m.observe_decision(123)  # type: ignore[arg-type]
        self.assertEqual(m.observations, 0)


if __name__ == "__main__":
    unittest.main()
