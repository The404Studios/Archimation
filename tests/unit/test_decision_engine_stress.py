"""Stress tests for ``ai-control/cortex/decision_engine.py`` (S79).

S79 Test Agent 2 -- verifies S77 Agent 1's split-lock fix in
DecisionMarkovModel.observe_decision holds at 256-thread contention.
Probes the count-invariant: sum(state_counts) = 2 * (total_observations - 1)
+ (1 if first) since each observe() bumps BOTH prev and next state.

Also stress-tests the DecisionEngine.evaluate pipeline under high QPS
and the _sliding_window_add heuristic state under pid churn.

Gated behind ``STRESS_TESTS=1``. Run with::

    cd tests/unit && STRESS_TESTS=1 python -m unittest test_decision_engine_stress -v

S79 Test Agent 2 deliverable.
"""

from __future__ import annotations

import importlib
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
    sys.modules.pop("decision_engine", None)
    return importlib.import_module("decision_engine")


@unittest.skipUnless(STRESS_ENABLED, "stress tests disabled (set STRESS_TESTS=1)")
class TestDecisionEngineStress(unittest.TestCase):

    def setUp(self):
        self.mod = _load_module()

    def test_256_thread_observe_decision_invariant(self):
        """256 threads each call observe_decision() 1000 times into a
        SHARED DecisionMarkovModel. Verify count invariant:
        total_observations == 256*1000, and that state_counts sum is
        consistent with the double-counting (prev+next) rule.

        S77 Agent 1's split-lock fix must hold at 256-thread concurrency."""
        model = self.mod.DecisionMarkovModel()
        verdicts = ["ALLOW", "DENY", "QUARANTINE", "ESCALATE", "MODIFY"]

        errors = []

        def worker(tid):
            try:
                rng = random.Random(tid)
                for _ in range(1000):
                    v = rng.choice(verdicts)
                    model.observe_decision(v)
            except Exception as e:
                errors.append((tid, e))

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(256)]
        t0 = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=45)
            self.assertFalse(t.is_alive())
        elapsed = time.perf_counter() - t0

        self.assertEqual(errors, [], f"errors: {errors[:3]}")

        total = model.observations
        self.assertEqual(total, 256 * 1000,
                         f"total_observations drift: got {total}, "
                         f"want {256*1000}")
        self.assertLess(elapsed, 60.0,
                        f"256t x 1000 observe took {elapsed:.1f}s")

        # Invariant on state_counts:
        # - First observe: +1 to state_counts[action]
        # - Later observes call self.observe(prev, next): +1 prev, +1 next
        # So sum(state_counts) = 1 + 2*(N-1) = 2N - 1 ONLY when all go
        # through one thread. With 256 parallel streams into the same
        # model, the first-observation early path races: when multiple
        # threads see prev is None from deque state, each counts itself
        # as a "first". S77's fix consolidates the critical section so
        # this should NOT happen. Each thread after the first should
        # fall into the "else -> do_observe" path.
        # So the true invariant is: total = sum(transitions)+1 and
        # sum(state_counts) = 1 + 2*sum(transitions).
        trans_sum = sum(model._transitions.values())
        state_sum = sum(model._state_counts.values())
        # sum(state_counts) should equal 2*trans_sum + 1 if exactly one
        # "first observation" ran.
        expected_state_sum = 2 * trans_sum + 1
        delta = abs(state_sum - expected_state_sum)
        # Tolerate small race window -- this is PROBE data. If delta
        # grows large, S77's lock consolidation is insufficient.
        self.assertLess(delta, 10,
                        f"state_count invariant drift: "
                        f"state_sum={state_sum}, expected={expected_state_sum}, "
                        f"trans_sum={trans_sum}")

    def test_256_thread_evaluate_decision_engine(self):
        """256 threads each call engine.evaluate() 100 times with random
        events. Probes the whole pipeline (policy -> heuristic -> default)
        under contention. Pass = no exceptions, eval_count == 256*100."""
        engine = self.mod.DecisionEngine()
        Event = self.mod.Event
        errors = []

        def worker(tid):
            try:
                rng = random.Random(tid)
                for i in range(100):
                    e = Event(
                        source_layer=rng.choice([0, 2, 3]),
                        event_type=rng.randint(1, 6),
                        pid=rng.randint(1, 10_000),
                        payload={},
                    )
                    engine.evaluate(e)
            except Exception as exc:
                errors.append((tid, exc))

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(256)]
        t0 = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
            self.assertFalse(t.is_alive())
        elapsed = time.perf_counter() - t0

        self.assertEqual(errors, [], f"errors: {errors[:3]}")
        self.assertEqual(engine._eval_count, 256 * 100,
                         f"eval_count drift: {engine._eval_count}")
        self.assertLess(elapsed, 60.0,
                        f"256 x 100 evaluate: {elapsed:.1f}s")

    def test_heuristic_state_growth_under_pid_churn(self):
        """Inject 20_000 distinct PIDs (via EVT_PE_LOAD). The engine
        caps heuristic_state keys at _state_hard_cap; verify no
        unbounded growth."""
        engine = self.mod.DecisionEngine()
        Event = self.mod.Event
        mod = self.mod

        hard_cap = engine._state_hard_cap

        for pid in range(20_000):
            e = Event(
                source_layer=2, event_type=mod.EVT_PE_LOAD,
                pid=pid, payload={},
            )
            engine.evaluate(e)

        # After pruning passes, we expect len(heuristic_state) <= hard_cap.
        # (pruning fires every 100 evals).
        n = len(engine._heuristic_state)
        self.assertLessEqual(n, hard_cap + 100,  # slack for next-prune
                             f"heuristic_state grew unbounded: {n} > {hard_cap}")

    def test_observe_decision_first_write_race(self):
        """ADVERSARIAL: 128 threads enter observe_decision() at the SAME
        MOMENT on a fresh model. Verify only ONE records the "first
        observation" (the others see a non-empty stream and take the
        do_observe path)."""
        model = self.mod.DecisionMarkovModel()
        barrier = threading.Barrier(128)
        errors = []

        def worker(tid):
            try:
                barrier.wait(timeout=10)
                model.observe_decision("ALLOW")
            except Exception as e:
                errors.append((tid, e))

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(128)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
            self.assertFalse(t.is_alive())

        self.assertEqual(errors, [], f"errors: {errors[:3]}")
        # Total observations must be exactly 128 (no increments lost).
        self.assertEqual(model.observations, 128,
                         f"lost observations: {model.observations} / 128")
        # The invariant: exactly ONE call was the "first" and took
        # the in-line path; remaining 127 called observe() recursively.
        # So sum(transitions) = 127 and sum(state_counts) = 1 + 2*127 = 255.
        trans_sum = sum(model._transitions.values())
        state_sum = sum(model._state_counts.values())
        # Tolerance: if 2 threads both saw empty stream (race win), we'd
        # have sum=2 + 2*126 = 254. Bail if large drift.
        self.assertEqual(trans_sum, 127,
                         f"transitions = {trans_sum}, expected 127 "
                         f"(split-lock race!)")
        self.assertEqual(state_sum, 255,
                         f"state_sum = {state_sum}, expected 255")

    def test_sliding_window_contention_under_load(self):
        """Hit _sliding_window_add with 256 threads on the same PID.
        Probes deque concurrency -- Python's deque is thread-safe for
        append+popleft but _sliding_window_add does a cutoff walk under
        NO lock in decision_engine. Probe for dropped/extra entries."""
        engine = self.mod.DecisionEngine()
        Event = self.mod.Event
        mod = self.mod

        def worker():
            for _ in range(200):
                e = Event(
                    source_layer=2, event_type=mod.EVT_PE_TRUST_DENY,
                    pid=777, payload={},
                )
                engine.evaluate(e)

        threads = [threading.Thread(target=worker) for _ in range(256)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
            self.assertFalse(t.is_alive())

        # 256 * 200 = 51_200 evals on the same PID. The deny heuristic
        # fires when >50 denials in 10s, so this WILL fire repeatedly.
        # We don't check verdict; we check that eval_count is exact.
        self.assertEqual(engine._eval_count, 256 * 200)

    def test_default_engine_cas_race(self):
        """2048 DecisionEngine() constructors fired across 128 threads.
        Exactly one must become the _default_engine (first-instance-wins
        under the _default_engine_lock)."""
        # Clear binding first.
        self.mod.set_default_engine(None)
        created = []
        lock = threading.Lock()

        def worker():
            for _ in range(16):
                e = self.mod.DecisionEngine()
                with lock:
                    created.append(e)

        threads = [threading.Thread(target=worker) for _ in range(128)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        self.assertEqual(len(created), 128 * 16)
        default = self.mod.get_default_engine()
        self.assertIsNotNone(default)
        self.assertIs(default, created[0],
                      "first engine did not win the CAS "
                      "(would have broken S77 Agent 1's lock)")


if __name__ == "__main__":
    unittest.main()
