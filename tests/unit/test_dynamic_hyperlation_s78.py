"""S78 Dev G -- dynamic_hyperlation deep audit coverage.

Fills the test-coverage gap the S77 Agent 1 audit explicitly deferred
(``dynamic_hyperlation.py`` 1878 LOC had zero unit tests prior to S78).

Covers:

* ``MarkovTransitionMatrix`` construction + ``recent_window_max`` honouring
  (S78 fix: direct constructor now sizes the ring to match; parity with
  ``from_dict``).
* ``MarkovTransitionMatrix.update`` bool-rejection (S78 fix: bool is an
  int subclass but would break ``MARKOV_STATES[idx]`` type contracts).
* ``MarkovTransitionMatrix`` absorbing behaviour (APOPTOSIS redirect),
  matrix normalization, stationary convergence, hitting-time edge cases.
* ``MarkovTransitionMatrix.from_dict`` / ``to_dict`` round-trip and
  defensive shape coercion.
* ``HyperlationFilter`` AND-composition + ``parse_query`` validation.
* ``HyperlationStateTracker.snapshot`` non-aliasing (S78 fix:
  caller-mutations to the returned dict must NOT leak into internal
  state seen by other callers).
* ``HyperlationStateTracker.state_for`` empty-on-None contract (S78 fix:
  a ``state=None`` value previously leaked None back; now returns "").
* ``HyperlationStateTracker.classify_hypothesis_violation`` slot logic
  for all four fixture shapes (starvation / divergence / steady /
  apoptosis).

Intentionally does NOT require /sys/kernel/trust_* to exist; every test
runs against synthetic in-memory state.
"""
from __future__ import annotations

import math
import sys
import time
import threading
import unittest
from collections import deque
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CORTEX_DIR = _REPO_ROOT / "ai-control" / "cortex"
if str(_CORTEX_DIR) not in sys.path:
    sys.path.insert(0, str(_CORTEX_DIR))

# Reset any stale singleton from a sibling test run.
sys.modules.pop("dynamic_hyperlation", None)
import dynamic_hyperlation as DH  # noqa: E402


# --------------------------------------------------------------------------
# MarkovTransitionMatrix: construction
# --------------------------------------------------------------------------

class MarkovConstructionTest(unittest.TestCase):
    def test_default_construction(self) -> None:
        m = DH.MarkovTransitionMatrix()
        self.assertEqual(m.last_seen_state, None)
        self.assertEqual(m.history_len, 0)
        self.assertEqual(len(m.counts), DH.MARKOV_N_STATES)
        self.assertTrue(all(len(r) == DH.MARKOV_N_STATES for r in m.counts))
        self.assertEqual(m.recent.maxlen, 32)

    def test_recent_window_max_honoured_by_constructor(self) -> None:
        """S78 fix: direct constructor now sizes the ring buffer."""
        m = DH.MarkovTransitionMatrix(recent_window_max=64)
        self.assertEqual(m.recent.maxlen, 64,
                         "direct constructor must honour recent_window_max")

    def test_recent_window_max_invalid_clamps_to_default(self) -> None:
        m = DH.MarkovTransitionMatrix(recent_window_max=0)
        self.assertEqual(m.recent.maxlen, 32)
        m2 = DH.MarkovTransitionMatrix(recent_window_max=-5)
        self.assertEqual(m2.recent.maxlen, 32)

    def test_preserves_pre_existing_recent_entries(self) -> None:
        # If a caller supplies `recent=deque([...])`, __post_init__ should
        # keep the contents while fixing the maxlen.
        m = DH.MarkovTransitionMatrix(
            recent_window_max=16,
            recent=deque([0, 1, 2]),
        )
        self.assertEqual(m.recent.maxlen, 16)
        self.assertEqual(list(m.recent), [0, 1, 2])


# --------------------------------------------------------------------------
# MarkovTransitionMatrix: update() type discipline
# --------------------------------------------------------------------------

class MarkovUpdateTest(unittest.TestCase):
    def test_rejects_non_int(self) -> None:
        m = DH.MarkovTransitionMatrix()
        m.update("STEADY_FLOW")  # type: ignore[arg-type]
        m.update(None)  # type: ignore[arg-type]
        m.update(1.5)  # type: ignore[arg-type]
        self.assertIsNone(m.last_seen_state)
        self.assertEqual(m.history_len, 0)

    def test_rejects_bool_even_though_int_subclass(self) -> None:
        """S78 fix: bool is an int subclass; must not slip through."""
        m = DH.MarkovTransitionMatrix()
        m.update(True)  # would previously be accepted as int
        m.update(False)
        self.assertIsNone(m.last_seen_state)
        self.assertEqual(m.history_len, 0)

    def test_rejects_out_of_range(self) -> None:
        m = DH.MarkovTransitionMatrix()
        m.update(-1)
        m.update(DH.MARKOV_N_STATES)
        m.update(999)
        self.assertIsNone(m.last_seen_state)

    def test_accepts_valid_index(self) -> None:
        m = DH.MarkovTransitionMatrix()
        m.update(0)
        m.update(1)
        self.assertEqual(m.last_seen_state, 1)
        self.assertEqual(m.history_len, 2)
        # First update (prev was None) does NOT count into counts matrix.
        self.assertEqual(m.counts[0][1], 1)

    def test_apoptosis_is_absorbing(self) -> None:
        m = DH.MarkovTransitionMatrix()
        m.update(0)
        m.update(DH.MARKOV_APOPTOSIS_IDX)  # enter absorbing
        m.update(1)  # should be redirected to APOPTOSIS
        self.assertEqual(m.last_seen_state, DH.MARKOV_APOPTOSIS_IDX)
        # counts[APOP][APOP] should increment when post-absorption updates arrive
        self.assertEqual(m.counts[DH.MARKOV_APOPTOSIS_IDX][DH.MARKOV_APOPTOSIS_IDX], 1)


# --------------------------------------------------------------------------
# MarkovTransitionMatrix: matrix / stationary / hitting-time
# --------------------------------------------------------------------------

class MarkovMathTest(unittest.TestCase):
    def test_empty_matrix_is_identity(self) -> None:
        m = DH.MarkovTransitionMatrix()
        P = m.matrix()
        for i in range(DH.MARKOV_N_STATES):
            for j in range(DH.MARKOV_N_STATES):
                self.assertEqual(P[i][j], 1.0 if i == j else 0.0)

    def test_rows_sum_to_one(self) -> None:
        m = DH.MarkovTransitionMatrix()
        # Seed with arbitrary transitions.
        for s in [0, 1, 0, 2, 1, 2, 0]:
            m.update(s)
        P = m.matrix()
        for i, row in enumerate(P):
            self.assertAlmostEqual(sum(row), 1.0, places=9,
                                   msg=f"row {i} does not sum to 1: {row}")

    def test_empty_stationary_is_uniform(self) -> None:
        m = DH.MarkovTransitionMatrix()
        pi = m.stationary()
        self.assertEqual(len(pi), DH.MARKOV_N_STATES)
        for v in pi:
            self.assertAlmostEqual(v, 1.0 / DH.MARKOV_N_STATES, places=6)

    def test_stationary_all_non_negative_and_normalized(self) -> None:
        m = DH.MarkovTransitionMatrix()
        for _ in range(30):
            m.update(0)
        for _ in range(10):
            m.update(1)
        m.update(0)
        pi = m.stationary()
        self.assertAlmostEqual(sum(pi), 1.0, places=6)
        for v in pi:
            self.assertGreaterEqual(v, 0.0)

    def test_hitting_time_apoptosis_is_zero_when_absorbed(self) -> None:
        m = DH.MarkovTransitionMatrix()
        m.update(0)
        m.update(DH.MARKOV_APOPTOSIS_IDX)
        self.assertEqual(m.expected_hitting_time_to_apoptosis(), 0.0)

    def test_hitting_time_none_when_no_history(self) -> None:
        m = DH.MarkovTransitionMatrix()
        self.assertEqual(m.expected_hitting_time_to_apoptosis(), 0.0)

    def test_hitting_time_finite_with_reachable_apoptosis(self) -> None:
        m = DH.MarkovTransitionMatrix()
        # Observe a path STEADY -> STEADY -> APOPTOSIS, then park last
        # back at a transient state.
        m.update(0)
        m.update(0)
        m.update(DH.MARKOV_APOPTOSIS_IDX)
        m.last_seen_state = 0
        hit = m.expected_hitting_time_to_apoptosis()
        self.assertTrue(math.isfinite(hit))
        self.assertGreater(hit, 0.0)


# --------------------------------------------------------------------------
# MarkovTransitionMatrix: KL drift anomaly
# --------------------------------------------------------------------------

class MarkovKLTest(unittest.TestCase):
    def test_kl_zero_when_steady(self) -> None:
        m = DH.MarkovTransitionMatrix()
        for _ in range(50):
            m.update(0)
        self.assertLess(m.kl_divergence_recent_vs_steady(), 0.05)

    def test_kl_spikes_on_recent_shift(self) -> None:
        m = DH.MarkovTransitionMatrix()
        for _ in range(50):
            m.update(0)
        baseline = m.kl_divergence_recent_vs_steady(recent_window=10)
        for _ in range(8):
            m.update(1)
        after = m.kl_divergence_recent_vs_steady(recent_window=10)
        self.assertGreater(after, baseline + 0.5)

    def test_kl_zero_on_empty_history(self) -> None:
        m = DH.MarkovTransitionMatrix()
        self.assertEqual(m.kl_divergence_recent_vs_steady(), 0.0)

    def test_kl_nonneg_with_unseen_state_in_recent(self) -> None:
        # State 2 present in recent but NEVER in historical transitions.
        # Epsilon smoothing should produce a finite, positive KL, not inf.
        m = DH.MarkovTransitionMatrix()
        for _ in range(10):
            m.update(0)
        # Force recent to have state 2 entries without touching counts.
        for _ in range(5):
            m.recent.append(2)
        kl = m.kl_divergence_recent_vs_steady(recent_window=5)
        self.assertTrue(math.isfinite(kl))
        self.assertGreater(kl, 0.0)


# --------------------------------------------------------------------------
# MarkovTransitionMatrix: serialization
# --------------------------------------------------------------------------

class MarkovSerializationTest(unittest.TestCase):
    def test_round_trip_preserves_fields(self) -> None:
        m = DH.MarkovTransitionMatrix()
        for s in [0, 0, 1, 2, 0, 1]:
            m.update(s)
        rt = DH.MarkovTransitionMatrix.from_dict(m.to_dict())
        self.assertEqual(rt.counts, m.counts)
        self.assertEqual(rt.history_len, m.history_len)
        self.assertEqual(rt.last_seen_state, m.last_seen_state)
        self.assertEqual(list(rt.recent), list(m.recent))

    def test_from_dict_defensive_against_bad_shape(self) -> None:
        # Truncated counts matrix, bad recent entries, negative window.
        bad = {
            "counts": [[1, 2]],
            "recent": ["foo", 999, -1, 1, 2],
            "recent_window_max": -1,
            "last_seen_state": "nope",
            "history_len": "not an int",
        }
        rt = DH.MarkovTransitionMatrix.from_dict(bad)
        # Counts coerced to full 4x4
        self.assertEqual(len(rt.counts), DH.MARKOV_N_STATES)
        self.assertTrue(all(len(r) == DH.MARKOV_N_STATES for r in rt.counts))
        # Recent only keeps the 2 in-range values
        self.assertEqual(list(rt.recent), [1, 2])
        # Default ring size applied
        self.assertEqual(rt.recent.maxlen, 32)
        # Bad last_seen rewrites to None
        self.assertIsNone(rt.last_seen_state)
        # Bad history_len rewrites to 0
        self.assertEqual(rt.history_len, 0)

    def test_from_dict_honours_recent_window_max(self) -> None:
        rt = DH.MarkovTransitionMatrix.from_dict({"recent_window_max": 16})
        self.assertEqual(rt.recent.maxlen, 16)


# --------------------------------------------------------------------------
# HyperlationFilter
# --------------------------------------------------------------------------

class FilterTest(unittest.TestCase):
    def test_empty_filter_matches_everything(self) -> None:
        f = DH.HyperlationFilter()
        self.assertTrue(f.matches({"id": 1, "state": "STEADY_FLOW"}))

    def test_state_filter_narrows(self) -> None:
        f = DH.HyperlationFilter(state_filter={"BEHAVIORAL_DIVERGENCE"})
        self.assertTrue(f.matches({"id": 1, "state": "BEHAVIORAL_DIVERGENCE"}))
        self.assertFalse(f.matches({"id": 1, "state": "STEADY_FLOW"}))

    def test_pid_filter(self) -> None:
        f = DH.HyperlationFilter(subject_ids={1, 3})
        self.assertTrue(f.matches({"id": 3, "state": "STEADY_FLOW"}))
        self.assertFalse(f.matches({"id": 2, "state": "STEADY_FLOW"}))

    def test_class_filter_uses_heuristic_when_missing(self) -> None:
        f = DH.HyperlationFilter(class_filter={"game"})
        # XY, S_t low -> heuristic returns "game"
        self.assertTrue(f.matches({"id": 9, "state": "STEADY_FLOW",
                                    "S_t": 20.0, "sex": DH.SEX_XY, "G_t": 0}))
        # XX kernel_driver -> rejected
        self.assertFalse(f.matches({"id": 9, "state": "STEADY_FLOW",
                                     "S_t": 90.0, "sex": DH.SEX_XX, "G_t": 1}))

    def test_parse_query_validates(self) -> None:
        with self.assertRaises(ValueError):
            DH.HyperlationFilter.parse_query(class_csv="weapon")
        with self.assertRaises(ValueError):
            DH.HyperlationFilter.parse_query(state_csv="PANIC")
        with self.assertRaises(ValueError):
            DH.HyperlationFilter.parse_query(pid_csv="abc")

    def test_parse_query_well_formed(self) -> None:
        f = DH.HyperlationFilter.parse_query(
            class_csv="game,user_app",
            state_csv="BEHAVIORAL_DIVERGENCE",
            pid_csv="1,3",
        )
        self.assertEqual(f.subject_ids, {1, 3})
        self.assertEqual(f.state_filter, {"BEHAVIORAL_DIVERGENCE"})
        self.assertEqual(f.class_filter, {"game", "user_app"})


# --------------------------------------------------------------------------
# HyperlationStateTracker: snapshot isolation (S78 aliasing fix)
# --------------------------------------------------------------------------

class SnapshotIsolationTest(unittest.TestCase):
    """Verify snapshot() returns caller-owned structures.

    Previously, snapshot() did `dict(self._snapshot)` (shallow) and then
    returned the internal `subjects` list. A caller that mutated the
    returned dict (added annotations, reordered, appended) corrupted
    what other concurrent callers observed. S78 fix: list + dict copies.
    """

    def setUp(self) -> None:
        self.tracker = DH.HyperlationStateTracker.get()
        with self.tracker._snapshot_lock:
            self.tracker._snapshot = {
                "subjects": [
                    {"id": 1, "state": "STEADY_FLOW", "class": "user_app"},
                    {"id": 2, "state": "BEHAVIORAL_DIVERGENCE",
                     "class": "game"},
                ],
                "global": {"total_metabolism": 0.5},
                "timestamp": time.time(),
                "source": "test",
            }

    def test_subjects_list_is_not_aliased(self) -> None:
        snap = self.tracker.snapshot()
        snap["subjects"].append({"id": 999, "state": "HACKED"})
        fresh = self.tracker.snapshot()
        self.assertEqual(len(fresh["subjects"]), 2,
                         "caller append leaked into internal state")

    def test_per_subject_dict_not_aliased(self) -> None:
        snap = self.tracker.snapshot()
        snap["subjects"][0]["hacked"] = True
        fresh = self.tracker.snapshot()
        self.assertNotIn("hacked", fresh["subjects"][0],
                         "caller mutation of per-subject dict leaked")

    def test_global_dict_not_aliased(self) -> None:
        snap = self.tracker.snapshot()
        snap["global"]["hacked"] = True
        fresh = self.tracker.snapshot()
        self.assertNotIn("hacked", fresh["global"])

    def test_filter_path_also_isolated(self) -> None:
        f = DH.HyperlationFilter(class_filter={"game"})
        snap = self.tracker.snapshot(filter=f)
        snap["subjects"].clear()
        fresh = self.tracker.snapshot()
        self.assertEqual(len(fresh["subjects"]), 2)


# --------------------------------------------------------------------------
# HyperlationStateTracker: state_for None handling (S78 fix)
# --------------------------------------------------------------------------

class StateForTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tracker = DH.HyperlationStateTracker.get()

    def test_missing_subject_returns_empty(self) -> None:
        with self.tracker._snapshot_lock:
            self.tracker._snapshot = {
                "subjects": [], "global": {},
                "timestamp": time.time(), "source": "test",
            }
        self.assertEqual(self.tracker.state_for(12345), "")

    def test_state_none_coerced_to_empty(self) -> None:
        """S78 fix: a subject with state=None must still degrade to ""."""
        with self.tracker._snapshot_lock:
            self.tracker._snapshot = {
                "subjects": [{"id": 7, "state": None}],
                "global": {}, "timestamp": time.time(), "source": "test",
            }
        self.assertEqual(self.tracker.state_for(7), "")

    def test_state_known_returns_named_state(self) -> None:
        with self.tracker._snapshot_lock:
            self.tracker._snapshot = {
                "subjects": [{"id": 7, "state": "BEHAVIORAL_DIVERGENCE"}],
                "global": {}, "timestamp": time.time(), "source": "test",
            }
        self.assertEqual(self.tracker.state_for(7), "BEHAVIORAL_DIVERGENCE")


# --------------------------------------------------------------------------
# HyperlationStateTracker: classify_hypothesis_violation
# --------------------------------------------------------------------------

class HypothesisClassifierTest(unittest.TestCase):
    def test_steady_flow_triggers_nothing(self) -> None:
        rec = {
            "id": 1, "C_t": 900.0, "S_t": 70.0,
            "metabolism_rate": 0.01, "state": "STEADY_FLOW",
        }
        got = DH.HyperlationStateTracker.classify_hypothesis_violation(rec)
        self.assertEqual(got, [])

    def test_metabolic_starvation_flags_dynamic_authority(self) -> None:
        rec = {
            "id": 1, "C_t": 50.0, "S_t": 45.0,
            "metabolism_rate": 0.3,  # > 2x baseline
            "state": "METABOLIC_STARVATION",
        }
        got = DH.HyperlationStateTracker.classify_hypothesis_violation(rec)
        self.assertIn(DH.HYP_DYNAMIC_AUTHORITY, got)

    def test_behavioral_divergence_flags_biological_trust(self) -> None:
        rec = {
            "id": 1, "C_t": 900.0, "S_t": 25.0,
            "metabolism_rate": 0.01,
            "state": "BEHAVIORAL_DIVERGENCE",
        }
        got = DH.HyperlationStateTracker.classify_hypothesis_violation(rec)
        self.assertIn(DH.HYP_BIOLOGICAL_TRUST, got)

    def test_apoptosis_explicit_flag(self) -> None:
        rec = {
            "id": 1, "C_t": 0.0, "S_t": 0.0,
            "metabolism_rate": 0.0, "state": "STEADY_FLOW",
            "apoptosis_event": True,
        }
        got = DH.HyperlationStateTracker.classify_hypothesis_violation(rec)
        self.assertIn(DH.HYP_APOPTOTIC_SAFETY, got)

    def test_apoptosis_inferred_from_score_collapse(self) -> None:
        # Both S_t and C_t collapsed to zero with no explicit flag =>
        # infer apoptosis.
        rec = {
            "id": 1, "C_t": 0.0, "S_t": 0.0,
            "metabolism_rate": 0.0, "state": "STEADY_FLOW",
        }
        got = DH.HyperlationStateTracker.classify_hypothesis_violation(rec)
        self.assertIn(DH.HYP_APOPTOTIC_SAFETY, got)

    def test_malformed_metabolism_rate_degrades_safely(self) -> None:
        rec = {
            "id": 1, "metabolism_rate": "nope", "state": "STEADY_FLOW",
            "S_t": 50.0, "C_t": 500.0,
        }
        got = DH.HyperlationStateTracker.classify_hypothesis_violation(rec)
        self.assertEqual(got, [])


# --------------------------------------------------------------------------
# HyperlationStateTracker: Markov update concurrency smoke
# --------------------------------------------------------------------------

class MarkovUpdateConcurrencyTest(unittest.TestCase):
    """Not an adversarial race test; just confirms the _history_lock holds
    up under a modest parallel load without losing or double-counting."""

    def test_parallel_updates_on_distinct_subjects(self) -> None:
        tracker = DH.HyperlationStateTracker.get()
        # Scrub lingering Markov state under the lock.
        with tracker._history_lock:
            tracker._markov_per_subject.clear()

        def worker(sid: int) -> None:
            with tracker._history_lock:
                if sid not in tracker._markov_per_subject:
                    tracker._markov_per_subject[sid] = \
                        DH.MarkovTransitionMatrix()
                for _ in range(25):
                    tracker._markov_per_subject[sid].update(0)

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
        with tracker._history_lock:
            for sid in range(8):
                m = tracker._markov_per_subject.get(sid)
                self.assertIsNotNone(m)
                # 25 updates, first one transitions prev=None -> no count;
                # remaining 24 self-transitions 0->0.
                self.assertEqual(m.history_len, 25)
                self.assertEqual(m.counts[0][0], 24)


if __name__ == "__main__":
    unittest.main(verbosity=2)
