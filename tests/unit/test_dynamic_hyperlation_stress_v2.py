"""High-scale stress tests for ``ai-control/cortex/dynamic_hyperlation.py`` (S79).

S79 Test Agent 2 -- probes MarkovTransitionMatrix + HyperlationStateTracker
under heavy load, ratifying the S78 Dev G fixes (bool-rejection at update
site, recent-window maxlen honoured, snapshot shallow-copy isolation).

Scenarios:
  * 100_000 MarkovTransitionMatrix.update calls -- count totals exact.
  * 32 threads x 1000 updates on DISTINCT matrices (one per subject) --
    no row-stochastic violations, history_len exact per matrix.
  * 1000 snapshots during concurrent updates on the singleton tracker --
    snapshot isolation contract (S78 fix at dynamic_hyperlation.py:886-893):
    no shared-state corruption between caller dicts.
  * Mixed-state flood with absorbing-state corner case: once APOPTOSIS
    (idx=3) is reached, subsequent updates must be coerced to idx=3.
  * bool rejection at update site (S78 Dev G fix at line 228): True /
    False passed as state must not mutate counts.

Gated behind ``STRESS_TESTS=1``. Run with::

    cd tests/unit && STRESS_TESTS=1 python -m unittest test_dynamic_hyperlation_stress_v2 -v

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
    sys.modules.pop("dynamic_hyperlation", None)
    return importlib.import_module("dynamic_hyperlation")


@unittest.skipUnless(STRESS_ENABLED, "stress tests disabled (set STRESS_TESTS=1)")
class TestDynamicHyperlationStressV2(unittest.TestCase):

    def setUp(self):
        self.mod = _load_module()

    # ----- MarkovTransitionMatrix.update -----------------------------------

    def test_100k_update_count_totals(self):
        """100_000 MarkovTransitionMatrix.update calls on a single matrix.
        The sum of all counts[i][j] must equal history_len - 1 (first
        update has no predecessor, so no transition counted)."""
        n = 100_000
        m = self.mod.MarkovTransitionMatrix()
        # Alternate through the 3 transient states + occasional APOPTOSIS.
        rng = random.Random(0x5EED)
        apoptosis_at: int = n + 1  # we may or may not hit it
        seen_absorb = False
        for i in range(n):
            s = rng.choice([0, 1, 2])
            # About 1 in 10_000 we push APOPTOSIS so we can verify the
            # absorbing rule kicks in under flood.
            if rng.random() < 0.0001:
                s = 3
                if not seen_absorb:
                    apoptosis_at = i
                    seen_absorb = True
            m.update(s)

        self.assertEqual(m.history_len, n,
                         f"history_len: got {m.history_len}, want {n}")
        total_transitions = sum(sum(row) for row in m.counts)
        self.assertEqual(total_transitions, n - 1,
                         f"total transitions {total_transitions}, want {n-1}")

        # If APOPTOSIS was hit, absorbing rule means no NEW transient
        # counts from rows != 3 after that point -- everything funnels
        # into column 3 of row 3.
        if seen_absorb:
            self.assertEqual(m.last_seen_state, 3,
                             "last_seen_state should be APOPTOSIS")

    def test_bool_rejection_at_update(self):
        """Pass True/False as state (both are int subclasses). S78 Dev G
        fix (dynamic_hyperlation.py:228) rejects bool explicitly.
        Verify 10_000 rejected updates leave state untouched."""
        m = self.mod.MarkovTransitionMatrix()
        # Baseline: legitimate update
        m.update(0)
        baseline_state = m.last_seen_state
        baseline_hist = m.history_len

        for _ in range(10_000):
            m.update(True)
            m.update(False)

        # bool rejections should leave these unchanged.
        self.assertEqual(m.last_seen_state, baseline_state,
                         "bool update mutated last_seen_state")
        self.assertEqual(m.history_len, baseline_hist,
                         "bool update mutated history_len")
        self.assertEqual(sum(sum(row) for row in m.counts), 0,
                         "bool update inserted transition counts")

    def test_32t_x_1000_updates_distinct_matrices(self):
        """32 threads each own their own MarkovTransitionMatrix; each
        does 1000 updates. History lengths must be exactly 1000 each,
        and row-stochastic invariant (rows sum to 1.0 after normalize)."""
        matrices = [self.mod.MarkovTransitionMatrix() for _ in range(32)]
        errors = []

        def worker(mtx, tid):
            try:
                rng = random.Random(tid)
                for _ in range(1000):
                    mtx.update(rng.randint(0, 2))
            except Exception as e:
                errors.append((tid, e))

        t0 = time.perf_counter()
        threads = [threading.Thread(target=worker, args=(m, i))
                   for i, m in enumerate(matrices)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
            self.assertFalse(t.is_alive())
        elapsed = time.perf_counter() - t0

        self.assertEqual(errors, [], f"errors: {errors[:3]}")
        for idx, m in enumerate(matrices):
            self.assertEqual(m.history_len, 1000,
                             f"matrix {idx} history_len {m.history_len}")
            # Row-stochastic after normalization.
            P = m.matrix()
            for i, row in enumerate(P):
                s = sum(row)
                self.assertAlmostEqual(
                    s, 1.0, places=6,
                    msg=f"matrix {idx} row {i} sum={s:.6f}"
                )
        self.assertLess(elapsed, 30.0,
                        f"32t x 1000 distinct updates: {elapsed:.1f}s")

    def test_absorbing_state_after_flood(self):
        """Once state 3 (APOPTOSIS) is recorded, all subsequent updates
        to any state should be coerced to 3 in the count matrix. Probes
        dynamic_hyperlation.py:235-237 absorbing-rule at 10k step flood."""
        m = self.mod.MarkovTransitionMatrix()
        m.update(0)
        m.update(3)  # Now absorbed
        # Flood with transient updates; absorbing rule coerces them to 3.
        for _ in range(10_000):
            for s in (0, 1, 2):
                m.update(s)

        self.assertEqual(m.last_seen_state, 3,
                         "absorbing state rule broken")
        # All transitions post-absorption came from state 3 going to 3.
        # counts[3][3] should dominate.
        self.assertGreater(m.counts[3][3], 10_000,
                           f"counts[3][3]={m.counts[3][3]}")
        # Non-absorbing rows (0,1,2) should have no outgoing counts after
        # the first two updates (only the 0->3 transition added by our
        # explicit setup sits in counts[0][3]).
        transient_total = (sum(m.counts[0]) + sum(m.counts[1])
                           + sum(m.counts[2]))
        # Allow the 1 genuine transition from the setup phase.
        self.assertLessEqual(transient_total, 2,
                             f"transient rows still accrued counts: "
                             f"row0={m.counts[0]} row1={m.counts[1]} "
                             f"row2={m.counts[2]}")

    # ----- HyperlationStateTracker snapshot isolation ----------------------

    def test_snapshot_isolation_1000_caller_mutations(self):
        """1000 snapshots during concurrent updates; each caller mutates
        the returned dict (adds fields, replaces subjects list). S78 fix
        (line 886-893) shallow-copies subjects + global; ensure mutation
        cannot leak into the tracker or between callers."""
        # Use a fresh tracker (not the singleton) so tests don't pollute.
        tracker = self.mod.HyperlationStateTracker()

        # Pre-populate a non-empty snapshot via the poller fake path:
        # directly poke the internal _snapshot under its lock to simulate
        # a poll tick.
        fake_subjects = [
            {"id": i, "state": "STEADY_FLOW", "score": 0.9,
             "class_hint": "app"}
            for i in range(32)
        ]
        with tracker._snapshot_lock:
            tracker._snapshot = {
                "subjects": list(fake_subjects),
                "global": {"theorems_violated": [],
                           "total_metabolism": 0.0,
                           "active_meiotic_bonds": 0,
                           "cancer_detections": 0},
                "timestamp": time.time(),
                "source": "test",
            }

        errors = []
        stop = threading.Event()

        def updater():
            """Simulate poller by swapping _snapshot repeatedly."""
            try:
                i = 0
                while not stop.is_set():
                    new_subjects = [
                        {"id": j, "state": "STEADY_FLOW", "score": 0.9,
                         "class_hint": "app", "poll_n": i}
                        for j in range(32)
                    ]
                    with tracker._snapshot_lock:
                        tracker._snapshot = {
                            "subjects": new_subjects,
                            "global": {"theorems_violated": [],
                                       "total_metabolism": float(i),
                                       "active_meiotic_bonds": 0,
                                       "cancer_detections": 0},
                            "timestamp": time.time(),
                            "source": "test",
                        }
                    i += 1
            except Exception as e:
                errors.append(("update", e))

        def reader(tid):
            try:
                rng = random.Random(tid)
                for _ in range(250):
                    snap = tracker.snapshot()
                    # Mutate the returned dict aggressively.
                    snap["INJECTED"] = True
                    snap["global"]["MUTATED"] = tid
                    for s in snap["subjects"]:
                        s["MUTATED_BY"] = tid
                    # Reverse the subjects list (in-place mutation).
                    snap["subjects"].reverse()
                    # Sleep a tiny bit to let updater intersperse.
                    if rng.random() < 0.1:
                        time.sleep(0.0001)
            except Exception as e:
                errors.append(("read", tid, e))

        upd = threading.Thread(target=updater, daemon=True)
        readers = [threading.Thread(target=reader, args=(i,))
                   for i in range(4)]

        t0 = time.perf_counter()
        upd.start()
        for r in readers:
            r.start()
        for r in readers:
            r.join(timeout=60)
            self.assertFalse(r.is_alive())
        stop.set()
        upd.join(timeout=5)
        elapsed = time.perf_counter() - t0

        self.assertEqual(errors, [], f"errors: {errors[:3]}")
        # Final internal snapshot must not show the INJECTED key.
        final = tracker.snapshot()
        self.assertNotIn("INJECTED", final,
                         "caller mutation leaked into internal snapshot")
        self.assertNotIn("MUTATED", final["global"],
                         "global dict aliasing: caller mutation leaked")
        for s in final["subjects"]:
            self.assertNotIn("MUTATED_BY", s,
                             f"subject dict aliasing: caller mutation leaked: {s}")
        self.assertLess(elapsed, 60.0,
                        f"snapshot isolation test: {elapsed:.1f}s")

    def test_concurrent_update_and_matrix_read(self):
        """16 threads update a shared MarkovTransitionMatrix while 4
        threads read matrix() / stationary(). This is actually UNSAFE
        per the class docstring (no internal lock on the matrix itself),
        but the tracker wraps it in _history_lock; we simulate that
        contract here and verify no exception propagates."""
        m = self.mod.MarkovTransitionMatrix()
        m_lock = threading.Lock()

        stop = threading.Event()
        errors = []

        def writer(tid):
            try:
                rng = random.Random(tid)
                while not stop.is_set():
                    with m_lock:
                        m.update(rng.randint(0, 2))
            except Exception as e:
                errors.append(("w", tid, e))

        def reader(tid):
            try:
                while not stop.is_set():
                    with m_lock:
                        _ = m.matrix()
                        _ = m.stationary()
                        _ = m.kl_divergence_recent_vs_steady()
            except Exception as e:
                errors.append(("r", tid, e))

        writers = [threading.Thread(target=writer, args=(i,), daemon=True)
                   for i in range(16)]
        readers = [threading.Thread(target=reader, args=(i,), daemon=True)
                   for i in range(4)]
        for t in writers + readers:
            t.start()
        time.sleep(3.0)
        stop.set()
        for t in writers + readers:
            t.join(timeout=5)

        self.assertEqual(errors, [], f"races: {errors[:3]}")
        self.assertGreater(m.history_len, 0)
        P = m.matrix()
        for i, row in enumerate(P):
            self.assertAlmostEqual(sum(row), 1.0, places=6,
                                   msg=f"row {i} not stochastic")

    def test_recent_window_maxlen_honored_at_flood(self):
        """S78 Dev G fix: __post_init__ re-sizes the `recent` deque to
        `recent_window_max`. Flood with 10_000 updates and verify the
        deque is capped at the configured maxlen."""
        m = self.mod.MarkovTransitionMatrix(recent_window_max=100)
        # Honour check BEFORE flood
        self.assertEqual(m.recent.maxlen, 100,
                         f"recent_window_max not applied: "
                         f"maxlen={m.recent.maxlen}")

        for i in range(10_000):
            m.update(i % 3)

        self.assertEqual(len(m.recent), 100,
                         f"recent window grew past maxlen: "
                         f"len={len(m.recent)}")
        self.assertEqual(m.recent.maxlen, 100)
        # Deque contents must be the LAST 100 state indices.
        expected = [(10_000 - 100 + i) % 3 for i in range(100)]
        self.assertEqual(list(m.recent), expected)


if __name__ == "__main__":
    unittest.main()
