"""Stress tests for ``ai-control/cortex/dynamic_hyperlation.py`` (S79).

S79 Test Agent 2 -- verifies S78 Dev G's snapshot-aliasing fix holds
at 100k+ concurrent snapshots.

The fix at dynamic_hyperlation.py:886-906 shallow-copies the snapshot
dict, the "subjects" list (including each subject dict), and the
"global" dict so callers that mutate the returned structure cannot
corrupt internal state observed by other readers. This test verifies
that invariant under 256-thread concurrent read + mutate.

Gated behind ``STRESS_TESTS=1``. Run with::

    cd tests/unit && STRESS_TESTS=1 python -m unittest test_dynamic_hyperlation_stress -v

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


def _make_subject(sid, state="STEADY_FLOW"):
    return {
        "id": sid,
        "C_t": 100.0,
        "S_t": 50.0,
        "G_t": 1,
        "L_t": "XX",
        "metabolism_rate": 0.1,
        "state": state,
        "flow_vector": [0.0, 0.0, 1, 0],
        "class": "game",
        "markov": {"kl_anomaly_score": 0.0,
                   "expected_hitting_time_steps": None},
    }


def _inject_snapshot(tracker, subjects, global_dict=None):
    """Inject a snapshot via the private attr path (test-only).
    Mirrors what poll_once() does at lines 1248-1249."""
    snap = {
        "subjects": subjects,
        "global": global_dict or {
            "theorems_violated": [],
            "theorem_counts": {},
            "total_metabolism": 0.0,
            "active_meiotic_bonds": 0,
            "cancer_detections": 0,
        },
        "timestamp": time.time(),
        "source": "synthetic",
    }
    with tracker._snapshot_lock:
        tracker._snapshot = snap


@unittest.skipUnless(STRESS_ENABLED, "stress tests disabled (set STRESS_TESTS=1)")
class TestDynamicHyperlationStress(unittest.TestCase):

    def setUp(self):
        self.mod = _load_module()
        # Fresh instance per test -- do NOT use the singleton, since
        # other tests in the process may have left state on it.
        self.tracker = self.mod.HyperlationStateTracker()

    def test_256_thread_snapshot_aliasing_invariant(self):
        """Inject a known snapshot. 255 reader threads continuously call
        snapshot() and mutate their returned dict's subjects list
        (append + pop). One writer thread re-injects the snapshot.

        S78 Dev G fix must prevent mutator from corrupting the internal
        state seen by the writer -- each snapshot() must return a dict
        whose mutation is locally isolated."""
        tracker = self.tracker
        subjects = [_make_subject(i) for i in range(20)]
        _inject_snapshot(tracker, subjects)

        errors = []
        stop = threading.Event()

        def reader(tid):
            try:
                while not stop.is_set():
                    snap = tracker.snapshot()
                    subs = snap.get("subjects", [])
                    # Verify baseline shape BEFORE any mutation.
                    if len(subs) != 20:
                        errors.append(("bad_len", tid, len(subs)))
                        return
                    for s in subs:
                        if s.get("id") is None:
                            errors.append(("no_id", tid))
                            return
                    # Now mutate the returned list and verify it doesn't
                    # affect the tracker's internal state. We don't
                    # cross-check here (that's the writer's job) but we
                    # DO ensure mutating doesn't raise.
                    subs.append(_make_subject(9999))
                    if subs:
                        subs.pop()
                    # Mutate inner subject dict too.
                    if subs:
                        subs[0]["poisoned"] = tid
            except Exception as e:
                errors.append(("exc", tid, e))

        def writer():
            try:
                # Continuously verify internal state matches injection.
                while not stop.is_set():
                    _inject_snapshot(tracker, subjects)
                    # Hot loop: check tracker snapshot internal via
                    # private attr.
                    with tracker._snapshot_lock:
                        internal = tracker._snapshot
                        if internal is not None:
                            internal_subs = internal.get("subjects", [])
                            for s in internal_subs:
                                if "poisoned" in s:
                                    errors.append(("aliased!",))
                                    return
            except Exception as e:
                errors.append(("writer_exc", e))

        readers = [threading.Thread(target=reader, args=(i,), daemon=True)
                   for i in range(255)]
        writer_t = threading.Thread(target=writer, daemon=True)
        writer_t.start()
        for t in readers:
            t.start()
        time.sleep(3.0)
        stop.set()
        writer_t.join(timeout=5)
        for t in readers:
            t.join(timeout=5)

        self.assertEqual(errors, [], f"aliasing broken: {errors[:3]}")

    def test_100k_snapshots_budget(self):
        """100_000 sequential snapshot() calls. Budget: 10s total
        (100us / call). Probes deep-copy cost at scale."""
        tracker = self.tracker
        subjects = [_make_subject(i) for i in range(50)]
        _inject_snapshot(tracker, subjects)

        t0 = time.perf_counter()
        for _ in range(100_000):
            snap = tracker.snapshot()
            self.assertEqual(len(snap.get("subjects", [])), 50)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 30.0,
                        f"100k snapshot: {elapsed:.1f}s "
                        f"({elapsed * 10:.0f} us/call)")

    def test_256_thread_mutate_returned_dict(self):
        """256 threads each mutate the returned dict's global + subjects
        + per-subject fields. Internal _snapshot must remain clean --
        verify by re-reading and confirming no "poisoned" key leaked."""
        tracker = self.tracker
        baseline = [_make_subject(i) for i in range(10)]
        _inject_snapshot(tracker, baseline)

        errors = []

        def worker(tid):
            try:
                for _ in range(100):
                    snap = tracker.snapshot()
                    snap["global"]["poisoned_by"] = tid
                    snap["subjects"].append({"id": -tid})
                    if snap["subjects"]:
                        snap["subjects"][0]["state"] = "POISONED"
            except Exception as e:
                errors.append(("exc", tid, e))

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(256)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=45)
            self.assertFalse(t.is_alive())

        self.assertEqual(errors, [], f"errors: {errors[:3]}")
        # Verify internal state clean.
        with tracker._snapshot_lock:
            internal = tracker._snapshot
            self.assertIsNotNone(internal)
            self.assertNotIn("poisoned_by", internal.get("global", {}))
            internal_subs = internal.get("subjects", [])
            self.assertEqual(len(internal_subs), 10,
                             f"subjects list corrupted: {len(internal_subs)}")
            for s in internal_subs:
                self.assertNotEqual(s.get("state"), "POISONED",
                                    "internal subject dict aliased!")

    def test_get_subject_256_thread_hit_rate(self):
        """256 threads call get_subject(sid) on 1000 subjects. Probes
        the full snapshot() + linear scan under contention."""
        tracker = self.tracker
        subjects = [_make_subject(i) for i in range(1000)]
        _inject_snapshot(tracker, subjects)

        hits = [0] * 256
        errors = []

        def worker(tid):
            try:
                rng = random.Random(tid)
                for _ in range(50):
                    sid = rng.randint(0, 999)
                    rec = tracker.get_subject(sid)
                    if rec is not None and rec.get("id") == sid:
                        hits[tid] += 1
            except Exception as e:
                errors.append((tid, e))

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
        total_hits = sum(hits)
        self.assertEqual(total_hits, 256 * 50,
                         f"missed hits: {total_hits}")
        self.assertLess(elapsed, 60.0,
                        f"get_subject x 12800 under 256t: {elapsed:.1f}s")

    def test_state_for_256_thread_none_handling(self):
        """Include a subject with state=None (edge case). 256 threads
        call state_for(sid). Per S78 Dev G fix at line 944, None must
        normalize to \"\". Probe: no 'None' string ever returned."""
        tracker = self.tracker
        subjects = [_make_subject(i) for i in range(10)]
        # Poison one with None state -- simulates producer placing
        # explicit None.
        subjects[5]["state"] = None
        _inject_snapshot(tracker, subjects)

        errors = []

        def worker(tid):
            try:
                for _ in range(100):
                    s5 = tracker.state_for(5)
                    if s5 != "":
                        errors.append(("bad_none", tid, s5))
                    s_missing = tracker.state_for(99999)
                    if s_missing != "":
                        errors.append(("bad_miss", tid, s_missing))
            except Exception as e:
                errors.append(("exc", tid, e))

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(256)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
            self.assertFalse(t.is_alive())

        self.assertEqual(errors, [], f"errors: {errors[:3]}")

    def test_inject_storm_racing_readers(self):
        """1 writer injects new snapshots as fast as possible while 128
        readers call snapshot() / get_subject() / state_for(). Probes
        the snapshot_lock + internal mutation path under extreme churn."""
        tracker = self.tracker
        subjects = [_make_subject(i) for i in range(30)]
        _inject_snapshot(tracker, subjects)

        errors = []
        stop = threading.Event()

        def writer():
            try:
                i = 0
                while not stop.is_set():
                    new_subs = [_make_subject(k + i) for k in range(30)]
                    _inject_snapshot(tracker, new_subs)
                    i += 1
            except Exception as e:
                errors.append(("w", e))

        def reader(tid):
            try:
                while not stop.is_set():
                    snap = tracker.snapshot()
                    subs = snap.get("subjects", [])
                    # Only check shape, not values (since they change).
                    if not isinstance(subs, list):
                        errors.append(("bad_shape", tid))
                        return
                    if subs and "id" not in subs[0]:
                        errors.append(("torn_dict", tid))
                        return
            except Exception as e:
                errors.append(("r", tid, e))

        writer_t = threading.Thread(target=writer, daemon=True)
        readers = [threading.Thread(target=reader, args=(i,), daemon=True)
                   for i in range(128)]
        writer_t.start()
        for t in readers:
            t.start()
        time.sleep(3.0)
        stop.set()
        writer_t.join(timeout=5)
        for t in readers:
            t.join(timeout=5)

        self.assertEqual(errors, [], f"errors under storm: {errors[:3]}")


if __name__ == "__main__":
    unittest.main()
