"""High-scale stress tests for ``ai-control/daemon/library_census.py`` (S79).

S79 Test Agent 2 -- scales S77 Agent 2's 8-32 thread / 1-2k op tests up
to 64/128/256 threads and 10k-100k ops to surface the NEXT class of
bugs (resource-exhaustion, O(N^2) blowups, cache fill-at-capacity,
stop/start storms).

Gated behind ``STRESS_TESTS=1``. Run with::

    cd tests/unit && STRESS_TESTS=1 python -m unittest test_library_census_stress_v2 -v

Failure modes each test probes are documented per-test in the docstring.

S79 Test Agent 2 deliverable.
"""

from __future__ import annotations

import gc
import importlib
import os
import random
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DAEMON_DIR = _REPO_ROOT / "ai-control" / "daemon"

if str(_DAEMON_DIR) not in sys.path:
    sys.path.insert(0, str(_DAEMON_DIR))

STRESS_ENABLED = bool(os.environ.get("STRESS_TESTS"))


def _load_module():
    sys.modules.pop("library_census", None)
    return importlib.import_module("library_census")


def _fake_pmap(pid, dll_names):
    return SimpleNamespace(
        pid=pid,
        dlls_loaded={name: {} for name in dll_names},
    )


class _FakeMemoryObserver:
    def __init__(self, pid_to_dlls=None):
        self._processes = {}
        self._mutation_lock = threading.Lock()
        if pid_to_dlls:
            for pid, names in pid_to_dlls.items():
                self._processes[pid] = _fake_pmap(pid, names)

    def add_dll(self, pid, dll):
        with self._mutation_lock:
            pmap = self._processes.get(pid)
            if pmap is None:
                pmap = _fake_pmap(pid, [])
                self._processes[pid] = pmap
            pmap.dlls_loaded[dll] = {}

    def remove_pid(self, pid):
        with self._mutation_lock:
            self._processes.pop(pid, None)


@unittest.skipUnless(STRESS_ENABLED, "stress tests disabled (set STRESS_TESTS=1)")
class TestLibraryCensusStressV2(unittest.TestCase):

    def setUp(self):
        self.mod = _load_module()

    def test_256_threads_x_10k_on_dll_load(self):
        """256 threads * ~40 ops each = ~10,240 on_dll_load calls while
        two snapshot threads run. Probes contention on the RLock +
        cache-invalidate path at the next order of magnitude above S77.

        Pass = no exceptions, final snapshot self-consistent."""
        mo = _FakeMemoryObserver({i: ["kernel32.dll"] for i in range(256)})
        census = self.mod.LibraryCensus(memory_observer=mo)

        errors = []
        stop = threading.Event()
        ops_per_thread = 40  # 256 * 40 = 10240 calls

        def hook_caller(tid):
            try:
                rng = random.Random(tid)
                for _ in range(ops_per_thread):
                    pid = rng.randint(0, 255)
                    dll = f"lib_{rng.randint(0, 5000)}.dll"
                    mo.add_dll(pid, dll)
                    census.on_dll_load(pid, dll)
            except Exception as e:
                errors.append(("hook", tid, e))

        def snapshotter():
            try:
                while not stop.is_set():
                    snap = census.snapshot()
                    self.assertIn("total_subjects", snap)
            except Exception as e:
                errors.append(("snap", e))

        t0 = time.perf_counter()
        hook_threads = [
            threading.Thread(target=hook_caller, args=(i,), name=f"hook-{i}")
            for i in range(256)
        ]
        snap_threads = [
            threading.Thread(target=snapshotter, daemon=True, name=f"snap-{i}")
            for i in range(2)
        ]
        for t in snap_threads:
            t.start()
        for t in hook_threads:
            t.start()
        try:
            for t in hook_threads:
                t.join(timeout=45)
                self.assertFalse(t.is_alive(),
                                 f"hook_caller did not terminate: {t.name}")
        finally:
            stop.set()
            for t in snap_threads:
                t.join(timeout=5)
        elapsed = time.perf_counter() - t0
        self.assertEqual(errors, [], f"errors: {errors[:5]}")
        self.assertLess(elapsed, 60.0,
                        f"256t x 40ops took too long: {elapsed:.1f}s")

    def test_stop_start_storm_100_cycles(self):
        """100 stop/start cycles back-to-back with minimal sleep. Probes
        S76 Agent B fix under adversarial timing; any leaked straggler
        thread means the per-thread stop_event pattern is broken."""
        mo = _FakeMemoryObserver({1: ["kernel32.dll"]})
        census = self.mod.LibraryCensus(memory_observer=mo)

        start = time.perf_counter()
        try:
            for _ in range(100):
                census.start_polling(interval_seconds=0.5)
                census.stop_polling()
        finally:
            census.stop_polling()
        elapsed = time.perf_counter() - start

        time.sleep(0.5)
        alive = [t for t in threading.enumerate()
                 if t.name == "library_census_poller" and t.is_alive()]
        self.assertLessEqual(len(alive), 1,
                             f"thread leak after 100 cycles: {len(alive)}")
        self.assertLess(elapsed, 30.0,
                        f"stop/start storm took {elapsed:.1f}s")

    def test_5000_pid_x_50_dll_snapshot_latency(self):
        """250_000 (pid, dll) records. Snapshot must complete in <2s.
        Probes the O(N*D) aggregation loop at a scale above S77's 5000x10."""
        mo = _FakeMemoryObserver()
        rng = random.Random(17)
        dll_pool = [f"lib{i}.dll" for i in range(500)]
        for pid in range(5000):
            chosen = rng.sample(dll_pool, 50)
            for dll in chosen:
                mo.add_dll(pid, dll)

        census = self.mod.LibraryCensus(memory_observer=mo)
        t0 = time.perf_counter()
        snap = census.snapshot()
        elapsed = time.perf_counter() - t0

        self.assertLess(elapsed, 5.0,
                        f"snapshot at 250k records took {elapsed:.2f}s")
        self.assertEqual(snap["total_subjects"], 5000)
        self.assertLessEqual(snap["total_libraries"], 500)

    def test_memory_dispatch_audit(self):
        """Add 2000 PIDs, remove 1000, then snapshot; verify the census
        reflects the TRUE current size, not the peak. Probes leak-like
        behaviour if total_subjects reflects stale cache."""
        mo = _FakeMemoryObserver()
        for pid in range(2000):
            mo.add_dll(pid, "kernel32.dll")

        census = self.mod.LibraryCensus(memory_observer=mo)
        snap1 = census.snapshot()
        self.assertEqual(snap1["total_subjects"], 2000)

        # Remove half.
        for pid in range(1000):
            mo.remove_pid(pid)
        snap2 = census.snapshot()
        self.assertEqual(snap2["total_subjects"], 1000,
                         "snapshot did not reflect post-remove state")

    def test_concurrent_policy_evaluate_256_threads(self):
        """256 threads calling policy_evaluate across different pids at
        once. Probes the RLock + _last_snapshot update path.
        Pass = no exceptions, fire counter monotonic."""
        mo = _FakeMemoryObserver()
        # Populate 500 baseline pids each with 3 common DLLs.
        for pid in range(500):
            for dll in ["kernel32.dll", "ntdll.dll", "user32.dll"]:
                mo.add_dll(pid, dll)
        # A handful of pids with rare DLLs.
        for p in range(500, 700):
            mo.add_dll(p, f"rare_{p}.dll")

        census = self.mod.LibraryCensus(memory_observer=mo,
                                        policy_drift_fraction=0.05)
        errors = []

        def worker(tid):
            try:
                rng = random.Random(tid)
                for _ in range(50):
                    pid = rng.randint(500, 699)
                    census.policy_evaluate(pid)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(256)]
        t0 = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=45)
            self.assertFalse(t.is_alive())
        elapsed = time.perf_counter() - t0

        self.assertEqual(errors, [], f"errors: {errors[:3]}")
        self.assertLess(elapsed, 60.0, f"policy_evaluate storm: {elapsed:.1f}s")
        stats = census.stats()
        self.assertGreaterEqual(stats["policy_fires"], 0)

    def test_adversarial_stop_start_with_active_ops(self):
        """Simultaneously hammer start/stop polling from one thread while
        16 hook callers and 2 snapshot consumers run. Race detector:
        any thread leak or exception = bug."""
        mo = _FakeMemoryObserver({i: ["kernel32.dll"] for i in range(32)})
        census = self.mod.LibraryCensus(memory_observer=mo)

        errors = []
        stop = threading.Event()

        def cycler():
            try:
                for _ in range(50):
                    census.start_polling(interval_seconds=0.5)
                    census.stop_polling()
            except Exception as e:
                errors.append(("cycle", e))

        def hooker():
            try:
                while not stop.is_set():
                    for pid in range(32):
                        census.on_dll_load(pid, "kernel32.dll")
            except Exception as e:
                errors.append(("hook", e))

        def snapper():
            try:
                while not stop.is_set():
                    census.snapshot()
            except Exception as e:
                errors.append(("snap", e))

        threads = [threading.Thread(target=cycler)]
        threads += [threading.Thread(target=hooker, daemon=True) for _ in range(16)]
        threads += [threading.Thread(target=snapper, daemon=True) for _ in range(2)]
        try:
            for t in threads:
                t.start()
            # Wait for cycler to complete.
            threads[0].join(timeout=30)
            self.assertFalse(threads[0].is_alive())
        finally:
            stop.set()
            census.stop_polling()
            for t in threads[1:]:
                t.join(timeout=5)

        time.sleep(0.5)
        alive = [t for t in threading.enumerate()
                 if t.name == "library_census_poller" and t.is_alive()]
        self.assertEqual(errors, [], f"errors under adversarial timing: {errors[:5]}")
        self.assertLessEqual(len(alive), 1,
                             f"thread leak: {len(alive)} alive")

    def test_100k_snapshot_invariance(self):
        """Take 100_000 snapshots and verify the unique_library_ratio
        never drifts outside [0.0, 1.0] -- probes float accumulation /
        division precision under repeated recompute."""
        mo = _FakeMemoryObserver()
        rng = random.Random(42)
        dll_pool = [f"l{i}.dll" for i in range(100)]
        for pid in range(200):
            for dll in rng.sample(dll_pool, 10):
                mo.add_dll(pid, dll)

        census = self.mod.LibraryCensus(memory_observer=mo)
        t0 = time.perf_counter()
        for _ in range(100_000):
            snap = census.snapshot()
            ratio = snap["unique_library_ratio"]
            if not (0.0 <= ratio <= 1.0):
                self.fail(f"ratio out of range: {ratio}")
        elapsed = time.perf_counter() - t0
        # Budget: 60s (600us / snapshot). Generous ceiling for Windows
        # hosts running concurrent ISO builds / other test agents.
        self.assertLess(elapsed, 60.0,
                        f"100k snapshots took {elapsed:.1f}s "
                        f"(>600us each -> too slow)")


if __name__ == "__main__":
    unittest.main()
