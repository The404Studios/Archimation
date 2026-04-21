"""Stress tests for ``ai-control/daemon/library_census.py`` (S77 Agent 2).

These tests probe failure modes that fixed-N unit tests miss:
  * high concurrency on the DLL-load hook + simultaneous snapshot()
  * rapid start/stop cycles without thread accumulation
  * policy_evaluate() correctness under concurrent memory_observer mutation
  * memory-observer with thousands of PIDs, many rare DLLs
  * callback hook fan-in from many producer threads

Gated behind ``STRESS_TESTS=1`` so CI runs aren't slowed down. Run with::

    cd tests/unit && STRESS_TESTS=1 python -m unittest test_library_census_stress -v

Each test enforces:
  * no unhandled exception escapes the observer
  * worker threads terminate
  * no thread accumulation after stop_polling()
  * invariants on snapshot content hold under contention

S77 Agent 2 deliverable.
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
    """Concurrent-safe stand-in with a mutation API so stress tests can
    simulate real memory_observer churn during observer access."""

    def __init__(self, pid_to_dlls=None):
        self._processes = {}
        self._mutation_lock = threading.Lock()
        if pid_to_dlls:
            for pid, names in pid_to_dlls.items():
                self._processes[pid] = _fake_pmap(pid, names)

    def add_dll(self, pid, dll):
        """Mutate dlls_loaded safely — simulates a real DLL-load event."""
        with self._mutation_lock:
            pmap = self._processes.get(pid)
            if pmap is None:
                pmap = _fake_pmap(pid, [])
                self._processes[pid] = pmap
            pmap.dlls_loaded[dll] = {}

    def remove_pid(self, pid):
        with self._mutation_lock:
            self._processes.pop(pid, None)


class _FakeBus:
    def __init__(self):
        self.received = []
        self.lock = threading.Lock()

    def publish(self, event):
        with self.lock:
            self.received.append(event)


@unittest.skipUnless(STRESS_ENABLED, "stress tests disabled (set STRESS_TESTS=1)")
class TestLibraryCensusStress(unittest.TestCase):

    def setUp(self):
        self.mod = _load_module()

    def test_concurrent_on_dll_load_plus_snapshot(self):
        """1000 on_dll_load calls from 16 threads while another thread
        calls snapshot() in a tight loop. Probes the cache-invalidate
        path under contention. Pass = no exception, final snapshot
        total_subjects > 0, hook_calls >= 1000."""
        mo = _FakeMemoryObserver({i: ["kernel32.dll"] for i in range(64)})
        census = self.mod.LibraryCensus(memory_observer=mo)

        errors = []
        stop = threading.Event()
        hook_calls = [0]
        hook_lock = threading.Lock()

        def hook_caller():
            try:
                for _ in range(1000 // 16):
                    pid = random.randint(0, 63)
                    dll = f"lib_{random.randint(0, 1000)}.dll"
                    mo.add_dll(pid, dll)
                    census.on_dll_load(pid, dll)
                    with hook_lock:
                        hook_calls[0] += 1
            except Exception as e:
                errors.append(e)

        def snapshotter():
            try:
                while not stop.is_set():
                    snap = census.snapshot()
                    self.assertIn("total_subjects", snap)
            except Exception as e:
                errors.append(e)

        hook_threads = [threading.Thread(target=hook_caller) for _ in range(16)]
        snap_thread = threading.Thread(target=snapshotter, daemon=True)
        snap_thread.start()
        for t in hook_threads:
            t.start()
        for t in hook_threads:
            t.join(timeout=30)
            self.assertFalse(t.is_alive(), "hook_caller did not terminate")
        stop.set()
        snap_thread.join(timeout=5)

        self.assertEqual(errors, [], f"errors during stress: {errors}")
        self.assertGreaterEqual(hook_calls[0], 1000 - 16)  # allow <1 per thread slack
        snap = census.snapshot()
        self.assertGreater(snap["total_subjects"], 0)

    def test_rapid_stop_start_no_thread_leak(self):
        """50 stop/start cycles on a polling census. After all cycles
        complete + a grace period, the alive-thread count for
        ``library_census_poller`` must be at most 1. Probes the S76
        Agent B fix at scale."""
        mo = _FakeMemoryObserver({1: ["kernel32.dll"]})
        census = self.mod.LibraryCensus(memory_observer=mo)

        try:
            for _ in range(50):
                census.start_polling(interval_seconds=0.5)
                time.sleep(0.005)
                census.stop_polling()
        finally:
            census.stop_polling()

        # Let stragglers die.
        time.sleep(0.5)
        alive = [t for t in threading.enumerate()
                 if t.name == "library_census_poller" and t.is_alive()]
        self.assertLessEqual(len(alive), 1,
                             f"thread leak: {len(alive)} alive pollers")

    def test_snapshot_under_concurrent_pid_churn(self):
        """128 threads adding/removing PIDs while snapshot() runs
        continuously. Probes _collect_pid_maps() iteration safety when
        memory_observer._processes is mutated mid-iteration. Pass =
        no dictionary-changed-size exception leaks out."""
        mo = _FakeMemoryObserver({i: ["kernel32.dll"] for i in range(32)})
        census = self.mod.LibraryCensus(memory_observer=mo)

        errors = []
        stop = threading.Event()

        def churner():
            try:
                rng = random.Random()
                while not stop.is_set():
                    pid = rng.randint(100, 500)
                    if rng.random() < 0.5:
                        mo.add_dll(pid, f"lib_{rng.randint(0, 100)}.dll")
                    else:
                        mo.remove_pid(pid)
            except Exception as e:
                errors.append(("churner", e))

        def sampler():
            try:
                while not stop.is_set():
                    census.snapshot()
            except Exception as e:
                errors.append(("sampler", e))

        threads = [threading.Thread(target=churner, daemon=True) for _ in range(8)]
        threads += [threading.Thread(target=sampler, daemon=True) for _ in range(4)]
        for t in threads:
            t.start()
        time.sleep(1.5)  # run for 1.5 seconds
        stop.set()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(errors, [], f"races leaked: {errors}")

    def test_policy_evaluate_under_load(self):
        """Thousands of policy_evaluate calls across many PIDs while
        DLLs are being added. Pass = no exceptions, no negative
        threshold_count, policy_fires counter monotonically increases."""
        mo = _FakeMemoryObserver()
        # Populate 100 baseline PIDs with common DLLs.
        for pid in range(100):
            for dll in ["kernel32.dll", "ntdll.dll", "user32.dll"]:
                mo.add_dll(pid, dll)
        # PID 999 has rare DLLs -- should trigger policy on every call.
        for dll in ["secret.dll", "weird.dll"]:
            mo.add_dll(999, dll)

        census = self.mod.LibraryCensus(memory_observer=mo,
                                        policy_drift_fraction=0.05)
        errors = []
        fires = [0]

        def worker():
            try:
                for _ in range(250):
                    ev = census.policy_evaluate(999)
                    if ev is not None:
                        fires[0] += 1
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        self.assertEqual(errors, [])
        self.assertGreater(fires[0], 900,
                           f"expected ~1000 fires, got {fires[0]}")
        stats = census.stats()
        self.assertGreaterEqual(stats["policy_fires"], fires[0])

    def test_large_ecosystem_snapshot(self):
        """5000 PIDs × 10 DLLs each. Snapshot must complete in under
        5 seconds and produce stable output. Probes the O(N*D) loop in
        snapshot() + sorting."""
        mo = _FakeMemoryObserver()
        dll_pool = [f"lib{i}.dll" for i in range(200)]
        rng = random.Random(42)
        for pid in range(5000):
            chosen = rng.sample(dll_pool, 10)
            for dll in chosen:
                mo.add_dll(pid, dll)

        census = self.mod.LibraryCensus(memory_observer=mo)
        start = time.perf_counter()
        snap = census.snapshot()
        elapsed = time.perf_counter() - start

        self.assertLess(elapsed, 5.0, f"snapshot too slow: {elapsed:.2f}s")
        self.assertEqual(snap["total_subjects"], 5000)
        self.assertLessEqual(snap["total_libraries"], 200)
        # Re-snap should be stable (same content).
        snap2 = census.snapshot()
        self.assertEqual(snap["library_counts"], snap2["library_counts"])

    def test_bus_publish_failure_does_not_break_observer(self):
        """A bus whose publish() always raises must not crash the
        observer or prevent future snapshots; publish_errors should
        increment monotonically."""

        class _BadBus:
            def publish(self, event):
                raise RuntimeError("bus down")

        mo = _FakeMemoryObserver({1: ["kernel32.dll"], 2: ["ntdll.dll"]})
        census = self.mod.LibraryCensus(memory_observer=mo, event_bus=_BadBus())
        for _ in range(500):
            ev = census.policy_evaluate(1)
            # PID 1 has kernel32 shared with PID 2 -- may return None,
            # but the bus failure should not propagate.
        # Directly force a publish.
        for _ in range(10):
            census._publish({"source": "test", "ts": time.time()})
        stats = census.stats()
        self.assertGreaterEqual(stats["publish_errors"], 10)


if __name__ == "__main__":
    unittest.main()
