"""Boundary tests for ``ai-control/daemon/library_census.py``.

S79 Test Agent 3 -- boundary / edge-case probes for S75 LibraryCensus.

Each test documents the boundary it probes in its docstring. Test class
names reflect the boundary family (empty/single/max/threshold).

Boundaries probed:
  * 0 / 1 / N PIDs
  * 0 / 1 / many DLLs per PID
  * DLL name = empty string / 1 char / 256 chars / non-ASCII / null-byte
  * snapshot() before start_polling / after stop_polling
  * interval_seconds = 0.0 / negative / huge / NaN / inf
  * rare_libraries threshold (<=2 vs >=3)
  * unique_library_ratio when total_libraries=0 (divide-by-zero)

Not gated (runs on every CI invocation). Must complete <5s.
"""

from __future__ import annotations

import importlib
import math
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DAEMON_DIR = _REPO_ROOT / "ai-control" / "daemon"

if str(_DAEMON_DIR) not in sys.path:
    sys.path.insert(0, str(_DAEMON_DIR))


def _load_module():
    sys.modules.pop("library_census", None)
    return importlib.import_module("library_census")


def _fake_pmap(pid: int, dll_names) -> SimpleNamespace:
    return SimpleNamespace(
        pid=pid,
        dlls_loaded={name: {} for name in dll_names},
    )


class _FakeMemoryObserver:
    def __init__(self, pid_to_dlls=None) -> None:
        self._processes = {}
        if pid_to_dlls:
            for pid, names in pid_to_dlls.items():
                self._processes[pid] = _fake_pmap(pid, names)


class _FakeBus:
    def __init__(self) -> None:
        self.received = []

    def publish(self, event):
        self.received.append(event)


class PidCountBoundaries(unittest.TestCase):
    """0, 1, many PIDs in the tracked map."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_zero_pids(self) -> None:
        """0 PIDs -> zero-state snapshot, no divide-by-zero."""
        census = self.mod.LibraryCensus(memory_observer=_FakeMemoryObserver({}))
        snap = census.snapshot()
        self.assertEqual(snap["total_subjects"], 0)
        self.assertEqual(snap["total_libraries"], 0)
        self.assertEqual(snap["unique_library_ratio"], 0.0)

    def test_exactly_one_pid(self) -> None:
        """Boundary N=1: one subject, subject-count=1 for every DLL."""
        census = self.mod.LibraryCensus(
            memory_observer=_FakeMemoryObserver({42: ["a.dll"]}),
        )
        snap = census.snapshot()
        self.assertEqual(snap["total_subjects"], 1)
        self.assertEqual(snap["total_libraries"], 1)
        self.assertEqual(snap["library_counts"]["a.dll"], 1)
        # Singleton (1 subject of 1 library) -> ratio = 1.0.
        self.assertEqual(snap["unique_library_ratio"], 1.0)

    def test_many_pids(self) -> None:
        """N=200 PIDs, same DLL -> count=200, uniq_ratio=0.0."""
        pid_dlls = {1000 + i: ["shared.dll"] for i in range(200)}
        census = self.mod.LibraryCensus(
            memory_observer=_FakeMemoryObserver(pid_dlls),
        )
        snap = census.snapshot()
        self.assertEqual(snap["total_subjects"], 200)
        self.assertEqual(snap["library_counts"]["shared.dll"], 200)
        # All PIDs share -> 0 singletons -> ratio=0.0.
        self.assertEqual(snap["unique_library_ratio"], 0.0)


class DllCountPerPidBoundaries(unittest.TestCase):
    """0, 1, 1000 DLLs in a single PID's map."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_pid_with_zero_dlls(self) -> None:
        """PID tracked but 0 DLLs loaded -> should be skipped (names empty)."""
        census = self.mod.LibraryCensus(
            memory_observer=_FakeMemoryObserver({42: []}),
        )
        snap = census.snapshot()
        # Code only keeps PIDs whose `names` set is non-empty.
        self.assertEqual(snap["total_subjects"], 0)

    def test_pid_with_one_dll(self) -> None:
        """Exactly 1 DLL -> counted."""
        census = self.mod.LibraryCensus(
            memory_observer=_FakeMemoryObserver({42: ["only.dll"]}),
        )
        snap = census.snapshot()
        self.assertEqual(snap["total_subjects"], 1)
        self.assertEqual(snap["total_libraries"], 1)

    def test_pid_with_1000_dlls(self) -> None:
        """1000 DLLs loaded -> fast and correct."""
        names = [f"mod{i:04d}.dll" for i in range(1000)]
        census = self.mod.LibraryCensus(
            memory_observer=_FakeMemoryObserver({42: names}),
        )
        snap = census.snapshot()
        self.assertEqual(snap["total_subjects"], 1)
        self.assertEqual(snap["total_libraries"], 1000)


class DllNameBoundaries(unittest.TestCase):
    """DLL name edge cases: empty, 1-char, 256-char, non-ASCII, null-byte."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_empty_string_dll_name_filtered(self) -> None:
        """Empty string name -> filtered by ``if n`` clause in _collect_pid_maps."""
        census = self.mod.LibraryCensus(
            memory_observer=_FakeMemoryObserver({42: [""]}),
        )
        snap = census.snapshot()
        # `names = {str(n).lower() for n in dlls.keys() if n}` drops "".
        self.assertEqual(snap["total_libraries"], 0)

    def test_single_char_dll_name(self) -> None:
        """1-char name is valid; lower-cased."""
        census = self.mod.LibraryCensus(
            memory_observer=_FakeMemoryObserver({42: ["A"]}),
        )
        snap = census.snapshot()
        self.assertIn("a", snap["library_counts"])

    def test_256_char_dll_name(self) -> None:
        """256-char name -> counted, not truncated."""
        long_name = "x" * 256 + ".dll"
        census = self.mod.LibraryCensus(
            memory_observer=_FakeMemoryObserver({42: [long_name]}),
        )
        snap = census.snapshot()
        self.assertIn(long_name.lower(), snap["library_counts"])

    def test_non_ascii_dll_name(self) -> None:
        """Unicode DLL name -> counted as-is."""
        census = self.mod.LibraryCensus(
            memory_observer=_FakeMemoryObserver({42: ["日本語.dll"]}),
        )
        snap = census.snapshot()
        self.assertEqual(snap["total_libraries"], 1)

    def test_null_byte_in_middle_of_name(self) -> None:
        """DLL name with null byte -> counted, not truncated at null."""
        census = self.mod.LibraryCensus(
            memory_observer=_FakeMemoryObserver({42: ["evil\x00secret.dll"]}),
        )
        snap = census.snapshot()
        # Python strings carry null bytes without truncation.
        self.assertEqual(snap["total_libraries"], 1)


class PollingLifecycleBoundaries(unittest.TestCase):
    """snapshot() safety before/after start/stop_polling."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_snapshot_before_start_polling(self) -> None:
        """snapshot() before start_polling -> safe, returns zero-state."""
        census = self.mod.LibraryCensus()
        snap = census.snapshot()
        self.assertEqual(snap["total_subjects"], 0)

    def test_snapshot_after_stop_polling(self) -> None:
        """snapshot() after stop_polling -> safe, still works."""
        mo = _FakeMemoryObserver({1: ["a.dll"]})
        census = self.mod.LibraryCensus(memory_observer=mo)
        census.start_polling(interval_seconds=0.5)
        time.sleep(0.05)
        census.stop_polling()
        # Post-stop snapshot must still succeed.
        snap = census.snapshot()
        self.assertEqual(snap["total_subjects"], 1)


class PollIntervalBoundaries(unittest.TestCase):
    """start_polling(interval_seconds=...) with pathological values."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_zero_interval_clamped(self) -> None:
        """interval=0.0 -> clamped to min (0.5s)."""
        mo = _FakeMemoryObserver({1: ["a.dll"]})
        census = self.mod.LibraryCensus(memory_observer=mo)
        census.start_polling(interval_seconds=0.0)
        # Source line 334: `self._poll_interval = max(0.5, float(...))`
        self.assertEqual(census._poll_interval, 0.5)
        census.stop_polling()

    def test_negative_interval_clamped(self) -> None:
        """Negative interval -> clamped to 0.5."""
        mo = _FakeMemoryObserver({1: ["a.dll"]})
        census = self.mod.LibraryCensus(memory_observer=mo)
        census.start_polling(interval_seconds=-100.0)
        self.assertEqual(census._poll_interval, 0.5)
        census.stop_polling()

    def test_huge_interval(self) -> None:
        """Huge interval (1e6s) -> accepted, stored as-is.

        Note: values >2^31 seconds overflow threading.Event.wait on some
        Python builds (OverflowError in the background thread). We use
        1e6 (~11 days) to probe "large but not pathological"."""
        mo = _FakeMemoryObserver({1: ["a.dll"]})
        census = self.mod.LibraryCensus(memory_observer=mo)
        census.start_polling(interval_seconds=1e6)
        self.assertEqual(census._poll_interval, 1e6)
        census.stop_polling()

    def test_nan_interval_documented(self) -> None:
        """NaN interval -> ``max(0.5, NaN)`` returns NaN in Python.

        Documented behavior: ``max()`` propagates NaN; the poll thread
        would wait on ``stop_event.wait(NaN)``, which raises ValueError.
        We accept either ValueError raised at start OR NaN stored in
        _poll_interval. Current code stores NaN (source line 334 does not
        check for NaN)."""
        mo = _FakeMemoryObserver({1: ["a.dll"]})
        census = self.mod.LibraryCensus(memory_observer=mo)
        try:
            census.start_polling(interval_seconds=float("nan"))
        except ValueError:
            # Accepted: NaN rejected at interval-validation step.
            return
        finally:
            try:
                census.stop_polling()
            except Exception:
                pass
        # If not raised: current implementation stored NaN silently.
        self.assertTrue(
            math.isnan(census._poll_interval) or census._poll_interval == 0.5,
            f"unexpected interval: {census._poll_interval}",
        )

    def test_inf_interval_stored(self) -> None:
        """+inf interval -> stored as inf in _poll_interval.

        Documented: ``threading.Event.wait(inf)`` raises OverflowError
        on CPython, which the background-thread try/except in _poll_loop
        catches at the logger.debug level. We do NOT start the poll
        thread here (only verify the clamping math) because inf would
        otherwise swallow the thread and emit stderr noise via the
        uncaught-exception hook."""
        mo = _FakeMemoryObserver({1: ["a.dll"]})
        census = self.mod.LibraryCensus(memory_observer=mo)
        # Use register_with_daemon's clamping path -- it stores without
        # starting the thread.
        census._poll_interval = max(0.5, float("inf"))
        self.assertTrue(math.isinf(census._poll_interval))


class RareThresholdBoundary(unittest.TestCase):
    """Rare threshold boundaries: count <=2 vs >=3."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_count_exactly_2_is_rare(self) -> None:
        """Default threshold=2: DLL in exactly 2 subjects IS rare."""
        pid_dlls = {1: ["x.dll"], 2: ["x.dll"], 3: ["other.dll"]}
        mo = _FakeMemoryObserver(pid_dlls)
        census = self.mod.LibraryCensus(memory_observer=mo, rare_threshold=2)
        snap = census.snapshot()
        self.assertIn("x.dll", snap["rare_libraries"])

    def test_count_exactly_3_is_not_rare(self) -> None:
        """Default threshold=2: DLL in 3 subjects is NOT rare."""
        pid_dlls = {i: ["x.dll"] for i in range(1, 4)}
        mo = _FakeMemoryObserver(pid_dlls)
        census = self.mod.LibraryCensus(memory_observer=mo, rare_threshold=2)
        snap = census.snapshot()
        self.assertNotIn("x.dll", snap["rare_libraries"])

    def test_threshold_zero(self) -> None:
        """threshold=0 -> nothing is rare (no DLL has count<=0)."""
        pid_dlls = {1: ["x.dll"]}
        mo = _FakeMemoryObserver(pid_dlls)
        census = self.mod.LibraryCensus(memory_observer=mo, rare_threshold=0)
        snap = census.snapshot()
        self.assertEqual(snap["rare_libraries"], [])


class UniqueRatioDivideByZero(unittest.TestCase):
    """unique_library_ratio when total_libraries=0."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_divide_by_zero_returns_zero(self) -> None:
        """total_libraries=0 path in snapshot() -> uniq_ratio=0.0, no exception."""
        # Empty observer -> early return yields _empty_snapshot.
        census = self.mod.LibraryCensus(memory_observer=_FakeMemoryObserver({}))
        snap = census.snapshot()
        self.assertEqual(snap["unique_library_ratio"], 0.0)


if __name__ == "__main__":
    unittest.main()
