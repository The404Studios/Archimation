"""Fuzz tests for library_census, depth_observer, differential_observer.

Targets:
  * LibraryCensus.snapshot()              -- fed via a fake memory_observer
  * DepthSampler.measure(data)            -- random byte buffers
  * DifferentialFilter.tick()             -- via a stub upstream observer

Invariants hammered:

  LibraryCensus:
    1. snapshot() never raises, even with empty / weird PIDs / unicode DLLs.
    2. total_subjects <= number of PIDs we supplied.
    3. library_counts entries are all int >= 1.
    4. unique_library_ratio is in [0, 1].
    5. rare_libraries are all present in library_counts.
    6. snapshot is JSON-serializable.

  DepthSampler:
    1. measure(any-bytes) returns a DepthResult (never raises).
    2. fast_ratio, slow_ratio >= 0, depth_proxy = fast - slow.
    3. classification is one of SHALLOW / DEEP / RANDOM / MIXED.
    4. result.size == len(input) or 0 for too-small inputs.

  DifferentialFilter:
    1. _delta_dict(old, new) never raises on mixed-type random dicts.
    2. _has_meaningful_change returns a bool (never raises).
    3. Nested dicts don't cause infinite recursion.

S79 Test Agent 1 deliverable.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import random
import string
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FUZZ_DIR = Path(__file__).resolve().parent
_DAEMON_DIR = _REPO_ROOT / "ai-control" / "daemon"

if str(_FUZZ_DIR) not in sys.path:
    sys.path.insert(0, str(_FUZZ_DIR))
if str(_DAEMON_DIR) not in sys.path:
    sys.path.insert(0, str(_DAEMON_DIR))

from _fuzz_helpers import (  # noqa: E402
    make_seed_logger,
    maybe_systemrandom,
    random_bytes,
    random_byte_pattern,
    random_nested_dict,
    random_scalar,
)

FUZZ_ENABLED = bool(os.environ.get("FUZZ_TESTS"))
FUZZ_ITERATIONS = int(os.environ.get("FUZZ_ITERATIONS", "1000"))
FUZZ_ROOT_SEED = 42


def _load_library_census():
    sys.modules.pop("library_census", None)
    return importlib.import_module("library_census")


def _load_depth_observer():
    sys.modules.pop("depth_observer", None)
    return importlib.import_module("depth_observer")


def _load_differential_observer():
    sys.modules.pop("differential_observer", None)
    return importlib.import_module("differential_observer")


# --------------------------------------------------------------------------
# Fake memory_observer (matches the interface library_census reads)
# --------------------------------------------------------------------------

class _FakePMap:
    """Mirrors the duck-type that LibraryCensus._collect_pid_maps reads."""
    def __init__(self, dlls_loaded: dict) -> None:
        self.dlls_loaded = dlls_loaded


class _FakeMemoryObserver:
    def __init__(self, pid_to_dll_names: dict) -> None:
        self._processes = {
            pid: _FakePMap({name: object() for name in names})
            for pid, names in pid_to_dll_names.items()
        }


def _random_pid_maps(rng: random.Random) -> dict:
    """Return {pid: [dll_name, ...]} with a wide variety of shapes."""
    n_pids = rng.randint(0, 20)
    out = {}
    for _ in range(n_pids):
        pid = rng.randint(1, 100000)
        n_dlls = rng.randint(0, 30)
        dlls = []
        for _ in range(n_dlls):
            # Mix of normal, unicode, empty, long, null-byte-embedded names
            mode = rng.randint(0, 4)
            if mode == 0:
                name = rng.choice([
                    "kernel32.dll", "ntdll.dll", "user32.dll",
                    "gdi32.dll", "vulkan-1.dll", "aclayers.dll",
                    "d3d11.dll", "xinput1_3.dll", "msvcrt.dll",
                ])
            elif mode == 1:
                name = "".join(
                    rng.choices(string.ascii_letters, k=rng.randint(1, 20))
                ) + ".dll"
            elif mode == 2:
                name = "weird\x00name.dll"
            elif mode == 3:
                # Unicode DLL name
                name = rng.choice(["😀.dll", "фыв.dll", "中文.dll",
                                   "", " ", "a" * 256])
            else:
                name = ""  # empty name -- library_census filters these
            dlls.append(name)
        out[pid] = dlls
    return out


@unittest.skipUnless(FUZZ_ENABLED, "fuzz tests disabled by default")
class LibraryCensusFuzzTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_library_census()

    def test_snapshot_random_pid_maps(self) -> None:
        """1000 random pid->dll mappings: snapshot never raises, shape holds."""
        rng = random.Random(FUZZ_ROOT_SEED)
        log = make_seed_logger("lc_snapshot")
        for i in range(FUZZ_ITERATIONS):
            seed = FUZZ_ROOT_SEED + i
            local_rng = random.Random(seed)
            pid_maps = _random_pid_maps(local_rng)
            mo = _FakeMemoryObserver(pid_maps)
            census = self.mod.LibraryCensus(memory_observer=mo)
            try:
                snap = census.snapshot()
            except Exception as e:
                log(seed, list(pid_maps.keys()))
                self.fail(f"snapshot() raised: {e!r}")
            self.assertIsInstance(snap, dict)
            # Documented keys present
            for k in ("source", "ts", "library_counts", "total_subjects",
                      "total_libraries", "rare_libraries",
                      "unique_library_ratio"):
                self.assertIn(k, snap)
            # total_subjects <= number of pids we fed (empty DLL-lists omitted)
            self.assertLessEqual(snap["total_subjects"], len(pid_maps))
            # library_counts values are positive ints
            for name, count in snap["library_counts"].items():
                self.assertIsInstance(name, str)
                self.assertIsInstance(count, int)
                self.assertGreaterEqual(count, 1)
            # unique_library_ratio in [0, 1]
            self.assertGreaterEqual(snap["unique_library_ratio"], 0.0)
            self.assertLessEqual(snap["unique_library_ratio"], 1.0)
            # rare_libraries are all in library_counts
            for rare in snap["rare_libraries"]:
                self.assertIn(rare, snap["library_counts"])
            # JSON-serializable
            try:
                json.dumps(snap)
            except (TypeError, ValueError) as e:
                log(seed, "non-json")
                self.fail(f"snapshot not JSON-safe: {e!r}")

    def test_snapshot_empty_observer(self) -> None:
        """No memory_observer -> zero-state snapshot."""
        census = self.mod.LibraryCensus(memory_observer=None)
        snap = census.snapshot()
        self.assertEqual(snap["total_subjects"], 0)
        self.assertEqual(snap["total_libraries"], 0)
        self.assertEqual(snap["library_counts"], {})

    def test_snapshot_100_dll_stress(self) -> None:
        """A single PID with 100+ DLL names."""
        rng = random.Random(FUZZ_ROOT_SEED + 1)
        for _ in range(50):
            names = ["dll{}".format(i) for i in range(200)]
            # Shuffle, duplicate a few, mix in unicode
            extras = ["😀.dll", "weird\x00.dll", ""]
            names.extend(extras)
            rng.shuffle(names)
            mo = _FakeMemoryObserver({1234: names})
            census = self.mod.LibraryCensus(memory_observer=mo)
            snap = census.snapshot()
            self.assertLessEqual(snap["total_subjects"], 1)

    def test_snapshot_bad_dlls_loaded_attr(self) -> None:
        """memory_observer with a bogus _processes should not crash."""
        class _WeirdPMap:
            dlls_loaded = "not a dict"
        class _WeirdMO:
            _processes = {1: _WeirdPMap()}
        census = self.mod.LibraryCensus(memory_observer=_WeirdMO())
        try:
            snap = census.snapshot()
        except Exception as e:
            self.fail(f"snapshot() raised on weird observer: {e!r}")
        self.assertIsInstance(snap, dict)


@unittest.skipUnless(FUZZ_ENABLED, "fuzz tests disabled by default")
class DepthSamplerFuzzTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_depth_observer()

    def test_measure_random_bytes_0_to_64k(self) -> None:
        """1000 random buffers 0..64k bytes: measure never raises."""
        rng = random.Random(FUZZ_ROOT_SEED + 1000)
        sampler = self.mod.DepthSampler()
        log = make_seed_logger("depth_measure")
        for i in range(FUZZ_ITERATIONS):
            size = rng.randint(0, 65536)
            buf = random_bytes(rng, size)
            try:
                r = sampler.measure(buf, name=f"fuzz_{i}")
            except Exception as e:
                log(FUZZ_ROOT_SEED + i, (size, buf[:32]))
                self.fail(f"measure(size={size}) raised: {e!r}")
            # size invariants
            self.assertEqual(r.size, len(buf))
            # non-neg ratios
            self.assertGreaterEqual(r.fast_ratio, 0.0)
            self.assertGreaterEqual(r.slow_ratio, 0.0)
            # depth_proxy = fast - slow (within rounding)
            self.assertAlmostEqual(
                r.depth_proxy, r.fast_ratio - r.slow_ratio, places=4)
            # classification is one of the four constants
            self.assertIn(r.classification, {
                self.mod.CLASS_SHALLOW, self.mod.CLASS_DEEP,
                self.mod.CLASS_RANDOM, self.mod.CLASS_MIXED,
            })

    def test_measure_pattern_bytes(self) -> None:
        """Pathological patterns classify reasonably."""
        rng = random.Random(FUZZ_ROOT_SEED + 1001)
        sampler = self.mod.DepthSampler()
        for _ in range(200):
            size = rng.choice([32, 64, 256, 1024, 8192])
            buf = random_byte_pattern(rng, size)
            r = sampler.measure(buf)
            self.assertIsInstance(r.classification, str)

    def test_measure_all_zero_is_shallow(self) -> None:
        """All-zero buffer of LARGE size compresses trivially -> shallow.

        NOTE: small all-zero buffers (~64 bytes) classify as "mixed" since
        the gzip header overhead (~20 bytes) bumps ratio above
        SHALLOW_RATIO_MAX=0.10. The shallow invariant is only valid once
        the buffer is large enough for the header to be negligible (1KB+).
        """
        sampler = self.mod.DepthSampler()
        for size in (1024, 16384, 65536):
            buf = b"\x00" * size
            r = sampler.measure(buf)
            self.assertEqual(r.classification, self.mod.CLASS_SHALLOW,
                             f"size={size}: fast={r.fast_ratio} "
                             f"slow={r.slow_ratio}")

    def test_measure_random_bytes_is_random(self) -> None:
        """urandom output should classify as RANDOM (or at least not
        SHALLOW -- truly random data cannot be compressed)."""
        rng = random.Random(FUZZ_ROOT_SEED + 1002)
        sampler = self.mod.DepthSampler()
        for _ in range(20):
            buf = random_bytes(rng, 8192)
            r = sampler.measure(buf)
            # Random bytes should NEVER be "shallow" at 8KB.
            self.assertNotEqual(r.classification, self.mod.CLASS_SHALLOW)

    def test_measure_empty_and_tiny(self) -> None:
        """Empty and <MIN_USEFUL_BYTES inputs give zero-state result."""
        sampler = self.mod.DepthSampler()
        r_empty = sampler.measure(b"")
        self.assertEqual(r_empty.size, 0)
        r_tiny = sampler.measure(b"\x00" * 16)
        self.assertEqual(r_tiny.size, 16)
        # Small inputs below MIN_USEFUL_BYTES skip compression path.


@unittest.skipUnless(FUZZ_ENABLED, "fuzz tests disabled by default")
class DifferentialFilterFuzzTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_differential_observer()

    # A StubObserver whose snapshot() returns the currently staged dict.
    class _StagedObserver:
        def __init__(self) -> None:
            self._next = {}
        def set_next(self, d: dict) -> None:
            self._next = d
        def snapshot(self) -> dict:
            return dict(self._next)

    def test_tick_random_nested_dicts(self) -> None:
        """1000 ticks with random nested dicts: no raise, delta is dict."""
        rng = random.Random(FUZZ_ROOT_SEED + 2000)
        obs = self._StagedObserver()
        flt = self.mod.DifferentialFilter(observer=obs, name="fuzz_stub")
        log = make_seed_logger("diff_tick")
        for i in range(FUZZ_ITERATIONS):
            snap = random_nested_dict(rng, depth=3, max_keys=6)
            obs.set_next(snap)
            try:
                delta = flt.tick()
            except Exception as e:
                log(FUZZ_ROOT_SEED + i, snap)
                self.fail(f"tick() raised: {e!r}")
            self.assertIsInstance(delta, dict)

    def test_delta_dict_mixed_types(self) -> None:
        """_delta_dict over random mixed-type snapshots never raises."""
        rng = random.Random(FUZZ_ROOT_SEED + 2001)
        log = make_seed_logger("delta_dict")
        for i in range(FUZZ_ITERATIONS):
            old = random_nested_dict(rng, depth=3, max_keys=8)
            new = random_nested_dict(rng, depth=3, max_keys=8)
            try:
                delta = self.mod._delta_dict(old, new)
            except Exception as e:
                log(FUZZ_ROOT_SEED + i, (old, new))
                self.fail(f"_delta_dict raised: {e!r}")
            self.assertIsInstance(delta, dict)
            # Keys are union of old + new
            self.assertEqual(set(delta.keys()),
                             set(old.keys()) | set(new.keys()))

    def test_has_meaningful_change_never_raises(self) -> None:
        """_has_meaningful_change over random deltas returns bool."""
        rng = random.Random(FUZZ_ROOT_SEED + 2002)
        for i in range(FUZZ_ITERATIONS):
            delta = random_nested_dict(rng, depth=3, max_keys=6)
            try:
                ok = self.mod.DifferentialFilter._has_meaningful_change(delta)
            except Exception as e:
                make_seed_logger("has_mc")(FUZZ_ROOT_SEED + i, delta)
                self.fail(f"_has_meaningful_change raised: {e!r}")
            self.assertIsInstance(ok, bool)

    def test_delta_collection_unhashable(self) -> None:
        """Lists-of-dicts / lists-of-lists fall back to summary shape."""
        rng = random.Random(FUZZ_ROOT_SEED + 2003)
        for _ in range(200):
            # Build two collections with unhashable elements
            old = [dict(x=rng.randint(0, 10)) for _ in range(rng.randint(0, 5))]
            new = [dict(x=rng.randint(0, 10)) for _ in range(rng.randint(0, 5))]
            d = self.mod._delta_collection(old, new)
            self.assertIsInstance(d, dict)
            # Either set-diff shape or summary shape
            if "added" in d:
                self.assertIn("removed", d)
            else:
                self.assertIn("changed", d)
                self.assertIn("old_len", d)
                self.assertIn("new_len", d)

    def test_tick_observer_raising_snapshot(self) -> None:
        """Observer whose snapshot() raises: tick() returns {} not crash."""
        class _BadObserver:
            def snapshot(self):
                raise RuntimeError("snapshot boom")
        flt = self.mod.DifferentialFilter(observer=_BadObserver(), name="bad")
        for _ in range(50):
            delta = flt.tick()
            self.assertEqual(delta, {})


@unittest.skipUnless(FUZZ_ENABLED, "fuzz tests disabled by default")
class ObserversSystemRandomCousinTest(unittest.TestCase):
    """One SystemRandom pass over each observer module."""

    def test_sysrand_depth_sampler(self) -> None:
        mod = _load_depth_observer()
        rng = maybe_systemrandom()
        sampler = mod.DepthSampler()
        for _ in range(100):
            size = rng.randint(0, 4096)
            buf = bytes(rng.getrandbits(8) for _ in range(size))
            r = sampler.measure(buf)
            self.assertEqual(r.size, len(buf))

    def test_sysrand_differential_filter(self) -> None:
        mod = _load_differential_observer()
        rng = maybe_systemrandom()
        # Build a random old/new many times
        for _ in range(100):
            # Tiny random dicts
            old = {str(k): rng.randint(0, 100) for k in range(rng.randint(0, 5))}
            new = {str(k): rng.randint(0, 100) for k in range(rng.randint(0, 5))}
            d = mod._delta_dict(old, new)
            self.assertIsInstance(d, dict)


if __name__ == "__main__":
    unittest.main(verbosity=2)
