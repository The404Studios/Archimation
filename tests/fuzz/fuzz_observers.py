"""Fuzz harness for daemon observer surfaces.

S79 Test Agent 1 deliverable.

Three observer modules covered (per task brief):

  * ``LibraryCensus.policy_evaluate`` (ai-control/daemon/library_census.py)
    -- random pids, random library sets in a stub memory_observer.
  * ``DepthSampler.measure``          (ai-control/daemon/depth_observer.py)
    -- random bytes from 0 to 1 MB; assert classification is one of the
    four known strings and ratios in [0, 1.5].
  * ``DifferentialFilter._delta_dict`` + ``_delta_collection``
    (ai-control/daemon/differential_observer.py) -- random nested
    dict / list / tuple / set structures. Assert no infinite recursion.

Env vars:
  * ``FUZZ_DEEP=1``          -> 100k iterations (byte-size fuzz).
  * ``FUZZ_ITERATIONS=N``    -> override iteration count.
"""

from __future__ import annotations

import importlib.util
import os
import random
import string
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FUZZ_DIR = Path(__file__).resolve().parent
if str(_FUZZ_DIR) not in sys.path:
    sys.path.insert(0, str(_FUZZ_DIR))

from _fuzz_helpers import (  # noqa: E402
    make_seed_logger,
    random_byte_pattern,
    random_bytes,
    random_nested_dict,
    random_scalar,
)

FUZZ_DEEP = bool(os.environ.get("FUZZ_DEEP"))
FUZZ_ITERATIONS = int(os.environ.get(
    "FUZZ_ITERATIONS",
    "100000" if FUZZ_DEEP else "500",
))
FUZZ_ROOT_SEED = int(os.environ.get("FUZZ_ROOT_SEED", "271828"))


def _load_daemon_module(name: str):
    mod_name = f"_fuzz_{name}"
    path = _REPO_ROOT / "ai-control" / "daemon" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


LC = _load_daemon_module("library_census")
DO = _load_daemon_module("depth_observer")
DIFF = _load_daemon_module("differential_observer")


# --------------------------------------------------------------------------
# Fake memory_observer for LibraryCensus
# --------------------------------------------------------------------------

class _FakePmap:
    def __init__(self, dlls: dict):
        self.dlls_loaded = dlls


class _FakeMemoryObserver:
    def __init__(self, procs: dict):
        self._processes = procs


def _random_dll_name(rng: random.Random) -> str:
    base = rng.choice([
        "kernel32", "ntdll", "user32", "gdi32", "msvcrt", "advapi32",
        "wow_rare", "aclayers", "malware_x", "vulkan-1", "dxgi",
    ])
    # Vary case + extension to stress the lowercase normalization.
    ext = rng.choice(["dll", "DLL", "Dll", ""])
    suffix = "".join(rng.choices(string.hexdigits, k=rng.randint(0, 4)))
    return f"{base}{suffix}.{ext}" if ext else base


def _build_observer(rng: random.Random) -> _FakeMemoryObserver:
    n_procs = rng.randint(0, 40)
    procs = {}
    # Mix normal / negative / huge / zero PIDs.
    for _ in range(n_procs):
        pid_choice = rng.randint(0, 4)
        if pid_choice == 0:
            pid = rng.randint(1, 99999)
        elif pid_choice == 1:
            pid = 0
        elif pid_choice == 2:
            pid = -rng.randint(1, 100000)
        elif pid_choice == 3:
            pid = 2 ** 31 - 1  # INT_MAX
        else:
            pid = 2 ** 63 - 1
        k = rng.randint(0, 20)
        dlls = {_random_dll_name(rng): None for _ in range(k)}
        procs[pid] = _FakePmap(dlls)
    return _FakeMemoryObserver(procs)


class FuzzLibraryCensus(unittest.TestCase):

    def test_policy_evaluate_random_populations(self):
        log = make_seed_logger(self._testMethodName)
        iters = min(FUZZ_ITERATIONS, 800)
        for i in range(iters):
            seed = FUZZ_ROOT_SEED + i
            rng = random.Random(seed)
            mo = _build_observer(rng)
            census = LC.LibraryCensus(memory_observer=mo)

            # Query with a random pid (may or may not exist in mo).
            target = rng.choice(list(mo._processes.keys())
                                + [rng.randint(-10, 10), 2**31 - 1,
                                   -1, 0])
            try:
                out = census.policy_evaluate(target)
            except Exception as exc:
                log(seed, target)
                raise AssertionError(
                    f"policy_evaluate raised {type(exc).__name__}: {exc} "
                    f"pid={target} seed={seed}"
                ) from exc
            # Returns None or a dict with a fixed schema.
            if out is not None:
                self.assertIsInstance(out, dict)
                self.assertEqual(out.get("source"), "library_census.policy")
                self.assertEqual(out.get("subject_pid"), int(target))
                self.assertIsInstance(out.get("rare_loaded"), list)

    def test_snapshot_never_raises(self):
        """snapshot() on random populations must produce well-formed output."""
        iters = min(FUZZ_ITERATIONS, 200)
        for i in range(iters):
            seed = FUZZ_ROOT_SEED + i
            rng = random.Random(seed)
            mo = _build_observer(rng)
            census = LC.LibraryCensus(memory_observer=mo)
            snap = census.snapshot()
            self.assertIsInstance(snap, dict)
            self.assertIn("library_counts", snap)
            self.assertIn("total_subjects", snap)
            self.assertGreaterEqual(snap["total_subjects"], 0)
            self.assertGreaterEqual(snap["unique_library_ratio"], 0.0)
            self.assertLessEqual(snap["unique_library_ratio"], 1.0)


# --------------------------------------------------------------------------
# DepthSampler
# --------------------------------------------------------------------------

class FuzzDepthSampler(unittest.TestCase):

    def test_measure_random_sizes(self):
        """measure() on 0..1MB buffers; classification invariants."""
        log = make_seed_logger(self._testMethodName)
        sampler = DO.DepthSampler()
        valid_classes = {
            DO.CLASS_SHALLOW, DO.CLASS_DEEP, DO.CLASS_RANDOM, DO.CLASS_MIXED,
        }
        # Cap iterations because large-buffer gzip is expensive.
        iters = min(FUZZ_ITERATIONS, 200)
        for i in range(iters):
            seed = FUZZ_ROOT_SEED + i
            rng = random.Random(seed)
            # Size distribution: heavy tail biased to small.
            shape = rng.randint(0, 4)
            if shape == 0:
                n = 0
            elif shape == 1:
                n = rng.randint(1, 31)  # below MIN_USEFUL_BYTES
            elif shape == 2:
                n = rng.randint(32, 4096)
            elif shape == 3:
                n = rng.randint(4096, 65536)
            else:
                n = rng.randint(65536, 1024 * 1024)
            data = random_byte_pattern(rng, n)
            try:
                res = sampler.measure(data, name=f"fuzz-{i}")
            except Exception as exc:
                log(seed, (n, data[:32]))
                raise AssertionError(
                    f"measure raised {type(exc).__name__}: {exc} "
                    f"size={n} seed={seed}"
                ) from exc
            self.assertIn(res.classification, valid_classes,
                          msg=f"seed={seed} size={n}")
            # Size matches.
            self.assertEqual(res.size, n)
            # Ratios are non-negative floats. gzip header can push above 1.0
            # on tiny inputs, so cap at 1.5 per the sampler docstring.
            self.assertGreaterEqual(res.fast_ratio, 0.0)
            self.assertGreaterEqual(res.slow_ratio, 0.0)
            self.assertLessEqual(res.fast_ratio, 1.5,
                                 msg=f"seed={seed} size={n} "
                                     f"fast_ratio={res.fast_ratio}")
            self.assertLessEqual(res.slow_ratio, 1.5,
                                 msg=f"seed={seed} size={n} "
                                     f"slow_ratio={res.slow_ratio}")


# --------------------------------------------------------------------------
# DifferentialFilter delta helpers
# --------------------------------------------------------------------------

class FuzzDifferentialFilter(unittest.TestCase):

    def test_delta_dict_deep_nesting(self):
        """Deeply nested dicts must not recurse beyond Python's default limit."""
        log = make_seed_logger(self._testMethodName)
        iters = min(FUZZ_ITERATIONS, 500)
        for i in range(iters):
            seed = FUZZ_ROOT_SEED + i
            rng = random.Random(seed)
            depth = rng.randint(0, 6)
            old = random_nested_dict(rng, depth=depth, max_keys=4)
            new = random_nested_dict(rng, depth=depth, max_keys=4)
            try:
                delta = DIFF._delta_dict(old, new)
            except RecursionError as exc:
                log(seed, (depth, old, new))
                raise AssertionError(
                    f"_delta_dict hit RecursionError at depth={depth} seed={seed}"
                ) from exc
            except Exception as exc:
                log(seed, (depth, old, new))
                raise AssertionError(
                    f"_delta_dict raised {type(exc).__name__}: {exc} seed={seed}"
                ) from exc
            self.assertIsInstance(delta, dict)

    def test_delta_collection_mixed_hashability(self):
        """Mixed hashable / unhashable members hit both code paths."""
        log = make_seed_logger(self._testMethodName)
        iters = min(FUZZ_ITERATIONS, 500)
        for i in range(iters):
            seed = FUZZ_ROOT_SEED + i
            rng = random.Random(seed)
            # Build mixed lists that sometimes contain unhashable values
            # (dicts, lists) which force the except-TypeError branch.
            def mk_list():
                n = rng.randint(0, 8)
                out = []
                for _ in range(n):
                    c = rng.randint(0, 3)
                    if c == 0:
                        out.append(random_scalar(rng))
                    elif c == 1:
                        out.append([random_scalar(rng)
                                    for _ in range(rng.randint(0, 3))])
                    elif c == 2:
                        out.append({"k": random_scalar(rng)})
                    else:
                        out.append((random_scalar(rng),))
                return out

            old = mk_list()
            new = mk_list()
            try:
                delta = DIFF._delta_collection(old, new)
            except Exception as exc:
                log(seed, (old, new))
                raise AssertionError(
                    f"_delta_collection raised {type(exc).__name__}: {exc} "
                    f"seed={seed}"
                ) from exc
            self.assertIsInstance(delta, dict)
            # Output always has one of these two shapes.
            shapes = (
                {"added", "removed"},
                {"changed", "old_len", "new_len"},
            )
            self.assertTrue(set(delta.keys()) in shapes,
                            msg=f"seed={seed} delta={delta}")


if __name__ == "__main__":
    unittest.main()
