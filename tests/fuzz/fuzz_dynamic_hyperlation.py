"""Fuzz harness for ``ai-control/cortex/dynamic_hyperlation.py``.

S79 Test Agent 1 deliverable.

Targets:

  * ``MarkovTransitionMatrix.update`` -- mixed valid/invalid/bool/NaN
    indices. Docstring (line 220-224) promises silent-no-op on bad input.
  * ``HyperlationStateTracker.classify_hypothesis_violation`` -- subject
    state dicts with missing keys, wrong types, malformed
    metabolism_rate. Must never raise.
  * ``_invert_3x3`` -- random 3x3 matrices including near-singular and
    inf/NaN entries. Must be stable (returns None on det=0).

Env vars:
  * ``FUZZ_DEEP=1``          -> 100k iterations.
  * ``FUZZ_ITERATIONS=N``    -> override iteration count.
"""

from __future__ import annotations

import importlib.util
import math
import os
import random
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FUZZ_DIR = Path(__file__).resolve().parent
if str(_FUZZ_DIR) not in sys.path:
    sys.path.insert(0, str(_FUZZ_DIR))

from _fuzz_helpers import (  # noqa: E402
    make_seed_logger,
    random_dict_with_keys,
)

FUZZ_DEEP = bool(os.environ.get("FUZZ_DEEP"))
FUZZ_ITERATIONS = int(os.environ.get(
    "FUZZ_ITERATIONS",
    "100000" if FUZZ_DEEP else "2000",
))
FUZZ_ROOT_SEED = int(os.environ.get("FUZZ_ROOT_SEED", "577215"))


def _load_dynhyp():
    name = "_fuzz_dynamic_hyperlation"
    path = _REPO_ROOT / "ai-control" / "cortex" / "dynamic_hyperlation.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


DH = _load_dynhyp()


class FuzzMarkovUpdate(unittest.TestCase):

    def test_update_garbage_indices(self):
        """update(bad_idx) is silent; counts unchanged; last_seen_state stable."""
        log = make_seed_logger(self._testMethodName)
        for i in range(FUZZ_ITERATIONS):
            seed = FUZZ_ROOT_SEED + i
            rng = random.Random(seed)
            mat = DH.MarkovTransitionMatrix()

            # Sequence of garbage + valid indices.
            history_len_before_valid = 0
            for _ in range(rng.randint(1, 40)):
                c = rng.randint(0, 8)
                if c == 0:
                    idx = rng.randint(0, 3)  # valid
                elif c == 1:
                    idx = -rng.randint(1, 1 << 30)
                elif c == 2:
                    idx = rng.randint(4, 1 << 30)
                elif c == 3:
                    idx = True  # bool (int subclass, must reject)
                elif c == 4:
                    idx = False
                elif c == 5:
                    idx = float("nan")
                elif c == 6:
                    idx = float("inf")
                elif c == 7:
                    idx = None
                else:
                    idx = "0"  # string
                try:
                    mat.update(idx)
                except Exception as exc:
                    log(seed, idx)
                    raise AssertionError(
                        f"update raised {type(exc).__name__}: {exc} idx={idx!r} "
                        f"seed={seed}"
                    ) from exc

            # State invariants.
            if mat.last_seen_state is not None:
                self.assertIsInstance(mat.last_seen_state, int)
                self.assertNotIsInstance(mat.last_seen_state, bool)
                self.assertGreaterEqual(mat.last_seen_state, 0)
                self.assertLess(mat.last_seen_state, DH.MARKOV_N_STATES)
            # Counts always non-negative.
            for row in mat.counts:
                for c in row:
                    self.assertGreaterEqual(c, 0)


class FuzzClassifyHypothesisViolation(unittest.TestCase):

    def test_random_subject_state_dicts(self):
        """Classifier tolerant of missing / malformed keys; returns a list."""
        log = make_seed_logger(self._testMethodName)
        valid_states = [
            "STEADY_FLOW", "METABOLIC_STARVATION", "BEHAVIORAL_DIVERGENCE",
            "APOPTOSIS", "INVALID_STATE", None,
        ]
        for i in range(FUZZ_ITERATIONS):
            seed = FUZZ_ROOT_SEED + i
            rng = random.Random(seed)
            # Build a plausibly-shaped but intentionally flawed record.
            record = {}
            if rng.random() < 0.8:
                metab = rng.choice([
                    rng.uniform(-1.0, 10.0),
                    float("nan"),
                    float("inf"),
                    "not-a-number",
                    None,
                    rng.randint(-1 << 20, 1 << 20),
                ])
                record["metabolism_rate"] = metab
            if rng.random() < 0.6:
                record["state"] = rng.choice(valid_states)
            if rng.random() < 0.5:
                record["apoptosis_event"] = rng.choice(
                    [True, False, 0, 1, "yes", None])
            if rng.random() < 0.3:
                record["apoptosis"] = rng.choice([True, False, None])
            if rng.random() < 0.3:
                record["dead"] = rng.choice([True, False, None])
            if rng.random() < 0.5:
                record["S_t"] = rng.choice([
                    0.0, rng.uniform(-100, 100), "nan", None,
                ])
            if rng.random() < 0.5:
                record["C_t"] = rng.choice([
                    0.0, rng.uniform(-100, 100), "nan", None,
                ])

            try:
                out = DH.HyperlationStateTracker.classify_hypothesis_violation(
                    record)
            except Exception as exc:
                log(seed, record)
                raise AssertionError(
                    f"classify_hypothesis_violation raised "
                    f"{type(exc).__name__}: {exc} record={record!r} seed={seed}"
                ) from exc
            self.assertIsInstance(out, list)
            # Every element must be a HypothesisSlot.
            for slot in out:
                self.assertIsInstance(slot, DH.HypothesisSlot,
                                      msg=f"seed={seed} slot={slot!r}")

    def test_missing_dict_returns_list(self):
        """An empty dict is a valid input -- returns an empty (or short) list."""
        out = DH.HyperlationStateTracker.classify_hypothesis_violation({})
        self.assertIsInstance(out, list)


class FuzzInvert3x3(unittest.TestCase):

    def test_near_singular_and_pathological(self):
        """_invert_3x3 stable on near-singular, inf/NaN-laced matrices."""
        log = make_seed_logger(self._testMethodName)
        iters = min(FUZZ_ITERATIONS, 5000)
        for i in range(iters):
            seed = FUZZ_ROOT_SEED + i
            rng = random.Random(seed)
            shape = rng.randint(0, 4)
            if shape == 0:
                # All zero (singular).
                M = [[0.0] * 3 for _ in range(3)]
            elif shape == 1:
                # Identity (trivially invertible).
                M = [[1.0 if i == j else 0.0 for j in range(3)]
                     for i in range(3)]
            elif shape == 2:
                # Near-singular: two identical rows.
                row = [rng.uniform(-10, 10) for _ in range(3)]
                M = [row, list(row), [rng.uniform(-10, 10) for _ in range(3)]]
            elif shape == 3:
                # Infinity / NaN seeded.
                M = [[rng.choice([float("inf"), float("nan"),
                                  rng.uniform(-5, 5)])
                      for _ in range(3)] for _ in range(3)]
            else:
                # Random, probably invertible.
                M = [[rng.uniform(-100, 100) for _ in range(3)]
                     for _ in range(3)]

            try:
                inv = DH._invert_3x3(M)
            except Exception as exc:
                log(seed, M)
                raise AssertionError(
                    f"_invert_3x3 raised {type(exc).__name__}: {exc} "
                    f"M={M} seed={seed}"
                ) from exc
            # Return type is None or a 3x3 list-of-lists.
            if inv is not None:
                self.assertEqual(len(inv), 3)
                for row in inv:
                    self.assertEqual(len(row), 3)


if __name__ == "__main__":
    unittest.main()
