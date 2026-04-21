"""Fuzz harness for ``algedonic_reader.decode_packet``.

S79 Test Agent 1 deliverable.

The algedonic channel is a fixed 40-byte wire format
(``trust_algedonic_packet`` in trust/include/trust_algedonic.h mirrored in
algedonic_reader.py). The decoder has a strict length check.

Tests:

  1. All sizes 0..79 EXCEPT 40 must raise ``ValueError``.
  2. Size-40 random bytes must NEVER raise, and the returned dict must
     contain expected fields of the right type.
  3. Reason code coverage: codes 0..9 map to known names; all other
     16-bit codes fall back to the ``unknown(N)`` label (never None, never
     raise).
  4. critical flag: sev > TRUST_ALG_SEVERITY_CRITICAL (=32768) toggles
     the ``critical`` bit.

NOTE: The task brief references ``_decode_packet`` but the actual public
function is ``decode_packet`` (algedonic_reader.py:90) -- no leading
underscore. We fuzz the real symbol.
"""

from __future__ import annotations

import importlib.util
import os
import random
import struct
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FUZZ_DIR = Path(__file__).resolve().parent
if str(_FUZZ_DIR) not in sys.path:
    sys.path.insert(0, str(_FUZZ_DIR))

from _fuzz_helpers import make_seed_logger, random_bytes  # noqa: E402

FUZZ_DEEP = bool(os.environ.get("FUZZ_DEEP"))
FUZZ_ITERATIONS = int(os.environ.get(
    "FUZZ_ITERATIONS",
    "100000" if FUZZ_DEEP else "2000",
))
FUZZ_ROOT_SEED = int(os.environ.get("FUZZ_ROOT_SEED", "161803"))


def _load_algedonic():
    name = "_fuzz_algedonic"
    path = _REPO_ROOT / "ai-control" / "daemon" / "algedonic_reader.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


AR = _load_algedonic()


class FuzzAlgedonicDecode(unittest.TestCase):

    def test_all_bad_sizes_raise(self):
        """Every size in 0..79 except 40 must raise ValueError."""
        for size in range(0, 80):
            if size == 40:
                continue
            buf = b"\x00" * size
            with self.assertRaises(ValueError, msg=f"size={size} did not raise"):
                AR.decode_packet(buf)

    def test_size_40_never_raises(self):
        """All random 40-byte buffers decode without raising."""
        log = make_seed_logger(self._testMethodName)
        for i in range(FUZZ_ITERATIONS):
            seed = FUZZ_ROOT_SEED + i
            rng = random.Random(seed)
            buf = random_bytes(rng, 40)
            try:
                out = AR.decode_packet(buf)
            except Exception as exc:
                log(seed, buf)
                raise AssertionError(
                    f"decode_packet raised {type(exc).__name__}: {exc} "
                    f"on 40-byte random seed={seed}"
                ) from exc
            # Schema checks
            self.assertIsInstance(out, dict)
            self.assertIn("ts_ns", out)
            self.assertIn("subject_pid", out)
            self.assertIn("severity", out)
            self.assertIn("reason_code", out)
            self.assertIn("reason_name", out)
            self.assertIn("payload", out)
            self.assertIn("critical", out)
            self.assertIsInstance(out["reason_name"], str)
            self.assertIsInstance(out["critical"], bool)
            self.assertIsInstance(out["payload"], list)
            self.assertEqual(len(out["payload"]), 3)
            # reason_code is a u16 -- bounded.
            self.assertGreaterEqual(out["reason_code"], 0)
            self.assertLess(out["reason_code"], 2**16)

    def test_reason_code_coverage(self):
        """Known 0..9 decode to named reasons; unknowns get 'unknown(N)'."""
        # Build a valid packet with a chosen reason.
        known = set(range(0, 10))
        for reason in list(known) + [10, 100, 1000, 30000, 2**16 - 1]:
            pkt = struct.pack(
                "<QIHHQQQ",
                0,           # ts_ns
                1234,        # pid
                100,         # sev
                reason,      # reason
                0, 0, 0,     # data[3]
            )
            self.assertEqual(len(pkt), 40)
            out = AR.decode_packet(pkt)
            self.assertEqual(out["reason_code"], reason)
            name = out["reason_name"]
            self.assertIsInstance(name, str)
            if reason in known:
                self.assertFalse(name.startswith("unknown("),
                                 msg=f"known reason {reason} labelled unknown")
            else:
                self.assertTrue(name.startswith("unknown("),
                                msg=f"unknown reason {reason} labelled {name}")

    def test_critical_bit_flip(self):
        """Severity > 32768 flips ``critical`` True; <= flips False."""
        for sev in [0, 1, 1024, 16384, 32768, 32769, 40000, 2**16 - 1]:
            pkt = struct.pack("<QIHHQQQ", 0, 1, sev, 0, 0, 0, 0)
            out = AR.decode_packet(pkt)
            if sev > AR.TRUST_ALG_SEVERITY_CRITICAL:
                self.assertTrue(out["critical"],
                                msg=f"sev={sev} did not set critical")
            else:
                self.assertFalse(out["critical"],
                                 msg=f"sev={sev} incorrectly set critical")

    def test_exact_40_ones_and_zeros_edge(self):
        """Boundary bit patterns -- all-zero, all-0xff, alternating."""
        patterns = [
            b"\x00" * 40,
            b"\xff" * 40,
            (b"\x00\xff" * 20),
            (b"\xaa" * 40),
            (b"\x55" * 40),
        ]
        for p in patterns:
            out = AR.decode_packet(p)
            self.assertIsInstance(out, dict)
            self.assertIsInstance(out["reason_name"], str)


if __name__ == "__main__":
    unittest.main()
