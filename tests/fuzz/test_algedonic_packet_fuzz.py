"""Fuzz tests for ``ai-control/daemon/algedonic_reader.decode_packet``.

Target: ``decode_packet(raw: bytes) -> dict``. Contract:

  * Exactly 40-byte input: returns a dict with documented keys.
  * Any OTHER length: raises ValueError (documented).
  * Any 16-bit reason code (0..65535): returns reason_name as either a
    known string from _REASON_NAMES or ``unknown(<n>)``.
  * Any 16-bit severity: returns severity as int, critical flag as bool.

This suite hammers the decoder with 1000+ random 40-byte buffers and
additionally tests boundary sizes 0..120 to make sure the wrong-size
path always raises the documented ValueError (and nothing else).

S79 Test Agent 1 deliverable.
"""

from __future__ import annotations

import importlib
import json
import os
import random
import re
import struct
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
    random_byte_pattern,
    random_bytes,
)

FUZZ_ENABLED = bool(os.environ.get("FUZZ_TESTS"))
FUZZ_ITERATIONS = int(os.environ.get("FUZZ_ITERATIONS", "1000"))
FUZZ_ROOT_SEED = 42


def _load_module():
    sys.modules.pop("algedonic_reader", None)
    return importlib.import_module("algedonic_reader")


_REASON_NAME_RE = re.compile(r"^(unknown\(\d+\)|[a-z_]+)$")
_KNOWN_REASON_NAMES = {
    "unknown", "pool_exhaustion", "ape_exhaustion", "cascade_apoptosis",
    "quorum_disputed_repeatedly", "morphogen_hot_spot", "cancer_detected",
    "tpm_drift", "proof_chain_break", "token_starvation_storm",
}


@unittest.skipUnless(FUZZ_ENABLED, "fuzz tests disabled by default")
class AlgedonicDecodeFuzzTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_module()

    def _validate_decoded_event(self, event: dict) -> None:
        """Assert the event dict matches the documented schema."""
        expected_keys = {
            "source", "topic", "ts_ns", "subject_pid", "severity",
            "reason_code", "reason_name", "payload", "critical",
        }
        self.assertEqual(set(event.keys()), expected_keys)
        # Types
        self.assertIsInstance(event["source"], str)
        self.assertIsInstance(event["topic"], str)
        self.assertIsInstance(event["ts_ns"], int)
        self.assertIsInstance(event["subject_pid"], int)
        self.assertIsInstance(event["severity"], int)
        self.assertIsInstance(event["reason_code"], int)
        self.assertIsInstance(event["reason_name"], str)
        self.assertIsInstance(event["payload"], list)
        self.assertIsInstance(event["critical"], bool)
        # reason_name shape: known name OR unknown(N)
        self.assertTrue(
            _REASON_NAME_RE.match(event["reason_name"]),
            f"reason_name has unexpected shape: {event['reason_name']!r}",
        )
        if event["reason_name"].startswith("unknown("):
            # Must be unknown(<digits>) with reason_code outside the map
            self.assertNotIn(event["reason_name"], _KNOWN_REASON_NAMES)
        # payload is 3 uints
        self.assertEqual(len(event["payload"]), 3)
        for x in event["payload"]:
            self.assertIsInstance(x, int)
        # topic always starts with trust.algedonic.
        self.assertTrue(event["topic"].startswith("trust.algedonic."))
        # critical iff severity > CRITICAL
        self.assertEqual(
            event["critical"],
            event["severity"] > self.mod.TRUST_ALG_SEVERITY_CRITICAL,
        )
        # JSON safe
        json.dumps(event)

    # ------------------------------------------------------------------
    # 40-byte random buffers
    # ------------------------------------------------------------------

    def test_fuzz_random_40byte_buffers(self) -> None:
        """1000 random 40-byte buffers: all decode to valid events."""
        rng = random.Random(FUZZ_ROOT_SEED)
        log = make_seed_logger("alg_decode_random")
        for i in range(FUZZ_ITERATIONS):
            raw = random_bytes(rng, 40)
            try:
                ev = self.mod.decode_packet(raw)
            except Exception as e:
                log(FUZZ_ROOT_SEED + i, raw)
                self.fail(f"decode_packet(random 40-byte) raised: {e!r}")
            self._validate_decoded_event(ev)

    def test_fuzz_pattern_40byte_buffers(self) -> None:
        """All-zero / all-FF / alternating patterns at 40 bytes."""
        rng = random.Random(FUZZ_ROOT_SEED + 1)
        for i in range(200):
            raw = random_byte_pattern(rng, 40)
            ev = self.mod.decode_packet(raw)
            self._validate_decoded_event(ev)

    def test_fuzz_all_reason_codes(self) -> None:
        """Sweep every 16-bit reason code from 0..65535 step 101."""
        rng = random.Random(FUZZ_ROOT_SEED + 2)
        for reason in range(0, 65536, 101):
            raw = struct.pack(
                "<QIHHQQQ",
                rng.randint(0, 1 << 63),       # ts_ns
                rng.randint(0, 1 << 31),       # pid
                rng.randint(0, 65535),         # severity
                reason,                        # reason
                rng.randint(0, 1 << 63),
                rng.randint(0, 1 << 63),
                rng.randint(0, 1 << 63),
            )
            ev = self.mod.decode_packet(raw)
            self.assertEqual(ev["reason_code"], reason)
            self.assertIsInstance(ev["reason_name"], str)

    def test_fuzz_severity_thresholds(self) -> None:
        """Severity 0, 1024, 16384, 32768, 32769, 65535 -> critical flag
        only True for severity > CRITICAL threshold (32768)."""
        cases = [(0, False), (1024, False), (16384, False),
                 (32768, False), (32769, True), (65535, True)]
        for sev, expect_crit in cases:
            raw = struct.pack("<QIHHQQQ", 0, 0, sev, 0, 0, 0, 0)
            ev = self.mod.decode_packet(raw)
            self.assertEqual(ev["severity"], sev)
            self.assertEqual(ev["critical"], expect_crit)

    # ------------------------------------------------------------------
    # Wrong-size buffers: must raise ValueError, never OSError / IndexError
    # ------------------------------------------------------------------

    def test_fuzz_wrong_size_always_valueerror(self) -> None:
        """Every size 0..120 except 40 must raise ValueError exactly."""
        rng = random.Random(FUZZ_ROOT_SEED + 3)
        for size in list(range(0, 40)) + list(range(41, 121)):
            for _ in range(5):
                raw = random_bytes(rng, size)
                with self.assertRaises(ValueError,
                                       msg=f"size={size}"):
                    self.mod.decode_packet(raw)

    def test_fuzz_oversized_buffers(self) -> None:
        """Very large buffers (up to 10KB): still ValueError."""
        rng = random.Random(FUZZ_ROOT_SEED + 4)
        for _ in range(100):
            size = rng.choice([200, 1024, 4096, 8192, 10000])
            raw = random_bytes(rng, size)
            with self.assertRaises(ValueError):
                self.mod.decode_packet(raw)

    # ------------------------------------------------------------------
    # SystemRandom cousin
    # ------------------------------------------------------------------

    def test_sysrand_40byte_iterations(self) -> None:
        rng = maybe_systemrandom()
        for _ in range(500):
            raw = bytes(rng.getrandbits(8) for _ in range(40))
            ev = self.mod.decode_packet(raw)
            self._validate_decoded_event(ev)


@unittest.skipUnless(FUZZ_ENABLED, "fuzz tests disabled by default")
class AlgedonicReasonNameFuzzTest(unittest.TestCase):
    """Direct probe of _reason_name helper."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_module()

    def test_fuzz_reason_name_never_raises(self) -> None:
        rng = random.Random(FUZZ_ROOT_SEED + 5)
        for _ in range(2000):
            # Could be any signed/unsigned int; _reason_name uses dict.get
            # so arbitrary ints are fine.
            code = rng.randint(-1000, 1 << 20)
            s = self.mod._reason_name(code)
            self.assertIsInstance(s, str)
            # Either known name or unknown(<n>)
            if code in self.mod._REASON_NAMES:
                self.assertEqual(s, self.mod._REASON_NAMES[code])
            else:
                self.assertTrue(s.startswith("unknown("))
                self.assertTrue(s.endswith(")"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
