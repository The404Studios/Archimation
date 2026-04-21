"""Boundary tests for ``ai-control/daemon/algedonic_reader.py``.

S79 Test Agent 3 -- wire-format edges in decode_packet().

Boundaries probed:
  * decode_packet(b"") -- empty -> raises ValueError
  * decode_packet 39 bytes -- too short by 1 -> ValueError
  * decode_packet 40 bytes all-zero -> successful decode
  * decode_packet 41 bytes -- too long by 1 -> ValueError
  * decode_packet 40 bytes all-ones -> successful decode
  * All 256 reason byte values -- never crash; unknown render as string

Not gated. Must complete <5s.
"""

from __future__ import annotations

import importlib
import struct
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DAEMON_DIR = _REPO_ROOT / "ai-control" / "daemon"

if str(_DAEMON_DIR) not in sys.path:
    sys.path.insert(0, str(_DAEMON_DIR))


def _load_module():
    sys.modules.pop("algedonic_reader", None)
    return importlib.import_module("algedonic_reader")


class PacketSizeBoundaries(unittest.TestCase):
    """40 bytes exact; off-by-one in either direction rejected."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_empty_bytes_raises(self) -> None:
        """b"" -> ValueError from size check in decode_packet."""
        with self.assertRaises(ValueError):
            self.mod.decode_packet(b"")

    def test_one_byte_short_raises(self) -> None:
        """39 bytes (_PACKET_SIZE - 1) -> ValueError."""
        raw = b"\x00" * 39
        with self.assertRaises(ValueError):
            self.mod.decode_packet(raw)

    def test_exact_40_bytes_all_zero(self) -> None:
        """40 bytes, all zero -> successful decode."""
        raw = b"\x00" * 40
        event = self.mod.decode_packet(raw)
        self.assertEqual(event["ts_ns"], 0)
        self.assertEqual(event["subject_pid"], 0)
        self.assertEqual(event["severity"], 0)
        self.assertEqual(event["reason_code"], 0)
        self.assertEqual(event["reason_name"], "unknown")
        self.assertEqual(event["payload"], [0, 0, 0])
        self.assertFalse(event["critical"])

    def test_one_byte_over_raises(self) -> None:
        """41 bytes (_PACKET_SIZE + 1) -> ValueError.

        decode_packet has `if len(raw) != _PACKET_SIZE: raise`, so longer
        input is rejected (not truncated)."""
        raw = b"\x00" * 41
        with self.assertRaises(ValueError):
            self.mod.decode_packet(raw)

    def test_exact_40_bytes_all_ones(self) -> None:
        """40 bytes, all 0xFF -> decodes to MAX field values.

        All-FFFF: ts_ns=0xFFFFFFFFFFFFFFFF, pid=0xFFFFFFFF, sev=0xFFFF,
        reason=0xFFFF, payload=[max, max, max]."""
        raw = b"\xff" * 40
        event = self.mod.decode_packet(raw)
        self.assertEqual(event["ts_ns"], (1 << 64) - 1)
        self.assertEqual(event["subject_pid"], (1 << 32) - 1)
        self.assertEqual(event["severity"], 0xFFFF)
        self.assertEqual(event["reason_code"], 0xFFFF)
        self.assertEqual(event["reason_name"], "unknown(65535)")
        # severity > TRUST_ALG_SEVERITY_CRITICAL -> critical=True.
        self.assertTrue(event["critical"])


class ReasonCodeBoundaries(unittest.TestCase):
    """All 0..255 reason bytes: known codes decode to names, unknown stringified."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_every_reason_byte_decodes_cleanly(self) -> None:
        """Sweep reason = 0..255; decode must never crash and name must be a str."""
        for reason in range(256):
            with self.subTest(reason=reason):
                raw = struct.pack("<QIHHQQQ", 0, 0, 0, reason, 0, 0, 0)
                event = self.mod.decode_packet(raw)
                self.assertEqual(event["reason_code"], reason)
                self.assertIsInstance(event["reason_name"], str)
                # Known reasons in _REASON_NAMES: no parentheses in their name.
                if reason in self.mod._REASON_NAMES:
                    self.assertEqual(
                        event["reason_name"],
                        self.mod._REASON_NAMES[reason],
                    )
                else:
                    # Unknown codes render as "unknown(<n>)".
                    self.assertIn("unknown(", event["reason_name"])

    def test_reason_above_byte_still_decodes(self) -> None:
        """Reason is a u16 field; values 256..65535 also decode via unknown()."""
        for reason in (256, 1024, 32768, 65535):
            with self.subTest(reason=reason):
                raw = struct.pack("<QIHHQQQ", 0, 0, 0, reason, 0, 0, 0)
                event = self.mod.decode_packet(raw)
                self.assertEqual(event["reason_code"], reason)


class SeverityCriticalBoundary(unittest.TestCase):
    """The "critical" flag toggles strictly above TRUST_ALG_SEVERITY_CRITICAL."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_at_critical_threshold_not_critical(self) -> None:
        """severity == CRITICAL -> critical=False (strict >)."""
        sev = self.mod.TRUST_ALG_SEVERITY_CRITICAL
        raw = struct.pack("<QIHHQQQ", 0, 0, sev, 0, 0, 0, 0)
        event = self.mod.decode_packet(raw)
        self.assertFalse(event["critical"])

    def test_above_critical_threshold_is_critical(self) -> None:
        """severity = CRITICAL + 1 -> critical=True."""
        sev = self.mod.TRUST_ALG_SEVERITY_CRITICAL + 1
        raw = struct.pack("<QIHHQQQ", 0, 0, sev, 0, 0, 0, 0)
        event = self.mod.decode_packet(raw)
        self.assertTrue(event["critical"])

    def test_below_critical_not_critical(self) -> None:
        """severity = 0 -> critical=False."""
        raw = struct.pack("<QIHHQQQ", 0, 0, 0, 0, 0, 0, 0)
        event = self.mod.decode_packet(raw)
        self.assertFalse(event["critical"])


if __name__ == "__main__":
    unittest.main()
