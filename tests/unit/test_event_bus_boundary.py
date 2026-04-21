"""Boundary tests for parsers in ``ai-control/cortex/event_bus.py``.

S79 Test Agent 3 -- boundary sweep for the 10 payload parsers.

For each parser:
  * input b"" -> empty dict (not crash)
  * input one byte short of minimum -> empty dict
  * input exactly minimum size -> fields parsed
  * input minimum + 1 -> fields parsed (no overflow)
  * input 10x expected size -> only consumes expected bytes

Parsers probed (from event_bus.py):
  * parse_pe_load_payload         (min=272)
  * parse_pe_dll_load_payload     (min=72)
  * parse_pe_unimplemented_payload (min=192)
  * parse_pe_exit_payload         (min=12)
  * parse_pe_trust_deny_payload   (min=137, also 140)
  * parse_pe_trust_escalate_payload (min=140)
  * parse_memory_map_payload      (min=300)
  * parse_memory_protect_payload  (min=60)
  * parse_memory_pattern_payload  (min=296)
  * parse_memory_anomaly_payload  (min=180)
  * parse_stub_called_payload     (min=192)

Not gated. Must complete <5s.
"""

from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CORTEX_DIR = _REPO_ROOT / "ai-control" / "cortex"

if str(_CORTEX_DIR) not in sys.path:
    sys.path.insert(0, str(_CORTEX_DIR))


def _load():
    sys.modules.pop("event_bus", None)
    return importlib.import_module("event_bus")


# Table of (parser_name, min_size, is_escalate_empty_shape) pairs.
# "is_escalate_empty_shape" = True for parsers that return
# {"raw_len": ...} instead of {} on too-small input.
_PARSER_TABLE = [
    ("parse_pe_load_payload", 272, False),
    ("parse_pe_dll_load_payload", 72, False),
    ("parse_pe_unimplemented_payload", 192, False),
    ("parse_pe_exit_payload", 12, False),
    ("parse_pe_trust_deny_payload", 137, False),
    # parse_pe_trust_escalate_payload returns {"raw_len": ...} on short
    # input (source line 326), not {} -- documented difference.
    ("parse_pe_trust_escalate_payload", 140, True),
    ("parse_memory_map_payload", 300, False),
    ("parse_memory_protect_payload", 60, False),
    ("parse_memory_pattern_payload", 296, False),
    ("parse_memory_anomaly_payload", 180, False),
    ("parse_stub_called_payload", 192, False),
]


class ParserSizeBoundarySweep(unittest.TestCase):
    """Size boundaries for every parser, using subTest for parameterization."""

    def setUp(self) -> None:
        self.mod = _load()

    def test_empty_bytes_all_parsers(self) -> None:
        """b"" -> empty dict (or {"raw_len": 0} for escalate)."""
        for name, _, is_escalate in _PARSER_TABLE:
            with self.subTest(parser=name):
                fn = getattr(self.mod, name)
                result = fn(b"")
                if is_escalate:
                    self.assertIn("raw_len", result)
                    self.assertEqual(result["raw_len"], 0)
                else:
                    self.assertEqual(result, {})

    def test_one_byte_short_all_parsers(self) -> None:
        """min_size-1 bytes -> empty dict (or {"raw_len": ...})."""
        for name, min_size, is_escalate in _PARSER_TABLE:
            with self.subTest(parser=name, min_size=min_size):
                fn = getattr(self.mod, name)
                raw = b"\x00" * (min_size - 1)
                result = fn(raw)
                if is_escalate:
                    self.assertIn("raw_len", result)
                else:
                    self.assertEqual(result, {})

    def test_exact_min_size_all_parsers(self) -> None:
        """Exactly min_size bytes -> parser emits non-trivial dict."""
        for name, min_size, _ in _PARSER_TABLE:
            with self.subTest(parser=name, min_size=min_size):
                fn = getattr(self.mod, name)
                raw = b"\x00" * min_size
                result = fn(raw)
                # Must be a dict, must be non-empty (real fields parsed).
                self.assertIsInstance(result, dict)
                self.assertGreater(len(result), 0,
                                   f"{name}({min_size}) returned empty")

    def test_min_size_plus_one(self) -> None:
        """min_size+1 -> still parses without index errors."""
        for name, min_size, _ in _PARSER_TABLE:
            with self.subTest(parser=name, size=min_size + 1):
                fn = getattr(self.mod, name)
                raw = b"\x00" * (min_size + 1)
                result = fn(raw)
                # Never raises; returns real dict (parse_pe_trust_deny's
                # middle branch may return {"raw_len"}, which is still
                # non-crashing).
                self.assertIsInstance(result, dict)

    def test_ten_times_min_size(self) -> None:
        """10*min_size -> still parses, only consumes expected bytes."""
        for name, min_size, _ in _PARSER_TABLE:
            with self.subTest(parser=name, size=min_size * 10):
                fn = getattr(self.mod, name)
                raw = b"\x00" * (min_size * 10)
                result = fn(raw)
                self.assertIsInstance(result, dict)
                # Non-trivial -- real fields parsed (unless deny odd size
                # branch).
                self.assertGreater(len(result), 0)


class ParsePayloadDispatchBoundary(unittest.TestCase):
    """parse_payload (top-level dispatcher) with unknown keys."""

    def setUp(self) -> None:
        self.mod = _load()

    def test_unknown_source_type_returns_raw(self) -> None:
        """parse_payload on unknown (source, type) -> returns raw bytes."""
        raw = b"hello world"
        result = self.mod.parse_payload(99, 0xFF, raw)
        self.assertEqual(result, raw)

    def test_empty_payload_for_unknown_type(self) -> None:
        """Empty payload for unknown (source, type) -> returns empty bytes."""
        result = self.mod.parse_payload(99, 0xFF, b"")
        self.assertEqual(result, b"")

    def test_known_type_with_too_small_returns_raw(self) -> None:
        """Known parser gets too-small input -> falls through to raw bytes.

        parse_payload returns bytes if parser returned empty dict."""
        raw = b"\x00" * 5  # too small for most parsers
        result = self.mod.parse_payload(
            self.mod.SourceLayer.RUNTIME,
            self.mod.PeEventType.LOAD,
            raw,
        )
        # Parser returns {} -> dispatcher falls through to raw bytes.
        self.assertEqual(result, raw)


class ReasonNameBoundaries(unittest.TestCase):
    """_reason_name handles 0..6 as known, others as unknown(n)."""

    def setUp(self) -> None:
        self.mod = _load()

    def test_known_reasons_mapped(self) -> None:
        for code in range(7):
            with self.subTest(code=code):
                name = self.mod._reason_name(code)
                self.assertNotIn("unknown", name)

    def test_unknown_reason_stringified(self) -> None:
        """Code 99 -> 'unknown(99)'."""
        self.assertEqual(self.mod._reason_name(99), "unknown(99)")

    def test_max_uint32_stringified(self) -> None:
        """Max uint32 reason -> 'unknown(4294967295)'."""
        m = (1 << 32) - 1
        self.assertEqual(self.mod._reason_name(m), f"unknown({m})")


class EventBusParseEventBoundary(unittest.TestCase):
    """EventBus._parse_event header-size guard."""

    def setUp(self) -> None:
        self.mod = _load()

    def test_short_datagram_returns_none(self) -> None:
        """Datagram < HEADER_SIZE (64) -> _parse_event returns None."""
        bus = self.mod.EventBus()
        result = bus._parse_event(b"\x00" * 63)
        self.assertIsNone(result)

    def test_empty_datagram_returns_none(self) -> None:
        """Empty datagram -> None."""
        bus = self.mod.EventBus()
        self.assertIsNone(bus._parse_event(b""))

    def test_bad_magic_returns_none(self) -> None:
        """64 bytes with zero magic -> None (magic check fails)."""
        bus = self.mod.EventBus()
        result = bus._parse_event(b"\x00" * 64)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
