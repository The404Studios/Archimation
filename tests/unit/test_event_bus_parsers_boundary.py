"""Boundary tests for ``ai-control/cortex/event_bus.py`` payload parsers.

S79 Test Agent 3 -- wire-format parser edges:
  * exact boundary sizes for pe_evt_* payloads
  * one-below-boundary (must return {})
  * oversize payloads (must still decode first N bytes)
  * trust_deny packed (137) vs padded (140) vs between (138, 139)
  * trust_escalate canonical (140) + unknown reason_name fallback (S78)
  * _decode_cstr boundary: null-at-0 / no-null / non-utf8 bytes

Not gated. Must complete <2s.
"""

from __future__ import annotations

import importlib
import struct
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CORTEX_DIR = _REPO_ROOT / "ai-control" / "cortex"

if str(_CORTEX_DIR) not in sys.path:
    sys.path.insert(0, str(_CORTEX_DIR))


def _load_module():
    sys.modules.pop("event_bus", None)
    return importlib.import_module("event_bus")


class DecodeCStrBoundaries(unittest.TestCase):
    """_decode_cstr edge cases."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_null_at_position_zero(self) -> None:
        r"""\\x00 at pos 0 -> empty string."""
        self.assertEqual(self.mod._decode_cstr(b"\x00abcd"), "")

    def test_no_null_at_all(self) -> None:
        """Buffer with no null terminator -> decoded in full."""
        self.assertEqual(self.mod._decode_cstr(b"abcd"), "abcd")

    def test_empty_buffer(self) -> None:
        r"""b\"\" -> empty string."""
        self.assertEqual(self.mod._decode_cstr(b""), "")

    def test_non_utf8_bytes_replaced(self) -> None:
        """Invalid utf-8 bytes -> replacement chars (errors=\"replace\")."""
        # 0xff is not a valid utf-8 leading byte by itself.
        out = self.mod._decode_cstr(b"\xff\xfe")
        # Must not raise; replacement chars in output.
        self.assertIsInstance(out, str)
        self.assertGreater(len(out), 0)

    def test_null_mid_buffer(self) -> None:
        r"""b\"abc\\x00garbage\" -> \"abc\" (null terminates)."""
        self.assertEqual(self.mod._decode_cstr(b"abc\x00garbage"), "abc")


class ParsePeLoadPayloadBoundaries(unittest.TestCase):
    """parse_pe_load_payload: 272 is the exact boundary."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_exactly_272_bytes(self) -> None:
        """272 bytes (the exact minimum) -> decoded dict."""
        payload = b"/tmp/a.exe".ljust(256, b"\x00") + struct.pack("<IIiI", 10, 0, 5, 100)
        self.assertEqual(len(payload), 272)
        out = self.mod.parse_pe_load_payload(payload)
        self.assertEqual(out["exe_path"], "/tmp/a.exe")
        self.assertEqual(out["imports_resolved"], 10)
        self.assertEqual(out["imports_unresolved"], 0)
        self.assertEqual(out["trust_score"], 5)
        self.assertEqual(out["token_budget"], 100)

    def test_271_bytes_returns_empty(self) -> None:
        """271 bytes (one below boundary) -> {}."""
        payload = b"\x00" * 271
        self.assertEqual(self.mod.parse_pe_load_payload(payload), {})

    def test_empty_bytes_returns_empty(self) -> None:
        """0 bytes -> {}."""
        self.assertEqual(self.mod.parse_pe_load_payload(b""), {})

    def test_oversize_payload_decodes_prefix(self) -> None:
        """1MB buffer -> still parses (first 272 bytes)."""
        first = b"win.exe".ljust(256, b"\x00") + struct.pack("<IIiI", 7, 2, -3, 50)
        payload = first + b"\xff" * (1024 * 1024)
        self.assertEqual(len(payload), 272 + 1024 * 1024)
        out = self.mod.parse_pe_load_payload(payload)
        self.assertEqual(out["exe_path"], "win.exe")
        self.assertEqual(out["imports_resolved"], 7)
        self.assertEqual(out["trust_score"], -3)  # signed parse


class ParsePeTrustDenyBoundaries(unittest.TestCase):
    """trust_deny supports packed (137) AND padded (140)."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_packed_layout_137_bytes(self) -> None:
        """Exactly 137 bytes -> packed path."""
        payload = (
            b"CreateFile".ljust(128, b"\x00")
            + bytes([3])  # category=3
            + struct.pack("<iI", -5, 200)
        )
        self.assertEqual(len(payload), 137)
        out = self.mod.parse_pe_trust_deny_payload(payload)
        self.assertEqual(out["api_name"], "CreateFile")
        self.assertEqual(out["category"], 3)
        self.assertEqual(out["score"], -5)
        self.assertEqual(out["tokens"], 200)

    def test_padded_layout_140_bytes(self) -> None:
        """Exactly 140 bytes -> padded path (3 bytes alignment after category)."""
        payload = (
            b"OpenKey".ljust(128, b"\x00")
            + bytes([2])  # category=2
            + b"\x00\x00\x00"  # 3 bytes pad
            + struct.pack("<iI", 10, 50)
        )
        self.assertEqual(len(payload), 140)
        out = self.mod.parse_pe_trust_deny_payload(payload)
        self.assertEqual(out["api_name"], "OpenKey")
        self.assertEqual(out["category"], 2)
        self.assertEqual(out["score"], 10)
        self.assertEqual(out["tokens"], 50)

    def test_138_bytes_between_layouts(self) -> None:
        """138 bytes (between 137 and 140): returns raw_len indicator."""
        payload = b"\x00" * 138
        out = self.mod.parse_pe_trust_deny_payload(payload)
        self.assertEqual(out, {"raw_len": 138})

    def test_136_bytes_below_boundary(self) -> None:
        """136 bytes (below min) -> {}."""
        payload = b"\x00" * 136
        self.assertEqual(self.mod.parse_pe_trust_deny_payload(payload), {})

    def test_empty_returns_empty(self) -> None:
        """0 bytes -> {}."""
        self.assertEqual(self.mod.parse_pe_trust_deny_payload(b""), {})


class ParsePeTrustEscalateBoundaries(unittest.TestCase):
    """trust_escalate: 140 canonical; unknown reason produces 'unknown(N)'."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def _make(self, api, from_s, to_s, reason):
        return (
            api.encode("utf-8").ljust(128, b"\x00")
            + struct.pack("<iiI", from_s, to_s, reason)
        )

    def test_exactly_140_bytes(self) -> None:
        """140 bytes (canonical) -> full dict with reason_name."""
        payload = self._make("NtQueryKey", -10, 50, 0)
        self.assertEqual(len(payload), 140)
        out = self.mod.parse_pe_trust_escalate_payload(payload)
        self.assertEqual(out["api_name"], "NtQueryKey")
        self.assertEqual(out["from_score"], -10)
        self.assertEqual(out["to_score"], 50)
        self.assertEqual(out["reason"], 0)
        self.assertEqual(out["reason_name"], "generic")

    def test_139_bytes_returns_raw_len(self) -> None:
        """139 bytes (one below boundary) -> {raw_len: 139}."""
        payload = b"\x00" * 139
        self.assertEqual(
            self.mod.parse_pe_trust_escalate_payload(payload),
            {"raw_len": 139},
        )

    def test_all_known_reasons(self) -> None:
        """Every named reason code decodes to its name (not 'unknown')."""
        for code, name in self.mod._REASON_NAMES.items():
            payload = self._make("api", 0, 0, code)
            out = self.mod.parse_pe_trust_escalate_payload(payload)
            self.assertEqual(out["reason_name"], name,
                             f"code={code} expected {name}")

    def test_unknown_reason_falls_back(self) -> None:
        """Unknown reason code N -> reason_name='unknown(N)' (S78 fix)."""
        payload = self._make("api", 0, 0, 9999)
        out = self.mod.parse_pe_trust_escalate_payload(payload)
        self.assertEqual(out["reason_name"], "unknown(9999)")

    def test_negative_scores_parsed_signed(self) -> None:
        """from_score/to_score parsed as int32 (S77 Agent 1 fix).

        Prior to the fix these were parsed as unsigned, so -50 became
        ~4.3e9. The fix uses 'i' format (signed). Check the boundary.
        """
        payload = self._make("sensitive", -1000, -999, 1)
        out = self.mod.parse_pe_trust_escalate_payload(payload)
        self.assertEqual(out["from_score"], -1000)
        self.assertEqual(out["to_score"], -999)
        # Confirm not misinterpreted as unsigned 32-bit
        self.assertLess(out["from_score"], 0)


class ParsePeDllLoadPayloadBoundaries(unittest.TestCase):
    """pe_evt_dll_load_t: 72 byte boundary."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_exactly_72_bytes(self) -> None:
        """72 bytes -> full decode."""
        payload = b"kernel32.dll".ljust(64, b"\x00") + struct.pack("<II", 20, 1)
        self.assertEqual(len(payload), 72)
        out = self.mod.parse_pe_dll_load_payload(payload)
        self.assertEqual(out["dll_name"], "kernel32.dll")
        self.assertEqual(out["resolved"], 20)
        self.assertEqual(out["unresolved"], 1)

    def test_71_bytes_returns_empty(self) -> None:
        """71 bytes -> {}."""
        self.assertEqual(self.mod.parse_pe_dll_load_payload(b"\x00" * 71), {})


class ParsePeExitPayloadBoundaries(unittest.TestCase):
    """pe_evt_exit_t: 12 byte boundary."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_exactly_12_bytes(self) -> None:
        """12 bytes (boundary) -> full decode."""
        payload = struct.pack("<III", 0, 42, 1234)
        out = self.mod.parse_pe_exit_payload(payload)
        self.assertEqual(out, {
            "exit_code": 0,
            "stubs_called": 42,
            "runtime_ms": 1234,
        })

    def test_11_bytes_returns_empty(self) -> None:
        """11 bytes -> {}."""
        self.assertEqual(self.mod.parse_pe_exit_payload(b"\x00" * 11), {})


class ParsePayloadDispatcher(unittest.TestCase):
    """Fallback / dispatch boundary in parse_payload()."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_unknown_source_type_returns_raw_bytes(self) -> None:
        """(source, type) with no parser -> returns raw bytes unchanged."""
        data = b"\x01\x02\x03"
        out = self.mod.parse_payload(
            source_layer=99, event_type=0x55, data=data,
        )
        self.assertEqual(out, data)

    def test_parser_returns_empty_falls_back_to_raw(self) -> None:
        """Parser returns {} (too-short payload) -> caller gets raw bytes back."""
        # pe_load with 10 bytes -> parser returns {}, parse_payload
        # then returns raw bytes per the `if result:` guard.
        out = self.mod.parse_payload(
            source_layer=int(self.mod.SourceLayer.RUNTIME),
            event_type=int(self.mod.PeEventType.LOAD),
            data=b"\xaa" * 10,
        )
        self.assertEqual(out, b"\xaa" * 10)


if __name__ == "__main__":
    unittest.main()
