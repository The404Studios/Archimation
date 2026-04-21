"""Fuzz tests for ``ai-control/cortex/event_bus.py`` payload parsers.

The event bus has 11 payload parser functions (parse_pe_load_payload,
parse_pe_dll_load_payload, parse_pe_unimplemented_payload,
parse_pe_exit_payload, parse_pe_trust_deny_payload,
parse_pe_trust_escalate_payload, parse_memory_map_payload,
parse_memory_protect_payload, parse_memory_pattern_payload,
parse_memory_anomaly_payload, parse_stub_called_payload) plus the
top-level ``parse_payload`` dispatcher. Each parser's contract:

  * Accept any bytes input (including truncated / oversized / random).
  * Return a dict of decoded fields on success.
  * Return ``{}`` (or a minimal ``{"raw_len": N}``) on short/bad input.
  * NEVER raise.

This module hammers each parser with N=FUZZ_ITERATIONS random inputs at
a range of sizes and shapes. Invariants checked:

  1. ``isinstance(result, dict)``.
  2. String-typed fields (exe_path, dll_name, api_name, ...) are always
     ``str`` (never bytes or None when the dict is non-empty).
  3. Numeric-typed fields are always Python ``int``.
  4. The result is JSON-serializable (no bytes leaking through).
  5. No exception propagates to the caller.

S79 Test Agent 1 deliverable.
"""

from __future__ import annotations

import importlib.util
import json
import os
import random
import struct
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FUZZ_DIR = Path(__file__).resolve().parent
_MODULE_PATH = _REPO_ROOT / "ai-control" / "cortex" / "event_bus.py"

if str(_FUZZ_DIR) not in sys.path:
    sys.path.insert(0, str(_FUZZ_DIR))

from _fuzz_helpers import (  # noqa: E402
    PE_DLL_LOAD_MIN_BYTES,
    PE_EXIT_MIN_BYTES,
    PE_LOAD_MIN_BYTES,
    PE_TRUST_DENY_MIN_BYTES,
    PE_TRUST_ESCALATE_MIN_BYTES,
    PE_UNIMPLEMENTED_MIN_BYTES,
    MEMORY_ANOMALY_MIN_BYTES,
    MEMORY_MAP_MIN_BYTES,
    MEMORY_PATTERN_MIN_BYTES,
    MEMORY_PROTECT_MIN_BYTES,
    STUB_CALLED_MIN_BYTES,
    build_pe_load_payload,
    build_trust_deny_packed,
    build_trust_escalate,
    make_seed_logger,
    maybe_systemrandom,
    random_byte_pattern,
    random_bytes,
    random_bytes_with_size,
    random_cstr_bytes,
)

FUZZ_ENABLED = bool(os.environ.get("FUZZ_TESTS"))
FUZZ_ITERATIONS = int(os.environ.get("FUZZ_ITERATIONS", "1000"))
FUZZ_ROOT_SEED = 42


def _load_module():
    """Load event_bus.py by path, keeping it isolated from the cortex pkg."""
    name = "cortex_event_bus_under_fuzz"
    spec = importlib.util.spec_from_file_location(name, _MODULE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(FUZZ_ENABLED, "fuzz tests disabled by default")
class EventBusPayloadParserFuzzTest(unittest.TestCase):
    """Fuzz every single payload parser over 1000 random inputs."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_module()

    # ----------------------------------------------------------------
    # Invariant helpers
    # ----------------------------------------------------------------

    def _assert_dict_json_safe(self, result, seed: int, parser_name: str,
                               payload: bytes) -> None:
        """Every parser MUST return a dict that is JSON-serializable."""
        log = make_seed_logger(f"{parser_name}:json_safe")
        try:
            self.assertIsInstance(result, dict,
                                  f"{parser_name} did not return dict")
            # JSON round-trip catches bytes / non-stringable values.
            json.dumps(result)
        except (AssertionError, TypeError, ValueError):
            log(seed, payload[:128])
            raise

    def _assert_types(self, result: dict, str_fields: list, int_fields: list,
                      seed: int, parser_name: str, payload: bytes) -> None:
        log = make_seed_logger(f"{parser_name}:types")
        try:
            for f in str_fields:
                if f in result:
                    self.assertIsInstance(
                        result[f], str,
                        f"{parser_name}: field {f!r} not str",
                    )
            for f in int_fields:
                if f in result:
                    self.assertIsInstance(
                        result[f], int,
                        f"{parser_name}: field {f!r} not int",
                    )
        except AssertionError:
            log(seed, payload[:128])
            raise

    # ----------------------------------------------------------------
    # parse_pe_load_payload (expected size >= 272)
    # ----------------------------------------------------------------

    def test_fuzz_pe_load_random_sizes(self) -> None:
        """Parser accepts any bytes length; returns {} if too short."""
        rng = random.Random(FUZZ_ROOT_SEED)
        for i in range(FUZZ_ITERATIONS):
            buf = random_bytes_with_size(rng, 0, 2048)
            try:
                result = self.mod.parse_pe_load_payload(buf)
            except Exception as e:
                make_seed_logger("pe_load:raise")(FUZZ_ROOT_SEED + i, buf)
                self.fail(f"parse_pe_load_payload raised: {e!r}")
            self._assert_dict_json_safe(result, FUZZ_ROOT_SEED + i,
                                        "pe_load", buf)
            self._assert_types(
                result, ["exe_path"],
                ["imports_resolved", "imports_unresolved",
                 "trust_score", "token_budget"],
                FUZZ_ROOT_SEED + i, "pe_load", buf,
            )
            if len(buf) < PE_LOAD_MIN_BYTES:
                self.assertEqual(result, {},
                                 "short buf must return {}")

    def test_fuzz_pe_load_wellformed_payloads(self) -> None:
        """Well-formed payloads: all fields must populate."""
        rng = random.Random(FUZZ_ROOT_SEED + 1)
        for i in range(FUZZ_ITERATIONS):
            buf = build_pe_load_payload(rng)
            result = self.mod.parse_pe_load_payload(buf)
            self.assertEqual(set(result.keys()),
                             {"exe_path", "imports_resolved",
                              "imports_unresolved", "trust_score",
                              "token_budget"})

    def test_fuzz_pe_load_pattern_payloads(self) -> None:
        """All-zero / all-FF / 0xAA / 0x55 buffers of exact size."""
        rng = random.Random(FUZZ_ROOT_SEED + 2)
        for i in range(200):
            buf = random_byte_pattern(rng, PE_LOAD_MIN_BYTES)
            result = self.mod.parse_pe_load_payload(buf)
            self.assertIsInstance(result, dict)
            # Must still be JSON-safe even when exe_path is junk bytes
            json.dumps(result)

    # ----------------------------------------------------------------
    # parse_pe_dll_load_payload (>= 72 bytes)
    # ----------------------------------------------------------------

    def test_fuzz_pe_dll_load(self) -> None:
        rng = random.Random(FUZZ_ROOT_SEED + 3)
        for i in range(FUZZ_ITERATIONS):
            buf = random_bytes_with_size(rng, 0, 256)
            try:
                result = self.mod.parse_pe_dll_load_payload(buf)
            except Exception as e:
                make_seed_logger("dll_load:raise")(FUZZ_ROOT_SEED + i, buf)
                self.fail(f"parse_pe_dll_load_payload raised: {e!r}")
            self._assert_dict_json_safe(result, FUZZ_ROOT_SEED + i,
                                        "dll_load", buf)
            self._assert_types(result, ["dll_name"],
                               ["resolved", "unresolved"],
                               FUZZ_ROOT_SEED + i, "dll_load", buf)
            if len(buf) < PE_DLL_LOAD_MIN_BYTES:
                self.assertEqual(result, {})

    # ----------------------------------------------------------------
    # parse_pe_unimplemented_payload (>= 192 bytes)
    # ----------------------------------------------------------------

    def test_fuzz_pe_unimplemented(self) -> None:
        rng = random.Random(FUZZ_ROOT_SEED + 4)
        for i in range(FUZZ_ITERATIONS):
            buf = random_bytes_with_size(rng, 0, 512)
            try:
                result = self.mod.parse_pe_unimplemented_payload(buf)
            except Exception as e:
                make_seed_logger("unimpl:raise")(FUZZ_ROOT_SEED + i, buf)
                self.fail(f"parse_pe_unimplemented_payload raised: {e!r}")
            self._assert_dict_json_safe(result, FUZZ_ROOT_SEED + i,
                                        "unimpl", buf)
            self._assert_types(result, ["dll_name", "func_name"], [],
                               FUZZ_ROOT_SEED + i, "unimpl", buf)
            if len(buf) < PE_UNIMPLEMENTED_MIN_BYTES:
                self.assertEqual(result, {})

    # ----------------------------------------------------------------
    # parse_pe_exit_payload (>= 12 bytes)
    # ----------------------------------------------------------------

    def test_fuzz_pe_exit(self) -> None:
        rng = random.Random(FUZZ_ROOT_SEED + 5)
        for i in range(FUZZ_ITERATIONS):
            buf = random_bytes_with_size(rng, 0, 64)
            try:
                result = self.mod.parse_pe_exit_payload(buf)
            except Exception as e:
                make_seed_logger("exit:raise")(FUZZ_ROOT_SEED + i, buf)
                self.fail(f"parse_pe_exit_payload raised: {e!r}")
            self._assert_dict_json_safe(result, FUZZ_ROOT_SEED + i,
                                        "exit", buf)
            self._assert_types(
                result, [],
                ["exit_code", "stubs_called", "runtime_ms"],
                FUZZ_ROOT_SEED + i, "exit", buf,
            )
            if len(buf) < PE_EXIT_MIN_BYTES:
                self.assertEqual(result, {})

    # ----------------------------------------------------------------
    # parse_pe_trust_deny_payload (packed 137, padded 140)
    # ----------------------------------------------------------------

    def test_fuzz_pe_trust_deny_packed_exact_137(self) -> None:
        """Packed layout: exactly 137 bytes. All fields populate."""
        rng = random.Random(FUZZ_ROOT_SEED + 6)
        for i in range(FUZZ_ITERATIONS):
            buf = build_trust_deny_packed(rng)
            self.assertEqual(len(buf), 137)
            result = self.mod.parse_pe_trust_deny_payload(buf)
            self.assertEqual(
                set(result.keys()),
                {"api_name", "category", "score", "tokens"},
            )
            self.assertIsInstance(result["api_name"], str)
            self.assertIsInstance(result["score"], int)
            self.assertIsInstance(result["tokens"], int)

    def test_fuzz_pe_trust_deny_padded_exact_140(self) -> None:
        """Padded layout: exactly 140 bytes (3 bytes padding)."""
        rng = random.Random(FUZZ_ROOT_SEED + 7)
        for i in range(500):
            api = random_cstr_bytes(rng, 128)
            cat = bytes([rng.randint(0, 255)])
            pad = b"\x00\x00\x00"
            tail = struct.pack("<iI",
                               rng.randint(-2000, 2000),
                               rng.randint(0, 1 << 24))
            buf = api + cat + pad + tail
            self.assertEqual(len(buf), 140)
            result = self.mod.parse_pe_trust_deny_payload(buf)
            self.assertIn("api_name", result)
            self.assertIn("score", result)

    def test_fuzz_pe_trust_deny_boundary_sizes(self) -> None:
        """Sizes 136, 137, 138, 139, 140, 141: only specific sizes
        produce fully-populated dicts; others fall back to {} or raw_len."""
        rng = random.Random(FUZZ_ROOT_SEED + 8)
        for size in (0, 1, 100, 128, 136, 137, 138, 139, 140, 141, 200):
            for _ in range(100):
                buf = random_bytes(rng, size)
                try:
                    result = self.mod.parse_pe_trust_deny_payload(buf)
                except Exception as e:
                    make_seed_logger("deny:raise")(FUZZ_ROOT_SEED, buf)
                    self.fail(f"parse_pe_trust_deny_payload raised: {e!r}")
                self.assertIsInstance(result, dict)
                json.dumps(result)
                if size < 137:
                    self.assertEqual(result, {})

    def test_fuzz_pe_trust_deny_random(self) -> None:
        rng = random.Random(FUZZ_ROOT_SEED + 9)
        for i in range(FUZZ_ITERATIONS):
            buf = random_bytes_with_size(rng, 0, 256)
            try:
                result = self.mod.parse_pe_trust_deny_payload(buf)
            except Exception as e:
                make_seed_logger("deny_rand:raise")(FUZZ_ROOT_SEED + i, buf)
                self.fail(f"parse_pe_trust_deny_payload raised: {e!r}")
            self._assert_dict_json_safe(result, FUZZ_ROOT_SEED + i,
                                        "deny", buf)

    # ----------------------------------------------------------------
    # parse_pe_trust_escalate_payload (>= 140 bytes, signed scores)
    # ----------------------------------------------------------------

    def test_fuzz_pe_trust_escalate_wellformed(self) -> None:
        """Well-formed payload: reason_name always populated."""
        rng = random.Random(FUZZ_ROOT_SEED + 10)
        for i in range(FUZZ_ITERATIONS):
            buf = build_trust_escalate(rng)
            result = self.mod.parse_pe_trust_escalate_payload(buf)
            self.assertIn("api_name", result)
            self.assertIn("from_score", result)
            self.assertIn("to_score", result)
            self.assertIn("reason", result)
            self.assertIn("reason_name", result)
            # reason_name MUST be str
            self.assertIsInstance(result["reason_name"], str)
            # Signed-int contract: from_score can be negative
            self.assertIsInstance(result["from_score"], int)
            self.assertIsInstance(result["to_score"], int)
            # Known codes or unknown(N)
            rn = result["reason_name"]
            if rn.startswith("unknown("):
                self.assertTrue(rn.endswith(")"))
            else:
                self.assertIn(rn, {
                    "generic", "quorum_discrepant", "quorum_divergent",
                    "ape_exhaustion", "privilege_adjust",
                    "driver_load", "anti_tamper",
                })

    def test_fuzz_pe_trust_escalate_signed_negative(self) -> None:
        """Regression-style: S77 Agent 1 fixed from_score from unsigned
        to signed. With our random range including negatives, verify
        the parser actually returns a negative int (not a huge positive)."""
        rng = random.Random(FUZZ_ROOT_SEED + 11)
        saw_negative = False
        for i in range(2000):
            api = random_cstr_bytes(rng, 128)
            # Force a negative from_score
            from_score = rng.randint(-1000, -1)
            to_score = rng.randint(-1000, 1000)
            reason = rng.randint(0, 10)
            buf = api + struct.pack("<iiI", from_score, to_score, reason)
            result = self.mod.parse_pe_trust_escalate_payload(buf)
            self.assertEqual(result["from_score"], from_score)
            if result["from_score"] < 0:
                saw_negative = True
        self.assertTrue(saw_negative,
                        "expected at least one negative from_score")

    def test_fuzz_pe_trust_escalate_random(self) -> None:
        rng = random.Random(FUZZ_ROOT_SEED + 12)
        for i in range(FUZZ_ITERATIONS):
            buf = random_bytes_with_size(rng, 0, 512)
            try:
                result = self.mod.parse_pe_trust_escalate_payload(buf)
            except Exception as e:
                make_seed_logger("esc:raise")(FUZZ_ROOT_SEED + i, buf)
                self.fail(f"parse_pe_trust_escalate_payload raised: {e!r}")
            self._assert_dict_json_safe(result, FUZZ_ROOT_SEED + i,
                                        "esc", buf)

    # ----------------------------------------------------------------
    # parse_memory_* payloads
    # ----------------------------------------------------------------

    def test_fuzz_memory_map(self) -> None:
        rng = random.Random(FUZZ_ROOT_SEED + 13)
        for i in range(FUZZ_ITERATIONS):
            buf = random_bytes_with_size(rng, 0, 512)
            try:
                result = self.mod.parse_memory_map_payload(buf)
            except Exception as e:
                make_seed_logger("mm_map:raise")(FUZZ_ROOT_SEED + i, buf)
                self.fail(f"parse_memory_map_payload raised: {e!r}")
            self._assert_dict_json_safe(result, FUZZ_ROOT_SEED + i,
                                        "mm_map", buf)
            self._assert_types(result, ["source_path", "tag"],
                               ["va", "size", "prot_flags"],
                               FUZZ_ROOT_SEED + i, "mm_map", buf)
            if len(buf) < MEMORY_MAP_MIN_BYTES:
                self.assertEqual(result, {})

    def test_fuzz_memory_protect(self) -> None:
        rng = random.Random(FUZZ_ROOT_SEED + 14)
        for i in range(FUZZ_ITERATIONS):
            buf = random_bytes_with_size(rng, 0, 128)
            try:
                result = self.mod.parse_memory_protect_payload(buf)
            except Exception as e:
                make_seed_logger("mm_prot:raise")(FUZZ_ROOT_SEED + i, buf)
                self.fail(f"parse_memory_protect_payload raised: {e!r}")
            self._assert_dict_json_safe(result, FUZZ_ROOT_SEED + i,
                                        "mm_prot", buf)
            self._assert_types(result, ["old_prot", "new_prot", "tag"],
                               ["va", "size"],
                               FUZZ_ROOT_SEED + i, "mm_prot", buf)
            if len(buf) < MEMORY_PROTECT_MIN_BYTES:
                self.assertEqual(result, {})

    def test_fuzz_memory_pattern(self) -> None:
        rng = random.Random(FUZZ_ROOT_SEED + 15)
        for i in range(FUZZ_ITERATIONS):
            buf = random_bytes_with_size(rng, 0, 512)
            try:
                result = self.mod.parse_memory_pattern_payload(buf)
            except Exception as e:
                make_seed_logger("mm_pat:raise")(FUZZ_ROOT_SEED + i, buf)
                self.fail(f"parse_memory_pattern_payload raised: {e!r}")
            self._assert_dict_json_safe(result, FUZZ_ROOT_SEED + i,
                                        "mm_pat", buf)
            self._assert_types(result,
                               ["pattern_id", "region", "category",
                                "description"], ["va"],
                               FUZZ_ROOT_SEED + i, "mm_pat", buf)
            if len(buf) < MEMORY_PATTERN_MIN_BYTES:
                self.assertEqual(result, {})

    def test_fuzz_memory_anomaly(self) -> None:
        rng = random.Random(FUZZ_ROOT_SEED + 16)
        for i in range(FUZZ_ITERATIONS):
            buf = random_bytes_with_size(rng, 0, 512)
            try:
                result = self.mod.parse_memory_anomaly_payload(buf)
            except Exception as e:
                make_seed_logger("mm_an:raise")(FUZZ_ROOT_SEED + i, buf)
                self.fail(f"parse_memory_anomaly_payload raised: {e!r}")
            self._assert_dict_json_safe(result, FUZZ_ROOT_SEED + i,
                                        "mm_an", buf)
            self._assert_types(result,
                               ["tag", "new_prot", "description"],
                               ["va", "size"],
                               FUZZ_ROOT_SEED + i, "mm_an", buf)
            if len(buf) < MEMORY_ANOMALY_MIN_BYTES:
                self.assertEqual(result, {})

    def test_fuzz_stub_called(self) -> None:
        rng = random.Random(FUZZ_ROOT_SEED + 17)
        for i in range(FUZZ_ITERATIONS):
            buf = random_bytes_with_size(rng, 0, 512)
            try:
                result = self.mod.parse_stub_called_payload(buf)
            except Exception as e:
                make_seed_logger("stub:raise")(FUZZ_ROOT_SEED + i, buf)
                self.fail(f"parse_stub_called_payload raised: {e!r}")
            self._assert_dict_json_safe(result, FUZZ_ROOT_SEED + i,
                                        "stub", buf)
            self._assert_types(result, ["dll", "function"], [],
                               FUZZ_ROOT_SEED + i, "stub", buf)
            if len(buf) < STUB_CALLED_MIN_BYTES:
                self.assertEqual(result, {})


@unittest.skipUnless(FUZZ_ENABLED, "fuzz tests disabled by default")
class EventBusPatternInputsTest(unittest.TestCase):
    """Cross-parser: every parser handles every pattern input gracefully."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_module()

    def _all_parsers(self):
        m = self.mod
        return [
            ("pe_load", m.parse_pe_load_payload),
            ("dll_load", m.parse_pe_dll_load_payload),
            ("unimpl", m.parse_pe_unimplemented_payload),
            ("exit", m.parse_pe_exit_payload),
            ("deny", m.parse_pe_trust_deny_payload),
            ("escalate", m.parse_pe_trust_escalate_payload),
            ("mm_map", m.parse_memory_map_payload),
            ("mm_prot", m.parse_memory_protect_payload),
            ("mm_pat", m.parse_memory_pattern_payload),
            ("mm_an", m.parse_memory_anomaly_payload),
            ("stub", m.parse_stub_called_payload),
        ]

    def test_all_zero_buffers(self) -> None:
        """All-zero at varied sizes: no parser raises."""
        for size in (0, 1, 40, 64, 128, 272, 500, 1024):
            buf = b"\x00" * size
            for name, parser in self._all_parsers():
                try:
                    result = parser(buf)
                    self.assertIsInstance(
                        result, dict,
                        f"{name}(all-zero, size={size}) non-dict")
                except Exception as e:
                    self.fail(f"{name}(all-zero, size={size}) raised: {e!r}")

    def test_all_ff_buffers(self) -> None:
        """All-0xFF at varied sizes: no parser raises."""
        for size in (0, 40, 137, 140, 272, 300, 1024):
            buf = b"\xff" * size
            for name, parser in self._all_parsers():
                try:
                    result = parser(buf)
                    self.assertIsInstance(
                        result, dict,
                        f"{name}(all-FF, size={size}) non-dict")
                except Exception as e:
                    self.fail(f"{name}(all-FF, size={size}) raised: {e!r}")

    def test_truncated_by_one_byte(self) -> None:
        """One byte short of each parser's minimum accepted size."""
        rng = random.Random(FUZZ_ROOT_SEED + 99)
        sizes = [
            (272, "pe_load"), (72, "dll_load"), (192, "unimpl"),
            (12, "exit"), (137, "deny"), (140, "escalate"),
            (300, "mm_map"), (60, "mm_prot"), (296, "mm_pat"),
            (180, "mm_an"), (192, "stub"),
        ]
        for min_size, _label in sizes:
            buf = random_bytes(rng, min_size - 1)
            for name, parser in self._all_parsers():
                try:
                    result = parser(buf)
                    self.assertIsInstance(result, dict)
                except Exception as e:
                    self.fail(
                        f"{name}(trunc-1, size={min_size-1}) raised: {e!r}")

    def test_oversized_10x_buffers(self) -> None:
        """10x oversized buffers must not cause parser to explode."""
        rng = random.Random(FUZZ_ROOT_SEED + 100)
        for _ in range(100):
            buf = random_bytes(rng, 4096)
            for name, parser in self._all_parsers():
                try:
                    result = parser(buf)
                    self.assertIsInstance(result, dict)
                except Exception as e:
                    self.fail(f"{name}(oversized) raised: {e!r}")

    def test_parse_payload_dispatch_never_raises(self) -> None:
        """Top-level parse_payload with random (src, type) pairs never raises."""
        rng = random.Random(FUZZ_ROOT_SEED + 101)
        for _ in range(500):
            src = rng.randint(0, 255)
            etype = rng.randint(0, 255)
            buf = random_bytes(rng, rng.randint(0, 2048))
            try:
                result = self.mod.parse_payload(src, etype, buf)
            except Exception as e:
                self.fail(
                    f"parse_payload(src={src}, et={etype}, "
                    f"len={len(buf)}) raised: {e!r}")
            # result is either dict OR raw bytes (for unmapped (src,et))
            self.assertTrue(
                isinstance(result, (dict, bytes)),
                f"parse_payload returned {type(result).__name__}")


@unittest.skipUnless(FUZZ_ENABLED, "fuzz tests disabled by default")
class EventBusSystemRandomCousinTest(unittest.TestCase):
    """One SystemRandom pass per parser to cover paths the seed misses."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_module()

    def test_sysrandom_200_iters_all_parsers(self) -> None:
        rng = maybe_systemrandom()
        m = self.mod
        parsers = [
            m.parse_pe_load_payload, m.parse_pe_dll_load_payload,
            m.parse_pe_unimplemented_payload, m.parse_pe_exit_payload,
            m.parse_pe_trust_deny_payload,
            m.parse_pe_trust_escalate_payload,
            m.parse_memory_map_payload, m.parse_memory_protect_payload,
            m.parse_memory_pattern_payload,
            m.parse_memory_anomaly_payload, m.parse_stub_called_payload,
        ]
        for _ in range(200):
            size = rng.randint(0, 2048)
            buf = bytes(rng.getrandbits(8) for _ in range(size))
            for p in parsers:
                try:
                    result = p(buf)
                    self.assertIsInstance(result, dict)
                except Exception as e:
                    self.fail(f"{p.__name__}(sysrand) raised: {e!r}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
