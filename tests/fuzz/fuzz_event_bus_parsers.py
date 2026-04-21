"""Fuzz harness for ``ai-control/cortex/event_bus.py`` payload parsers.

S79 Test Agent 1 deliverable. Complements the existing
``test_event_bus_fuzz.py`` in this directory with a per-parser suite
gated on ``FUZZ_DEEP=1`` for the 100k iteration deep path.

Six parsers covered (per task brief):

    parse_pe_load_payload
    parse_pe_dll_load_payload
    parse_pe_unimplemented_payload
    parse_pe_exit_payload
    parse_pe_trust_deny_payload
    parse_pe_trust_escalate_payload

Invariants enforced:

  * No uncaught exception may escape.
  * Result is always a ``dict``.
  * When non-empty, string fields are ``str`` (never bytes / None).
  * For trust_escalate: ``reason_name`` is ALWAYS a str (contract) and
    ``reason`` (if present) fits uint32.
  * Exact-size buffers (137, 140) exercise the contract paths in
    parse_pe_trust_deny_payload and parse_pe_trust_escalate_payload.

Each iteration captures the originating seed so a failing input can be
reproduced by setting ``FUZZ_ROOT_SEED`` back to the logged value.

Env vars:
  * ``FUZZ_DEEP=1``          -> 100k iterations + SystemRandom cousin.
  * ``FUZZ_ITERATIONS=N``    -> override iteration count.
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

from _fuzz_helpers import (  # noqa: E402
    build_pe_load_payload,
    build_trust_deny_packed,
    build_trust_escalate,
    make_seed_logger,
    maybe_systemrandom,
    random_bytes,
    random_bytes_with_size,
    random_cstr_bytes,
)

FUZZ_DEEP = bool(os.environ.get("FUZZ_DEEP"))
FUZZ_ITERATIONS = int(os.environ.get(
    "FUZZ_ITERATIONS",
    "100000" if FUZZ_DEEP else "1000",
))
FUZZ_ROOT_SEED = int(os.environ.get("FUZZ_ROOT_SEED", "424242"))


def _load_event_bus():
    """Load event_bus.py by path so we don't pull the whole cortex package."""
    name = "_fuzz_event_bus"
    path = _REPO_ROOT / "ai-control" / "cortex" / "event_bus.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


EB = _load_event_bus()


class FuzzEventBusParsers(unittest.TestCase):
    """Blanket-hammer the six PE-runtime payload parsers."""

    def setUp(self) -> None:
        self.rng = random.Random(FUZZ_ROOT_SEED)
        self.syscounter = maybe_systemrandom() if FUZZ_DEEP else None
        self.log = make_seed_logger(self._testMethodName)

    # ---- generic harness --------------------------------------------------

    def _run_blanket(self, parser, *, min_len: int, max_len: int,
                     required_string_fields=(),
                     required_int_fields=()) -> None:
        """Drive ``parser`` with random payloads, assert invariants."""
        for i in range(FUZZ_ITERATIONS):
            seed = FUZZ_ROOT_SEED + i
            local = random.Random(seed)
            buf = random_bytes_with_size(local, min_len, max_len)
            try:
                out = parser(buf)
            except Exception as exc:
                self.log(seed, buf)
                raise AssertionError(
                    f"{parser.__name__} raised {type(exc).__name__}: {exc} "
                    f"on len={len(buf)} seed={seed}"
                ) from exc

            if not isinstance(out, dict):
                self.log(seed, buf)
                self.fail(f"{parser.__name__} returned {type(out).__name__}, not dict")

            if out:
                for field in required_string_fields:
                    if field in out and not isinstance(out[field], str):
                        self.log(seed, buf)
                        self.fail(
                            f"{parser.__name__}[{field}] is "
                            f"{type(out[field]).__name__}, not str"
                        )
                for field in required_int_fields:
                    if field in out and not isinstance(out[field], int):
                        self.log(seed, buf)
                        self.fail(
                            f"{parser.__name__}[{field}] is "
                            f"{type(out[field]).__name__}, not int"
                        )

        # Optional extra SystemRandom pass (opt-in, non-reproducible, short).
        if self.syscounter is not None:
            extra = min(1000, FUZZ_ITERATIONS // 10)
            for _ in range(extra):
                buf = bytes(self.syscounter.getrandbits(8)
                            for _ in range(self.syscounter.randint(min_len, max_len)))
                out = parser(buf)
                self.assertIsInstance(out, dict)

    # ---- per-parser cases -------------------------------------------------

    def test_parse_pe_load_payload(self):
        self._run_blanket(
            EB.parse_pe_load_payload,
            min_len=0, max_len=512,
            required_string_fields=("exe_path",),
            required_int_fields=("imports_resolved", "imports_unresolved",
                                 "trust_score", "token_budget"),
        )

    def test_parse_pe_dll_load_payload(self):
        self._run_blanket(
            EB.parse_pe_dll_load_payload,
            min_len=0, max_len=256,
            required_string_fields=("dll_name",),
            required_int_fields=("resolved", "unresolved"),
        )

    def test_parse_pe_unimplemented_payload(self):
        self._run_blanket(
            EB.parse_pe_unimplemented_payload,
            min_len=0, max_len=384,
            required_string_fields=("dll_name", "func_name"),
        )

    def test_parse_pe_exit_payload(self):
        self._run_blanket(
            EB.parse_pe_exit_payload,
            min_len=0, max_len=64,
            required_int_fields=("exit_code", "stubs_called", "runtime_ms"),
        )

    def test_parse_pe_trust_deny_payload(self):
        # Mostly exercise the 0..200 byte range to hit both packed (137)
        # and padded (140) layouts frequently.
        self._run_blanket(
            EB.parse_pe_trust_deny_payload,
            min_len=0, max_len=200,
            required_string_fields=("api_name",),
            required_int_fields=("category", "score", "tokens"),
        )

    def test_parse_pe_trust_escalate_payload(self):
        # reason_name is contractually always a string when the dict is
        # the "full" shape (len >= 140). Extra tighter invariants below.
        for i in range(FUZZ_ITERATIONS):
            seed = FUZZ_ROOT_SEED + i
            local = random.Random(seed)
            buf = random_bytes_with_size(local, 0, 200)
            try:
                out = EB.parse_pe_trust_escalate_payload(buf)
            except Exception as exc:
                self.log(seed, buf)
                raise AssertionError(
                    f"parse_pe_trust_escalate_payload raised {exc!r} "
                    f"on len={len(buf)} seed={seed}"
                ) from exc
            self.assertIsInstance(out, dict)
            if "reason" in out:
                self.assertIsInstance(out["reason"], int,
                                      msg=f"seed={seed}")
                self.assertGreaterEqual(out["reason"], 0)
                self.assertLess(out["reason"], 2**32)
                # reason_name ALWAYS a str when reason present.
                self.assertIn("reason_name", out, msg=f"seed={seed}")
                self.assertIsInstance(out["reason_name"], str,
                                      msg=f"seed={seed}")

    # ---- exact-size contract paths ---------------------------------------

    def test_trust_deny_exact_137(self):
        """Packed layout: 137 bytes. Must decode fully."""
        for i in range(200):
            local = random.Random(FUZZ_ROOT_SEED + i)
            buf = build_trust_deny_packed(local)
            self.assertEqual(len(buf), 137)
            out = EB.parse_pe_trust_deny_payload(buf)
            self.assertIsInstance(out, dict)
            self.assertIn("api_name", out)
            self.assertIn("category", out)
            self.assertIn("score", out)
            self.assertIn("tokens", out)
            self.assertIsInstance(out["api_name"], str)
            self.assertIsInstance(out["score"], int)

    def test_trust_deny_exact_140(self):
        """Padded layout: 140 bytes. Must decode via padded branch."""
        for i in range(200):
            local = random.Random(FUZZ_ROOT_SEED + i)
            buf = build_trust_deny_packed(local) + b"\x00\x00\x00"
            # Note: the packer puts score+tokens at off 129 for a 137 buf.
            # For the 140-byte path the parser reads at off 132, so the
            # decoded score/tokens won't match our original packer — we
            # only assert the shape is valid (no crash, contains fields).
            out = EB.parse_pe_trust_deny_payload(buf)
            self.assertIsInstance(out, dict)
            # When 140 exactly, full decode happens; 137 branch doesn't fire.
            # The dict should carry the three expected int fields.
            if "score" in out:
                self.assertIsInstance(out["score"], int)
                self.assertIsInstance(out["tokens"], int)
                self.assertIsInstance(out["category"], int)

    def test_trust_escalate_exact_140(self):
        """Canonical packed layout per pe_event.h _Static_assert."""
        for i in range(200):
            local = random.Random(FUZZ_ROOT_SEED + i)
            buf = build_trust_escalate(local)
            self.assertEqual(len(buf), 140)
            out = EB.parse_pe_trust_escalate_payload(buf)
            self.assertIn("reason", out)
            self.assertIn("reason_name", out)
            self.assertIsInstance(out["reason_name"], str)
            self.assertIsInstance(out["from_score"], int)
            self.assertIsInstance(out["to_score"], int)

    def test_trust_escalate_reason_code_coverage(self):
        """Every known reason (0..6) + a handful of unknown codes get a name."""
        # Build a valid 140-byte payload, overwrite the reason field,
        # confirm reason_name is always a string.
        local = random.Random(FUZZ_ROOT_SEED)
        api_prefix = b"fuzz_api\x00" + b"\x00" * (128 - 9)
        for reason in list(range(0, 7)) + [7, 42, 1 << 20, 2**32 - 1]:
            buf = api_prefix + struct.pack("<iiI", 100, 200, reason)
            self.assertEqual(len(buf), 140)
            out = EB.parse_pe_trust_escalate_payload(buf)
            self.assertEqual(out["reason"], reason)
            self.assertIsInstance(out["reason_name"], str)
            self.assertGreater(len(out["reason_name"]), 0)


if __name__ == "__main__":
    unittest.main()
