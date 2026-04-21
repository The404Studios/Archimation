"""Common generators used by S79 fuzz suites.

Each generator is deterministic when given a seeded ``random.Random``
so failing cases can be reproduced from the seed printed on failure.

Design principle: these are LOW-LEVEL byte / struct generators. Each
fuzz test file composes them into module-specific workloads. Keep the
helpers free of project-module imports so the helpers themselves never
fail to load when a source module has a regression.

S79 Test Agent 1.
"""

from __future__ import annotations

import os
import random
import string
import struct
from typing import Any, Callable, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------
# Byte-buffer generators
# --------------------------------------------------------------------------

def random_bytes(rng: random.Random, n: int) -> bytes:
    """Return ``n`` uniformly-random bytes using the supplied RNG.

    Using rng.getrandbits(8) per byte is portable across CPython builds
    and gives us a deterministic byte stream for a given seed.
    """
    if n <= 0:
        return b""
    return bytes(rng.getrandbits(8) for _ in range(n))


def random_bytes_with_size(rng: random.Random, min_size: int = 0,
                           max_size: int = 2048) -> bytes:
    """Return a random byte buffer of random length in [min_size, max_size]."""
    n = rng.randint(min_size, max_size)
    return random_bytes(rng, n)


def random_byte_pattern(rng: random.Random, n: int) -> bytes:
    """Return one of several common pathological byte patterns of size ``n``.

    Includes: all-zero, all-0xff, alternating 0x00/0xff, repeating AA/55,
    0x7f pattern, purely random. Shapes most likely to break parsers.
    """
    if n <= 0:
        return b""
    choice = rng.randint(0, 6)
    if choice == 0:
        return b"\x00" * n
    if choice == 1:
        return b"\xff" * n
    if choice == 2:
        return (b"\x00\xff" * ((n + 1) // 2))[:n]
    if choice == 3:
        return b"\xaa" * n
    if choice == 4:
        return b"\x55" * n
    if choice == 5:
        return b"\x7f" * n
    return random_bytes(rng, n)


def random_cstr_bytes(rng: random.Random, field_size: int,
                      include_embedded_nulls: bool = True) -> bytes:
    """Return ``field_size`` bytes representing a C string field.

    If ``include_embedded_nulls`` and rng picks so, we embed a null byte
    somewhere in the middle so parsers relying on _decode_cstr truncate.
    """
    if field_size <= 0:
        return b""
    # Randomly pick: empty, short, filled, filled-with-mid-null
    mode = rng.randint(0, 4)
    if mode == 0:
        # Empty (just nulls)
        return b"\x00" * field_size
    if mode == 1:
        # Short string padded with nulls
        n = rng.randint(1, min(field_size, 16))
        s = bytes(rng.choices(string.ascii_letters.encode("ascii"), k=n))
        return s + b"\x00" * (field_size - n)
    if mode == 2:
        # Fully filled, NO null terminator (parser should still cope)
        return bytes(rng.getrandbits(8) for _ in range(field_size))
    if mode == 3 and include_embedded_nulls:
        # Non-null prefix, null byte in middle, garbage after
        cut = rng.randint(1, field_size - 1)
        prefix = bytes(rng.getrandbits(8) or 1 for _ in range(cut))
        # ensure no zero bytes in prefix
        prefix = bytes(b if b != 0 else 0x41 for b in prefix)
        return prefix + b"\x00" + random_bytes(rng, field_size - cut - 1)
    # mode 4: printable ASCII all the way, no null
    return bytes(rng.choices(string.printable.encode("ascii"), k=field_size))


def random_packed_struct_bytes(rng: random.Random, fmt: str) -> bytes:
    """Return bytes matching ``struct.calcsize(fmt)`` with random values."""
    size = struct.calcsize(fmt)
    return random_bytes(rng, size)


# --------------------------------------------------------------------------
# Dict / primitive generators
# --------------------------------------------------------------------------

def random_scalar(rng: random.Random):
    """Return a mixed-type scalar: int / float / str / bool / None.

    Includes weird-string edge cases (empty, whitespace, zero-width
    space, emoji, high-byte) to exercise text decoding paths.
    """
    choice = rng.randint(0, 5)
    if choice == 0:
        return rng.randint(-(1 << 31), (1 << 31) - 1)
    if choice == 1:
        return rng.choice([
            rng.uniform(-1e9, 1e9),
            rng.uniform(-1.0, 1.0),
            0.0,
            1e-300,
            1e300,
        ])
    if choice == 2:
        n = rng.randint(0, 32)
        return "".join(rng.choices(string.printable, k=n))
    if choice == 3:
        return rng.choice([True, False])
    if choice == 4:
        return None
    # choice 5 -- weird unicode and edge strings
    return rng.choice([
        "",
        " ",
        "literal-backslash-x00",
        "\u200b",
        "\U0001F600",
        "\u00ff",
    ])


def random_dict_with_keys(rng: random.Random, keys: List[str],
                          *, missing_rate: float = 0.0,
                          extra_rate: float = 0.0,
                          extra_keys: Optional[List[str]] = None) -> Dict[str, Any]:
    """Return a dict populated with random scalars for each key in ``keys``.

    * ``missing_rate`` -- drop each key with that probability.
    * ``extra_rate`` -- add each optional extra key with that probability.
    """
    out: Dict[str, Any] = {}
    for k in keys:
        if rng.random() < missing_rate:
            continue
        out[k] = random_scalar(rng)
    if extra_keys:
        for k in extra_keys:
            if rng.random() < extra_rate:
                out[k] = random_scalar(rng)
    return out


def random_nested_dict(rng: random.Random, depth: int = 3,
                       max_keys: int = 6) -> Dict[str, Any]:
    """Return a nested dict of the given depth with a mix of value types."""
    if depth <= 0:
        return {}
    out: Dict[str, Any] = {}
    n = rng.randint(0, max_keys)
    for _ in range(n):
        k = "".join(rng.choices(string.ascii_letters, k=rng.randint(1, 8)))
        v_choice = rng.randint(0, 4)
        if v_choice == 0:
            out[k] = random_scalar(rng)
        elif v_choice == 1:
            out[k] = [random_scalar(rng) for _ in range(rng.randint(0, 4))]
        elif v_choice == 2 and depth > 1:
            out[k] = random_nested_dict(rng, depth - 1, max_keys)
        elif v_choice == 3:
            out[k] = tuple(random_scalar(rng) for _ in range(rng.randint(0, 3)))
        else:
            out[k] = random_scalar(rng)
    return out


# --------------------------------------------------------------------------
# PE-specific byte-buffer generators (payload layouts from event_bus.py)
# --------------------------------------------------------------------------

# Packed layouts -- these match the MINIMUM sizes the event_bus parsers
# accept. Fuzzers then perturb around these points.
PE_LOAD_MIN_BYTES = 272       # 256 (exe_path) + 4 + 4 + 4 + 4
PE_DLL_LOAD_MIN_BYTES = 72     # 64 + 4 + 4
PE_UNIMPLEMENTED_MIN_BYTES = 192   # 64 + 128
PE_EXIT_MIN_BYTES = 12
PE_TRUST_DENY_MIN_BYTES = 137   # packed layout; 140 is padded layout
PE_TRUST_ESCALATE_MIN_BYTES = 140
MEMORY_MAP_MIN_BYTES = 300
MEMORY_PROTECT_MIN_BYTES = 60
MEMORY_PATTERN_MIN_BYTES = 296
MEMORY_ANOMALY_MIN_BYTES = 180
STUB_CALLED_MIN_BYTES = 192


def build_pe_load_payload(rng: random.Random) -> bytes:
    """Build a well-formed pe_evt_load_t payload."""
    exe_path = random_cstr_bytes(rng, 256)
    rest = struct.pack(
        "<IIiI",
        rng.randint(0, 1 << 30),
        rng.randint(0, 1 << 30),
        rng.randint(-(1 << 15), (1 << 15) - 1),
        rng.randint(0, 1 << 30),
    )
    return exe_path + rest


def build_trust_deny_packed(rng: random.Random) -> bytes:
    api = random_cstr_bytes(rng, 128)
    category = bytes([rng.randint(0, 255)])
    rest = struct.pack("<iI",
                       rng.randint(-(1 << 15), (1 << 15) - 1),
                       rng.randint(0, 1 << 20))
    return api + category + rest  # 137 bytes


def build_trust_escalate(rng: random.Random) -> bytes:
    api = random_cstr_bytes(rng, 128)
    rest = struct.pack(
        "<iiI",
        rng.randint(-2000, 2000),
        rng.randint(-2000, 2000),
        rng.randint(0, 255),
    )
    return api + rest  # 140 bytes


# --------------------------------------------------------------------------
# Logging / repro helpers
# --------------------------------------------------------------------------

def make_seed_logger(test_name: str) -> Callable[[int, Any], None]:
    """Return a helper that logs seed + input on invariant failure.

    Pattern used at call-sites::

        log_repro = make_seed_logger("test_foo")
        try:
            assert invariant(x)
        except AssertionError:
            log_repro(seed, payload_bytes)
            raise
    """
    def _log(seed: int, payload: Any) -> None:
        dump = repr(payload)
        if len(dump) > 256:
            dump = dump[:256] + "...(truncated)"
        import sys as _sys
        _sys.stderr.write(
            f"\n[fuzz-fail] {test_name}: seed={seed} input={dump}\n"
        )
    return _log


def maybe_systemrandom() -> random.Random:
    """Return a ``random.SystemRandom`` instance.

    Callers that want to explore rare paths (non-deterministic coverage
    hunting) build a SystemRandom cousin alongside the seeded suite.
    """
    return random.SystemRandom()
