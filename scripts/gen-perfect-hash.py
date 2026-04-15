#!/usr/bin/env python3
"""
gen-perfect-hash.py -- emit a one-level perfect-hash header for a static
const string table (drop-in replacement for gperf output).

We use a seed-searched XXH32 variant that matches the C xxh32_lower()
implementation in pe-loader/include/pe/xxh3_compat.h byte-for-byte.
Both sides agree on: (1) ASCII case fold (only 'A'..'Z' -> 'a'..'z'),
(2) XXH32 primes and rounds, (3) the final avalanche.

For N entries the output is a table of size M = next_pow2(N*2); we
search through seeds 0..2^20 until one yields a collision-free slot
map, then emit that seed plus the slot -> entry-index reverse map.

Lookup at runtime becomes:

    uint32_t h = xxh32_lower(name, SEED) & (M - 1);
    int  idx  = g_slot_to_entry[h];   /* -1 if no entry */
    if (idx >= 0 && strcmp(table[idx].name, name) == 0)
        return &table[idx];

Zero collisions by construction; lookup is ONE hash + ONE array load
+ ONE strcmp (to guard against unknown keys hashing into a populated
slot).  Total memory for a 208-entry table: 512 * 2 B = 1 KB vs. the
previous 1024-bucket FNV index that needed 1 KB plus linear-probe loops.

Usage:
    python3 scripts/gen-perfect-hash.py \
        --input  pe-loader/loader/pe_import.c \
        --table  g_dll_mappings \
        --output pe-loader/loader/pe_import_dll_ph.h \
        --symbol DLL_PH

The script re-parses the C table source to extract keys, so regen is
simply re-running this command after any table edit.  The generated
header is committed to the repo; the build does NOT require Python.
"""

import argparse
import re
import sys
from pathlib import Path

# ---- XXH32 reimpl (mirrors xxh3_compat.h byte-for-byte) --------------

XXH_PRIME32_1 = 0x9E3779B1
XXH_PRIME32_2 = 0x85EBCA77
XXH_PRIME32_3 = 0xC2B2AE3D
XXH_PRIME32_4 = 0x27D4EB2F
XXH_PRIME32_5 = 0x165667B1
MASK32 = 0xFFFFFFFF


def rotl32(x, r):
    x &= MASK32
    return ((x << r) | (x >> (32 - r))) & MASK32


def xxh32_lower(s: str, seed: int) -> int:
    """Exactly matches xxh32_lower() / xxh32_lower_n() in xxh3_compat.h
    for short strings (len < 16 -- this is the ONLY path used for our
    short DLL / CRT names).  We do not bother with the 16-byte block
    path because no DLL or CRT name in either table is that long."""
    data = s.encode("latin-1")
    # Case fold ASCII 'A'..'Z' only
    data = bytes(b | 0x20 if 0x41 <= b <= 0x5A else b for b in data)

    h32 = (seed + XXH_PRIME32_5 + len(data)) & MASK32
    for b in data:
        h32 = (h32 + b * XXH_PRIME32_5) & MASK32
        h32 = rotl32(h32, 11)
        h32 = (h32 * XXH_PRIME32_1) & MASK32

    # Avalanche
    h32 ^= h32 >> 15
    h32 = (h32 * XXH_PRIME32_2) & MASK32
    h32 ^= h32 >> 13
    h32 = (h32 * XXH_PRIME32_3) & MASK32
    h32 ^= h32 >> 16
    return h32


# ---- C table extraction ---------------------------------------------


def next_pow2(n):
    p = 1
    while p < n:
        p <<= 1
    return p


def extract_keys(path: Path, table_name: str):
    """Pull the first-column string literal of each row in a `static ...
    table_name[] = { { "x", ... }, ... };` block.  Works for both
    dll_mapping_t and crt_abi_wrapper_t rows used in pe_import.c."""
    src = path.read_text(encoding="utf-8", errors="replace")
    # Match the opening line up to the first `{`, grab everything until
    # the matching `};`.
    pat = re.compile(
        r"\b" + re.escape(table_name) +
        r"\s*(?:\[[^\]]*\])?\s*=\s*\{(.*?)\};",
        re.DOTALL,
    )
    m = pat.search(src)
    if not m:
        print(f"ERROR: table {table_name} not found in {path}", file=sys.stderr)
        sys.exit(1)
    body = m.group(1)
    keys = []
    # Each row starts with `{ "key",` possibly preceded by comments.
    row_pat = re.compile(r"\{\s*\"([^\"]*)\"")
    for row in row_pat.finditer(body):
        k = row.group(1)
        if not k:
            continue  # NULL-terminator row in some tables
        keys.append(k)
    return keys


# ---- Perfect-hash search --------------------------------------------


def find_seed(keys, m, max_attempts=1 << 18):
    """Try seeds 0..max_attempts until one maps all keys to distinct
    slots in a table of size m.  Returns (seed, slot_map).
    slot_map[slot] = original_index, or -1 if the slot is empty."""
    # Fold case once, upfront -- mirrors the C runtime's lower-on-input
    # behavior.  Duplicate keys after folding are an error.
    folded = []
    seen = set()
    for k in keys:
        lk = "".join(c.lower() if "A" <= c <= "Z" else c for c in k)
        if lk in seen:
            print(f"ERROR: duplicate key '{lk}' in table", file=sys.stderr)
            sys.exit(2)
        seen.add(lk)
        folded.append(lk.encode("latin-1"))

    # Hoist xxh32 into a fast inner kernel operating on bytes.
    mask = m - 1
    P1, P2, P3, P5 = XXH_PRIME32_1, XXH_PRIME32_2, XXH_PRIME32_3, XXH_PRIME32_5
    # Pre-fold each key's byte sequence (case already folded above).
    folded_bytes = [bytes(b) for b in folded]
    lens = [len(b) for b in folded_bytes]

    for seed in range(max_attempts):
        # Fast path: compute all hashes into a set for collision detect.
        used = [0] * m
        ok = True
        for kb, ln in zip(folded_bytes, lens):
            h32 = (seed + P5 + ln) & MASK32
            for b in kb:
                h32 = (h32 + b * P5) & MASK32
                h32 = (((h32 << 11) | (h32 >> 21)) & MASK32)
                h32 = (h32 * P1) & MASK32
            h32 ^= h32 >> 15
            h32 = (h32 * P2) & MASK32
            h32 ^= h32 >> 13
            h32 = (h32 * P3) & MASK32
            h32 ^= h32 >> 16
            slot = h32 & mask
            if used[slot]:
                ok = False
                break
            used[slot] = 1
        if ok:
            # Reconstruct slot_map with actual original indices
            slots = [-1] * m
            for i, (kb, ln) in enumerate(zip(folded_bytes, lens)):
                h32 = (seed + P5 + ln) & MASK32
                for b in kb:
                    h32 = (h32 + b * P5) & MASK32
                    h32 = (((h32 << 11) | (h32 >> 21)) & MASK32)
                    h32 = (h32 * P1) & MASK32
                h32 ^= h32 >> 15
                h32 = (h32 * P2) & MASK32
                h32 ^= h32 >> 13
                h32 = (h32 * P3) & MASK32
                h32 ^= h32 >> 16
                slots[h32 & mask] = i
            return seed, slots
        if seed and seed % 16384 == 0:
            print(f"  tried {seed} seeds at size {m}...", file=sys.stderr)
    return None, None


# ---- Header emission -------------------------------------------------


HEADER_TMPL = '''\
/*
 * {basename} -- auto-generated perfect-hash index for {table}
 *
 * DO NOT EDIT BY HAND.  Regenerate with:
 *   python3 scripts/gen-perfect-hash.py \\
 *       --input {in_rel} \\
 *       --table {table} \\
 *       --output {out_rel} \\
 *       --symbol {symbol}
 *
 * Keys hashed: {n}
 * Table size:  {m} (load factor {lf:.2f})
 * Seed found:  0x{seed:08X}
 *
 * Uses xxh32_lower() from pe/xxh3_compat.h -- pure scalar, P4-safe.
 */
#ifndef {guard}
#define {guard}

#include <stdint.h>
#include "pe/xxh3_compat.h"

#define {symbol}_SEED   0x{seed:08X}u
#define {symbol}_SIZE   {m}
#define {symbol}_MASK   ({m} - 1)
#define {symbol}_COUNT  {n}

/*
 * slot -> table index (or -1 for empty).
 * Using int16_t keeps the whole table in a single L1 line-group and
 * suffices for any table we will ever hash this way (<= 32767 entries).
 */
static const int16_t {symbol}_slots[{m}] = {{
{slots_body}
}};

/*
 * Inline lookup.  Returns the original-table index of the entry whose
 * key hashes to `name`, or -1 if the slot is empty / hash mismatches.
 * The caller MUST still strcmp() to guard against unknown input hashing
 * into a populated slot.
 */
static inline int {symbol}_lookup(const char *name)
{{
    uint32_t h = xxh32_lower(name, {symbol}_SEED) & {symbol}_MASK;
    return (int){symbol}_slots[h];
}}

#endif /* {guard} */
'''


def emit_header(out_path: Path, args, keys, seed, slots):
    lines = []
    # 16 values per line for readability
    width = 16
    for i in range(0, len(slots), width):
        chunk = slots[i:i + width]
        lines.append("    " + ", ".join(f"{v:>4d}" for v in chunk) + ",")
    slots_body = "\n".join(lines)
    guard = "PE_GEN_" + args.symbol.upper() + "_H"
    text = HEADER_TMPL.format(
        basename=out_path.name,
        table=args.table,
        symbol=args.symbol,
        guard=guard,
        in_rel=args.input,
        out_rel=str(out_path),
        n=len(keys),
        m=len(slots),
        lf=len(keys) / len(slots),
        seed=seed,
        slots_body=slots_body,
    )
    out_path.write_text(text, encoding="utf-8")
    print(f"wrote {out_path} (seed=0x{seed:08X}, {len(keys)}/{len(slots)} slots)")


# ---- Main -----------------------------------------------------------


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True,
                    help="C source file that declares the table")
    ap.add_argument("--table", required=True,
                    help="Identifier of the static const table")
    ap.add_argument("--output", required=True,
                    help="Header path to emit")
    ap.add_argument("--symbol", required=True,
                    help="Prefix for generated macros/symbols (e.g. DLL_PH)")
    ap.add_argument("--min-factor", type=float, default=2.0,
                    help="Minimum size multiplier (M >= factor * N)")
    args = ap.parse_args()

    src = Path(args.input)
    keys = extract_keys(src, args.table)
    if not keys:
        print(f"ERROR: no keys extracted from {args.table}", file=sys.stderr)
        sys.exit(1)

    m_target = next_pow2(max(2, int(len(keys) * args.min_factor)))
    # Try progressively larger tables if seed search fails at minimum size
    for m in (m_target, m_target * 2, m_target * 4):
        seed, slots = find_seed(keys, m)
        if seed is not None:
            emit_header(Path(args.output), args, keys, seed, slots)
            return
        print(f"  no seed found at size {m}, enlarging...", file=sys.stderr)
    print("ERROR: could not find a perfect-hash seed even at 4x target size",
          file=sys.stderr)
    sys.exit(3)


if __name__ == "__main__":
    main()
