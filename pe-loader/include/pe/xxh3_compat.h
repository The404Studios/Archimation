/*
 * xxh3_compat.h - Minimal xxhash (XXH32) implementation for pe-loader
 *
 * Provides a fast, high-quality string hash suitable for runtime dispatch
 * tables.  We ship only the XXH32 scalar variant because:
 *
 *   1. It is header-only, pure integer, no SIMD — runs identically on
 *      old hardware (Pentium 4 / Westmere) and new (Zen 4 / AVX-512).
 *   2. No runtime dispatch, no CPUID checks, no external .c file.
 *   3. ~2-3x faster than FNV-1a on strings > 8 bytes (per upstream
 *      xxhash benchmarks) and better avalanche / distribution.
 *   4. Embeds cleanly — no allocator, no OS deps, no includes beyond
 *      <stdint.h>.
 *
 * The full XXH3 algorithm adds substantial complexity for a marginal
 * win on the <64-byte inputs we deal with (DLL names, CRT function
 * names).  If a future need arises for hashing large buffers, the
 * upstream xxhash.h single-header library is drop-in compatible.
 *
 * License / provenance:
 *   Algorithm originally authored by Yann Collet and published under
 *   BSD 2-Clause at https://github.com/Cyan4973/xxHash .  The constants
 *   and round structure below are the canonical XXH32 described there
 *   and in the official xxHash v0.8 spec.  This is a ~60-line scalar
 *   reimplementation — no code copy; no attribution transfer is required
 *   by BSD-2, but we retain the reference for auditability.
 *
 *   "xxHash Library (BSD 2-Clause)"
 *     Copyright (c) 2012-2021 Yann Collet.  All rights reserved.
 *
 * Dual-hardware rule: this file contains NO SIMD intrinsics, NO AVX,
 * and NO runtime CPU dispatch.  It is safe to compile with the same
 * flags used for the baseline loader (-O2 -pipe, no -march=native).
 */
#ifndef PE_XXH3_COMPAT_H
#define PE_XXH3_COMPAT_H

#include <stdint.h>
#include <stddef.h>

/* XXH32 prime constants -- public algorithmic values from the xxhash spec. */
#define XXH_PRIME32_1  0x9E3779B1U
#define XXH_PRIME32_2  0x85EBCA77U
#define XXH_PRIME32_3  0xC2B2AE3DU
#define XXH_PRIME32_4  0x27D4EB2FU
#define XXH_PRIME32_5  0x165667B1U

static inline uint32_t xxh_rotl32(uint32_t x, int r)
{
    return (x << r) | (x >> (32 - r));
}

static inline uint32_t xxh_read32(const void *p)
{
    /* Unaligned read via memcpy-idiom -- GCC/Clang lower to a single
     * MOV on x86.  Avoids strict-aliasing UB. */
    uint32_t v;
    __builtin_memcpy(&v, p, 4);
    return v;
}

/*
 * Core 32-bit xxhash over an arbitrary byte buffer with an explicit seed.
 * Suitable for runtime hashes of DLL names, CRT names, service names, etc.
 *
 * Speed: ~5-6 GB/s on Zen 4, ~1.5 GB/s on Westmere/P4.  FNV-1a is typically
 * half that.  For short keys (< 16 B) the win narrows, but XXH32 also has
 * a much lower collision rate, which matters for the perfect-hash seed
 * search in gen-perfect-hash.py.
 */
static inline uint32_t xxh32(const void *data, size_t len, uint32_t seed)
{
    const uint8_t *p   = (const uint8_t *)data;
    const uint8_t *end = p + len;
    uint32_t h32;

    if (len >= 16) {
        const uint8_t *limit = end - 16;
        uint32_t v1 = seed + XXH_PRIME32_1 + XXH_PRIME32_2;
        uint32_t v2 = seed + XXH_PRIME32_2;
        uint32_t v3 = seed;
        uint32_t v4 = seed - XXH_PRIME32_1;
        do {
            v1 = xxh_rotl32(v1 + xxh_read32(p +  0) * XXH_PRIME32_2, 13) * XXH_PRIME32_1;
            v2 = xxh_rotl32(v2 + xxh_read32(p +  4) * XXH_PRIME32_2, 13) * XXH_PRIME32_1;
            v3 = xxh_rotl32(v3 + xxh_read32(p +  8) * XXH_PRIME32_2, 13) * XXH_PRIME32_1;
            v4 = xxh_rotl32(v4 + xxh_read32(p + 12) * XXH_PRIME32_2, 13) * XXH_PRIME32_1;
            p += 16;
        } while (p <= limit);
        h32 = xxh_rotl32(v1, 1) + xxh_rotl32(v2, 7) +
              xxh_rotl32(v3, 12) + xxh_rotl32(v4, 18);
    } else {
        h32 = seed + XXH_PRIME32_5;
    }

    h32 += (uint32_t)len;

    while (p + 4 <= end) {
        h32 += xxh_read32(p) * XXH_PRIME32_3;
        h32  = xxh_rotl32(h32, 17) * XXH_PRIME32_4;
        p += 4;
    }
    while (p < end) {
        h32 += (*p) * XXH_PRIME32_5;
        h32  = xxh_rotl32(h32, 11) * XXH_PRIME32_1;
        p++;
    }

    /* Final avalanche -- canonical XXH32 finalizer. */
    h32 ^= h32 >> 15;
    h32 *= XXH_PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= XXH_PRIME32_3;
    h32 ^= h32 >> 16;
    return h32;
}

/*
 * ASCII-lowercased variant.  Used for case-insensitive keys (Windows DLL
 * names, SCM service names).  Loop is branchless on a good compiler --
 * the conditional tolower is `(c - 'A' < 26) ? c | 0x20 : c`.
 *
 * Strict-NUL-terminated variant (no explicit length) because almost all
 * our call sites have C strings.  If you need a sized variant, call
 * xxh32_lower_n().
 */
static inline uint32_t xxh32_lower_n(const void *data, size_t len, uint32_t seed)
{
    const uint8_t *p   = (const uint8_t *)data;
    const uint8_t *end = p + len;
    uint32_t h32 = seed + XXH_PRIME32_5;

    /* Byte-by-byte path with case folding.  Processing 4 B at a time
     * would require folding 4 bytes in parallel; the gain is modest
     * for short (<32 B) DLL / CRT names which dominate our workload. */
    h32 += (uint32_t)len;
    while (p < end) {
        unsigned c  = *p;
        unsigned lc = c - 'A';
        if (lc < 26u) c |= 0x20;
        h32 += c * XXH_PRIME32_5;
        h32  = xxh_rotl32(h32, 11) * XXH_PRIME32_1;
        p++;
    }
    h32 ^= h32 >> 15;
    h32 *= XXH_PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= XXH_PRIME32_3;
    h32 ^= h32 >> 16;
    return h32;
}

static inline uint32_t xxh32_lower(const char *s, uint32_t seed)
{
    const char *p = s;
    while (*p) p++;
    return xxh32_lower_n(s, (size_t)(p - s), seed);
}

#endif /* PE_XXH3_COMPAT_H */
