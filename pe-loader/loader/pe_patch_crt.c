/*
 * pe_patch_crt.c - Optimized ms_abi CRT bodies used by pe_patch_apply()
 *
 * Each function satisfies the Windows CRT semantic contract exactly:
 *   memcpy  -> undefined behaviour on overlap (like libc)
 *   memmove -> defined for overlap (forward or backward copy chosen)
 *   memset  -> byte-fill, value truncated to unsigned char
 *   memcmp  -> unsigned byte compare, 0 on full match
 *   strlen  -> NUL-terminated byte count
 *   strcmp  -> unsigned char compare on first differing byte (NUL-stop)
 *   strncmp -> strcmp bounded to n bytes
 *   strcpy  -> copy including NUL, returns dst
 *   strncpy -> copy up to n bytes, zero-pad to n if src shorter (POSIX)
 *   wcslen  -> 16-bit unit count to NUL terminator
 *   wcscmp  -> compare 16-bit units as unsigned
 *
 * Hardware strategy (dual-HW rule):
 *   SSE2 is guaranteed on x86_64 (Pentium-4 and newer).  AVX2 is
 *   runtime-dispatched via __builtin_cpu_supports; anything older than
 *   Haswell falls back to SSE2 / rep movsb.  No AVX-512 here.
 *
 * Every external entry point carries __attribute__((ms_abi)) so the PE
 * caller's RCX/RDX/R8/R9 land in the expected x86_64-sysv registers
 * inside the body (the compiler issues the translation prologue).
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

#include "pe/pe_patch_abi.h"

/* SSE2 is unconditional on x86_64; AVX2 is runtime-dispatched.
 * We avoid target attributes on function prototypes so the dispatchers
 * stay ABI-stable; inline helpers in the TU can be SSE2 freely. */
#include <emmintrin.h>   /* SSE2 */
#ifdef __AVX2__
#include <immintrin.h>
#endif

/* Cached CPU-feature bits.  Primed on first call; branch-predictable
 * after that.  __builtin_cpu_supports requires glibc's ifunc resolver
 * to have initialised; safe after libc is up, which is before the
 * loader ever calls a patched body. */
static int g_have_avx2 = -1;

static inline int have_avx2(void)
{
    if (__builtin_expect(g_have_avx2 < 0, 0)) {
#if defined(__GNUC__) && (__GNUC__ >= 5 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8))
        g_have_avx2 = __builtin_cpu_supports("avx2") ? 1 : 0;
#else
        g_have_avx2 = 0;
#endif
    }
    return g_have_avx2;
}

/* ------------------------------------------------------------------
 * memcpy -- forward-only copy with SSE2 bulk + rep movsb tail
 * ------------------------------------------------------------------ */
static inline void copy_small(uint8_t *d, const uint8_t *s, size_t n)
{
    /* For n < 16 a byte loop is near-optimal and avoids the mispredict
     * penalty of entering SSE for a handful of bytes. */
    while (n--) *d++ = *s++;
}

static void copy_sse2(uint8_t *d, const uint8_t *s, size_t n)
{
    /* n known >= 16.  Handle a head so the main body is 16-aligned on d. */
    size_t head = (-(uintptr_t)d) & 15u;
    if (head) {
        if (head > n) head = n;
        copy_small(d, s, head);
        d += head; s += head; n -= head;
    }
    while (n >= 64) {
        __m128i a = _mm_loadu_si128((const __m128i *)(s + 0));
        __m128i b = _mm_loadu_si128((const __m128i *)(s + 16));
        __m128i c = _mm_loadu_si128((const __m128i *)(s + 32));
        __m128i e = _mm_loadu_si128((const __m128i *)(s + 48));
        _mm_store_si128((__m128i *)(d + 0),  a);
        _mm_store_si128((__m128i *)(d + 16), b);
        _mm_store_si128((__m128i *)(d + 32), c);
        _mm_store_si128((__m128i *)(d + 48), e);
        d += 64; s += 64; n -= 64;
    }
    while (n >= 16) {
        __m128i a = _mm_loadu_si128((const __m128i *)s);
        _mm_store_si128((__m128i *)d, a);
        d += 16; s += 16; n -= 16;
    }
    if (n) copy_small(d, s, n);
}

#ifdef __AVX2__
__attribute__((target("avx2")))
static void copy_avx2(uint8_t *d, const uint8_t *s, size_t n)
{
    /* Unaligned AVX2 loads/stores; the hardware penalty on modern
     * cores is negligible for sequential streams. */
    while (n >= 128) {
        __m256i a = _mm256_loadu_si256((const __m256i *)(s + 0));
        __m256i b = _mm256_loadu_si256((const __m256i *)(s + 32));
        __m256i c = _mm256_loadu_si256((const __m256i *)(s + 64));
        __m256i e = _mm256_loadu_si256((const __m256i *)(s + 96));
        _mm256_storeu_si256((__m256i *)(d + 0),  a);
        _mm256_storeu_si256((__m256i *)(d + 32), b);
        _mm256_storeu_si256((__m256i *)(d + 64), c);
        _mm256_storeu_si256((__m256i *)(d + 96), e);
        d += 128; s += 128; n -= 128;
    }
    while (n >= 32) {
        __m256i a = _mm256_loadu_si256((const __m256i *)s);
        _mm256_storeu_si256((__m256i *)d, a);
        d += 32; s += 32; n -= 32;
    }
    if (n >= 16) {
        __m128i a = _mm_loadu_si128((const __m128i *)s);
        _mm_storeu_si128((__m128i *)d, a);
        d += 16; s += 16; n -= 16;
    }
    if (n) copy_small(d, s, n);
}
#endif /* __AVX2__ */

void *__attribute__((ms_abi)) pe_patched_memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    if (!n) return dst;
    if (n < 16) { copy_small(d, s, n); return dst; }
#ifdef __AVX2__
    if (n >= 256 && have_avx2()) { copy_avx2(d, s, n); return dst; }
#endif
    copy_sse2(d, s, n);
    return dst;
}

/* ------------------------------------------------------------------
 * memmove -- overlap-safe; forward-or-backward based on pointer order
 * ------------------------------------------------------------------ */
void *__attribute__((ms_abi)) pe_patched_memmove(void *dst, const void *src, size_t n)
{
    uint8_t       *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    if (!n || d == s) return dst;

    /* Non-overlapping (or dst comes before src) -> forward copy is safe. */
    if (d < s || d >= s + n) {
        return pe_patched_memcpy(dst, src, n);
    }

    /* Overlap with d > s: copy tail-first.  We unroll by 16 with SSE2
     * for the bulk; head remainder is byte-wise.  No AVX2 here because
     * the reverse direction doesn't cleanly parallelise for small tails. */
    d += n;
    s += n;
    while (n >= 16) {
        d -= 16; s -= 16; n -= 16;
        __m128i a = _mm_loadu_si128((const __m128i *)s);
        _mm_storeu_si128((__m128i *)d, a);
    }
    while (n--) {
        d--; s--;
        *d = *s;
    }
    return dst;
}

/* ------------------------------------------------------------------
 * memset -- byte-fill, SSE2 bulk + small-loop tail
 * ------------------------------------------------------------------ */
void *__attribute__((ms_abi)) pe_patched_memset(void *dst, int c, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    uint8_t  b = (uint8_t)c;
    if (!n) return dst;

    if (n < 16) {
        while (n--) *d++ = b;
        return dst;
    }

    __m128i v = _mm_set1_epi8((char)b);

    /* Align to 16 for the store loop. */
    size_t head = (-(uintptr_t)d) & 15u;
    if (head) {
        if (head > n) head = n;
        for (size_t i = 0; i < head; i++) d[i] = b;
        d += head; n -= head;
    }

    while (n >= 64) {
        _mm_store_si128((__m128i *)(d + 0),  v);
        _mm_store_si128((__m128i *)(d + 16), v);
        _mm_store_si128((__m128i *)(d + 32), v);
        _mm_store_si128((__m128i *)(d + 48), v);
        d += 64; n -= 64;
    }
    while (n >= 16) {
        _mm_store_si128((__m128i *)d, v);
        d += 16; n -= 16;
    }
    while (n--) *d++ = b;
    return dst;
}

/* ------------------------------------------------------------------
 * memcmp -- SSE2 pcmpeqb, locate first differing byte manually
 * ------------------------------------------------------------------ */
int __attribute__((ms_abi)) pe_patched_memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;

    while (n >= 16) {
        __m128i va = _mm_loadu_si128((const __m128i *)pa);
        __m128i vb = _mm_loadu_si128((const __m128i *)pb);
        __m128i eq = _mm_cmpeq_epi8(va, vb);
        uint32_t m = (uint32_t)_mm_movemask_epi8(eq);
        if (m != 0xFFFFu) {
            /* ~m has a 1 at the first differing lane.  Find it. */
            uint32_t diff = (~m) & 0xFFFFu;
            int idx = __builtin_ctz(diff);
            return (int)pa[idx] - (int)pb[idx];
        }
        pa += 16; pb += 16; n -= 16;
    }
    while (n--) {
        int d = (int)*pa++ - (int)*pb++;
        if (d) return d;
    }
    return 0;
}

/* ------------------------------------------------------------------
 * strlen -- SSE2 scan for NUL (16 bytes/iter)
 *
 * Safe vs page crossing: we align the pointer down to a 16-byte boundary
 * and mask out the prefix bits so bytes *before* s are ignored.  A
 * 16-byte aligned load cannot straddle a page.
 * ------------------------------------------------------------------ */
size_t __attribute__((ms_abi)) pe_patched_strlen(const char *s)
{
    const char *p = s;
    uintptr_t off = (uintptr_t)p & 15u;
    const __m128i zero = _mm_setzero_si128();

    if (off) {
        const char *aligned = p - off;
        __m128i v = _mm_load_si128((const __m128i *)aligned);
        __m128i eq = _mm_cmpeq_epi8(v, zero);
        uint32_t m = (uint32_t)_mm_movemask_epi8(eq) >> off;
        if (m) return (size_t)__builtin_ctz(m);
        p = aligned + 16;
    }

    for (;;) {
        __m128i v = _mm_load_si128((const __m128i *)p);
        __m128i eq = _mm_cmpeq_epi8(v, zero);
        uint32_t m = (uint32_t)_mm_movemask_epi8(eq);
        if (m) return (size_t)(p - s) + (size_t)__builtin_ctz(m);
        p += 16;
    }
}

/* ------------------------------------------------------------------
 * strcmp -- SSE2 compare with early-exit on diff or NUL
 *
 * We read 16 bytes at a time from both sides.  Byte pairs must be
 * equal AND non-zero to continue; any mismatch or NUL bit ends the
 * loop.  Uses aligned-down loads on both pointers so neither can
 * cross a page.
 * ------------------------------------------------------------------ */
int __attribute__((ms_abi)) pe_patched_strcmp(const char *a, const char *b)
{
    /* Fast scalar start: if the very first byte differs, avoid SSE
     * setup cost altogether.  Also handles misalignment cheaply. */
    unsigned char ca, cb;
    for (;;) {
        ca = (unsigned char)*a; cb = (unsigned char)*b;
        if (ca != cb) return (int)ca - (int)cb;
        if (!ca) return 0;
        /* Advance until both pointers share the same 16-byte bucket. */
        if ((((uintptr_t)a | (uintptr_t)b) & 15u) == 0) break;
        a++; b++;
    }

    /* Both a and b are 16-aligned now; SSE2 loop. */
    const __m128i zero = _mm_setzero_si128();
    for (;;) {
        __m128i va = _mm_load_si128((const __m128i *)a);
        __m128i vb = _mm_load_si128((const __m128i *)b);
        __m128i eq = _mm_cmpeq_epi8(va, vb);
        __m128i z  = _mm_cmpeq_epi8(va, zero);
        /* stop_bits: any position that is either a mismatch or a NUL. */
        uint32_t neq  = (~(uint32_t)_mm_movemask_epi8(eq)) & 0xFFFFu;
        uint32_t zbit = (uint32_t)_mm_movemask_epi8(z) & 0xFFFFu;
        uint32_t stop = neq | zbit;
        if (stop) {
            int idx = __builtin_ctz(stop);
            return (int)(unsigned char)a[idx] - (int)(unsigned char)b[idx];
        }
        a += 16; b += 16;
    }
}

/* ------------------------------------------------------------------
 * strncmp -- bounded; scalar is good enough for the common short-n case
 * ------------------------------------------------------------------ */
int __attribute__((ms_abi)) pe_patched_strncmp(const char *a, const char *b, size_t n)
{
    while (n >= 16) {
        /* Unaligned 16-byte comparisons for throughput on long n. */
        __m128i va = _mm_loadu_si128((const __m128i *)a);
        __m128i vb = _mm_loadu_si128((const __m128i *)b);
        __m128i eq = _mm_cmpeq_epi8(va, vb);
        __m128i z  = _mm_cmpeq_epi8(va, _mm_setzero_si128());
        uint32_t neq  = (~(uint32_t)_mm_movemask_epi8(eq)) & 0xFFFFu;
        uint32_t zbit = (uint32_t)_mm_movemask_epi8(z) & 0xFFFFu;
        uint32_t stop = neq | zbit;
        if (stop) {
            int idx = __builtin_ctz(stop);
            return (int)(unsigned char)a[idx] - (int)(unsigned char)b[idx];
        }
        a += 16; b += 16; n -= 16;
    }
    while (n--) {
        unsigned char ca = (unsigned char)*a++;
        unsigned char cb = (unsigned char)*b++;
        if (ca != cb) return (int)ca - (int)cb;
        if (!ca) return 0;
    }
    return 0;
}

/* ------------------------------------------------------------------
 * strcpy -- byte copy including NUL; returns dst
 * ------------------------------------------------------------------ */
char *__attribute__((ms_abi)) pe_patched_strcpy(char *d, const char *s)
{
    size_t len = pe_patched_strlen(s);
    /* Copy len+1 bytes (include the NUL). */
    pe_patched_memcpy(d, s, len + 1);
    return d;
}

/* ------------------------------------------------------------------
 * strncpy -- POSIX: copy up to n bytes, zero-pad if src shorter.
 * Unlike strcpy, dst may NOT be NUL-terminated if strlen(s) >= n.
 * ------------------------------------------------------------------ */
char *__attribute__((ms_abi)) pe_patched_strncpy(char *d, const char *s, size_t n)
{
    size_t i = 0;
    /* Copy up to n bytes or until NUL. */
    while (i < n && s[i]) { d[i] = s[i]; i++; }
    if (i < n) {
        /* Pad remainder with zeros using fast memset. */
        pe_patched_memset(d + i, 0, n - i);
    }
    return d;
}

/* ------------------------------------------------------------------
 * wcslen / wcscmp -- 2-byte units.  Uses SSE2 pcmpeqw for 8 chars/iter.
 *
 * The existing SWAR implementation in dlls/common/wchar_util.c is
 * preserved as the fallback for builds without SSE2 (impossible on
 * x86_64 but kept for defence in depth); here we upgrade to SSE2.
 * ------------------------------------------------------------------ */
size_t __attribute__((ms_abi)) pe_patched_wcslen(const uint16_t *s)
{
    if (!s) return 0;
    const uint16_t *p = s;

    /* Align down to 16 bytes (8 wchars). */
    uintptr_t off = (uintptr_t)p & 15u;
    const __m128i zero = _mm_setzero_si128();

    if (off) {
        /* off is a byte count; for wchars we shift by 1 to get lane index. */
        const uint16_t *aligned = (const uint16_t *)((uintptr_t)p - off);
        __m128i v = _mm_load_si128((const __m128i *)aligned);
        __m128i eq = _mm_cmpeq_epi16(v, zero);
        /* movemask_epi8 returns one bit per byte; each wchar occupies
         * two adjacent bits that are both set on match.  Shift by the
         * byte offset to hide pre-pointer lanes. */
        uint32_t m = (uint32_t)_mm_movemask_epi8(eq) >> off;
        if (m) {
            /* Each matching wchar gives two consecutive 1-bits; find
             * the first, then divide by 2 for the wchar index. */
            int byte_idx = __builtin_ctz(m);
            return (size_t)(byte_idx >> 1);
        }
        p = aligned + 8;
    }

    for (;;) {
        __m128i v = _mm_load_si128((const __m128i *)p);
        __m128i eq = _mm_cmpeq_epi16(v, zero);
        uint32_t m = (uint32_t)_mm_movemask_epi8(eq);
        if (m) {
            int byte_idx = __builtin_ctz(m);
            return (size_t)(p - s) + (size_t)(byte_idx >> 1);
        }
        p += 8;
    }
}

int __attribute__((ms_abi)) pe_patched_wcscmp(const uint16_t *a, const uint16_t *b)
{
    /* Scalar preamble -- handles fast-path mismatches and alignment. */
    uint16_t wa, wb;
    for (;;) {
        wa = *a; wb = *b;
        if (wa != wb) return (int)wa - (int)wb;
        if (!wa) return 0;
        if ((((uintptr_t)a | (uintptr_t)b) & 15u) == 0) break;
        a++; b++;
    }

    const __m128i zero = _mm_setzero_si128();
    for (;;) {
        __m128i va = _mm_load_si128((const __m128i *)a);
        __m128i vb = _mm_load_si128((const __m128i *)b);
        __m128i eq = _mm_cmpeq_epi16(va, vb);
        __m128i z  = _mm_cmpeq_epi16(va, zero);
        uint32_t neq  = (~(uint32_t)_mm_movemask_epi8(eq)) & 0xFFFFu;
        uint32_t zbit = (uint32_t)_mm_movemask_epi8(z)  & 0xFFFFu;
        uint32_t stop = neq | zbit;
        if (stop) {
            int byte_idx = __builtin_ctz(stop);
            int idx = byte_idx >> 1;
            return (int)a[idx] - (int)b[idx];
        }
        a += 8; b += 8;
    }
}

/* ------------------------------------------------------------------
 * Name -> replacement dispatch (consumed by pe_patch.c)
 *
 * Kept lower-cased to avoid runtime tolower() on every lookup.
 * The name table is small (11 entries) so a linear sweep is faster
 * than a hash with this many entries.
 * ------------------------------------------------------------------ */

typedef struct {
    const char *name;   /* Lower-case */
    void       *addr;
    uint32_t    idx;
} pe_patch_name_entry_t;

static const pe_patch_name_entry_t g_patch_table[PE_PATCH_COUNT] = {
    { "memcpy",  (void *)(uintptr_t)pe_patched_memcpy,  PE_PATCH_IDX_MEMCPY  },
    { "memset",  (void *)(uintptr_t)pe_patched_memset,  PE_PATCH_IDX_MEMSET  },
    { "memmove", (void *)(uintptr_t)pe_patched_memmove, PE_PATCH_IDX_MEMMOVE },
    { "memcmp",  (void *)(uintptr_t)pe_patched_memcmp,  PE_PATCH_IDX_MEMCMP  },
    { "strlen",  (void *)(uintptr_t)pe_patched_strlen,  PE_PATCH_IDX_STRLEN  },
    { "strcmp",  (void *)(uintptr_t)pe_patched_strcmp,  PE_PATCH_IDX_STRCMP  },
    { "strncmp", (void *)(uintptr_t)pe_patched_strncmp, PE_PATCH_IDX_STRNCMP },
    { "strcpy",  (void *)(uintptr_t)pe_patched_strcpy,  PE_PATCH_IDX_STRCPY  },
    { "strncpy", (void *)(uintptr_t)pe_patched_strncpy, PE_PATCH_IDX_STRNCPY },
    { "wcslen",  (void *)(uintptr_t)pe_patched_wcslen,  PE_PATCH_IDX_WCSLEN  },
    { "wcscmp",  (void *)(uintptr_t)pe_patched_wcscmp,  PE_PATCH_IDX_WCSCMP  },
};

void *pe_patch_replacement_by_idx(uint32_t idx)
{
    if (idx >= (uint32_t)PE_PATCH_COUNT) return NULL;
    return g_patch_table[idx].addr;
}

int pe_patch_lookup_name(const char *name)
{
    if (!name || !*name) return -1;

    /* Lowercase into a fixed buffer; PE CRT names are short. */
    char lower[16];
    size_t i;
    for (i = 0; i < sizeof(lower) - 1 && name[i]; i++) {
        unsigned char c = (unsigned char)name[i];
        unsigned lc = c - 'A';
        lower[i] = (lc < 26u) ? (char)(c | 0x20u) : (char)c;
    }
    lower[i] = '\0';
    if (name[i] != '\0') return -1; /* Name too long for a known CRT */

    for (uint32_t k = 0; k < (uint32_t)PE_PATCH_COUNT; k++) {
        if (strcmp(lower, g_patch_table[k].name) == 0)
            return (int)g_patch_table[k].idx;
    }
    return -1;
}
