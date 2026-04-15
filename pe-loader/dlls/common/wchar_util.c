/*
 * wchar_util.c - Proper UTF-16/UTF-8 conversion utilities
 *
 * Replaces ad-hoc char-by-char conversions with proper UTF handling
 * including surrogate pairs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "common/dll_common.h"

/*
 * Convert UTF-16LE to UTF-8.
 * NOTE: when src_len < 0, the source NUL is included in the conversion and
 * counted in the return value (length INCLUDING null terminator). When
 * src_len >= 0, the return is the byte count for the input span (callers
 * supply an explicit length and get back the byte count consumed). The
 * dll_common.h `wide_to_narrow_safe` wrapper strips the trailing null.
 *
 * Returns number of bytes written (or required if dst is NULL/too small).
 * Lone or invalid surrogates are replaced with U+FFFD (REPLACEMENT
 * CHARACTER) rather than encoded as a bare 3-byte UTF-8 surrogate value
 * (which would be malformed UTF-8 and is rejected by strict validators
 * like glibc opendir() / sqlite / most games).
 */
int utf16_to_utf8(const WCHAR *src, int src_len, char *dst, int dst_size)
{
    if (!src) return 0;

    /* Calculate source length if -1 */
    if (src_len < 0) {
        src_len = 0;
        while (src[src_len]) src_len++;
        src_len++; /* Include null */
    }

    int pos = 0;
    int i = 0;

    while (i < src_len) {
        uint32_t cp;
        WCHAR w = src[i++];

        if (w == 0) {
            if (dst && pos < dst_size) dst[pos] = 0;
            pos++;
            break;
        }

        /* Handle surrogate pairs.  A lone high surrogate (0xD800-0xDBFF)
         * without a valid low surrogate following, OR a stray low surrogate
         * (0xDC00-0xDFFF) anywhere, is malformed UTF-16.  Substitute
         * U+FFFD to produce valid UTF-8 output. */
        if (w >= 0xD800 && w <= 0xDBFF) {
            if (i < src_len) {
                WCHAR w2 = src[i];
                if (w2 >= 0xDC00 && w2 <= 0xDFFF) {
                    cp = 0x10000 + ((uint32_t)(w - 0xD800) << 10) + (w2 - 0xDC00);
                    i++;
                } else {
                    cp = 0xFFFD; /* Lone high surrogate */
                }
            } else {
                cp = 0xFFFD; /* Truncated: high surrogate at end of input */
            }
        } else if (w >= 0xDC00 && w <= 0xDFFF) {
            cp = 0xFFFD; /* Stray low surrogate */
        } else {
            cp = w;
        }

        /* Encode as UTF-8 */
        if (cp < 0x80) {
            if (dst && pos < dst_size) dst[pos] = (char)cp;
            pos++;
        } else if (cp < 0x800) {
            if (dst && pos + 1 < dst_size) {
                dst[pos] = (char)(0xC0 | (cp >> 6));
                dst[pos + 1] = (char)(0x80 | (cp & 0x3F));
            }
            pos += 2;
        } else if (cp < 0x10000) {
            if (dst && pos + 2 < dst_size) {
                dst[pos] = (char)(0xE0 | (cp >> 12));
                dst[pos + 1] = (char)(0x80 | ((cp >> 6) & 0x3F));
                dst[pos + 2] = (char)(0x80 | (cp & 0x3F));
            }
            pos += 3;
        } else {
            if (dst && pos + 3 < dst_size) {
                dst[pos] = (char)(0xF0 | (cp >> 18));
                dst[pos + 1] = (char)(0x80 | ((cp >> 12) & 0x3F));
                dst[pos + 2] = (char)(0x80 | ((cp >> 6) & 0x3F));
                dst[pos + 3] = (char)(0x80 | (cp & 0x3F));
            }
            pos += 4;
        }
    }

    return pos;
}

/*
 * Convert UTF-8 to UTF-16LE.
 * Returns number of WCHARs written (includes null terminator when the
 * source ends with one -- symmetric with utf16_to_utf8).
 *
 * Malformed UTF-8 is replaced with U+FFFD (REPLACEMENT CHARACTER). We
 * reject:
 *   - truncated multi-byte sequences
 *   - invalid continuation bytes (high bits not 10xxxxxx)
 *   - overlong encodings (e.g. C0 80 for NUL, E0 80 80 for anything)
 *   - surrogate code points (U+D800..U+DFFF) in UTF-8 input
 *   - code points above U+10FFFF
 *   - lead bytes F8-FF (5/6-byte forms, no longer valid UTF-8 per RFC 3629)
 */
int utf8_to_utf16(const char *src, int src_len, WCHAR *dst, int dst_size)
{
    if (!src) return 0;

    if (src_len < 0)
        src_len = (int)strlen(src) + 1;

    int pos = 0;
    int i = 0;

    while (i < src_len) {
        uint32_t cp;
        unsigned char c = (unsigned char)src[i++];

        if (c == 0) {
            if (dst && pos < dst_size) dst[pos] = 0;
            pos++;
            break;
        }

        if (c < 0x80) {
            cp = c;
        } else if (c < 0xC2) {
            /* c < 0xC0 = stray continuation byte; 0xC0/0xC1 = overlong 2-byte */
            cp = 0xFFFD;
        } else if (c < 0xE0) {
            /* 2-byte sequence: C2..DF, expects 1 continuation byte */
            if (i >= src_len) { cp = 0xFFFD; }
            else {
                unsigned char c1 = (unsigned char)src[i];
                if ((c1 & 0xC0) != 0x80) { cp = 0xFFFD; }
                else {
                    cp = ((uint32_t)(c & 0x1F) << 6) | (c1 & 0x3F);
                    i++;
                    /* range check 0x80..0x7FF -- shorter encodings are overlong */
                    if (cp < 0x80) cp = 0xFFFD;
                }
            }
        } else if (c < 0xF0) {
            /* 3-byte sequence: E0..EF, expects 2 continuation bytes */
            if (i + 1 >= src_len) { cp = 0xFFFD; }
            else {
                unsigned char c1 = (unsigned char)src[i];
                unsigned char c2 = (unsigned char)src[i + 1];
                if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80) {
                    cp = 0xFFFD;
                } else {
                    cp = ((uint32_t)(c & 0x0F) << 12)
                       | ((uint32_t)(c1 & 0x3F) << 6)
                       | (c2 & 0x3F);
                    i += 2;
                    /* Reject overlong (< 0x800) and UTF-16 surrogates. */
                    if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))
                        cp = 0xFFFD;
                }
            }
        } else if (c < 0xF5) {
            /* 4-byte sequence: F0..F4, expects 3 continuation bytes.
             * F5..FF are invalid (would encode >U+10FFFF). */
            if (i + 2 >= src_len) { cp = 0xFFFD; }
            else {
                unsigned char c1 = (unsigned char)src[i];
                unsigned char c2 = (unsigned char)src[i + 1];
                unsigned char c3 = (unsigned char)src[i + 2];
                if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80) {
                    cp = 0xFFFD;
                } else {
                    cp = ((uint32_t)(c & 0x07) << 18)
                       | ((uint32_t)(c1 & 0x3F) << 12)
                       | ((uint32_t)(c2 & 0x3F) << 6)
                       | (c3 & 0x3F);
                    i += 3;
                    if (cp < 0x10000 || cp > 0x10FFFF)
                        cp = 0xFFFD;
                }
            }
        } else {
            /* F5..FF: invalid UTF-8 lead byte. */
            cp = 0xFFFD;
        }

        /* Encode as UTF-16 */
        if (cp < 0x10000) {
            if (dst && pos < dst_size) dst[pos] = (WCHAR)cp;
            pos++;
        } else if (cp <= 0x10FFFF) {
            /* Surrogate pair */
            cp -= 0x10000;
            if (dst && pos + 1 < dst_size) {
                dst[pos] = (WCHAR)(0xD800 + (cp >> 10));
                dst[pos + 1] = (WCHAR)(0xDC00 + (cp & 0x3FF));
            }
            pos += 2;
        } else {
            if (dst && pos < dst_size) dst[pos] = 0xFFFD;
            pos++;
        }
    }

    return pos;
}

/*
 * Convenience: wide string length (in WCHARs, not including null).
 */
int wcslen_safe(const WCHAR *s)
{
    if (!s) return 0;
    int len = 0;
    while (s[len]) len++;
    return len;
}

/*
 * Convenience: wide string duplicate.
 */
WCHAR *wcsdup_safe(const WCHAR *s)
{
    if (!s) return NULL;
    int len = wcslen_safe(s);
    WCHAR *dup = calloc(len + 1, sizeof(WCHAR));
    if (dup) memcpy(dup, s, (len + 1) * sizeof(WCHAR));
    return dup;
}

/*
 * Case-insensitive wide string compare.  ASCII-only folding (sufficient
 * for file-extension matches like ".EXE" vs ".exe"; Unicode case folding
 * belongs in casefold.c).
 *
 * Cast to int BEFORE subtraction to avoid 16-bit underflow: WCHAR is
 * uint16_t, so the subtraction would be done in `int` anyway under usual
 * arithmetic promotions, but being explicit avoids surprises on compilers
 * where WCHAR might be widened differently.
 */
int wcsicmp_safe(const WCHAR *s1, const WCHAR *s2)
{
    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;

    while (*s1 && *s2) {
        WCHAR c1 = *s1, c2 = *s2;
        if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
        if (c1 != c2) return (int)c1 - (int)c2;
        s1++; s2++;
    }
    return (int)*s1 - (int)*s2;
}

/* ---- uint16_t wide string functions for CRT replacement ----
 * These replace libc wcs* functions which expect 4-byte wchar_t on Linux.
 * PE binaries use 2-byte UTF-16LE, so we need uint16_t versions.
 */

size_t wcslen16(const uint16_t *s)
{
    if (!s) return 0;

    /* Scalar align-up to 8-byte boundary so the word-at-a-time scan below
     * is aligned and can't straddle a page boundary. Worst case ~3 iters. */
    size_t len = 0;
    while ((((uintptr_t)(s + len)) & 7) != 0) {
        if (!s[len]) return len;
        len++;
    }

    /* SWAR (SIMD Within A Register): load 4 uint16_t at a time and test for
     * zero using the (x - 0x0001)&~x&0x8000 bit trick (Mycroft).  Advances
     * 4 chars per branch, which is a 4–10x speedup vs the scalar byte loop
     * on both Pentium-4-class HW (no SSE) and modern x86-64 with no need for
     * AVX/SSE4 — integer ops only, matches the dual-hardware rule.
     * libc memchr()-based approaches would require a byte buffer; this is
     * the cleanest 16-bit analogue.
     *
     * Safety: we started aligned (above) and the PE input strings are
     * zero-terminated, so we will hit the sentinel before running off the
     * buffer. Page-crossing is avoided because 8-byte alignment guarantees
     * the 8-byte load stays within the current page's 4K boundary. */
    const uint64_t *w = (const uint64_t *)(s + len);
    for (;;) {
        uint64_t v = *w;
        /* For each 16-bit lane: zero if v_lane == 0 */
        uint64_t test = (v - 0x0001000100010001ULL) & ~v & 0x8000800080008000ULL;
        if (test) {
            /* Find which lane (0..3) holds the terminator */
            if ((v & 0xFFFF) == 0) return len;
            if ((v & 0xFFFF0000ULL) == 0) return len + 1;
            if ((v & 0xFFFF00000000ULL) == 0) return len + 2;
            return len + 3;
        }
        len += 4;
        w++;
    }
}

int wcscmp16(const uint16_t *a, const uint16_t *b)
{
    while (*a && *b && *a == *b) { a++; b++; }
    return (int)*a - (int)*b;
}

int wcsncmp16(const uint16_t *a, const uint16_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return (int)a[i] - (int)b[i];
        if (a[i] == 0) return 0;
    }
    return 0;
}

uint16_t *wcscpy16(uint16_t *d, const uint16_t *s)
{
    uint16_t *ret = d;
    while ((*d++ = *s++));
    return ret;
}

uint16_t *wcsncpy16(uint16_t *d, const uint16_t *s, size_t n)
{
    uint16_t *ret = d;
    size_t i;
    for (i = 0; i < n && s[i]; i++)
        d[i] = s[i];
    for (; i < n; i++)
        d[i] = 0;
    return ret;
}

uint16_t *wcscat16(uint16_t *d, const uint16_t *s)
{
    uint16_t *ret = d;
    while (*d) d++;
    while ((*d++ = *s++));
    return ret;
}

uint16_t *wcschr16(const uint16_t *s, uint16_t c)
{
    while (*s) {
        if (*s == c) return (uint16_t *)s;
        s++;
    }
    return c == 0 ? (uint16_t *)s : NULL;
}

uint16_t *wcsrchr16(const uint16_t *s, uint16_t c)
{
    const uint16_t *last = NULL;
    while (*s) {
        if (*s == c) last = s;
        s++;
    }
    if (c == 0) return (uint16_t *)s;
    return (uint16_t *)last;
}

uint16_t *wcsstr16(const uint16_t *haystack, const uint16_t *needle)
{
    if (!*needle) return (uint16_t *)haystack;
    size_t nlen = wcslen16(needle);
    while (*haystack) {
        if (wcsncmp16(haystack, needle, nlen) == 0)
            return (uint16_t *)haystack;
        haystack++;
    }
    return NULL;
}

long wcstol16(const uint16_t *s, uint16_t **endptr, int base)
{
    const uint16_t *start = s;

    /* Skip whitespace */
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;

    int neg = 0;
    if (*s == '-') { neg = 1; s++; }
    else if (*s == '+') s++;

    if (base < 0 || base == 1 || base > 36) {
        /* Invalid base: POSIX says set errno=EINVAL; we don't have errno
         * here for uint16_t wide variants.  Just return 0 with endptr at
         * the original input so callers can detect "no conversion". */
        if (endptr) *endptr = (uint16_t *)start;
        return 0;
    }

    if (base == 0) {
        if (*s == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; s += 2; }
        else if (*s == '0') { base = 8; s++; }
        else base = 10;
    } else if (base == 16 && *s == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }

    /* Overflow bound.  POSIX wcstol saturates at LONG_MAX / LONG_MIN on
     * overflow; detect using `val > (LONG_MAX - digit) / base` pattern. */
    long val = 0;
    int  overflow = 0;
    const uint16_t *digits_start = s;
    while (*s) {
        int digit;
        if (*s >= '0' && *s <= '9') digit = *s - '0';
        else if (*s >= 'a' && *s <= 'z') digit = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'Z') digit = *s - 'A' + 10;
        else break;
        if (digit >= base) break;

        if (!overflow) {
            /* Guard: would val*base+digit exceed LONG_MAX? */
            if (val > (LONG_MAX - digit) / base) {
                overflow = 1;
                val = neg ? LONG_MIN : LONG_MAX;
            } else {
                val = val * base + digit;
            }
        }
        s++;
    }

    /* No conversion: endptr should point to the original input */
    if (s == digits_start) {
        if (endptr) *endptr = (uint16_t *)start;
        return 0;
    }

    if (endptr) *endptr = (uint16_t *)s;
    if (overflow) return val;
    return neg ? -val : val;
}
