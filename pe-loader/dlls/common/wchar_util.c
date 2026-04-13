/*
 * wchar_util.c - Proper UTF-16/UTF-8 conversion utilities
 *
 * Replaces ad-hoc char-by-char conversions with proper UTF handling
 * including surrogate pairs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common/dll_common.h"

/*
 * Convert UTF-16LE to UTF-8.
 * Returns number of bytes written (excluding null terminator),
 * or required buffer size if dst is NULL.
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

        /* Handle surrogate pairs */
        if (w >= 0xD800 && w <= 0xDBFF && i < src_len) {
            WCHAR w2 = src[i];
            if (w2 >= 0xDC00 && w2 <= 0xDFFF) {
                cp = 0x10000 + ((w - 0xD800) << 10) + (w2 - 0xDC00);
                i++;
            } else {
                cp = w; /* Lone surrogate */
            }
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
 * Returns number of WCHARs written (excluding null),
 * or required buffer size if dst is NULL.
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
        } else if (c < 0xC0) {
            cp = 0xFFFD; /* Invalid continuation byte */
        } else if (c < 0xE0) {
            cp = c & 0x1F;
            if (i < src_len) cp = (cp << 6) | ((unsigned char)src[i++] & 0x3F);
        } else if (c < 0xF0) {
            cp = c & 0x0F;
            if (i < src_len) cp = (cp << 6) | ((unsigned char)src[i++] & 0x3F);
            if (i < src_len) cp = (cp << 6) | ((unsigned char)src[i++] & 0x3F);
        } else {
            cp = c & 0x07;
            if (i < src_len) cp = (cp << 6) | ((unsigned char)src[i++] & 0x3F);
            if (i < src_len) cp = (cp << 6) | ((unsigned char)src[i++] & 0x3F);
            if (i < src_len) cp = (cp << 6) | ((unsigned char)src[i++] & 0x3F);
        }

        /* Encode as UTF-16 */
        if (cp < 0x10000) {
            if (dst && pos < dst_size) dst[pos] = (WCHAR)cp;
            pos++;
        } else if (cp < 0x110000) {
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
 * Case-insensitive wide string compare.
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
        if (c1 != c2) return c1 - c2;
        s1++; s2++;
    }
    return *s1 - *s2;
}

/* ---- uint16_t wide string functions for CRT replacement ----
 * These replace libc wcs* functions which expect 4-byte wchar_t on Linux.
 * PE binaries use 2-byte UTF-16LE, so we need uint16_t versions.
 */

size_t wcslen16(const uint16_t *s)
{
    if (!s) return 0;
    size_t len = 0;
    while (s[len]) len++;
    return len;
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
    /* Skip whitespace */
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;

    int neg = 0;
    if (*s == '-') { neg = 1; s++; }
    else if (*s == '+') s++;

    if (base == 0) {
        if (*s == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; s += 2; }
        else if (*s == '0') { base = 8; s++; }
        else base = 10;
    } else if (base == 16 && *s == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }

    long val = 0;
    while (*s) {
        int digit;
        if (*s >= '0' && *s <= '9') digit = *s - '0';
        else if (*s >= 'a' && *s <= 'f') digit = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'F') digit = *s - 'A' + 10;
        else break;
        if (digit >= base) break;
        val = val * base + digit;
        s++;
    }
    if (endptr) *endptr = (uint16_t *)s;
    return neg ? -val : val;
}
