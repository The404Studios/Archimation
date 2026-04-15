/*
 * msvcrt_string.c - MSVCRT/UCRT string, wide string, printf, and path functions
 *
 * Covers: secure string (_s variants), wide string conversions, _snprintf/_vsnprintf,
 * wide I/O (_wfopen etc.), path manipulation (_splitpath_s, _makepath_s),
 * and process argument accessors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <wctype.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>

#include "common/dll_common.h"
#include "compat/ms_abi_format.h"

/* ========== Secure String Functions (_s variants) ========== */

WINAPI_EXPORT int strcpy_s(char *dest, size_t destsz, const char *src)
{
    if (!dest || destsz == 0) return 22; /* EINVAL */
    if (!src) { dest[0] = '\0'; return 22; }
    size_t len = strlen(src);
    if (len >= destsz) { dest[0] = '\0'; return 34; /* ERANGE */ }
    memcpy(dest, src, len + 1);
    return 0;
}

WINAPI_EXPORT int strcat_s(char *dest, size_t destsz, const char *src)
{
    if (!dest || destsz == 0 || !src) return 22;
    size_t dlen = strlen(dest);
    size_t slen = strlen(src);
    if (dlen + slen >= destsz) return 34;
    memcpy(dest + dlen, src, slen + 1);
    return 0;
}

WINAPI_EXPORT int strncpy_s(char *dest, size_t destsz, const char *src, size_t count)
{
    if (!dest || destsz == 0) return 22;
    if (!src) { dest[0] = '\0'; return 22; }
    size_t len = strlen(src);
    if (count < len) len = count;
    if (len >= destsz) { dest[0] = '\0'; return 34; }
    memcpy(dest, src, len);
    dest[len] = '\0';
    return 0;
}

WINAPI_EXPORT int strncat_s(char *dest, size_t destsz, const char *src, size_t count)
{
    if (!dest || destsz == 0 || !src) return 22;
    size_t dlen = strlen(dest);
    size_t slen = strlen(src);
    if (count < slen) slen = count;
    if (dlen + slen >= destsz) return 34;
    memcpy(dest + dlen, src, slen);
    dest[dlen + slen] = '\0';
    return 0;
}

WINAPI_EXPORT int memcpy_s(void *dest, size_t destsz, const void *src, size_t count)
{
    if (!dest || !src) return 22;
    if (count > destsz) return 34;
    memcpy(dest, src, count);
    return 0;
}

WINAPI_EXPORT int memmove_s(void *dest, size_t destsz, const void *src, size_t count)
{
    if (!dest || !src) return 22;
    if (count > destsz) return 34;
    memmove(dest, src, count);
    return 0;
}

/* ========== Wide String Secure Functions ========== */

WINAPI_EXPORT int wcscpy_s(uint16_t *dest, size_t destsz, const uint16_t *src)
{
    if (!dest || destsz == 0) return 22;
    if (!src) { dest[0] = 0; return 22; }
    size_t len = 0;
    while (src[len]) len++;
    if (len >= destsz) { dest[0] = 0; return 34; }
    memcpy(dest, src, (len + 1) * sizeof(uint16_t));
    return 0;
}

WINAPI_EXPORT int wcscat_s(uint16_t *dest, size_t destsz, const uint16_t *src)
{
    if (!dest || destsz == 0 || !src) return 22;
    size_t dlen = 0;
    while (dest[dlen]) dlen++;
    size_t slen = 0;
    while (src[slen]) slen++;
    if (dlen + slen >= destsz) return 34;
    memcpy(dest + dlen, src, (slen + 1) * sizeof(uint16_t));
    return 0;
}

WINAPI_EXPORT int wcsncpy_s(uint16_t *dest, size_t destsz, const uint16_t *src, size_t count)
{
    if (!dest || destsz == 0) return 22;
    if (!src) { dest[0] = 0; return 22; }
    size_t len = 0;
    while (src[len] && len < count) len++;
    if (len >= destsz) { dest[0] = 0; return 34; }
    memcpy(dest, src, len * sizeof(uint16_t));
    dest[len] = 0;
    return 0;
}

/* ========== Wide String Manipulation ========== */

WINAPI_EXPORT uint16_t *_wcsdup(const uint16_t *strSource)
{
    if (!strSource) return NULL;
    size_t len = 0;
    while (strSource[len]) len++;
    uint16_t *dup = malloc((len + 1) * sizeof(uint16_t));
    if (dup) memcpy(dup, strSource, (len + 1) * sizeof(uint16_t));
    return dup;
}

WINAPI_EXPORT uint16_t *_wcslwr(uint16_t *str)
{
    if (!str) return NULL;
    for (uint16_t *p = str; *p; p++)
        if (*p >= 'A' && *p <= 'Z') *p += 32;
    return str;
}

WINAPI_EXPORT int _wcslwr_s(uint16_t *str, size_t sizeInWords)
{
    if (!str || sizeInWords == 0) return 22;
    _wcslwr(str);
    return 0;
}

WINAPI_EXPORT uint16_t *_wcsupr(uint16_t *str)
{
    if (!str) return NULL;
    for (uint16_t *p = str; *p; p++)
        if (*p >= 'a' && *p <= 'z') *p -= 32;
    return str;
}

WINAPI_EXPORT int _wcsupr_s(uint16_t *str, size_t sizeInWords)
{
    if (!str || sizeInWords == 0) return 22;
    _wcsupr(str);
    return 0;
}

WINAPI_EXPORT char *_strlwr(char *str)
{
    if (!str) return NULL;
    for (char *p = str; *p; p++)
        if (*p >= 'A' && *p <= 'Z') *p += 32;
    return str;
}

WINAPI_EXPORT char *_strupr(char *str)
{
    if (!str) return NULL;
    for (char *p = str; *p; p++)
        if (*p >= 'a' && *p <= 'z') *p -= 32;
    return str;
}

/* _strdup, _stricmp, _strnicmp are in msvcrt_stdio.c */

WINAPI_EXPORT int _wcsicmp(const uint16_t *s1, const uint16_t *s2)
{
    while (*s1 && *s2) {
        uint16_t c1 = (*s1 >= 'A' && *s1 <= 'Z') ? *s1 + 32 : *s1;
        uint16_t c2 = (*s2 >= 'A' && *s2 <= 'Z') ? *s2 + 32 : *s2;
        if (c1 != c2) return (int)c1 - (int)c2;
        s1++; s2++;
    }
    return (int)*s1 - (int)*s2;
}

WINAPI_EXPORT int _wcsnicmp(const uint16_t *s1, const uint16_t *s2, size_t count)
{
    /* Correctness fix: the original loop terminated as soon as EITHER string
     * hit a NUL, but then returned 0. That meant _wcsnicmp("ab", "abcd", 4)
     * wrongly returned 0 instead of the expected negative diff. Real Windows
     * compares all `count` chars and returns the signed char difference at
     * the first mismatch; a NUL in one string is just a char with value 0. */
    for (size_t i = 0; i < count; i++) {
        uint16_t a = s1[i], b = s2[i];
        uint16_t c1 = (a >= 'A' && a <= 'Z') ? a + 32 : a;
        uint16_t c2 = (b >= 'A' && b <= 'Z') ? b + 32 : b;
        if (c1 != c2) return (int)c1 - (int)c2;
        if (a == 0) return 0; /* both equal AND both NUL → same string */
    }
    return 0;
}

WINAPI_EXPORT char *_strrev(char *str)
{
    if (!str) return NULL;
    size_t len = strlen(str);
    for (size_t i = 0; i < len / 2; i++) {
        char tmp = str[i];
        str[i] = str[len - 1 - i];
        str[len - 1 - i] = tmp;
    }
    return str;
}

WINAPI_EXPORT uint16_t *_wcsrev(uint16_t *str)
{
    if (!str) return NULL;
    size_t len = 0;
    while (str[len]) len++;
    for (size_t i = 0; i < len / 2; i++) {
        uint16_t tmp = str[i];
        str[i] = str[len - 1 - i];
        str[len - 1 - i] = tmp;
    }
    return str;
}

/* ========== Conversion Functions ========== */

WINAPI_EXPORT int wcstombs_s(size_t *pReturnValue, char *mbstr, size_t sizeInBytes,
                              const uint16_t *wcstr, size_t count)
{
    if (!wcstr) { if (pReturnValue) *pReturnValue = 0; return 22; }
    /* Manually convert uint16_t (UTF-16LE) to narrow chars (Latin-1 subset) */
    size_t src_len = 0;
    while (wcstr[src_len]) src_len++;
    size_t to_copy = src_len;
    if (count != (size_t)-1 && count < to_copy) to_copy = count;
    if (mbstr && sizeInBytes > 0) {
        if (to_copy >= sizeInBytes) to_copy = sizeInBytes - 1;
        for (size_t i = 0; i < to_copy; i++)
            mbstr[i] = (char)(wcstr[i] & 0xFF);
        mbstr[to_copy] = '\0';
    }
    if (pReturnValue) *pReturnValue = to_copy + 1;
    return 0;
}

WINAPI_EXPORT int mbstowcs_s(size_t *pReturnValue, uint16_t *wcstr, size_t sizeInWords,
                              const char *mbstr, size_t count)
{
    if (!mbstr) { if (pReturnValue) *pReturnValue = 0; return 22; }
    /* Manually convert narrow chars to uint16_t (UTF-16LE, ASCII subset) */
    size_t src_len = strlen(mbstr);
    size_t to_copy = src_len;
    if (count != (size_t)-1 && count < to_copy) to_copy = count;
    if (wcstr && sizeInWords > 0) {
        if (to_copy >= sizeInWords) to_copy = sizeInWords - 1;
        for (size_t i = 0; i < to_copy; i++)
            wcstr[i] = (uint16_t)(unsigned char)mbstr[i];
        wcstr[to_copy] = 0;
    }
    if (pReturnValue) *pReturnValue = to_copy + 1;
    return 0;
}

/* Helper: convert integer to string with arbitrary radix (2-36) */
static void int_to_radix(unsigned long long uval, int is_neg, char *buffer, size_t size, int radix)
{
    static const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    char tmp[68]; /* enough for 64-bit binary + sign + NUL */
    int pos = 0;

    if (uval == 0) {
        tmp[pos++] = '0';
    } else {
        while (uval > 0) {
            tmp[pos++] = digits[uval % radix];
            uval /= radix;
        }
    }
    if (is_neg) tmp[pos++] = '-';

    /* Reverse into buffer */
    size_t len = (size_t)pos;
    if (len + 1 > size) {
        buffer[0] = '\0';
        return;
    }
    for (int i = 0; i < pos; i++)
        buffer[i] = tmp[pos - 1 - i];
    buffer[pos] = '\0';
}

WINAPI_EXPORT int _itoa_s(int value, char *buffer, size_t sizeInCharacters, int radix)
{
    if (!buffer || sizeInCharacters == 0) return 22;
    if (radix < 2 || radix > 36) return 22;
    int is_neg = (value < 0 && radix == 10) ? 1 : 0;
    unsigned long long uval = is_neg ? (unsigned long long)(-(long long)value) : (unsigned int)value;
    int_to_radix(uval, is_neg, buffer, sizeInCharacters, radix);
    return 0;
}

WINAPI_EXPORT int _ltoa_s(long value, char *buffer, size_t sizeInCharacters, int radix)
{
    if (!buffer || sizeInCharacters == 0) return 22;
    if (radix < 2 || radix > 36) return 22;
    int is_neg = (value < 0 && radix == 10) ? 1 : 0;
    unsigned long long uval = is_neg ? (unsigned long long)(-(long long)value) : (unsigned long)value;
    int_to_radix(uval, is_neg, buffer, sizeInCharacters, radix);
    return 0;
}

WINAPI_EXPORT int _ultoa_s(unsigned long value, char *buffer, size_t sizeInCharacters, int radix)
{
    if (!buffer || sizeInCharacters == 0) return 22;
    if (radix < 2 || radix > 36) return 22;
    int_to_radix((unsigned long long)value, 0, buffer, sizeInCharacters, radix);
    return 0;
}

WINAPI_EXPORT char *_i64toa(int64_t value, char *buffer, int radix)
{
    if (!buffer) return NULL;
    if (radix == 16) sprintf(buffer, "%llx", (unsigned long long)value);
    else if (radix == 8) sprintf(buffer, "%llo", (unsigned long long)value);
    else sprintf(buffer, "%lld", (long long)value);
    return buffer;
}

WINAPI_EXPORT int _i64toa_s(int64_t value, char *buffer, size_t sizeInCharacters, int radix)
{
    if (!buffer || sizeInCharacters == 0) return 22;
    _i64toa(value, buffer, radix);
    return 0;
}

WINAPI_EXPORT int64_t _atoi64(const char *str)
{
    if (!str) return 0;
    return strtoll(str, NULL, 10);
}

WINAPI_EXPORT int64_t _strtoi64(const char *nptr, char **endptr, int base)
{
    return strtoll(nptr, endptr, base);
}

WINAPI_EXPORT uint64_t _strtoui64(const char *nptr, char **endptr, int base)
{
    return strtoull(nptr, endptr, base);
}

WINAPI_EXPORT int _itow_s(int value, uint16_t *buffer, size_t sizeInCharacters, int radix)
{
    if (!buffer || sizeInCharacters == 0) return 22;
    char tmp[64];
    _itoa_s(value, tmp, sizeof(tmp), radix);
    size_t len = strlen(tmp);
    if (len >= sizeInCharacters) return 34;
    for (size_t i = 0; i <= len; i++)
        buffer[i] = (uint16_t)(uint8_t)tmp[i];
    return 0;
}

WINAPI_EXPORT int _wtoi(const uint16_t *str)
{
    if (!str) return 0;
    char buf[64];
    int i = 0;
    while (str[i] && i < 63) { buf[i] = (char)str[i]; i++; }
    buf[i] = '\0';
    return atoi(buf);
}

WINAPI_EXPORT long _wtol(const uint16_t *str)
{
    return (long)_wtoi(str);
}

WINAPI_EXPORT int64_t _wtoi64(const uint16_t *str)
{
    if (!str) return 0;
    char buf[64];
    int i = 0;
    while (str[i] && i < 63) { buf[i] = (char)str[i]; i++; }
    buf[i] = '\0';
    return strtoll(buf, NULL, 10);
}

/* Helper: convert uint16_t string to narrow char.
 * Safety: guard against bufsz==0 (the prior "bufsz - 1" underflowed to
 * SIZE_MAX, allowing an unbounded write when callers passed 0) and
 * NULL input (prior version would deref ws[0] and crash). */
static size_t wcs_to_narrow(const uint16_t *ws, char *buf, size_t bufsz)
{
    if (!buf || bufsz == 0) return 0;
    if (!ws) { buf[0] = '\0'; return 0; }
    size_t i = 0;
    while (ws[i] && i < bufsz - 1) { buf[i] = (char)ws[i]; i++; }
    buf[i] = '\0';
    return i;
}

/* Windows wchar_t is 2 bytes (uint16_t), Linux wchar_t is 4 bytes.
 * We cannot use the standard names (wcstol, etc.) because they conflict
 * with libc's wchar.h declarations.  Use pe_ prefix; the PE import
 * resolver maps Windows names to these at load time. */
WINAPI_EXPORT long pe_wcstol(const uint16_t *nptr, uint16_t **endptr, int base)
{
    char buf[128]; wcs_to_narrow(nptr, buf, sizeof(buf));
    char *ep = NULL;
    long r = strtol(buf, &ep, base);
    if (endptr) *endptr = (uint16_t*)(nptr + (ep - buf));
    return r;
}

WINAPI_EXPORT unsigned long pe_wcstoul(const uint16_t *nptr, uint16_t **endptr, int base)
{
    char buf[128]; wcs_to_narrow(nptr, buf, sizeof(buf));
    char *ep = NULL;
    unsigned long r = strtoul(buf, &ep, base);
    if (endptr) *endptr = (uint16_t*)(nptr + (ep - buf));
    return r;
}

WINAPI_EXPORT double pe_wcstod(const uint16_t *nptr, uint16_t **endptr)
{
    char buf[128]; wcs_to_narrow(nptr, buf, sizeof(buf));
    char *ep = NULL;
    double r = strtod(buf, &ep);
    if (endptr) *endptr = (uint16_t*)(nptr + (ep - buf));
    return r;
}

WINAPI_EXPORT float pe_wcstof(const uint16_t *nptr, uint16_t **endptr)
{
    return (float)pe_wcstod(nptr, endptr);
}

WINAPI_EXPORT long long pe_wcstoll(const uint16_t *nptr, uint16_t **endptr, int base)
{
    char buf[128]; wcs_to_narrow(nptr, buf, sizeof(buf));
    char *ep = NULL;
    long long r = strtoll(buf, &ep, base);
    if (endptr) *endptr = (uint16_t*)(nptr + (ep - buf));
    return r;
}

WINAPI_EXPORT unsigned long long pe_wcstoull(const uint16_t *nptr, uint16_t **endptr, int base)
{
    char buf[128]; wcs_to_narrow(nptr, buf, sizeof(buf));
    char *ep = NULL;
    unsigned long long r = strtoull(buf, &ep, base);
    if (endptr) *endptr = (uint16_t*)(nptr + (ep - buf));
    return r;
}

/* _wtof - wide string to double */
WINAPI_EXPORT double _wtof(const uint16_t *str)
{
    return pe_wcstod(str, NULL);
}

/* _wtol2 - wide string to long with base */
WINAPI_EXPORT long _wcstol(const uint16_t *nptr, uint16_t **endptr, int base)
{
    return pe_wcstol(nptr, endptr, base);
}

WINAPI_EXPORT unsigned long _wcstoul(const uint16_t *nptr, uint16_t **endptr, int base)
{
    return pe_wcstoul(nptr, endptr, base);
}

/* ========== Printf/Scanf Variants ========== */
/* _snprintf is in msvcrt_stdio.c */

WINAPI_EXPORT int _snprintf_s(char *buffer, size_t sizeOfBuffer, size_t count,
                               const char *format, ...)
{
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    /* Treat sizeOfBuffer==0 or buffer==NULL as "measure only" by passing
     * NULL buffer to ms_abi_vformat; otherwise the engine would underflow
     * bufsz-1 when writing.  MS returns -1 in this mode on real truncation
     * but _snprintf_s (unlike _snprintf) writes nothing when buffer is 0. */
    size_t max = count < sizeOfBuffer ? count : sizeOfBuffer;
    int ret;
    if (!buffer || max == 0) {
        ret = ms_abi_vformat(NULL, NULL, 0, format, args);
    } else {
        ret = ms_abi_vformat(NULL, buffer, max, format, args);
    }
    __builtin_ms_va_end(args);
    return ret;
}

/* _vsnprintf is in msvcrt_stdio.c */

WINAPI_EXPORT int _vsnprintf_s(char *buffer, size_t sizeOfBuffer, size_t count,
                                const char *format, __builtin_ms_va_list argptr)
{
    /* ms_abi variadic: va_list from a PE caller is __builtin_ms_va_list
     * (char*); libc vsnprintf expects sysv va_list (24-byte struct).
     * Forwarding the raw pointer would misread arg slots.  Route through
     * the ms_abi-safe engine. */
    size_t max = count < sizeOfBuffer ? count : sizeOfBuffer;
    if (!buffer || max == 0)
        return ms_abi_vformat(NULL, NULL, 0, format, argptr);
    return ms_abi_vformat(NULL, buffer, max, format, argptr);
}

WINAPI_EXPORT int _vscprintf(const char *format, __builtin_ms_va_list argptr)
{
    return ms_abi_vformat(NULL, NULL, 0, format, argptr);
}

/* Wide printf variants - forward declare _vsnwprintf (defined below) */
WINAPI_EXPORT int _vsnwprintf(uint16_t *buffer, size_t count, const uint16_t *format, __builtin_ms_va_list argptr);

WINAPI_EXPORT int _snwprintf(uint16_t *buffer, size_t count, const uint16_t *format, ...)
{
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, format);
    int ret = _vsnwprintf(buffer, count, format, ap);
    __builtin_ms_va_end(ap);
    return ret;
}

WINAPI_EXPORT int _snwprintf_s(uint16_t *buffer, size_t sizeOfBuffer, size_t count,
                                const uint16_t *format, ...)
{
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, format);
    size_t max = count < sizeOfBuffer ? count : sizeOfBuffer;
    int ret = _vsnwprintf(buffer, max, format, ap);
    __builtin_ms_va_end(ap);
    return ret;
}

WINAPI_EXPORT int _vsnwprintf(uint16_t *buffer, size_t count, const uint16_t *format, __builtin_ms_va_list argptr)
{
    /* Convert wide format to narrow, format, then convert result back to wide */
    if (!format) return -1;
    char narrow_fmt[2048] = {0};
    for (int i = 0; format[i] && i < 2047; i++)
        narrow_fmt[i] = (char)(format[i] < 128 ? format[i] : '?');
    char narrow_out[4096] = {0};
    int len = ms_abi_vformat(NULL, narrow_out, sizeof(narrow_out), narrow_fmt, argptr);
    if (len < 0) return -1;
    if (buffer && count > 0) {
        /* count==1 means only space for the NUL; copy zero chars. */
        size_t max_out = count - 1;
        size_t copy = ((size_t)len < max_out) ? (size_t)len : max_out;
        for (size_t i = 0; i < copy; i++)
            buffer[i] = (uint16_t)(unsigned char)narrow_out[i];
        buffer[copy] = 0;
    }
    return len;
}

WINAPI_EXPORT int _vsnwprintf_s(uint16_t *buffer, size_t sizeOfBuffer, size_t count,
                                 const uint16_t *format, __builtin_ms_va_list argptr)
{
    /* MS docs: buffer limited to min(sizeOfBuffer, count) wide chars. */
    size_t max = count < sizeOfBuffer ? count : sizeOfBuffer;
    return _vsnwprintf(buffer, max, format, argptr);
}

WINAPI_EXPORT int _vscwprintf(const uint16_t *format, __builtin_ms_va_list argptr)
{
    /* Convert wide format to narrow, compute length via ms_abi_vformat */
    if (!format) return -1;
    char narrow_fmt[2048] = {0};
    for (int i = 0; format[i] && i < 2047; i++)
        narrow_fmt[i] = (char)(format[i] < 128 ? format[i] : '?');
    return ms_abi_vformat(NULL, NULL, 0, narrow_fmt, argptr);
}

WINAPI_EXPORT int sprintf_s(char *buffer, size_t sizeOfBuffer, const char *format, ...)
{
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    int ret;
    /* Guard against bufsz==0 underflow in the ms_abi_vformat engine. */
    if (!buffer || sizeOfBuffer == 0)
        ret = ms_abi_vformat(NULL, NULL, 0, format, args);
    else
        ret = ms_abi_vformat(NULL, buffer, sizeOfBuffer, format, args);
    __builtin_ms_va_end(args);
    return ret;
}

WINAPI_EXPORT int vsprintf_s(char *buffer, size_t sizeOfBuffer, const char *format, __builtin_ms_va_list argptr)
{
    if (!buffer || sizeOfBuffer == 0)
        return ms_abi_vformat(NULL, NULL, 0, format, argptr);
    return ms_abi_vformat(NULL, buffer, sizeOfBuffer, format, argptr);
}

WINAPI_EXPORT int swprintf_s(uint16_t *buffer, size_t sizeOfBuffer, const uint16_t *format, ...)
{
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, format);
    int ret = _vsnwprintf(buffer, sizeOfBuffer, format, ap);
    __builtin_ms_va_end(ap);
    return ret;
}

WINAPI_EXPORT int _scprintf(const char *format, ...)
{
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    int ret = ms_abi_vformat(NULL, NULL, 0, format, args);
    __builtin_ms_va_end(args);
    return ret;
}

/* ========== Wide File I/O ========== */

/* Helper: convert UTF-16 to UTF-8.
 * Correctness: handles surrogate pairs (non-BMP codepoints), which the
 * prior version silently truncated to 3-byte encodings of the high
 * surrogate — producing malformed UTF-8 rejected by glibc opendir()
 * and most games' save-path logic when users have emoji/rare-script
 * characters in their profile path. */
static char *wchar_to_utf8(const uint16_t *wstr)
{
    if (!wstr) return NULL;
    size_t len = 0;
    while (wstr[len]) len++;
    char *buf = malloc(len * 4 + 1);
    if (!buf) return NULL;
    size_t pos = 0;
    for (size_t i = 0; i < len; i++) {
        uint32_t c = wstr[i];

        /* Surrogate pair decoding */
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < len) {
            uint32_t lo = wstr[i + 1];
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                i++;
            } else {
                c = 0xFFFD; /* lone high surrogate */
            }
        } else if (c >= 0xDC00 && c <= 0xDFFF) {
            c = 0xFFFD; /* stray low surrogate */
        }

        if (c < 0x80) {
            buf[pos++] = (char)c;
        } else if (c < 0x800) {
            buf[pos++] = (char)(0xC0 | (c >> 6));
            buf[pos++] = (char)(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            buf[pos++] = (char)(0xE0 | (c >> 12));
            buf[pos++] = (char)(0x80 | ((c >> 6) & 0x3F));
            buf[pos++] = (char)(0x80 | (c & 0x3F));
        } else {
            /* 4-byte UTF-8 for U+10000..U+10FFFF */
            buf[pos++] = (char)(0xF0 | (c >> 18));
            buf[pos++] = (char)(0x80 | ((c >> 12) & 0x3F));
            buf[pos++] = (char)(0x80 | ((c >> 6) & 0x3F));
            buf[pos++] = (char)(0x80 | (c & 0x3F));
        }
    }
    buf[pos] = '\0';
    return buf;
}

static char *wmode_to_mode(const uint16_t *wmode)
{
    if (!wmode) return strdup("r");
    char buf[16];
    int i = 0;
    while (wmode[i] && i < 15) { buf[i] = (char)wmode[i]; i++; }
    buf[i] = '\0';
    return strdup(buf);
}

WINAPI_EXPORT FILE *_wfopen(const uint16_t *filename, const uint16_t *mode)
{
    char *fn = wchar_to_utf8(filename);
    char *m = wmode_to_mode(mode);
    if (!fn || !m) { free(fn); free(m); return NULL; }
    FILE *f = fopen(fn, m);
    free(fn);
    free(m);
    return f;
}

WINAPI_EXPORT int _wfopen_s(FILE **pFile, const uint16_t *filename, const uint16_t *mode)
{
    if (!pFile) return 22;
    *pFile = _wfopen(filename, mode);
    return *pFile ? 0 : errno;
}

WINAPI_EXPORT FILE *_wfreopen(const uint16_t *filename, const uint16_t *mode, FILE *stream)
{
    char *fn = wchar_to_utf8(filename);
    char *m = wmode_to_mode(mode);
    if (!fn || !m) { free(fn); free(m); return NULL; }
    FILE *f = freopen(fn, m, stream);
    free(fn);
    free(m);
    return f;
}

WINAPI_EXPORT int _wremove(const uint16_t *filename)
{
    char *fn = wchar_to_utf8(filename);
    if (!fn) return -1;
    int ret = remove(fn);
    free(fn);
    return ret;
}

WINAPI_EXPORT int _wrename(const uint16_t *oldname, const uint16_t *newname)
{
    char *old_fn = wchar_to_utf8(oldname);
    char *new_fn = wchar_to_utf8(newname);
    if (!old_fn || !new_fn) { free(old_fn); free(new_fn); return -1; }
    int ret = rename(old_fn, new_fn);
    free(old_fn);
    free(new_fn);
    return ret;
}

WINAPI_EXPORT int _waccess(const uint16_t *path, int mode)
{
    char *fn = wchar_to_utf8(path);
    if (!fn) return -1;
    int ret = access(fn, mode);
    free(fn);
    return ret;
}

WINAPI_EXPORT int _wmkdir(const uint16_t *dirname)
{
    char *fn = wchar_to_utf8(dirname);
    if (!fn) return -1;
    int ret = mkdir(fn, 0755);
    free(fn);
    return ret;
}

WINAPI_EXPORT int _wrmdir(const uint16_t *dirname)
{
    char *fn = wchar_to_utf8(dirname);
    if (!fn) return -1;
    int ret = rmdir(fn);
    free(fn);
    return ret;
}

WINAPI_EXPORT int _wunlink(const uint16_t *filename)
{
    char *fn = wchar_to_utf8(filename);
    if (!fn) return -1;
    int ret = unlink(fn);
    free(fn);
    return ret;
}

/* ========== Path Manipulation ========== */

WINAPI_EXPORT char *_fullpath(char *absPath, const char *relPath, size_t maxLength)
{
    if (!relPath) return NULL;
    /* If caller provided a buffer with 0 size, MS returns NULL (EINVAL).
     * Without this guard, "maxLength - 1" underflows to SIZE_MAX. */
    if (absPath && maxLength == 0) return NULL;
    char resolved[PATH_MAX];
    if (realpath(relPath, resolved)) {
        if (absPath) {
            size_t len = strlen(resolved);
            if (len >= maxLength) len = maxLength - 1;
            memcpy(absPath, resolved, len);
            absPath[len] = '\0';
            return absPath;
        } else {
            return strdup(resolved);
        }
    }
    /* If realpath fails (file doesn't exist), just return the path as-is */
    if (absPath) {
        size_t len = strlen(relPath);
        if (len >= maxLength) len = maxLength - 1;
        memcpy(absPath, relPath, len);
        absPath[len] = '\0';
        return absPath;
    }
    return strdup(relPath);
}

WINAPI_EXPORT uint16_t *_wfullpath(uint16_t *absPath, const uint16_t *relPath, size_t maxLength)
{
    char *rel = wchar_to_utf8(relPath);
    if (!rel) return NULL;
    char resolved[PATH_MAX];
    char *result = _fullpath(resolved, rel, sizeof(resolved));
    free(rel);
    if (!result) return NULL;
    size_t len = strlen(result);
    if (!absPath) {
        absPath = malloc((len + 1) * sizeof(uint16_t));
        if (!absPath) return NULL;
        maxLength = len + 1;
    }
    for (size_t i = 0; i < len && i < maxLength - 1; i++)
        absPath[i] = (uint16_t)(uint8_t)result[i];
    absPath[len < maxLength ? len : maxLength - 1] = 0;
    return absPath;
}

WINAPI_EXPORT int _splitpath_s(const char *path,
                                char *drive, size_t driveNumberOfElements,
                                char *dir, size_t dirNumberOfElements,
                                char *fname, size_t nameNumberOfElements,
                                char *ext, size_t extNumberOfElements)
{
    if (!path) return 22;

    /* Drive: always empty on Linux */
    if (drive && driveNumberOfElements > 0) drive[0] = '\0';

    /* Find last separator */
    const char *last_sep = strrchr(path, '/');
    const char *last_bsep = strrchr(path, '\\');
    if (last_bsep && (!last_sep || last_bsep > last_sep)) last_sep = last_bsep;

    /* Directory */
    if (dir && dirNumberOfElements > 0) {
        if (last_sep) {
            size_t dlen = last_sep - path + 1;
            if (dlen >= dirNumberOfElements) dlen = dirNumberOfElements - 1;
            memcpy(dir, path, dlen);
            dir[dlen] = '\0';
        } else {
            dir[0] = '\0';
        }
    }

    /* Filename + extension */
    const char *base = last_sep ? last_sep + 1 : path;
    const char *dot = strrchr(base, '.');

    if (fname && nameNumberOfElements > 0) {
        size_t flen = dot ? (size_t)(dot - base) : strlen(base);
        if (flen >= nameNumberOfElements) flen = nameNumberOfElements - 1;
        memcpy(fname, base, flen);
        fname[flen] = '\0';
    }

    if (ext && extNumberOfElements > 0) {
        if (dot) {
            strncpy(ext, dot, extNumberOfElements - 1);
            ext[extNumberOfElements - 1] = '\0';
        } else {
            ext[0] = '\0';
        }
    }

    return 0;
}

WINAPI_EXPORT int _wsplitpath_s(const uint16_t *path,
                                 uint16_t *drive, size_t driveNumberOfElements,
                                 uint16_t *dir, size_t dirNumberOfElements,
                                 uint16_t *fname, size_t nameNumberOfElements,
                                 uint16_t *ext, size_t extNumberOfElements)
{
    char *narrow = wchar_to_utf8(path);
    if (!narrow) return 22;

    char d_drv[8], d_dir[512], d_name[256], d_ext[64];
    int ret = _splitpath_s(narrow, d_drv, sizeof(d_drv), d_dir, sizeof(d_dir),
                            d_name, sizeof(d_name), d_ext, sizeof(d_ext));
    free(narrow);
    if (ret) return ret;

    /* Convert results to wide */
    if (drive && driveNumberOfElements > 0) {
        size_t i;
        for (i = 0; d_drv[i] && i < driveNumberOfElements - 1; i++)
            drive[i] = (uint16_t)(uint8_t)d_drv[i];
        drive[i] = 0;
    }
    if (dir && dirNumberOfElements > 0) {
        size_t i;
        for (i = 0; d_dir[i] && i < dirNumberOfElements - 1; i++)
            dir[i] = (uint16_t)(uint8_t)d_dir[i];
        dir[i] = 0;
    }
    if (fname && nameNumberOfElements > 0) {
        size_t i;
        for (i = 0; d_name[i] && i < nameNumberOfElements - 1; i++)
            fname[i] = (uint16_t)(uint8_t)d_name[i];
        fname[i] = 0;
    }
    if (ext && extNumberOfElements > 0) {
        size_t i;
        for (i = 0; d_ext[i] && i < extNumberOfElements - 1; i++)
            ext[i] = (uint16_t)(uint8_t)d_ext[i];
        ext[i] = 0;
    }
    return 0;
}

WINAPI_EXPORT int _makepath_s(char *path, size_t sizeInCharacters,
                               const char *drive, const char *dir,
                               const char *fname, const char *ext)
{
    if (!path || sizeInCharacters == 0) return 22;
    /* Build up path with explicit bounds; do NOT use "sizeInCharacters -
     * strlen(path) - 1" as that underflows to SIZE_MAX on overflow. */
    size_t pos = 0;
    path[0] = '\0';
    #define _APPEND_PART(s) do {                                    \
        const char *_p = (s);                                       \
        while (_p && *_p && pos + 1 < sizeInCharacters) {           \
            path[pos++] = *_p++;                                    \
        }                                                           \
        if (_p && *_p) { path[0] = '\0'; return 34; /* ERANGE */ }  \
    } while (0)
    if (drive) _APPEND_PART(drive);
    if (dir)   _APPEND_PART(dir);
    if (fname) _APPEND_PART(fname);
    if (ext && ext[0]) {
        if (ext[0] != '.') {
            if (pos + 1 < sizeInCharacters) path[pos++] = '.';
            else { path[0] = '\0'; return 34; }
        }
        _APPEND_PART(ext);
    }
    #undef _APPEND_PART
    path[pos] = '\0';
    return 0;
}

WINAPI_EXPORT int _wmakepath_s(uint16_t *path, size_t sizeInWords,
                                const uint16_t *drive, const uint16_t *dir,
                                const uint16_t *fname, const uint16_t *ext)
{
    if (!path || sizeInWords == 0) return 22;
    path[0] = 0;
    /* Simple concatenation */
    size_t pos = 0;
    const uint16_t *parts[] = { drive, dir, fname, NULL };
    for (int i = 0; parts[i]; i++) {
        const uint16_t *s = parts[i];
        while (*s && pos < sizeInWords - 1) path[pos++] = *s++;
    }
    if (ext && ext[0]) {
        if (ext[0] != '.') { if (pos < sizeInWords - 1) path[pos++] = '.'; }
        while (*ext && pos < sizeInWords - 1) path[pos++] = *ext++;
    }
    path[pos] = 0;
    return 0;
}

/* ========== Process Argument Accessors ========== */
/* NOTE: __p___argc, __p___argv, __p__environ, __msvcrt_set_args are in msvcrt_stdio.c */

static uint16_t **g_wargv = NULL;

WINAPI_EXPORT uint16_t ***__p___wargv(void)
{
    return &g_wargv;
}

WINAPI_EXPORT uint16_t ***__p__wenviron(void)
{
    static uint16_t **wenviron = NULL;
    return &wenviron;
}

/* ========== Misc String Functions ========== */

WINAPI_EXPORT int _stricmp_l(const char *s1, const char *s2, void *locale)
{
    (void)locale;
    return strcasecmp(s1, s2);
}

WINAPI_EXPORT int _strnicmp_l(const char *s1, const char *s2, size_t count, void *locale)
{
    (void)locale;
    return strncasecmp(s1, s2, count);
}

WINAPI_EXPORT size_t _mbstrlen(const char *str)
{
    return strlen(str);
}

WINAPI_EXPORT int _mbscmp(const unsigned char *s1, const unsigned char *s2)
{
    return strcmp((const char *)s1, (const char *)s2);
}

WINAPI_EXPORT int _mbsicmp(const unsigned char *s1, const unsigned char *s2)
{
    return strcasecmp((const char *)s1, (const char *)s2);
}

WINAPI_EXPORT unsigned char *_mbschr(const unsigned char *str, unsigned int c)
{
    return (unsigned char *)strchr((const char *)str, (int)c);
}

WINAPI_EXPORT unsigned char *_mbsrchr(const unsigned char *str, unsigned int c)
{
    return (unsigned char *)strrchr((const char *)str, (int)c);
}

WINAPI_EXPORT unsigned char *_mbsstr(const unsigned char *str, const unsigned char *substr)
{
    return (unsigned char *)strstr((const char *)str, (const char *)substr);
}

WINAPI_EXPORT size_t _mbslen(const unsigned char *str)
{
    return strlen((const char *)str);
}

/* strtok_s */
WINAPI_EXPORT char *strtok_s(char *strToken, const char *strDelimit, char **context)
{
    return strtok_r(strToken, strDelimit, context);
}

WINAPI_EXPORT uint16_t *wcstok_s(uint16_t *str, const uint16_t *delimit, uint16_t **context)
{
    /* Simple wide strtok */
    if (!str && context) str = *context;
    if (!str) return NULL;

    /* Skip delimiters */
    while (*str) {
        int is_delim = 0;
        for (const uint16_t *d = delimit; *d; d++)
            if (*str == *d) { is_delim = 1; break; }
        if (!is_delim) break;
        str++;
    }
    if (!*str) { if (context) *context = str; return NULL; }

    uint16_t *start = str;
    while (*str) {
        int is_delim = 0;
        for (const uint16_t *d = delimit; *d; d++)
            if (*str == *d) { is_delim = 1; break; }
        if (is_delim) { *str++ = 0; break; }
        str++;
    }
    if (context) *context = str;
    return start;
}

/* ---------- _errno family ----------
 * Defined as a real thread-local translation helper in msvcrt_stdio.c.
 * _errno_func() is an alias used when PE imports come through the
 * *_func() indirection (older MSVCRT symbol naming).
 */
extern int *_errno(void);
extern int pe_map_errno_linux_to_win(int e);

WINAPI_EXPORT int *_errno_func(void)
{
    return _errno();
}

/* _strerror — MS-specific: returns pointer to static buffer with message
 * for CURRENT errno (ignores strErrMsg prefix in MSVC too when NULL).
 * Since libc strerror() takes Linux errno space, use real errno directly. */
WINAPI_EXPORT char *_strerror(const char *strErrMsg)
{
    (void)strErrMsg;
    return strerror(errno);
}

/* strerror_s — errnum is in Windows errno space (apps pass values from
 * MSVC errno.h).  Translate back to Linux space before calling libc
 * strerror() so the message matches the code the app expects. */
WINAPI_EXPORT int strerror_s(char *buffer, size_t sizeInBytes, int errnum)
{
    if (!buffer || sizeInBytes == 0) return 22;
    extern int pe_map_errno_win_to_linux(int e);
    int linux_errnum = pe_map_errno_win_to_linux(errnum);
    const char *msg = strerror(linux_errnum);
    if (!msg) msg = "Unknown error";
    size_t len = strlen(msg);
    if (len >= sizeInBytes) len = sizeInBytes - 1;
    memcpy(buffer, msg, len);
    buffer[len] = '\0';
    return 0;
}

/* _wcserror_s — wide-char error message lookup.  Same Windows-space
 * translation as strerror_s; converts ASCII message to UTF-16. */
WINAPI_EXPORT int _wcserror_s(uint16_t *buffer, size_t sizeInWords, int errnum)
{
    if (!buffer || sizeInWords == 0) return 22;
    extern int pe_map_errno_win_to_linux(int e);
    int linux_errnum = pe_map_errno_win_to_linux(errnum);
    const char *msg = strerror(linux_errnum);
    if (!msg) msg = "Unknown error";
    size_t i = 0;
    for (; msg[i] && i + 1 < sizeInWords; i++)
        buffer[i] = (uint16_t)(unsigned char)msg[i];
    buffer[i] = 0;
    return 0;
}

/* _wcserror — non-secure form, returns pointer to thread-local buffer. */
WINAPI_EXPORT uint16_t *_wcserror(int errnum)
{
    static __thread uint16_t wbuf[128];
    _wcserror_s(wbuf, 128, errnum);
    return wbuf;
}

WINAPI_EXPORT uint64_t _wcstoui64(const uint16_t *nptr, uint16_t **endptr, int base)
{
    /* MS declares this returning unsigned __int64.  The previous
     * "int" return truncated values > 2^31 and ignored endptr entirely,
     * breaking any caller that parses large hex or chains tokens. */
    if (!nptr) { if (endptr) *endptr = NULL; return 0; }
    char buf[128];
    int i = 0;
    while (nptr[i] && i < 127) { buf[i] = (char)nptr[i]; i++; }
    buf[i] = '\0';
    char *ep = NULL;
    uint64_t r = (uint64_t)strtoull(buf, &ep, base);
    if (endptr) *endptr = (uint16_t *)(nptr + (ep - buf));
    return r;
}

/* ================================================================
 * _o_ prefixed UCRT private function aliases.
 * Real Windows apps (notepad, calc, Steam) import these from ucrtbase.dll.
 * They are identical to their non-prefixed counterparts.
 * ================================================================ */

/* Secure string functions */
WINAPI_EXPORT int _o_strcpy_s(char *d, size_t n, const char *s) { return strcpy_s(d, n, s); }
WINAPI_EXPORT int _o_strcat_s(char *d, size_t n, const char *s) { return strcat_s(d, n, s); }
WINAPI_EXPORT int _o_strncpy_s(char *d, size_t dn, const char *s, size_t c) { return strncpy_s(d, dn, s, c); }
WINAPI_EXPORT int _o_strncat_s(char *d, size_t dn, const char *s, size_t c) { return strncat_s(d, dn, s, c); }
WINAPI_EXPORT int _o_memcpy_s(void *d, size_t dn, const void *s, size_t c) { return memcpy_s(d, dn, s, c); }
WINAPI_EXPORT int _o_memmove_s(void *d, size_t dn, const void *s, size_t c) { return memmove_s(d, dn, s, c); }
WINAPI_EXPORT int _o_wcscpy_s(uint16_t *d, size_t n, const uint16_t *s) { return wcscpy_s(d, n, s); }
WINAPI_EXPORT int _o_wcscat_s(uint16_t *d, size_t n, const uint16_t *s) { return wcscat_s(d, n, s); }
WINAPI_EXPORT int _o_wcsncpy_s(uint16_t *d, size_t dn, const uint16_t *s, size_t c) { return wcsncpy_s(d, dn, s, c); }

/* Wide string manipulation */
WINAPI_EXPORT uint16_t *_o__wcsdup(const uint16_t *s) { return _wcsdup(s); }
WINAPI_EXPORT uint16_t *_o__wcslwr(uint16_t *s) { return _wcslwr(s); }
WINAPI_EXPORT int _o__wcslwr_s(uint16_t *s, size_t n) { return _wcslwr_s(s, n); }
WINAPI_EXPORT uint16_t *_o__wcsupr(uint16_t *s) { return _wcsupr(s); }
WINAPI_EXPORT int _o__wcsupr_s(uint16_t *s, size_t n) { return _wcsupr_s(s, n); }
WINAPI_EXPORT int _o__wcsnicmp(const uint16_t *a, const uint16_t *b, size_t c) { return _wcsnicmp(a, b, c); }
WINAPI_EXPORT char *_o__strrev(char *s) { return _strrev(s); }
WINAPI_EXPORT uint16_t *_o__wcsrev(uint16_t *s) { return _wcsrev(s); }
WINAPI_EXPORT char *_o__strlwr(char *s) { return _strlwr(s); }
WINAPI_EXPORT char *_o__strupr(char *s) { return _strupr(s); }

/* Conversion functions */
WINAPI_EXPORT int _o_wcstombs_s(size_t *r, char *d, size_t dn, const uint16_t *s, size_t c) { return wcstombs_s(r, d, dn, s, c); }
WINAPI_EXPORT int _o_mbstowcs_s(size_t *r, uint16_t *d, size_t dn, const char *s, size_t c) { return mbstowcs_s(r, d, dn, s, c); }
WINAPI_EXPORT int _o__itoa_s(int v, char *b, size_t n, int r) { return _itoa_s(v, b, n, r); }
WINAPI_EXPORT int _o__ltoa_s(long v, char *b, size_t n, int r) { return _ltoa_s(v, b, n, r); }
WINAPI_EXPORT int _o__ultoa_s(unsigned long v, char *b, size_t n, int r) { return _ultoa_s(v, b, n, r); }
WINAPI_EXPORT char *_o__i64toa(long long v, char *b, int r) { return _i64toa(v, b, r); }
WINAPI_EXPORT int _o__i64toa_s(long long v, char *b, size_t n, int r) { return _i64toa_s(v, b, n, r); }
WINAPI_EXPORT long long _o__atoi64(const char *s) { return _atoi64(s); }
WINAPI_EXPORT long long _o__strtoi64(const char *s, char **e, int b) { return _strtoi64(s, e, b); }
WINAPI_EXPORT unsigned long long _o__strtoui64(const char *s, char **e, int b) { return _strtoui64(s, e, b); }
WINAPI_EXPORT int _o__itow_s(int v, uint16_t *b, size_t n, int r) { return _itow_s(v, b, n, r); }
WINAPI_EXPORT int _o__wtoi(const uint16_t *s) { return _wtoi(s); }
WINAPI_EXPORT long long _o__wtoi64(const uint16_t *s) { return _wtoi64(s); }

/* Printf/sprintf variants */
WINAPI_EXPORT int _o__vscprintf(const char *f, __builtin_ms_va_list a) { return _vscprintf(f, a); }
WINAPI_EXPORT int _o__scprintf(const char *f, ...) { __builtin_ms_va_list a; __builtin_ms_va_start(a, f); int r = ms_abi_vformat(NULL, NULL, 0, f, a); __builtin_ms_va_end(a); return r; }

/* Wide file I/O */
WINAPI_EXPORT FILE *_o__wfopen(const uint16_t *n, const uint16_t *m) { return _wfopen(n, m); }
WINAPI_EXPORT int _o__wfopen_s(FILE **f, const uint16_t *n, const uint16_t *m) { return _wfopen_s(f, n, m); }
WINAPI_EXPORT int _o__waccess(const uint16_t *p, int m) { return _waccess(p, m); }

/* Path manipulation */
WINAPI_EXPORT char *_o__fullpath(char *a, const char *r, size_t m) { return _fullpath(a, r, m); }
WINAPI_EXPORT uint16_t *_o__wfullpath(uint16_t *a, const uint16_t *r, size_t m) { return _wfullpath(a, r, m); }

/* Multi-byte string */
WINAPI_EXPORT size_t _o__mbstrlen(const char *s) { return _mbstrlen(s); }
WINAPI_EXPORT int _o__mbscmp(const unsigned char *a, const unsigned char *b) { return _mbscmp(a, b); }
WINAPI_EXPORT int _o__mbsicmp(const unsigned char *a, const unsigned char *b) { return _mbsicmp(a, b); }

/* Locale-sensitive comparison */
WINAPI_EXPORT int _o__stricmp(const char *a, const char *b) { return strcasecmp(a, b); }
WINAPI_EXPORT int _o__strnicmp(const char *a, const char *b, size_t n) { return strncasecmp(a, b, n); }
WINAPI_EXPORT char *_o__strdup(const char *s) { return strdup(s); }

/* Token */
WINAPI_EXPORT char *_o_strtok_s(char *s, const char *d, char **c) { return strtok_s(s, d, c); }
WINAPI_EXPORT uint16_t *_o_wcstok_s(uint16_t *s, const uint16_t *d, uint16_t **c) { return wcstok_s(s, d, c); }

/* Error string */
WINAPI_EXPORT int _o_strerror_s(char *b, size_t n, int e) { return strerror_s(b, n, e); }
WINAPI_EXPORT int _o__wcserror_s(uint16_t *b, size_t n, int e) { return _wcserror_s(b, n, e); }
WINAPI_EXPORT uint16_t *_o__wcserror(int e) { return _wcserror(e); }
WINAPI_EXPORT char *_o__strerror(const char *m) { return _strerror(m); }

WINAPI_EXPORT long _o_wcstol(const uint16_t *s, uint16_t **e, int b) { return pe_wcstol(s, e, b); }
WINAPI_EXPORT unsigned long _o_wcstoul(const uint16_t *s, uint16_t **e, int b) { return pe_wcstoul(s, e, b); }
WINAPI_EXPORT double _o_wcstod(const uint16_t *s, uint16_t **e) { return pe_wcstod(s, e); }
WINAPI_EXPORT float _o_wcstof(const uint16_t *s, uint16_t **e) { return pe_wcstof(s, e); }
WINAPI_EXPORT long long _o_wcstoll(const uint16_t *s, uint16_t **e, int b) { return pe_wcstoll(s, e, b); }
WINAPI_EXPORT unsigned long long _o_wcstoull(const uint16_t *s, uint16_t **e, int b) { return pe_wcstoull(s, e, b); }
WINAPI_EXPORT double _o__wtof(const uint16_t *s) { return _wtof(s); }

/* ================================================================
 * Locale, codepage, and runtime utility functions
 *
 * Required by DXVK d3d9.dll and other modern Win32 apps that import
 * from api-ms-win-crt-locale-l1-1-0.dll, api-ms-win-crt-runtime-l1-1-0.dll,
 * api-ms-win-crt-utility-l1-1-0.dll, etc.
 * ================================================================ */

#include <time.h>
#include <setjmp.h>
#include <fcntl.h>

/*
 * ___lc_codepage_func — return the active locale codepage.
 * We always return 65001 (UTF-8) since the PE compat layer runs on Linux
 * which is natively UTF-8.
 */
WINAPI_EXPORT uint32_t ___lc_codepage_func(void)
{
    return 65001; /* CP_UTF8 */
}

/*
 * ___mb_cur_max_func — return maximum bytes per multibyte character.
 * For UTF-8 this is 4.
 */
WINAPI_EXPORT int ___mb_cur_max_func(void)
{
    return 4; /* UTF-8 max bytes per character */
}

/*
 * _tzset — initialize timezone from TZ environment variable.
 * Forwards to POSIX tzset().
 */
WINAPI_EXPORT void _tzset(void)
{
    tzset();
}

/*
 * rand_s — generate a cryptographically random unsigned int.
 * Reads from /dev/urandom for true randomness.
 * Returns 0 on success, non-zero on failure.
 */
WINAPI_EXPORT int rand_s(unsigned int *randomValue)
{
    if (!randomValue) return 22; /* EINVAL */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 5; /* EIO */
    ssize_t n = read(fd, randomValue, sizeof(*randomValue));
    close(fd);
    if (n != (ssize_t)sizeof(*randomValue)) return 5;
    return 0;
}

/*
 * _crt_at_quick_exit — register a function to be called at quick_exit().
 * Maps to C11 at_quick_exit().
 */
WINAPI_EXPORT int _crt_at_quick_exit(void (*func)(void))
{
    if (!func) return 22;
    return at_quick_exit(func);
}

/*
 * _execute_onexit_table — execute all registered onexit callbacks.
 * Used by UCRT during CRT shutdown. We stub this since our onexit
 * functions are registered via atexit() which libc handles.
 */
WINAPI_EXPORT int _execute_onexit_table(void *table)
{
    (void)table;
    return 0; /* Success — atexit handles cleanup */
}

/*
 * __intrinsic_setjmpex — MSVC intrinsic setjmp variant.
 * Used by SEH (Structured Exception Handling) infrastructure.
 * We use the standard setjmp as a best-effort approximation.
 */
WINAPI_EXPORT int __intrinsic_setjmpex(jmp_buf buf)
{
    if (!buf) return 0;
    return setjmp(buf);
}
