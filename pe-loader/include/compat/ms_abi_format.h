/*
 * ms_abi_format.h - MS ABI printf/scanf format helpers
 *
 * These static helper functions bridge the Windows x86-64 calling
 * convention (ms_abi) to libc I/O. They are defined as 'static' so
 * each translation unit that includes this header gets its own copy
 * with no linker conflicts.
 *
 * USAGE: Include AFTER <stdio.h>, <stdint.h>, and <string.h>.
 *        Used by both pe_import.c (loader) and msvcrt_stdio.c (DLL stub).
 *
 * WHY: Windows variadic functions use a different va_list layout from
 *      Linux. ms_abi va_list is a simple char* with 8-byte-aligned slots,
 *      while sysv_abi va_list is a 24-byte struct. We cannot call libc
 *      printf/scanf with a Windows va_list; instead we use these helpers.
 */

#ifndef MS_ABI_FORMAT_H
#define MS_ABI_FORMAT_H

/* wchar.h is included by files that need ms_abi_vwscan (e.g., msvcrt_stdio.c)
 * but NOT here globally — it conflicts with uint16_t-based wcstol/etc. in
 * msvcrt_string.c which redefines these functions for Windows WCHAR (2-byte). */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/*
 * MS_VA_ARG - extract a typed argument from ms_abi va_list.
 * On Windows x86-64, va_list is char* with each slot 8 bytes wide.
 * GCC provides __builtin_ms_va_start/end but NOT __builtin_ms_va_arg,
 * so we manually advance the pointer.
 */
#ifndef MS_VA_ARG
#define MS_VA_ARG(ap, type) \
    (*(type *)((ap) += 8, (ap) - 8))
#endif

/*
 * ms_abi_vformat - internal ms_abi-safe printf engine.
 *
 * Writes to 'out' (FILE*) or 'buf' (char buffer); exactly one must be
 * non-NULL. Returns the number of characters written (or would write).
 *
 * Supports: %d %i %u %x %X %o %p %s %S %c %f %F %e %E %g %G %% %n
 * Modifiers: - 0 + space # (flags), width, .precision, l ll z I64
 */
static int ms_abi_vformat(FILE *out, char *buf, size_t bufsz,
                          const char *fmt, __builtin_ms_va_list ap)
{
    int total = 0;
    char tmp[64];

    #define _EMIT_CHAR(c) do { \
        if (out) { fputc((c), out); } \
        else if (buf && (size_t)total < bufsz - 1) { buf[total] = (c); } \
        total++; \
    } while(0)

    #define _EMIT_STR(s) do { \
        const char *_s = (s); \
        while (*_s) { _EMIT_CHAR(*_s); _s++; } \
    } while(0)

    while (*fmt) {
        if (*fmt != '%') { _EMIT_CHAR(*fmt); fmt++; continue; }
        fmt++; /* skip % */

        /* Flags */
        int left_align = 0, zero_pad = 0, plus_sign = 0, space_sign = 0, hash = 0;
        for (;;) {
            if      (*fmt == '-') { left_align = 1; fmt++; }
            else if (*fmt == '0') { zero_pad   = 1; fmt++; }
            else if (*fmt == '+') { plus_sign  = 1; fmt++; }
            else if (*fmt == ' ') { space_sign = 1; fmt++; }
            else if (*fmt == '#') { hash       = 1; fmt++; }
            else break;
        }
        (void)left_align; (void)plus_sign; (void)space_sign; (void)hash;

        /* Width */
        int width = 0;
        if (*fmt == '*') { width = MS_VA_ARG(ap, int); fmt++; }
        else { while (*fmt >= '0' && *fmt <= '9') { width = width*10 + (*fmt - '0'); fmt++; } }
        if (width > 4096) width = 4096;  /* Prevent excessive padding output */

        /* Precision */
        int prec = -1;
        if (*fmt == '.') {
            fmt++; prec = 0;
            if (*fmt == '*') { prec = MS_VA_ARG(ap, int); fmt++; }
            else { while (*fmt >= '0' && *fmt <= '9') { prec = prec*10 + (*fmt - '0'); fmt++; } }
        }

        /* Length modifiers */
        int len_l = 0, len_h = 0, len_ll = 0, len_z = 0, len_I64 = 0;
        if      (*fmt == 'l') { len_l = 1; fmt++; if (*fmt == 'l') { len_ll = 1; fmt++; } }
        else if (*fmt == 'h') { len_h = 1; fmt++; if (*fmt == 'h') { fmt++; } }
        else if (*fmt == 'z') { len_z = 1; fmt++; }
        else if (*fmt == 'I' && fmt[1] == '6' && fmt[2] == '4') { len_I64 = 1; fmt += 3; }
        (void)len_h;

        char padc = zero_pad ? '0' : ' ';
        int len;

        switch (*fmt) {
        case 'd': case 'i': {
            long long val;
            if (len_ll || len_I64) val = MS_VA_ARG(ap, long long);
            else if (len_l || len_z) val = MS_VA_ARG(ap, long);
            else val = MS_VA_ARG(ap, int);
            len = snprintf(tmp, sizeof(tmp), "%lld", val);
            for (int i = len; i < width; i++) _EMIT_CHAR(padc);
            _EMIT_STR(tmp);
            break;
        }
        case 'u': {
            unsigned long long val;
            if (len_ll || len_I64) val = MS_VA_ARG(ap, unsigned long long);
            else if (len_l || len_z) val = MS_VA_ARG(ap, unsigned long);
            else val = MS_VA_ARG(ap, unsigned int);
            len = snprintf(tmp, sizeof(tmp), "%llu", val);
            for (int i = len; i < width; i++) _EMIT_CHAR(padc);
            _EMIT_STR(tmp);
            break;
        }
        case 'x': case 'X': {
            unsigned long long val;
            if (len_ll || len_I64) val = MS_VA_ARG(ap, unsigned long long);
            else if (len_l || len_z) val = MS_VA_ARG(ap, unsigned long);
            else val = MS_VA_ARG(ap, unsigned int);
            len = snprintf(tmp, sizeof(tmp),
                           *fmt == 'X' ? "%llX" : "%llx", val);
            for (int i = len; i < width; i++) _EMIT_CHAR(padc);
            _EMIT_STR(tmp);
            break;
        }
        case 'o': {
            unsigned long long val;
            if (len_ll || len_I64) val = MS_VA_ARG(ap, unsigned long long);
            else if (len_l) val = MS_VA_ARG(ap, unsigned long);
            else val = MS_VA_ARG(ap, unsigned int);
            len = snprintf(tmp, sizeof(tmp), "%llo", val);
            _EMIT_STR(tmp);
            break;
        }
        case 'p': {
            void *val = MS_VA_ARG(ap, void *);
            len = snprintf(tmp, sizeof(tmp), "0x%llx",
                           (unsigned long long)(uintptr_t)val);
            _EMIT_STR(tmp);
            break;
        }
        case 's': {
            const char *val = MS_VA_ARG(ap, const char *);
            if (!val) val = "(null)";
            if (prec >= 0) {
                int slen = 0;
                while (slen < prec && val[slen]) { _EMIT_CHAR(val[slen]); slen++; }
            } else {
                _EMIT_STR(val);
            }
            break;
        }
        case 'S': { /* Wide string (%S in Windows printf) */
            const uint16_t *val = MS_VA_ARG(ap, const uint16_t *);
            if (!val) { _EMIT_STR("(null)"); }
            else {
                while (*val) {
                    if (*val < 128) _EMIT_CHAR((char)*val);
                    else _EMIT_CHAR('?');
                    val++;
                }
            }
            break;
        }
        case 'c': {
            int val = MS_VA_ARG(ap, int);
            _EMIT_CHAR((char)val);
            break;
        }
        case 'f': case 'F': {
            double val = MS_VA_ARG(ap, double);
            if (prec >= 0)
                len = snprintf(tmp, sizeof(tmp), "%.*f", prec, val);
            else
                len = snprintf(tmp, sizeof(tmp), "%f", val);
            _EMIT_STR(tmp);
            break;
        }
        case 'e': case 'E': {
            double val = MS_VA_ARG(ap, double);
            len = snprintf(tmp, sizeof(tmp), *fmt == 'E' ? "%E" : "%e", val);
            _EMIT_STR(tmp);
            break;
        }
        case 'g': case 'G': {
            double val = MS_VA_ARG(ap, double);
            len = snprintf(tmp, sizeof(tmp), *fmt == 'G' ? "%G" : "%g", val);
            _EMIT_STR(tmp);
            break;
        }
        case '%':
            _EMIT_CHAR('%');
            break;
        case 'n': {
            int *val = MS_VA_ARG(ap, int *);
            if (val) *val = total;
            break;
        }
        case '\0':
            goto done;
        default:
            _EMIT_CHAR('%');
            _EMIT_CHAR(*fmt);
            break;
        }
        fmt++;
    }
done:
    if (buf && bufsz > 0) {
        size_t idx = ((size_t)total < bufsz - 1) ? (size_t)total : bufsz - 1;
        buf[idx] = '\0';
    }
    #undef _EMIT_CHAR
    #undef _EMIT_STR
    return total;
}

/*
 * ms_abi_vscan - scanf bridge for MS ABI va_list.
 *
 * All scanf arguments are output pointers (void*), 8 bytes each in the
 * MS ABI stack frame. We extract up to 16 upfront and pass them to the
 * libc fscanf/sscanf which ignores extras. Handles up to 16 format items.
 */
__attribute__((unused))
static int ms_abi_vscan(FILE *in, const char *src,
                        const char *fmt, __builtin_ms_va_list ap)
{
    void *a0  = MS_VA_ARG(ap, void*), *a1  = MS_VA_ARG(ap, void*);
    void *a2  = MS_VA_ARG(ap, void*), *a3  = MS_VA_ARG(ap, void*);
    void *a4  = MS_VA_ARG(ap, void*), *a5  = MS_VA_ARG(ap, void*);
    void *a6  = MS_VA_ARG(ap, void*), *a7  = MS_VA_ARG(ap, void*);
    void *a8  = MS_VA_ARG(ap, void*), *a9  = MS_VA_ARG(ap, void*);
    void *a10 = MS_VA_ARG(ap, void*), *a11 = MS_VA_ARG(ap, void*);
    void *a12 = MS_VA_ARG(ap, void*), *a13 = MS_VA_ARG(ap, void*);
    void *a14 = MS_VA_ARG(ap, void*), *a15 = MS_VA_ARG(ap, void*);
    if (in)
        return fscanf(in, fmt,
            a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15);
    else
        return sscanf(src, fmt,
            a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15);
}

/*
 * ms_abi_vwscan - wide-char scanf bridge for MS ABI va_list.
 *
 * Only available when <wchar.h> is included BEFORE this header.
 * msvcrt_stdio.c includes it; msvcrt_string.c does NOT (it defines
 * its own uint16_t-based wcstol/etc. that would conflict).
 */
#ifdef _WCHAR_H
__attribute__((unused))
static int ms_abi_vwscan(FILE *in, const wchar_t *src,
                         const wchar_t *fmt, __builtin_ms_va_list ap)
{
    void *a0  = MS_VA_ARG(ap, void*), *a1  = MS_VA_ARG(ap, void*);
    void *a2  = MS_VA_ARG(ap, void*), *a3  = MS_VA_ARG(ap, void*);
    void *a4  = MS_VA_ARG(ap, void*), *a5  = MS_VA_ARG(ap, void*);
    void *a6  = MS_VA_ARG(ap, void*), *a7  = MS_VA_ARG(ap, void*);
    void *a8  = MS_VA_ARG(ap, void*), *a9  = MS_VA_ARG(ap, void*);
    void *a10 = MS_VA_ARG(ap, void*), *a11 = MS_VA_ARG(ap, void*);
    void *a12 = MS_VA_ARG(ap, void*), *a13 = MS_VA_ARG(ap, void*);
    void *a14 = MS_VA_ARG(ap, void*), *a15 = MS_VA_ARG(ap, void*);
    if (in)
        return fwscanf(in, fmt,
            a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15);
    else
        return swscanf(src, fmt,
            a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15);
}
#endif /* _WCHAR_H */

#endif /* MS_ABI_FORMAT_H */
