/*
 * kernel32_string.c - String conversion functions
 *
 * MultiByteToWideChar, WideCharToMultiByte, lstrlen, lstrcpy, etc.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <wchar.h>
#include <wctype.h>
#include <dlfcn.h>
#include "common/dll_common.h"

/* Code page constants */
#define CP_ACP      0
#define CP_UTF8     65001
#define CP_UTF7     65000

/* Flag constants */
#define MB_ERR_INVALID_CHARS  0x00000008

/* Error codes */
#ifndef ERROR_INSUFFICIENT_BUFFER
#define ERROR_INSUFFICIENT_BUFFER  122
#endif
#ifndef ERROR_NO_UNICODE_TRANSLATION
#define ERROR_NO_UNICODE_TRANSLATION  1113
#endif

/*
 * Decode a single UTF-8 sequence starting at src.
 * Returns the Unicode codepoint, advances *consumed by bytes read.
 * Returns 0xFFFD (replacement char) on invalid sequences.
 */
static unsigned int utf8_decode(const unsigned char *src, int avail, int *consumed)
{
    unsigned int cp;
    int expect;

    if (src[0] < 0x80) {
        *consumed = 1;
        return src[0];
    } else if ((src[0] & 0xE0) == 0xC0) {
        cp = src[0] & 0x1F;
        expect = 2;
    } else if ((src[0] & 0xF0) == 0xE0) {
        cp = src[0] & 0x0F;
        expect = 3;
    } else if ((src[0] & 0xF8) == 0xF0) {
        cp = src[0] & 0x07;
        expect = 4;
    } else {
        *consumed = 1;
        return 0xFFFD;
    }

    if (expect > avail) {
        *consumed = 1;
        return 0xFFFD;
    }

    for (int i = 1; i < expect; i++) {
        if ((src[i] & 0xC0) != 0x80) {
            *consumed = i;
            return 0xFFFD;
        }
        cp = (cp << 6) | (src[i] & 0x3F);
    }
    *consumed = expect;
    return cp;
}

WINAPI_EXPORT int MultiByteToWideChar(
    UINT CodePage,
    DWORD dwFlags,
    LPCSTR lpMultiByteStr,
    int cbMultiByte,
    LPWSTR lpWideCharStr,
    int cchWideChar)
{
    if (!lpMultiByteStr) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    int src_len = (cbMultiByte == -1) ? (int)strlen(lpMultiByteStr) + 1 : cbMultiByte;

    /* For non-UTF-8 code pages, fall back to byte-for-byte (Latin-1) */
    if (CodePage != CP_UTF8 && CodePage != CP_ACP) {
        int need = src_len;
        if (cchWideChar == 0) return need;
        if (need > cchWideChar) {
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        for (int i = 0; i < need; i++)
            lpWideCharStr[i] = (WCHAR)(unsigned char)lpMultiByteStr[i];
        return need;
    }

    /* UTF-8 decode */
    const unsigned char *src = (const unsigned char *)lpMultiByteStr;
    int si = 0, di = 0;
    int had_invalid = 0;

    /* First pass: count required wide chars */
    if (cchWideChar == 0) {
        int count = 0;
        while (si < src_len) {
            if (src[si] == 0 && cbMultiByte == -1) { count++; break; }
            int consumed;
            unsigned int cp = utf8_decode(src + si, src_len - si, &consumed);
            if (cp == 0xFFFD) had_invalid = 1;
            si += consumed;
            if (cp > 0xFFFF) count += 2; /* surrogate pair */
            else count++;
        }
        if (had_invalid && (dwFlags & MB_ERR_INVALID_CHARS)) {
            set_last_error(ERROR_NO_UNICODE_TRANSLATION);
            return 0;
        }
        return count;
    }

    /* Second pass: actually decode */
    si = 0;
    while (si < src_len) {
        int consumed;
        unsigned int cp = utf8_decode(src + si, src_len - si, &consumed);
        if (cp == 0xFFFD) had_invalid = 1;
        si += consumed;
        if (cp > 0xFFFF) {
            /* Encode as UTF-16 surrogate pair */
            if (di + 2 > cchWideChar) {
                set_last_error(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            cp -= 0x10000;
            lpWideCharStr[di++] = (WCHAR)(0xD800 | (cp >> 10));
            lpWideCharStr[di++] = (WCHAR)(0xDC00 | (cp & 0x3FF));
        } else {
            if (di + 1 > cchWideChar) {
                set_last_error(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            lpWideCharStr[di++] = (WCHAR)cp;
        }
    }

    if (had_invalid && (dwFlags & MB_ERR_INVALID_CHARS)) {
        set_last_error(ERROR_NO_UNICODE_TRANSLATION);
        return 0;
    }

    return di;
}

WINAPI_EXPORT int WideCharToMultiByte(
    UINT CodePage,
    DWORD dwFlags,
    LPCWSTR lpWideCharStr,
    int cchWideChar,
    LPSTR lpMultiByteStr,
    int cbMultiByte,
    LPCSTR lpDefaultChar,
    BOOL *lpUsedDefaultChar)
{
    (void)dwFlags;
    (void)lpDefaultChar;

    if (lpUsedDefaultChar)
        *lpUsedDefaultChar = FALSE;

    if (!lpWideCharStr) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    /* Calculate source length */
    int src_len;
    if (cchWideChar == -1) {
        src_len = 0;
        while (lpWideCharStr[src_len])
            src_len++;
        src_len++; /* Include null */
    } else {
        src_len = cchWideChar;
    }

    /* For non-UTF-8 code pages, fall back to simple truncation */
    if (CodePage != CP_UTF8 && CodePage != CP_ACP) {
        if (cbMultiByte == 0) return src_len;
        if (src_len > cbMultiByte) {
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        for (int i = 0; i < src_len; i++) {
            if (lpWideCharStr[i] < 0x80)
                lpMultiByteStr[i] = (char)lpWideCharStr[i];
            else {
                lpMultiByteStr[i] = '?';
                if (lpUsedDefaultChar) *lpUsedDefaultChar = TRUE;
            }
        }
        return src_len;
    }

    /* UTF-8 encode */
    int si = 0, di = 0;

    /* Count mode */
    if (cbMultiByte == 0) {
        int count = 0;
        for (si = 0; si < src_len; si++) {
            unsigned int cp = (unsigned int)(unsigned short)lpWideCharStr[si];
            /* Handle surrogate pairs */
            if (cp >= 0xD800 && cp <= 0xDBFF && si + 1 < src_len) {
                unsigned int lo = (unsigned int)(unsigned short)lpWideCharStr[si + 1];
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    si++;
                }
            }
            if (cp < 0x80) count += 1;
            else if (cp < 0x800) count += 2;
            else if (cp < 0x10000) count += 3;
            else count += 4;
        }
        return count;
    }

    /* Encode into buffer */
    unsigned char *out = (unsigned char *)lpMultiByteStr;
    for (si = 0; si < src_len; si++) {
        unsigned int cp = (unsigned int)(unsigned short)lpWideCharStr[si];
        /* Handle surrogate pairs */
        if (cp >= 0xD800 && cp <= 0xDBFF && si + 1 < src_len) {
            unsigned int lo = (unsigned int)(unsigned short)lpWideCharStr[si + 1];
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                si++;
            }
        }

        int need;
        if (cp < 0x80) need = 1;
        else if (cp < 0x800) need = 2;
        else if (cp < 0x10000) need = 3;
        else need = 4;

        if (di + need > cbMultiByte) {
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }

        if (cp < 0x80) {
            out[di++] = (unsigned char)cp;
        } else if (cp < 0x800) {
            out[di++] = 0xC0 | (cp >> 6);
            out[di++] = 0x80 | (cp & 0x3F);
        } else if (cp < 0x10000) {
            out[di++] = 0xE0 | (cp >> 12);
            out[di++] = 0x80 | ((cp >> 6) & 0x3F);
            out[di++] = 0x80 | (cp & 0x3F);
        } else {
            out[di++] = 0xF0 | (cp >> 18);
            out[di++] = 0x80 | ((cp >> 12) & 0x3F);
            out[di++] = 0x80 | ((cp >> 6) & 0x3F);
            out[di++] = 0x80 | (cp & 0x3F);
        }
    }

    return di;
}

WINAPI_EXPORT int lstrlenA(LPCSTR lpString)
{
    if (!lpString) return 0;
    return (int)strlen(lpString);
}

WINAPI_EXPORT int lstrlenW(LPCWSTR lpString)
{
    if (!lpString) return 0;
    int len = 0;
    while (lpString[len]) len++;
    return len;
}

/* NOTE: lstrcpyA is intentionally unbounded per Windows API contract.
 * Callers must ensure lpString1 is large enough. */
WINAPI_EXPORT LPSTR lstrcpyA(LPSTR lpString1, LPCSTR lpString2)
{
    if (!lpString1 || !lpString2) return lpString1;
    return strcpy(lpString1, lpString2);
}

WINAPI_EXPORT LPSTR lstrcpynA(LPSTR lpString1, LPCSTR lpString2, int iMaxLength)
{
    if (!lpString1 || iMaxLength <= 0) return lpString1;
    if (!lpString2) { lpString1[0] = '\0'; return lpString1; }
    strncpy(lpString1, lpString2, iMaxLength - 1);
    lpString1[iMaxLength - 1] = '\0';
    return lpString1;
}

/* NOTE: lstrcatA is intentionally unbounded per Windows API contract.
 * Callers must ensure lpString1 is large enough. */
WINAPI_EXPORT LPSTR lstrcatA(LPSTR lpString1, LPCSTR lpString2)
{
    if (!lpString1 || !lpString2) return lpString1;
    return strcat(lpString1, lpString2);
}

WINAPI_EXPORT int lstrcmpA(LPCSTR lpString1, LPCSTR lpString2)
{
    if (!lpString1 && !lpString2) return 0;
    if (!lpString1) return -1;
    if (!lpString2) return 1;
    return strcmp(lpString1, lpString2);
}

WINAPI_EXPORT int lstrcmpiA(LPCSTR lpString1, LPCSTR lpString2)
{
    if (!lpString1 && !lpString2) return 0;
    if (!lpString1) return -1;
    if (!lpString2) return 1;
    return strcasecmp(lpString1, lpString2);
}

WINAPI_EXPORT BOOL IsValidCodePage(UINT CodePage)
{
    (void)CodePage;
    return TRUE;
}

WINAPI_EXPORT int CompareStringA(
    DWORD Locale, DWORD dwCmpFlags,
    LPCSTR lpString1, int cchCount1,
    LPCSTR lpString2, int cchCount2)
{
    (void)Locale;

    if (!lpString1 || !lpString2) return 0; /* Failure */
    int len1 = (cchCount1 == -1) ? (int)strlen(lpString1) : cchCount1;
    int len2 = (cchCount2 == -1) ? (int)strlen(lpString2) : cchCount2;
    int min_len = len1 < len2 ? len1 : len2;

    int result;
    if (dwCmpFlags & 0x1) /* NORM_IGNORECASE */
        result = strncasecmp(lpString1, lpString2, min_len);
    else
        result = strncmp(lpString1, lpString2, min_len);

    if (result == 0) {
        if (len1 < len2) return 1;      /* CSTR_LESS_THAN */
        if (len1 > len2) return 3;      /* CSTR_GREATER_THAN */
        return 2;                         /* CSTR_EQUAL */
    }
    return result < 0 ? 1 : 3;
}

WINAPI_EXPORT int CompareStringW(
    DWORD Locale, DWORD dwCmpFlags,
    LPCWSTR lpString1, int cchCount1,
    LPCWSTR lpString2, int cchCount2)
{
    (void)Locale;

    if (!lpString1 || !lpString2) return 0; /* Failure */
    int len1 = cchCount1;
    int len2 = cchCount2;
    if (len1 == -1) { len1 = 0; while (lpString1[len1]) len1++; }
    if (len2 == -1) { len2 = 0; while (lpString2[len2]) len2++; }

    int ignore_case = (dwCmpFlags & 0x1); /* NORM_IGNORECASE */
    int min_len = len1 < len2 ? len1 : len2;
    for (int i = 0; i < min_len; i++) {
        WCHAR c1 = lpString1[i];
        WCHAR c2 = lpString2[i];
        if (ignore_case) {
            if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
            if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
        }
        if (c1 < c2) return 1;
        if (c1 > c2) return 3;
    }
    if (len1 < len2) return 1;
    if (len1 > len2) return 3;
    return 2;
}

/* ---------- CompareStringOrdinal ---------- */

WINAPI_EXPORT int CompareStringOrdinal(
    LPCWSTR lpString1, int cchCount1,
    LPCWSTR lpString2, int cchCount2,
    BOOL bIgnoreCase)
{
    if (!lpString1 || !lpString2) return 0; /* Failure */
    int len1 = cchCount1;
    int len2 = cchCount2;
    if (len1 == -1) { len1 = 0; while (lpString1[len1]) len1++; }
    if (len2 == -1) { len2 = 0; while (lpString2[len2]) len2++; }

    int min_len = len1 < len2 ? len1 : len2;
    for (int i = 0; i < min_len; i++) {
        WCHAR c1 = lpString1[i];
        WCHAR c2 = lpString2[i];
        if (bIgnoreCase) {
            if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
            if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
        }
        if (c1 < c2) return 1; /* CSTR_LESS_THAN */
        if (c1 > c2) return 3; /* CSTR_GREATER_THAN */
    }
    if (len1 < len2) return 1;
    if (len1 > len2) return 3;
    return 2; /* CSTR_EQUAL */
}

/* ---------- lstrcmpiW ---------- */

WINAPI_EXPORT int lstrcmpiW(LPCWSTR lpString1, LPCWSTR lpString2)
{
    if (!lpString1 || !lpString2)
        return lpString1 == lpString2 ? 0 : (lpString1 ? 1 : -1);
    while (*lpString1 && *lpString2) {
        uint16_t c1 = *lpString1, c2 = *lpString2;
        if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
        if (c1 != c2) return (int)c1 - (int)c2;
        lpString1++; lpString2++;
    }
    return (int)*lpString1 - (int)*lpString2;
}

/* ---------- MulDiv ---------- */

WINAPI_EXPORT int MulDiv(int nNumber, int nNumerator, int nDenominator)
{
    if (nDenominator == 0)
        return -1;
    return (int)((int64_t)nNumber * nNumerator / nDenominator);
}

/* GetUserDefaultUILanguage moved to kernel32_locale.c */

/* ---------- IsTextUnicode ---------- */

WINAPI_EXPORT BOOL IsTextUnicode(const void *lpv, int iSize, int *lpiResult)
{
    (void)lpv;
    (void)iSize;
    if (lpiResult) *lpiResult = 0;
    return FALSE;
}

/* ---------- GetDateFormatW ---------- */

WINAPI_EXPORT int GetDateFormatW(
    DWORD Locale, DWORD dwFlags,
    const void *lpDate, LPCWSTR lpFormat,
    LPWSTR lpDateStr, int cchDate)
{
    (void)Locale; (void)dwFlags; (void)lpDate;
    (void)lpFormat; (void)lpDateStr; (void)cchDate;
    set_last_error(ERROR_INVALID_PARAMETER);
    return 0;
}

/* ---------- GetTimeFormatW ---------- */

WINAPI_EXPORT int GetTimeFormatW(
    DWORD Locale, DWORD dwFlags,
    const void *lpTime, LPCWSTR lpFormat,
    LPWSTR lpTimeStr, int cchTime)
{
    (void)Locale; (void)dwFlags; (void)lpTime;
    (void)lpFormat; (void)lpTimeStr; (void)cchTime;
    set_last_error(ERROR_INVALID_PARAMETER);
    return 0;
}

/* GetLocaleInfoW moved to kernel32_locale.c */

/* ---------- FoldStringW ---------- */

WINAPI_EXPORT int FoldStringW(
    DWORD dwMapFlags, LPCWSTR lpSrcStr, int cchSrc,
    LPWSTR lpDestStr, int cchDest)
{
    (void)dwMapFlags; (void)lpSrcStr; (void)cchSrc;
    (void)lpDestStr; (void)cchDest;
    set_last_error(ERROR_INVALID_PARAMETER);
    return 0;
}

/* ---- Wide-string lstr* functions ---- */

static __attribute__((unused)) int wcslen16(const uint16_t *s) { int n = 0; while (s[n]) n++; return n; }

/* NOTE: lstrcpyW is intentionally unbounded per Windows API contract.
 * Callers must ensure dst is large enough. */
WINAPI_EXPORT uint16_t *lstrcpyW(uint16_t *dst, const uint16_t *src)
{
    uint16_t *d = dst;
    while ((*d++ = *src++)) {}
    return dst;
}

WINAPI_EXPORT uint16_t *lstrcpynW(uint16_t *dst, const uint16_t *src, int maxLen)
{
    if (maxLen <= 0) return dst;
    int i = 0;
    while (i < maxLen - 1 && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = 0;
    return dst;
}

/* NOTE: lstrcatW is intentionally unbounded per Windows API contract.
 * Callers must ensure dst is large enough. */
WINAPI_EXPORT uint16_t *lstrcatW(uint16_t *dst, const uint16_t *src)
{
    uint16_t *d = dst;
    while (*d) d++;
    while ((*d++ = *src++)) {}
    return dst;
}

WINAPI_EXPORT int lstrcmpW(const uint16_t *s1, const uint16_t *s2)
{
    while (*s1 && *s1 == *s2) { s1++; s2++; }
    return (int)*s1 - (int)*s2;
}

/* ---- EncodePointer / DecodePointer ---- */

static const uintptr_t g_ptr_cookie = 0xDEADBEEF12345678ULL;

WINAPI_EXPORT void *EncodePointer(void *Ptr)
{
    return (void *)((uintptr_t)Ptr ^ g_ptr_cookie);
}

WINAPI_EXPORT void *DecodePointer(void *Ptr)
{
    return (void *)((uintptr_t)Ptr ^ g_ptr_cookie);
}

WINAPI_EXPORT void *EncodeSystemPointer(void *Ptr)
{
    return EncodePointer(Ptr);
}

WINAPI_EXPORT void *DecodeSystemPointer(void *Ptr)
{
    return DecodePointer(Ptr);
}

/* ---- Misc string/locale ---- */

WINAPI_EXPORT BOOL EnumSystemLocalesW(void *lpLocaleEnumProc, DWORD dwFlags)
{
    (void)lpLocaleEnumProc; (void)dwFlags;
    return TRUE;
}

WINAPI_EXPORT BOOL EnumSystemLocalesA(void *lpLocaleEnumProc, DWORD dwFlags)
{
    (void)lpLocaleEnumProc; (void)dwFlags;
    return TRUE;
}

WINAPI_EXPORT UINT SetErrorMode(UINT uMode)
{
    (void)uMode;
    return 0;
}

WINAPI_EXPORT BOOL Beep(DWORD dwFreq, DWORD dwDuration)
{
    (void)dwFreq; (void)dwDuration;
    return TRUE;
}

WINAPI_EXPORT BOOL ClearCommBreak(HANDLE hFile)
{
    (void)hFile;
    return TRUE;
}

/* ---------- Functions unique to this file (rest moved to kernel32_locale.c) ---------- */

WINAPI_EXPORT DWORD GetThreadLocale(void) { return 0x0409; }
WINAPI_EXPORT BOOL SetThreadLocale(DWORD Locale) { (void)Locale; return TRUE; }

WINAPI_EXPORT BOOL GetHandleInformation(HANDLE hObject, LPDWORD lpdwFlags)
{
    (void)hObject;
    if (lpdwFlags) *lpdwFlags = 0;
    return TRUE;
}

/* ----------------------------------------------------------------
 * RtlUnwind / RtlUnwindEx - forwarded to canonical ntdll
 *
 * Windows executables commonly import these from kernel32.dll.
 * The canonical implementations live in ntdll (ntdll_exception.c).
 * We forward at runtime via dlsym.
 * ---------------------------------------------------------------- */

WINAPI_EXPORT void WINAPI RtlUnwind(void *TargetFrame, void *TargetIp,
                                     void *ExceptionRecord, void *ReturnValue)
{
    typedef void (WINAPI *fn_t)(void*, void*, void*, void*);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        void *h = dlopen("libpe_ntdll.so", RTLD_LAZY);
        if (h) real_fn = (fn_t)dlsym(h, "RtlUnwind");
    }
    if (real_fn) real_fn(TargetFrame, TargetIp, ExceptionRecord, ReturnValue);
}

WINAPI_EXPORT void WINAPI RtlUnwindEx(void *TargetFrame, void *TargetIp,
                                       void *ExceptionRecord, void *ReturnValue,
                                       void *ContextRecord, void *HistoryTable)
{
    typedef void (WINAPI *fn_t)(void*, void*, void*, void*, void*, void*);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        void *h = dlopen("libpe_ntdll.so", RTLD_LAZY);
        if (h) real_fn = (fn_t)dlsym(h, "RtlUnwindEx");
    }
    if (real_fn) real_fn(TargetFrame, TargetIp, ExceptionRecord, ReturnValue,
                         ContextRecord, HistoryTable);
}
