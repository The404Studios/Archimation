/*
 * kernel32_locale.c - Locale, string type, and misc functions
 *
 * Functions needed by PuTTY and Steam that were reported UNRESOLVED.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>
#include <sys/sysinfo.h>

#include "common/dll_common.h"

/* Forward-declare LocalAlloc from kernel32_memory.c */
extern HLOCAL __attribute__((ms_abi)) LocalAlloc(UINT uFlags, SIZE_T uBytes);

/* FindNextFileW is in kernel32_find.c (proper dir enumeration implementation) */

/* ---- FormatMessageA ---- */
#define FORMAT_MESSAGE_FROM_SYSTEM     0x00001000
#define FORMAT_MESSAGE_IGNORE_INSERTS  0x00000200
#define FORMAT_MESSAGE_ALLOCATE_BUFFER 0x00000100

WINAPI_EXPORT DWORD FormatMessageA(DWORD dwFlags, LPCVOID lpSource,
    DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer,
    DWORD nSize, void *Arguments)
{
    (void)lpSource; (void)dwLanguageId; (void)Arguments;

    const char *msg = "Unknown error";
    char buf[256];

    /* Map common NTSTATUS/Win32 error codes */
    switch (dwMessageId) {
        case 0: msg = "The operation completed successfully."; break;
        case 2: msg = "The system cannot find the file specified."; break;
        case 3: msg = "The system cannot find the path specified."; break;
        case 5: msg = "Access is denied."; break;
        case 6: msg = "The handle is invalid."; break;
        case 87: msg = "The parameter is incorrect."; break;
        case 122: msg = "The data area passed to a system call is too small."; break;
        default:
            snprintf(buf, sizeof(buf), "Error %u (0x%08X)", (unsigned)dwMessageId, (unsigned)dwMessageId);
            msg = buf;
            break;
    }

    if (dwFlags & FORMAT_MESSAGE_ALLOCATE_BUFFER) {
        /* Allocate buffer and return pointer */
        size_t len = strlen(msg) + 1;
        char *alloc = (char *)LocalAlloc(0, len);
        if (alloc) {
            memcpy(alloc, msg, len);
            *(char **)lpBuffer = alloc;
        }
        return (DWORD)strlen(msg);
    }

    if (lpBuffer && nSize > 0) {
        size_t len = strlen(msg);
        if (len >= nSize) len = nSize - 1;
        memcpy(lpBuffer, msg, len);
        lpBuffer[len] = '\0';
        return (DWORD)len;
    }
    return 0;
}

WINAPI_EXPORT DWORD FormatMessageW(DWORD dwFlags, LPCVOID lpSource,
    DWORD dwMessageId, DWORD dwLanguageId, uint16_t *lpBuffer,
    DWORD nSize, void *Arguments)
{
    /* Get narrow message first */
    char narrow[256];
    DWORD len = FormatMessageA(
        (dwFlags & ~FORMAT_MESSAGE_ALLOCATE_BUFFER) | FORMAT_MESSAGE_FROM_SYSTEM,
        lpSource, dwMessageId, dwLanguageId, narrow, sizeof(narrow), Arguments);

    if (dwFlags & FORMAT_MESSAGE_ALLOCATE_BUFFER) {
        uint16_t *alloc = (uint16_t *)LocalAlloc(0, (len + 1) * 2);
        if (alloc) {
            for (DWORD i = 0; i <= len; i++)
                alloc[i] = (uint16_t)(unsigned char)narrow[i];
            *(uint16_t **)lpBuffer = alloc;
        }
        return len;
    }

    if (lpBuffer && nSize > 0) {
        if (len >= nSize) len = nSize - 1;
        for (DWORD i = 0; i < len; i++)
            lpBuffer[i] = (uint16_t)(unsigned char)narrow[i];
        lpBuffer[len] = 0;
    }
    return len;
}

/* ---- Locale functions ---- */

typedef struct {
    DWORD MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
} CPINFO;

WINAPI_EXPORT BOOL GetCPInfo(UINT CodePage, CPINFO *lpCPInfo)
{
    (void)CodePage;
    if (!lpCPInfo) return FALSE;
    memset(lpCPInfo, 0, sizeof(CPINFO));
    lpCPInfo->MaxCharSize = 1; /* single-byte codepage */
    lpCPInfo->DefaultChar[0] = '?';
    return TRUE;
}

WINAPI_EXPORT BOOL GetCPInfoExA(UINT CodePage, DWORD dwFlags, void *lpCPInfoEx)
{
    (void)CodePage; (void)dwFlags; (void)lpCPInfoEx;
    return FALSE;
}

WINAPI_EXPORT int GetLocaleInfoA(DWORD Locale, DWORD LCType, LPSTR lpLCData, int cchData)
{
    (void)Locale;
    const char *val = "";

    /* Common LCType values */
    switch (LCType & 0xFFFF) {
        case 0x0001: val = "en-US"; break;    /* LOCALE_SLANGUAGE */
        case 0x0002: val = "English"; break;  /* LOCALE_SABBREVLANGNAME */
        case 0x0003: val = "English (United States)"; break;
        case 0x000F: val = "."; break;         /* LOCALE_SDECIMAL */
        case 0x0010: val = ","; break;         /* LOCALE_STHOUSAND */
        case 0x0014: val = "en-US"; break;     /* LOCALE_SISO639LANGNAME */
        case 0x001D: val = "1"; break;         /* LOCALE_RETURN_NUMBER mapped */
        case 0x1004: val = "MM/dd/yyyy"; break;/* LOCALE_SSHORTDATE */
        default: val = ""; break;
    }

    int len = (int)strlen(val) + 1;
    if (cchData == 0) return len;
    if (lpLCData && cchData > 0) {
        int copy = len < cchData ? len : cchData;
        memcpy(lpLCData, val, copy);
        if (copy < cchData) lpLCData[copy - 1] = '\0';
    }
    return len;
}

WINAPI_EXPORT int GetLocaleInfoW(DWORD Locale, DWORD LCType, uint16_t *lpLCData, int cchData)
{
    char narrow[256];
    int len = GetLocaleInfoA(Locale, LCType, narrow, sizeof(narrow));
    if (cchData == 0) return len;
    if (lpLCData && cchData > 0) {
        int copy = len < cchData ? len : cchData;
        for (int i = 0; i < copy; i++)
            lpLCData[i] = (uint16_t)(unsigned char)narrow[i];
    }
    return len;
}

WINAPI_EXPORT BOOL GetStringTypeW(DWORD dwInfoType, const uint16_t *lpSrcStr,
    int cchSrc, uint16_t *lpCharType)
{
    (void)dwInfoType;
    if (!lpSrcStr || !lpCharType) return FALSE;

    int len = cchSrc;
    if (len < 0) {
        len = 0;
        while (lpSrcStr[len]) len++;
    }

    /* CT_CTYPE1 classification */
    for (int i = 0; i < len; i++) {
        uint16_t c = lpSrcStr[i];
        uint16_t type = 0;
        if (c >= '0' && c <= '9') type |= 0x0004; /* C1_DIGIT */
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) type |= 0x0100; /* C1_ALPHA */
        if (c >= 'a' && c <= 'z') type |= 0x0002; /* C1_LOWER */
        if (c >= 'A' && c <= 'Z') type |= 0x0001; /* C1_UPPER */
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') type |= 0x0008; /* C1_SPACE */
        if (c < 0x20 || c == 0x7F) type |= 0x0020; /* C1_CNTRL */
        if (c >= 0x20 && c < 0x7F) type |= 0x0040; /* C1_BLANK/printable */
        if ((c >= '!' && c <= '/') || (c >= ':' && c <= '@') ||
            (c >= '[' && c <= '`') || (c >= '{' && c <= '~'))
            type |= 0x0010; /* C1_PUNCT */
        lpCharType[i] = type;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL GetStringTypeA(DWORD dwInfoType, LPCSTR lpSrcStr,
    int cchSrc, uint16_t *lpCharType)
{
    if (!lpSrcStr || !lpCharType) return FALSE;
    int len = cchSrc < 0 ? (int)strlen(lpSrcStr) : cchSrc;

    /* Convert to wide and delegate */
    uint16_t *wide = (uint16_t *)alloca(len * sizeof(uint16_t));
    for (int i = 0; i < len; i++)
        wide[i] = (uint16_t)(unsigned char)lpSrcStr[i];
    return GetStringTypeW(dwInfoType, wide, len, lpCharType);
}

WINAPI_EXPORT DWORD GetUserDefaultLCID(void) { return 0x0409; /* en-US */ }
WINAPI_EXPORT DWORD GetUserDefaultUILanguage(void) { return 0x0409; }
WINAPI_EXPORT DWORD GetSystemDefaultLCID(void) { return 0x0409; }
WINAPI_EXPORT DWORD GetSystemDefaultUILanguage(void) { return 0x0409; }

WINAPI_EXPORT BOOL IsValidLocale(DWORD Locale, DWORD dwFlags)
{
    (void)Locale; (void)dwFlags;
    return TRUE;
}

WINAPI_EXPORT BOOL IsDBCSLeadByte(BYTE TestChar) { (void)TestChar; return FALSE; }
WINAPI_EXPORT BOOL IsDBCSLeadByteEx(UINT CodePage, BYTE TestChar)
{
    (void)CodePage; (void)TestChar;
    return FALSE;
}

WINAPI_EXPORT int LCMapStringW(DWORD Locale, DWORD dwMapFlags,
    const uint16_t *lpSrcStr, int cchSrc,
    uint16_t *lpDestStr, int cchDest)
{
    (void)Locale;
    int len = cchSrc;
    if (len < 0) {
        len = 0;
        while (lpSrcStr[len]) len++;
        len++; /* include null */
    }

    if (cchDest == 0) return len;

    int copy = len < cchDest ? len : cchDest;
    for (int i = 0; i < copy; i++) {
        uint16_t c = lpSrcStr[i];
        if (dwMapFlags & 0x00000100) { /* LCMAP_LOWERCASE */
            if (c >= 'A' && c <= 'Z') c += 32;
        }
        if (dwMapFlags & 0x00000200) { /* LCMAP_UPPERCASE */
            if (c >= 'a' && c <= 'z') c -= 32;
        }
        lpDestStr[i] = c;
    }
    return copy;
}

WINAPI_EXPORT int LCMapStringA(DWORD Locale, DWORD dwMapFlags,
    LPCSTR lpSrcStr, int cchSrc,
    LPSTR lpDestStr, int cchDest)
{
    (void)Locale;
    int len = cchSrc < 0 ? (int)strlen(lpSrcStr) + 1 : cchSrc;
    if (cchDest == 0) return len;

    int copy = len < cchDest ? len : cchDest;
    for (int i = 0; i < copy; i++) {
        char c = lpSrcStr[i];
        if (dwMapFlags & 0x00000100) { /* LCMAP_LOWERCASE */
            if (c >= 'A' && c <= 'Z') c += 32;
        }
        if (dwMapFlags & 0x00000200) { /* LCMAP_UPPERCASE */
            if (c >= 'a' && c <= 'z') c -= 32;
        }
        lpDestStr[i] = c;
    }
    return copy;
}

/* ---- Memory info ---- */

typedef struct {
    DWORD dwLength;
    DWORD dwMemoryLoad;
    SIZE_T dwTotalPhys;
    SIZE_T dwAvailPhys;
    SIZE_T dwTotalPageFile;
    SIZE_T dwAvailPageFile;
    SIZE_T dwTotalVirtual;
    SIZE_T dwAvailVirtual;
} MEMORYSTATUS;

WINAPI_EXPORT void GlobalMemoryStatus(MEMORYSTATUS *lpBuffer)
{
    if (!lpBuffer) return;
    memset(lpBuffer, 0, sizeof(MEMORYSTATUS));
    lpBuffer->dwLength = sizeof(MEMORYSTATUS);
    lpBuffer->dwMemoryLoad = 50;
    lpBuffer->dwTotalPhys = (SIZE_T)8ULL * 1024 * 1024 * 1024;  /* 8 GB */
    lpBuffer->dwAvailPhys = (SIZE_T)4ULL * 1024 * 1024 * 1024;
    lpBuffer->dwTotalPageFile = (SIZE_T)16ULL * 1024 * 1024 * 1024;
    lpBuffer->dwAvailPageFile = (SIZE_T)12ULL * 1024 * 1024 * 1024;
    lpBuffer->dwTotalVirtual = (SIZE_T)0x7FFE0000ULL;
    lpBuffer->dwAvailVirtual = (SIZE_T)0x7FFC0000ULL;
}

typedef struct {
    DWORD dwLength;
    DWORD dwMemoryLoad;
    ULONGLONG ullTotalPhys;
    ULONGLONG ullAvailPhys;
    ULONGLONG ullTotalPageFile;
    ULONGLONG ullAvailPageFile;
    ULONGLONG ullTotalVirtual;
    ULONGLONG ullAvailVirtual;
    ULONGLONG ullAvailExtendedVirtual;
} MEMORYSTATUSEX;

WINAPI_EXPORT BOOL GlobalMemoryStatusEx(MEMORYSTATUSEX *lpBuffer)
{
    if (!lpBuffer) return FALSE;
    memset(lpBuffer, 0, sizeof(MEMORYSTATUSEX));
    lpBuffer->dwLength = sizeof(MEMORYSTATUSEX);

    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        ULONGLONG total = (ULONGLONG)si.totalram * si.mem_unit;
        ULONGLONG avail = (ULONGLONG)si.freeram * si.mem_unit;
        ULONGLONG swap_total = (ULONGLONG)si.totalswap * si.mem_unit;
        ULONGLONG swap_free = (ULONGLONG)si.freeswap * si.mem_unit;
        lpBuffer->ullTotalPhys = total;
        lpBuffer->ullAvailPhys = avail;
        lpBuffer->ullTotalPageFile = total + swap_total;
        lpBuffer->ullAvailPageFile = avail + swap_free;
        if (total > 0)
            lpBuffer->dwMemoryLoad = (DWORD)(((total - avail) * 100) / total);
    } else {
        /* Fallback: 8 GB */
        lpBuffer->dwMemoryLoad = 50;
        lpBuffer->ullTotalPhys = 8ULL * 1024 * 1024 * 1024;
        lpBuffer->ullAvailPhys = 4ULL * 1024 * 1024 * 1024;
        lpBuffer->ullTotalPageFile = 16ULL * 1024 * 1024 * 1024;
        lpBuffer->ullAvailPageFile = 12ULL * 1024 * 1024 * 1024;
    }
    /* Windows 64-bit user-mode address space: 128 TB */
    lpBuffer->ullTotalVirtual  = 0x00007FFFFFFEFFFFULL;
    lpBuffer->ullAvailVirtual  = 0x00007FFFFFFEFFFFULL;
    lpBuffer->ullAvailExtendedVirtual = 0;
    return TRUE;
}

/* ---- Process/Thread ---- */

WINAPI_EXPORT BOOL GetThreadTimes(HANDLE hThread, FILETIME *lpCreation,
    FILETIME *lpExit, FILETIME *lpKernel, FILETIME *lpUser)
{
    (void)hThread;
    FILETIME zero = {0, 0};
    if (lpCreation) *lpCreation = zero;
    if (lpExit) *lpExit = zero;
    if (lpKernel) *lpKernel = zero;
    if (lpUser) *lpUser = zero;
    return TRUE;
}

/* ---- Console ---- */

WINAPI_EXPORT BOOL ReadConsoleW(HANDLE hConsoleInput, void *lpBuffer,
    DWORD nNumberOfCharsToRead, LPDWORD lpNumberOfCharsRead, void *pInputControl)
{
    (void)hConsoleInput; (void)lpBuffer; (void)nNumberOfCharsToRead;
    (void)pInputControl;
    if (lpNumberOfCharsRead) *lpNumberOfCharsRead = 0;
    return FALSE;
}

WINAPI_EXPORT BOOL SetHandleInformation(HANDLE hObject, DWORD dwMask, DWORD dwFlags)
{
    (void)hObject; (void)dwMask; (void)dwFlags;
    return TRUE;
}

/* ---- Serial port stubs (for PuTTY) ---- */

typedef struct {
    DWORD DCBlength;
    DWORD BaudRate;
    /* ... simplified */
    BYTE ByteSize;
    BYTE Parity;
    BYTE StopBits;
} DCB;

typedef struct {
    DWORD ReadIntervalTimeout;
    DWORD ReadTotalTimeoutMultiplier;
    DWORD ReadTotalTimeoutConstant;
    DWORD WriteTotalTimeoutMultiplier;
    DWORD WriteTotalTimeoutConstant;
} COMMTIMEOUTS;

WINAPI_EXPORT BOOL GetCommState(HANDLE hFile, DCB *lpDCB)
{
    (void)hFile; (void)lpDCB;
    set_last_error(1); /* ERROR_INVALID_FUNCTION */
    return FALSE;
}

WINAPI_EXPORT BOOL SetCommState(HANDLE hFile, DCB *lpDCB)
{
    (void)hFile; (void)lpDCB;
    return FALSE;
}

WINAPI_EXPORT BOOL SetCommTimeouts(HANDLE hFile, COMMTIMEOUTS *lpCommTimeouts)
{
    (void)hFile; (void)lpCommTimeouts;
    return FALSE;
}

WINAPI_EXPORT BOOL SetCommBreak(HANDLE hFile)
{
    (void)hFile;
    return FALSE;
}

/* ---- RTL functions (forwarded from kernel32) ---- */

WINAPI_EXPORT void *RtlPcToFileHeader(void *PcValue, void **BaseOfImage)
{
    /* Return the PE image base for a given PC */
    if (BaseOfImage) *BaseOfImage = NULL;
    (void)PcValue;
    return NULL;
}
