/*
 * version_info.c - version.dll stubs
 *
 * GetFileVersionInfoA/W, GetFileVersionInfoSizeA/W,
 * VerQueryValueA/W, GetFileVersionInfoExA/W.
 *
 * Most Windows applications call these to check DLL/EXE version
 * resources.  We return "no version info available" for everything.
 */

#include <stdio.h>
#include <string.h>

#include "common/dll_common.h"

/* ---------- GetFileVersionInfoSize ---------- */

WINAPI_EXPORT DWORD GetFileVersionInfoSizeA(LPCSTR lpFileName, LPDWORD lpdwHandle)
{
    fprintf(stderr, "[version] GetFileVersionInfoSizeA(\"%s\")\n",
            lpFileName ? lpFileName : "(null)");

    if (lpdwHandle)
        *lpdwHandle = 0;

    /* Return 0 = no version information available */
    return 0;
}

WINAPI_EXPORT DWORD GetFileVersionInfoSizeW(LPCWSTR lpFileName, LPDWORD lpdwHandle)
{
    (void)lpFileName;
    fprintf(stderr, "[version] GetFileVersionInfoSizeW(...)\n");

    if (lpdwHandle)
        *lpdwHandle = 0;

    return 0;
}

/* ---------- GetFileVersionInfo ---------- */

WINAPI_EXPORT BOOL GetFileVersionInfoA(
    LPCSTR lpFileName,
    DWORD  dwHandle,
    DWORD  dwLen,
    LPVOID lpData)
{
    (void)dwHandle;
    (void)dwLen;
    (void)lpData;

    fprintf(stderr, "[version] GetFileVersionInfoA(\"%s\")\n",
            lpFileName ? lpFileName : "(null)");

    return FALSE;
}

WINAPI_EXPORT BOOL GetFileVersionInfoW(
    LPCWSTR lpFileName,
    DWORD   dwHandle,
    DWORD   dwLen,
    LPVOID  lpData)
{
    (void)lpFileName;
    (void)dwHandle;
    (void)dwLen;
    (void)lpData;

    fprintf(stderr, "[version] GetFileVersionInfoW(...)\n");

    return FALSE;
}

/* ---------- VerQueryValue ---------- */

WINAPI_EXPORT BOOL VerQueryValueA(
    LPCVOID pBlock,
    LPCSTR  lpSubBlock,
    LPVOID *lplpBuffer,
    UINT   *puLen)
{
    (void)pBlock;

    fprintf(stderr, "[version] VerQueryValueA(\"%s\")\n",
            lpSubBlock ? lpSubBlock : "(null)");

    if (lplpBuffer)
        *lplpBuffer = NULL;
    if (puLen)
        *puLen = 0;

    return FALSE;
}

WINAPI_EXPORT BOOL VerQueryValueW(
    LPCVOID  pBlock,
    LPCWSTR  lpSubBlock,
    LPVOID  *lplpBuffer,
    UINT    *puLen)
{
    (void)pBlock;
    (void)lpSubBlock;

    fprintf(stderr, "[version] VerQueryValueW(...)\n");

    if (lplpBuffer)
        *lplpBuffer = NULL;
    if (puLen)
        *puLen = 0;

    return FALSE;
}

/* ---------- GetFileVersionInfoEx ---------- */

WINAPI_EXPORT BOOL GetFileVersionInfoExA(
    DWORD   dwFlags,
    LPCSTR  lpFileName,
    DWORD   dwHandle,
    DWORD   dwLen,
    LPVOID  lpData)
{
    (void)dwFlags;
    (void)dwHandle;
    (void)dwLen;
    (void)lpData;

    fprintf(stderr, "[version] GetFileVersionInfoExA(\"%s\")\n",
            lpFileName ? lpFileName : "(null)");

    return FALSE;
}

WINAPI_EXPORT BOOL GetFileVersionInfoExW(
    DWORD    dwFlags,
    LPCWSTR  lpFileName,
    DWORD    dwHandle,
    DWORD    dwLen,
    LPVOID   lpData)
{
    (void)dwFlags;
    (void)lpFileName;
    (void)dwHandle;
    (void)dwLen;
    (void)lpData;

    fprintf(stderr, "[version] GetFileVersionInfoExW(...)\n");

    return FALSE;
}
