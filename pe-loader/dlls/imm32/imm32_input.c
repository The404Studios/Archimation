/*
 * imm32_input.c - Input Method Manager stubs
 *
 * PuTTY and many GUI apps import from imm32.dll for CJK input support.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/dll_common.h"

typedef void *HIMC;

WINAPI_EXPORT LONG ImmGetCompositionStringW(HIMC hIMC, DWORD dwIndex,
    void *lpBuf, DWORD dwBufLen)
{
    (void)hIMC; (void)dwIndex; (void)lpBuf; (void)dwBufLen;
    return 0; /* IMM_ERROR_NODATA */
}

WINAPI_EXPORT LONG ImmGetCompositionStringA(HIMC hIMC, DWORD dwIndex,
    void *lpBuf, DWORD dwBufLen)
{
    (void)hIMC; (void)dwIndex; (void)lpBuf; (void)dwBufLen;
    return 0;
}

WINAPI_EXPORT HIMC ImmGetContext(HWND hWnd)
{
    (void)hWnd;
    return NULL;
}

WINAPI_EXPORT BOOL ImmReleaseContext(HWND hWnd, HIMC hIMC)
{
    (void)hWnd; (void)hIMC;
    return TRUE;
}

WINAPI_EXPORT BOOL ImmSetCompositionFontA(HIMC hIMC, void *lplf)
{
    (void)hIMC; (void)lplf;
    return TRUE;
}

WINAPI_EXPORT BOOL ImmSetCompositionFontW(HIMC hIMC, void *lplf)
{
    (void)hIMC; (void)lplf;
    return TRUE;
}

WINAPI_EXPORT BOOL ImmSetCompositionWindow(HIMC hIMC, void *lpCompForm)
{
    (void)hIMC; (void)lpCompForm;
    return TRUE;
}

WINAPI_EXPORT BOOL ImmSetOpenStatus(HIMC hIMC, BOOL fOpen)
{
    (void)hIMC; (void)fOpen;
    return TRUE;
}

WINAPI_EXPORT BOOL ImmGetOpenStatus(HIMC hIMC)
{
    (void)hIMC;
    return FALSE;
}

WINAPI_EXPORT BOOL ImmNotifyIME(HIMC hIMC, DWORD dwAction, DWORD dwIndex, DWORD dwValue)
{
    (void)hIMC; (void)dwAction; (void)dwIndex; (void)dwValue;
    return TRUE;
}

WINAPI_EXPORT HIMC ImmAssociateContext(HWND hWnd, HIMC hIMC)
{
    (void)hWnd; (void)hIMC;
    return NULL;
}

WINAPI_EXPORT BOOL ImmIsIME(void *hKL)
{
    (void)hKL;
    return FALSE;
}

WINAPI_EXPORT UINT ImmGetIMEFileNameA(void *hKL, char *lpszFileName, UINT uBufLen)
{
    (void)hKL; (void)lpszFileName; (void)uBufLen;
    return 0;
}
