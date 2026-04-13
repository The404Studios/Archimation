/*
 * comdlg32_dialogs.c - Common Dialog Box Library stubs
 *
 * File Open/Save, Choose Color, Choose Font dialogs.
 * These are GUI-only functions - return failure for headless operation.
 */

#include <stdio.h>
#include <string.h>

#include "common/dll_common.h"

#ifndef ERROR_CANCELLED
#define ERROR_CANCELLED 1223
#endif

/* OPENFILENAMEA/W structures (simplified) */
typedef struct {
    DWORD         lStructSize;
    HWND          hwndOwner;
    HINSTANCE     hInstance;
    LPCSTR        lpstrFilter;
    LPSTR         lpstrCustomFilter;
    DWORD         nMaxCustFilter;
    DWORD         nFilterIndex;
    LPSTR         lpstrFile;
    DWORD         nMaxFile;
    LPSTR         lpstrFileTitle;
    DWORD         nMaxFileTitle;
    LPCSTR        lpstrInitialDir;
    LPCSTR        lpstrTitle;
    DWORD         Flags;
    WORD          nFileOffset;
    WORD          nFileExtension;
    LPCSTR        lpstrDefExt;
    LPARAM        lCustData;
    void         *lpfnHook;
    LPCSTR        lpTemplateName;
} OPENFILENAMEA;

typedef struct {
    DWORD         lStructSize;
    HWND          hwndOwner;
    HINSTANCE     hInstance;
    LPCWSTR       lpstrFilter;
    LPWSTR        lpstrCustomFilter;
    DWORD         nMaxCustFilter;
    DWORD         nFilterIndex;
    LPWSTR        lpstrFile;
    DWORD         nMaxFile;
    LPWSTR        lpstrFileTitle;
    DWORD         nMaxFileTitle;
    LPCWSTR       lpstrInitialDir;
    LPCWSTR       lpstrTitle;
    DWORD         Flags;
    WORD          nFileOffset;
    WORD          nFileExtension;
    LPCWSTR       lpstrDefExt;
    LPARAM        lCustData;
    void         *lpfnHook;
    LPCWSTR       lpTemplateName;
} OPENFILENAMEW;

/* CHOOSECOLORA structure (simplified) */
typedef struct {
    DWORD        lStructSize;
    HWND         hwndOwner;
    HWND         hInstance;
    DWORD        rgbResult;
    DWORD       *lpCustColors;
    DWORD        Flags;
    LPARAM       lCustData;
    void        *lpfnHook;
    LPCSTR       lpTemplateName;
} CHOOSECOLORA;

/* CHOOSEFONTA structure (simplified) */
typedef struct {
    DWORD        lStructSize;
    HWND         hwndOwner;
    HDC          hDC;
    void        *lpLogFont;
    INT          iPointSize;
    DWORD        Flags;
    DWORD        rgbColors;
    LPARAM       lCustData;
    void        *lpfnHook;
    LPCSTR       lpTemplateName;
    HINSTANCE    hInstance;
    LPSTR        lpszStyle;
    WORD         nFontType;
    INT          nSizeMin;
    INT          nSizeMax;
} CHOOSEFONTA;

/* ---------- File Open/Save Dialogs ---------- */

WINAPI_EXPORT BOOL GetOpenFileNameA(OPENFILENAMEA *lpofn)
{
    fprintf(stderr, "[comdlg32] GetOpenFileNameA() - stub (no GUI)\n");
    (void)lpofn;
    set_last_error(ERROR_CANCELLED);
    return FALSE;
}

WINAPI_EXPORT BOOL GetOpenFileNameW(OPENFILENAMEW *lpofn)
{
    fprintf(stderr, "[comdlg32] GetOpenFileNameW() - stub (no GUI)\n");
    (void)lpofn;
    set_last_error(ERROR_CANCELLED);
    return FALSE;
}

WINAPI_EXPORT BOOL GetSaveFileNameA(OPENFILENAMEA *lpofn)
{
    fprintf(stderr, "[comdlg32] GetSaveFileNameA() - stub (no GUI)\n");
    (void)lpofn;
    set_last_error(ERROR_CANCELLED);
    return FALSE;
}

WINAPI_EXPORT BOOL GetSaveFileNameW(OPENFILENAMEW *lpofn)
{
    fprintf(stderr, "[comdlg32] GetSaveFileNameW() - stub (no GUI)\n");
    (void)lpofn;
    set_last_error(ERROR_CANCELLED);
    return FALSE;
}

/* ---------- Color/Font Dialogs ---------- */

WINAPI_EXPORT BOOL ChooseColorA(CHOOSECOLORA *lpcc)
{
    fprintf(stderr, "[comdlg32] ChooseColorA() - stub (no GUI)\n");
    (void)lpcc;
    set_last_error(ERROR_CANCELLED);
    return FALSE;
}

WINAPI_EXPORT BOOL ChooseColorW(void *lpcc)
{
    fprintf(stderr, "[comdlg32] ChooseColorW() - stub (no GUI)\n");
    (void)lpcc;
    set_last_error(ERROR_CANCELLED);
    return FALSE;
}

WINAPI_EXPORT BOOL ChooseFontA(CHOOSEFONTA *lpcf)
{
    fprintf(stderr, "[comdlg32] ChooseFontA() - stub (no GUI)\n");
    (void)lpcf;
    set_last_error(ERROR_CANCELLED);
    return FALSE;
}

WINAPI_EXPORT BOOL ChooseFontW(void *lpcf)
{
    fprintf(stderr, "[comdlg32] ChooseFontW() - stub (no GUI)\n");
    (void)lpcf;
    set_last_error(ERROR_CANCELLED);
    return FALSE;
}

/* ---------- Other Common Dialogs ---------- */

WINAPI_EXPORT BOOL PrintDlgA(void *lppd)
{
    (void)lppd;
    set_last_error(ERROR_CANCELLED);
    return FALSE;
}

WINAPI_EXPORT BOOL PrintDlgW(void *lppd)
{
    (void)lppd;
    set_last_error(ERROR_CANCELLED);
    return FALSE;
}

WINAPI_EXPORT BOOL PageSetupDlgA(void *lppsd)
{
    (void)lppsd;
    set_last_error(ERROR_CANCELLED);
    return FALSE;
}

WINAPI_EXPORT BOOL PageSetupDlgW(void *lppsd)
{
    (void)lppsd;
    set_last_error(ERROR_CANCELLED);
    return FALSE;
}

WINAPI_EXPORT DWORD CommDlgExtendedError(void)
{
    return 0; /* No error */
}

WINAPI_EXPORT BOOL FindTextA(void *lpfr)
{
    (void)lpfr;
    return FALSE;
}

WINAPI_EXPORT BOOL FindTextW(void *lpfr)
{
    (void)lpfr;
    return FALSE;
}

WINAPI_EXPORT BOOL ReplaceTextA(void *lpfr)
{
    (void)lpfr;
    return FALSE;
}

WINAPI_EXPORT BOOL ReplaceTextW(void *lpfr)
{
    (void)lpfr;
    return FALSE;
}
