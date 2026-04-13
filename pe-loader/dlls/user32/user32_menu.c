/*
 * user32_menu.c - Menu, caret, scroll, drawing, and misc UI stubs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/dll_common.h"

/* ---- Menu functions ---- */

WINAPI_EXPORT HMENU CreateMenu(void)
{
    return (HMENU)(uintptr_t)0xAA0001;
}

WINAPI_EXPORT HMENU CreatePopupMenu(void)
{
    return (HMENU)(uintptr_t)0xAA0002;
}

WINAPI_EXPORT BOOL DestroyMenu(HMENU hMenu)
{
    (void)hMenu;
    return TRUE;
}

WINAPI_EXPORT BOOL AppendMenuA(HMENU hMenu, UINT uFlags, ULONG_PTR uIDNewItem, LPCSTR lpNewItem)
{
    (void)hMenu; (void)uFlags; (void)uIDNewItem; (void)lpNewItem;
    return TRUE;
}

WINAPI_EXPORT BOOL AppendMenuW(HMENU hMenu, UINT uFlags, ULONG_PTR uIDNewItem, const uint16_t *lpNewItem)
{
    (void)hMenu; (void)uFlags; (void)uIDNewItem; (void)lpNewItem;
    return TRUE;
}

WINAPI_EXPORT BOOL InsertMenuA(HMENU hMenu, UINT uPosition, UINT uFlags,
    ULONG_PTR uIDNewItem, LPCSTR lpNewItem)
{
    (void)hMenu; (void)uPosition; (void)uFlags; (void)uIDNewItem; (void)lpNewItem;
    return TRUE;
}

WINAPI_EXPORT BOOL InsertMenuW(HMENU hMenu, UINT uPosition, UINT uFlags,
    ULONG_PTR uIDNewItem, const uint16_t *lpNewItem)
{
    (void)hMenu; (void)uPosition; (void)uFlags; (void)uIDNewItem; (void)lpNewItem;
    return TRUE;
}

WINAPI_EXPORT BOOL DeleteMenu(HMENU hMenu, UINT uPosition, UINT uFlags)
{
    (void)hMenu; (void)uPosition; (void)uFlags;
    return TRUE;
}

WINAPI_EXPORT BOOL TrackPopupMenu(HMENU hMenu, UINT uFlags, int x, int y,
    int nReserved, HWND hWnd, const void *prcRect)
{
    (void)hMenu; (void)uFlags; (void)x; (void)y;
    (void)nReserved; (void)hWnd; (void)prcRect;
    return 0;
}

/* ---- System colors ---- */

static const DWORD g_sys_colors[] = {
    0x00C8C8C8, /* COLOR_SCROLLBAR (0) */
    0x00D1B499, /* COLOR_BACKGROUND (1) */
    0x00A05C28, /* COLOR_ACTIVECAPTION (2) */
    0x00808080, /* COLOR_INACTIVECAPTION (3) */
    0x00F0F0F0, /* COLOR_MENU (4) */
    0x00FFFFFF, /* COLOR_WINDOW (5) */
    0x00000000, /* COLOR_WINDOWFRAME (6) */
    0x00000000, /* COLOR_MENUTEXT (7) */
    0x00000000, /* COLOR_WINDOWTEXT (8) */
    0x00FFFFFF, /* COLOR_CAPTIONTEXT (9) */
    0x00F0F0F0, /* COLOR_ACTIVEBORDER (10) */
    0x00F0F0F0, /* COLOR_INACTIVEBORDER (11) */
    0x00808080, /* COLOR_APPWORKSPACE (12) */
    0x00FF6633, /* COLOR_HIGHLIGHT (13) */
    0x00FFFFFF, /* COLOR_HIGHLIGHTTEXT (14) */
    0x00F0F0F0, /* COLOR_BTNFACE (15) */
    0x00808080, /* COLOR_BTNSHADOW (16) */
    0x00808080, /* COLOR_GRAYTEXT (17) */
    0x00000000, /* COLOR_BTNTEXT (18) */
    0x00808080, /* COLOR_INACTIVECAPTIONTEXT (19) */
    0x00FFFFFF, /* COLOR_BTNHIGHLIGHT (20) */
};

WINAPI_EXPORT DWORD GetSysColor(int nIndex)
{
    if (nIndex >= 0 && nIndex < (int)(sizeof(g_sys_colors)/sizeof(g_sys_colors[0])))
        return g_sys_colors[nIndex];
    return 0;
}

WINAPI_EXPORT HANDLE GetSysColorBrush(int nIndex)
{
    (void)nIndex;
    return (HANDLE)(uintptr_t)(0xBB0100 + (nIndex & 0xFF));
}

/* ---- Caret functions ---- */

WINAPI_EXPORT BOOL CreateCaret(HWND hWnd, HANDLE hBitmap, int nWidth, int nHeight)
{
    (void)hWnd; (void)hBitmap; (void)nWidth; (void)nHeight;
    return TRUE;
}

WINAPI_EXPORT BOOL DestroyCaret(void) { return TRUE; }
WINAPI_EXPORT BOOL SetCaretPos(int X, int Y) { (void)X; (void)Y; return TRUE; }
WINAPI_EXPORT BOOL HideCaret(HWND hWnd) { (void)hWnd; return TRUE; }
WINAPI_EXPORT BOOL ShowCaret(HWND hWnd) { (void)hWnd; return TRUE; }
WINAPI_EXPORT UINT GetCaretBlinkTime(void) { return 530; }

/* ---- Scroll functions ---- */

WINAPI_EXPORT BOOL GetScrollInfo(HWND hWnd, int nBar, void *lpScrollInfo)
{
    (void)hWnd; (void)nBar; (void)lpScrollInfo;
    return FALSE;
}

WINAPI_EXPORT int SetScrollInfo(HWND hWnd, int nBar, const void *lpScrollInfo, BOOL bRedraw)
{
    (void)hWnd; (void)nBar; (void)lpScrollInfo; (void)bRedraw;
    return 0;
}

/* ---- Drawing stubs ---- */

WINAPI_EXPORT BOOL DrawEdge(HANDLE hdc, void *qrc, UINT edge, UINT grfFlags)
{
    (void)hdc; (void)qrc; (void)edge; (void)grfFlags;
    return TRUE;
}

WINAPI_EXPORT BOOL DrawIconEx(HANDLE hdc, int xLeft, int yTop, HANDLE hIcon,
    int cxWidth, int cyHeight, UINT istepIfAniCur,
    HANDLE hbrFlickerFreeDraw, UINT diFlags)
{
    (void)hdc; (void)xLeft; (void)yTop; (void)hIcon;
    (void)cxWidth; (void)cyHeight; (void)istepIfAniCur;
    (void)hbrFlickerFreeDraw; (void)diFlags;
    return TRUE;
}

WINAPI_EXPORT BOOL DrawFrameControl(HANDLE hdc, void *lprc, UINT uType, UINT uState)
{
    (void)hdc; (void)lprc; (void)uType; (void)uState;
    return TRUE;
}

/* ---- Window misc ---- */

/* SetClassLongW/SetClassLongPtrA/SetClassLongPtrW moved to user32_window.c */

WINAPI_EXPORT LRESULT CallWindowProcW(void *lpPrevWndFunc, HWND hWnd,
    UINT Msg, WPARAM wParam, LPARAM lParam)
{
    if (lpPrevWndFunc) {
        typedef LRESULT (__attribute__((ms_abi)) *WNDPROC_T)(HWND, UINT, WPARAM, LPARAM);
        return ((WNDPROC_T)lpPrevWndFunc)(hWnd, Msg, wParam, lParam);
    }
    return 0;
}

WINAPI_EXPORT LRESULT CallWindowProcA(void *lpPrevWndFunc, HWND hWnd,
    UINT Msg, WPARAM wParam, LPARAM lParam)
{
    return CallWindowProcW(lpPrevWndFunc, hWnd, Msg, wParam, lParam);
}

WINAPI_EXPORT BOOL GetClassInfoW(HINSTANCE hInstance, const uint16_t *lpClassName, void *lpWndClass)
{
    (void)hInstance; (void)lpClassName; (void)lpWndClass;
    return FALSE;
}

WINAPI_EXPORT BOOL GetClassInfoExW(HINSTANCE hInstance, const uint16_t *lpszClass, void *lpwcx)
{
    (void)hInstance; (void)lpszClass; (void)lpwcx;
    return FALSE;
}

/* FindWindowExW/FindWindowExA/IsZoomed/FlashWindow moved to user32_window.c */

WINAPI_EXPORT LRESULT DefDlgProcA(HWND hDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    (void)hDlg; (void)Msg; (void)wParam; (void)lParam;
    return 0;
}

WINAPI_EXPORT LRESULT DefDlgProcW(HWND hDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    (void)hDlg; (void)Msg; (void)wParam; (void)lParam;
    return 0;
}

/* ---- Message misc ---- */

WINAPI_EXPORT DWORD GetMessagePos(void) { return 0; }

WINAPI_EXPORT LONG GetMessageTime(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (LONG)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

WINAPI_EXPORT LRESULT SendMessageTimeoutW(HWND hWnd, UINT Msg, WPARAM wParam,
    LPARAM lParam, UINT fuFlags, UINT uTimeout, ULONG_PTR *lpdwResult)
{
    (void)hWnd; (void)Msg; (void)wParam; (void)lParam;
    (void)fuFlags; (void)uTimeout;
    if (lpdwResult) *lpdwResult = 0;
    return 0;
}

WINAPI_EXPORT DWORD MsgWaitForMultipleObjects(DWORD nCount, const HANDLE *pHandles,
    BOOL fWaitAll, DWORD dwMilliseconds, DWORD dwWakeMask)
{
    (void)nCount; (void)pHandles; (void)fWaitAll;
    (void)dwMilliseconds; (void)dwWakeMask;
    return 258; /* WAIT_TIMEOUT */
}

WINAPI_EXPORT BOOL ExitWindowsEx(UINT uFlags, DWORD dwReason)
{
    (void)uFlags; (void)dwReason;
    return FALSE;
}

/* ---- Clipboard ---- */

/* ---- Bitmap/Icon stubs ---- */

WINAPI_EXPORT HANDLE LoadBitmapW(HINSTANCE hInstance, const uint16_t *lpBitmapName)
{
    (void)hInstance; (void)lpBitmapName;
    return NULL;
}

WINAPI_EXPORT HANDLE LoadBitmapA(HINSTANCE hInstance, LPCSTR lpBitmapName)
{
    (void)hInstance; (void)lpBitmapName;
    return NULL;
}

/* ---- MessageBox ---- */

WINAPI_EXPORT int MessageBoxIndirectW(const void *lpMsgBoxParams)
{
    (void)lpMsgBoxParams;
    return 1; /* IDOK */
}

/* ---- Char functions ---- */

WINAPI_EXPORT uint16_t *CharPrevW(const uint16_t *lpszStart, const uint16_t *lpszCurrent)
{
    if (lpszCurrent > lpszStart)
        return (uint16_t *)(lpszCurrent - 1);
    return (uint16_t *)lpszStart;
}

WINAPI_EXPORT char *CharNextA(const char *lpsz)
{
    if (lpsz && *lpsz)
        return (char *)(lpsz + 1);
    return (char *)lpsz;
}

WINAPI_EXPORT char *CharPrevA(const char *lpszStart, const char *lpszCurrent)
{
    if (lpszCurrent > lpszStart)
        return (char *)(lpszCurrent - 1);
    return (char *)lpszStart;
}

/* ---- Keyboard ---- */

WINAPI_EXPORT int ToAsciiEx(UINT uVirtKey, UINT uScanCode, const void *lpKeyState,
    uint16_t *lpChar, UINT uFlags, void *dwhkl)
{
    (void)uVirtKey; (void)uScanCode; (void)lpKeyState;
    (void)lpChar; (void)uFlags; (void)dwhkl;
    return 0;
}

/* ---- DDE stubs ---- */

WINAPI_EXPORT BOOL DdeUninitialize(DWORD idInst) { (void)idInst; return TRUE; }

/* ---- Misc ---- */

WINAPI_EXPORT BOOL IsWindowUnicode(HWND hWnd) { (void)hWnd; return TRUE; }
