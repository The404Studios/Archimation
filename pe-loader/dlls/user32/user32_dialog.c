/*
 * user32_dialog.c - Dialog box infrastructure
 *
 * Implements DialogBoxParamA/W, CreateDialogParamA/W, EndDialog,
 * IsDialogMessage, GetDlgItem, SetDlgItemTextA/W, GetDlgItemTextA/W,
 * GetDlgItemInt, SetDlgItemInt, CheckDlgButton, IsDlgButtonChecked,
 * MapDialogRect, GetDlgCtrlID, GetNextDlgTabItem, SendDlgItemMessageA.
 *
 * Dialog boxes are windows with a DLGPROC that receives WM_INITDIALOG
 * and other dialog-specific messages. Modal dialogs run their own
 * message loop; modeless dialogs return immediately.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/dll_common.h"

/* Window messages */
#define WM_INITDIALOG   0x0110
#define WM_COMMAND      0x0111
#define WM_CLOSE        0x0010
#define WM_DESTROY      0x0002
#define WM_QUIT         0x0012
#define WM_SETTEXT      0x000C
#define WM_GETTEXT      0x000D
#define WM_GETTEXTLENGTH 0x000E
#define WM_SETFONT      0x0030
#define WM_GETFONT      0x0031
#define WM_USER         0x0400

/* Dialog styles */
#define DS_ABSALIGN     0x01
#define DS_SYSMODAL     0x02
#define DS_3DLOOK       0x04
#define DS_FIXEDSYS     0x08
#define DS_NOFAILCREATE 0x10
#define DS_SETFONT      0x40
#define DS_MODALFRAME   0x80
#define DS_CENTER       0x0800
#define DS_CENTERMOUSE   0x1000
#define DS_SETFOREGROUND 0x0200
#define DS_SHELLFONT    0x40

/* Dialog controls */
#define IDOK        1
#define IDCANCEL    2
#define IDABORT     3
#define IDRETRY     4
#define IDIGNORE    5
#define IDYES       6
#define IDNO        7
#define IDCLOSE     8
#define IDHELP      9

/* Button check states */
#define BST_UNCHECKED   0x0000
#define BST_CHECKED     0x0001
#define BST_INDETERMINATE 0x0002

/* Button messages */
#define BM_GETCHECK     0x00F0
#define BM_SETCHECK     0x00F1

/* DLGPROC type */
typedef INT_PTR (__attribute__((ms_abi)) *DLGPROC)(HWND, UINT, WPARAM, LPARAM);

/* Window creation/message functions (from user32_window.c and user32_message.c) */
#ifndef _WNDPROC_DEFINED
#define _WNDPROC_DEFINED
typedef LRESULT (__attribute__((ms_abi)) *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
#endif

/* MSG structure (matches user32_message.c) */
#ifndef _MSG_DEFINED
#define _MSG_DEFINED
typedef struct {
    HWND    hwnd;
    UINT    message;
    WPARAM  wParam;
    LPARAM  lParam;
    DWORD   time;
    POINT   pt;
} MSG, *LPMSG;
#endif

/* External references — must use ms_abi since all are WINAPI_EXPORT */
#define MSABI __attribute__((ms_abi))
extern MSABI HWND CreateWindowExA(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int,
                            HWND, HMENU, HINSTANCE, LPVOID);
extern MSABI BOOL DestroyWindow(HWND);
extern MSABI BOOL ShowWindow(HWND, int);
extern MSABI BOOL UpdateWindow(HWND);
extern MSABI BOOL GetMessageA(LPMSG, HWND, UINT, UINT);
extern MSABI BOOL TranslateMessage(const MSG *);
extern MSABI LRESULT DispatchMessageA(const MSG *);
extern MSABI BOOL IsWindow(HWND);
extern MSABI LRESULT SendMessageA(HWND, UINT, WPARAM, LPARAM);
extern MSABI BOOL SetWindowTextA(HWND, LPCSTR);
extern MSABI BOOL EnableWindow(HWND, BOOL);
extern MSABI LRESULT DefWindowProcA(HWND, UINT, WPARAM, LPARAM);
/* Internal helpers (not ms_abi — they're static/non-WINAPI_EXPORT) */
extern HWND hwnd_find_child_by_id(HWND parent, int control_id);
extern int hwnd_get_control_id(HWND hwnd);

/* ----------------------------------------------------------------
 * Dialog tracking
 * ---------------------------------------------------------------- */

#define MAX_DIALOGS 64

typedef struct {
    HWND        hwnd;
    DLGPROC     dlgproc;
    HWND        owner;
    INT_PTR     result;
    int         ended;      /* Set by EndDialog */
    int         modal;
    int         used;
    /* Child control tracking */
    struct {
        HWND    hwnd;
        int     id;
        int     used;
    } controls[64];
    int control_count;
} dialog_entry_t;

static dialog_entry_t g_dialogs[MAX_DIALOGS];

static dialog_entry_t *find_dialog(HWND hwnd)
{
    for (int i = 0; i < MAX_DIALOGS; i++) {
        if (g_dialogs[i].used && g_dialogs[i].hwnd == hwnd)
            return &g_dialogs[i];
    }
    return NULL;
}

static dialog_entry_t *alloc_dialog(void)
{
    for (int i = 0; i < MAX_DIALOGS; i++) {
        if (!g_dialogs[i].used) {
            memset(&g_dialogs[i], 0, sizeof(g_dialogs[i]));
            g_dialogs[i].used = 1;
            return &g_dialogs[i];
        }
    }
    return NULL;
}

static void free_dialog(dialog_entry_t *d)
{
    if (d) {
        d->used = 0;
        d->hwnd = NULL;
    }
}

/* ----------------------------------------------------------------
 * Dialog window procedure wrapper
 *
 * The DLGPROC returns INT_PTR (TRUE if handled, FALSE if not).
 * We wrap it in a WNDPROC that calls DefWindowProcA for
 * unhandled messages.
 * ---------------------------------------------------------------- */

/* DefWindowProcA declared above with MSABI */

static LRESULT __attribute__((ms_abi)) __attribute__((unused)) dialog_wndproc_wrapper(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    dialog_entry_t *d = find_dialog(hwnd);
    if (d && d->dlgproc) {
        INT_PTR result = d->dlgproc(hwnd, msg, wParam, lParam);
        if (result)
            return 0; /* Message was handled */
    }

    /* Handle WM_CLOSE for dialogs: call EndDialog */
    if (msg == WM_CLOSE) {
        if (d && !d->ended) {
            d->ended = 1;
            d->result = IDCANCEL;
        }
        return 0;
    }

    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

/* ----------------------------------------------------------------
 * CreateDialogParamA / CreateDialogParamW (modeless dialogs)
 * ---------------------------------------------------------------- */

WINAPI_EXPORT HWND CreateDialogParamA(
    HINSTANCE hInstance,
    LPCSTR lpTemplateName,
    HWND hWndParent,
    DLGPROC lpDialogFunc,
    LPARAM dwInitParam)
{
    (void)hInstance;
    (void)lpTemplateName;

    dialog_entry_t *d = alloc_dialog();
    if (!d) {
        set_last_error(ERROR_OUTOFMEMORY);
        return NULL;
    }

    d->dlgproc = lpDialogFunc;
    d->owner = hWndParent;
    d->modal = 0;

    /* Create the dialog window */
    /* We use a generic dialog class - real implementation would parse
     * the dialog template resource for dimensions and controls */
    HWND hwnd = CreateWindowExA(
        0x00000100 /* WS_EX_WINDOWEDGE */,
        "DIALOG",   /* Built-in dialog class */
        "",         /* Title from template */
        0x00C00000 | 0x10000000,  /* WS_CAPTION | WS_VISIBLE */
        100, 100,   /* Position */
        300, 200,   /* Size - default, real impl uses template */
        hWndParent,
        NULL,
        hInstance,
        NULL);

    if (!hwnd) {
        free_dialog(d);
        return NULL;
    }

    d->hwnd = hwnd;

    /* Send WM_INITDIALOG */
    if (d->dlgproc) {
        d->dlgproc(hwnd, WM_INITDIALOG, (WPARAM)0, dwInitParam);
    }

    return hwnd;
}

WINAPI_EXPORT HWND CreateDialogParamW(
    HINSTANCE hInstance,
    LPCWSTR lpTemplateName,
    HWND hWndParent,
    DLGPROC lpDialogFunc,
    LPARAM dwInitParam)
{
    /* Convert template name if it's a real wide string (not MAKEINTRESOURCE) */
    char nameA_buf[260];
    LPCSTR nameA;
    if ((uintptr_t)lpTemplateName > 0xFFFF) {
        /* Real wide string - convert to narrow */
        int i;
        for (i = 0; lpTemplateName[i] && i < 259; i++)
            nameA_buf[i] = (char)(lpTemplateName[i] & 0xFF);
        nameA_buf[i] = '\0';
        nameA = nameA_buf;
    } else {
        /* MAKEINTRESOURCE - pass through */
        nameA = (LPCSTR)lpTemplateName;
    }
    return CreateDialogParamA(hInstance, nameA, hWndParent, lpDialogFunc, dwInitParam);
}

/* ----------------------------------------------------------------
 * DialogBoxParamA / DialogBoxParamW (modal dialogs)
 * ---------------------------------------------------------------- */

WINAPI_EXPORT INT_PTR DialogBoxParamA(
    HINSTANCE hInstance,
    LPCSTR lpTemplateName,
    HWND hWndParent,
    DLGPROC lpDialogFunc,
    LPARAM dwInitParam)
{
    HWND hdlg = CreateDialogParamA(hInstance, lpTemplateName,
                                    hWndParent, lpDialogFunc, dwInitParam);
    if (!hdlg)
        return -1;

    dialog_entry_t *d = find_dialog(hdlg);
    if (!d)
        return -1;

    d->modal = 1;

    /* Disable owner */
    if (hWndParent)
        EnableWindow(hWndParent, FALSE);

    ShowWindow(hdlg, 1 /* SW_SHOWNORMAL */);
    UpdateWindow(hdlg);

    /* Run modal message loop */
    MSG msg;
    while (!d->ended) {
        BOOL ret = GetMessageA(&msg, NULL, 0, 0);
        if (ret == 0 || ret == -1)
            break;

        /* Give the dialog first crack */
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    INT_PTR result = d->result;

    /* Re-enable owner */
    if (hWndParent)
        EnableWindow(hWndParent, TRUE);

    /* Destroy dialog window */
    DestroyWindow(hdlg);
    free_dialog(d);

    return result;
}

WINAPI_EXPORT INT_PTR DialogBoxParamW(
    HINSTANCE hInstance,
    LPCWSTR lpTemplateName,
    HWND hWndParent,
    DLGPROC lpDialogFunc,
    LPARAM dwInitParam)
{
    char nameA_buf[260];
    LPCSTR nameA;
    if ((uintptr_t)lpTemplateName > 0xFFFF) {
        /* Real wide string - convert to narrow */
        int i;
        for (i = 0; lpTemplateName[i] && i < 259; i++)
            nameA_buf[i] = (char)(lpTemplateName[i] & 0xFF);
        nameA_buf[i] = '\0';
        nameA = nameA_buf;
    } else {
        /* MAKEINTRESOURCE - pass through */
        nameA = (LPCSTR)lpTemplateName;
    }
    return DialogBoxParamA(hInstance, nameA, hWndParent, lpDialogFunc, dwInitParam);
}

/* Simplified versions without lParam */
WINAPI_EXPORT INT_PTR DialogBoxA(HINSTANCE hInstance, LPCSTR lpTemplate,
                                  HWND hWndParent, DLGPROC lpDialogFunc)
{
    return DialogBoxParamA(hInstance, lpTemplate, hWndParent, lpDialogFunc, 0);
}

WINAPI_EXPORT INT_PTR DialogBoxW(HINSTANCE hInstance, LPCWSTR lpTemplate,
                                  HWND hWndParent, DLGPROC lpDialogFunc)
{
    return DialogBoxParamW(hInstance, lpTemplate, hWndParent, lpDialogFunc, 0);
}

/* ----------------------------------------------------------------
 * EndDialog
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL EndDialog(HWND hDlg, INT_PTR nResult)
{
    dialog_entry_t *d = find_dialog(hDlg);
    if (!d) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    d->result = nResult;
    d->ended = 1;

    if (!d->modal) {
        /* For modeless dialogs, destroy immediately */
        DestroyWindow(hDlg);
        free_dialog(d);
    }

    return TRUE;
}

/* ----------------------------------------------------------------
 * IsDialogMessage
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL IsDialogMessageA(HWND hDlg, LPMSG lpMsg)
{
    (void)hDlg;
    (void)lpMsg;
    /* Simplified: just return FALSE to let the normal message loop handle it */
    return FALSE;
}

WINAPI_EXPORT BOOL IsDialogMessageW(HWND hDlg, LPMSG lpMsg)
{
    return IsDialogMessageA(hDlg, lpMsg);
}

/* ----------------------------------------------------------------
 * Dialog control functions
 * ---------------------------------------------------------------- */

WINAPI_EXPORT HWND GetDlgItem(HWND hDlg, int nIDDlgItem)
{
    /* First check dialog tracking table */
    dialog_entry_t *d = find_dialog(hDlg);
    if (d) {
        for (int i = 0; i < d->control_count; i++) {
            if (d->controls[i].used && d->controls[i].id == nIDDlgItem)
                return d->controls[i].hwnd;
        }
    }

    /* Fall back to searching the HWND map for child windows with matching control ID */
    return hwnd_find_child_by_id(hDlg, nIDDlgItem);
}

WINAPI_EXPORT BOOL SetDlgItemTextA(HWND hDlg, int nIDDlgItem, LPCSTR lpString)
{
    HWND hCtrl = GetDlgItem(hDlg, nIDDlgItem);
    if (hCtrl)
        return SetWindowTextA(hCtrl, lpString);

    /* If control not found, just log it */
    fprintf(stderr, "[user32] SetDlgItemTextA: control %d not found\n", nIDDlgItem);
    return TRUE;
}

WINAPI_EXPORT BOOL SetDlgItemTextW(HWND hDlg, int nIDDlgItem, LPCWSTR lpString)
{
    /* Convert to ANSI */
    char buf[1024] = {0};
    if (lpString) {
        for (int i = 0; i < 1023 && lpString[i]; i++)
            buf[i] = (char)(lpString[i] & 0xFF);
    }
    return SetDlgItemTextA(hDlg, nIDDlgItem, buf);
}

WINAPI_EXPORT UINT GetDlgItemTextA(HWND hDlg, int nIDDlgItem, LPSTR lpString, int cchMax)
{
    if (!lpString || cchMax <= 0)
        return 0;

    HWND hCtrl = GetDlgItem(hDlg, nIDDlgItem);
    if (hCtrl) {
        return (UINT)SendMessageA(hCtrl, WM_GETTEXT, (WPARAM)cchMax, (LPARAM)lpString);
    }

    lpString[0] = '\0';
    return 0;
}

WINAPI_EXPORT UINT GetDlgItemTextW(HWND hDlg, int nIDDlgItem, LPWSTR lpString, int cchMax)
{
    if (!lpString || cchMax <= 0)
        return 0;

    /* Get as ANSI, convert */
    char buf[1024] = {0};
    UINT len = GetDlgItemTextA(hDlg, nIDDlgItem, buf, sizeof(buf));

    UINT copy = 0;
    for (UINT i = 0; i < len && (int)copy < cchMax - 1; i++)
        lpString[copy++] = (WCHAR)(unsigned char)buf[i];
    lpString[copy] = 0;

    return copy;
}

WINAPI_EXPORT UINT GetDlgItemInt(HWND hDlg, int nIDDlgItem, BOOL *lpTranslated, BOOL bSigned)
{
    char buf[64];
    if (GetDlgItemTextA(hDlg, nIDDlgItem, buf, sizeof(buf)) == 0) {
        if (lpTranslated) *lpTranslated = FALSE;
        return 0;
    }

    char *endp;
    long val = strtol(buf, &endp, 10);
    if (endp == buf || *endp != '\0') {
        if (lpTranslated) *lpTranslated = FALSE;
        return 0;
    }

    if (lpTranslated) *lpTranslated = TRUE;
    return bSigned ? (UINT)val : (UINT)(unsigned long)val;
}

WINAPI_EXPORT BOOL SetDlgItemInt(HWND hDlg, int nIDDlgItem, UINT uValue, BOOL bSigned)
{
    char buf[32];
    if (bSigned)
        snprintf(buf, sizeof(buf), "%d", (int)uValue);
    else
        snprintf(buf, sizeof(buf), "%u", uValue);
    return SetDlgItemTextA(hDlg, nIDDlgItem, buf);
}

WINAPI_EXPORT BOOL CheckDlgButton(HWND hDlg, int nIDButton, UINT uCheck)
{
    HWND hBtn = GetDlgItem(hDlg, nIDButton);
    if (hBtn)
        SendMessageA(hBtn, BM_SETCHECK, (WPARAM)uCheck, 0);
    return TRUE;
}

WINAPI_EXPORT UINT IsDlgButtonChecked(HWND hDlg, int nIDButton)
{
    HWND hBtn = GetDlgItem(hDlg, nIDButton);
    if (hBtn)
        return (UINT)SendMessageA(hBtn, BM_GETCHECK, 0, 0);
    return BST_UNCHECKED;
}

WINAPI_EXPORT BOOL MapDialogRect(HWND hDlg, LPRECT lpRect)
{
    (void)hDlg;
    /* Dialog units to pixels conversion.
     * Approximate: 1 DLU horizontal = ~1.75 pixels, vertical = ~1.75 pixels
     * at standard 96 DPI with default dialog font. */
    if (lpRect) {
        lpRect->left   = lpRect->left * 7 / 4;
        lpRect->top    = lpRect->top * 7 / 4;
        lpRect->right  = lpRect->right * 7 / 4;
        lpRect->bottom = lpRect->bottom * 7 / 4;
    }
    return TRUE;
}

WINAPI_EXPORT int GetDlgCtrlID(HWND hWnd)
{
    /* First check dialog tracking */
    for (int d = 0; d < MAX_DIALOGS; d++) {
        if (!g_dialogs[d].used) continue;
        for (int c = 0; c < g_dialogs[d].control_count; c++) {
            if (g_dialogs[d].controls[c].used &&
                g_dialogs[d].controls[c].hwnd == hWnd)
                return g_dialogs[d].controls[c].id;
        }
    }
    /* Fall back to HWND entry control_id */
    return hwnd_get_control_id(hWnd);
}

WINAPI_EXPORT HWND GetNextDlgTabItem(HWND hDlg, HWND hCtl, BOOL bPrevious)
{
    (void)hDlg;
    (void)hCtl;
    (void)bPrevious;
    return NULL; /* Stub */
}

WINAPI_EXPORT LRESULT SendDlgItemMessageA(HWND hDlg, int nIDDlgItem,
                                           UINT Msg, WPARAM wParam, LPARAM lParam)
{
    HWND hCtrl = GetDlgItem(hDlg, nIDDlgItem);
    if (hCtrl)
        return SendMessageA(hCtrl, Msg, wParam, lParam);
    return 0;
}

WINAPI_EXPORT LRESULT SendDlgItemMessageW(HWND hDlg, int nIDDlgItem,
                                           UINT Msg, WPARAM wParam, LPARAM lParam)
{
    return SendDlgItemMessageA(hDlg, nIDDlgItem, Msg, wParam, lParam);
}

/* ----------------------------------------------------------------
 * CreateDialogIndirectParamW (modeless dialog from template in memory)
 * ---------------------------------------------------------------- */

WINAPI_EXPORT HWND CreateDialogIndirectParamW(
    HINSTANCE hInstance,
    const void *lpTemplate,
    HWND hWndParent,
    void *lpDialogFunc,
    LPARAM dwInitParam)
{
    (void)hInstance;
    (void)lpTemplate;
    (void)hWndParent;
    (void)lpDialogFunc;
    (void)dwInitParam;
    return NULL;
}

/* ----------------------------------------------------------------
 * CheckRadioButton
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL CheckRadioButton(HWND hDlg, int nIDFirstButton,
                                     int nIDLastButton, int nIDCheckButton)
{
    (void)hDlg;
    (void)nIDFirstButton;
    (void)nIDLastButton;
    (void)nIDCheckButton;
    return TRUE;
}
