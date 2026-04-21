/*
 * comctl32_tab.c - SysTabControl32 widget.
 *
 * Top tab strip + content area below.  No images, no multi-line tabs.
 *
 * Messages: TCM_INSERTITEMA, TCM_DELETEITEM, TCM_DELETEALLITEMS,
 *           TCM_GETITEMCOUNT, TCM_GETCURSEL, TCM_SETCURSEL.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "comctl_internal.h"

#define RGB(r,g,b) ((DWORD)(((BYTE)(r)|((WORD)((BYTE)(g))<<8))|(((DWORD)(BYTE)(b))<<16)))

#define TAB_MAX        32
#define TAB_MAX_TEXT   64
#define TAB_HEIGHT     24

#define TCIF_TEXT      0x0001
#define TCIF_PARAM     0x0008

typedef struct {
    UINT    mask;
    DWORD   dwState;
    DWORD   dwStateMask;
    char   *pszText;
    int     cchTextMax;
    int     iImage;
    LPARAM  lParam;
} TCITEMA_local;

typedef struct {
    char   text[TAB_MAX_TEXT];
    LPARAM user_param;
} tab_t;

typedef struct {
    int   count;
    int   sel;
    tab_t tabs[TAB_MAX];
} tab_state_t;

static tab_state_t *tab_get_or_alloc(HWND hwnd)
{
    tab_state_t *s = (tab_state_t *)comctl_state_get(hwnd, COMCTL_KIND_TAB);
    if (s) return s;
    s = (tab_state_t *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->sel = -1;
    comctl_state_set(hwnd, COMCTL_KIND_TAB, s);
    return s;
}

static void tab_paint(HWND hwnd, tab_state_t *s)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->BeginPaint || !im->EndPaint) return;

    PAINTSTRUCT_local ps;
    HDC hdc = im->BeginPaint(hwnd, &ps);
    if (!hdc) return;

    RECT rc = {0};
    if (im->GetClientRect) im->GetClientRect(hwnd, &rc);

    int v6 = comctl32_v6();
    DWORD bg, tab_bg, sel_bg, border, text_col;
    if (v6) {
        bg       = RGB(0xF0, 0xF0, 0xF0);
        tab_bg   = RGB(0xE0, 0xE7, 0xEE);
        sel_bg   = RGB(0xFF, 0xFF, 0xFF);
        border   = RGB(0x88, 0xA8, 0xC8);
        text_col = RGB(0x10, 0x10, 0x10);
    } else {
        bg       = RGB(0xC0, 0xC0, 0xC0);
        tab_bg   = RGB(0xC0, 0xC0, 0xC0);
        sel_bg   = RGB(0xD0, 0xD0, 0xD0);
        border   = RGB(0x80, 0x80, 0x80);
        text_col = RGB(0x00, 0x00, 0x00);
    }

    /* Content panel */
    RECT panel = {rc.left, rc.top + TAB_HEIGHT, rc.right, rc.bottom};
    HBRUSH pb = im->CreateSolidBrush ? im->CreateSolidBrush(bg) : NULL;
    if (im->FillRect) im->FillRect(hdc, &panel, pb);
    if (pb && im->DeleteObject) im->DeleteObject(pb);
    if (im->Rectangle) {
        HPEN pen = im->CreatePen ? im->CreatePen(0, 1, border) : NULL;
        HGDIOBJ old = pen && im->SelectObject ? im->SelectObject(hdc, pen) : NULL;
        im->Rectangle(hdc, panel.left, panel.top, panel.right, panel.bottom);
        if (old && im->SelectObject) im->SelectObject(hdc, old);
        if (pen && im->DeleteObject) im->DeleteObject(pen);
    }

    /* Tabs */
    if (im->SetBkMode) im->SetBkMode(hdc, 1);
    if (im->SetTextColor) im->SetTextColor(hdc, text_col);

    int x = rc.left + 4;
    for (int i = 0; i < s->count; i++) {
        int len = (int)strlen(s->tabs[i].text);
        int tab_w = 16 + len * 7;
        if (tab_w < 60) tab_w = 60;
        RECT trc = {x, rc.top + 2, x + tab_w, rc.top + TAB_HEIGHT};
        DWORD fill = (i == s->sel) ? sel_bg : tab_bg;
        HBRUSH tb = im->CreateSolidBrush ? im->CreateSolidBrush(fill) : NULL;
        if (im->FillRect) im->FillRect(hdc, &trc, tb);
        if (tb && im->DeleteObject) im->DeleteObject(tb);
        if (im->Rectangle) {
            HPEN pen = im->CreatePen ? im->CreatePen(0, 1, border) : NULL;
            HGDIOBJ old = pen && im->SelectObject ? im->SelectObject(hdc, pen) : NULL;
            im->Rectangle(hdc, trc.left, trc.top, trc.right, trc.bottom);
            if (old && im->SelectObject) im->SelectObject(hdc, old);
            if (pen && im->DeleteObject) im->DeleteObject(pen);
        }
        if (im->TextOutA) {
            im->TextOutA(hdc, x + 8, rc.top + 6, s->tabs[i].text, len);
        }
        x += tab_w + 2;
        if (x > rc.right - 4) break;
    }

    im->EndPaint(hwnd, &ps);
}

static LRESULT MSABI tab_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    tab_state_t *s = tab_get_or_alloc(hwnd);
    const comctl_imports_t *im = comctl_get_imports();

    switch (msg) {
        case WM_PAINT:
            if (s) tab_paint(hwnd, s);
            return 0;

        case TCM_GETITEMCOUNT:
            return s ? s->count : 0;

        case TCM_GETCURSEL:
            return s ? s->sel : -1;

        case TCM_SETCURSEL:
            if (s) {
                int prev = s->sel;
                int idx = (int)wparam;
                if (idx < -1 || idx >= s->count) return -1;
                s->sel = idx;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                if (prev != idx) comctl_notify_parent(hwnd, TCN_SELCHANGE);
                return prev;
            }
            return -1;

        case WM_LBUTTONDOWN:
            if (s && s->count > 0) {
                int x_click = (int)(short)(lparam & 0xFFFF);
                int y_click = (int)(short)((lparam >> 16) & 0xFFFF);
                if (y_click >= 0 && y_click < TAB_HEIGHT) {
                    /* Replay tab_paint's layout to find the clicked index. */
                    int x = 4;
                    int hit = -1;
                    for (int i = 0; i < s->count; i++) {
                        int len = (int)strlen(s->tabs[i].text);
                        int tab_w = 16 + len * 7;
                        if (tab_w < 60) tab_w = 60;
                        if (x_click >= x && x_click < x + tab_w) { hit = i; break; }
                        x += tab_w + 2;
                    }
                    if (hit >= 0 && hit != s->sel) {
                        s->sel = hit;
                        if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                        comctl_notify_parent(hwnd, TCN_SELCHANGE);
                    }
                }
            }
            return 0;

        case TCM_INSERTITEMA:
            if (s && lparam) {
                const TCITEMA_local *it = (const TCITEMA_local *)lparam;
                int idx = (int)wparam;
                if (idx < 0 || idx > s->count || s->count >= TAB_MAX) return -1;
                for (int i = s->count; i > idx; i--) s->tabs[i] = s->tabs[i - 1];
                memset(&s->tabs[idx], 0, sizeof(tab_t));
                if ((it->mask & TCIF_TEXT) && it->pszText) {
                    strncpy(s->tabs[idx].text, it->pszText, TAB_MAX_TEXT - 1);
                    s->tabs[idx].text[TAB_MAX_TEXT - 1] = '\0';
                }
                if (it->mask & TCIF_PARAM) s->tabs[idx].user_param = it->lParam;
                s->count++;
                if (s->sel < 0) s->sel = idx;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return idx;
            }
            return -1;

        case TCM_DELETEITEM:
            if (s) {
                int idx = (int)wparam;
                if (idx < 0 || idx >= s->count) return FALSE;
                for (int i = idx; i < s->count - 1; i++) s->tabs[i] = s->tabs[i + 1];
                s->count--;
                if (s->sel >= s->count) s->sel = s->count - 1;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return TRUE;
            }
            return FALSE;

        case TCM_DELETEALLITEMS:
            if (s) {
                s->count = 0;
                s->sel = -1;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return TRUE;
            }
            return FALSE;

        case WM_NCDESTROY:
            comctl_state_free(hwnd);
            break;
    }

    return im->DefWindowProcA ? im->DefWindowProcA(hwnd, msg, wparam, lparam) : 0;
}

void register_tab_class(void)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->RegisterClassA) return;

    WNDCLASSA_local wc = {0};
    wc.style         = 0x0003;
    wc.lpfnWndProc   = tab_wndproc;
    wc.lpszClassName = WC_TABCONTROL_A;
    im->RegisterClassA(&wc);
    fprintf(stderr, "[comctl32] register_tab_class: %s registered (v6=%d)\n",
            WC_TABCONTROL_A, comctl32_v6());
}
