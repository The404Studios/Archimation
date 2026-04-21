/*
 * comctl32_toolbar.c - ToolbarWindow32 widget.
 *
 * Horizontal row of buttons.  TB_BUTTONSTRUCTSIZE seeds the per-button
 * size, then TB_ADDBUTTONS appends count items.
 *
 * Messages: TB_BUTTONSTRUCTSIZE, TB_ADDBUTTONSA, TB_INSERTBUTTONA,
 *           TB_AUTOSIZE, TB_BUTTONCOUNT, TB_GETBUTTONSIZE, TB_ENABLEBUTTON.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "comctl_internal.h"

#define RGB(r,g,b) ((DWORD)(((BYTE)(r)|((WORD)((BYTE)(g))<<8))|(((DWORD)(BYTE)(b))<<16)))

#define TB_MAX 64

/* TBBUTTON mirror — first 7 fields, total 24 bytes on x64 */
typedef struct {
    int       iBitmap;
    int       idCommand;
    BYTE      fsState;
    BYTE      fsStyle;
    BYTE      bReserved[6];
    DWORD_PTR dwData;
    INT_PTR   iString;
} TBBUTTON_local;

#define TBSTATE_ENABLED   0x04
#define TBSTYLE_BUTTON    0x00
#define TBSTYLE_SEP       0x01

typedef struct {
    int            tbb_size;     /* TB_BUTTONSTRUCTSIZE — must match before adds */
    int            count;
    TBBUTTON_local btns[TB_MAX];
    int            btn_w;
    int            btn_h;
} toolbar_state_t;

static toolbar_state_t *tb_get_or_alloc(HWND hwnd)
{
    toolbar_state_t *s = (toolbar_state_t *)comctl_state_get(hwnd, COMCTL_KIND_TOOLBAR);
    if (s) return s;
    s = (toolbar_state_t *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->tbb_size = (int)sizeof(TBBUTTON_local);
    s->btn_w = 24;
    s->btn_h = 22;
    comctl_state_set(hwnd, COMCTL_KIND_TOOLBAR, s);
    return s;
}

static void tb_paint(HWND hwnd, toolbar_state_t *s)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->BeginPaint || !im->EndPaint) return;

    PAINTSTRUCT_local ps;
    HDC hdc = im->BeginPaint(hwnd, &ps);
    if (!hdc) return;

    RECT rc = {0};
    if (im->GetClientRect) im->GetClientRect(hwnd, &rc);

    int v6 = comctl32_v6();
    DWORD bg, btn_face, border, sep, text_col, dis_col;
    if (v6) {
        bg       = RGB(0xF8, 0xF8, 0xF8);
        btn_face = RGB(0xF0, 0xF0, 0xF0);
        border   = RGB(0xC0, 0xC0, 0xC0);
        sep      = RGB(0xD0, 0xD0, 0xD0);
        text_col = RGB(0x10, 0x10, 0x10);
        dis_col  = RGB(0xA0, 0xA0, 0xA0);
    } else {
        bg       = RGB(0xC0, 0xC0, 0xC0);
        btn_face = RGB(0xC0, 0xC0, 0xC0);
        border   = RGB(0x80, 0x80, 0x80);
        sep      = RGB(0x80, 0x80, 0x80);
        text_col = RGB(0x00, 0x00, 0x00);
        dis_col  = RGB(0x80, 0x80, 0x80);
    }

    int painted_bg = 0;
    if (v6 && im->GradientFill) {
        DWORD top = RGB(0xFC, 0xFC, 0xFC);
        DWORD bot = RGB(0xE8, 0xE8, 0xE8);
        TRIVERTEX vx[2];
        vx[0].x = rc.left;  vx[0].y = rc.top;
        vx[0].Red   = (USHORT)(((top      ) & 0xFF) << 8);
        vx[0].Green = (USHORT)(((top >>  8) & 0xFF) << 8);
        vx[0].Blue  = (USHORT)(((top >> 16) & 0xFF) << 8);
        vx[0].Alpha = 0;
        vx[1].x = rc.right; vx[1].y = rc.bottom;
        vx[1].Red   = (USHORT)(((bot      ) & 0xFF) << 8);
        vx[1].Green = (USHORT)(((bot >>  8) & 0xFF) << 8);
        vx[1].Blue  = (USHORT)(((bot >> 16) & 0xFF) << 8);
        vx[1].Alpha = 0;
        GRADIENT_RECT gr = {0, 1};
        painted_bg = im->GradientFill(hdc, vx, 2, &gr, 1, GRADIENT_FILL_RECT_V) ? 1 : 0;
    }
    if (!painted_bg) {
        HBRUSH bgb = im->CreateSolidBrush ? im->CreateSolidBrush(bg) : NULL;
        if (im->FillRect) im->FillRect(hdc, &rc, bgb);
        if (bgb && im->DeleteObject) im->DeleteObject(bgb);
    }

    if (im->SetBkMode) im->SetBkMode(hdc, 1);

    int x = rc.left + 4;
    for (int i = 0; i < s->count && x < rc.right; i++) {
        TBBUTTON_local *b = &s->btns[i];
        if (b->fsStyle & TBSTYLE_SEP) {
            /* Vertical separator */
            if (im->MoveToEx && im->LineTo) {
                HPEN pen = im->CreatePen ? im->CreatePen(0, 1, sep) : NULL;
                HGDIOBJ old = pen && im->SelectObject ? im->SelectObject(hdc, pen) : NULL;
                im->MoveToEx(hdc, x + 2, rc.top + 4, NULL);
                im->LineTo(hdc, x + 2, rc.bottom - 4);
                if (old && im->SelectObject) im->SelectObject(hdc, old);
                if (pen && im->DeleteObject) im->DeleteObject(pen);
            }
            x += 6;
        } else {
            RECT brc = {x, rc.top + 2, x + s->btn_w, rc.top + 2 + s->btn_h};
            HBRUSH face = im->CreateSolidBrush ? im->CreateSolidBrush(btn_face) : NULL;
            if (im->FillRect) im->FillRect(hdc, &brc, face);
            if (face && im->DeleteObject) im->DeleteObject(face);
            if (im->Rectangle) {
                HPEN pen = im->CreatePen ? im->CreatePen(0, 1, border) : NULL;
                HGDIOBJ old = pen && im->SelectObject ? im->SelectObject(hdc, pen) : NULL;
                im->Rectangle(hdc, brc.left, brc.top, brc.right, brc.bottom);
                if (old && im->SelectObject) im->SelectObject(hdc, old);
                if (pen && im->DeleteObject) im->DeleteObject(pen);
            }
            /* Draw command id as a tiny digit when no bitmap available */
            char buf[16];
            snprintf(buf, sizeof(buf), "%d", b->idCommand);
            DWORD col = (b->fsState & TBSTATE_ENABLED) ? text_col : dis_col;
            if (im->SetTextColor) im->SetTextColor(hdc, col);
            if (im->TextOutA) im->TextOutA(hdc, x + 4, rc.top + 6, buf, (int)strlen(buf));
            x += s->btn_w + 2;
        }
    }

    im->EndPaint(hwnd, &ps);
}

static LRESULT MSABI tb_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    toolbar_state_t *s = tb_get_or_alloc(hwnd);
    const comctl_imports_t *im = comctl_get_imports();

    switch (msg) {
        case WM_PAINT:
            if (s) tb_paint(hwnd, s);
            return 0;

        case TB_BUTTONSTRUCTSIZE:
            if (s) s->tbb_size = (int)wparam;
            return 0;

        case TB_ADDBUTTONSA:
            if (s && lparam) {
                int n = (int)wparam;
                const TBBUTTON_local *src = (const TBBUTTON_local *)lparam;
                for (int i = 0; i < n && s->count < TB_MAX; i++) {
                    s->btns[s->count++] = src[i];
                }
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return TRUE;
            }
            return FALSE;

        case TB_INSERTBUTTONA:
            if (s && lparam) {
                int idx = (int)wparam;
                if (idx < 0) idx = 0;
                if (idx > s->count) idx = s->count;
                if (s->count >= TB_MAX) return FALSE;
                for (int i = s->count; i > idx; i--) s->btns[i] = s->btns[i - 1];
                s->btns[idx] = *(const TBBUTTON_local *)lparam;
                s->count++;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return TRUE;
            }
            return FALSE;

        case TB_AUTOSIZE:
            /* Recompute extents — for our flat layout there's nothing to do
             * other than trigger a repaint. */
            if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
            return 0;

        case TB_BUTTONCOUNT:
            return s ? s->count : 0;

        case TB_GETBUTTONSIZE:
            /* LOWORD = width, HIWORD = height */
            if (s) return (LRESULT)((s->btn_w & 0xFFFF) | ((s->btn_h & 0xFFFF) << 16));
            return 0;

        case WM_LBUTTONDOWN:
            if (s && s->count > 0) {
                int x_click = (int)(short)(lparam & 0xFFFF);
                /* Replay tb_paint layout to find which button was hit. */
                int x = 4;
                int hit_cmd = -1;
                for (int i = 0; i < s->count; i++) {
                    if (s->btns[i].fsStyle & TBSTYLE_SEP) {
                        x += 6;
                        continue;
                    }
                    if (x_click >= x && x_click < x + s->btn_w) {
                        if (s->btns[i].fsState & TBSTATE_ENABLED) {
                            hit_cmd = s->btns[i].idCommand;
                        }
                        break;
                    }
                    x += s->btn_w + 2;
                }
                if (hit_cmd >= 0) {
                    /* Toolbar buttons notify the parent via WM_COMMAND with
                     * idFrom = idCommand and BN_CLICKED.  Bypass the helper
                     * because the ctrl_id in our case is the per-button
                     * command, not the toolbar HWND id. */
                    const comctl_imports_t *im2 = comctl_get_imports();
                    if (im2->GetParent && im2->SendMessageA) {
                        HWND parent = im2->GetParent(hwnd);
                        if (parent) {
                            im2->SendMessageA(parent, WM_COMMAND,
                                MAKEWPARAM(hit_cmd, BN_CLICKED),
                                (LPARAM)(uintptr_t)hwnd);
                        }
                    }
                }
            }
            return 0;

        case TB_ENABLEBUTTON:
            if (s) {
                int cmd = (int)wparam;
                int enable = (int)(lparam & 0xFFFF);
                for (int i = 0; i < s->count; i++) {
                    if (s->btns[i].idCommand == cmd) {
                        if (enable) s->btns[i].fsState |= TBSTATE_ENABLED;
                        else        s->btns[i].fsState &= (BYTE)~TBSTATE_ENABLED;
                    }
                }
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

void register_toolbar_class(void)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->RegisterClassA) return;

    WNDCLASSA_local wc = {0};
    wc.style         = 0x0003;
    wc.lpfnWndProc   = tb_wndproc;
    wc.lpszClassName = TOOLBARCLASSNAME_A;
    im->RegisterClassA(&wc);
    fprintf(stderr, "[comctl32] register_toolbar_class: %s registered (v6=%d)\n",
            TOOLBARCLASSNAME_A, comctl32_v6());
}
