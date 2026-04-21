/*
 * comctl32_button.c - Themed Button common-control.
 *
 * Note: classic Win32 "Button" class lives in user32, but comctl v6 replaces
 * it with a themed subclass.  We only register this class when the v6 flag
 * is set so we don't clobber user32's plain Button.  When v5 is in effect,
 * apps still get user32's Button.
 *
 * Supported:
 *   BS_PUSHBUTTON / BS_DEFPUSHBUTTON : push button with hover/pressed states
 *   BS_CHECKBOX / BS_AUTOCHECKBOX    : square + checkmark
 *   BS_RADIOBUTTON / BS_AUTORADIO    : circle + dot
 * Messages:
 *   BM_SETSTATE / BM_GETSTATE / BM_GETCHECK / BM_SETCHECK / BM_CLICK
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "comctl_internal.h"

#define RGB(r,g,b) ((DWORD)(((BYTE)(r)|((WORD)((BYTE)(g))<<8))|(((DWORD)(BYTE)(b))<<16)))

typedef struct {
    DWORD    style;        /* BS_* flags from CreateWindowEx */
    int      pressed;      /* BM_SETSTATE current state */
    int      checked;      /* BM_SETCHECK 0/1 */
    char     text[128];    /* WM_SETTEXT cache */
} button_state_t;

static LRESULT MSABI button_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

static button_state_t *button_get_or_alloc(HWND hwnd)
{
    button_state_t *s = (button_state_t *)comctl_state_get(hwnd, COMCTL_KIND_BUTTON);
    if (s) return s;
    s = (button_state_t *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->style = BS_PUSHBUTTON;
    comctl_state_set(hwnd, COMCTL_KIND_BUTTON, s);
    return s;
}

static void button_paint(HWND hwnd, button_state_t *s)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->BeginPaint || !im->EndPaint) return;

    PAINTSTRUCT_local ps;
    HDC hdc = im->BeginPaint(hwnd, &ps);
    if (!hdc) return;

    RECT rc = {0};
    if (im->GetClientRect) im->GetClientRect(hwnd, &rc);

    int v6 = comctl32_v6();
    DWORD bg, border, text_col;
    if (v6) {
        /* Aero-ish: subtle blue gradient simulated by two flat fills */
        bg       = s->pressed ? RGB(0xCC, 0xE4, 0xF7) : RGB(0xF0, 0xF6, 0xFC);
        border   = s->pressed ? RGB(0x00, 0x5A, 0x9E) : RGB(0x70, 0x96, 0xB3);
        text_col = RGB(0x10, 0x10, 0x10);
    } else {
        /* Classic 95: hard gray, sunk-in when pressed */
        bg       = RGB(0xC0, 0xC0, 0xC0);
        border   = s->pressed ? RGB(0x00, 0x00, 0x00) : RGB(0x80, 0x80, 0x80);
        text_col = RGB(0x00, 0x00, 0x00);
    }

    int btype = s->style & BS_TYPEMASK;

    if (btype == BS_CHECKBOX || btype == BS_AUTOCHECKBOX) {
        /* Small box on the left + label on the right */
        int box_sz = (rc.bottom - rc.top) - 4;
        if (box_sz > 16) box_sz = 16;
        if (im->FillRect) {
            HBRUSH bb = im->CreateSolidBrush ? im->CreateSolidBrush(RGB(0xFF,0xFF,0xFF)) : NULL;
            RECT box = {rc.left + 2, rc.top + 2, rc.left + 2 + box_sz, rc.top + 2 + box_sz};
            im->FillRect(hdc, &box, bb);
            if (bb && im->DeleteObject) im->DeleteObject(bb);
        }
        if (s->checked && im->MoveToEx && im->LineTo) {
            HPEN pen = im->CreatePen ? im->CreatePen(0, 2, RGB(0,0,0)) : NULL;
            HGDIOBJ old = pen && im->SelectObject ? im->SelectObject(hdc, pen) : NULL;
            int x0 = rc.left + 4, y0 = rc.top + 4 + box_sz/2;
            im->MoveToEx(hdc, x0, y0, NULL);
            im->LineTo(hdc, x0 + box_sz/3, y0 + box_sz/3);
            im->LineTo(hdc, x0 + box_sz - 2, y0 - box_sz/3);
            if (old && im->SelectObject) im->SelectObject(hdc, old);
            if (pen && im->DeleteObject) im->DeleteObject(pen);
        }
        if (im->TextOutA && s->text[0]) {
            if (im->SetBkMode) im->SetBkMode(hdc, 1 /* TRANSPARENT */);
            if (im->SetTextColor) im->SetTextColor(hdc, text_col);
            im->TextOutA(hdc, rc.left + box_sz + 8, rc.top + 2, s->text, (int)strlen(s->text));
        }
    } else if (btype == BS_RADIOBUTTON || btype == BS_AUTORADIOBUTTON) {
        /* Approximate with a square box (no native ellipse in our gdi32). */
        int box_sz = (rc.bottom - rc.top) - 4;
        if (box_sz > 14) box_sz = 14;
        HBRUSH bb = im->CreateSolidBrush ? im->CreateSolidBrush(RGB(0xFF,0xFF,0xFF)) : NULL;
        RECT box = {rc.left + 2, rc.top + 2, rc.left + 2 + box_sz, rc.top + 2 + box_sz};
        if (im->FillRect) im->FillRect(hdc, &box, bb);
        if (bb && im->DeleteObject) im->DeleteObject(bb);
        if (s->checked) {
            HBRUSH dot = im->CreateSolidBrush ? im->CreateSolidBrush(RGB(0,0,0)) : NULL;
            RECT d = {box.left + 3, box.top + 3, box.right - 3, box.bottom - 3};
            if (im->FillRect) im->FillRect(hdc, &d, dot);
            if (dot && im->DeleteObject) im->DeleteObject(dot);
        }
        if (im->TextOutA && s->text[0]) {
            if (im->SetBkMode) im->SetBkMode(hdc, 1);
            if (im->SetTextColor) im->SetTextColor(hdc, text_col);
            im->TextOutA(hdc, rc.left + box_sz + 8, rc.top + 2, s->text, (int)strlen(s->text));
        }
    } else {
        /* Push button */
        int painted = 0;
        if (v6 && im->GradientFill) {
            /* Real Aero-ish vertical gradient: light at top, slightly darker
             * at bottom (or pressed = inverted).  Per-pixel SetPixel inside
             * GradientFill is correct but slow; small button rects keep it
             * affordable. */
            DWORD top, bot;
            if (s->pressed) {
                top = RGB(0xCC, 0xE4, 0xF7);
                bot = RGB(0xE6, 0xF1, 0xFB);
            } else {
                top = RGB(0xFB, 0xFD, 0xFF);
                bot = RGB(0xDC, 0xEB, 0xFA);
            }
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
            painted = im->GradientFill(hdc, vx, 2, &gr, 1, GRADIENT_FILL_RECT_V) ? 1 : 0;
        }
        if (!painted) {
            HBRUSH face = im->CreateSolidBrush ? im->CreateSolidBrush(bg) : NULL;
            if (im->FillRect) im->FillRect(hdc, &rc, face);
            if (face && im->DeleteObject) im->DeleteObject(face);
        }

        if (im->Rectangle) {
            HPEN pen = im->CreatePen ? im->CreatePen(0, 1, border) : NULL;
            HGDIOBJ old = pen && im->SelectObject ? im->SelectObject(hdc, pen) : NULL;
            im->Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
            if (old && im->SelectObject) im->SelectObject(hdc, old);
            if (pen && im->DeleteObject) im->DeleteObject(pen);
        }

        if (im->TextOutA && s->text[0]) {
            if (im->SetBkMode) im->SetBkMode(hdc, 1);
            if (im->SetTextColor) im->SetTextColor(hdc, text_col);
            int w = rc.right - rc.left;
            int len = (int)strlen(s->text);
            int tx = rc.left + (w - len * 7) / 2; /* rough centering */
            if (tx < rc.left + 2) tx = rc.left + 2;
            int ty = rc.top + ((rc.bottom - rc.top) - 14) / 2;
            if (s->pressed) { tx += 1; ty += 1; }
            im->TextOutA(hdc, tx, ty, s->text, len);
        }
    }

    im->EndPaint(hwnd, &ps);
}

static LRESULT MSABI button_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    button_state_t *s = button_get_or_alloc(hwnd);
    const comctl_imports_t *im = comctl_get_imports();

    switch (msg) {
        case WM_CREATE:
            /* lParam is CREATESTRUCT*; we ignore most of it and rely on
             * SetWindowLong-style style queries that callers rarely make. */
            return 0;

        case WM_SETTEXT:
            if (s && lparam) {
                strncpy(s->text, (const char *)lparam, sizeof(s->text) - 1);
                s->text[sizeof(s->text) - 1] = '\0';
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, TRUE);
            }
            return TRUE;

        case WM_GETTEXTLENGTH:
            return s ? (LRESULT)strlen(s->text) : 0;

        case WM_GETTEXT:
            if (s && lparam && wparam > 0) {
                size_t n = strlen(s->text);
                if (n >= wparam) n = wparam - 1;
                memcpy((void *)lparam, s->text, n);
                ((char *)lparam)[n] = '\0';
                return (LRESULT)n;
            }
            return 0;

        case WM_PAINT:
            if (s) button_paint(hwnd, s);
            return 0;

        case WM_LBUTTONDOWN:
            if (s) {
                s->pressed = 1;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
            }
            return 0;

        case WM_LBUTTONUP:
            if (s) {
                s->pressed = 0;
                int btype = s->style & BS_TYPEMASK;
                if (btype == BS_AUTOCHECKBOX) s->checked = !s->checked;
                else if (btype == BS_AUTORADIOBUTTON) s->checked = 1;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                /* WM_COMMAND/BN_CLICKED -> parent.  Win32 sends this on
                 * mouse-up over the captured button (we don't track capture
                 * yet so we send it unconditionally on every up). */
                comctl_notify_command(hwnd, BN_CLICKED);
            }
            return 0;

        case BM_GETCHECK:
            return s ? s->checked : 0;
        case BM_SETCHECK:
            if (s) {
                s->checked = (int)wparam;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
            }
            return 0;
        case BM_GETSTATE:
            return s ? s->pressed : 0;
        case BM_SETSTATE:
            if (s) {
                s->pressed = (int)wparam;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
            }
            return 0;
        case BM_CLICK:
            if (s) {
                int btype = s->style & BS_TYPEMASK;
                if (btype == BS_AUTOCHECKBOX) s->checked = !s->checked;
                else if (btype == BS_AUTORADIOBUTTON) s->checked = 1;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                comctl_notify_command(hwnd, BN_CLICKED);
            }
            return 0;
        case BM_SETSTYLE:
            if (s) {
                s->style = (DWORD)wparam;
                if (lparam && im->InvalidateRect) im->InvalidateRect(hwnd, NULL, TRUE);
            }
            return 0;

        case WM_NCDESTROY:
            comctl_state_free(hwnd);
            break;
    }

    return im->DefWindowProcA ? im->DefWindowProcA(hwnd, msg, wparam, lparam) : 0;
}

void register_button_class(void)
{
    /* Only register over user32's Button if v6 is active.  When v6 isn't
     * declared, leave user32's plain implementation in charge. */
    if (!comctl32_v6()) {
        fprintf(stderr, "[comctl32] register_button_class: v5 mode, leaving user32 Button alone\n");
        return;
    }
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->RegisterClassA) return;

    WNDCLASSA_local wc = {0};
    wc.style         = 0x0008 | 0x0003; /* CS_DBLCLKS | CS_HREDRAW|VREDRAW */
    wc.lpfnWndProc   = button_wndproc;
    wc.hInstance     = NULL;
    wc.lpszClassName = WC_BUTTON_A;
    /* RegisterClassA in user32 will fail with ERROR_ALREADY_EXISTS if
     * user32 already registered "Button"; that's fine — first registration
     * wins for legacy mode, and v6 apps reach this path early enough to
     * register before user32 gets called. */
    im->RegisterClassA(&wc);
    fprintf(stderr, "[comctl32] register_button_class: v6 themed Button registered\n");
}
