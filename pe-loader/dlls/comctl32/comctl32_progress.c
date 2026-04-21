/*
 * comctl32_progress.c - msctls_progress32 widget.
 *
 * Messages: PBM_SETRANGE, PBM_SETRANGE32, PBM_GETRANGE, PBM_SETPOS,
 *           PBM_GETPOS, PBM_DELTAPOS, PBM_SETSTEP, PBM_STEPIT,
 *           PBM_SETBARCOLOR, PBM_SETBKCOLOR.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "comctl_internal.h"

#define RGB(r,g,b) ((DWORD)(((BYTE)(r)|((WORD)((BYTE)(g))<<8))|(((DWORD)(BYTE)(b))<<16)))

typedef struct {
    int     range_lo;
    int     range_hi;
    int     pos;
    int     step;
    DWORD   bar_color;     /* user-overridden via PBM_SETBARCOLOR */
    DWORD   bk_color;
    int     bar_color_set;
    int     bk_color_set;
} progress_state_t;

static progress_state_t *prog_get_or_alloc(HWND hwnd)
{
    progress_state_t *s = (progress_state_t *)comctl_state_get(hwnd, COMCTL_KIND_PROGRESS);
    if (s) return s;
    s = (progress_state_t *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->range_lo = 0;
    s->range_hi = 100;
    s->pos      = 0;
    s->step     = 10;
    comctl_state_set(hwnd, COMCTL_KIND_PROGRESS, s);
    return s;
}

static void prog_paint(HWND hwnd, progress_state_t *s)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->BeginPaint || !im->EndPaint) return;

    PAINTSTRUCT_local ps;
    HDC hdc = im->BeginPaint(hwnd, &ps);
    if (!hdc) return;

    RECT rc = {0};
    if (im->GetClientRect) im->GetClientRect(hwnd, &rc);

    int v6 = comctl32_v6();
    DWORD bg, bar, border;
    if (s->bk_color_set)  bg  = s->bk_color;
    else bg  = v6 ? RGB(0xE6, 0xE6, 0xE6) : RGB(0xC0, 0xC0, 0xC0);
    if (s->bar_color_set) bar = s->bar_color;
    else bar = v6 ? RGB(0x06, 0xB0, 0x25) : RGB(0x00, 0x00, 0x80);
    border = v6 ? RGB(0xBC, 0xBC, 0xBC) : RGB(0x80, 0x80, 0x80);

    HBRUSH bgb = im->CreateSolidBrush ? im->CreateSolidBrush(bg) : NULL;
    if (im->FillRect) im->FillRect(hdc, &rc, bgb);
    if (bgb && im->DeleteObject) im->DeleteObject(bgb);

    int range = s->range_hi - s->range_lo;
    if (range > 0) {
        int span  = rc.right - rc.left - 2;
        int p     = s->pos - s->range_lo;
        if (p < 0) p = 0;
        if (p > range) p = range;
        int w     = (int)((long long)span * p / range);
        RECT bar_rc = {rc.left + 1, rc.top + 1, rc.left + 1 + w, rc.bottom - 1};
        int painted = 0;
        if (v6 && im->GradientFill && w > 0) {
            /* Vista-style gradient: lighter top stripe, body color bottom. */
            DWORD top, bot;
            BYTE br = (BYTE)(bar);
            BYTE bg2 = (BYTE)((bar) >> 8);
            BYTE bb2 = (BYTE)((bar) >> 16);
            int lr = br + (255 - br) / 2;
            int lg = bg2 + (255 - bg2) / 2;
            int lb = bb2 + (255 - bb2) / 2;
            top = (DWORD)((BYTE)lr | ((WORD)((BYTE)lg) << 8) | ((DWORD)((BYTE)lb) << 16));
            bot = bar;
            TRIVERTEX vx[2];
            vx[0].x = bar_rc.left;  vx[0].y = bar_rc.top;
            vx[0].Red   = (USHORT)(((top      ) & 0xFF) << 8);
            vx[0].Green = (USHORT)(((top >>  8) & 0xFF) << 8);
            vx[0].Blue  = (USHORT)(((top >> 16) & 0xFF) << 8);
            vx[0].Alpha = 0;
            vx[1].x = bar_rc.right; vx[1].y = bar_rc.bottom;
            vx[1].Red   = (USHORT)(((bot      ) & 0xFF) << 8);
            vx[1].Green = (USHORT)(((bot >>  8) & 0xFF) << 8);
            vx[1].Blue  = (USHORT)(((bot >> 16) & 0xFF) << 8);
            vx[1].Alpha = 0;
            GRADIENT_RECT gr = {0, 1};
            painted = im->GradientFill(hdc, vx, 2, &gr, 1, GRADIENT_FILL_RECT_V) ? 1 : 0;
        }
        if (!painted) {
            HBRUSH bb3 = im->CreateSolidBrush ? im->CreateSolidBrush(bar) : NULL;
            if (im->FillRect) im->FillRect(hdc, &bar_rc, bb3);
            if (bb3 && im->DeleteObject) im->DeleteObject(bb3);
        }
    }

    if (im->Rectangle) {
        HPEN pen = im->CreatePen ? im->CreatePen(0, 1, border) : NULL;
        HGDIOBJ old = pen && im->SelectObject ? im->SelectObject(hdc, pen) : NULL;
        im->Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
        if (old && im->SelectObject) im->SelectObject(hdc, old);
        if (pen && im->DeleteObject) im->DeleteObject(pen);
    }

    im->EndPaint(hwnd, &ps);
}

static LRESULT MSABI prog_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    progress_state_t *s = prog_get_or_alloc(hwnd);
    const comctl_imports_t *im = comctl_get_imports();

    switch (msg) {
        case WM_PAINT:
            if (s) prog_paint(hwnd, s);
            return 0;

        case PBM_SETRANGE:
            /* Old API: LOWORD(lparam)=lo, HIWORD(lparam)=hi (16-bit) */
            if (s) {
                int prev = (s->range_hi << 16) | (s->range_lo & 0xFFFF);
                s->range_lo = (int)(short)((lparam) & 0xFFFF);
                s->range_hi = (int)(short)(((lparam) >> 16) & 0xFFFF);
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return prev;
            }
            return 0;

        case PBM_SETRANGE32:
            if (s) {
                s->range_lo = (int)wparam;
                s->range_hi = (int)lparam;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
            }
            return 0;

        case PBM_GETRANGE:
            /* lparam is PPBRANGE* — for simplicity we honor wparam selector */
            if (s && lparam) {
                int *out = (int *)lparam;
                out[0] = s->range_lo;
                out[1] = s->range_hi;
            }
            return s ? (wparam ? s->range_lo : s->range_hi) : 0;

        case PBM_SETPOS:
            if (s) {
                int prev = s->pos;
                s->pos = (int)wparam;
                if (s->pos < s->range_lo) s->pos = s->range_lo;
                if (s->pos > s->range_hi) s->pos = s->range_hi;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return prev;
            }
            return 0;

        case PBM_GETPOS:
            return s ? s->pos : 0;

        case PBM_DELTAPOS:
            if (s) {
                int prev = s->pos;
                s->pos += (int)wparam;
                if (s->pos < s->range_lo) s->pos = s->range_lo;
                if (s->pos > s->range_hi) s->pos = s->range_hi;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return prev;
            }
            return 0;

        case PBM_SETSTEP:
            if (s) {
                int prev = s->step;
                s->step = (int)wparam;
                return prev;
            }
            return 0;

        case PBM_STEPIT:
            if (s) {
                int prev = s->pos;
                s->pos += s->step;
                if (s->pos > s->range_hi) s->pos = s->range_lo; /* wrap */
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return prev;
            }
            return 0;

        case PBM_SETBARCOLOR:
            if (s) {
                DWORD prev = s->bar_color;
                s->bar_color = (DWORD)lparam;
                s->bar_color_set = 1;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return prev;
            }
            return 0;

        case PBM_SETBKCOLOR:
            if (s) {
                DWORD prev = s->bk_color;
                s->bk_color = (DWORD)lparam;
                s->bk_color_set = 1;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return prev;
            }
            return 0;

        case WM_NCDESTROY:
            comctl_state_free(hwnd);
            break;
    }

    return im->DefWindowProcA ? im->DefWindowProcA(hwnd, msg, wparam, lparam) : 0;
}

void register_progress_class(void)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->RegisterClassA) return;

    WNDCLASSA_local wc = {0};
    wc.style         = 0x0003;  /* CS_HREDRAW|VREDRAW */
    wc.lpfnWndProc   = prog_wndproc;
    wc.lpszClassName = PROGRESS_CLASS_A;
    im->RegisterClassA(&wc);
    fprintf(stderr, "[comctl32] register_progress_class: %s registered (v6=%d)\n",
            PROGRESS_CLASS_A, comctl32_v6());
}
