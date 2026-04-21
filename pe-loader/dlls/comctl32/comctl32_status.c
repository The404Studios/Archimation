/*
 * comctl32_status.c - msctls_statusbar32 widget.
 *
 * Bottom of window, divided into N panes by SB_SETPARTS.
 *
 * Messages: SB_SETPARTS, SB_GETPARTS, SB_SETTEXTA, SB_GETTEXTA,
 *           SB_GETTEXTLENGTHA, SB_GETBORDERS, SB_SETMINHEIGHT, SB_SIMPLE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "comctl_internal.h"

#define RGB(r,g,b) ((DWORD)(((BYTE)(r)|((WORD)((BYTE)(g))<<8))|(((DWORD)(BYTE)(b))<<16)))

#define SB_MAX_PARTS  16
#define SB_MAX_TEXT   256

typedef struct {
    int   n_parts;
    int   right_edges[SB_MAX_PARTS]; /* x coordinates; -1 = extend to right */
    char  texts[SB_MAX_PARTS][SB_MAX_TEXT];
    int   simple;
    char  simple_text[SB_MAX_TEXT];
    int   min_height;
} statusbar_state_t;

static statusbar_state_t *sb_get_or_alloc(HWND hwnd)
{
    statusbar_state_t *s = (statusbar_state_t *)comctl_state_get(hwnd, COMCTL_KIND_STATUSBAR);
    if (s) return s;
    s = (statusbar_state_t *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->n_parts = 1;
    s->right_edges[0] = -1;
    comctl_state_set(hwnd, COMCTL_KIND_STATUSBAR, s);
    return s;
}

static void sb_paint(HWND hwnd, statusbar_state_t *s)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->BeginPaint || !im->EndPaint) return;

    PAINTSTRUCT_local ps;
    HDC hdc = im->BeginPaint(hwnd, &ps);
    if (!hdc) return;

    RECT rc = {0};
    if (im->GetClientRect) im->GetClientRect(hwnd, &rc);

    int v6 = comctl32_v6();
    DWORD bg, sep, text_col;
    if (v6) {
        bg       = RGB(0xF0, 0xF0, 0xF0);
        sep      = RGB(0xC8, 0xC8, 0xC8);
        text_col = RGB(0x10, 0x10, 0x10);
    } else {
        bg       = RGB(0xC0, 0xC0, 0xC0);
        sep      = RGB(0x80, 0x80, 0x80);
        text_col = RGB(0x00, 0x00, 0x00);
    }

    HBRUSH bgb = im->CreateSolidBrush ? im->CreateSolidBrush(bg) : NULL;
    if (im->FillRect) im->FillRect(hdc, &rc, bgb);
    if (bgb && im->DeleteObject) im->DeleteObject(bgb);

    /* Top edge */
    if (im->MoveToEx && im->LineTo) {
        HPEN pen = im->CreatePen ? im->CreatePen(0, 1, sep) : NULL;
        HGDIOBJ old = pen && im->SelectObject ? im->SelectObject(hdc, pen) : NULL;
        im->MoveToEx(hdc, rc.left, rc.top, NULL);
        im->LineTo(hdc, rc.right, rc.top);
        if (old && im->SelectObject) im->SelectObject(hdc, old);
        if (pen && im->DeleteObject) im->DeleteObject(pen);
    }

    if (im->SetBkMode) im->SetBkMode(hdc, 1);
    if (im->SetTextColor) im->SetTextColor(hdc, text_col);

    if (s->simple) {
        if (im->TextOutA && s->simple_text[0]) {
            im->TextOutA(hdc, rc.left + 4, rc.top + 4, s->simple_text,
                         (int)strlen(s->simple_text));
        }
    } else {
        int x_prev = rc.left;
        for (int i = 0; i < s->n_parts; i++) {
            int x_end = (s->right_edges[i] < 0) ? rc.right : s->right_edges[i];
            if (im->TextOutA && s->texts[i][0]) {
                im->TextOutA(hdc, x_prev + 4, rc.top + 4, s->texts[i],
                             (int)strlen(s->texts[i]));
            }
            /* Vertical separator */
            if (i < s->n_parts - 1 && im->MoveToEx && im->LineTo) {
                HPEN pen = im->CreatePen ? im->CreatePen(0, 1, sep) : NULL;
                HGDIOBJ old = pen && im->SelectObject ? im->SelectObject(hdc, pen) : NULL;
                im->MoveToEx(hdc, x_end - 1, rc.top + 2, NULL);
                im->LineTo(hdc, x_end - 1, rc.bottom - 2);
                if (old && im->SelectObject) im->SelectObject(hdc, old);
                if (pen && im->DeleteObject) im->DeleteObject(pen);
            }
            x_prev = x_end;
        }
    }

    im->EndPaint(hwnd, &ps);
}

static LRESULT MSABI sb_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    statusbar_state_t *s = sb_get_or_alloc(hwnd);
    const comctl_imports_t *im = comctl_get_imports();

    switch (msg) {
        case WM_PAINT:
            if (s) sb_paint(hwnd, s);
            return 0;

        case SB_SETPARTS:
            if (s && lparam) {
                int n = (int)wparam;
                if (n < 1) n = 1;
                if (n > SB_MAX_PARTS) n = SB_MAX_PARTS;
                const int *edges = (const int *)lparam;
                for (int i = 0; i < n; i++) s->right_edges[i] = edges[i];
                s->n_parts = n;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return TRUE;
            }
            return FALSE;

        case SB_GETPARTS:
            if (s && lparam && wparam > 0) {
                int n = (int)wparam;
                if (n > s->n_parts) n = s->n_parts;
                int *out = (int *)lparam;
                for (int i = 0; i < n; i++) out[i] = s->right_edges[i];
                return s->n_parts;
            }
            return s ? s->n_parts : 0;

        case SB_SETTEXTA:
            if (s) {
                int idx = (int)(wparam & 0xFF);
                if (idx == 255) { /* SB_SIMPLEID */
                    if (lparam) {
                        strncpy(s->simple_text, (const char *)lparam, SB_MAX_TEXT - 1);
                        s->simple_text[SB_MAX_TEXT - 1] = '\0';
                    }
                } else if (idx >= 0 && idx < SB_MAX_PARTS) {
                    if (lparam) {
                        strncpy(s->texts[idx], (const char *)lparam, SB_MAX_TEXT - 1);
                        s->texts[idx][SB_MAX_TEXT - 1] = '\0';
                    } else {
                        s->texts[idx][0] = '\0';
                    }
                }
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return TRUE;
            }
            return FALSE;

        case SB_GETTEXTA:
            if (s && lparam) {
                int idx = (int)(wparam & 0xFF);
                const char *src = (idx == 255) ? s->simple_text :
                                  (idx >= 0 && idx < SB_MAX_PARTS) ? s->texts[idx] : "";
                size_t n = strlen(src);
                memcpy((void *)lparam, src, n);
                ((char *)lparam)[n] = '\0';
                return (LRESULT)n;
            }
            return 0;

        case SB_GETTEXTLENGTHA:
            if (s) {
                int idx = (int)(wparam & 0xFF);
                const char *src = (idx == 255) ? s->simple_text :
                                  (idx >= 0 && idx < SB_MAX_PARTS) ? s->texts[idx] : "";
                return (LRESULT)strlen(src);
            }
            return 0;

        case SB_GETBORDERS:
            /* Returns horiz, vert, separator widths in three int slots */
            if (lparam) {
                int *out = (int *)lparam;
                out[0] = 2;
                out[1] = 2;
                out[2] = 2;
                return TRUE;
            }
            return FALSE;

        case SB_SETMINHEIGHT:
            if (s) {
                s->min_height = (int)wparam;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
            }
            return 0;

        case SB_SIMPLE:
            if (s) {
                s->simple = (int)wparam ? 1 : 0;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
            }
            return TRUE;

        case WM_NCDESTROY:
            comctl_state_free(hwnd);
            break;
    }

    return im->DefWindowProcA ? im->DefWindowProcA(hwnd, msg, wparam, lparam) : 0;
}

void register_statusbar_class(void)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->RegisterClassA) return;

    WNDCLASSA_local wc = {0};
    wc.style         = 0x0003;
    wc.lpfnWndProc   = sb_wndproc;
    wc.lpszClassName = STATUSCLASSNAME_A;
    im->RegisterClassA(&wc);
    fprintf(stderr, "[comctl32] register_statusbar_class: %s registered (v6=%d)\n",
            STATUSCLASSNAME_A, comctl32_v6());
}
