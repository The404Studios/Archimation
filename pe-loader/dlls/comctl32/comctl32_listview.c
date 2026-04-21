/*
 * comctl32_listview.c - SysListView32 widget (LVS_REPORT focus).
 *
 * Implements the report (table) mode: header row + scrollable item rows
 * with per-subitem text.  No icons, no virtual mode, no sort, no editing.
 * That's the 80% of real-world ListView usage.
 *
 * Messages: LVM_INSERTCOLUMNA, LVM_INSERTITEMA, LVM_SETITEMTEXTA,
 *           LVM_GETITEMCOUNT, LVM_GETCOLUMNCOUNT, LVM_DELETEITEM,
 *           LVM_DELETEALLITEMS, LVM_SETBKCOLOR, LVM_GETBKCOLOR.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "comctl_internal.h"

#define RGB(r,g,b) ((DWORD)(((BYTE)(r)|((WORD)((BYTE)(g))<<8))|(((DWORD)(BYTE)(b))<<16)))

#define LV_MAX_COLS  16
#define LV_MAX_ITEMS 1024
#define LV_MAX_TEXT  256

/* LVCOLUMNA — only fields we read */
typedef struct {
    UINT  mask;
    int   fmt;
    int   cx;
    char *pszText;
    int   cchTextMax;
    int   iSubItem;
} LVCOLUMNA_local;

/* LVITEMA — only fields we read */
typedef struct {
    UINT       mask;
    int        iItem;
    int        iSubItem;
    UINT       state;
    UINT       stateMask;
    char      *pszText;
    int        cchTextMax;
    int        iImage;
    LPARAM     lParam;
} LVITEMA_local;

#define LVIF_TEXT    0x0001
#define LVCF_TEXT    0x0004
#define LVCF_WIDTH   0x0002

typedef struct {
    char  text[LV_MAX_TEXT];
    int   width;
} lv_col_t;

typedef struct {
    char   cells[LV_MAX_COLS][LV_MAX_TEXT];
    LPARAM lparam;            /* User lParam passed at LVM_INSERTITEMA; echoed
                               * back out on NMLISTVIEW.lParam for notifies. */
} lv_row_t;

typedef struct {
    int      n_cols;
    int      n_rows;
    lv_col_t cols[LV_MAX_COLS];
    lv_row_t *rows; /* heap, capacity = LV_MAX_ITEMS */
    DWORD    bk_color;
    int      bk_color_set;
    int      v_scroll_offset; /* pixels scrolled past the top of the items
                               * region.  Always >=0 and <= max valid offset.
                               * WM_PAINT subtracts this from row Y; WM_VSCROLL
                               * adjusts it. */
    int      sel_row;         /* -1 = none.  Updated on WM_LBUTTONDOWN inside
                               * the items region; drives LVN_ITEMCHANGED. */
    bool     ws_vscroll_enabled; /* true if WS_VSCROLL was set at create time,
                                  * so we primed SetScrollInfo eagerly instead
                                  * of waiting for the first paint. */
} listview_state_t;

static listview_state_t *lv_get_or_alloc(HWND hwnd)
{
    listview_state_t *s = (listview_state_t *)comctl_state_get(hwnd, COMCTL_KIND_LISTVIEW);
    if (s) return s;
    s = (listview_state_t *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->rows = (lv_row_t *)calloc(LV_MAX_ITEMS, sizeof(lv_row_t));
    if (!s->rows) { free(s); return NULL; }
    /* Default column width when caller doesn't set one */
    for (int i = 0; i < LV_MAX_COLS; i++) s->cols[i].width = 100;
    s->v_scroll_offset = 0;
    s->sel_row = -1;
    comctl_state_set(hwnd, COMCTL_KIND_LISTVIEW, s);
    return s;
}

/* Tunables shared between paint + WM_VSCROLL.  Keeping them at file scope
 * means a future style change touches one spot. */
#define LV_HEADER_H  22
#define LV_ROW_H     18

/* Compute the maximum valid v_scroll_offset given current state + visible
 * region.  Returns 0 when content fits.  Public so WM_SIZE / scroll
 * handlers stay in sync. */
static int lv_max_scroll(const listview_state_t *s, int client_h)
{
    int items_h    = client_h - LV_HEADER_H;
    if (items_h < 0) items_h = 0;
    int total_h    = s->n_rows * LV_ROW_H;
    int overflow_h = total_h - items_h;
    return overflow_h > 0 ? overflow_h : 0;
}

/* Push current scrollbar metrics to user32. */
static void lv_update_scrollinfo(HWND hwnd, listview_state_t *s, int client_h)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->SetScrollInfo) return;
    int items_h = client_h - LV_HEADER_H;
    if (items_h < 0) items_h = 0;
    SCROLLINFO_local si;
    si.cbSize    = sizeof(si);
    si.fMask     = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMin      = 0;
    si.nMax      = s->n_rows * LV_ROW_H; /* total content height */
    si.nPage     = (UINT)items_h;        /* visible page in pixels */
    si.nPos      = s->v_scroll_offset;
    si.nTrackPos = s->v_scroll_offset;
    im->SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
}

static void lv_paint(HWND hwnd, listview_state_t *s)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->BeginPaint || !im->EndPaint) return;

    PAINTSTRUCT_local ps;
    HDC hdc = im->BeginPaint(hwnd, &ps);
    if (!hdc) return;

    RECT rc = {0};
    if (im->GetClientRect) im->GetClientRect(hwnd, &rc);

    int v6 = comctl32_v6();
    DWORD bg, header_bg, header_text, item_text, gridline;
    if (v6) {
        bg          = s->bk_color_set ? s->bk_color : RGB(0xFF, 0xFF, 0xFF);
        header_bg   = RGB(0xF0, 0xF0, 0xF0);
        header_text = RGB(0x33, 0x33, 0x33);
        item_text   = RGB(0x10, 0x10, 0x10);
        gridline    = RGB(0xE0, 0xE0, 0xE0);
    } else {
        bg          = s->bk_color_set ? s->bk_color : RGB(0xFF, 0xFF, 0xFF);
        header_bg   = RGB(0xC0, 0xC0, 0xC0);
        header_text = RGB(0x00, 0x00, 0x00);
        item_text   = RGB(0x00, 0x00, 0x00);
        gridline    = RGB(0x80, 0x80, 0x80);
    }

    /* Background */
    HBRUSH bgb = im->CreateSolidBrush ? im->CreateSolidBrush(bg) : NULL;
    if (im->FillRect) im->FillRect(hdc, &rc, bgb);
    if (bgb && im->DeleteObject) im->DeleteObject(bgb);

    int header_h = LV_HEADER_H;
    int row_h    = LV_ROW_H;

    /* Clamp scroll offset to current geometry — caller may have removed rows
     * since the last scroll without sending a new SB_PAGEDOWN. */
    int max_off = lv_max_scroll(s, rc.bottom - rc.top);
    if (s->v_scroll_offset > max_off) s->v_scroll_offset = max_off;
    if (s->v_scroll_offset < 0)       s->v_scroll_offset = 0;

    /* Header row */
    RECT hrc = {rc.left, rc.top, rc.right, rc.top + header_h};
    HBRUSH hbb = im->CreateSolidBrush ? im->CreateSolidBrush(header_bg) : NULL;
    if (im->FillRect) im->FillRect(hdc, &hrc, hbb);
    if (hbb && im->DeleteObject) im->DeleteObject(hbb);

    if (im->SetBkMode) im->SetBkMode(hdc, 1 /* TRANSPARENT */);
    if (im->SetTextColor) im->SetTextColor(hdc, header_text);

    int x = rc.left;
    for (int c = 0; c < s->n_cols && x < rc.right; c++) {
        if (im->TextOutA && s->cols[c].text[0]) {
            im->TextOutA(hdc, x + 4, rc.top + 4, s->cols[c].text,
                         (int)strlen(s->cols[c].text));
        }
        x += s->cols[c].width;
        /* Vertical separator after each column */
        if (im->MoveToEx && im->LineTo) {
            HPEN pen = im->CreatePen ? im->CreatePen(0, 1, gridline) : NULL;
            HGDIOBJ old = pen && im->SelectObject ? im->SelectObject(hdc, pen) : NULL;
            im->MoveToEx(hdc, x - 1, rc.top, NULL);
            im->LineTo(hdc, x - 1, rc.bottom);
            if (old && im->SelectObject) im->SelectObject(hdc, old);
            if (pen && im->DeleteObject) im->DeleteObject(pen);
        }
    }

    /* Header underline */
    if (im->MoveToEx && im->LineTo) {
        HPEN pen = im->CreatePen ? im->CreatePen(0, 1, gridline) : NULL;
        HGDIOBJ old = pen && im->SelectObject ? im->SelectObject(hdc, pen) : NULL;
        im->MoveToEx(hdc, rc.left, rc.top + header_h - 1, NULL);
        im->LineTo(hdc, rc.right, rc.top + header_h - 1);
        if (old && im->SelectObject) im->SelectObject(hdc, old);
        if (pen && im->DeleteObject) im->DeleteObject(pen);
    }

    /* Item rows — apply scroll offset to compute starting row + initial Y. */
    if (im->SetTextColor) im->SetTextColor(hdc, item_text);
    int first_row = s->v_scroll_offset / row_h;
    int phase     = s->v_scroll_offset - first_row * row_h; /* fractional row */
    int items_top = rc.top + header_h;
    int y = items_top - phase;
    for (int r = first_row; r < s->n_rows && y < rc.bottom; r++, y += row_h) {
        if (y + row_h <= items_top) continue; /* fully clipped above */
        /* Alternating row tint in v6 only.  Index by absolute row so the
         * stripes remain stable while scrolling. */
        if (v6 && (r & 1)) {
            RECT rrc = {rc.left, y, rc.right, y + row_h};
            HBRUSH alt = im->CreateSolidBrush ? im->CreateSolidBrush(RGB(0xF7, 0xFA, 0xFD)) : NULL;
            if (im->FillRect) im->FillRect(hdc, &rrc, alt);
            if (alt && im->DeleteObject) im->DeleteObject(alt);
        }
        if (r == s->sel_row) {
            RECT rrc = {rc.left, y, rc.right, y + row_h};
            HBRUSH sel = im->CreateSolidBrush ?
                im->CreateSolidBrush(v6 ? RGB(0xCB, 0xE2, 0xF6) : RGB(0x33, 0x66, 0xCC)) : NULL;
            if (im->FillRect) im->FillRect(hdc, &rrc, sel);
            if (sel && im->DeleteObject) im->DeleteObject(sel);
            if (im->SetTextColor) im->SetTextColor(hdc, v6 ? item_text : RGB(0xFF, 0xFF, 0xFF));
        }
        x = rc.left;
        for (int c = 0; c < s->n_cols && x < rc.right; c++) {
            if (im->TextOutA && s->rows[r].cells[c][0]) {
                im->TextOutA(hdc, x + 4, y + 2, s->rows[r].cells[c],
                             (int)strlen(s->rows[r].cells[c]));
            }
            x += s->cols[c].width;
        }
        if (r == s->sel_row && im->SetTextColor) im->SetTextColor(hdc, item_text);
    }

    /* Sync scrollbar position after every paint — cheap and keeps the
     * thumb glued to model state under DPI/size changes. */
    lv_update_scrollinfo(hwnd, s, rc.bottom - rc.top);

    im->EndPaint(hwnd, &ps);
}

/* Hit-test a click in the items region to a row index.  Returns -1 outside
 * any row or in the header. */
static int lv_hit_test_row(listview_state_t *s, int y_client, RECT *rc)
{
    if (y_client < rc->top + LV_HEADER_H) return -1;
    int rel = y_client - (rc->top + LV_HEADER_H) + s->v_scroll_offset;
    int idx = rel / LV_ROW_H;
    if (idx < 0 || idx >= s->n_rows) return -1;
    return idx;
}

/* Hit-test an X-coordinate to a sub-item (column) index.  Walks accumulated
 * column widths left-to-right; returns -1 outside any column.  Used by the
 * NM_CLICK / LVN_ITEMCHANGED notify path so the parent can tell which cell
 * was clicked without replaying our layout math itself. */
static int lv_hit_test_subitem(const listview_state_t *s, int x_client, RECT *rc)
{
    int x = rc->left;
    for (int c = 0; c < s->n_cols; c++) {
        int next_x = x + s->cols[c].width;
        if (x_client >= x && x_client < next_x) return c;
        x = next_x;
    }
    return -1;
}

static LRESULT MSABI lv_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    listview_state_t *s = lv_get_or_alloc(hwnd);
    const comctl_imports_t *im = comctl_get_imports();

    switch (msg) {
        case WM_NCCREATE:
        case WM_CREATE:
            /* A SysListView32 window is essentially always going to need a
             * vertical scrollbar sooner or later — report-mode rows spill past
             * the client area quickly.  Many real Win32 apps (including .NET's
             * System.Windows.Forms.ListView) omit WS_VSCROLL at CreateWindowEx
             * time on the assumption that comctl32 will manage it, then read
             * GetClientRect and lay out siblings based on the expected
             * scrollbar width.  If WS_VSCROLL is missing we silently OR it in
             * here so the non-client frame reserves the bar from frame 1.
             *
             * Once set, prime SetScrollInfo with zero-range metrics so the
             * track renders on the first paint instead of waiting for rows to
             * overflow.  We repeat this work in lv_update_scrollinfo on every
             * paint, but a client-drawn scrollbar needs nonzero metrics at
             * the instant of the first NCCALCSIZE — otherwise the bar is
             * hidden and the ::rect shrinks back after we add rows, causing a
             * visible layout shift. */
            if (s && im->GetWindowLongA) {
                LONG style = im->GetWindowLongA(hwnd, GWL_STYLE);
                if (!(style & WS_VSCROLL) && im->SetWindowLongA) {
                    /* Auto-enable the scrollbar.  Keep the write idempotent —
                     * SetWindowLongA returns the previous value but we don't
                     * need it.  Report-style only; if the app is in LVS_LIST
                     * or iconic mode they'll see an unused bar but the layout
                     * stays consistent with real Win32. */
                    im->SetWindowLongA(hwnd, GWL_STYLE, style | WS_VSCROLL);
                    style |= WS_VSCROLL;
                }
                if (style & WS_VSCROLL) {
                    SCROLLINFO_local si;
                    si.cbSize    = sizeof(si);
                    si.fMask     = SIF_ALL;
                    si.nMin      = 0;
                    si.nMax      = 0;   /* no rows yet */
                    si.nPage     = 1;
                    si.nPos      = 0;
                    si.nTrackPos = 0;
                    if (im->SetScrollInfo)
                        im->SetScrollInfo(hwnd, SB_VERT, &si, FALSE);
                    s->ws_vscroll_enabled = true;
                }
            }
            return (msg == WM_NCCREATE) ? TRUE : 0;

        case WM_PAINT:
            if (s) lv_paint(hwnd, s);
            return 0;

        case LVM_GETITEMCOUNT:
            return s ? s->n_rows : 0;

        case LVM_GETCOLUMNCOUNT:
            return s ? s->n_cols : 0;

        case LVM_INSERTCOLUMNA:
            if (s && lparam) {
                const LVCOLUMNA_local *col = (const LVCOLUMNA_local *)lparam;
                int idx = (int)wparam;
                if (idx < 0 || idx >= LV_MAX_COLS) return -1;
                /* Capacity check MUST run before the shift: when n_cols is
                 * already at LV_MAX_COLS and idx < LV_MAX_COLS, the shift
                 * loop below would write s->cols[LV_MAX_COLS] (one past the
                 * fixed-size array). Reject at-capacity inserts up front. */
                if (s->n_cols >= LV_MAX_COLS) return -1;
                if (idx > s->n_cols) idx = s->n_cols;
                /* Shift right — safe now that n_cols < LV_MAX_COLS so
                 * s->cols[n_cols] is a valid in-bounds slot. */
                for (int i = s->n_cols; i > idx; i--) s->cols[i] = s->cols[i - 1];
                memset(&s->cols[idx], 0, sizeof(lv_col_t));
                s->cols[idx].width = (col->mask & LVCF_WIDTH) ? col->cx : 100;
                if ((col->mask & LVCF_TEXT) && col->pszText) {
                    strncpy(s->cols[idx].text, col->pszText, LV_MAX_TEXT - 1);
                    s->cols[idx].text[LV_MAX_TEXT - 1] = '\0';
                }
                s->n_cols++;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return idx;
            }
            return -1;

        case LVM_INSERTITEMA:
            if (s && lparam) {
                const LVITEMA_local *it = (const LVITEMA_local *)lparam;
                int idx = it->iItem;
                if (idx < 0 || idx > s->n_rows || s->n_rows >= LV_MAX_ITEMS) return -1;
                /* Shift down */
                for (int i = s->n_rows; i > idx; i--) s->rows[i] = s->rows[i - 1];
                memset(&s->rows[idx], 0, sizeof(lv_row_t));
                if ((it->mask & LVIF_TEXT) && it->pszText && it->iSubItem >= 0
                    && it->iSubItem < LV_MAX_COLS) {
                    strncpy(s->rows[idx].cells[it->iSubItem], it->pszText, LV_MAX_TEXT - 1);
                    s->rows[idx].cells[it->iSubItem][LV_MAX_TEXT - 1] = '\0';
                }
                /* Stash caller's lParam (LVIF_PARAM mask) — echoed on
                 * NMLISTVIEW.lParam in WM_NOTIFY so the parent can resolve
                 * its own per-row context (typical Win32 pattern). */
                if (it->mask & LVIF_PARAM) s->rows[idx].lparam = it->lParam;
                s->n_rows++;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return idx;
            }
            return -1;

        case LVM_SETITEMTEXTA:
            if (s && lparam) {
                const LVITEMA_local *it = (const LVITEMA_local *)lparam;
                int idx = (int)wparam;
                if (idx < 0 || idx >= s->n_rows) return FALSE;
                if (it->iSubItem < 0 || it->iSubItem >= LV_MAX_COLS) return FALSE;
                if (it->pszText) {
                    strncpy(s->rows[idx].cells[it->iSubItem], it->pszText, LV_MAX_TEXT - 1);
                    s->rows[idx].cells[it->iSubItem][LV_MAX_TEXT - 1] = '\0';
                }
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return TRUE;
            }
            return FALSE;

        case LVM_DELETEITEM:
            if (s) {
                int idx = (int)wparam;
                if (idx < 0 || idx >= s->n_rows) return FALSE;
                for (int i = idx; i < s->n_rows - 1; i++) s->rows[i] = s->rows[i + 1];
                s->n_rows--;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return TRUE;
            }
            return FALSE;

        case LVM_DELETEALLITEMS:
            if (s) {
                s->n_rows = 0;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return TRUE;
            }
            return FALSE;

        case LVM_SETBKCOLOR:
            if (s) {
                s->bk_color = (DWORD)lparam;
                s->bk_color_set = 1;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
            }
            return TRUE;

        case LVM_GETBKCOLOR:
            return s ? (LRESULT)s->bk_color : 0;

        case WM_VSCROLL:
            if (s) {
                RECT rc = {0};
                if (im->GetClientRect) im->GetClientRect(hwnd, &rc);
                int max_off = lv_max_scroll(s, rc.bottom - rc.top);
                int code = (int)(wparam & 0xFFFF);
                int step = LV_ROW_H;
                int page = ((rc.bottom - rc.top) - LV_HEADER_H) - LV_ROW_H;
                if (page < step) page = step;
                int prev = s->v_scroll_offset;
                switch (code) {
                case SB_LINEUP:        s->v_scroll_offset -= step; break;
                case SB_LINEDOWN:      s->v_scroll_offset += step; break;
                case SB_PAGEUP:        s->v_scroll_offset -= page; break;
                case SB_PAGEDOWN:      s->v_scroll_offset += page; break;
                case SB_THUMBPOSITION:
                case SB_THUMBTRACK:    s->v_scroll_offset = (int)((wparam >> 16) & 0xFFFF); break;
                case SB_TOP:           s->v_scroll_offset = 0; break;
                case SB_BOTTOM:        s->v_scroll_offset = max_off; break;
                default: break;
                }
                if (s->v_scroll_offset < 0)        s->v_scroll_offset = 0;
                if (s->v_scroll_offset > max_off)  s->v_scroll_offset = max_off;
                if (prev != s->v_scroll_offset && im->InvalidateRect)
                    im->InvalidateRect(hwnd, NULL, FALSE);
            }
            return 0;

        case WM_MOUSEWHEEL:
            if (s) {
                /* High word of wparam is the wheel delta in multiples of 120
                 * (WHEEL_DELTA).  Three rows per notch matches MS default. */
                int delta = (int)(short)((wparam >> 16) & 0xFFFF);
                int notches = delta / 120;
                if (!notches) notches = (delta > 0) - (delta < 0);
                int prev = s->v_scroll_offset;
                s->v_scroll_offset -= notches * LV_ROW_H * 3;
                RECT rc = {0};
                if (im->GetClientRect) im->GetClientRect(hwnd, &rc);
                int max_off = lv_max_scroll(s, rc.bottom - rc.top);
                if (s->v_scroll_offset < 0)       s->v_scroll_offset = 0;
                if (s->v_scroll_offset > max_off) s->v_scroll_offset = max_off;
                if (prev != s->v_scroll_offset && im->InvalidateRect)
                    im->InvalidateRect(hwnd, NULL, FALSE);
            }
            return 0;

        case WM_LBUTTONDOWN:
            if (s) {
                /* lparam packs (x,y) — y is the high word of the low DWORD. */
                int x_click = (int)(short)(lparam & 0xFFFF);
                int y_click = (int)(short)((lparam >> 16) & 0xFFFF);
                RECT rc = {0};
                if (im->GetClientRect) im->GetClientRect(hwnd, &rc);
                int row = lv_hit_test_row(s, y_click, &rc);
                if (row >= 0 && row != s->sel_row) {
                    int prev = s->sel_row;
                    int subitem = lv_hit_test_subitem(s, x_click, &rc);
                    if (subitem < 0) subitem = 0;
                    s->sel_row = row;
                    if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                    /* Two notifies in the exact order real comctl32 uses:
                     *   1. NM_CLICK   — parent often uses this to open menus
                     *      or drive drag-start heuristics before selection
                     *      changes; we send the *full* NMLISTVIEW so the
                     *      parent can cast to it and read iItem/iSubItem/
                     *      ptAction/lParam.  uChanged = 0 per MS docs for
                     *      NM_CLICK (state change is reported separately).
                     *   2. LVN_ITEMCHANGED — carries the actual selection
                     *      transition with uNewState/uOldState/uChanged set. */
                    if (im->GetParent && im->SendMessageA) {
                        HWND parent = im->GetParent(hwnd);
                        if (parent) {
                            int ctrl_id = im->GetDlgCtrlID ? im->GetDlgCtrlID(hwnd) : 0;

                            NMLISTVIEW nmlv_click = {0};
                            nmlv_click.hdr.hwndFrom = hwnd;
                            nmlv_click.hdr.idFrom   = (UINT_PTR)ctrl_id;
                            nmlv_click.hdr.code     = NM_CLICK;
                            nmlv_click.iItem        = row;
                            nmlv_click.iSubItem     = subitem;
                            nmlv_click.uChanged     = 0;
                            nmlv_click.ptAction.x   = x_click;
                            nmlv_click.ptAction.y   = y_click;
                            nmlv_click.lParam       = s->rows[row].lparam;
                            im->SendMessageA(parent, WM_NOTIFY,
                                             (WPARAM)ctrl_id, (LPARAM)(uintptr_t)&nmlv_click);

                            NMLISTVIEW nmlv = {0};
                            nmlv.hdr.hwndFrom = hwnd;
                            nmlv.hdr.idFrom   = (UINT_PTR)ctrl_id;
                            nmlv.hdr.code     = LVN_ITEMCHANGED;
                            nmlv.iItem        = row;
                            nmlv.iSubItem     = subitem;
                            nmlv.uNewState    = LVIS_SELECTED | LVIS_FOCUSED;
                            nmlv.uOldState    = (prev == row) ? (LVIS_SELECTED | LVIS_FOCUSED) : 0;
                            nmlv.uChanged     = LVIF_STATE;
                            nmlv.ptAction.x   = x_click;
                            nmlv.ptAction.y   = y_click;
                            nmlv.lParam       = s->rows[row].lparam; /* real user data */
                            im->SendMessageA(parent, WM_NOTIFY,
                                             (WPARAM)ctrl_id, (LPARAM)(uintptr_t)&nmlv);
                        }
                    }
                }
            }
            return 0;

        case WM_NCDESTROY:
            if (s) free(s->rows);
            comctl_state_free(hwnd);
            break;
    }

    return im->DefWindowProcA ? im->DefWindowProcA(hwnd, msg, wparam, lparam) : 0;
}

void register_listview_class(void)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->RegisterClassA) return;

    WNDCLASSA_local wc = {0};
    wc.style         = 0x0003;
    wc.lpfnWndProc   = lv_wndproc;
    wc.lpszClassName = WC_LISTVIEW_A;
    im->RegisterClassA(&wc);
    fprintf(stderr, "[comctl32] register_listview_class: %s registered (v6=%d)\n",
            WC_LISTVIEW_A, comctl32_v6());
}
