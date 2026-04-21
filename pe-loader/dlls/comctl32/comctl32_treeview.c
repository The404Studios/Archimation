/*
 * comctl32_treeview.c - SysTreeView32 widget.
 *
 * Hierarchical view with expand/collapse +/- glyphs.  HTREEITEM is just an
 * opaque pointer to one of our tv_node_t entries (well within the legal
 * "treat HTREEITEM as opaque" contract).
 *
 * Messages: TVM_INSERTITEMA, TVM_DELETEITEM, TVM_EXPAND, TVM_GETCOUNT,
 *           TVM_GETITEMRECT.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "comctl_internal.h"

#define RGB(r,g,b) ((DWORD)(((BYTE)(r)|((WORD)((BYTE)(g))<<8))|(((DWORD)(BYTE)(b))<<16)))

#define TV_MAX_TEXT  256
#define TV_MAX_NODES 1024

#define TVI_ROOT  ((HANDLE)(intptr_t)-0x10000)
#define TVI_LAST  ((HANDLE)(intptr_t)-0x0FFFF)

#define TVIF_TEXT  0x0001
#define TVIF_PARAM 0x0004

typedef struct tv_node {
    char      text[TV_MAX_TEXT];
    int       expanded;
    LPARAM    user_param;
    int       parent;     /* index in nodes[] or -1 for root-level */
    int       used;
} tv_node_t;

/* TVITEMA mirror (subset) */
typedef struct {
    UINT      mask;
    HANDLE    hItem;
    UINT      state;
    UINT      stateMask;
    char     *pszText;
    int       cchTextMax;
    int       iImage;
    int       iSelectedImage;
    int       cChildren;
    LPARAM    lParam;
} TVITEMA_local;

typedef struct {
    UINT          mask;
    HANDLE        hParent;
    HANDLE        hInsertAfter;
    TVITEMA_local item;
} TVINSERTSTRUCTA_local;

typedef struct {
    tv_node_t nodes[TV_MAX_NODES];
    int       count;
    int       v_scroll_offset; /* pixels scrolled past the top.  WM_PAINT
                                * shifts y by this; WM_VSCROLL adjusts. */
    int       last_content_h;  /* total visible-tree pixels at last paint —
                                * used to clamp scroll offset on size /
                                * delete events. */
    int       sel_node;        /* idx in nodes[] or -1 */
    bool      ws_vscroll_enabled; /* true if WS_VSCROLL was set at create time;
                                   * drives eager SetScrollInfo prime so the
                                   * track renders before first tv_paint. */
} treeview_state_t;

#define TV_ROW_H 18

static treeview_state_t *tv_get_or_alloc(HWND hwnd)
{
    treeview_state_t *s = (treeview_state_t *)comctl_state_get(hwnd, COMCTL_KIND_TREEVIEW);
    if (s) return s;
    s = (treeview_state_t *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    for (int i = 0; i < TV_MAX_NODES; i++) s->nodes[i].parent = -2; /* sentinel */
    s->sel_node = -1;
    comctl_state_set(hwnd, COMCTL_KIND_TREEVIEW, s);
    return s;
}

/* Push current scroll metrics to user32. */
static void tv_update_scrollinfo(HWND hwnd, treeview_state_t *s, int client_h)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->SetScrollInfo) return;
    SCROLLINFO_local si;
    si.cbSize    = sizeof(si);
    si.fMask     = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMin      = 0;
    si.nMax      = s->last_content_h;
    si.nPage     = (UINT)(client_h > 0 ? client_h : 0);
    si.nPos      = s->v_scroll_offset;
    si.nTrackPos = s->v_scroll_offset;
    im->SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
}

static int tv_alloc_node(treeview_state_t *s)
{
    for (int i = 0; i < TV_MAX_NODES; i++) {
        if (!s->nodes[i].used) {
            memset(&s->nodes[i], 0, sizeof(tv_node_t));
            s->nodes[i].used = 1;
            s->nodes[i].parent = -1;
            s->count++;
            return i;
        }
    }
    return -1;
}

static int tv_node_to_idx(treeview_state_t *s, HANDLE h)
{
    if (h == TVI_ROOT || !h) return -1;
    /* HTREEITEM is &s->nodes[idx]; recover idx by pointer arithmetic. */
    tv_node_t *n = (tv_node_t *)h;
    if (n < &s->nodes[0] || n >= &s->nodes[TV_MAX_NODES]) return -1;
    int idx = (int)(n - &s->nodes[0]);
    if (!s->nodes[idx].used) return -1;
    return idx;
}

/* Recursive paint helper — single-pass DFS, indent based on parent chain.
 * Returns the new running Y after this subtree. */
static int tv_paint_node(HDC hdc, treeview_state_t *s, int idx, int depth, int y,
                         RECT *rc, const comctl_imports_t *im,
                         DWORD line_col)
{
    int row_h = TV_ROW_H;
    int x = rc->left + depth * 16;
    /* Skip rows entirely above the visible region (scrolled off the top). */
    if (y + row_h <= rc->top) {
        int next_y = y + row_h;
        if (s->nodes[idx].expanded) {
            for (int j = 0; j < TV_MAX_NODES; j++) {
                if (s->nodes[j].used && s->nodes[j].parent == idx)
                    next_y = tv_paint_node(hdc, s, j, depth + 1, next_y, rc, im, line_col);
            }
        }
        return next_y;
    }
    /* Selection background (full row) */
    if (idx == s->sel_node && im->FillRect && im->CreateSolidBrush) {
        RECT srrc = {rc->left, y, rc->right, y + row_h};
        HBRUSH sel = im->CreateSolidBrush(comctl32_v6() ?
            RGB(0xCB, 0xE2, 0xF6) : RGB(0x33, 0x66, 0xCC));
        im->FillRect(hdc, &srrc, sel);
        if (im->DeleteObject) im->DeleteObject(sel);
    }

    /* Plus/minus glyph if has visible children */
    int has_children = 0;
    for (int j = 0; j < TV_MAX_NODES; j++) {
        if (s->nodes[j].used && s->nodes[j].parent == idx) { has_children = 1; break; }
    }
    if (has_children) {
        if (im->Rectangle) {
            HPEN pen = im->CreatePen ? im->CreatePen(0, 1, line_col) : NULL;
            HGDIOBJ old = pen && im->SelectObject ? im->SelectObject(hdc, pen) : NULL;
            im->Rectangle(hdc, x, y + 4, x + 10, y + 14);
            if (old && im->SelectObject) im->SelectObject(hdc, old);
            if (pen && im->DeleteObject) im->DeleteObject(pen);
        }
        if (im->TextOutA) {
            const char *glyph = s->nodes[idx].expanded ? "-" : "+";
            im->TextOutA(hdc, x + 3, y + 2, glyph, 1);
        }
    }

    if (im->TextOutA && s->nodes[idx].text[0]) {
        im->TextOutA(hdc, x + 16, y + 2, s->nodes[idx].text,
                     (int)strlen(s->nodes[idx].text));
    }
    y += row_h;

    if (s->nodes[idx].expanded) {
        for (int j = 0; j < TV_MAX_NODES; j++) {
            if (s->nodes[j].used && s->nodes[j].parent == idx && y < rc->bottom) {
                y = tv_paint_node(hdc, s, j, depth + 1, y, rc, im, line_col);
            }
        }
    }
    return y;
}

static void tv_paint(HWND hwnd, treeview_state_t *s)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->BeginPaint || !im->EndPaint) return;

    PAINTSTRUCT_local ps;
    HDC hdc = im->BeginPaint(hwnd, &ps);
    if (!hdc) return;

    RECT rc = {0};
    if (im->GetClientRect) im->GetClientRect(hwnd, &rc);

    int v6 = comctl32_v6();
    DWORD bg, line_col, text_col;
    if (v6) {
        bg = RGB(0xFF, 0xFF, 0xFF);
        line_col = RGB(0xCC, 0xCC, 0xCC);
        text_col = RGB(0x10, 0x10, 0x10);
    } else {
        bg = RGB(0xFF, 0xFF, 0xFF);
        line_col = RGB(0x80, 0x80, 0x80);
        text_col = RGB(0x00, 0x00, 0x00);
    }

    HBRUSH bgb = im->CreateSolidBrush ? im->CreateSolidBrush(bg) : NULL;
    if (im->FillRect) im->FillRect(hdc, &rc, bgb);
    if (bgb && im->DeleteObject) im->DeleteObject(bgb);

    if (im->SetBkMode) im->SetBkMode(hdc, 1);
    if (im->SetTextColor) im->SetTextColor(hdc, text_col);

    /* Paint root-level nodes (parent == -1) in the order they appear.
     * Apply v_scroll_offset by starting above rc.top by that many pixels;
     * tv_paint_node skips rows whose bottom is still < rc.top. */
    int y = rc.top + 2 - s->v_scroll_offset;
    int start_y = y;
    for (int i = 0; i < TV_MAX_NODES && y < rc.bottom; i++) {
        if (s->nodes[i].used && s->nodes[i].parent == -1) {
            y = tv_paint_node(hdc, s, i, 0, y, &rc, im, line_col);
        }
    }
    /* Cache the laid-out content height (relative) for scrollbar metrics. */
    s->last_content_h = y - start_y;
    int max_off = s->last_content_h - (rc.bottom - rc.top);
    if (max_off < 0) max_off = 0;
    if (s->v_scroll_offset > max_off) s->v_scroll_offset = max_off;
    if (s->v_scroll_offset < 0)       s->v_scroll_offset = 0;

    tv_update_scrollinfo(hwnd, s, rc.bottom - rc.top);

    im->EndPaint(hwnd, &ps);
}

/* Find the visible-row index at (y_client) by replaying the DFS the paint
 * uses.  Returns node idx or -1.  Updates *out_y if non-NULL. */
static int tv_hit_test(treeview_state_t *s, int y_client, RECT *rc)
{
    int y = rc->top + 2 - s->v_scroll_offset;
    int target_idx = -1;
    /* Iterative pre-order traversal mirroring tv_paint_node */
    int stack[TV_MAX_NODES];
    int depth_stack[TV_MAX_NODES];
    int sp = 0;
    /* Push root nodes in reverse so we visit in order */
    int last_root = -1;
    for (int i = TV_MAX_NODES - 1; i >= 0; i--) {
        if (s->nodes[i].used && s->nodes[i].parent == -1) {
            if (sp < TV_MAX_NODES) {
                stack[sp] = i;
                depth_stack[sp] = 0;
                sp++;
            }
            last_root = i;
        }
    }
    (void)last_root;
    while (sp > 0) {
        sp--;
        int idx = stack[sp];
        int depth = depth_stack[sp];
        if (y_client >= y && y_client < y + TV_ROW_H) {
            target_idx = idx;
            break;
        }
        y += TV_ROW_H;
        if (s->nodes[idx].expanded) {
            for (int j = TV_MAX_NODES - 1; j >= 0; j--) {
                if (s->nodes[j].used && s->nodes[j].parent == idx) {
                    if (sp < TV_MAX_NODES) {
                        stack[sp] = j;
                        depth_stack[sp] = depth + 1;
                        sp++;
                    }
                }
            }
        }
    }
    return target_idx;
}

static LRESULT MSABI tv_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    treeview_state_t *s = tv_get_or_alloc(hwnd);
    const comctl_imports_t *im = comctl_get_imports();

    switch (msg) {
        case WM_NCCREATE:
        case WM_CREATE:
            /* A SysTreeView32 window almost always ends up taller than the
             * client area once the user expands the tree.  Mirror the listview
             * behavior: if the caller didn't request WS_VSCROLL we OR it in
             * here so the non-client frame reserves the bar from frame 1 and
             * sibling layout math using GetClientRect doesn't shift when the
             * first node gets inserted.  Then prime SetScrollInfo with zero-
             * range metrics so the track is visible immediately; real metrics
             * get written on the first paint once we know the client rect +
             * node count. */
            if (s && im->GetWindowLongA) {
                LONG style = im->GetWindowLongA(hwnd, GWL_STYLE);
                if (!(style & WS_VSCROLL) && im->SetWindowLongA) {
                    im->SetWindowLongA(hwnd, GWL_STYLE, style | WS_VSCROLL);
                    style |= WS_VSCROLL;
                }
                if (style & WS_VSCROLL) {
                    SCROLLINFO_local si;
                    si.cbSize    = sizeof(si);
                    si.fMask     = SIF_ALL;
                    si.nMin      = 0;
                    si.nMax      = 0;
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
            if (s) tv_paint(hwnd, s);
            return 0;

        case TVM_GETCOUNT:
            return s ? s->count : 0;

        case TVM_INSERTITEMA:
            if (s && lparam) {
                const TVINSERTSTRUCTA_local *ins = (const TVINSERTSTRUCTA_local *)lparam;
                int idx = tv_alloc_node(s);
                if (idx < 0) return 0;
                if ((ins->item.mask & TVIF_TEXT) && ins->item.pszText) {
                    strncpy(s->nodes[idx].text, ins->item.pszText, TV_MAX_TEXT - 1);
                    s->nodes[idx].text[TV_MAX_TEXT - 1] = '\0';
                }
                if (ins->item.mask & TVIF_PARAM) {
                    s->nodes[idx].user_param = ins->item.lParam;
                }
                int parent_idx = tv_node_to_idx(s, ins->hParent);
                s->nodes[idx].parent = parent_idx;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return (LRESULT)(uintptr_t)&s->nodes[idx];
            }
            return 0;

        case TVM_DELETEITEM:
            if (s) {
                int idx = tv_node_to_idx(s, (HANDLE)lparam);
                if (idx < 0) {
                    /* TVI_ROOT == delete-all */
                    if ((HANDLE)lparam == TVI_ROOT) {
                        for (int i = 0; i < TV_MAX_NODES; i++) {
                            if (s->nodes[i].used) {
                                s->nodes[i].used = 0;
                            }
                        }
                        s->count = 0;
                        if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                        return TRUE;
                    }
                    return FALSE;
                }
                /* Recursively delete children */
                int changed;
                do {
                    changed = 0;
                    for (int i = 0; i < TV_MAX_NODES; i++) {
                        if (s->nodes[i].used && s->nodes[i].parent == idx) {
                            s->nodes[i].used = 0;
                            s->count--;
                            changed = 1;
                        }
                    }
                } while (changed);
                s->nodes[idx].used = 0;
                s->count--;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return TRUE;
            }
            return FALSE;

        case TVM_EXPAND:
            if (s) {
                int idx = tv_node_to_idx(s, (HANDLE)lparam);
                if (idx < 0) return FALSE;
                int code = (int)wparam & 0xF;
                if (code == TVE_EXPAND)   s->nodes[idx].expanded = 1;
                else if (code == TVE_COLLAPSE) s->nodes[idx].expanded = 0;
                else if (code == TVE_TOGGLE)   s->nodes[idx].expanded = !s->nodes[idx].expanded;
                if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                return TRUE;
            }
            return FALSE;

        case TVM_GETITEMRECT:
            /* Approximation: return full client rect.  Real impl would walk
             * the visible-row list to find the right Y. */
            if (lparam && im->GetClientRect) {
                im->GetClientRect(hwnd, (LPRECT)lparam);
                return TRUE;
            }
            return FALSE;

        case WM_VSCROLL:
            if (s) {
                RECT rc = {0};
                if (im->GetClientRect) im->GetClientRect(hwnd, &rc);
                int max_off = s->last_content_h - (rc.bottom - rc.top);
                if (max_off < 0) max_off = 0;
                int code = (int)(wparam & 0xFFFF);
                int step = TV_ROW_H;
                int page = (rc.bottom - rc.top) - TV_ROW_H;
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
                if (s->v_scroll_offset < 0)       s->v_scroll_offset = 0;
                if (s->v_scroll_offset > max_off) s->v_scroll_offset = max_off;
                if (prev != s->v_scroll_offset && im->InvalidateRect)
                    im->InvalidateRect(hwnd, NULL, FALSE);
            }
            return 0;

        case WM_MOUSEWHEEL:
            if (s) {
                int delta = (int)(short)((wparam >> 16) & 0xFFFF);
                int notches = delta / 120;
                if (!notches) notches = (delta > 0) - (delta < 0);
                int prev = s->v_scroll_offset;
                s->v_scroll_offset -= notches * TV_ROW_H * 3;
                RECT rc = {0};
                if (im->GetClientRect) im->GetClientRect(hwnd, &rc);
                int max_off = s->last_content_h - (rc.bottom - rc.top);
                if (max_off < 0) max_off = 0;
                if (s->v_scroll_offset < 0)       s->v_scroll_offset = 0;
                if (s->v_scroll_offset > max_off) s->v_scroll_offset = max_off;
                if (prev != s->v_scroll_offset && im->InvalidateRect)
                    im->InvalidateRect(hwnd, NULL, FALSE);
            }
            return 0;

        case WM_LBUTTONDOWN:
            if (s) {
                int x_click = (int)(short)(lparam & 0xFFFF);
                int y_click = (int)(short)((lparam >> 16) & 0xFFFF);
                RECT rc = {0};
                if (im->GetClientRect) im->GetClientRect(hwnd, &rc);
                int idx = tv_hit_test(s, y_click, &rc);
                if (idx >= 0 && idx != s->sel_node) {
                    int prev = s->sel_node;
                    s->sel_node = idx;
                    if (im->InvalidateRect) im->InvalidateRect(hwnd, NULL, FALSE);
                    comctl_notify_parent(hwnd, NM_CLICK);
                    /* Emit full NMTREEVIEW so the parent can read the new/old
                     * item lParams (the caller passed them in TVM_INSERTITEMA
                     * via TVIF_PARAM — we stashed them in tv_node_t.user_param). */
                    if (im->GetParent && im->SendMessageA) {
                        HWND parent = im->GetParent(hwnd);
                        if (parent) {
                            int ctrl_id = im->GetDlgCtrlID ? im->GetDlgCtrlID(hwnd) : 0;
                            NMTREEVIEW nmtv = {0};
                            nmtv.hdr.hwndFrom = hwnd;
                            nmtv.hdr.idFrom   = (UINT_PTR)ctrl_id;
                            nmtv.hdr.code     = TVN_SELCHANGEDA;
                            nmtv.action       = TVC_BYMOUSE;
                            nmtv.itemNew.hItem  = (HANDLE)&s->nodes[idx];
                            nmtv.itemNew.state  = 0x0002 /*TVIS_SELECTED*/;
                            nmtv.itemNew.lParam = s->nodes[idx].user_param;
                            if (prev >= 0) {
                                nmtv.itemOld.hItem  = (HANDLE)&s->nodes[prev];
                                nmtv.itemOld.lParam = s->nodes[prev].user_param;
                            }
                            nmtv.ptDrag.x = x_click;
                            nmtv.ptDrag.y = y_click;
                            im->SendMessageA(parent, WM_NOTIFY,
                                             (WPARAM)ctrl_id, (LPARAM)(uintptr_t)&nmtv);
                        }
                    }
                }
            }
            return 0;

        case WM_NCDESTROY:
            comctl_state_free(hwnd);
            break;
    }

    return im->DefWindowProcA ? im->DefWindowProcA(hwnd, msg, wparam, lparam) : 0;
}

void register_treeview_class(void)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->RegisterClassA) return;

    WNDCLASSA_local wc = {0};
    wc.style         = 0x0003;
    wc.lpfnWndProc   = tv_wndproc;
    wc.lpszClassName = WC_TREEVIEW_A;
    im->RegisterClassA(&wc);
    fprintf(stderr, "[comctl32] register_treeview_class: %s registered (v6=%d)\n",
            WC_TREEVIEW_A, comctl32_v6());
}
