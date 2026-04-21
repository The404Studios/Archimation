/*
 * comctl_runtime.c - Shared runtime helpers for comctl32 widgets.
 *
 * Two responsibilities:
 *   1. Resolve user32/gdi32 entrypoints via dlsym(RTLD_DEFAULT) (the same
 *      pattern user32 itself uses to call gdi32, see user32_window.c).
 *   2. Maintain the per-HWND widget state table.
 *
 * Both are protected by a single mutex.  Slot count is fixed and small;
 * apps that exceed it lose new widgets but existing ones keep working.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <dlfcn.h>

#include "comctl_internal.h"

/* g_common_controls_v6 lives in pe-loader/loader/pe_resource.c, set during
 * EXE load when the manifest declares Microsoft.Windows.Common-Controls 6.x.
 * We resolve it via dlsym so this .so can load even when the loader symbol
 * isn't available (e.g. unit tests linking comctl32 stand-alone). */
int comctl32_v6(void)
{
    static int *cached = NULL;
    static int resolved = 0;
    if (!resolved) {
        cached = (int *)dlsym(RTLD_DEFAULT, "g_common_controls_v6");
        resolved = 1;
    }
    return cached ? *cached : 0;
}

/* ------------------------------------------------------------------
 * Import resolver — singleton, lazy.
 * ------------------------------------------------------------------ */

static comctl_imports_t g_imports;
static pthread_mutex_t g_imports_lock = PTHREAD_MUTEX_INITIALIZER;

const comctl_imports_t *comctl_get_imports(void)
{
    pthread_mutex_lock(&g_imports_lock);
    if (!g_imports.resolved) {
        g_imports.RegisterClassA   = (pfn_RegisterClassA)dlsym(RTLD_DEFAULT, "RegisterClassA");
        g_imports.BeginPaint       = (pfn_BeginPaint)dlsym(RTLD_DEFAULT, "BeginPaint");
        g_imports.EndPaint         = (pfn_EndPaint)dlsym(RTLD_DEFAULT, "EndPaint");
        g_imports.GetClientRect    = (pfn_GetClientRect)dlsym(RTLD_DEFAULT, "GetClientRect");
        g_imports.DefWindowProcA   = (pfn_DefWindowProcA)dlsym(RTLD_DEFAULT, "DefWindowProcA");
        g_imports.InvalidateRect   = (pfn_InvalidateRect)dlsym(RTLD_DEFAULT, "InvalidateRect");
        g_imports.CreateSolidBrush = (pfn_CreateSolidBrush)dlsym(RTLD_DEFAULT, "CreateSolidBrush");
        g_imports.CreatePen        = (pfn_CreatePen)dlsym(RTLD_DEFAULT, "CreatePen");
        g_imports.SelectObject     = (pfn_SelectObject)dlsym(RTLD_DEFAULT, "SelectObject");
        g_imports.DeleteObject     = (pfn_DeleteObject)dlsym(RTLD_DEFAULT, "DeleteObject");
        g_imports.FillRect         = (pfn_FillRect)dlsym(RTLD_DEFAULT, "FillRect");
        g_imports.Rectangle        = (pfn_Rectangle)dlsym(RTLD_DEFAULT, "Rectangle");
        g_imports.MoveToEx         = (pfn_MoveToEx)dlsym(RTLD_DEFAULT, "MoveToEx");
        g_imports.LineTo           = (pfn_LineTo)dlsym(RTLD_DEFAULT, "LineTo");
        g_imports.TextOutA         = (pfn_TextOutA)dlsym(RTLD_DEFAULT, "TextOutA");
        g_imports.SetBkMode        = (pfn_SetBkMode)dlsym(RTLD_DEFAULT, "SetBkMode");
        g_imports.SetTextColor     = (pfn_SetTextColor)dlsym(RTLD_DEFAULT, "SetTextColor");
        /* Notify-path / scroll / parent helpers — all live in user32 except
         * GradientFill, which we ship in this very gdi32 (alias also
         * exported as GdiGradientFill).  RTLD_DEFAULT will find them. */
        g_imports.SendMessageA     = (pfn_SendMessageA)dlsym(RTLD_DEFAULT, "SendMessageA");
        g_imports.GetParent        = (pfn_GetParent)dlsym(RTLD_DEFAULT, "GetParent");
        g_imports.GetDlgCtrlID     = (pfn_GetDlgCtrlID)dlsym(RTLD_DEFAULT, "GetDlgCtrlID");
        g_imports.SetScrollInfo    = (pfn_SetScrollInfo)dlsym(RTLD_DEFAULT, "SetScrollInfo");
        g_imports.GetScrollInfo    = (pfn_GetScrollInfo)dlsym(RTLD_DEFAULT, "GetScrollInfo");
        g_imports.GetWindowLongA   = (pfn_GetWindowLongA)dlsym(RTLD_DEFAULT, "GetWindowLongA");
        g_imports.SetWindowLongA   = (pfn_SetWindowLongA)dlsym(RTLD_DEFAULT, "SetWindowLongA");
        g_imports.GradientFill     = (pfn_GradientFill)dlsym(RTLD_DEFAULT, "GradientFill");
        if (!g_imports.GradientFill) {
            /* msimg32 alias may be the canonical name in some loads. */
            g_imports.GradientFill = (pfn_GradientFill)dlsym(RTLD_DEFAULT, "GdiGradientFill");
        }
        g_imports.resolved         = 1;
    }
    pthread_mutex_unlock(&g_imports_lock);
    return &g_imports;
}

/* ------------------------------------------------------------------
 * Per-HWND state table.
 * ------------------------------------------------------------------ */

typedef struct {
    HWND          hwnd;
    comctl_kind_t kind;
    void         *state;
} comctl_slot_t;

static comctl_slot_t g_slots[COMCTL_MAX_INSTANCES];
static pthread_mutex_t g_slots_lock = PTHREAD_MUTEX_INITIALIZER;

void comctl_state_set(HWND hwnd, comctl_kind_t kind, void *state)
{
    if (!hwnd) return;
    pthread_mutex_lock(&g_slots_lock);

    /* Replace an existing slot for this HWND first (control swap). */
    for (int i = 0; i < COMCTL_MAX_INSTANCES; i++) {
        if (g_slots[i].hwnd == hwnd) {
            /* Don't free — caller owns previous state pointer. */
            g_slots[i].kind  = kind;
            g_slots[i].state = state;
            pthread_mutex_unlock(&g_slots_lock);
            return;
        }
    }
    /* Allocate a new slot. */
    for (int i = 0; i < COMCTL_MAX_INSTANCES; i++) {
        if (g_slots[i].hwnd == NULL) {
            g_slots[i].hwnd  = hwnd;
            g_slots[i].kind  = kind;
            g_slots[i].state = state;
            pthread_mutex_unlock(&g_slots_lock);
            return;
        }
    }
    pthread_mutex_unlock(&g_slots_lock);
    fprintf(stderr, "[comctl32] state table full; dropping HWND=%p\n", (void *)hwnd);
}

void *comctl_state_get(HWND hwnd, comctl_kind_t kind)
{
    if (!hwnd) return NULL;
    pthread_mutex_lock(&g_slots_lock);
    for (int i = 0; i < COMCTL_MAX_INSTANCES; i++) {
        if (g_slots[i].hwnd == hwnd && g_slots[i].kind == kind) {
            void *s = g_slots[i].state;
            pthread_mutex_unlock(&g_slots_lock);
            return s;
        }
    }
    pthread_mutex_unlock(&g_slots_lock);
    return NULL;
}

void comctl_state_free(HWND hwnd)
{
    if (!hwnd) return;
    pthread_mutex_lock(&g_slots_lock);
    for (int i = 0; i < COMCTL_MAX_INSTANCES; i++) {
        if (g_slots[i].hwnd == hwnd) {
            free(g_slots[i].state);
            g_slots[i].hwnd  = NULL;
            g_slots[i].kind  = COMCTL_KIND_NONE;
            g_slots[i].state = NULL;
            /* No break — a single HWND should never appear in two slots,
             * but defensively scan the rest. */
        }
    }
    pthread_mutex_unlock(&g_slots_lock);
}

/* ------------------------------------------------------------------
 * Parent-notification helpers used by every widget.
 *
 * Win32 child controls notify their parent via WM_COMMAND (simple
 * ones like Button) or WM_NOTIFY (complex ones that need extra fields
 * past wparam/lparam — ListView, TreeView, TabControl).
 *
 * We use the public user32 API: GetParent + GetDlgCtrlID + SendMessageA.
 * GWLP_HWNDPARENT/GWLP_ID would also work but our user32 stub doesn't
 * recognize those indices yet.
 * ------------------------------------------------------------------ */
void comctl_notify_command(HWND hwnd, UINT notify_code)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->GetParent || !im->SendMessageA) return;
    HWND parent = im->GetParent(hwnd);
    if (!parent) return;
    int ctrl_id = im->GetDlgCtrlID ? im->GetDlgCtrlID(hwnd) : 0;
    im->SendMessageA(parent, WM_COMMAND,
                     MAKEWPARAM(ctrl_id, notify_code), (LPARAM)(uintptr_t)hwnd);
}

void comctl_notify_parent(HWND hwnd, UINT notify_code)
{
    const comctl_imports_t *im = comctl_get_imports();
    if (!im->GetParent || !im->SendMessageA) return;
    HWND parent = im->GetParent(hwnd);
    if (!parent) return;
    int ctrl_id = im->GetDlgCtrlID ? im->GetDlgCtrlID(hwnd) : 0;

    /* Stack-local NMHDR — one-per-call, no shared state across threads.
     * Safe because user32::SendMessageA is synchronous (returns to us before
     * the parent's WndProc returns), so the parent's handler has already
     * read &nh by the time this frame unwinds.  If we ever go async (Post
     * instead of Send), this would need a per-call heap alloc. */
    NMHDR nh;
    nh.hwndFrom = hwnd;
    nh.idFrom   = (UINT_PTR)ctrl_id;
    nh.code     = notify_code;
    im->SendMessageA(parent, WM_NOTIFY, (WPARAM)ctrl_id, (LPARAM)(uintptr_t)&nh);
}
