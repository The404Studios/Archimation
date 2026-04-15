/*
 * gdi32_dc.c - Device context management stubs
 *
 * Implements GDI device context APIs: GetDC, ReleaseDC, CreateCompatibleDC,
 * DeleteDC, BeginPaint, EndPaint, SelectObject, GetStockObject, DeleteObject,
 * SetBkMode, SetBkColor, SetTextColor.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdatomic.h>

#include "common/dll_common.h"
#include "../../graphics/gfx_backend.h"

/* --------------------------------------------------------------------------
 * COLORREF type and RGB macro
 * -------------------------------------------------------------------------- */

typedef DWORD COLORREF;
typedef DWORD *LPCOLORREF;

#define RGB(r,g,b)          ((COLORREF)(((BYTE)(r)) | ((WORD)((BYTE)(g)) << 8) | ((DWORD)((BYTE)(b)) << 16)))
#define GetRValue(rgb)      ((BYTE)(rgb))
#define GetGValue(rgb)      ((BYTE)((WORD)(rgb) >> 8))
#define GetBValue(rgb)      ((BYTE)((rgb) >> 16))

#define CLR_INVALID         0xFFFFFFFF

/* Background modes */
#define TRANSPARENT         1
#define OPAQUE              2

/* Text alignment */
#define TA_LEFT             0x0000
#define TA_RIGHT            0x0002
#define TA_CENTER           0x0006
#define TA_TOP              0x0000
#define TA_BOTTOM           0x0008
#define TA_BASELINE         0x0018
#define TA_NOUPDATECP       0x0000
#define TA_UPDATECP         0x0001

/* Stock object indices */
#define WHITE_BRUSH         0
#define LTGRAY_BRUSH        1
#define GRAY_BRUSH          2
#define DKGRAY_BRUSH        3
#define BLACK_BRUSH         4
#define NULL_BRUSH          5
#define HOLLOW_BRUSH        NULL_BRUSH
#define WHITE_PEN           6
#define BLACK_PEN           7
#define NULL_PEN            8
#define OEM_FIXED_FONT      10
#define ANSI_FIXED_FONT     11
#define ANSI_VAR_FONT       12
#define SYSTEM_FONT         13
#define DEVICE_DEFAULT_FONT 14
#define DEFAULT_PALETTE     15
#define SYSTEM_FIXED_FONT   16
#define DEFAULT_GUI_FONT    17

/* ROP2 constants */
#define R2_BLACK            1
#define R2_COPYPEN          13
#define R2_WHITE            16

/* Mapping modes */
#define MM_TEXT             1
#define MM_LOMETRIC         2
#define MM_HIMETRIC         3
#define MM_LOENGLISH        4
#define MM_HIENGLISH        5
#define MM_TWIPS            6
#define MM_ISOTROPIC        7
#define MM_ANISOTROPIC      8

/* StretchBlt modes */
#define BLACKONWHITE        1
#define WHITEONBLACK        2
#define COLORONCOLOR        3
#define HALFTONE            4

/* --------------------------------------------------------------------------
 * PAINTSTRUCT
 * -------------------------------------------------------------------------- */

typedef struct tagPAINTSTRUCT {
    HDC         hdc;
    BOOL        fErase;
    RECT        rcPaint;
    BOOL        fRestore;
    BOOL        fIncUpdate;
    BYTE        rgbReserved[32];
} PAINTSTRUCT, *PPAINTSTRUCT, *LPPAINTSTRUCT;

/* --------------------------------------------------------------------------
 * GDI object types
 * -------------------------------------------------------------------------- */

typedef enum {
    GDI_OBJ_INVALID = 0,
    GDI_OBJ_BRUSH,
    GDI_OBJ_PEN,
    GDI_OBJ_FONT,
    GDI_OBJ_BITMAP,
    GDI_OBJ_REGION,
    GDI_OBJ_DC,
    GDI_OBJ_PALETTE,
} gdi_obj_type_t;

typedef struct {
    gdi_obj_type_t  type;
    int             stock;      /* 1 if stock object (don't delete) */
    COLORREF        color;      /* For brushes/pens */
    int             width;      /* For pens */
    int             style;      /* For pens */
    void           *data;       /* Type-specific data */
    int             used;
} gdi_object_t;

#define MAX_GDI_OBJECTS 1024

static gdi_object_t g_gdi_objects[MAX_GDI_OBJECTS];
/* Session 30: ensure_gdi_init was racy — multiple threads calling
 * GetStockObject concurrently at startup could double-init the object pool
 * (stock handles allocated twice, leaking slots). Use pthread_once so
 * initialization is idempotent + deterministic, and guard the pool itself
 * with g_gdi_pool_lock. */
static pthread_once_t g_gdi_init_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_gdi_pool_lock = PTHREAD_MUTEX_INITIALIZER;

/* Stock objects (pre-allocated) */
static HGDIOBJ g_stock_objects[32];

static void ensure_gdi_init(void);

/* Internal: allocate a slot without running ensure_gdi_init() — used by
 * the init-once callback to populate stock objects. Callers outside init
 * MUST go through gdi_alloc() which runs init first. */
static gdi_object_t *gdi_alloc_nolock_internal(gdi_obj_type_t type)
{
    for (int i = 0; i < MAX_GDI_OBJECTS; i++) {
        if (!g_gdi_objects[i].used) {
            memset(&g_gdi_objects[i], 0, sizeof(gdi_object_t));
            g_gdi_objects[i].used = 1;
            g_gdi_objects[i].type = type;
            return &g_gdi_objects[i];
        }
    }
    return NULL;
}

static gdi_object_t *gdi_alloc(gdi_obj_type_t type)
{
    ensure_gdi_init();
    pthread_mutex_lock(&g_gdi_pool_lock);
    gdi_object_t *r = gdi_alloc_nolock_internal(type);
    pthread_mutex_unlock(&g_gdi_pool_lock);
    return r;
}

static HGDIOBJ gdi_to_handle(gdi_object_t *obj)
{
    if (!obj) return NULL;
    /* Use index + 0x80000000 to distinguish from other handles */
    uintptr_t idx = (uintptr_t)(obj - g_gdi_objects);
    return (HGDIOBJ)(idx + 0x80000000UL);
}

static gdi_object_t *handle_to_gdi(HGDIOBJ h)
{
    if (!h) return NULL;
    uintptr_t idx = (uintptr_t)h;
    if (idx < 0x80000000UL || idx >= 0x80000000UL + MAX_GDI_OBJECTS)
        return NULL;
    idx -= 0x80000000UL;
    if (!g_gdi_objects[idx].used)
        return NULL;
    return &g_gdi_objects[idx];
}

static void gdi_init_once_cb(void);
static void ensure_gdi_init(void)
{
    pthread_once(&g_gdi_init_once, gdi_init_once_cb);
}

static void gdi_init_once_cb(void)
{
    memset(g_gdi_objects, 0, sizeof(g_gdi_objects));
    memset(g_stock_objects, 0, sizeof(g_stock_objects));

    /* Create stock brushes */
    struct { int idx; COLORREF color; } stock_brushes[] = {
        { WHITE_BRUSH,  RGB(255, 255, 255) },
        { LTGRAY_BRUSH, RGB(192, 192, 192) },
        { GRAY_BRUSH,   RGB(128, 128, 128) },
        { DKGRAY_BRUSH, RGB(64, 64, 64) },
        { BLACK_BRUSH,  RGB(0, 0, 0) },
    };
    for (int i = 0; i < 5; i++) {
        gdi_object_t *obj = gdi_alloc_nolock_internal(GDI_OBJ_BRUSH);
        if (obj) {
            obj->stock = 1;
            obj->color = stock_brushes[i].color;
            g_stock_objects[stock_brushes[i].idx] = gdi_to_handle(obj);
        }
    }

    /* NULL_BRUSH */
    {
        gdi_object_t *obj = gdi_alloc_nolock_internal(GDI_OBJ_BRUSH);
        if (obj) {
            obj->stock = 1;
            obj->color = CLR_INVALID;  /* No fill */
            g_stock_objects[NULL_BRUSH] = gdi_to_handle(obj);
        }
    }

    /* Stock pens */
    struct { int idx; COLORREF color; } stock_pens[] = {
        { WHITE_PEN, RGB(255, 255, 255) },
        { BLACK_PEN, RGB(0, 0, 0) },
    };
    for (int i = 0; i < 2; i++) {
        gdi_object_t *obj = gdi_alloc_nolock_internal(GDI_OBJ_PEN);
        if (obj) {
            obj->stock = 1;
            obj->color = stock_pens[i].color;
            obj->width = 1;
            g_stock_objects[stock_pens[i].idx] = gdi_to_handle(obj);
        }
    }

    /* NULL_PEN */
    {
        gdi_object_t *obj = gdi_alloc_nolock_internal(GDI_OBJ_PEN);
        if (obj) {
            obj->stock = 1;
            obj->color = CLR_INVALID;
            obj->width = 0;
            g_stock_objects[NULL_PEN] = gdi_to_handle(obj);
        }
    }

    /* Stock fonts.
     *
     * Record the stock-font identity in obj->style so SelectObject and
     * GetObjectA can reconstruct a sensible LOGFONTA (Session 26 Agent 7:
     * stock fonts selected via SelectObject didn't update font_dc_state_t,
     * so TextOut always used default metrics; GetObjectA also returned 0).
     * obj->style is unused for fonts (pens-only field), so we repurpose it.
     * +1 offset so zero never collides with "stock_id not set". */
    int font_indices[] = { OEM_FIXED_FONT, ANSI_FIXED_FONT, ANSI_VAR_FONT,
                           SYSTEM_FONT, DEVICE_DEFAULT_FONT, SYSTEM_FIXED_FONT,
                           DEFAULT_GUI_FONT };
    for (int i = 0; i < 7; i++) {
        gdi_object_t *obj = gdi_alloc_nolock_internal(GDI_OBJ_FONT);
        if (obj) {
            obj->stock = 1;
            obj->style = font_indices[i] + 1;  /* stock-id tag, +1 so 0 = unset */
            g_stock_objects[font_indices[i]] = gdi_to_handle(obj);
        }
    }
}

/* --------------------------------------------------------------------------
 * HDC to gfx_dc_t mapping
 * -------------------------------------------------------------------------- */

#define MAX_DC_MAP 256

typedef struct {
    HDC         hdc;
    gfx_dc_t  *gfx_dc;
    HWND        hwnd;       /* Owning window (NULL for memory DCs) */
    COLORREF    text_color;
    COLORREF    bg_color;
    int         bg_mode;
    int         text_align;
    int         map_mode;
    int         rop2;           /* Drawing mode (R2_COPYPEN default) */
    int         stretch_mode;   /* StretchBlt mode (COLORONCOLOR default) */
    HGDIOBJ     selected_brush;
    HGDIOBJ     selected_pen;
    HGDIOBJ     selected_font;
    HGDIOBJ     selected_bitmap;
    int         used;
} dc_entry_t;

static dc_entry_t g_dc_map[MAX_DC_MAP];
/* Session 30: g_next_hdc was plain uintptr_t with no synchronization,
 * concurrent GetDC/CreateCompatibleDC from the UI thread + background
 * preload threads could hand out the SAME hdc to two DCs. Use atomic. */
static _Atomic(uintptr_t) g_next_hdc = 0x20000;
static pthread_mutex_t g_dc_map_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_dc_map_init_once = PTHREAD_ONCE_INIT;

static void dc_map_init_cb(void)
{
    memset(g_dc_map, 0, sizeof(g_dc_map));
}

static void ensure_dc_map_init(void)
{
    pthread_once(&g_dc_map_init_once, dc_map_init_cb);
}

static dc_entry_t *dc_alloc(gfx_dc_t *gfx_dc, HWND hwnd)
{
    ensure_dc_map_init();
    pthread_mutex_lock(&g_dc_map_lock);
    for (int i = 0; i < MAX_DC_MAP; i++) {
        if (!g_dc_map[i].used) {
            memset(&g_dc_map[i], 0, sizeof(dc_entry_t));
            g_dc_map[i].used = 1;
            /* atomic post-increment so concurrent dc_alloc calls each get a
             * unique hdc value. */
            g_dc_map[i].hdc = (HDC)atomic_fetch_add(&g_next_hdc, 1);
            g_dc_map[i].gfx_dc = gfx_dc;
            g_dc_map[i].hwnd = hwnd;
            g_dc_map[i].text_color = RGB(0, 0, 0);
            g_dc_map[i].bg_color = RGB(255, 255, 255);
            g_dc_map[i].bg_mode = OPAQUE;
            g_dc_map[i].text_align = TA_LEFT | TA_TOP;
            g_dc_map[i].map_mode = MM_TEXT;
            g_dc_map[i].rop2 = R2_COPYPEN;
            g_dc_map[i].stretch_mode = COLORONCOLOR;
            pthread_mutex_unlock(&g_dc_map_lock);
            return &g_dc_map[i];
        }
    }
    pthread_mutex_unlock(&g_dc_map_lock);
    return NULL;
}

static dc_entry_t *dc_lookup(HDC hdc)
{
    ensure_dc_map_init();
    /* Caller relies on returned pointer surviving briefly — dc_free only
     * clears ->used, the slot itself is static. No concurrent mutation of
     * per-entry fields is safe across dc_free; callers observing a just-
     * freed entry see used==0 on the next lookup. Snapshot under the lock
     * to avoid torn reads of the hdc field during dc_alloc. */
    pthread_mutex_lock(&g_dc_map_lock);
    for (int i = 0; i < MAX_DC_MAP; i++) {
        if (g_dc_map[i].used && g_dc_map[i].hdc == hdc) {
            pthread_mutex_unlock(&g_dc_map_lock);
            return &g_dc_map[i];
        }
    }
    pthread_mutex_unlock(&g_dc_map_lock);
    return NULL;
}

static void dc_free(HDC hdc)
{
    ensure_dc_map_init();
    pthread_mutex_lock(&g_dc_map_lock);
    for (int i = 0; i < MAX_DC_MAP; i++) {
        if (g_dc_map[i].used && g_dc_map[i].hdc == hdc) {
            g_dc_map[i].used = 0;
            pthread_mutex_unlock(&g_dc_map_lock);
            return;
        }
    }
    pthread_mutex_unlock(&g_dc_map_lock);
}

/* --------------------------------------------------------------------------
 * External: get gfx_window_t from HWND (from user32_window.c)
 * -------------------------------------------------------------------------- */

extern gfx_window_t *hwnd_to_gfx(HWND hwnd);

/* --------------------------------------------------------------------------
 * GetDC / ReleaseDC
 * -------------------------------------------------------------------------- */

/* GetDC/ReleaseDC/GetWindowDC/BeginPaint/EndPaint are user32 exports per
 * Windows spec.  We keep internal implementations here for gdi32-internal
 * use, but do NOT export them (user32_window.c owns the exports). */
HDC gdi32_GetDC(HWND hWnd)
{
    gfx_backend_t *backend = gfx_get_backend();
    if (!backend) {
        /* If no backend, return a dummy DC */
        dc_entry_t *entry = dc_alloc(NULL, hWnd);
        return entry ? entry->hdc : NULL;
    }

    gfx_window_t *win = NULL;
    if (hWnd) {
        win = hwnd_to_gfx(hWnd);
    }

    gfx_dc_t *gfx_dc = backend->get_dc(backend, win);
    dc_entry_t *entry = dc_alloc(gfx_dc, hWnd);
    if (!entry) {
        if (gfx_dc)
            backend->release_dc(backend, win, gfx_dc);
        return NULL;
    }

    return entry->hdc;
}

/* Defined in gdi32_font.c -- releases per-DC font state slot so the
 * 64-slot font DC state table doesn't leak entries on every GetDC. */
extern void gdi32_font_dc_release(HDC hdc);

int gdi32_ReleaseDC(HWND hWnd, HDC hDC)
{
    dc_entry_t *entry = dc_lookup(hDC);
    if (!entry)
        return 0;

    gfx_backend_t *backend = gfx_get_backend();
    if (backend && entry->gfx_dc) {
        gfx_window_t *win = hWnd ? hwnd_to_gfx(hWnd) : NULL;
        backend->release_dc(backend, win, entry->gfx_dc);
    }

    gdi32_font_dc_release(hDC);
    dc_free(hDC);
    return 1;
}

HDC gdi32_GetWindowDC(HWND hWnd)
{
    return gdi32_GetDC(hWnd);
}

/* --------------------------------------------------------------------------
 * CreateCompatibleDC / DeleteDC
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HDC CreateCompatibleDC(HDC hdc)
{
    (void)hdc;

    gfx_dc_t *gfx_dc = gfx_alloc_dc();
    if (gfx_dc) {
        gfx_dc->is_memory_dc = 1;
        gfx_dc->text_color = GFX_RGB(0, 0, 0);
        gfx_dc->bg_color = GFX_RGB(255, 255, 255);
        gfx_dc->bg_mode = OPAQUE;
    }

    dc_entry_t *entry = dc_alloc(gfx_dc, NULL);
    if (!entry) {
        if (gfx_dc)
            gfx_free_dc(gfx_dc);
        return NULL;
    }

    return entry->hdc;
}

WINAPI_EXPORT BOOL DeleteDC(HDC hdc)
{
    dc_entry_t *entry = dc_lookup(hdc);
    if (!entry)
        return FALSE;

    if (entry->gfx_dc) {
        /* For memory DCs, free bitmap data */
        if (entry->gfx_dc->bitmap_data) {
            free(entry->gfx_dc->bitmap_data);
            entry->gfx_dc->bitmap_data = NULL;
        }
        gfx_free_dc(entry->gfx_dc);
    }

    gdi32_font_dc_release(hdc);
    dc_free(hdc);
    return TRUE;
}

/* --------------------------------------------------------------------------
 * BeginPaint / EndPaint
 * -------------------------------------------------------------------------- */

HDC gdi32_BeginPaint(HWND hWnd, LPPAINTSTRUCT lpPaint)
{
    if (!lpPaint)
        return NULL;

    memset(lpPaint, 0, sizeof(PAINTSTRUCT));

    HDC hdc = gdi32_GetDC(hWnd);
    lpPaint->hdc = hdc;
    lpPaint->fErase = TRUE;

    /* Set the paint rectangle to the full client area */
    gfx_window_t *win = hwnd_to_gfx(hWnd);
    if (win) {
        lpPaint->rcPaint.left = 0;
        lpPaint->rcPaint.top = 0;
        lpPaint->rcPaint.right = win->client_width;
        lpPaint->rcPaint.bottom = win->client_height;
        win->needs_repaint = 0;
    }

    return hdc;
}

BOOL gdi32_EndPaint(HWND hWnd, const PAINTSTRUCT *lpPaint)
{
    if (!lpPaint)
        return FALSE;

    if (lpPaint->hdc)
        gdi32_ReleaseDC(hWnd, lpPaint->hdc);

    return TRUE;
}

/* --------------------------------------------------------------------------
 * SelectObject
 *
 * Dispatches by handle range (Session 23 DeleteObject pattern):
 *   0x80000000-0x800003FF : gdi_object_t pool (pens/brushes/regions)
 *   0xB0000000-0xBFFFFFFF : bitmap pool (gdi32_bitmap.c)
 *   0xF1000000-0xF1FFFFFF : font pool   (gdi32_font.c)
 *
 * Session 23 bug: old code called handle_to_gdi(h) which only validated the
 * gdi_object_t range, so bitmap/font handles returned NULL --
 * entry->selected_bitmap was never set, breaking StretchBlt/BitBlt on
 * off-screen memory DCs.
 * -------------------------------------------------------------------------- */

/* Defined in gdi32_bitmap.c and gdi32_font.c (same .so). Each validates
 * the handle, updates the DC's selected_bitmap/selected_font slot, and
 * returns the previously-selected handle. */
extern __attribute__((ms_abi)) HBITMAP gdi32_bitmap_select_on_dc(HDC hdc, HBITMAP new_hbm);
extern __attribute__((ms_abi)) HFONT   gdi32_font_select_on_dc(HDC hdc, HFONT new_hf);

/* Defined in gdi32_font.c.  Called from SelectObject's GDI_OBJ_FONT case when
 * the app selects a stock font.  `stock_id` is the GetStockObject index
 * (SYSTEM_FONT, DEFAULT_GUI_FONT, ...).  The helper ensures a font_entry_t
 * exists for `stock_handle` (so font_lookup finds it) and points the
 * font_dc_state_t at it so TextOut / GetTextMetrics pick up the right
 * defaults instead of Arial-16. */
extern void gdi32_font_sync_stock_on_dc(HDC hdc, HGDIOBJ stock_handle, int stock_id);

/* OBJ_* constants (wingdi.h) -- defined once here, re-defined later
 * for the GetCurrentObject helper section. */
#ifndef OBJ_PEN
#define OBJ_PEN     1
#define OBJ_BRUSH   2
#define OBJ_FONT    6
#define OBJ_BITMAP  7
#endif

/* Called by the bitmap/font helpers to swap the DC's slot and return old. */
__attribute__((ms_abi)) HGDIOBJ gdi32_dc_set_selected(HDC hdc, int obj_type, HGDIOBJ new_h)
{
    dc_entry_t *entry = dc_lookup(hdc);
    if (!entry) return NULL;

    HGDIOBJ old = NULL;
    switch (obj_type) {
    case OBJ_BITMAP:
        old = entry->selected_bitmap;
        entry->selected_bitmap = new_h;
        if (entry->gfx_dc)
            entry->gfx_dc->current_bitmap = NULL;  /* bitmap ptr tracked elsewhere */
        break;
    case OBJ_FONT:
        old = entry->selected_font;
        entry->selected_font = new_h;
        if (entry->gfx_dc)
            entry->gfx_dc->current_font = NULL;  /* font ptr not valid here */
        break;
    default:
        break;
    }
    return old;
}

WINAPI_EXPORT HGDIOBJ SelectObject(HDC hdc, HGDIOBJ h)
{
    dc_entry_t *entry = dc_lookup(hdc);
    if (!entry)
        return NULL;
    if (!h)
        return NULL;

    uintptr_t hv = (uintptr_t)h;

    /* Bitmap range -- dispatch to gdi32_bitmap.c */
    if (hv >= 0xB0000000UL && hv < 0xC0000000UL) {
        return (HGDIOBJ)gdi32_bitmap_select_on_dc(hdc, (HBITMAP)h);
    }

    /* Font range -- dispatch to gdi32_font.c */
    if (hv >= 0xF1000000UL && hv < 0xF2000000UL) {
        return (HGDIOBJ)gdi32_font_select_on_dc(hdc, (HFONT)h);
    }

    /* gdi_object_t range (pens/brushes/stock) */
    gdi_object_t *obj = handle_to_gdi(h);
    if (!obj)
        return NULL;

    HGDIOBJ old = NULL;

    switch (obj->type) {
    case GDI_OBJ_BRUSH:
        old = entry->selected_brush;
        entry->selected_brush = h;
        if (entry->gfx_dc)
            entry->gfx_dc->current_brush = obj;
        break;
    case GDI_OBJ_PEN:
        old = entry->selected_pen;
        entry->selected_pen = h;
        if (entry->gfx_dc)
            entry->gfx_dc->current_pen = obj;
        break;
    case GDI_OBJ_FONT:
        /* Stock fonts live in gdi_object_t pool. Update dc_entry AND push
         * the stock-font identity into gdi32_font.c's font_dc_state_t so
         * TextOut / GetTextMetrics use the right LOGFONTA instead of the
         * default Arial-16 (Session 26 Agent 7 fix). obj->style carries
         * the stock-font id + 1 (0 means no tag). */
        old = entry->selected_font;
        entry->selected_font = h;
        if (entry->gfx_dc)
            entry->gfx_dc->current_font = obj;
        if (obj->stock && obj->style > 0)
            gdi32_font_sync_stock_on_dc(hdc, h, obj->style - 1);
        break;
    case GDI_OBJ_BITMAP:
        /* Bitmap in gdi_object_t pool (unusual; normally in 0xB... range) */
        old = entry->selected_bitmap;
        entry->selected_bitmap = h;
        if (entry->gfx_dc)
            entry->gfx_dc->current_bitmap = obj;
        break;
    default:
        return NULL;
    }

    return old;
}

/* --------------------------------------------------------------------------
 * GetObject dispatch for gdi_object_t pool (pens/brushes)
 *
 * gdi32_bitmap.c owns the WINAPI_EXPORT GetObjectA/W. It dispatches by
 * handle range and calls this helper for gdi_object_t (pen/brush) handles.
 * -------------------------------------------------------------------------- */

/* LOGPEN: { UINT lopnStyle; POINT lopnWidth; COLORREF lopnColor; } = 16 bytes */
typedef struct tagLOGPEN {
    UINT     lopnStyle;
    POINT    lopnWidth;   /* only .x is used; .y is ignored */
    COLORREF lopnColor;
} LOGPEN;

/* LOGBRUSH: { UINT lbStyle; COLORREF lbColor; ULONG_PTR lbHatch; } */
typedef struct tagLOGBRUSH {
    UINT      lbStyle;
    COLORREF  lbColor;
    uintptr_t lbHatch;
} LOGBRUSH;

__attribute__((ms_abi)) int gdi32_dc_get_object_info(HGDIOBJ h, int cb, void *pv)
{
    gdi_object_t *obj = handle_to_gdi(h);
    if (!obj)
        return 0;

    switch (obj->type) {
    case GDI_OBJ_PEN: {
        if (!pv) return (int)sizeof(LOGPEN);
        if (cb < (int)sizeof(LOGPEN)) return 0;
        LOGPEN *lp = (LOGPEN *)pv;
        lp->lopnStyle = (UINT)obj->style;
        lp->lopnWidth.x = obj->width;
        lp->lopnWidth.y = 0;
        lp->lopnColor = obj->color;
        return (int)sizeof(LOGPEN);
    }
    case GDI_OBJ_BRUSH: {
        if (!pv) return (int)sizeof(LOGBRUSH);
        if (cb < (int)sizeof(LOGBRUSH)) return 0;
        LOGBRUSH *lb = (LOGBRUSH *)pv;
        lb->lbStyle = (obj->color == CLR_INVALID) ? 1 /* BS_NULL/HOLLOW */ : 0 /* BS_SOLID */;
        lb->lbColor = obj->color;
        lb->lbHatch = 0;
        return (int)sizeof(LOGBRUSH);
    }
    case GDI_OBJ_FONT:
        /* Stock font: fill LOGFONTA from defaults keyed by stock-id.
         * Session 26 Agent 7: GetObjectA used to return 0 here, so apps
         * calling GetObjectA(GetStockObject(DEFAULT_GUI_FONT), ...) got
         * nothing.  We now hand back a sensible default.  The per-stock-id
         * template lives in gdi32_font.c (one source of truth). */
        if (obj->stock && obj->style > 0) {
            /* Declared extern; defined in gdi32_font.c */
            extern int gdi32_font_fill_stock_logfonta(int stock_id, int cb, void *pv);
            return gdi32_font_fill_stock_logfonta(obj->style - 1, cb, pv);
        }
        return 0;
    case GDI_OBJ_REGION:
    case GDI_OBJ_DC:
    case GDI_OBJ_PALETTE:
    default:
        return 0;
    }
}

/* --------------------------------------------------------------------------
 * GetStockObject
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HGDIOBJ GetStockObject(int i)
{
    ensure_gdi_init();
    if (i < 0 || i >= 32)
        return NULL;
    return g_stock_objects[i];
}

/* --------------------------------------------------------------------------
 * GetCurrentObject helper (called from gdi32_bitmap.c)
 * -------------------------------------------------------------------------- */

/* OBJ_* defined earlier (guarded by #ifndef OBJ_PEN) before SelectObject. */

HGDIOBJ gdi32_dc_get_selected(HDC hdc, int obj_type)
{
    dc_entry_t *entry = dc_lookup(hdc);
    if (!entry) return NULL;

    switch (obj_type) {
    case OBJ_PEN:    return entry->selected_pen;
    case OBJ_BRUSH:  return entry->selected_brush;
    case OBJ_FONT:   return entry->selected_font;
    case OBJ_BITMAP: return entry->selected_bitmap;
    default:         return NULL;
    }
}

/* --------------------------------------------------------------------------
 * Per-DC state accessors (called from gdi32_bitmap.c, gdi32_text.c)
 * -------------------------------------------------------------------------- */

int gdi32_dc_get_stretch_mode(HDC hdc)
{
    dc_entry_t *entry = dc_lookup(hdc);
    return entry ? entry->stretch_mode : COLORONCOLOR;
}

int gdi32_dc_set_stretch_mode(HDC hdc, int mode)
{
    dc_entry_t *entry = dc_lookup(hdc);
    if (!entry)
        return 0;
    int old = entry->stretch_mode;
    entry->stretch_mode = mode;
    return old;
}

UINT gdi32_dc_get_text_align(HDC hdc)
{
    dc_entry_t *entry = dc_lookup(hdc);
    return entry ? (UINT)entry->text_align : (TA_LEFT | TA_TOP);
}

UINT gdi32_dc_set_text_align(HDC hdc, UINT align)
{
    dc_entry_t *entry = dc_lookup(hdc);
    if (!entry)
        return (TA_LEFT | TA_TOP);
    UINT old = (UINT)entry->text_align;
    entry->text_align = (int)align;
    return old;
}

/* --------------------------------------------------------------------------
 * DeleteObject
 *
 * Handles all GDI object ranges:
 *   0x80000000-0x800003FF : gdi_object_t pool (pens/brushes/stock items)
 *   0xB0000000-0xBFFFFFFF : bitmap pool (gdi32_bitmap.c)
 *   0xF1000000-0xF1FFFFFF : font pool   (gdi32_font.c)
 *
 * Without the range dispatch, DeleteObject would silently return FALSE
 * for every bitmap and font -- leaking pixel buffers and LOGFONT data.
 * -------------------------------------------------------------------------- */

/* Defined in gdi32_bitmap.c and gdi32_font.c (same .so) */
extern __attribute__((ms_abi)) BOOL DeleteBitmap(HBITMAP hbm);
extern int gdi32_font_delete(HFONT hf);

WINAPI_EXPORT BOOL DeleteObject(HGDIOBJ ho)
{
    if (!ho)
        return FALSE;

    uintptr_t h = (uintptr_t)ho;

    /* Bitmap range -- dispatch to gdi32_bitmap.c */
    if (h >= 0xB0000000UL && h < 0xC0000000UL) {
        return DeleteBitmap((HBITMAP)ho);
    }

    /* Font range -- dispatch to gdi32_font.c */
    if (h >= 0xF1000000UL && h < 0xF2000000UL) {
        return gdi32_font_delete((HFONT)ho) ? TRUE : FALSE;
    }

    gdi_object_t *obj = handle_to_gdi(ho);
    if (!obj)
        return FALSE;

    /* Don't delete stock objects */
    if (obj->stock)
        return TRUE;

    if (obj->data) {
        free(obj->data);
        obj->data = NULL;
    }
    obj->used = 0;
    obj->type = GDI_OBJ_INVALID;

    return TRUE;
}

/* --------------------------------------------------------------------------
 * SetBkMode / GetBkMode
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT int SetBkMode(HDC hdc, int mode)
{
    dc_entry_t *entry = dc_lookup(hdc);
    if (!entry)
        return 0;

    int old = entry->bg_mode;
    entry->bg_mode = mode;

    if (entry->gfx_dc)
        entry->gfx_dc->bg_mode = mode;

    return old;
}

WINAPI_EXPORT int GetBkMode(HDC hdc)
{
    dc_entry_t *entry = dc_lookup(hdc);
    return entry ? entry->bg_mode : 0;
}

/* --------------------------------------------------------------------------
 * SetBkColor / GetBkColor
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT COLORREF SetBkColor(HDC hdc, COLORREF color)
{
    dc_entry_t *entry = dc_lookup(hdc);
    if (!entry)
        return CLR_INVALID;

    COLORREF old = entry->bg_color;
    entry->bg_color = color;

    if (entry->gfx_dc)
        entry->gfx_dc->bg_color = (gfx_color_t)color;

    return old;
}

WINAPI_EXPORT COLORREF GetBkColor(HDC hdc)
{
    dc_entry_t *entry = dc_lookup(hdc);
    return entry ? entry->bg_color : CLR_INVALID;
}

/* --------------------------------------------------------------------------
 * SetTextColor / GetTextColor
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT COLORREF SetTextColor(HDC hdc, COLORREF color)
{
    dc_entry_t *entry = dc_lookup(hdc);
    if (!entry)
        return CLR_INVALID;

    COLORREF old = entry->text_color;
    entry->text_color = color;

    if (entry->gfx_dc)
        entry->gfx_dc->text_color = (gfx_color_t)color;

    return old;
}

WINAPI_EXPORT COLORREF GetTextColor(HDC hdc)
{
    dc_entry_t *entry = dc_lookup(hdc);
    return entry ? entry->text_color : CLR_INVALID;
}

/* --------------------------------------------------------------------------
 * SetMapMode / GetMapMode
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT int SetMapMode(HDC hdc, int iMode)
{
    dc_entry_t *entry = dc_lookup(hdc);
    if (!entry)
        return 0;

    int old = entry->map_mode;
    entry->map_mode = iMode;
    return old;
}

WINAPI_EXPORT int GetMapMode(HDC hdc)
{
    dc_entry_t *entry = dc_lookup(hdc);
    return entry ? entry->map_mode : 0;
}

/* --------------------------------------------------------------------------
 * SetROP2 / GetROP2
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT int SetROP2(HDC hdc, int rop2)
{
    dc_entry_t *entry = dc_lookup(hdc);
    if (!entry)
        return 0;

    int old = entry->rop2;
    entry->rop2 = rop2;
    return old;
}

WINAPI_EXPORT int GetROP2(HDC hdc)
{
    dc_entry_t *entry = dc_lookup(hdc);
    return entry ? entry->rop2 : R2_COPYPEN;
}

/* --------------------------------------------------------------------------
 * Brush/Pen creation
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HBRUSH CreateSolidBrush(COLORREF color)
{
    gdi_object_t *obj = gdi_alloc(GDI_OBJ_BRUSH);
    if (!obj) return NULL;
    obj->color = color;
    return (HBRUSH)gdi_to_handle(obj);
}

WINAPI_EXPORT HBRUSH CreateHatchBrush(int iHatch, COLORREF color)
{
    (void)iHatch;
    /* Simplified: treat as solid brush */
    return CreateSolidBrush(color);
}

WINAPI_EXPORT HPEN CreatePen(int iStyle, int cWidth, COLORREF color)
{
    gdi_object_t *obj = gdi_alloc(GDI_OBJ_PEN);
    if (!obj) return NULL;
    obj->color = color;
    obj->width = cWidth;
    obj->style = iStyle;
    return (HPEN)gdi_to_handle(obj);
}

/* --------------------------------------------------------------------------
 * Drawing primitives
 * -------------------------------------------------------------------------- */

/* ----------------------------------------------------------------
 * FillRect - forwarded to canonical user32
 *
 * Some Windows executables import FillRect from gdi32.dll even though
 * the canonical implementation lives in user32.dll.  We forward at
 * runtime via dlsym.
 * ---------------------------------------------------------------- */

WINAPI_EXPORT int WINAPI FillRect(HDC hDC, const void *lprc, HBRUSH hbr)
{
    typedef int (WINAPI *fn_t)(HDC, const void*, HBRUSH);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        void *h = dlopen("libpe_user32.so", RTLD_LAZY);
        if (h) real_fn = (fn_t)dlsym(h, "FillRect");
    }
    return real_fn ? real_fn(hDC, lprc, hbr) : 0;
}

WINAPI_EXPORT BOOL Rectangle(HDC hdc, int left, int top, int right, int bottom)
{
    dc_entry_t *entry = dc_lookup(hdc);
    gfx_backend_t *backend = gfx_get_backend();

    if (!entry || !backend || !entry->gfx_dc)
        return FALSE;

    /* Fill with current brush */
    gdi_object_t *brush = entry->selected_brush ? handle_to_gdi(entry->selected_brush) : NULL;
    if (brush && brush->color != CLR_INVALID) {
        backend->paint_rect(backend, entry->gfx_dc,
                           left, top, right - left, bottom - top,
                           (gfx_color_t)brush->color);
    }

    return TRUE;
}

WINAPI_EXPORT BOOL MoveToEx(HDC hdc, int x, int y, LPPOINT lppt)
{
    (void)hdc;
    (void)x;
    (void)y;
    if (lppt) {
        lppt->x = 0;
        lppt->y = 0;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL LineTo(HDC hdc, int x, int y)
{
    (void)hdc;
    (void)x;
    (void)y;
    /* Stub - line drawing would need backend support */
    return TRUE;
}

WINAPI_EXPORT BOOL Ellipse(HDC hdc, int left, int top, int right, int bottom)
{
    (void)hdc;
    (void)left;
    (void)top;
    (void)right;
    (void)bottom;
    /* Stub */
    return TRUE;
}

WINAPI_EXPORT COLORREF SetPixel(HDC hdc, int x, int y, COLORREF color)
{
    dc_entry_t *entry = dc_lookup(hdc);
    gfx_backend_t *backend = gfx_get_backend();

    if (entry && backend && entry->gfx_dc) {
        backend->paint_rect(backend, entry->gfx_dc, x, y, 1, 1, (gfx_color_t)color);
    }

    return color;
}

WINAPI_EXPORT COLORREF GetPixel(HDC hdc, int x, int y)
{
    (void)hdc;
    (void)x;
    (void)y;
    return RGB(0, 0, 0);  /* Stub */
}

WINAPI_EXPORT int SaveDC(HDC hdc)
{
    (void)hdc;
    return 1;  /* Stub - return save level 1 */
}

WINAPI_EXPORT BOOL RestoreDC(HDC hdc, int nSavedDC)
{
    (void)hdc;
    (void)nSavedDC;
    return TRUE;
}

/* --------------------------------------------------------------------------
 * Region stubs
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HRGN CreateRectRgn(int x1, int y1, int x2, int y2)
{
    (void)x1; (void)y1; (void)x2; (void)y2;
    gdi_object_t *obj = gdi_alloc(GDI_OBJ_REGION);
    if (!obj) return NULL;
    return (HRGN)gdi_to_handle(obj);
}

WINAPI_EXPORT HRGN CreateRectRgnIndirect(const RECT *lprect)
{
    if (!lprect) return NULL;
    return CreateRectRgn(lprect->left, lprect->top, lprect->right, lprect->bottom);
}

WINAPI_EXPORT int GetClipBox(HDC hdc, LPRECT lprect)
{
    (void)hdc;
    if (lprect) {
        lprect->left = 0;
        lprect->top = 0;
        lprect->right = 1920;
        lprect->bottom = 1080;
    }
    return 1;  /* SIMPLEREGION */
}

WINAPI_EXPORT int SelectClipRgn(HDC hdc, HRGN hrgn)
{
    (void)hdc;
    (void)hrgn;
    return 1;  /* SIMPLEREGION */
}

WINAPI_EXPORT int IntersectClipRect(HDC hdc, int left, int top, int right, int bottom)
{
    (void)hdc;
    (void)left; (void)top; (void)right; (void)bottom;
    return 1;  /* SIMPLEREGION */
}

WINAPI_EXPORT int ExcludeClipRect(HDC hdc, int left, int top, int right, int bottom)
{
    (void)hdc;
    (void)left; (void)top; (void)right; (void)bottom;
    return 1;  /* SIMPLEREGION */
}

/* --------------------------------------------------------------------------
 * GetDeviceCaps
 * -------------------------------------------------------------------------- */

/* GetDeviceCaps index constants -- values match wingdi.h */
#define DRIVERVERSION   0
#define TECHNOLOGY      2
#define HORZSIZE        4       /* mm */
#define VERTSIZE        6       /* mm */
#define HORZRES         8       /* pixels */
#define VERTRES         10      /* pixels */
#define BITSPIXEL       12
#define PLANES          14
#define NUMBRUSHES      16
#define NUMPENS         18
#define NUMMARKERS      20
#define NUMFONTS        22
#define NUMCOLORS       24
#define PDEVICESIZE     26
#define CURVECAPS       28
#define LINECAPS        30
#define POLYGONALCAPS   32
#define TEXTCAPS        34
#define CLIPCAPS        36
#define RASTERCAPS      38
#define ASPECTX         40
#define ASPECTY         42
#define ASPECTXY        44
#define LOGPIXELSX      88
#define LOGPIXELSY      90
#define SIZEPALETTE     104
#define NUMRESERVED     106
#define COLORRES        108
#define PHYSICALWIDTH   110
#define PHYSICALHEIGHT  111
#define PHYSICALOFFSETX 112
#define PHYSICALOFFSETY 113
#define VREFRESH        116
#define DESKTOPVERTRES  117
#define DESKTOPHORZRES  118
#define BLTALIGNMENT    119
#define SHADEBLENDCAPS  120
#define COLORMGMTCAPS   121

/* RASTERCAPS bits */
#define RC_BITBLT       1
#define RC_BANDING      2
#define RC_SCALING      4
#define RC_BITMAP64     8
#define RC_DI_BITMAP    0x0080
#define RC_PALETTE      0x0100
#define RC_DIBTODEV     0x0200
#define RC_STRETCHBLT   0x0800
#define RC_STRETCHDIB   0x2000

WINAPI_EXPORT int GetDeviceCaps(HDC hdc, int index)
{
    (void)hdc;

    gfx_backend_t *backend = gfx_get_backend();
    gfx_screen_size_t sz = { 1920, 1080 };
    if (backend)
        sz = backend->get_screen_size(backend);

    switch (index) {
    case DRIVERVERSION:     return 0x0600;      /* Windows Vista+ driver */
    case TECHNOLOGY:        return 1;           /* DT_RASDISPLAY */
    case HORZSIZE:          return (sz.width * 254) / (96 * 10);  /* mm from DPI */
    case VERTSIZE:          return (sz.height * 254) / (96 * 10);
    case HORZRES:           return sz.width;
    case VERTRES:           return sz.height;
    case BITSPIXEL:         return 32;
    case PLANES:            return 1;
    case NUMBRUSHES:        return -1;          /* Unlimited */
    case NUMPENS:           return -1;
    case NUMFONTS:          return 0;           /* Device fonts (we use TrueType) */
    case NUMCOLORS:         return -1;          /* True color */
    case ASPECTX:           return 36;
    case ASPECTY:           return 36;
    case ASPECTXY:          return 51;
    case PDEVICESIZE:       return 0;
    case CURVECAPS:         return 0xFF;        /* All curve caps */
    case LINECAPS:          return 0xFF;        /* All line caps */
    case POLYGONALCAPS:     return 0xFF;        /* All polygon caps */
    case TEXTCAPS:          return 0;           /* GDI handles text */
    case CLIPCAPS:          return 1;           /* CP_RECTANGLE */
    case RASTERCAPS:        return RC_BITBLT | RC_DI_BITMAP | RC_DIBTODEV |
                                   RC_STRETCHBLT | RC_STRETCHDIB | RC_BITMAP64;
    case LOGPIXELSX:        return 96;
    case LOGPIXELSY:        return 96;
    case SIZEPALETTE:       return 0;
    case NUMRESERVED:       return 0;
    case COLORRES:          return 24;          /* 8 bits per channel */
    case PHYSICALWIDTH:     return sz.width;    /* Same as HORZRES for displays */
    case PHYSICALHEIGHT:    return sz.height;
    case PHYSICALOFFSETX:   return 0;
    case PHYSICALOFFSETY:   return 0;
    case VREFRESH:          return 60;          /* 60 Hz */
    case DESKTOPHORZRES:    return sz.width;
    case DESKTOPVERTRES:    return sz.height;
    case BLTALIGNMENT:      return 0;
    case SHADEBLENDCAPS:    return 0xFF;        /* Full alpha/gradient blend */
    case COLORMGMTCAPS:     return 1;           /* CM_DEVICE_ICM */
    default:                return 0;
    }
}

/* --------------------------------------------------------------------------
 * Coordinate transforms
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL DPtoLP(HDC hdc, LPPOINT lppt, int c)
{
    (void)hdc; (void)lppt; (void)c;
    return TRUE;  /* MM_TEXT is identity */
}

WINAPI_EXPORT BOOL LPtoDP(HDC hdc, LPPOINT lppt, int c)
{
    (void)hdc; (void)lppt; (void)c;
    return TRUE;
}

WINAPI_EXPORT BOOL SetViewportOrgEx(HDC hdc, int x, int y, LPPOINT lppt)
{
    (void)hdc; (void)x; (void)y;
    if (lppt) { lppt->x = 0; lppt->y = 0; }
    return TRUE;
}

WINAPI_EXPORT BOOL SetWindowOrgEx(HDC hdc, int x, int y, LPPOINT lppt)
{
    (void)hdc; (void)x; (void)y;
    if (lppt) { lppt->x = 0; lppt->y = 0; }
    return TRUE;
}

WINAPI_EXPORT BOOL SetViewportExtEx(HDC hdc, int x, int y, LPSIZE lpSize)
{
    (void)hdc; (void)x; (void)y;
    if (lpSize) { lpSize->cx = 0; lpSize->cy = 0; }
    return TRUE;
}

WINAPI_EXPORT BOOL SetWindowExtEx(HDC hdc, int x, int y, LPSIZE lpSize)
{
    (void)hdc; (void)x; (void)y;
    if (lpSize) { lpSize->cx = 0; lpSize->cy = 0; }
    return TRUE;
}
