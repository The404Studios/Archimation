/*
 * gdi32_font.c - GDI font management, text metrics, and text output stubs
 *
 * Canonical implementations for the following Win32 GDI APIs:
 *   Font creation:   CreateFontA/W, CreateFontIndirectA/W
 *   Font selection:  SelectObject_Font, GetObjectA_Font
 *   Text metrics:    GetTextMetricsA/W, GetTextExtentPoint32A/W
 *   Font enum:       EnumFontFamiliesExA/W
 *   Font resources:  AddFontResourceA/W, RemoveFontResourceA/W
 *   DC text state:   SetTextColor/GetTextColor, SetBkColor/GetBkColor,
 *                    SetBkMode/GetBkMode
 *   Text output:     TextOutA/W, ExtTextOutA/W
 *   Text face:       GetTextFaceA/W
 *   Char widths:     GetCharWidthA, GetCharWidth32A
 *   Char extra:      GetTextCharacterExtra, SetTextCharacterExtra
 *
 * Uses a small static DC state table (up to 64 DCs) to track per-DC font
 * properties (text color, background color, background mode, selected font,
 * character extra spacing).
 *
 * Text-rendering-only APIs (DrawText, SetTextAlign, GetCharABCWidths, etc.)
 * live in gdi32_text.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>

#include "common/dll_common.h"

/* --------------------------------------------------------------------------
 * COLORREF type and RGB macro
 * -------------------------------------------------------------------------- */

typedef DWORD COLORREF;
typedef DWORD *LPCOLORREF;

#define RGB_FONT(r,g,b) ((COLORREF)(((BYTE)(r)) | ((WORD)((BYTE)(g)) << 8) | ((DWORD)((BYTE)(b)) << 16)))

#define CLR_INVALID_FONT    0xFFFFFFFF

/* Background modes */
#define TRANSPARENT_MODE    1
#define OPAQUE_MODE         2

/* Font weight constants */
#define FW_DONTCARE     0
#define FW_THIN         100
#define FW_EXTRALIGHT   200
#define FW_ULTRALIGHT   200
#define FW_LIGHT        300
#define FW_NORMAL       400
#define FW_REGULAR      400
#define FW_MEDIUM       500
#define FW_SEMIBOLD     600
#define FW_DEMIBOLD     600
#define FW_BOLD         700
#define FW_EXTRABOLD    800
#define FW_ULTRABOLD    800
#define FW_HEAVY        900
#define FW_BLACK        900

/* Font charset */
#define ANSI_CHARSET        0
#define DEFAULT_CHARSET     1
#define SYMBOL_CHARSET      2
#define OEM_CHARSET         255

/* Font output precision */
#define OUT_DEFAULT_PRECIS      0
#define OUT_STRING_PRECIS       1
#define OUT_TT_PRECIS           4

/* Font clip precision */
#define CLIP_DEFAULT_PRECIS     0

/* Font quality */
#define DEFAULT_QUALITY         0
#define DRAFT_QUALITY           1
#define PROOF_QUALITY           2
#define NONANTIALIASED_QUALITY  3
#define ANTIALIASED_QUALITY     4
#define CLEARTYPE_QUALITY       5

/* Font pitch */
#define DEFAULT_PITCH       0
#define FIXED_PITCH         1
#define VARIABLE_PITCH      2

/* Font family */
#define FF_DONTCARE     (0 << 4)
#define FF_ROMAN        (1 << 4)
#define FF_SWISS        (2 << 4)
#define FF_MODERN       (3 << 4)
#define FF_SCRIPT       (4 << 4)
#define FF_DECORATIVE   (5 << 4)

/* Font type flags for EnumFontFamiliesEx callback */
#define RASTER_FONTTYPE     0x0001
#define DEVICE_FONTTYPE     0x0002
#define TRUETYPE_FONTTYPE   0x0004

/* ExtTextOut flags */
#define ETO_OPAQUE      0x0002
#define ETO_CLIPPED     0x0004

/* --------------------------------------------------------------------------
 * LOGFONT structures
 * -------------------------------------------------------------------------- */

#define LF_FACESIZE     32
#define LF_FULLFACESIZE 64

typedef struct tagLOGFONTA {
    LONG    lfHeight;
    LONG    lfWidth;
    LONG    lfEscapement;
    LONG    lfOrientation;
    LONG    lfWeight;
    BYTE    lfItalic;
    BYTE    lfUnderline;
    BYTE    lfStrikeOut;
    BYTE    lfCharSet;
    BYTE    lfOutPrecision;
    BYTE    lfClipPrecision;
    BYTE    lfQuality;
    BYTE    lfPitchAndFamily;
    CHAR    lfFaceName[LF_FACESIZE];
} LOGFONTA, *LPLOGFONTA;

typedef struct tagLOGFONTW {
    LONG    lfHeight;
    LONG    lfWidth;
    LONG    lfEscapement;
    LONG    lfOrientation;
    LONG    lfWeight;
    BYTE    lfItalic;
    BYTE    lfUnderline;
    BYTE    lfStrikeOut;
    BYTE    lfCharSet;
    BYTE    lfOutPrecision;
    BYTE    lfClipPrecision;
    BYTE    lfQuality;
    BYTE    lfPitchAndFamily;
    WCHAR   lfFaceName[LF_FACESIZE];
} LOGFONTW, *LPLOGFONTW;

/* --------------------------------------------------------------------------
 * TEXTMETRIC structures
 * -------------------------------------------------------------------------- */

typedef struct tagTEXTMETRICA {
    LONG    tmHeight;
    LONG    tmAscent;
    LONG    tmDescent;
    LONG    tmInternalLeading;
    LONG    tmExternalLeading;
    LONG    tmAveCharWidth;
    LONG    tmMaxCharWidth;
    LONG    tmWeight;
    LONG    tmOverhang;
    LONG    tmDigitizedAspectX;
    LONG    tmDigitizedAspectY;
    BYTE    tmFirstChar;
    BYTE    tmLastChar;
    BYTE    tmDefaultChar;
    BYTE    tmBreakChar;
    BYTE    tmItalic;
    BYTE    tmUnderlined;
    BYTE    tmStruckOut;
    BYTE    tmPitchAndFamily;
    BYTE    tmCharSet;
} TEXTMETRICA, *LPTEXTMETRICA;

typedef struct tagTEXTMETRICW {
    LONG    tmHeight;
    LONG    tmAscent;
    LONG    tmDescent;
    LONG    tmInternalLeading;
    LONG    tmExternalLeading;
    LONG    tmAveCharWidth;
    LONG    tmMaxCharWidth;
    LONG    tmWeight;
    LONG    tmOverhang;
    LONG    tmDigitizedAspectX;
    LONG    tmDigitizedAspectY;
    WCHAR   tmFirstChar;
    WCHAR   tmLastChar;
    WCHAR   tmDefaultChar;
    WCHAR   tmBreakChar;
    BYTE    tmItalic;
    BYTE    tmUnderlined;
    BYTE    tmStruckOut;
    BYTE    tmPitchAndFamily;
    BYTE    tmCharSet;
} TEXTMETRICW, *LPTEXTMETRICW;

/* --------------------------------------------------------------------------
 * ENUMLOGFONTEX / NEWTEXTMETRICEX for EnumFontFamiliesEx callback
 * -------------------------------------------------------------------------- */

typedef struct tagENUMLOGFONTEXA {
    LOGFONTA elfLogFont;
    char     elfFullName[LF_FULLFACESIZE];
    char     elfStyle[LF_FACESIZE];
    char     elfScript[LF_FACESIZE];
} ENUMLOGFONTEXA;

typedef struct tagNEWTEXTMETRICEXA {
    TEXTMETRICA ntmTm;
    DWORD       ntmFontSig[2];  /* Simplified FONTSIGNATURE */
} NEWTEXTMETRICEXA;

/* --------------------------------------------------------------------------
 * Font handle table
 * -------------------------------------------------------------------------- */

#define MAX_FONT_HANDLES 256

typedef struct {
    HFONT       handle;
    LOGFONTA    logfont;
    int         pixel_height;   /* Effective pixel height */
    int         avg_width;      /* Average character width */
    int         used;
} font_entry_t;

static font_entry_t g_font_table[MAX_FONT_HANDLES];
/* Session 30: make font-handle allocation thread-safe. Same rationale as
 * the dc_map lock — Unity/UE can touch font state from the render thread
 * while the worker thread is still loading assets via SelectObject. */
static _Atomic(uintptr_t) g_next_font_handle = 0xF1000000;
static pthread_mutex_t g_font_table_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t  g_font_table_once = PTHREAD_ONCE_INIT;

static void font_table_init_cb(void)
{
    memset(g_font_table, 0, sizeof(g_font_table));
}

static void ensure_font_table_init(void)
{
    pthread_once(&g_font_table_once, font_table_init_cb);
}

static font_entry_t *font_alloc(const LOGFONTA *lf)
{
    ensure_font_table_init();
    pthread_mutex_lock(&g_font_table_lock);
    for (int i = 0; i < MAX_FONT_HANDLES; i++) {
        if (!g_font_table[i].used) {
            memset(&g_font_table[i], 0, sizeof(font_entry_t));
            g_font_table[i].used = 1;
            g_font_table[i].handle = (HFONT)atomic_fetch_add(&g_next_font_handle, 1);

            if (lf) {
                g_font_table[i].logfont = *lf;
                int h = lf->lfHeight;
                if (h < 0) h = -h;
                if (h == 0) h = 16;
                g_font_table[i].pixel_height = h;
                g_font_table[i].avg_width = (h > 2) ? (h * 2) / 3 : 8;
                if (g_font_table[i].avg_width < 1)
                    g_font_table[i].avg_width = 8;
            } else {
                /* Default font metrics */
                g_font_table[i].pixel_height = 16;
                g_font_table[i].avg_width = 8;
                strncpy(g_font_table[i].logfont.lfFaceName, "Arial",
                        LF_FACESIZE - 1);
                g_font_table[i].logfont.lfHeight = -16;
                g_font_table[i].logfont.lfWeight = FW_NORMAL;
                g_font_table[i].logfont.lfCharSet = DEFAULT_CHARSET;
                g_font_table[i].logfont.lfPitchAndFamily = DEFAULT_PITCH | FF_SWISS;
            }

            pthread_mutex_unlock(&g_font_table_lock);
            return &g_font_table[i];
        }
    }
    pthread_mutex_unlock(&g_font_table_lock);
    return NULL;
}

static font_entry_t *font_lookup(HFONT hf)
{
    ensure_font_table_init();
    if (!hf) return NULL;
    pthread_mutex_lock(&g_font_table_lock);
    for (int i = 0; i < MAX_FONT_HANDLES; i++) {
        if (g_font_table[i].used && g_font_table[i].handle == hf) {
            pthread_mutex_unlock(&g_font_table_lock);
            return &g_font_table[i];
        }
    }
    pthread_mutex_unlock(&g_font_table_lock);
    return NULL;
}

/*
 * Free a font entry by handle.  Called from DeleteObject in gdi32_dc.c
 * when the handle falls in our font range, and from any direct
 * DeleteFont callers.  Returns TRUE on success, FALSE if handle
 * wasn't found.  Not exported (internal helper).
 */
int gdi32_font_delete(HFONT hf)
{
    ensure_font_table_init();
    if (!hf) return 0;
    pthread_mutex_lock(&g_font_table_lock);
    for (int i = 0; i < MAX_FONT_HANDLES; i++) {
        if (g_font_table[i].used && g_font_table[i].handle == hf) {
            memset(&g_font_table[i], 0, sizeof(g_font_table[i]));
            pthread_mutex_unlock(&g_font_table_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_font_table_lock);
    return 0;
}

/* gdi32_font_dc_release() defined below after g_font_dc is declared. */

/* --------------------------------------------------------------------------
 * Per-DC state tracking
 *
 * Small table of up to 64 DCs. Each DC tracks its text color, background
 * color, background mode, selected font, and character extra spacing.
 * The HDC value is used as-is for lookup (simple linear scan).
 * -------------------------------------------------------------------------- */

#define MAX_FONT_DCS 64

typedef struct {
    HDC         hdc;
    COLORREF    text_color;
    COLORREF    bg_color;
    int         bg_mode;
    HFONT       selected_font;
    HFONT       prev_font;          /* Previously selected font */
    int         char_extra;
    int         used;
} font_dc_state_t;

static font_dc_state_t g_font_dc[MAX_FONT_DCS];
static int g_font_dc_initialized = 0;

static void ensure_font_dc_init(void)
{
    if (!g_font_dc_initialized) {
        memset(g_font_dc, 0, sizeof(g_font_dc));
        g_font_dc_initialized = 1;
    }
}

static font_dc_state_t *font_dc_lookup(HDC hdc)
{
    ensure_font_dc_init();
    if (!hdc) return NULL;
    for (int i = 0; i < MAX_FONT_DCS; i++) {
        if (g_font_dc[i].used && g_font_dc[i].hdc == hdc)
            return &g_font_dc[i];
    }
    return NULL;
}

/*
 * Get or create a DC state entry for the given HDC.
 * If the DC is not yet tracked, allocate a slot with defaults.
 */
static font_dc_state_t *font_dc_get_or_create(HDC hdc)
{
    if (!hdc) return NULL;
    ensure_font_dc_init();

    /* Try existing lookup first */
    font_dc_state_t *dc = font_dc_lookup(hdc);
    if (dc) return dc;

    /* Allocate a new slot */
    for (int i = 0; i < MAX_FONT_DCS; i++) {
        if (!g_font_dc[i].used) {
            memset(&g_font_dc[i], 0, sizeof(font_dc_state_t));
            g_font_dc[i].used = 1;
            g_font_dc[i].hdc = hdc;
            g_font_dc[i].text_color = RGB_FONT(0, 0, 0);         /* Black */
            g_font_dc[i].bg_color = RGB_FONT(255, 255, 255);     /* White */
            g_font_dc[i].bg_mode = OPAQUE_MODE;
            g_font_dc[i].selected_font = NULL;
            g_font_dc[i].prev_font = NULL;
            g_font_dc[i].char_extra = 0;
            return &g_font_dc[i];
        }
    }
    return NULL;
}

/*
 * Release per-DC font state.  Called from DeleteDC/ReleaseDC in
 * gdi32_dc.c so the 64-slot g_font_dc table doesn't leak entries on
 * every GetDC.  Once all 64 slots fill, font_dc_get_or_create() returns
 * NULL and SetTextColor_Font / SelectObject_Font / etc fail silently.
 */
void gdi32_font_dc_release(HDC hdc)
{
    if (!hdc) return;
    ensure_font_dc_init();
    for (int i = 0; i < MAX_FONT_DCS; i++) {
        if (g_font_dc[i].used && g_font_dc[i].hdc == hdc) {
            memset(&g_font_dc[i], 0, sizeof(g_font_dc[i]));
            return;
        }
    }
}

/* --------------------------------------------------------------------------
 * Stock-font support (Session 26 Agent 7 follow-up)
 *
 * Stock fonts come from GetStockObject(SYSTEM_FONT / DEFAULT_GUI_FONT / ...).
 * They are allocated as gdi_object_t in gdi32_dc.c (handle range
 * 0x80000000-0x800003FF) -- NOT as font_entry_t in our font pool -- so
 * font_lookup() used to return NULL for them.  Effect: TextOut/GetTextMetrics
 * fell back to Arial-16 regardless of which stock font the app selected,
 * and GetObjectA on a stock font handle returned 0.
 *
 * Fix: when SelectObject (in gdi32_dc.c) or GetObjectA dispatches a stock-font
 * handle here, we materialise a font_entry_t on demand keyed by the stock
 * HGDIOBJ itself, backed by a per-stock-id LOGFONTA template.
 *
 * The stock-id constants must match the GetStockObject(n) indices used in
 * gdi32_dc.c so the two files stay in sync.
 * -------------------------------------------------------------------------- */

#define GDI_STOCK_OEM_FIXED_FONT      10
#define GDI_STOCK_ANSI_FIXED_FONT     11
#define GDI_STOCK_ANSI_VAR_FONT       12
#define GDI_STOCK_SYSTEM_FONT         13
#define GDI_STOCK_DEVICE_DEFAULT_FONT 14
#define GDI_STOCK_SYSTEM_FIXED_FONT   16
#define GDI_STOCK_DEFAULT_GUI_FONT    17

/* Fill LOGFONTA with sensible defaults for each stock-font id.
 * Heights are negative (= cell height in pixels, Windows convention). */
static void fill_stock_logfont_defaults(int stock_id, LOGFONTA *lf)
{
    memset(lf, 0, sizeof(*lf));
    lf->lfCharSet        = DEFAULT_CHARSET;
    lf->lfOutPrecision   = OUT_DEFAULT_PRECIS;
    lf->lfClipPrecision  = CLIP_DEFAULT_PRECIS;
    lf->lfQuality        = DEFAULT_QUALITY;

    switch (stock_id) {
    case GDI_STOCK_OEM_FIXED_FONT:
        lf->lfHeight         = -12;
        lf->lfWeight         = FW_NORMAL;
        lf->lfCharSet        = OEM_CHARSET;
        lf->lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
        strncpy(lf->lfFaceName, "Terminal", LF_FACESIZE - 1);
        break;
    case GDI_STOCK_ANSI_FIXED_FONT:
    case GDI_STOCK_SYSTEM_FIXED_FONT:
        lf->lfHeight         = -12;
        lf->lfWeight         = FW_NORMAL;
        lf->lfCharSet        = ANSI_CHARSET;
        lf->lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
        strncpy(lf->lfFaceName, "Courier", LF_FACESIZE - 1);
        break;
    case GDI_STOCK_ANSI_VAR_FONT:
        lf->lfHeight         = -12;
        lf->lfWeight         = FW_NORMAL;
        lf->lfCharSet        = ANSI_CHARSET;
        lf->lfPitchAndFamily = VARIABLE_PITCH | FF_SWISS;
        strncpy(lf->lfFaceName, "MS Sans Serif", LF_FACESIZE - 1);
        break;
    case GDI_STOCK_SYSTEM_FONT:
        lf->lfHeight         = -16;
        lf->lfWeight         = FW_BOLD;
        lf->lfCharSet        = ANSI_CHARSET;
        lf->lfPitchAndFamily = VARIABLE_PITCH | FF_SWISS;
        strncpy(lf->lfFaceName, "System", LF_FACESIZE - 1);
        break;
    case GDI_STOCK_DEVICE_DEFAULT_FONT:
        lf->lfHeight         = -16;
        lf->lfWeight         = FW_NORMAL;
        lf->lfCharSet        = ANSI_CHARSET;
        lf->lfPitchAndFamily = VARIABLE_PITCH | FF_SWISS;
        strncpy(lf->lfFaceName, "System", LF_FACESIZE - 1);
        break;
    case GDI_STOCK_DEFAULT_GUI_FONT:
    default:
        lf->lfHeight         = -11;
        lf->lfWeight         = FW_NORMAL;
        lf->lfCharSet        = DEFAULT_CHARSET;
        lf->lfPitchAndFamily = VARIABLE_PITCH | FF_SWISS;
        strncpy(lf->lfFaceName, "MS Shell Dlg", LF_FACESIZE - 1);
        break;
    }
    lf->lfFaceName[LF_FACESIZE - 1] = '\0';
}

/*
 * Ensure a font_entry_t exists in g_font_table with handle == stock_handle.
 * Idempotent: if an entry for that handle is already present, returns it.
 * Called from SelectObject's stock-font dispatch so font_lookup() finds
 * metrics for the stock handle and TextOut / GetTextMetrics pick up the
 * stock font's LOGFONTA instead of the Arial-16 fallback.
 */
static font_entry_t *stock_font_entry_ensure(HGDIOBJ stock_handle, int stock_id)
{
    ensure_font_table_init();
    if (!stock_handle) return NULL;

    /* Reuse existing entry for this handle if already materialised. */
    for (int i = 0; i < MAX_FONT_HANDLES; i++) {
        if (g_font_table[i].used &&
            g_font_table[i].handle == (HFONT)stock_handle) {
            return &g_font_table[i];
        }
    }

    /* Allocate a slot and install the stock-font LOGFONTA template. */
    for (int i = 0; i < MAX_FONT_HANDLES; i++) {
        if (!g_font_table[i].used) {
            memset(&g_font_table[i], 0, sizeof(font_entry_t));
            g_font_table[i].used = 1;
            g_font_table[i].handle = (HFONT)stock_handle;
            fill_stock_logfont_defaults(stock_id, &g_font_table[i].logfont);

            int h = g_font_table[i].logfont.lfHeight;
            if (h < 0) h = -h;
            if (h == 0) h = 16;
            g_font_table[i].pixel_height = h;
            g_font_table[i].avg_width = (h > 2) ? (h * 2) / 3 : 8;
            if (g_font_table[i].avg_width < 1)
                g_font_table[i].avg_width = 8;
            return &g_font_table[i];
        }
    }
    return NULL;  /* Table full */
}

/*
 * Called from gdi32_dc.c:SelectObject when a stock-font gdi_object_t is
 * selected.  Side effects:
 *   1. Materialise a font_entry_t for the stock handle (so font_lookup works).
 *   2. Point the font_dc_state_t's selected_font at the stock handle.
 *
 * No return value -- gdi32_dc.c handles the "previous selection" reporting
 * through its own dc_entry_t state.
 */
void gdi32_font_sync_stock_on_dc(HDC hdc, HGDIOBJ stock_handle, int stock_id)
{
    if (!hdc || !stock_handle) return;

    font_entry_t *fe = stock_font_entry_ensure(stock_handle, stock_id);
    if (!fe) return;

    font_dc_state_t *dc = font_dc_get_or_create(hdc);
    if (!dc) return;

    dc->prev_font = dc->selected_font;
    dc->selected_font = (HFONT)stock_handle;
}

/*
 * Called from gdi32_dc.c:gdi32_dc_get_object_info when GetObjectA is invoked
 * on a stock-font handle.  Fills the caller's LOGFONTA (or reports the
 * required buffer size when pv==NULL).  Returns bytes written, matching
 * the Win32 GetObjectA contract.
 */
int gdi32_font_fill_stock_logfonta(int stock_id, int cb, void *pv)
{
    if (!pv) return (int)sizeof(LOGFONTA);
    if (cb < (int)sizeof(LOGFONTA)) return 0;

    LOGFONTA *out = (LOGFONTA *)pv;
    fill_stock_logfont_defaults(stock_id, out);
    return (int)sizeof(LOGFONTA);
}

/* --------------------------------------------------------------------------
 * Helper: get the active font's metrics for a DC
 * -------------------------------------------------------------------------- */

static void get_active_font_metrics(HDC hdc, int *out_height, int *out_avg_width)
{
    int height = 16;
    int avg_width = 8;

    font_dc_state_t *dc = font_dc_lookup(hdc);
    if (dc && dc->selected_font) {
        font_entry_t *fe = font_lookup(dc->selected_font);
        if (fe) {
            height = fe->pixel_height;
            avg_width = fe->avg_width;
        }
    }

    if (out_height)    *out_height = height;
    if (out_avg_width) *out_avg_width = avg_width;
}

/* ==========================================================================
 * CreateFontA / CreateFontW
 * ========================================================================== */

WINAPI_EXPORT HFONT CreateFontA(
    int     cHeight,
    int     cWidth,
    int     cEscapement,
    int     cOrientation,
    int     cWeight,
    DWORD   bItalic,
    DWORD   bUnderline,
    DWORD   bStrikeOut,
    DWORD   iCharSet,
    DWORD   iOutPrecision,
    DWORD   iClipPrecision,
    DWORD   iQuality,
    DWORD   iPitchAndFamily,
    LPCSTR  pszFaceName)
{
    LOGFONTA lf;
    memset(&lf, 0, sizeof(lf));

    lf.lfHeight         = cHeight;
    lf.lfWidth          = cWidth;
    lf.lfEscapement     = cEscapement;
    lf.lfOrientation    = cOrientation;
    lf.lfWeight         = cWeight;
    lf.lfItalic         = (BYTE)bItalic;
    lf.lfUnderline      = (BYTE)bUnderline;
    lf.lfStrikeOut      = (BYTE)bStrikeOut;
    lf.lfCharSet        = (BYTE)iCharSet;
    lf.lfOutPrecision   = (BYTE)iOutPrecision;
    lf.lfClipPrecision  = (BYTE)iClipPrecision;
    lf.lfQuality        = (BYTE)iQuality;
    lf.lfPitchAndFamily = (BYTE)iPitchAndFamily;

    if (pszFaceName) {
        strncpy(lf.lfFaceName, pszFaceName, LF_FACESIZE - 1);
        lf.lfFaceName[LF_FACESIZE - 1] = '\0';
    }

    font_entry_t *fe = font_alloc(&lf);
    return fe ? fe->handle : NULL;
}

WINAPI_EXPORT HFONT CreateFontW(
    int     cHeight,
    int     cWidth,
    int     cEscapement,
    int     cOrientation,
    int     cWeight,
    DWORD   bItalic,
    DWORD   bUnderline,
    DWORD   bStrikeOut,
    DWORD   iCharSet,
    DWORD   iOutPrecision,
    DWORD   iClipPrecision,
    DWORD   iQuality,
    DWORD   iPitchAndFamily,
    LPCWSTR pszFaceName)
{
    char face_narrow[LF_FACESIZE] = {0};
    if (pszFaceName) {
        int i;
        for (i = 0; pszFaceName[i] && i < LF_FACESIZE - 1; i++)
            face_narrow[i] = (char)(pszFaceName[i] & 0xFF);
        face_narrow[i] = '\0';
    }

    return CreateFontA(cHeight, cWidth, cEscapement, cOrientation, cWeight,
                       bItalic, bUnderline, bStrikeOut, iCharSet,
                       iOutPrecision, iClipPrecision, iQuality,
                       iPitchAndFamily,
                       pszFaceName ? face_narrow : NULL);
}

/* ==========================================================================
 * CreateFontIndirectA / CreateFontIndirectW
 * ========================================================================== */

WINAPI_EXPORT HFONT CreateFontIndirectA(const LOGFONTA *lplf)
{
    if (!lplf)
        return NULL;

    font_entry_t *fe = font_alloc(lplf);
    return fe ? fe->handle : NULL;
}

WINAPI_EXPORT HFONT CreateFontIndirectW(const LOGFONTW *lplf)
{
    if (!lplf)
        return NULL;

    LOGFONTA lfa;
    memset(&lfa, 0, sizeof(lfa));
    lfa.lfHeight        = lplf->lfHeight;
    lfa.lfWidth         = lplf->lfWidth;
    lfa.lfEscapement    = lplf->lfEscapement;
    lfa.lfOrientation   = lplf->lfOrientation;
    lfa.lfWeight        = lplf->lfWeight;
    lfa.lfItalic        = lplf->lfItalic;
    lfa.lfUnderline     = lplf->lfUnderline;
    lfa.lfStrikeOut     = lplf->lfStrikeOut;
    lfa.lfCharSet       = lplf->lfCharSet;
    lfa.lfOutPrecision  = lplf->lfOutPrecision;
    lfa.lfClipPrecision = lplf->lfClipPrecision;
    lfa.lfQuality       = lplf->lfQuality;
    lfa.lfPitchAndFamily = lplf->lfPitchAndFamily;

    /* Convert wide face name to narrow */
    for (int i = 0; i < LF_FACESIZE - 1 && lplf->lfFaceName[i]; i++)
        lfa.lfFaceName[i] = (char)(lplf->lfFaceName[i] & 0xFF);

    font_entry_t *fe = font_alloc(&lfa);
    return fe ? fe->handle : NULL;
}

/* ==========================================================================
 * SelectObject_Font - Font selection stub; returns previously selected handle
 *
 * NOTE: This is called by the dispatcher in gdi32_dc.c's SelectObject when
 * the handle is identified as a font.  It keeps the _Font suffix to avoid
 * colliding with the SelectObject in gdi32_dc.c.
 * ========================================================================== */

WINAPI_EXPORT HGDIOBJ SelectObject_Font(HDC hdc, HGDIOBJ h)
{
    if (!hdc || !h)
        return NULL;

    font_dc_state_t *dc = font_dc_get_or_create(hdc);
    if (!dc)
        return NULL;

    /* Verify this is one of our font handles */
    font_entry_t *fe = font_lookup((HFONT)h);
    if (!fe)
        return NULL;

    HGDIOBJ old = (HGDIOBJ)dc->selected_font;
    dc->prev_font = dc->selected_font;
    dc->selected_font = (HFONT)h;

    fprintf(stderr, "gdi32_font: SelectObject_Font(hdc=%p, font=%p) -> prev=%p\n",
            hdc, h, old);
    return old;
}

/* ==========================================================================
 * gdi32_font_select_on_dc - dispatcher entry point from gdi32_dc.c
 *
 * Called by SelectObject in gdi32_dc.c when the handle is in the font range
 * (0xF1000000-0xF1FFFFFF).  Validates the handle, updates both the
 * canonical dc_entry_t.selected_font (via gdi32_dc_set_selected) AND the
 * local g_font_dc state table so text metrics / TextOut lookups stay in
 * sync.  Returns the previously-selected font handle.
 *
 * Note: two sources of truth for selected_font exist today (dc_entry_t in
 * gdi32_dc.c and font_dc_state_t here).  We update both.  Cleaning up the
 * duplication is deferred (cross-file coordination required).
 * ========================================================================== */

extern __attribute__((ms_abi)) HGDIOBJ gdi32_dc_set_selected(HDC hdc, int obj_type, HGDIOBJ new_h);

#ifndef OBJ_FONT
#define OBJ_FONT 6
#endif

__attribute__((ms_abi)) HFONT gdi32_font_select_on_dc(HDC hdc, HFONT new_hf)
{
    if (!hdc || !new_hf)
        return NULL;

    /* Validate this is one of our font handles */
    if (!font_lookup(new_hf))
        return NULL;

    /* Update local font_dc state table (for TextOut/metrics) */
    font_dc_state_t *dc = font_dc_get_or_create(hdc);
    if (dc) {
        dc->prev_font = dc->selected_font;
        dc->selected_font = new_hf;
    }

    /* Update canonical dc_entry_t in gdi32_dc.c and get the old handle */
    return (HFONT)gdi32_dc_set_selected(hdc, OBJ_FONT, (HGDIOBJ)new_hf);
}

/* ==========================================================================
 * GetObjectA_Font - Return font info (LOGFONTA) from handle
 *
 * NOTE: Keeps _Font suffix because gdi32_bitmap.c defines GetObjectA
 * for bitmaps.  The loader's export table should dispatch based on
 * handle type.
 * ========================================================================== */

WINAPI_EXPORT int GetObjectA_Font(HANDLE h, int cbBuffer, LPVOID pv)
{
    if (!h)
        return 0;

    font_entry_t *fe = font_lookup((HFONT)h);
    if (!fe)
        return 0;

    /* If pv is NULL, return the required buffer size */
    if (!pv)
        return (int)sizeof(LOGFONTA);

    if (cbBuffer < (int)sizeof(LOGFONTA))
        return 0;

    memcpy(pv, &fe->logfont, sizeof(LOGFONTA));
    return (int)sizeof(LOGFONTA);
}

/* ==========================================================================
 * GetTextMetricsA - Fill TEXTMETRIC with reasonable defaults
 * ========================================================================== */

WINAPI_EXPORT BOOL GetTextMetricsA(HDC hdc, LPTEXTMETRICA lptm)
{
    if (!lptm)
        return FALSE;

    memset(lptm, 0, sizeof(TEXTMETRICA));

    int height = 16;
    int avg_width = 8;
    int weight = FW_NORMAL;
    BYTE charset = ANSI_CHARSET;
    BYTE italic = 0;
    BYTE underline = 0;
    BYTE strikeout = 0;

    /* Use selected font metrics if available */
    font_dc_state_t *dc = font_dc_lookup(hdc);
    if (dc && dc->selected_font) {
        font_entry_t *fe = font_lookup(dc->selected_font);
        if (fe) {
            height = fe->pixel_height;
            avg_width = fe->avg_width;
            weight = fe->logfont.lfWeight;
            charset = fe->logfont.lfCharSet;
            italic = fe->logfont.lfItalic;
            underline = fe->logfont.lfUnderline;
            strikeout = fe->logfont.lfStrikeOut;
        }
    }

    lptm->tmHeight              = height;
    lptm->tmAscent              = (height * 13) / 16;  /* ~81% ascent */
    lptm->tmDescent             = height - lptm->tmAscent;
    lptm->tmInternalLeading     = (height > 12) ? (height - 12) / 4 : 0;
    lptm->tmExternalLeading     = 0;
    lptm->tmAveCharWidth        = avg_width;
    lptm->tmMaxCharWidth        = avg_width * 2;
    lptm->tmWeight              = weight;
    lptm->tmOverhang            = 0;
    lptm->tmDigitizedAspectX    = 96;
    lptm->tmDigitizedAspectY    = 96;
    lptm->tmFirstChar           = 0x20;
    lptm->tmLastChar            = 0xFF;
    lptm->tmDefaultChar         = '?';
    lptm->tmBreakChar           = ' ';
    lptm->tmItalic              = italic;
    lptm->tmUnderlined          = underline;
    lptm->tmStruckOut           = strikeout;
    lptm->tmPitchAndFamily      = FIXED_PITCH | FF_MODERN;
    lptm->tmCharSet             = charset;

    return TRUE;
}

/* ==========================================================================
 * GetTextMetricsW - Wide version, fills TEXTMETRICW
 * ========================================================================== */

WINAPI_EXPORT BOOL GetTextMetricsW(HDC hdc, LPTEXTMETRICW lptm)
{
    if (!lptm)
        return FALSE;

    /* Get the ANSI metrics and convert */
    TEXTMETRICA tma;
    if (!GetTextMetricsA(hdc, &tma))
        return FALSE;

    memset(lptm, 0, sizeof(TEXTMETRICW));
    lptm->tmHeight              = tma.tmHeight;
    lptm->tmAscent              = tma.tmAscent;
    lptm->tmDescent             = tma.tmDescent;
    lptm->tmInternalLeading     = tma.tmInternalLeading;
    lptm->tmExternalLeading     = tma.tmExternalLeading;
    lptm->tmAveCharWidth        = tma.tmAveCharWidth;
    lptm->tmMaxCharWidth        = tma.tmMaxCharWidth;
    lptm->tmWeight              = tma.tmWeight;
    lptm->tmOverhang            = tma.tmOverhang;
    lptm->tmDigitizedAspectX    = tma.tmDigitizedAspectX;
    lptm->tmDigitizedAspectY    = tma.tmDigitizedAspectY;
    lptm->tmFirstChar           = (WCHAR)tma.tmFirstChar;
    lptm->tmLastChar            = (WCHAR)tma.tmLastChar;
    lptm->tmDefaultChar         = (WCHAR)tma.tmDefaultChar;
    lptm->tmBreakChar           = (WCHAR)tma.tmBreakChar;
    lptm->tmItalic              = tma.tmItalic;
    lptm->tmUnderlined          = tma.tmUnderlined;
    lptm->tmStruckOut           = tma.tmStruckOut;
    lptm->tmPitchAndFamily      = tma.tmPitchAndFamily;
    lptm->tmCharSet             = tma.tmCharSet;

    return TRUE;
}

/* ==========================================================================
 * GetTextExtentPoint32A - Compute text size (approximate)
 * Width = len * avgCharWidth, Height = pixel_height
 * ========================================================================== */

WINAPI_EXPORT BOOL GetTextExtentPoint32A(HDC hdc, LPCSTR lpString, int c,
                                          LPSIZE psizl)
{
    if (!psizl)
        return FALSE;

    if (!lpString || c <= 0) {
        psizl->cx = 0;
        psizl->cy = 0;
        return TRUE;
    }

    int height, avg_width;
    get_active_font_metrics(hdc, &height, &avg_width);

    /* Account for character extra spacing */
    int extra = 0;
    font_dc_state_t *dc = font_dc_lookup(hdc);
    if (dc)
        extra = dc->char_extra;

    psizl->cx = c * (avg_width + extra);
    psizl->cy = height;

    return TRUE;
}

/* ==========================================================================
 * GetTextExtentPoint32W - Wide version
 * ========================================================================== */

WINAPI_EXPORT BOOL GetTextExtentPoint32W(HDC hdc, LPCWSTR lpString, int c,
                                          LPSIZE psizl)
{
    if (!psizl)
        return FALSE;

    if (!lpString || c <= 0) {
        psizl->cx = 0;
        psizl->cy = 0;
        return TRUE;
    }

    int height, avg_width;
    get_active_font_metrics(hdc, &height, &avg_width);

    int extra = 0;
    font_dc_state_t *dc = font_dc_lookup(hdc);
    if (dc)
        extra = dc->char_extra;

    psizl->cx = c * (avg_width + extra);
    psizl->cy = height;

    return TRUE;
}

/* ==========================================================================
 * EnumFontFamiliesExA - Call callback once with a default font
 * ========================================================================== */

typedef int (CALLBACK *FONTENUMPROCA)(
    const LOGFONTA *, const TEXTMETRICA *, DWORD, LPARAM);

WINAPI_EXPORT int EnumFontFamiliesExA(HDC hdc, LPLOGFONTA lpLogfont,
                                       FONTENUMPROCA lpProc,
                                       LPARAM lParam, DWORD dwFlags)
{
    (void)hdc;
    (void)dwFlags;

    if (!lpProc)
        return 1;

    /* Build a default LOGFONT for the callback */
    LOGFONTA lf;
    memset(&lf, 0, sizeof(lf));
    lf.lfHeight         = -16;
    lf.lfWeight         = FW_NORMAL;
    lf.lfCharSet        = ANSI_CHARSET;
    lf.lfOutPrecision   = OUT_DEFAULT_PRECIS;
    lf.lfClipPrecision  = CLIP_DEFAULT_PRECIS;
    lf.lfQuality        = DEFAULT_QUALITY;
    lf.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
    strncpy(lf.lfFaceName, "Arial", LF_FACESIZE - 1);

    /* If the caller specified a face name filter, echo it back */
    if (lpLogfont && lpLogfont->lfFaceName[0]) {
        strncpy(lf.lfFaceName, lpLogfont->lfFaceName, LF_FACESIZE - 1);
        lf.lfFaceName[LF_FACESIZE - 1] = '\0';
    }

    /* Build default TEXTMETRIC */
    TEXTMETRICA tm;
    memset(&tm, 0, sizeof(tm));
    tm.tmHeight             = 16;
    tm.tmAscent             = 13;
    tm.tmDescent            = 3;
    tm.tmInternalLeading    = 3;
    tm.tmExternalLeading    = 0;
    tm.tmAveCharWidth       = 8;
    tm.tmMaxCharWidth       = 16;
    tm.tmWeight             = FW_NORMAL;
    tm.tmOverhang           = 0;
    tm.tmDigitizedAspectX   = 96;
    tm.tmDigitizedAspectY   = 96;
    tm.tmFirstChar          = 0x20;
    tm.tmLastChar           = 0xFF;
    tm.tmDefaultChar        = '?';
    tm.tmBreakChar          = ' ';
    tm.tmPitchAndFamily     = FIXED_PITCH | FF_MODERN;
    tm.tmCharSet            = ANSI_CHARSET;

    /* Call back once with TRUETYPE_FONTTYPE */
    return lpProc(&lf, &tm, TRUETYPE_FONTTYPE, lParam);
}

/* ==========================================================================
 * EnumFontFamiliesExW - Wide version
 * ========================================================================== */

typedef int (CALLBACK *FONTENUMPROCW)(
    const LOGFONTW *, const TEXTMETRICW *, DWORD, LPARAM);

WINAPI_EXPORT int EnumFontFamiliesExW(HDC hdc, LPLOGFONTW lpLogfont,
                                       FONTENUMPROCW lpProc,
                                       LPARAM lParam, DWORD dwFlags)
{
    (void)hdc;
    (void)dwFlags;

    if (!lpProc)
        return 1;

    /* Build a default wide LOGFONT */
    LOGFONTW lfw;
    memset(&lfw, 0, sizeof(lfw));
    lfw.lfHeight         = -16;
    lfw.lfWeight         = FW_NORMAL;
    lfw.lfCharSet        = ANSI_CHARSET;
    lfw.lfOutPrecision   = OUT_DEFAULT_PRECIS;
    lfw.lfClipPrecision  = CLIP_DEFAULT_PRECIS;
    lfw.lfQuality        = DEFAULT_QUALITY;
    lfw.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;

    const char *default_face = "Arial";
    for (int i = 0; default_face[i] && i < LF_FACESIZE - 1; i++)
        lfw.lfFaceName[i] = (WCHAR)default_face[i];

    /* If the caller specified a face name filter, echo it back */
    if (lpLogfont && lpLogfont->lfFaceName[0]) {
        memcpy(lfw.lfFaceName, lpLogfont->lfFaceName,
               sizeof(WCHAR) * LF_FACESIZE);
        lfw.lfFaceName[LF_FACESIZE - 1] = L'\0';
    }

    /* Build default wide TEXTMETRIC */
    TEXTMETRICW tmw;
    memset(&tmw, 0, sizeof(tmw));
    tmw.tmHeight             = 16;
    tmw.tmAscent             = 13;
    tmw.tmDescent            = 3;
    tmw.tmInternalLeading    = 3;
    tmw.tmExternalLeading    = 0;
    tmw.tmAveCharWidth       = 8;
    tmw.tmMaxCharWidth       = 16;
    tmw.tmWeight             = FW_NORMAL;
    tmw.tmDigitizedAspectX   = 96;
    tmw.tmDigitizedAspectY   = 96;
    tmw.tmFirstChar          = 0x0020;
    tmw.tmLastChar           = 0x00FF;
    tmw.tmDefaultChar        = L'?';
    tmw.tmBreakChar          = L' ';
    tmw.tmPitchAndFamily     = FIXED_PITCH | FF_MODERN;
    tmw.tmCharSet            = ANSI_CHARSET;

    return lpProc(&lfw, &tmw, TRUETYPE_FONTTYPE, lParam);
}

/* ==========================================================================
 * AddFontResourceA / AddFontResourceW - Stubs returning 1
 * ========================================================================== */

WINAPI_EXPORT int AddFontResourceA(LPCSTR lpszFilename)
{
    fprintf(stderr, "gdi32_font: AddFontResourceA('%s') stub\n",
            lpszFilename ? lpszFilename : "(null)");
    return 1;  /* Pretend one font was added */
}

WINAPI_EXPORT int AddFontResourceW(LPCWSTR lpszFilename)
{
    /* Convert wide filename for logging */
    char narrow[260] = {0};
    if (lpszFilename) {
        for (int i = 0; lpszFilename[i] && i < 259; i++)
            narrow[i] = (char)(lpszFilename[i] & 0xFF);
    }
    fprintf(stderr, "gdi32_font: AddFontResourceW('%s') stub\n", narrow);
    return 1;
}

/* ==========================================================================
 * RemoveFontResourceA / RemoveFontResourceW - Stubs returning TRUE
 * ========================================================================== */

WINAPI_EXPORT BOOL RemoveFontResourceA(LPCSTR lpszFilename)
{
    (void)lpszFilename;
    return TRUE;
}

WINAPI_EXPORT BOOL RemoveFontResourceW(LPCWSTR lpszFilename)
{
    (void)lpszFilename;
    return TRUE;
}

/* ==========================================================================
 * SetTextColor / GetTextColor - Track DC text color
 * ========================================================================== */

WINAPI_EXPORT COLORREF SetTextColor_Font(HDC hdc, COLORREF color)
{
    font_dc_state_t *dc = font_dc_get_or_create(hdc);
    if (!dc)
        return CLR_INVALID_FONT;

    COLORREF old = dc->text_color;
    dc->text_color = color;
    return old;
}

WINAPI_EXPORT COLORREF GetTextColor_Font(HDC hdc)
{
    font_dc_state_t *dc = font_dc_lookup(hdc);
    return dc ? dc->text_color : CLR_INVALID_FONT;
}

/* ==========================================================================
 * SetBkColor / GetBkColor - Track DC background color
 * ========================================================================== */

WINAPI_EXPORT COLORREF SetBkColor_Font(HDC hdc, COLORREF color)
{
    font_dc_state_t *dc = font_dc_get_or_create(hdc);
    if (!dc)
        return CLR_INVALID_FONT;

    COLORREF old = dc->bg_color;
    dc->bg_color = color;
    return old;
}

WINAPI_EXPORT COLORREF GetBkColor_Font(HDC hdc)
{
    font_dc_state_t *dc = font_dc_lookup(hdc);
    return dc ? dc->bg_color : CLR_INVALID_FONT;
}

/* ==========================================================================
 * SetBkMode / GetBkMode - Track TRANSPARENT / OPAQUE
 * ========================================================================== */

WINAPI_EXPORT int SetBkMode_Font(HDC hdc, int mode)
{
    font_dc_state_t *dc = font_dc_get_or_create(hdc);
    if (!dc)
        return 0;

    int old = dc->bg_mode;
    dc->bg_mode = mode;
    return old;
}

WINAPI_EXPORT int GetBkMode_Font(HDC hdc)
{
    font_dc_state_t *dc = font_dc_lookup(hdc);
    return dc ? dc->bg_mode : 0;
}

/* ==========================================================================
 * TextOutA / TextOutW
 * ========================================================================== */

WINAPI_EXPORT BOOL TextOutA(HDC hdc, int x, int y, LPCSTR lpString, int c)
{
    if (!lpString)
        return FALSE;
    if (c < 0)
        c = (int)strlen(lpString);
    if (c == 0)
        return TRUE;

    fprintf(stderr, "gdi32_font: TextOutA(hdc=%p, %d,%d, \"%.*s\")\n",
            hdc, x, y, c, lpString);
    return TRUE;
}

WINAPI_EXPORT BOOL TextOutW(HDC hdc, int x, int y, LPCWSTR lpString, int c)
{
    if (!lpString)
        return FALSE;

    /* Convert wide to narrow for the A version */
    char narrow[4096];
    int len;
    if (c < 0) {
        for (len = 0; lpString[len] && len < 4095; len++)
            ;
    } else {
        len = (c < 4095) ? c : 4095;
    }

    for (int i = 0; i < len; i++)
        narrow[i] = (char)(lpString[i] & 0xFF);
    narrow[len] = '\0';

    return TextOutA(hdc, x, y, narrow, len);
}

/* ==========================================================================
 * ExtTextOutA / ExtTextOutW
 * ========================================================================== */

WINAPI_EXPORT BOOL ExtTextOutA(HDC hdc, int x, int y, UINT options,
                                const RECT *lprect, LPCSTR lpString,
                                UINT c, const INT *lpDx)
{
    (void)options;
    (void)lprect;
    (void)lpDx;

    if (!lpString || c == 0)
        return TRUE;

    return TextOutA(hdc, x, y, lpString, (int)c);
}

WINAPI_EXPORT BOOL ExtTextOutW(HDC hdc, int x, int y, UINT options,
                                const RECT *lprect, LPCWSTR lpString,
                                UINT c, const INT *lpDx)
{
    (void)options;
    (void)lprect;
    (void)lpDx;

    if (!lpString || c == 0)
        return TRUE;

    return TextOutW(hdc, x, y, lpString, (int)c);
}

/* ==========================================================================
 * GetTextFaceA / GetTextFaceW - Return font face name
 * ========================================================================== */

WINAPI_EXPORT int GetTextFaceA(HDC hdc, int c, LPSTR lpName)
{
    const char *face = "Arial";

    /* Try to get the face name from the selected font */
    font_dc_state_t *dc = font_dc_lookup(hdc);
    if (dc && dc->selected_font) {
        font_entry_t *fe = font_lookup(dc->selected_font);
        if (fe && fe->logfont.lfFaceName[0])
            face = fe->logfont.lfFaceName;
    }

    int face_len = (int)strlen(face);

    if (lpName && c > 0) {
        int copy = (face_len < c - 1) ? face_len : c - 1;
        memcpy(lpName, face, copy);
        lpName[copy] = '\0';
    }

    return face_len + 1;  /* Include null terminator in count */
}

WINAPI_EXPORT int GetTextFaceW(HDC hdc, int c, LPWSTR lpName)
{
    /* Get the narrow face name first */
    char narrow[LF_FACESIZE] = {0};
    GetTextFaceA(hdc, LF_FACESIZE, narrow);

    int len = (int)strlen(narrow);

    if (lpName && c > 0) {
        int copy = (len < c - 1) ? len : c - 1;
        for (int i = 0; i < copy; i++)
            lpName[i] = (WCHAR)(unsigned char)narrow[i];
        lpName[copy] = L'\0';
    }

    return len + 1;
}

/* ==========================================================================
 * GetCharWidthA / GetCharWidth32A - Fill array with character widths
 * ========================================================================== */

WINAPI_EXPORT BOOL GetCharWidthA(HDC hdc, UINT iFirst, UINT iLast,
                                  LPINT lpBuffer)
{
    if (!lpBuffer)
        return FALSE;

    if (iFirst > iLast) {
        set_last_error(87);  /* ERROR_INVALID_PARAMETER */
        return FALSE;
    }

    int avg_width = 8;
    font_dc_state_t *dc = font_dc_lookup(hdc);
    if (dc && dc->selected_font) {
        font_entry_t *fe = font_lookup(dc->selected_font);
        if (fe)
            avg_width = fe->avg_width;
    }

    for (UINT i = iFirst; i <= iLast; i++)
        lpBuffer[i - iFirst] = avg_width;

    return TRUE;
}

WINAPI_EXPORT BOOL GetCharWidth32A(HDC hdc, UINT iFirst, UINT iLast,
                                    LPINT lpBuffer)
{
    return GetCharWidthA(hdc, iFirst, iLast, lpBuffer);
}

/* ==========================================================================
 * GetTextCharacterExtra / SetTextCharacterExtra
 * ========================================================================== */

WINAPI_EXPORT int GetTextCharacterExtra(HDC hdc)
{
    font_dc_state_t *dc = font_dc_lookup(hdc);
    return dc ? dc->char_extra : 0;
}

WINAPI_EXPORT int SetTextCharacterExtra(HDC hdc, int nCharExtra)
{
    font_dc_state_t *dc = font_dc_get_or_create(hdc);
    if (!dc)
        return 0x80000000;  /* GDI error value */

    int old = dc->char_extra;
    dc->char_extra = nCharExtra;
    return old;
}
