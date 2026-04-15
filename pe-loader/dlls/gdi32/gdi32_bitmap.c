/*
 * gdi32_bitmap.c - Bitmap operation stubs
 *
 * Implements bitmap creation, BitBlt, StretchBlt, DIB operations.
 * Provides BITMAPINFO, BITMAPINFOHEADER structures.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/dll_common.h"
#include "../../graphics/gfx_backend.h"

/* --------------------------------------------------------------------------
 * Bitmap structures
 * -------------------------------------------------------------------------- */

typedef struct tagBITMAPFILEHEADER {
    WORD    bfType;
    DWORD   bfSize;
    WORD    bfReserved1;
    WORD    bfReserved2;
    DWORD   bfOffBits;
} __attribute__((packed)) BITMAPFILEHEADER, *LPBITMAPFILEHEADER;

typedef struct tagBITMAPINFOHEADER {
    DWORD   biSize;
    LONG    biWidth;
    LONG    biHeight;
    WORD    biPlanes;
    WORD    biBitCount;
    DWORD   biCompression;
    DWORD   biSizeImage;
    LONG    biXPelsPerMeter;
    LONG    biYPelsPerMeter;
    DWORD   biClrUsed;
    DWORD   biClrImportant;
} BITMAPINFOHEADER, *LPBITMAPINFOHEADER;

typedef struct tagRGBQUAD {
    BYTE    rgbBlue;
    BYTE    rgbGreen;
    BYTE    rgbRed;
    BYTE    rgbReserved;
} RGBQUAD;

typedef struct tagBITMAPINFO {
    BITMAPINFOHEADER    bmiHeader;
    RGBQUAD             bmiColors[1];
} BITMAPINFO, *LPBITMAPINFO;

/* Compression types */
#define BI_RGB          0
#define BI_RLE8         1
#define BI_RLE4         2
#define BI_BITFIELDS    3

/* DIB color table usage */
#define DIB_RGB_COLORS  0
#define DIB_PAL_COLORS  1

/* BitBlt raster operations */
#define SRCCOPY         0x00CC0020
#define SRCPAINT        0x00EE0086
#define SRCAND          0x008800C6
#define SRCINVERT       0x00660046
#define SRCERASE        0x00440328
#define NOTSRCCOPY      0x00330008
#define NOTSRCERASE     0x001100A6
#define MERGECOPY       0x00C000CA
#define MERGEPAINT      0x00BB0226
#define PATCOPY         0x00F00021
#define PATPAINT        0x00FB0A09
#define PATINVERT       0x005A0049
#define DSTINVERT       0x00550009
#define BLACKNESS       0x00000042
#define WHITENESS       0x00FF0062

/* GDI object types (wingdi.h OBJ_*) -- used by StretchBlt to look up DC bitmaps */
#ifndef OBJ_BITMAP
#define OBJ_BITMAP  7
#endif

/* --------------------------------------------------------------------------
 * Internal bitmap data
 * -------------------------------------------------------------------------- */

typedef struct {
    int         width;
    int         height;
    int         bpp;            /* Bits per pixel */
    int         stride;         /* Bytes per row */
    uint8_t    *data;           /* Pixel data */
    int         is_dib;         /* Created via CreateDIBSection */
    void       *dib_bits;       /* Pointer given to caller for DIB */
} bitmap_data_t;

/* --------------------------------------------------------------------------
 * External references
 * -------------------------------------------------------------------------- */

extern gfx_window_t *hwnd_to_gfx(HWND hwnd);
extern HGDIOBJ gdi32_dc_get_selected(HDC hdc, int obj_type);

/* We need gdi object allocation from gdi32_dc.c -- use simplified local approach */
/* Since these are in the same SO, we can share state, but to keep things simple
 * we use handle values in a known range for bitmaps. */

#define MAX_BITMAPS 256

static struct {
    HBITMAP         handle;
    bitmap_data_t   bmp;
    int             used;
} g_bitmaps[MAX_BITMAPS];
static int g_bitmaps_initialized = 0;
static uintptr_t g_next_bitmap_handle = 0xB0000000;

static void ensure_bitmaps_init(void)
{
    if (!g_bitmaps_initialized) {
        memset(g_bitmaps, 0, sizeof(g_bitmaps));
        g_bitmaps_initialized = 1;
    }
}

static int alloc_bitmap_slot(void)
{
    ensure_bitmaps_init();
    for (int i = 0; i < MAX_BITMAPS; i++) {
        if (!g_bitmaps[i].used) {
            g_bitmaps[i].used = 1;
            g_bitmaps[i].handle = (HBITMAP)(g_next_bitmap_handle++);
            return i;
        }
    }
    return -1;
}

static bitmap_data_t *lookup_bitmap(HBITMAP hbm)
{
    ensure_bitmaps_init();
    for (int i = 0; i < MAX_BITMAPS; i++) {
        if (g_bitmaps[i].used && g_bitmaps[i].handle == hbm)
            return &g_bitmaps[i].bmp;
    }
    return NULL;
}

static void free_bitmap(HBITMAP hbm)
{
    ensure_bitmaps_init();
    for (int i = 0; i < MAX_BITMAPS; i++) {
        if (g_bitmaps[i].used && g_bitmaps[i].handle == hbm) {
            /* Free the pixel data buffer.  For DIB sections, data ==
             * dib_bits (both point to the same calloc'd block), so a
             * single free() is correct.  The caller must not reference
             * the dib_bits pointer after DeleteObject/DeleteBitmap. */
            if (g_bitmaps[i].bmp.data) {
                free(g_bitmaps[i].bmp.data);
            }
            memset(&g_bitmaps[i], 0, sizeof(g_bitmaps[i]));
            return;
        }
    }
}

/* --------------------------------------------------------------------------
 * Calculate stride (rows aligned to 4 bytes)
 * -------------------------------------------------------------------------- */

static int calc_stride(int width, int bpp)
{
    return ((width * bpp + 31) / 32) * 4;
}

/* --------------------------------------------------------------------------
 * CreateBitmap
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HBITMAP CreateBitmap(int nWidth, int nHeight, UINT nPlanes,
                                   UINT nBitCount, const void *lpBits)
{
    (void)nPlanes;  /* Always treat as 1 */

    if (nWidth <= 0 || nHeight <= 0)
        return NULL;

    int slot = alloc_bitmap_slot();
    if (slot < 0)
        return NULL;

    bitmap_data_t *bmp = &g_bitmaps[slot].bmp;
    bmp->width = nWidth;
    bmp->height = nHeight;
    bmp->bpp = nBitCount ? nBitCount : 32;
    bmp->stride = calc_stride(nWidth, bmp->bpp);

    size_t size = (size_t)bmp->stride * nHeight;
    bmp->data = calloc(1, size);
    if (!bmp->data) {
        g_bitmaps[slot].used = 0;
        return NULL;
    }

    if (lpBits) {
        memcpy(bmp->data, lpBits, size);
    }

    return g_bitmaps[slot].handle;
}

/* --------------------------------------------------------------------------
 * CreateCompatibleBitmap
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HBITMAP CreateCompatibleBitmap(HDC hdc, int cx, int cy)
{
    (void)hdc;

    if (cx <= 0 || cy <= 0)
        return NULL;

    return CreateBitmap(cx, cy, 1, 32, NULL);
}

/* --------------------------------------------------------------------------
 * CreateDIBSection
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HBITMAP CreateDIBSection(HDC hdc, const BITMAPINFO *pbmi,
                                       UINT usage, void **ppvBits,
                                       HANDLE hSection, DWORD offset)
{
    (void)hdc;
    (void)usage;
    (void)hSection;
    (void)offset;

    if (!pbmi)
        return NULL;

    int width = pbmi->bmiHeader.biWidth;
    int height = pbmi->bmiHeader.biHeight;
    int bpp = pbmi->bmiHeader.biBitCount;

    if (width <= 0)
        return NULL;
    if (height < 0)
        height = -height;  /* Top-down bitmap */
    if (height == 0)
        return NULL;

    int slot = alloc_bitmap_slot();
    if (slot < 0)
        return NULL;

    bitmap_data_t *bmp = &g_bitmaps[slot].bmp;
    bmp->width = width;
    bmp->height = height;
    bmp->bpp = bpp ? bpp : 32;
    bmp->stride = calc_stride(width, bmp->bpp);
    bmp->is_dib = 1;

    size_t size = (size_t)bmp->stride * height;
    bmp->data = calloc(1, size);
    if (!bmp->data) {
        g_bitmaps[slot].used = 0;
        return NULL;
    }

    bmp->dib_bits = bmp->data;

    if (ppvBits)
        *ppvBits = bmp->dib_bits;

    return g_bitmaps[slot].handle;
}

/* --------------------------------------------------------------------------
 * DeleteBitmap (via DeleteObject)
 * -------------------------------------------------------------------------- */

/* DeleteObject in gdi32_dc.c handles GDI_OBJ_BITMAP.
 * We also provide a direct bitmap cleanup: */
WINAPI_EXPORT BOOL DeleteBitmap(HBITMAP hbm)
{
    free_bitmap(hbm);
    return TRUE;
}

/* --------------------------------------------------------------------------
 * GetObject (dispatches by handle range; owner of the WINAPI export)
 *
 * Session 23 bug: old GetObjectA only knew about bitmaps; pen/brush/font
 * handles returned 0 -- callers that used GetObject to inspect selected
 * objects failed silently.
 *
 * Handle ranges:
 *   0x80000000-0x800003FF : gdi_object_t pool (pens/brushes) -> gdi32_dc.c
 *   0xB0000000-0xBFFFFFFF : bitmap pool (here)
 *   0xF1000000-0xF1FFFFFF : font pool (gdi32_font.c)
 * -------------------------------------------------------------------------- */

typedef struct tagBITMAP {
    LONG    bmType;
    LONG    bmWidth;
    LONG    bmHeight;
    LONG    bmWidthBytes;
    WORD    bmPlanes;
    WORD    bmBitsPixel;
    LPVOID  bmBits;
} BITMAP, *PBITMAP, *LPBITMAP;

/* Dispatchers in other TUs (same .so) */
extern __attribute__((ms_abi)) int gdi32_dc_get_object_info(HGDIOBJ h, int cb, void *pv);
extern __attribute__((ms_abi)) int GetObjectA_Font(HANDLE h, int cb, LPVOID pv);

static int bitmap_get_object_info(HBITMAP hbm, int c, LPVOID pv)
{
    bitmap_data_t *bmp = lookup_bitmap(hbm);
    if (!bmp)
        return 0;

    /* Query-size mode: pv==NULL -> return required size */
    if (!pv)
        return (int)sizeof(BITMAP);
    if (c < (int)sizeof(BITMAP))
        return 0;

    BITMAP *pbm = (BITMAP *)pv;
    memset(pbm, 0, sizeof(BITMAP));
    pbm->bmType = 0;
    pbm->bmWidth = bmp->width;
    pbm->bmHeight = bmp->height;
    pbm->bmWidthBytes = bmp->stride;
    pbm->bmPlanes = 1;
    pbm->bmBitsPixel = bmp->bpp;
    pbm->bmBits = bmp->data;
    return (int)sizeof(BITMAP);
}

WINAPI_EXPORT int GetObjectA(HANDLE h, int c, LPVOID pv)
{
    if (!h)
        return 0;

    uintptr_t hv = (uintptr_t)h;

    /* Bitmap range */
    if (hv >= 0xB0000000UL && hv < 0xC0000000UL) {
        return bitmap_get_object_info((HBITMAP)h, c, pv);
    }

    /* Font range -- delegate to gdi32_font.c */
    if (hv >= 0xF1000000UL && hv < 0xF2000000UL) {
        return GetObjectA_Font(h, c, pv);
    }

    /* gdi_object_t pool (pens/brushes) -- delegate to gdi32_dc.c */
    if (hv >= 0x80000000UL && hv < 0x80000400UL) {
        return gdi32_dc_get_object_info((HGDIOBJ)h, c, pv);
    }

    return 0;
}

WINAPI_EXPORT int GetObjectW(HANDLE h, int c, LPVOID pv)
{
    return GetObjectA(h, c, pv);
}

/* --------------------------------------------------------------------------
 * gdi32_bitmap_select_on_dc
 *
 * Called by gdi32_dc.c:SelectObject when the handle is in the bitmap range.
 * Validates the handle is a known bitmap, then asks gdi32_dc.c to swap the
 * DC's selected_bitmap slot and return the old handle.
 *
 * Returns the previously-selected bitmap handle (NULL on first select).
 * -------------------------------------------------------------------------- */

extern __attribute__((ms_abi)) HGDIOBJ gdi32_dc_set_selected(HDC hdc, int obj_type, HGDIOBJ new_h);

#ifndef OBJ_BITMAP
#define OBJ_BITMAP 7
#endif

__attribute__((ms_abi)) HBITMAP gdi32_bitmap_select_on_dc(HDC hdc, HBITMAP new_hbm)
{
    if (!hdc || !new_hbm)
        return NULL;
    if (!lookup_bitmap(new_hbm))
        return NULL;  /* Unknown/freed bitmap handle */
    return (HBITMAP)gdi32_dc_set_selected(hdc, OBJ_BITMAP, (HGDIOBJ)new_hbm);
}

/* --------------------------------------------------------------------------
 * BitBlt
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL BitBlt(HDC hdc, int x, int y, int cx, int cy,
                          HDC hdcSrc, int x1, int y1, DWORD rop)
{
    gfx_backend_t *backend = gfx_get_backend();
    if (!backend)
        return FALSE;

    /*
     * For simple SRCCOPY with a valid backend, delegate to the
     * backend's blit operation. For other ROPs, provide basic
     * stub behavior.
     */

    switch (rop) {
    case BLACKNESS: {
        /* Fill destination with black */
        /* Need dc lookup -- simplified approach */
        return TRUE;
    }
    case WHITENESS: {
        /* Fill destination with white */
        return TRUE;
    }
    case SRCCOPY:
    default:
        /* Attempt backend blit */
        /* This is a simplified stub -- real implementation would
         * look up gfx_dc_t for both HDCs and call blit_bitmap */
        (void)hdc;
        (void)x; (void)y; (void)cx; (void)cy;
        (void)hdcSrc; (void)x1; (void)y1;
        return TRUE;
    }
}

/* --------------------------------------------------------------------------
 * StretchBlt
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL StretchBlt(HDC hdcDest, int xDest, int yDest,
                               int wDest, int hDest,
                               HDC hdcSrc, int xSrc, int ySrc,
                               int wSrc, int hSrc, DWORD rop)
{
    (void)rop;  /* Only SRCCOPY behaviour for now */

    /* Validate dimensions */
    if (wDest == 0 || hDest == 0 || wSrc == 0 || hSrc == 0)
        return TRUE;

    /* Look up source and destination bitmaps via gdi32_dc_get_selected.
     * dc_lookup is static to gdi32_dc.c, but we can reach the selected
     * bitmap handle through the OBJ_BITMAP accessor and then resolve
     * the bitmap_data_t locally. */
    HBITMAP src_hbm = (HBITMAP)gdi32_dc_get_selected(hdcSrc, OBJ_BITMAP);
    HBITMAP dst_hbm = (HBITMAP)gdi32_dc_get_selected(hdcDest, OBJ_BITMAP);
    if (!src_hbm || !dst_hbm)
        return TRUE;  /* No bitmap selected -- succeed silently like Windows */

    bitmap_data_t *src_bmp = lookup_bitmap(src_hbm);
    bitmap_data_t *dst_bmp = lookup_bitmap(dst_hbm);
    if (!src_bmp || !dst_bmp || !src_bmp->data || !dst_bmp->data)
        return TRUE;

    int bpp = src_bmp->bpp / 8;  /* bytes per pixel */
    if (bpp <= 0 || bpp != dst_bmp->bpp / 8)
        return TRUE;  /* Mismatched or unsupported pixel format */

    int src_stride = src_bmp->stride;
    int dst_stride = dst_bmp->stride;

    /* Handle negative dimensions (mirroring) by adjusting origin and using
     * absolute values for the loop counts. */
    int abs_wDest = wDest < 0 ? -wDest : wDest;
    int abs_hDest = hDest < 0 ? -hDest : hDest;
    int abs_wSrc  = wSrc  < 0 ? -wSrc  : wSrc;
    int abs_hSrc  = hSrc  < 0 ? -hSrc  : hSrc;

    /* Nearest-neighbor stretch blit */
    for (int dy = 0; dy < abs_hDest; dy++) {
        int dest_y = yDest + (hDest < 0 ? (abs_hDest - 1 - dy) : dy);
        if (dest_y < 0 || dest_y >= dst_bmp->height)
            continue;

        int sy = ySrc + (dy * abs_hSrc) / abs_hDest;
        if (hSrc < 0) sy = ySrc + abs_hSrc - 1 - (dy * abs_hSrc) / abs_hDest;
        if (sy < 0 || sy >= src_bmp->height)
            continue;

        uint8_t *dst_row = dst_bmp->data + dest_y * dst_stride;
        uint8_t *src_row = src_bmp->data + sy * src_stride;

        for (int dx = 0; dx < abs_wDest; dx++) {
            int dest_x = xDest + (wDest < 0 ? (abs_wDest - 1 - dx) : dx);
            if (dest_x < 0 || dest_x >= dst_bmp->width)
                continue;

            int sx = xSrc + (dx * abs_wSrc) / abs_wDest;
            if (wSrc < 0) sx = xSrc + abs_wSrc - 1 - (dx * abs_wSrc) / abs_wDest;
            if (sx < 0 || sx >= src_bmp->width)
                continue;

            memcpy(dst_row + dest_x * bpp, src_row + sx * bpp, bpp);
        }
    }
    return TRUE;
}

/* --------------------------------------------------------------------------
 * StretchDIBits
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT int StretchDIBits(HDC hdc, int xDest, int yDest,
                                 int DestWidth, int DestHeight,
                                 int xSrc, int ySrc,
                                 int SrcWidth, int SrcHeight,
                                 const void *lpBits,
                                 const BITMAPINFO *lpbmi,
                                 UINT iUsage, DWORD rop)
{
    (void)hdc; (void)xDest; (void)yDest;
    (void)DestWidth; (void)DestHeight;
    (void)xSrc; (void)ySrc;
    (void)SrcWidth; (void)SrcHeight;
    (void)lpBits; (void)lpbmi;
    (void)iUsage; (void)rop;

    /* Stub */
    return SrcHeight;
}

/* --------------------------------------------------------------------------
 * SetDIBits / GetDIBits
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT int SetDIBits(HDC hdc, HBITMAP hbm, UINT start, UINT cLines,
                            const void *lpBits, const BITMAPINFO *lpbmi, UINT ColorUse)
{
    (void)hdc;
    (void)ColorUse;

    if (!lpBits || !lpbmi)
        return 0;

    bitmap_data_t *bmp = lookup_bitmap(hbm);
    if (!bmp || !bmp->data)
        return 0;

    int src_stride = calc_stride(lpbmi->bmiHeader.biWidth, lpbmi->bmiHeader.biBitCount);
    int lines_to_copy = cLines;
    if ((int)(start + cLines) > bmp->height)
        lines_to_copy = bmp->height - start;
    if (lines_to_copy <= 0)
        return 0;

    /* Copy scan lines */
    int copy_stride = (src_stride < bmp->stride) ? src_stride : bmp->stride;
    for (int i = 0; i < lines_to_copy; i++) {
        memcpy(bmp->data + (start + i) * bmp->stride,
               (const uint8_t *)lpBits + i * src_stride,
               copy_stride);
    }

    return lines_to_copy;
}

WINAPI_EXPORT int GetDIBits(HDC hdc, HBITMAP hbm, UINT start, UINT cLines,
                            void *lpBits, BITMAPINFO *lpbmi, UINT usage)
{
    (void)hdc;
    (void)usage;

    bitmap_data_t *bmp = lookup_bitmap(hbm);
    if (!bmp)
        return 0;

    /* Fill in the BITMAPINFOHEADER if lpBits is NULL (query mode) */
    if (!lpBits && lpbmi) {
        lpbmi->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        lpbmi->bmiHeader.biWidth = bmp->width;
        lpbmi->bmiHeader.biHeight = bmp->height;
        lpbmi->bmiHeader.biPlanes = 1;
        lpbmi->bmiHeader.biBitCount = bmp->bpp;
        lpbmi->bmiHeader.biCompression = BI_RGB;
        lpbmi->bmiHeader.biSizeImage = bmp->stride * bmp->height;
        return bmp->height;
    }

    if (!lpBits || !bmp->data)
        return 0;

    int lines_to_copy = cLines;
    if ((int)(start + cLines) > bmp->height)
        lines_to_copy = bmp->height - start;
    if (lines_to_copy <= 0)
        return 0;

    for (int i = 0; i < lines_to_copy; i++) {
        memcpy((uint8_t *)lpBits + i * bmp->stride,
               bmp->data + (start + i) * bmp->stride,
               bmp->stride);
    }

    return lines_to_copy;
}

/* --------------------------------------------------------------------------
 * SetDIBitsToDevice
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT int SetDIBitsToDevice(HDC hdc, int xDest, int yDest,
                                     DWORD w, DWORD h,
                                     int xSrc, int ySrc,
                                     UINT StartScan, UINT cLines,
                                     const void *lpBits,
                                     const BITMAPINFO *lpbmi,
                                     UINT ColorUse)
{
    (void)hdc; (void)xDest; (void)yDest;
    (void)w; (void)h;
    (void)xSrc; (void)ySrc;
    (void)StartScan;
    (void)lpBits; (void)lpbmi; (void)ColorUse;

    return (int)cLines;
}

/* --------------------------------------------------------------------------
 * PatBlt
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL PatBlt(HDC hdc, int x, int y, int w, int h, DWORD rop)
{
    (void)hdc;

    switch (rop) {
    case BLACKNESS:
    case WHITENESS:
    case PATCOPY:
    case PATINVERT:
    case DSTINVERT:
        /* Stub implementations -- just succeed */
        (void)x; (void)y; (void)w; (void)h;
        return TRUE;
    default:
        return TRUE;
    }
}

/* --------------------------------------------------------------------------
 * GetBitmapBits / SetBitmapBits (legacy)
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT LONG GetBitmapBits(HBITMAP hbit, LONG cb, LPVOID lpvBits)
{
    bitmap_data_t *bmp = lookup_bitmap(hbit);
    if (!bmp || !bmp->data || !lpvBits)
        return 0;

    LONG total = (LONG)(bmp->stride * bmp->height);
    LONG to_copy = (cb < total) ? cb : total;
    memcpy(lpvBits, bmp->data, to_copy);
    return to_copy;
}

WINAPI_EXPORT LONG SetBitmapBits(HBITMAP hbm, DWORD cb, const void *pvBits)
{
    bitmap_data_t *bmp = lookup_bitmap(hbm);
    if (!bmp || !bmp->data || !pvBits)
        return 0;

    LONG total = (LONG)(bmp->stride * bmp->height);
    LONG to_copy = ((LONG)cb < total) ? (LONG)cb : total;
    memcpy(bmp->data, pvBits, to_copy);
    return to_copy;
}

/* --------------------------------------------------------------------------
 * SetStretchBltMode / GetStretchBltMode
 * -------------------------------------------------------------------------- */

#define BLACKONWHITE    1
#define WHITEONBLACK    2
#define COLORONCOLOR    3
#define HALFTONE        4
#define STRETCH_ANDSCANS    BLACKONWHITE
#define STRETCH_ORSCANS     WHITEONBLACK
#define STRETCH_DELETESCANS COLORONCOLOR
#define STRETCH_HALFTONE    HALFTONE

/* Per-DC stretch mode accessors in gdi32_dc.c */
extern int gdi32_dc_set_stretch_mode(HDC hdc, int mode);
extern int gdi32_dc_get_stretch_mode(HDC hdc);

WINAPI_EXPORT int SetStretchBltMode(HDC hdc, int mode)
{
    return gdi32_dc_set_stretch_mode(hdc, mode);
}

WINAPI_EXPORT int GetStretchBltMode(HDC hdc)
{
    return gdi32_dc_get_stretch_mode(hdc);
}

/* --------------------------------------------------------------------------
 * GdiFlush
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL GdiFlush(void)
{
    return TRUE;
}

/* ---- Palette functions ---- */

WINAPI_EXPORT HPALETTE CreatePalette(const void *lplgpl)
{
    (void)lplgpl;
    return (HPALETTE)(uintptr_t)0xCC0001;
}

WINAPI_EXPORT HPALETTE SelectPalette(HDC hdc, HPALETTE hPal, BOOL bForceBackground)
{
    (void)hdc; (void)bForceBackground;
    return hPal;
}

WINAPI_EXPORT UINT RealizePalette(HDC hdc)
{
    (void)hdc;
    return 0;
}

WINAPI_EXPORT UINT SetPaletteEntries(HPALETTE hPal, UINT iStart, UINT cEntries, const void *pPalEntries)
{
    (void)hPal; (void)iStart; (void)pPalEntries;
    return cEntries;
}

WINAPI_EXPORT BOOL UnrealizeObject(HANDLE hObj)
{
    (void)hObj;
    return TRUE;
}

WINAPI_EXPORT BOOL UpdateColors(HDC hdc)
{
    (void)hdc;
    return TRUE;
}

WINAPI_EXPORT BOOL TranslateCharsetInfo(DWORD *lpSrc, void *lpCs, DWORD dwFlags)
{
    (void)lpSrc; (void)lpCs; (void)dwFlags;
    return FALSE;
}

/* GetCurrentObject: forward to gdi32_dc.c's DC table via extern */
/* OBJ_* constants from wingdi.h */
#define OBJ_PEN     1
#define OBJ_BRUSH   2
#define OBJ_DC      3
#define OBJ_FONT    6
#define OBJ_BITMAP  7

/* These are defined in gdi32_dc.c and shared within the same .so */
extern HGDIOBJ gdi32_dc_get_selected(HDC hdc, int obj_type);

WINAPI_EXPORT HANDLE GetCurrentObject(HDC hdc, UINT type)
{
    if (!hdc) return NULL;
    /* Map OBJ_* to our internal type code expected by gdi32_dc_get_selected */
    return (HANDLE)gdi32_dc_get_selected(hdc, (int)type);
}

/* Forward to CreateSolidBrush in gdi32_dc.c for proper handle tracking */
extern __attribute__((ms_abi)) HBRUSH CreateSolidBrush(DWORD color);

WINAPI_EXPORT HBRUSH CreateBrushIndirect(const void *lplb)
{
    /* LOGBRUSH: { UINT lbStyle; COLORREF lbColor; ULONG_PTR lbHatch; } */
    if (!lplb)
        return NULL;
    const DWORD *lb = (const DWORD *)lplb;
    DWORD color = lb[1];  /* lbColor at offset 4 */
    return CreateSolidBrush(color);
}

/* ---- Character width functions ---- */

WINAPI_EXPORT BOOL GetCharABCWidthsFloatA(HDC hdc, UINT iFirst, UINT iLast, void *lpABCF)
{
    (void)hdc;
    if (iFirst > iLast)
        return FALSE;
    if (lpABCF) {
        /* ABCFLOAT is 3 floats: abcfA, abcfB, abcfC */
        UINT count = iLast - iFirst + 1;
        float *f = (float *)lpABCF;
        for (UINT i = 0; i < count; i++) {
            f[i*3 + 0] = 0.0f;  /* A */
            f[i*3 + 1] = 8.0f;  /* B (char width) */
            f[i*3 + 2] = 0.0f;  /* C */
        }
    }
    return TRUE;
}

WINAPI_EXPORT BOOL GetCharWidth32W(HDC hdc, UINT iFirst, UINT iLast, int *lpBuffer)
{
    (void)hdc;
    if (iFirst > iLast)
        return FALSE;
    if (lpBuffer) {
        for (UINT i = iFirst; i <= iLast; i++)
            lpBuffer[i - iFirst] = 8;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL GetCharWidthW(HDC hdc, UINT iFirst, UINT iLast, int *lpBuffer)
{
    return GetCharWidth32W(hdc, iFirst, iLast, lpBuffer);
}

WINAPI_EXPORT DWORD GetCharacterPlacementW(HDC hdc, const uint16_t *lpString,
    int nCount, int nMexExtent, void *lpResults, DWORD dwFlags)
{
    (void)hdc; (void)lpString; (void)nCount;
    (void)nMexExtent; (void)lpResults; (void)dwFlags;
    return 0;
}

WINAPI_EXPORT UINT GetOutlineTextMetricsA(HDC hdc, UINT cbData, void *lpOTM)
{
    (void)hdc; (void)cbData; (void)lpOTM;
    return 0;
}

WINAPI_EXPORT BOOL GetTextExtentExPointA(HDC hdc, LPCSTR lpszString,
    int cchString, int nMaxExtent, int *lpnFit, int *lpnDx, void *lpSize)
{
    (void)hdc; (void)nMaxExtent; (void)lpnDx;
    /* SIZE is { LONG cx, LONG cy } */
    if (lpSize) {
        LONG *s = (LONG *)lpSize;
        s[0] = cchString * 8;  /* cx */
        s[1] = 16;             /* cy */
    }
    if (lpnFit) *lpnFit = cchString;
    (void)lpszString;
    return TRUE;
}
