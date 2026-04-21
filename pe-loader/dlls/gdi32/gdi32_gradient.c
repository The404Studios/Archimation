/*
 * gdi32_gradient.c - GdiGradientFill / GradientFill implementation.
 *
 * msimg32.dll's GradientFill is mapped to libpe_gdi32.so by pe_import.c
 * (see the alias entry at the top of pe-loader/loader/pe_import.c), so we
 * have to export both names from the same .so.  Real Windows ships the
 * implementation in msimg32 and forwards GdiGradientFill in gdi32 — we
 * collapse both into one body to keep DLLs lean.
 *
 * Supported:
 *   GRADIENT_FILL_RECT_H -- horizontal interpolation between left/right
 *                           edge of each rect (UpperLeft/LowerRight).
 *   GRADIENT_FILL_RECT_V -- vertical interpolation top->bottom.
 *   GRADIENT_FILL_TRIANGLE -- barycentric per-pixel interpolation across
 *                             the three vertices of each GRADIENT_TRIANGLE.
 *
 * Implementation notes:
 *   - SetPixel is the most portable primitive in our gdi32; for backends
 *     that have a fast paint_rect we fall through to a per-scanline
 *     1xH or Wx1 fill which is meaningfully faster.
 *   - TRIVERTEX color components are USHORTs in the high 8 bits of each
 *     channel (Win32 quirk, kept for ABI parity).  We shift right by 8 to
 *     get an 8-bit value.
 *   - Alpha is currently ignored: the only places we draw with Alpha != 0
 *     would need a real compositor.  Apps rarely care.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "common/dll_common.h"

typedef DWORD COLORREF;
#define RGB(r,g,b) ((COLORREF)(((BYTE)(r)) | ((WORD)((BYTE)(g)) << 8) | ((DWORD)((BYTE)(b)) << 16)))

typedef struct tagTRIVERTEX {
    LONG    x;
    LONG    y;
    USHORT  Red;
    USHORT  Green;
    USHORT  Blue;
    USHORT  Alpha;
} TRIVERTEX, *PTRIVERTEX;

typedef struct _GRADIENT_RECT {
    ULONG UpperLeft;
    ULONG LowerRight;
} GRADIENT_RECT, *PGRADIENT_RECT;

typedef struct _GRADIENT_TRIANGLE {
    ULONG Vertex1;
    ULONG Vertex2;
    ULONG Vertex3;
} GRADIENT_TRIANGLE, *PGRADIENT_TRIANGLE;

#define GRADIENT_FILL_RECT_H    0x00000000
#define GRADIENT_FILL_RECT_V    0x00000001
#define GRADIENT_FILL_TRIANGLE  0x00000002
#define GRADIENT_FILL_OP_FLAG   0x000000FF

/* The two gdi32_dc.c primitives we need.  Forward-declare with the same
 * ms_abi attribute the rest of the DLL uses so the compiler emits the
 * right call sequence. */
extern WINAPI_EXPORT COLORREF SetPixel(HDC hdc, int x, int y, COLORREF color);
extern WINAPI_EXPORT int      FillRect(HDC hdc, const void *lprc, HBRUSH hbr);
extern WINAPI_EXPORT HBRUSH   CreateSolidBrush(COLORREF c);
extern WINAPI_EXPORT BOOL     DeleteObject(HGDIOBJ obj);

/* Linear interpolation helper.  c0/c1 are full TRIVERTEX channel values
 * (high-8-bit-only semantics), ratio is num/denom in [0..denom]. */
static inline BYTE lerp8(USHORT c0, USHORT c1, int num, int denom)
{
    if (denom <= 0) return (BYTE)(c0 >> 8);
    int v0 = (int)(c0 >> 8);
    int v1 = (int)(c1 >> 8);
    int v  = v0 + ((v1 - v0) * num) / denom;
    if (v < 0) v = 0;
    if (v > 255) v = 255;
    return (BYTE)v;
}

/* Fill a single horizontal scanline at row y0 from x0..x1 with `color`.
 * Uses a 1-pixel-tall FillRect when available; falls back to per-pixel
 * SetPixel.  FillRect is reused so that backends with hardware accel
 * dispatch a real blit. */
static void fill_hline(HDC hdc, int x0, int x1, int y, COLORREF color)
{
    if (x1 <= x0) return;
    HBRUSH br = CreateSolidBrush(color);
    if (br) {
        RECT r = {x0, y, x1, y + 1};
        FillRect(hdc, &r, br);
        DeleteObject((HGDIOBJ)br);
    } else {
        for (int x = x0; x < x1; x++) SetPixel(hdc, x, y, color);
    }
}

static void fill_vline(HDC hdc, int x, int y0, int y1, COLORREF color)
{
    if (y1 <= y0) return;
    HBRUSH br = CreateSolidBrush(color);
    if (br) {
        RECT r = {x, y0, x + 1, y1};
        FillRect(hdc, &r, br);
        DeleteObject((HGDIOBJ)br);
    } else {
        for (int y = y0; y < y1; y++) SetPixel(hdc, x, y, color);
    }
}

/* Rasterize a single GRADIENT_RECT in horizontal-interpolation mode. */
static BOOL grad_rect_h(HDC hdc, const TRIVERTEX *v0, const TRIVERTEX *v1)
{
    int x0 = (int)v0->x, x1 = (int)v1->x;
    int y0 = (int)v0->y, y1 = (int)v1->y;
    if (x1 < x0) { int t = x0; x0 = x1; x1 = t; }
    if (y1 < y0) { int t = y0; y0 = y1; y1 = t; }
    int w = x1 - x0;
    if (w <= 0 || y1 - y0 <= 0) return TRUE;
    /* For each column compute its color, then fill that column with a
     * single vertical 1px-wide rectangle.  This is O(w) brushes which is
     * fine for the small surfaces our common-controls draw. */
    for (int x = 0; x < w; x++) {
        BYTE r = lerp8(v0->Red,   v1->Red,   x, w);
        BYTE g = lerp8(v0->Green, v1->Green, x, w);
        BYTE b = lerp8(v0->Blue,  v1->Blue,  x, w);
        fill_vline(hdc, x0 + x, y0, y1, RGB(r, g, b));
    }
    return TRUE;
}

static BOOL grad_rect_v(HDC hdc, const TRIVERTEX *v0, const TRIVERTEX *v1)
{
    int x0 = (int)v0->x, x1 = (int)v1->x;
    int y0 = (int)v0->y, y1 = (int)v1->y;
    if (x1 < x0) { int t = x0; x0 = x1; x1 = t; }
    if (y1 < y0) { int t = y0; y0 = y1; y1 = t; }
    int h = y1 - y0;
    if (h <= 0 || x1 - x0 <= 0) return TRUE;
    for (int y = 0; y < h; y++) {
        BYTE r = lerp8(v0->Red,   v1->Red,   y, h);
        BYTE g = lerp8(v0->Green, v1->Green, y, h);
        BYTE b = lerp8(v0->Blue,  v1->Blue,  y, h);
        fill_hline(hdc, x0, x1, y0 + y, RGB(r, g, b));
    }
    return TRUE;
}

/* Triangle barycentric rasterizer.  Walks a bounding box and tests each
 * pixel via signed edge functions; same approach Pineda introduced and
 * every modern triangle rasterizer descends from.  Slower than the rect
 * paths but correct for any triangle orientation. */
static int edge(int ax, int ay, int bx, int by, int cx, int cy)
{
    return (cx - ax) * (by - ay) - (cy - ay) * (bx - ax);
}

static BOOL grad_triangle(HDC hdc, const TRIVERTEX *a, const TRIVERTEX *b,
                          const TRIVERTEX *c)
{
    int xmin = a->x; if (b->x < xmin) xmin = b->x; if (c->x < xmin) xmin = c->x;
    int xmax = a->x; if (b->x > xmax) xmax = b->x; if (c->x > xmax) xmax = c->x;
    int ymin = a->y; if (b->y < ymin) ymin = b->y; if (c->y < ymin) ymin = c->y;
    int ymax = a->y; if (b->y > ymax) ymax = b->y; if (c->y > ymax) ymax = c->y;
    if (xmax <= xmin || ymax <= ymin) return TRUE;
    /* Win32 triangle coords are LONG (32-bit signed). Edge values can reach
     * 2^31 for large triangles so we compute in int64_t to avoid UB on
     * signed overflow during the cross-product / channel accumulation. */
    int64_t total = (int64_t)edge(a->x, a->y, b->x, b->y, c->x, c->y);
    if (total == 0) return TRUE; /* degenerate */
    int64_t sign = total > 0 ? 1 : -1;

    for (int py = ymin; py < ymax; py++) {
        for (int px = xmin; px < xmax; px++) {
            int64_t w0 = (int64_t)edge(b->x, b->y, c->x, c->y, px, py) * sign;
            int64_t w1 = (int64_t)edge(c->x, c->y, a->x, a->y, px, py) * sign;
            int64_t w2 = (int64_t)edge(a->x, a->y, b->x, b->y, px, py) * sign;
            if (w0 < 0 || w1 < 0 || w2 < 0) continue;
            int64_t abs_total = total * sign;
            int64_t r = (((int64_t)(a->Red   >> 8)) * w0 +
                        ((int64_t)(b->Red   >> 8)) * w1 +
                        ((int64_t)(c->Red   >> 8)) * w2) / abs_total;
            int64_t g = (((int64_t)(a->Green >> 8)) * w0 +
                        ((int64_t)(b->Green >> 8)) * w1 +
                        ((int64_t)(c->Green >> 8)) * w2) / abs_total;
            int64_t bl= (((int64_t)(a->Blue  >> 8)) * w0 +
                        ((int64_t)(b->Blue  >> 8)) * w1 +
                        ((int64_t)(c->Blue  >> 8)) * w2) / abs_total;
            if (r < 0)  r = 0;
            if (r > 255) r = 255;
            if (g < 0)  g = 0;
            if (g > 255) g = 255;
            if (bl < 0) bl = 0;
            if (bl > 255) bl = 255;
            SetPixel(hdc, px, py, RGB((BYTE)r, (BYTE)g, (BYTE)bl));
        }
    }
    return TRUE;
}

WINAPI_EXPORT BOOL GdiGradientFill(HDC hdc, PTRIVERTEX pVertex, ULONG nVertex,
                                   PVOID pMesh, ULONG nMesh, ULONG ulMode)
{
    if (!hdc || !pVertex || !pMesh || nVertex == 0 || nMesh == 0) return FALSE;
    ULONG mode = ulMode & GRADIENT_FILL_OP_FLAG;
    if (mode == GRADIENT_FILL_RECT_H || mode == GRADIENT_FILL_RECT_V) {
        const GRADIENT_RECT *rects = (const GRADIENT_RECT *)pMesh;
        for (ULONG m = 0; m < nMesh; m++) {
            ULONG i0 = rects[m].UpperLeft;
            ULONG i1 = rects[m].LowerRight;
            if (i0 >= nVertex || i1 >= nVertex) continue;
            const TRIVERTEX *v0 = &pVertex[i0];
            const TRIVERTEX *v1 = &pVertex[i1];
            if (mode == GRADIENT_FILL_RECT_H) grad_rect_h(hdc, v0, v1);
            else                              grad_rect_v(hdc, v0, v1);
        }
        return TRUE;
    } else if (mode == GRADIENT_FILL_TRIANGLE) {
        const GRADIENT_TRIANGLE *tris = (const GRADIENT_TRIANGLE *)pMesh;
        for (ULONG m = 0; m < nMesh; m++) {
            ULONG i0 = tris[m].Vertex1;
            ULONG i1 = tris[m].Vertex2;
            ULONG i2 = tris[m].Vertex3;
            if (i0 >= nVertex || i1 >= nVertex || i2 >= nVertex) continue;
            grad_triangle(hdc, &pVertex[i0], &pVertex[i1], &pVertex[i2]);
        }
        return TRUE;
    }
    return FALSE;
}

/* msimg32.dll exports this name; gdi32 forwards to GdiGradientFill on real
 * Windows.  Keep both bodies callable so dlsym from either side works. */
WINAPI_EXPORT BOOL GradientFill(HDC hdc, PTRIVERTEX pVertex, ULONG nVertex,
                                PVOID pMesh, ULONG nMesh, ULONG ulMode)
{
    return GdiGradientFill(hdc, pVertex, nVertex, pMesh, nMesh, ulMode);
}

/* AlphaBlend / TransparentBlt are also msimg32 exports.  Ship trivial
 * stubs so apps that import them at all from the alias don't fail to
 * resolve.  Real implementations would need a software compositor. */
WINAPI_EXPORT BOOL AlphaBlend(HDC hdcDst, int xDst, int yDst, int wDst, int hDst,
                              HDC hdcSrc, int xSrc, int ySrc, int wSrc, int hSrc,
                              DWORD blend)
{
    (void)hdcDst; (void)xDst; (void)yDst; (void)wDst; (void)hDst;
    (void)hdcSrc; (void)xSrc; (void)ySrc; (void)wSrc; (void)hSrc; (void)blend;
    return TRUE;
}

WINAPI_EXPORT BOOL TransparentBlt(HDC hdcDst, int xDst, int yDst, int wDst, int hDst,
                                  HDC hdcSrc, int xSrc, int ySrc, int wSrc, int hSrc,
                                  UINT crTransparent)
{
    (void)hdcDst; (void)xDst; (void)yDst; (void)wDst; (void)hDst;
    (void)hdcSrc; (void)xSrc; (void)ySrc; (void)wSrc; (void)hSrc; (void)crTransparent;
    return TRUE;
}
