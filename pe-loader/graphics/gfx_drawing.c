/*
 * gfx_drawing.c - GDI drawing primitives (supplemental)
 *
 * Most GDI/User32 functions are in their proper DLL stubs:
 *   - gdi32_dc.c      (DC, pen, brush, stock objects, map modes, drawing, BitBlt, clip)
 *   - gdi32_bitmap.c   (GetObject, DIB, compatible bitmap, regions)
 *   - gdi32_text.c     (font creation, text output, text metrics, EnumFontFamiliesExA)
 *   - user32_window.c  (FillRect)
 *
 * This file retains only functions NOT provided by those DLL stubs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/dll_common.h"

/* GDI object types */
#define OBJ_PEN         1
#define OBJ_BRUSH       2
#define OBJ_FONT        6
#define OBJ_BITMAP      7
#define OBJ_REGION      8

WINAPI_EXPORT int GetObjectType(HANDLE h)
{
    (void)h;
    /* Without our own GDI object table, return a reasonable default */
    return h ? OBJ_PEN : 0;
}

WINAPI_EXPORT BOOL Polyline(HANDLE hdc, const void *apt, int cpt)
{
    (void)hdc; (void)apt; (void)cpt;
    return TRUE;
}

WINAPI_EXPORT BOOL Polygon(HANDLE hdc, const void *apt, int cpt)
{
    (void)hdc; (void)apt; (void)cpt;
    return TRUE;
}

WINAPI_EXPORT BOOL Arc(HANDLE hdc, int x1, int y1, int x2, int y2,
                        int x3, int y3, int x4, int y4)
{
    (void)hdc; (void)x1; (void)y1; (void)x2; (void)y2;
    (void)x3; (void)y3; (void)x4; (void)y4;
    return TRUE;
}

/* ---------- Region helpers ---------- */

WINAPI_EXPORT int CombineRgn(HANDLE hrgnDst, HANDLE hrgnSrc1, HANDLE hrgnSrc2, int iMode)
{
    (void)hrgnDst; (void)hrgnSrc1; (void)hrgnSrc2; (void)iMode;
    return 1; /* SIMPLEREGION */
}

WINAPI_EXPORT BOOL PtInRegion(HANDLE hrgn, int x, int y)
{
    (void)hrgn; (void)x; (void)y;
    return TRUE;
}

WINAPI_EXPORT int GetRgnBox(HANDLE hrgn, void *lprc)
{
    (void)hrgn;
    if (lprc) memset(lprc, 0, sizeof(int) * 4);
    return 1;
}

/* EnumFontFamiliesExW moved to gdi32_font.c (canonical font API location) */
