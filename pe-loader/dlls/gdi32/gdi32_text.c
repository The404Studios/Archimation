/*
 * gdi32_text.c - Text rendering and text-specific APIs
 *
 * Implements text output and measurement APIs that are NOT handled by
 * gdi32_font.c: DrawTextA/W, SetTextAlign, GetTextAlign,
 * GetTextExtentPointA, GetCharABCWidthsA, GetGlyphOutlineA,
 * GetFontData, AddFontResourceExA, RemoveFontResourceExA.
 *
 * Font creation, font metrics, TextOut/ExtTextOut, character widths,
 * and other font-management APIs live in gdi32_font.c to avoid
 * duplicate symbol definitions (all files link into libpe_gdi32.so).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "common/dll_common.h"
#include "../../graphics/gfx_backend.h"

/* --------------------------------------------------------------------------
 * Text alignment constants
 * -------------------------------------------------------------------------- */

#define TA_LEFT         0x0000
#define TA_RIGHT        0x0002
#define TA_CENTER       0x0006
#define TA_TOP          0x0000
#define TA_BOTTOM       0x0008
#define TA_BASELINE     0x0018
#define TA_NOUPDATECP   0x0000
#define TA_UPDATECP     0x0001

/* --------------------------------------------------------------------------
 * DrawText format flags
 * -------------------------------------------------------------------------- */

#define DT_LEFT         0x00000000
#define DT_CENTER       0x00000001
#define DT_RIGHT        0x00000002
#define DT_TOP          0x00000000
#define DT_VCENTER      0x00000004
#define DT_BOTTOM       0x00000008
#define DT_WORDBREAK    0x00000010
#define DT_SINGLELINE   0x00000020
#define DT_EXPANDTABS   0x00000040
#define DT_NOCLIP       0x00000100
#define DT_CALCRECT     0x00000400
#define DT_NOPREFIX     0x00000800
#define DT_END_ELLIPSIS 0x00008000

/* --------------------------------------------------------------------------
 * DC text-alignment state (simplified)
 *
 * SetTextAlign / GetTextAlign are DC-level properties.  gdi32_font.c
 * already manages per-DC font state; here we track just alignment.
 * -------------------------------------------------------------------------- */

/* Per-DC text alignment accessors in gdi32_dc.c */
extern UINT gdi32_dc_set_text_align(HDC hdc, UINT align);
extern UINT gdi32_dc_get_text_align(HDC hdc);

/* --------------------------------------------------------------------------
 * External: TextOutA from gdi32_font.c (canonical implementation)
 * -------------------------------------------------------------------------- */

/* Must use ms_abi since these are WINAPI_EXPORT in gdi32_font.c */
extern __attribute__((ms_abi)) BOOL TextOutA(HDC hdc, int x, int y, LPCSTR lpString, int c);
extern __attribute__((ms_abi)) BOOL TextOutW(HDC hdc, int x, int y, LPCWSTR lpString, int c);

/* --------------------------------------------------------------------------
 * SetTextAlign / GetTextAlign
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT UINT SetTextAlign(HDC hdc, UINT align)
{
    return gdi32_dc_set_text_align(hdc, align);
}

WINAPI_EXPORT UINT GetTextAlign(HDC hdc)
{
    return gdi32_dc_get_text_align(hdc);
}

/* --------------------------------------------------------------------------
 * GetTextExtentPointA  (legacy wrapper around GetTextExtentPoint32A)
 * -------------------------------------------------------------------------- */

extern __attribute__((ms_abi)) BOOL GetTextExtentPoint32A(HDC hdc, LPCSTR lpString, int c, LPSIZE psizl);

WINAPI_EXPORT BOOL GetTextExtentPointA(HDC hdc, LPCSTR lpString, int c, LPSIZE psizl)
{
    return GetTextExtentPoint32A(hdc, lpString, c, psizl);
}

/* --------------------------------------------------------------------------
 * DrawTextA / DrawTextW
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT int DrawTextA(HDC hdc, LPCSTR lpchText, int cchText,
                             LPRECT lprc, UINT format)
{
    if (!lpchText || !lprc)
        return 0;

    if (cchText < 0)
        cchText = (int)strlen(lpchText);

    /* For DT_CALCRECT, just estimate the rectangle */
    if (format & DT_CALCRECT) {
        /* Rough estimate: 8 pixels per char width, 16 pixels height */
        lprc->right = lprc->left + cchText * 8;
        lprc->bottom = lprc->top + 16;
        return 16;
    }

    /* Draw the text at the rect position */
    int x = lprc->left;
    int y = lprc->top;

    if (format & DT_CENTER) {
        int text_width = cchText * 8;
        int rect_width = lprc->right - lprc->left;
        x = lprc->left + (rect_width - text_width) / 2;
    }
    if (format & DT_RIGHT) {
        int text_width = cchText * 8;
        x = lprc->right - text_width;
    }
    if (format & DT_VCENTER) {
        int rect_height = lprc->bottom - lprc->top;
        y = lprc->top + (rect_height - 16) / 2;
    }
    if (format & DT_BOTTOM) {
        y = lprc->bottom - 16;
    }

    TextOutA(hdc, x, y, lpchText, cchText);
    return 16;  /* Return height */
}

/* ----------------------------------------------------------------
 * DrawTextW - forwarded to canonical user32
 *
 * Some Windows executables import DrawTextW from gdi32.dll even though
 * the canonical implementation lives in user32.dll.  We forward at
 * runtime via dlsym.
 * ---------------------------------------------------------------- */

WINAPI_EXPORT int WINAPI DrawTextW(HDC hDC, LPCWSTR lpchText, int cchText,
                                    void *lprc, UINT format)
{
    typedef int (WINAPI *fn_t)(HDC, LPCWSTR, int, void*, UINT);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        void *h = dlopen("libpe_user32.so", RTLD_LAZY);
        if (h) real_fn = (fn_t)dlsym(h, "DrawTextW");
    }
    return real_fn ? real_fn(hDC, lpchText, cchText, lprc, format) : 0;
}

/* --------------------------------------------------------------------------
 * GetCharABCWidthsA
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL GetCharABCWidthsA(HDC hdc, UINT first, UINT last, void *lpABC)
{
    (void)hdc;

    if (first > last)
        return FALSE;

    if (!lpABC)
        return FALSE;

    /* ABC structure: {int A, UINT B, int C} */
    /* Fill with defaults: A=0, B=8, C=0 for each character */
    struct { int abcA; UINT abcB; int abcC; } *abc = lpABC;
    for (UINT i = first; i <= last; i++) {
        abc[i - first].abcA = 0;
        abc[i - first].abcB = 8;
        abc[i - first].abcC = 0;
    }

    return TRUE;
}

/* --------------------------------------------------------------------------
 * GetGlyphOutlineA
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT DWORD GetGlyphOutlineA(HDC hdc, UINT uChar, UINT fuFormat,
                                      void *lpgm, DWORD cjBuffer,
                                      LPVOID pvBuffer, const void *lpmat2)
{
    (void)hdc; (void)uChar; (void)fuFormat;
    (void)lpgm; (void)cjBuffer; (void)pvBuffer; (void)lpmat2;
    /* Return GDI_ERROR */
    return (DWORD)-1;
}

/* --------------------------------------------------------------------------
 * GetFontData
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT DWORD GetFontData(HDC hdc, DWORD dwTable, DWORD dwOffset,
                                 LPVOID pvBuffer, DWORD cjBuffer)
{
    (void)hdc; (void)dwTable; (void)dwOffset;
    (void)pvBuffer; (void)cjBuffer;
    return (DWORD)-1;  /* GDI_ERROR */
}

/* --------------------------------------------------------------------------
 * AddFontResourceExA / RemoveFontResourceExA
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT int AddFontResourceExA(LPCSTR name, DWORD fl, PVOID res)
{
    (void)name; (void)fl; (void)res;
    return 1;
}

WINAPI_EXPORT BOOL RemoveFontResourceExA(LPCSTR name, DWORD fl, PVOID res)
{
    (void)name; (void)fl; (void)res;
    return TRUE;
}
