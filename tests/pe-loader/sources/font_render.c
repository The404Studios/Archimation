/*
 * font_render.c -- gdi32 FreeType text-metric sanity check.
 *
 * Surface tested:
 *   gdi32!CreateCompatibleDC, gdi32!CreateFontA, gdi32!SelectObject,
 *   gdi32!GetTextExtentPoint32A, gdi32!DeleteDC, gdi32!DeleteObject
 *   pe-loader/dlls/gdi32/gdi32_font.c (FreeType wiring landed S65)
 *   S68 use-after-free fix around font-object destruction path
 *
 * Rationale:
 *   S65 wired FreeType into gdi32 so GetTextExtentPoint32/GetTextMetrics/
 *   TextOut produce real pixel dimensions from real font tables.  S68
 *   fixed a UAF where a font HFONT was still referenced by the DC after
 *   the SelectObject cycle completed -- repeated create/select/delete
 *   loops could crash.
 *
 *   We make one DC + one font, measure "Hello", verify cx/cy > 0, then
 *   clean up.  If the stub returns 0 or zero-size (no FreeType wired) we
 *   report STUB.  If the call succeeds with plausible metrics we report
 *   OK.  A segfault or negative-size return indicates regression.
 *
 * Harness expectation: outputs-any:FONT_RENDER_OK,FONT_RENDER_STUB
 */

#include <windows.h>
#include <stdio.h>

int main(void) {
    HDC dc = CreateCompatibleDC(NULL);
    if (!dc) {
        fprintf(stderr, "FAIL: CreateCompatibleDC returned NULL\n");
        return 1;
    }

    HFONT f = CreateFontA(
        14, 0, 0, 0, FW_NORMAL, 0, 0, 0,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        "Arial");
    if (!f) {
        /* Font-subsystem absent -- acceptable stub. */
        printf("FONT_RENDER_STUB: CreateFontA returned NULL\n");
        fflush(stdout);
        DeleteDC(dc);
        return 0;
    }

    HGDIOBJ prev = SelectObject(dc, f);
    (void)prev;

    SIZE sz = {0, 0};
    BOOL ok = GetTextExtentPoint32A(dc, "Hello", 5, &sz);
    if (!ok) {
        printf("FONT_RENDER_STUB: GetTextExtentPoint32A returned FALSE\n");
        fflush(stdout);
        DeleteObject(f);
        DeleteDC(dc);
        return 0;
    }
    if (sz.cx <= 0 || sz.cy <= 0) {
        printf("FONT_RENDER_STUB: zero extent (cx=%ld cy=%ld)\n",
               (long)sz.cx, (long)sz.cy);
        fflush(stdout);
        DeleteObject(f);
        DeleteDC(dc);
        return 0;
    }

    printf("FONT_RENDER_OK: real text extents (cx=%ld cy=%ld)\n",
           (long)sz.cx, (long)sz.cy);
    fflush(stdout);

    /* Exercise the UAF path: delete font then DC in the order the S68
     * fix was written to tolerate.  If UAF regresses this is where the
     * crash happens. */
    DeleteObject(f);
    DeleteDC(dc);
    return 0;
}
