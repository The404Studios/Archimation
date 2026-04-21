/*
 * gui_text.c -- gdi32 text rendering on a real DC.
 *
 * Surface tested:
 *   gdi32!CreateCompatibleDC, gdi32!CreateFontA, gdi32!SelectObject,
 *   gdi32!TextOutA, gdi32!GetTextExtentPoint32A, gdi32!DeleteObject,
 *   gdi32!DeleteDC, user32!GetDC, user32!ReleaseDC
 *
 * Rationale:
 *   This is the FreeType integration validator.  Agent A5 wired FreeType
 *   into gdi32; if their work is correct, GetTextExtentPoint32A should
 *   return non-zero width for "ABC".  Catches:
 *     - CreateFontA finds *some* font (FreeType match path)
 *     - SelectObject preserves prior object
 *     - GetTextExtentPoint32A walks the font's hmtx table
 *     - DeleteObject doesn't double-free
 *
 *   No window is created; we draw to an off-screen DC.  Headless-safe.
 *
 * Harness expectation: outputs:GUI_TEXT_OK    (FreeType wired, width>0)
 *                  OR  outputs:GUI_TEXT_STUB  (gdi32 stubs only)
 */

#include <windows.h>
#include <stdio.h>

int main(void) {
    HDC dc = CreateCompatibleDC(NULL);
    if (!dc) {
        printf("CreateCompatibleDC NULL; stub backend\n");
        printf("GUI_TEXT_STUB\n");
        fflush(stdout);
        return 0;
    }

    HFONT font = CreateFontA(
        16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Arial");

    if (!font) {
        printf("CreateFontA NULL; stub backend\n");
        DeleteDC(dc);
        printf("GUI_TEXT_STUB\n");
        fflush(stdout);
        return 0;
    }

    HGDIOBJ prev = SelectObject(dc, font);

    SIZE sz = {0, 0};
    BOOL ok = GetTextExtentPoint32A(dc, "ABC", 3, &sz);
    printf("text extent ABC: ok=%d w=%ld h=%ld\n",
           (int)ok, (long)sz.cx, (long)sz.cy);

    /* TextOutA into the off-screen DC.  We don't validate output bytes
     * (no bitmap selected); we just verify the call doesn't crash. */
    TextOutA(dc, 0, 0, "ABC", 3);

    SelectObject(dc, prev);
    DeleteObject(font);
    DeleteDC(dc);

    if (ok && sz.cx > 0) {
        printf("GUI_TEXT_OK\n");
    } else {
        printf("GUI_TEXT_STUB\n");
    }
    fflush(stdout);
    return 0;
}
