/*
 * comctl32_controls.c - Common Controls library stubs
 *
 * GUI applications use comctl32.dll for rich UI elements: toolbars,
 * status bars, image lists, property sheets, task dialogs, etc.
 * We stub everything so headless/CLI apps that happen to link
 * comctl32 don't crash.
 */

#include <stdio.h>
#include <string.h>

#include "common/dll_common.h"

/* HRESULT codes */
#define S_OK            ((HRESULT)0x00000000)
#define E_NOTIMPL       ((HRESULT)0x80004001)

/* Fake HIMAGELIST handle */
#define FAKE_HIMAGELIST ((HANDLE)(intptr_t)0x2000)

/* -----------------------------------------------------------------------
 * InitCommonControls / InitCommonControlsEx
 *
 * Applications call these at startup to register window classes for
 * the standard common controls. No-ops for us.
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT void InitCommonControls(void)
{
    fprintf(stderr, "[comctl32] InitCommonControls()\n");
}

WINAPI_EXPORT BOOL InitCommonControlsEx(void *icc)
{
    (void)icc;

    fprintf(stderr, "[comctl32] InitCommonControlsEx()\n");

    return TRUE;
}

/* -----------------------------------------------------------------------
 * ImageList_Create / Destroy / Add / GetImageCount / ReplaceIcon
 *
 * Return a fake handle and pretend the list is always empty.
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT HANDLE ImageList_Create(
    int cx,
    int cy,
    UINT flags,
    int initial,
    int grow)
{
    (void)cx;
    (void)cy;
    (void)flags;
    (void)initial;
    (void)grow;

    fprintf(stderr, "[comctl32] ImageList_Create(%dx%d, flags=0x%x)\n", cx, cy, flags);

    return FAKE_HIMAGELIST;
}

WINAPI_EXPORT BOOL ImageList_Destroy(HANDLE himl)
{
    (void)himl;

    fprintf(stderr, "[comctl32] ImageList_Destroy()\n");

    return TRUE;
}

WINAPI_EXPORT int ImageList_Add(HANDLE himl, HANDLE hbm, HANDLE hbmMask)
{
    (void)himl;
    (void)hbm;
    (void)hbmMask;

    fprintf(stderr, "[comctl32] ImageList_Add()\n");

    return 0;
}

WINAPI_EXPORT int ImageList_GetImageCount(HANDLE himl)
{
    (void)himl;

    fprintf(stderr, "[comctl32] ImageList_GetImageCount() -> 0\n");

    return 0;
}

WINAPI_EXPORT int ImageList_AddMasked(HANDLE himl, HANDLE hbmImage, DWORD crMask)
{
    (void)himl; (void)hbmImage; (void)crMask;

    fprintf(stderr, "[comctl32] ImageList_AddMasked()\n");

    return 0; /* index of first new image */
}

WINAPI_EXPORT BOOL ImageList_SetImageCount(HANDLE himl, UINT uNewCount)
{
    (void)himl; (void)uNewCount;

    fprintf(stderr, "[comctl32] ImageList_SetImageCount(%u)\n", uNewCount);

    return TRUE;
}

WINAPI_EXPORT BOOL ImageList_Remove(HANDLE himl, int i)
{
    (void)himl; (void)i;

    fprintf(stderr, "[comctl32] ImageList_Remove(index=%d)\n", i);

    return TRUE;
}

WINAPI_EXPORT BOOL ImageList_Draw(HANDLE himl, int i, HANDLE hdcDst,
    int x, int y, UINT fStyle)
{
    (void)himl; (void)i; (void)hdcDst; (void)x; (void)y; (void)fStyle;

    fprintf(stderr, "[comctl32] ImageList_Draw(index=%d, x=%d, y=%d)\n", i, x, y);

    return TRUE;
}

WINAPI_EXPORT BOOL ImageList_DrawEx(HANDLE himl, int i, HANDLE hdcDst,
    int x, int y, int dx, int dy, DWORD rgbBk, DWORD rgbFg, UINT fStyle)
{
    (void)himl; (void)i; (void)hdcDst; (void)x; (void)y;
    (void)dx; (void)dy; (void)rgbBk; (void)rgbFg; (void)fStyle;

    fprintf(stderr, "[comctl32] ImageList_DrawEx(index=%d, x=%d, y=%d)\n", i, x, y);

    return TRUE;
}

WINAPI_EXPORT int ImageList_ReplaceIcon(HANDLE himl, int i, HANDLE hicon)
{
    (void)himl;
    (void)i;
    (void)hicon;

    fprintf(stderr, "[comctl32] ImageList_ReplaceIcon(index=%d)\n", i);

    return 0;
}

/* -----------------------------------------------------------------------
 * CreateStatusWindowA
 *
 * Return NULL — no window created.
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT HWND CreateStatusWindowA(
    LONG style,
    LPCSTR text,
    HWND parent,
    UINT id)
{
    (void)style;
    (void)text;
    (void)parent;
    (void)id;

    fprintf(stderr, "[comctl32] CreateStatusWindowA(text='%s') -> NULL\n",
            text ? text : "(null)");

    return NULL;
}

/* -----------------------------------------------------------------------
 * CreateToolbarEx
 *
 * Return NULL — no toolbar created.
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT HWND CreateToolbarEx(
    HWND parent,
    DWORD style,
    UINT id,
    int nBitmaps,
    HANDLE hBMInst,
    UINT wBMID,
    void *buttons,
    int iNumButtons,
    int dxButton,
    int dyButton,
    int dxBitmap,
    int dyBitmap,
    UINT uStructSize)
{
    (void)parent;
    (void)style;
    (void)id;
    (void)nBitmaps;
    (void)hBMInst;
    (void)wBMID;
    (void)buttons;
    (void)iNumButtons;
    (void)dxButton;
    (void)dyButton;
    (void)dxBitmap;
    (void)dyBitmap;
    (void)uStructSize;

    fprintf(stderr, "[comctl32] CreateToolbarEx(buttons=%d) -> NULL\n", iNumButtons);

    return NULL;
}

/* -----------------------------------------------------------------------
 * PropertySheetA
 *
 * Return 0 (no pages navigated).
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT int PropertySheetA(void *header)
{
    (void)header;

    fprintf(stderr, "[comctl32] PropertySheetA() -> 0\n");

    return 0;
}

/* -----------------------------------------------------------------------
 * TaskDialogIndirect
 *
 * Return E_NOTIMPL — task dialogs are not supported.
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT HRESULT TaskDialogIndirect(
    void *config,
    int *button,
    int *radioButton,
    BOOL *verified)
{
    (void)config;
    (void)button;
    (void)radioButton;
    (void)verified;

    fprintf(stderr, "[comctl32] TaskDialogIndirect() -> E_NOTIMPL\n");

    return E_NOTIMPL;
}

/* -----------------------------------------------------------------------
 * _TrackMouseEvent
 *
 * Return TRUE — pretend we registered the tracking request.
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT BOOL _TrackMouseEvent(void *tme)
{
    (void)tme;

    fprintf(stderr, "[comctl32] _TrackMouseEvent()\n");

    return TRUE;
}
