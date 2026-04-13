/*
 * dwmapi_stubs.c - Desktop Window Manager API stubs with HDR support
 *
 * Stubs for dwmapi.dll. Used by WPF apps, modern Windows UI, and
 * games that query DWM for HDR composition state.
 *
 * Windows 11 HDR flow:
 *   DwmSetWindowAttribute(DWMWA_USE_IMMERSIVE_DARK_MODE) for dark mode
 *   DwmGetWindowAttribute(DWMWA_CAPTION_COLOR) for accent colors
 *   DwmIsCompositionEnabled() always TRUE on Win10+
 *
 * For HDR, DWM composites in scRGB color space and the GPU driver
 * outputs HDR10 to the display. Games check composition state to
 * decide whether to enable HDR swap chains.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/dll_common.h"

#define S_OK ((HRESULT)0x00000000)
#define E_INVALIDARG ((HRESULT)0x80070057)
#define DWM_E_COMPOSITIONDISABLED ((HRESULT)0x80263001)

/* DWM Window Attributes — Windows 11 22H2+ */
#define DWMWA_NCRENDERING_ENABLED          1
#define DWMWA_NCRENDERING_POLICY           2
#define DWMWA_TRANSITIONS_FORCEDISABLED    3
#define DWMWA_ALLOW_NCPAINT                4
#define DWMWA_CAPTION_BUTTON_BOUNDS        5
#define DWMWA_NONCLIENT_RTL_LAYOUT         6
#define DWMWA_FORCE_ICONIC_REPRESENTATION  7
#define DWMWA_FLIP3D_POLICY                8
#define DWMWA_EXTENDED_FRAME_BOUNDS        9
#define DWMWA_HAS_ICONIC_BITMAP           10
#define DWMWA_DISALLOW_PEEK               11
#define DWMWA_EXCLUDED_FROM_PEEK          12
#define DWMWA_CLOAK                       13
#define DWMWA_CLOAKED                     14
#define DWMWA_FREEZE_REPRESENTATION       15
#define DWMWA_PASSIVE_UPDATE_MODE         16
#define DWMWA_USE_HOSTBACKDROPBRUSH       17
#define DWMWA_USE_IMMERSIVE_DARK_MODE     20  /* Windows 10 1903+ */
#define DWMWA_WINDOW_CORNER_PREFERENCE    33  /* Windows 11 */
#define DWMWA_BORDER_COLOR                34  /* Windows 11 */
#define DWMWA_CAPTION_COLOR               35  /* Windows 11 */
#define DWMWA_TEXT_COLOR                   36  /* Windows 11 */
#define DWMWA_VISIBLE_FRAME_BORDER_THICKNESS 37
#define DWMWA_SYSTEMBACKDROP_TYPE         38  /* Windows 11 22H2 */

/* DWM_SYSTEMBACKDROP_TYPE */
#define DWMSBT_AUTO          0
#define DWMSBT_NONE          1
#define DWMSBT_MAINWINDOW    2  /* Mica */
#define DWMSBT_TRANSIENTWINDOW 3  /* Acrylic */
#define DWMSBT_TABBEDWINDOW  4  /* Tabbed Mica */

/* Window corner preference */
#define DWMWCP_DEFAULT    0
#define DWMWCP_DONOTROUND 1
#define DWMWCP_ROUND      2
#define DWMWCP_ROUNDSMALL 3

typedef struct { int left, top, right, bottom; } MARGINS;

WINAPI_EXPORT HRESULT DwmIsCompositionEnabled(BOOL *pfEnabled)
{
    /* Always enabled — Windows 10+ never disables DWM */
    if (pfEnabled) *pfEnabled = TRUE;
    return S_OK;
}

WINAPI_EXPORT HRESULT DwmEnableComposition(UINT uCompositionAction)
{
    (void)uCompositionAction;
    /* Deprecated since Windows 8 — composition is always on */
    return S_OK;
}

WINAPI_EXPORT HRESULT DwmGetWindowAttribute(HANDLE hwnd, DWORD dwAttribute,
    void *pvAttribute, DWORD cbAttribute)
{
    (void)hwnd;

    if (!pvAttribute || cbAttribute == 0)
        return E_INVALIDARG;

    switch (dwAttribute) {
    case DWMWA_NCRENDERING_ENABLED:
        if (cbAttribute >= sizeof(BOOL))
            *(BOOL *)pvAttribute = TRUE;
        break;

    case DWMWA_EXTENDED_FRAME_BOUNDS:
        /* Return a reasonable window rect */
        if (cbAttribute >= 16) {
            INT *rect = (INT *)pvAttribute;
            rect[0] = 0; rect[1] = 0;
            rect[2] = 1920; rect[3] = 1080;
        }
        break;

    case DWMWA_CLOAKED:
        if (cbAttribute >= sizeof(DWORD))
            *(DWORD *)pvAttribute = 0; /* Not cloaked */
        break;

    case DWMWA_USE_IMMERSIVE_DARK_MODE:
        if (cbAttribute >= sizeof(BOOL))
            *(BOOL *)pvAttribute = TRUE; /* Dark mode enabled */
        break;

    case DWMWA_WINDOW_CORNER_PREFERENCE:
        if (cbAttribute >= sizeof(DWORD))
            *(DWORD *)pvAttribute = DWMWCP_ROUND; /* Rounded corners */
        break;

    case DWMWA_BORDER_COLOR:
    case DWMWA_CAPTION_COLOR:
        if (cbAttribute >= sizeof(DWORD))
            *(DWORD *)pvAttribute = 0xFF1F1F1F; /* Dark theme */
        break;

    case DWMWA_TEXT_COLOR:
        if (cbAttribute >= sizeof(DWORD))
            *(DWORD *)pvAttribute = 0xFFFFFFFF; /* White text */
        break;

    case DWMWA_VISIBLE_FRAME_BORDER_THICKNESS:
        if (cbAttribute >= sizeof(UINT))
            *(UINT *)pvAttribute = 1;
        break;

    case DWMWA_SYSTEMBACKDROP_TYPE:
        if (cbAttribute >= sizeof(DWORD))
            *(DWORD *)pvAttribute = DWMSBT_MAINWINDOW; /* Mica */
        break;

    default:
        memset(pvAttribute, 0, cbAttribute);
        break;
    }
    return S_OK;
}

WINAPI_EXPORT HRESULT DwmSetWindowAttribute(HANDLE hwnd, DWORD dwAttribute,
    const void *pvAttribute, DWORD cbAttribute)
{
    (void)hwnd; (void)pvAttribute; (void)cbAttribute;

    /* Log HDR-relevant attributes */
    switch (dwAttribute) {
    case DWMWA_USE_IMMERSIVE_DARK_MODE:
        fprintf(stderr, "[dwmapi] SetWindowAttribute: IMMERSIVE_DARK_MODE = %d\n",
                pvAttribute ? *(const BOOL *)pvAttribute : -1);
        break;
    case DWMWA_SYSTEMBACKDROP_TYPE:
        fprintf(stderr, "[dwmapi] SetWindowAttribute: SYSTEMBACKDROP_TYPE = %u\n",
                pvAttribute ? *(const DWORD *)pvAttribute : 0);
        break;
    default:
        break;
    }

    return S_OK;
}

WINAPI_EXPORT HRESULT DwmExtendFrameIntoClientArea(HANDLE hWnd, const MARGINS *pMarInset)
{
    (void)hWnd; (void)pMarInset;
    return S_OK;
}

WINAPI_EXPORT HRESULT DwmEnableBlurBehindWindow(HANDLE hWnd, const void *pBlurBehind)
{
    (void)hWnd; (void)pBlurBehind;
    return S_OK;
}

WINAPI_EXPORT HRESULT DwmGetColorizationColor(DWORD *pcrColorization, BOOL *pfOpaqueBlend)
{
    /* Dark theme accent color */
    if (pcrColorization) *pcrColorization = 0xFF1F1F1F;
    if (pfOpaqueBlend) *pfOpaqueBlend = TRUE;
    return S_OK;
}

WINAPI_EXPORT HRESULT DwmFlush(void)
{
    return S_OK;
}

WINAPI_EXPORT HRESULT DwmDefWindowProc(HANDLE hwnd, UINT msg, void *wParam, void *lParam, void *plResult)
{
    (void)hwnd; (void)msg; (void)wParam; (void)lParam;
    if (plResult) *(LONG *)plResult = 0;
    return S_OK;
}

WINAPI_EXPORT HRESULT DwmSetPresentParameters(HANDLE hwnd, void *pPresentParams)
{
    (void)hwnd; (void)pPresentParams;
    return S_OK;
}

WINAPI_EXPORT HRESULT DwmInvalidateIconicBitmaps(HANDLE hwnd)
{
    (void)hwnd;
    return S_OK;
}

WINAPI_EXPORT HRESULT DwmRegisterThumbnail(HANDLE hwndDest, HANDLE hwndSrc, void *phThumbnailId)
{
    (void)hwndDest; (void)hwndSrc; (void)phThumbnailId;
    return S_OK;
}

WINAPI_EXPORT HRESULT DwmUnregisterThumbnail(HANDLE hThumbnailId)
{
    (void)hThumbnailId;
    return S_OK;
}

WINAPI_EXPORT HRESULT DwmUpdateThumbnailProperties(HANDLE hThumbnailId, const void *ptnProperties)
{
    (void)hThumbnailId; (void)ptnProperties;
    return S_OK;
}

/* DwmGetDpiForMonitor — Windows 8.1+ DPI awareness */
WINAPI_EXPORT HRESULT DwmGetDpiForMonitor(HANDLE hMonitor, UINT dpiType, UINT *dpiX, UINT *dpiY)
{
    (void)hMonitor; (void)dpiType;
    if (dpiX) *dpiX = 96;
    if (dpiY) *dpiY = 96;
    return S_OK;
}
