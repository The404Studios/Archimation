/*
 * user32_display.c - Display/Monitor enumeration and configuration stubs
 *
 * Functions needed by DXVK d3d9.dll for display setup:
 * ChangeDisplaySettingsExW, CreateIconIndirect, DisplayConfigGetDeviceInfo,
 * EnumDisplayDevicesA, EnumDisplayMonitors, EnumDisplaySettingsW,
 * GetDCEx, GetDisplayConfigBufferSizes, GetMonitorInfoW,
 * MonitorFromPoint, QueryDisplayConfig.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "common/dll_common.h"

/* --------------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------------- */

#define DISP_CHANGE_SUCCESSFUL  0
#define ERROR_NOT_SUPPORTED_VAL 50
#define MONITORINFOF_PRIMARY    0x00000001
#define DISPLAY_DEVICE_ACTIVE           0x00000001
#define DISPLAY_DEVICE_PRIMARY_DEVICE   0x00000004

/* Fake handles for monitor/icon/DC */
#define FAKE_MONITOR_HANDLE ((HANDLE)(uintptr_t)0x00B0B001)
#define FAKE_ICON_HANDLE    ((HANDLE)(uintptr_t)0x01C0B001)
#define FAKE_DC_HANDLE      ((HDC)(uintptr_t)0x00DC0001)

/* --------------------------------------------------------------------------
 * DISPLAY_DEVICEA structure (420 bytes)
 * -------------------------------------------------------------------------- */

typedef struct {
    DWORD cb;
    CHAR  DeviceName[32];
    CHAR  DeviceString[128];
    DWORD StateFlags;
    CHAR  DeviceID[128];
    CHAR  DeviceKey[128];
} DISPLAY_DEVICEA;

/* --------------------------------------------------------------------------
 * MONITORINFOEXW structure
 *   cbSize (DWORD), rcMonitor (4 LONGs), rcWork (4 LONGs),
 *   dwFlags (DWORD), szDevice (32 WCHARs = 64 bytes)
 * Total: 4 + 16 + 16 + 4 + 64 = 104 bytes
 * -------------------------------------------------------------------------- */

typedef struct {
    DWORD   cbSize;
    RECT    rcMonitor;
    RECT    rcWork;
    DWORD   dwFlags;
    WCHAR   szDevice[32];
} MONITORINFOEXW;

/* --------------------------------------------------------------------------
 * Callback type for EnumDisplayMonitors
 * -------------------------------------------------------------------------- */

typedef BOOL (__attribute__((ms_abi)) *MONITORENUMPROC)(HANDLE, HDC, LPRECT, LPARAM);

/* --------------------------------------------------------------------------
 * ChangeDisplaySettingsExW
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT LONG ChangeDisplaySettingsExW(
    const WCHAR *lpszDeviceName,
    void *lpDevMode,
    HWND hwnd,
    DWORD dwflags,
    void *lParam)
{
    (void)lpszDeviceName;
    (void)lpDevMode;
    (void)hwnd;
    (void)dwflags;
    (void)lParam;
    return DISP_CHANGE_SUCCESSFUL;
}

/* --------------------------------------------------------------------------
 * CreateIconIndirect
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HICON CreateIconIndirect(void *piconinfo)
{
    (void)piconinfo;
    /* Return a fake icon handle */
    return (HICON)FAKE_ICON_HANDLE;
}

/* --------------------------------------------------------------------------
 * DisplayConfigGetDeviceInfo
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT LONG DisplayConfigGetDeviceInfo(void *requestPacket)
{
    (void)requestPacket;
    return ERROR_NOT_SUPPORTED_VAL; /* ERROR_NOT_SUPPORTED = 50 */
}

/* --------------------------------------------------------------------------
 * EnumDisplayDevicesA
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL EnumDisplayDevicesA(
    LPCSTR lpDevice,
    DWORD iDevNum,
    void *lpDisplayDevice,
    DWORD dwFlags)
{
    (void)lpDevice;
    (void)dwFlags;

    if (iDevNum != 0 || !lpDisplayDevice) {
        /* Only one display device (index 0) */
        return FALSE;
    }

    DISPLAY_DEVICEA *dd = (DISPLAY_DEVICEA *)lpDisplayDevice;
    /* Preserve cb, fill the rest */
    memset(dd->DeviceName, 0, sizeof(dd->DeviceName));
    memset(dd->DeviceString, 0, sizeof(dd->DeviceString));
    memset(dd->DeviceID, 0, sizeof(dd->DeviceID));
    memset(dd->DeviceKey, 0, sizeof(dd->DeviceKey));

    strncpy(dd->DeviceName, "\\\\.\\DISPLAY1", sizeof(dd->DeviceName) - 1);
    strncpy(dd->DeviceString, "PE-Compat Virtual Display", sizeof(dd->DeviceString) - 1);
    dd->StateFlags = DISPLAY_DEVICE_ACTIVE | DISPLAY_DEVICE_PRIMARY_DEVICE;
    strncpy(dd->DeviceID, "PCI\\VEN_0000&DEV_0000&SUBSYS_00000000&REV_00",
            sizeof(dd->DeviceID) - 1);

    return TRUE;
}

/* --------------------------------------------------------------------------
 * EnumDisplayMonitors
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL EnumDisplayMonitors(
    HDC hdc,
    void *lprcClip,
    void *lpfnEnum,
    LPARAM dwData)
{
    (void)hdc;
    (void)lprcClip;

    if (!lpfnEnum)
        return FALSE;

    MONITORENUMPROC callback = (MONITORENUMPROC)lpfnEnum;

    /* Call the callback once with a fake monitor handle and screen rect */
    RECT monRect;
    monRect.left   = 0;
    monRect.top    = 0;
    monRect.right  = 1920;
    monRect.bottom = 1080;

    HANDLE hMonitor = (HANDLE)(uintptr_t)0x00B0B001;
    callback(hMonitor, NULL, &monRect, dwData);

    return TRUE;
}

/* --------------------------------------------------------------------------
 * EnumDisplaySettingsW
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL EnumDisplaySettingsW(
    const WCHAR *lpszDeviceName,
    DWORD iModeNum,
    void *lpDevMode)
{
    (void)lpszDeviceName;

    if (!lpDevMode)
        return FALSE;

    /* Only report one mode (index 0) or current settings (-1 / -2) */
    if (iModeNum != 0 && iModeNum != (DWORD)-1 && iModeNum != (DWORD)-2)
        return FALSE;

    /*
     * DEVMODEW layout (relevant offsets for x64):
     *   dmDeviceName: offset 0, 64 bytes (32 WCHARs)
     *   dmBitsPerPel: offset 168, DWORD
     *   dmPelsWidth:  offset 172, DWORD
     *   dmPelsHeight: offset 176, DWORD
     *   dmDisplayFrequency: offset 180, DWORD
     *
     * We zero the whole structure (using first DWORD as dmSize hint)
     * and set the specific fields.
     */
    unsigned char *dm = (unsigned char *)lpDevMode;

    /* Always zero the full expected size to avoid reading uninitialized fields */
    memset(dm, 0, 220);

    /* Read dmSize - use 220 as default (already zeroed above) */
    uint16_t dmSize = 220;

    /* Set device name */
    const WCHAR devName[] = { '\\','\\','.','\\','D','I','S','P','L','A','Y','1',0 };
    memcpy(dm, devName, sizeof(devName));

    /* dmSize at offset 68 */
    *(uint16_t *)(dm + 68) = dmSize;

    /* dmBitsPerPel at offset 168 */
    *(DWORD *)(dm + 168) = 32;

    /* dmPelsWidth at offset 172 */
    *(DWORD *)(dm + 172) = 1920;

    /* dmPelsHeight at offset 176 */
    *(DWORD *)(dm + 176) = 1080;

    /* dmDisplayFrequency at offset 180 */
    *(DWORD *)(dm + 180) = 60;

    /* dmFields at offset 72 - indicate which fields are valid */
    /* DM_BITSPERPEL|DM_PELSWIDTH|DM_PELSHEIGHT|DM_DISPLAYFREQUENCY */
    *(DWORD *)(dm + 72) = 0x00040000 | 0x00080000 | 0x00100000 | 0x00400000;

    return TRUE;
}

/* --------------------------------------------------------------------------
 * GetDCEx
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HDC GetDCEx(HWND hwnd, void *hrgnClip, DWORD flags)
{
    (void)hrgnClip;
    (void)flags;

    /* If hwnd is valid, delegate to GetDC which is in user32_window.c.
     * For DXVK, this is typically called on NULL or desktop HWND.
     * Return a fake DC. */
    (void)hwnd;
    return FAKE_DC_HANDLE;
}

/* --------------------------------------------------------------------------
 * GetDisplayConfigBufferSizes
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT LONG GetDisplayConfigBufferSizes(
    DWORD flags,
    DWORD *numPathArrayElements,
    DWORD *numModeInfoArrayElements)
{
    (void)flags;

    if (numPathArrayElements)
        *numPathArrayElements = 1;
    if (numModeInfoArrayElements)
        *numModeInfoArrayElements = 1;

    return 0; /* ERROR_SUCCESS */
}

/* --------------------------------------------------------------------------
 * GetMonitorInfoW
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL GetMonitorInfoW(HANDLE hMonitor, void *lpmi)
{
    (void)hMonitor;

    if (!lpmi)
        return FALSE;

    MONITORINFOEXW *mi = (MONITORINFOEXW *)lpmi;
    DWORD cbSize = mi->cbSize;

    /* Fill MONITORINFO part (minimum 40 bytes) */
    mi->rcMonitor.left   = 0;
    mi->rcMonitor.top    = 0;
    mi->rcMonitor.right  = 1920;
    mi->rcMonitor.bottom = 1080;

    mi->rcWork.left   = 0;
    mi->rcWork.top    = 0;
    mi->rcWork.right  = 1920;
    mi->rcWork.bottom = 1080;

    mi->dwFlags = MONITORINFOF_PRIMARY;

    /* If cbSize indicates MONITORINFOEXW (>= 104 bytes), fill szDevice */
    if (cbSize >= sizeof(MONITORINFOEXW)) {
        const WCHAR devName[] = { '\\','\\','.','\\','D','I','S','P','L','A','Y','1',0 };
        memset(mi->szDevice, 0, sizeof(mi->szDevice));
        memcpy(mi->szDevice, devName, sizeof(devName));
    }

    return TRUE;
}

/* --------------------------------------------------------------------------
 * MonitorFromPoint
 *
 * POINT is 8 bytes (x:LONG, y:LONG). On ms_abi x64 it may be passed
 * as a 64-bit register value. We accept int64_t and ignore the value.
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HANDLE MonitorFromPoint(int64_t pt, DWORD dwFlags)
{
    (void)pt;
    (void)dwFlags;
    return (HANDLE)(uintptr_t)0x00B0B001;
}

/* --------------------------------------------------------------------------
 * QueryDisplayConfig
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT LONG QueryDisplayConfig(
    DWORD flags,
    DWORD *numPathArrayElements,
    void *pathArray,
    DWORD *numModeInfoArrayElements,
    void *modeInfoArray,
    void *currentTopologyId)
{
    (void)flags;
    (void)pathArray;
    (void)modeInfoArray;
    (void)currentTopologyId;

    if (numPathArrayElements)
        *numPathArrayElements = 0;
    if (numModeInfoArrayElements)
        *numModeInfoArrayElements = 0;

    return 0; /* ERROR_SUCCESS */
}
