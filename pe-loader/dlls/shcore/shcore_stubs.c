/*
 * shcore_stubs.c - Shell Core DPI awareness API stubs
 *
 * Stubs for shcore.dll. Provides DPI awareness APIs that apps like
 * PuTTY probe via LoadLibrary/GetProcAddress at runtime.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/dll_common.h"

#define S_OK    ((HRESULT)0x00000000)

/* PROCESS_DPI_AWARENESS enum values (for reference):
 *   0 = PROCESS_DPI_UNAWARE
 *   1 = PROCESS_SYSTEM_DPI_AWARE
 *   2 = PROCESS_PER_MONITOR_DPI_AWARE
 */

/* MONITOR_DPI_TYPE enum values (for reference):
 *   0 = MDT_EFFECTIVE_DPI
 *   1 = MDT_ANGULAR_DPI
 *   2 = MDT_RAW_DPI
 */

/*
 * SetProcessDpiAwareness - Declare DPI awareness level for the process.
 * We accept any value and return S_OK (the app thinks it succeeded).
 */
WINAPI_EXPORT HRESULT SetProcessDpiAwareness(int value)
{
    (void)value;
    fprintf(stderr, "[shcore] SetProcessDpiAwareness(%d) -> stub S_OK\n", value);
    return S_OK;
}

/*
 * GetDpiForMonitor - Get DPI values for a monitor.
 * Returns 96 DPI (100% scaling, standard Windows default).
 */
WINAPI_EXPORT HRESULT GetDpiForMonitor(HANDLE hmonitor, int dpiType,
    UINT *dpiX, UINT *dpiY)
{
    (void)hmonitor;
    (void)dpiType;
    if (dpiX) *dpiX = 96;
    if (dpiY) *dpiY = 96;
    return S_OK;
}

/*
 * GetProcessDpiAwareness - Query the DPI awareness of a process.
 * Returns PROCESS_DPI_UNAWARE (0) since we don't track it.
 */
WINAPI_EXPORT HRESULT GetProcessDpiAwareness(HANDLE hProcess, int *value)
{
    (void)hProcess;
    if (value) *value = 0; /* PROCESS_DPI_UNAWARE */
    return S_OK;
}

/*
 * GetScaleFactorForMonitor - Get the scale factor for a monitor.
 * Returns 100 (meaning 100%, no scaling).
 */
WINAPI_EXPORT HRESULT GetScaleFactorForMonitor(HANDLE hMon, int *pScale)
{
    (void)hMon;
    if (pScale) *pScale = 100; /* SCALE_100_PERCENT */
    return S_OK;
}

/*
 * SHCreateMemStream - Create a memory-backed IStream.
 * We don't implement COM IStream, so return NULL.
 * Callers typically check for NULL and fall back.
 */
WINAPI_EXPORT void *SHCreateMemStream(const BYTE *pInit, UINT cbInit)
{
    (void)pInit;
    (void)cbInit;
    return NULL;
}
