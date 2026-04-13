/*
 * winpix_stubs.c - WinPixEventRuntime.dll stubs
 *
 * UE5 optionally imports PIX GPU profiling marker functions.
 * All are no-ops — they exist solely to prevent unresolved import crashes.
 */

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "common/dll_common.h"

/* PIX event functions — all no-ops */

WINAPI_EXPORT void PIXBeginEventOnCommandList(void *commandList, uint64_t color,
                                               const char *formatString, ...)
{
    (void)commandList; (void)color; (void)formatString;
}

WINAPI_EXPORT void PIXEndEventOnCommandList(void *commandList)
{
    (void)commandList;
}

WINAPI_EXPORT void PIXSetMarkerOnCommandList(void *commandList, uint64_t color,
                                              const char *formatString, ...)
{
    (void)commandList; (void)color; (void)formatString;
}

/* Context-based variants (used by UE5) */
WINAPI_EXPORT void PIXBeginEvent(uint64_t color, const char *formatString, ...)
{
    (void)color; (void)formatString;
}

WINAPI_EXPORT void PIXEndEvent(void)
{
}

WINAPI_EXPORT void PIXSetMarker(uint64_t color, const char *formatString, ...)
{
    (void)color; (void)formatString;
}

/* Wide-string variants */
WINAPI_EXPORT void PIXBeginEventW(uint64_t color, const uint16_t *formatString, ...)
{
    (void)color; (void)formatString;
}

WINAPI_EXPORT void PIXEndEventW(void)
{
}

WINAPI_EXPORT void PIXSetMarkerW(uint64_t color, const uint16_t *formatString, ...)
{
    (void)color; (void)formatString;
}

/* Capture control */
WINAPI_EXPORT void PIXBeginCapture(uint32_t flags, void *params)
{
    (void)flags; (void)params;
}

WINAPI_EXPORT void PIXEndCapture(int discard)
{
    (void)discard;
}

WINAPI_EXPORT uint32_t PIXGetCaptureState(void)
{
    return 0; /* Not capturing */
}

/* Fence/event support */
WINAPI_EXPORT void PIXNotifyWakeFromFenceSignal(void *event)
{
    (void)event;
}

WINAPI_EXPORT void PIXReportCounter(const uint16_t *name, float value)
{
    (void)name; (void)value;
}

/* Block management (UE5 may call these) */
WINAPI_EXPORT uint64_t PIXEventsReplaceBlock(int isRealtime)
{
    (void)isRealtime;
    return 0;
}

/* Timestamp — use clock_gettime for a reasonable monotonic value */
WINAPI_EXPORT uint64_t PIXGetTimestampCounter(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* GPU timing */
WINAPI_EXPORT void PIXSetHUDOptions(uint32_t flags)
{
    (void)flags;
}

WINAPI_EXPORT BOOL PIXIsAttachedForGpuCapture(void)
{
    return FALSE;
}

WINAPI_EXPORT uint32_t PIXGetThreadInfo(void)
{
    return 0;
}
