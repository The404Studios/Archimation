/*
 * kernel32_time.c - Time and performance counter stubs
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "common/dll_common.h"

/* Windows FILETIME epoch: Jan 1, 1601 (100-ns intervals)
 * Unix epoch: Jan 1, 1970
 * Difference: 11644473600 seconds = 116444736000000000 100-ns intervals */
#define FILETIME_UNIX_DIFF 116444736000000000ULL

static void unix_to_filetime(time_t t, FILETIME *ft)
{
    uint64_t ticks = ((uint64_t)t * 10000000ULL) + FILETIME_UNIX_DIFF;
    ft->dwLowDateTime = (DWORD)(ticks & 0xFFFFFFFF);
    ft->dwHighDateTime = (DWORD)(ticks >> 32);
}

/*
 * Use CLOCK_MONOTONIC_RAW for QPC (high-precision, no NTP drift) and
 * CLOCK_MONOTONIC_COARSE for GetTickCount (millisecond granularity is
 * fine — real Windows has 15.6 ms tick). COARSE avoids the VDSO-read-of-
 * the-real-hardware-counter cost on old HW where rdtsc+scaling per call
 * is ~30–100ns vs ~2–5ns for COARSE (just a VDSO memory read).
 *
 * All timing sources must be consistent (QPC, GetTickCount, GetTickCount64)
 * to avoid anti-cheat detection — COARSE and RAW both advance monotonically
 * and stay within the same second, so cross-call consistency is preserved.
 */
#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW 4
#endif
#ifndef CLOCK_MONOTONIC_COARSE
#define CLOCK_MONOTONIC_COARSE 6
#endif
#ifndef CLOCK_REALTIME_COARSE
#define CLOCK_REALTIME_COARSE 5
#endif

static void get_raw_monotonic(struct timespec *ts)
{
    /* Try CLOCK_MONOTONIC_RAW first, fall back to CLOCK_MONOTONIC */
    if (clock_gettime(CLOCK_MONOTONIC_RAW, ts) != 0)
        clock_gettime(CLOCK_MONOTONIC, ts);
}

/* Coarse monotonic clock for GetTickCount — ~10x cheaper than RAW on old HW.
 * Linux ships CLOCK_MONOTONIC_COARSE since 2.6.32 (2009), so essentially
 * universal. Fall back gracefully to MONOTONIC if the clock is unavailable
 * (pre-2.6.32 or cgroup/seccomp blocking). */
static void get_coarse_monotonic(struct timespec *ts)
{
    if (clock_gettime(CLOCK_MONOTONIC_COARSE, ts) != 0 &&
        clock_gettime(CLOCK_MONOTONIC, ts) != 0) {
        ts->tv_sec = 0;
        ts->tv_nsec = 0;
    }
}

WINAPI_EXPORT DWORD GetTickCount(void)
{
    struct timespec ts;
    get_coarse_monotonic(&ts);
    /* Cast to 64-bit BEFORE multiply to avoid 32-bit overflow on systems
     * with >~49 days uptime where (int)ts.tv_sec * 1000 wraps at 2^31. */
    return (DWORD)((uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL);
}

WINAPI_EXPORT ULONGLONG GetTickCount64(void)
{
    struct timespec ts;
    get_coarse_monotonic(&ts);
    return (ULONGLONG)ts.tv_sec * 1000ULL + (ULONGLONG)ts.tv_nsec / 1000000ULL;
}

WINAPI_EXPORT BOOL QueryPerformanceCounter(PLARGE_INTEGER lpPerformanceCount)
{
    struct timespec ts;
    get_raw_monotonic(&ts);
    lpPerformanceCount->QuadPart = (LONGLONG)ts.tv_sec * 1000000000LL + ts.tv_nsec;
    return TRUE;
}

WINAPI_EXPORT BOOL QueryPerformanceFrequency(PLARGE_INTEGER lpFrequency)
{
    lpFrequency->QuadPart = 1000000000LL; /* Nanosecond resolution */
    return TRUE;
}

WINAPI_EXPORT void GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
{
    /* Use CLOCK_REALTIME_COARSE (VDSO-backed memory read on Linux) instead
     * of gettimeofday() for the ~10x speedup. GetSystemTimeAsFileTime is
     * hit on every CRT tick, logging timestamp, and stdio flush, so this
     * is one of the hottest kernel32 exports.
     * Precision stays at jiffy granularity (~1–10ms) which matches Windows'
     * own 15.6ms FILETIME tick — indistinguishable from real Win10. */
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME_COARSE, &ts) != 0)
        clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t ticks = ((uint64_t)ts.tv_sec * 10000000ULL) +
                     ((uint64_t)ts.tv_nsec / 100ULL) +
                     FILETIME_UNIX_DIFF;
    lpSystemTimeAsFileTime->dwLowDateTime = (DWORD)(ticks & 0xFFFFFFFF);
    lpSystemTimeAsFileTime->dwHighDateTime = (DWORD)(ticks >> 32);
}

WINAPI_EXPORT void GetLocalTime(void *lpSystemTime)
{
    /* SYSTEMTIME structure */
    typedef struct {
        WORD wYear;
        WORD wMonth;
        WORD wDayOfWeek;
        WORD wDay;
        WORD wHour;
        WORD wMinute;
        WORD wSecond;
        WORD wMilliseconds;
    } SYSTEMTIME;

    SYSTEMTIME *st = (SYSTEMTIME *)lpSystemTime;
    if (!st) return;
    struct timespec ts;
    /* VDSO fast path via COARSE; jiffy-granularity matches Win10 15.6ms tick */
    if (clock_gettime(CLOCK_REALTIME_COARSE, &ts) != 0)
        clock_gettime(CLOCK_REALTIME, &ts);
    time_t now = ts.tv_sec;
    struct tm tm_buf;
    struct tm *tm = localtime_r(&now, &tm_buf);
    if (!tm) { memset(st, 0, sizeof(*st)); return; }

    st->wYear = tm->tm_year + 1900;
    st->wMonth = tm->tm_mon + 1;
    st->wDayOfWeek = tm->tm_wday;
    st->wDay = tm->tm_mday;
    st->wHour = tm->tm_hour;
    st->wMinute = tm->tm_min;
    st->wSecond = tm->tm_sec;
    st->wMilliseconds = (WORD)(ts.tv_nsec / 1000000);
}

WINAPI_EXPORT void GetSystemTime(void *lpSystemTime)
{
    typedef struct {
        WORD wYear, wMonth, wDayOfWeek, wDay;
        WORD wHour, wMinute, wSecond, wMilliseconds;
    } SYSTEMTIME;

    SYSTEMTIME *st = (SYSTEMTIME *)lpSystemTime;
    if (!st) return;
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME_COARSE, &ts) != 0)
        clock_gettime(CLOCK_REALTIME, &ts);
    time_t now = ts.tv_sec;
    struct tm tm_buf;
    struct tm *tm = gmtime_r(&now, &tm_buf);
    if (!tm) { memset(st, 0, sizeof(*st)); return; }

    st->wYear = tm->tm_year + 1900;
    st->wMonth = tm->tm_mon + 1;
    st->wDayOfWeek = tm->tm_wday;
    st->wDay = tm->tm_mday;
    st->wHour = tm->tm_hour;
    st->wMinute = tm->tm_min;
    st->wSecond = tm->tm_sec;
    st->wMilliseconds = (WORD)(ts.tv_nsec / 1000000);
}

WINAPI_EXPORT DWORD GetTimeZoneInformation(void *lpTimeZoneInformation)
{
    /* TIME_ZONE_INFORMATION structure - just zero it */
    memset(lpTimeZoneInformation, 0, 172); /* sizeof(TIME_ZONE_INFORMATION) */
    return 0; /* TIME_ZONE_ID_UNKNOWN */
}

WINAPI_EXPORT BOOL FileTimeToSystemTime(const FILETIME *lpFileTime, void *lpSystemTime)
{
    typedef struct {
        WORD wYear, wMonth, wDayOfWeek, wDay;
        WORD wHour, wMinute, wSecond, wMilliseconds;
    } SYSTEMTIME;

    if (!lpFileTime || !lpSystemTime) return FALSE;

    uint64_t ticks = ((uint64_t)lpFileTime->dwHighDateTime << 32) | lpFileTime->dwLowDateTime;
    ticks -= FILETIME_UNIX_DIFF;
    time_t unix_time = ticks / 10000000ULL;

    SYSTEMTIME *st = (SYSTEMTIME *)lpSystemTime;
    struct tm tm_buf;
    struct tm *tm = gmtime_r(&unix_time, &tm_buf);
    if (!tm) return FALSE;

    st->wYear = tm->tm_year + 1900;
    st->wMonth = tm->tm_mon + 1;
    st->wDayOfWeek = tm->tm_wday;
    st->wDay = tm->tm_mday;
    st->wHour = tm->tm_hour;
    st->wMinute = tm->tm_min;
    st->wSecond = tm->tm_sec;
    st->wMilliseconds = (WORD)((ticks % 10000000ULL) / 10000);
    return TRUE;
}

WINAPI_EXPORT BOOL FileTimeToLocalFileTime(const FILETIME *lpFileTime, LPFILETIME lpLocalFileTime)
{
    /* For simplicity, just copy (ignore timezone) */
    *lpLocalFileTime = *lpFileTime;
    return TRUE;
}

WINAPI_EXPORT BOOL SystemTimeToFileTime(const void *lpSystemTime, LPFILETIME lpFileTime)
{
    typedef struct {
        WORD wYear, wMonth, wDayOfWeek, wDay;
        WORD wHour, wMinute, wSecond, wMilliseconds;
    } SYSTEMTIME;

    const SYSTEMTIME *st = (const SYSTEMTIME *)lpSystemTime;
    struct tm tm = {0};
    tm.tm_year = st->wYear - 1900;
    tm.tm_mon = st->wMonth - 1;
    tm.tm_mday = st->wDay;
    tm.tm_hour = st->wHour;
    tm.tm_min = st->wMinute;
    tm.tm_sec = st->wSecond;

    time_t t = timegm(&tm);
    unix_to_filetime(t, lpFileTime);
    return TRUE;
}

WINAPI_EXPORT BOOL LocalFileTimeToFileTime(const FILETIME *lpLocalFileTime, LPFILETIME lpFileTime)
{
    *lpFileTime = *lpLocalFileTime;
    return TRUE;
}

WINAPI_EXPORT BOOL SetLocalTime(const void *lpSystemTime)
{
    (void)lpSystemTime;
    return TRUE;
}

WINAPI_EXPORT BOOL SetSystemTime(const void *lpSystemTime)
{
    (void)lpSystemTime;
    return TRUE;
}

WINAPI_EXPORT DWORD GetCurrentTime(void)
{
    return GetTickCount();
}

WINAPI_EXPORT BOOL QueryUnbiasedInterruptTime(ULONGLONG *UnbiasedTime)
{
    if (!UnbiasedTime) return FALSE;
    struct timespec ts;
    get_raw_monotonic(&ts);
    /* Return in 100-ns units like Windows */
    *UnbiasedTime = (ULONGLONG)ts.tv_sec * 10000000ULL + ts.tv_nsec / 100ULL;
    return TRUE;
}

WINAPI_EXPORT void GetSystemTimePreciseAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
{
    /* Windows contract: precise sub-microsecond wall-clock time. Use full
     * CLOCK_REALTIME (VDSO-backed nanosecond resolution on all modern HW)
     * rather than the COARSE path used by GetSystemTimeAsFileTime. */
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
        return;
    }
    uint64_t ticks = ((uint64_t)ts.tv_sec * 10000000ULL) +
                     ((uint64_t)ts.tv_nsec / 100ULL) +
                     FILETIME_UNIX_DIFF;
    lpSystemTimeAsFileTime->dwLowDateTime = (DWORD)(ticks & 0xFFFFFFFF);
    lpSystemTimeAsFileTime->dwHighDateTime = (DWORD)(ticks >> 32);
}

WINAPI_EXPORT BOOL SystemTimeToTzSpecificLocalTime(
    const void *lpTimeZoneInformation,
    const void *lpUniversalTime,
    void *lpLocalTime)
{
    (void)lpTimeZoneInformation;
    if (lpUniversalTime && lpLocalTime)
        memcpy(lpLocalTime, lpUniversalTime, 16); /* sizeof(SYSTEMTIME) */
    return TRUE;
}

WINAPI_EXPORT BOOL TzSpecificLocalTimeToSystemTime(
    const void *lpTimeZoneInformation,
    const void *lpLocalTime,
    void *lpUniversalTime)
{
    (void)lpTimeZoneInformation;
    if (lpLocalTime && lpUniversalTime)
        memcpy(lpUniversalTime, lpLocalTime, 16);
    return TRUE;
}

WINAPI_EXPORT int CompareFileTime(const FILETIME *lpFileTime1, const FILETIME *lpFileTime2)
{
    uint64_t t1 = ((uint64_t)lpFileTime1->dwHighDateTime << 32) | lpFileTime1->dwLowDateTime;
    uint64_t t2 = ((uint64_t)lpFileTime2->dwHighDateTime << 32) | lpFileTime2->dwLowDateTime;
    if (t1 < t2) return -1;
    if (t1 > t2) return 1;
    return 0;
}
