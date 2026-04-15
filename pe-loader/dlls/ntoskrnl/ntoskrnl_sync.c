/*
 * ntoskrnl_sync.c - Synchronization stubs for ntoskrnl.exe
 *
 * Spinlocks, events, timers, and IRQL management.
 * Maps Windows synchronization primitives to pthreads.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#include "common/dll_common.h"
#include "win32/wdm.h"

#define LOG_PREFIX "[ntoskrnl/sync] "

/* ===== Spinlock ===== */

/*
 * Windows KSPIN_LOCK is a pointer-sized value.
 * We store a pointer to a pthread_mutex_t in it.
 */
WINAPI_EXPORT void KeInitializeSpinLock(PKSPIN_LOCK SpinLock)
{
    *SpinLock = 0;  /* L5 audit fix: ensure zero on failure */
    pthread_mutex_t *mtx = (pthread_mutex_t *)calloc(1, sizeof(pthread_mutex_t));
    if (mtx) {
        if (pthread_mutex_init(mtx, NULL) == 0) {
            *SpinLock = (KSPIN_LOCK)(uintptr_t)mtx;
        } else {
            free(mtx);
        }
    }
}

WINAPI_EXPORT void KeAcquireSpinLock(PKSPIN_LOCK SpinLock, PKIRQL OldIrql)
{
    if (OldIrql)
        *OldIrql = PASSIVE_LEVEL;
    pthread_mutex_t *mtx = (pthread_mutex_t *)(uintptr_t)*SpinLock;
    if (mtx)
        pthread_mutex_lock(mtx);
}

WINAPI_EXPORT void KeReleaseSpinLock(PKSPIN_LOCK SpinLock, KIRQL NewIrql)
{
    (void)NewIrql;
    pthread_mutex_t *mtx = (pthread_mutex_t *)(uintptr_t)*SpinLock;
    if (mtx)
        pthread_mutex_unlock(mtx);
}

WINAPI_EXPORT void KeAcquireSpinLockAtDpcLevel(PKSPIN_LOCK SpinLock)
{
    pthread_mutex_t *mtx = (pthread_mutex_t *)(uintptr_t)*SpinLock;
    if (mtx)
        pthread_mutex_lock(mtx);
}

WINAPI_EXPORT void KeReleaseSpinLockFromDpcLevel(PKSPIN_LOCK SpinLock)
{
    pthread_mutex_t *mtx = (pthread_mutex_t *)(uintptr_t)*SpinLock;
    if (mtx)
        pthread_mutex_unlock(mtx);
}

/* ===== IRQL (no-ops in userspace) ===== */

WINAPI_EXPORT KIRQL KeGetCurrentIrql(void)
{
    return PASSIVE_LEVEL;
}

WINAPI_EXPORT KIRQL KeRaiseIrqlToDpcLevel(void)
{
    return PASSIVE_LEVEL;
}

WINAPI_EXPORT void KeLowerIrql(KIRQL NewIrql)
{
    (void)NewIrql;
}

WINAPI_EXPORT void KeRaiseIrql(KIRQL NewIrql, PKIRQL OldIrql)
{
    if (OldIrql)
        *OldIrql = PASSIVE_LEVEL;
    (void)NewIrql;
}

/* ===== Events ===== */

/*
 * KEVENT._internal layout:
 *   [0] = pthread_mutex_t*
 *   [1] = pthread_cond_t*
 *   [2] = (uintptr_t) event type (Notification or Synchronization)
 *   [3] = unused
 */

WINAPI_EXPORT void KeInitializeEvent(
    PKEVENT Event, EVENT_TYPE Type, BOOLEAN State)
{
    if (!Event) return;
    pthread_mutex_t *mtx = (pthread_mutex_t *)calloc(1, sizeof(pthread_mutex_t));
    pthread_cond_t *cond = (pthread_cond_t *)calloc(1, sizeof(pthread_cond_t));
    if (mtx && cond) {
        pthread_mutex_init(mtx, NULL);
        pthread_cond_init(cond, NULL);
        Event->_internal[0] = mtx;
        Event->_internal[1] = cond;
        Event->_internal[2] = (PVOID)(uintptr_t)Type;
    } else {
        /* H5 audit fix: clean up partial allocation */
        free(mtx);
        free(cond);
        Event->_internal[0] = NULL;
        Event->_internal[1] = NULL;
        Event->_internal[2] = (PVOID)(uintptr_t)Type;
    }
    Event->Header.SignalState = State ? 1 : 0;
}

WINAPI_EXPORT LONG KeSetEvent(PKEVENT Event, LONG Increment, BOOLEAN Wait)
{
    (void)Increment;
    (void)Wait;
    LONG prev = Event->Header.SignalState;
    pthread_mutex_t *mtx = (pthread_mutex_t *)Event->_internal[0];
    pthread_cond_t *cond = (pthread_cond_t *)Event->_internal[1];
    if (mtx && cond) {
        pthread_mutex_lock(mtx);
        Event->Header.SignalState = 1;
        pthread_cond_broadcast(cond);
        pthread_mutex_unlock(mtx);
    }
    return prev;
}

WINAPI_EXPORT void KeResetEvent(PKEVENT Event)
{
    pthread_mutex_t *mtx = (pthread_mutex_t *)Event->_internal[0];
    if (mtx) {
        pthread_mutex_lock(mtx);
        Event->Header.SignalState = 0;
        pthread_mutex_unlock(mtx);
    }
}

WINAPI_EXPORT void KeClearEvent(PKEVENT Event)
{
    KeResetEvent(Event);
}

WINAPI_EXPORT NTSTATUS KeWaitForSingleObject(
    PVOID Object, ULONG WaitReason, UCHAR WaitMode,
    BOOLEAN Alertable, LARGE_INTEGER *Timeout)
{
    (void)WaitReason;
    (void)WaitMode;
    (void)Alertable;

    /* We treat the Object as a KEVENT */
    PKEVENT event = (PKEVENT)Object;
    pthread_mutex_t *mtx = (pthread_mutex_t *)event->_internal[0];
    pthread_cond_t *cond = (pthread_cond_t *)event->_internal[1];

    if (!mtx || !cond)
        return STATUS_SUCCESS;

    pthread_mutex_lock(mtx);

    if (Timeout && Timeout->QuadPart == 0) {
        /* Non-blocking check */
        NTSTATUS result = event->Header.SignalState ? STATUS_SUCCESS : STATUS_TIMEOUT;
        if (result == STATUS_SUCCESS) {
            EVENT_TYPE type = (EVENT_TYPE)(uintptr_t)event->_internal[2];
            if (type == SynchronizationEvent)
                event->Header.SignalState = 0;
        }
        pthread_mutex_unlock(mtx);
        return result;
    }

    while (!event->Header.SignalState) {
        if (Timeout) {
            /* Convert 100ns intervals to timespec */
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            long long ns = (-Timeout->QuadPart) * 100; /* negative = relative */
            ts.tv_sec += ns / 1000000000LL;
            ts.tv_nsec += ns % 1000000000LL;
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000L;
            }
            int rc = pthread_cond_timedwait(cond, mtx, &ts);
            if (rc != 0) {
                pthread_mutex_unlock(mtx);
                return STATUS_TIMEOUT;
            }
        } else {
            pthread_cond_wait(cond, mtx);
        }
    }

    /* Auto-reset for synchronization events */
    EVENT_TYPE type = (EVENT_TYPE)(uintptr_t)event->_internal[2];
    if (type == SynchronizationEvent)
        event->Header.SignalState = 0;

    pthread_mutex_unlock(mtx);
    return STATUS_SUCCESS;
}

/* ===== Timer ===== */

WINAPI_EXPORT void KeInitializeTimer(PKTIMER Timer)
{
    memset(Timer, 0, sizeof(KTIMER));
}

WINAPI_EXPORT void KeInitializeTimerEx(PKTIMER Timer, ULONG Type)
{
    (void)Type;
    memset(Timer, 0, sizeof(KTIMER));
}

WINAPI_EXPORT BOOLEAN KeSetTimer(
    PKTIMER Timer, LARGE_INTEGER DueTime, PKDPC Dpc)
{
    (void)Timer;
    (void)DueTime;
    (void)Dpc;
    /* Stub: timers not fully emulated */
    return FALSE;
}

WINAPI_EXPORT BOOLEAN KeCancelTimer(PKTIMER Timer)
{
    (void)Timer;
    return FALSE;
}

/* ===== Delay ===== */

WINAPI_EXPORT NTSTATUS KeDelayExecutionThread(
    UCHAR WaitMode, BOOLEAN Alertable, LARGE_INTEGER *Interval)
{
    (void)WaitMode;
    (void)Alertable;

    if (Interval) {
        /* Convert 100ns units to microseconds. Negative = relative time. */
        long long hundred_ns = Interval->QuadPart < 0 ? -Interval->QuadPart : Interval->QuadPart;
        long long us_total = hundred_ns / 10;
        /* usleep rejects values >= 1000000; split into sleep() + usleep() */
        while (us_total > 0) {
            long long chunk = us_total > 999999LL ? 999999LL : us_total;
            usleep((useconds_t)chunk);
            us_total -= chunk;
        }
    }

    return STATUS_SUCCESS;
}

/* ===== DPC ===== */

WINAPI_EXPORT void KeInitializeDpc(
    PKDPC Dpc, PKDEFERRED_ROUTINE DeferredRoutine, PVOID DeferredContext)
{
    if (Dpc) {
        memset(Dpc, 0, sizeof(KDPC));
        Dpc->DeferredRoutine = (PVOID)DeferredRoutine;
        Dpc->DeferredContext = DeferredContext;
    }
}

WINAPI_EXPORT BOOLEAN KeInsertQueueDpc(
    PKDPC Dpc, PVOID SystemArgument1, PVOID SystemArgument2)
{
    (void)Dpc;
    (void)SystemArgument1;
    (void)SystemArgument2;
    /* DPCs not implemented in userspace */
    return TRUE;
}
