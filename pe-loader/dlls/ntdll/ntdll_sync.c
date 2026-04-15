/*
 * ntdll_sync.c - NT native synchronization primitives
 *
 * NtCreateEvent, NtCreateMutant, RtlInitializeCriticalSection, etc.
 * Also includes Rtl* variants that many CRT libraries call directly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include "common/dll_common.h"

#ifndef STATUS_MUTANT_NOT_OWNED
#define STATUS_MUTANT_NOT_OWNED ((NTSTATUS)0xC0000046)
#endif

/* Event data for NT events */
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    int             signaled;
    int             manual_reset;
} nt_event_data_t;

/* Mutant (mutex) data */
typedef struct {
    pthread_mutex_t mutex;
    DWORD           owner;
    LONG            count;
} nt_mutant_data_t;

/* Semaphore data */
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    LONG            count;
    LONG            max_count;
} nt_semaphore_data_t;

/* RTL_CRITICAL_SECTION (Windows layout) */
typedef struct {
    PVOID  DebugInfo;
    LONG   LockCount;
    LONG   RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
} RTL_CRITICAL_SECTION;

/* We store the actual pthread_mutex in DebugInfo slot */
typedef struct {
    pthread_mutex_t mutex;
} cs_internal_t;

/* --- Events --- */

WINAPI_EXPORT NTSTATUS NtCreateEvent(
    HANDLE *EventHandle,
    DWORD DesiredAccess,
    PVOID ObjectAttributes,
    ULONG EventType,
    BOOL InitialState)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;

    if (!EventHandle)
        return STATUS_INVALID_PARAMETER;

    nt_event_data_t *evt = calloc(1, sizeof(nt_event_data_t));
    if (!evt)
        return STATUS_UNSUCCESSFUL;

    pthread_mutex_init(&evt->mutex, NULL);
    pthread_cond_init(&evt->cond, NULL);
    evt->signaled = InitialState ? 1 : 0;
    evt->manual_reset = (EventType == 0) ? 1 : 0; /* NotificationEvent=0, SynchronizationEvent=1 */

    HANDLE h = handle_alloc(HANDLE_TYPE_EVENT, -1, evt);
    if (h == INVALID_HANDLE_VALUE) {
        pthread_cond_destroy(&evt->cond);
        pthread_mutex_destroy(&evt->mutex);
        free(evt);
        *EventHandle = NULL;
        return STATUS_UNSUCCESSFUL;
    }
    *EventHandle = h;
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtSetEvent(HANDLE EventHandle, PLONG PreviousState)
{
    handle_entry_t *entry = handle_lookup(EventHandle);
    if (!entry || entry->type != HANDLE_TYPE_EVENT)
        return STATUS_INVALID_HANDLE;

    nt_event_data_t *evt = (nt_event_data_t *)entry->data;
    if (!evt)
        return STATUS_INVALID_HANDLE;
    pthread_mutex_lock(&evt->mutex);
    int prev = evt->signaled;
    evt->signaled = 1;
    if (evt->manual_reset)
        pthread_cond_broadcast(&evt->cond);
    else
        pthread_cond_signal(&evt->cond);
    pthread_mutex_unlock(&evt->mutex);

    if (PreviousState)
        *PreviousState = prev;
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtResetEvent(HANDLE EventHandle, PLONG PreviousState)
{
    handle_entry_t *entry = handle_lookup(EventHandle);
    if (!entry || entry->type != HANDLE_TYPE_EVENT)
        return STATUS_INVALID_HANDLE;

    nt_event_data_t *evt = (nt_event_data_t *)entry->data;
    if (!evt)
        return STATUS_INVALID_HANDLE;
    pthread_mutex_lock(&evt->mutex);
    int prev = evt->signaled;
    evt->signaled = 0;
    pthread_mutex_unlock(&evt->mutex);

    if (PreviousState)
        *PreviousState = prev;
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtPulseEvent(HANDLE EventHandle, PLONG PreviousState)
{
    handle_entry_t *entry = handle_lookup(EventHandle);
    if (!entry || entry->type != HANDLE_TYPE_EVENT)
        return STATUS_INVALID_HANDLE;

    nt_event_data_t *evt = (nt_event_data_t *)entry->data;
    if (!evt)
        return STATUS_INVALID_HANDLE;
    pthread_mutex_lock(&evt->mutex);
    int prev = evt->signaled;
    evt->signaled = 1;
    if (evt->manual_reset)
        pthread_cond_broadcast(&evt->cond);
    else
        pthread_cond_signal(&evt->cond);
    evt->signaled = 0;
    pthread_mutex_unlock(&evt->mutex);

    if (PreviousState)
        *PreviousState = prev;
    return STATUS_SUCCESS;
}

/* --- Mutants (Mutexes) --- */

WINAPI_EXPORT NTSTATUS NtCreateMutant(
    HANDLE *MutantHandle,
    DWORD DesiredAccess,
    PVOID ObjectAttributes,
    BOOL InitialOwner)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;

    if (!MutantHandle)
        return STATUS_INVALID_PARAMETER;

    nt_mutant_data_t *mtx = calloc(1, sizeof(nt_mutant_data_t));
    if (!mtx)
        return STATUS_UNSUCCESSFUL;

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&mtx->mutex, &attr);
    pthread_mutexattr_destroy(&attr);

    if (InitialOwner) {
        pthread_mutex_lock(&mtx->mutex);
        mtx->count = 1;
    }

    HANDLE h = handle_alloc(HANDLE_TYPE_MUTEX, -1, mtx);
    if (h == INVALID_HANDLE_VALUE) {
        if (InitialOwner)
            pthread_mutex_unlock(&mtx->mutex);
        pthread_mutex_destroy(&mtx->mutex);
        free(mtx);
        *MutantHandle = NULL;
        return STATUS_UNSUCCESSFUL;
    }
    *MutantHandle = h;
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtReleaseMutant(HANDLE MutantHandle, PLONG PreviousCount)
{
    handle_entry_t *entry = handle_lookup(MutantHandle);
    if (!entry || entry->type != HANDLE_TYPE_MUTEX)
        return STATUS_INVALID_HANDLE;

    nt_mutant_data_t *mtx = (nt_mutant_data_t *)entry->data;
    if (!mtx)
        return STATUS_INVALID_HANDLE;
    if (PreviousCount)
        *PreviousCount = mtx->count;
    /* Only actually release if we held it. Recursive pthread_mutex_unlock on
     * an unheld mutex returns EPERM and leaves state intact — calling it
     * anyway raises warnings and clobbers errno for no benefit. */
    if (mtx->count > 0) {
        mtx->count--;
        pthread_mutex_unlock(&mtx->mutex);
    } else {
        return STATUS_MUTANT_NOT_OWNED;
    }
    return STATUS_SUCCESS;
}

/* --- Semaphores --- */

WINAPI_EXPORT NTSTATUS NtCreateSemaphore(
    HANDLE *SemaphoreHandle,
    DWORD DesiredAccess,
    PVOID ObjectAttributes,
    LONG InitialCount,
    LONG MaximumCount)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;

    if (!SemaphoreHandle)
        return STATUS_INVALID_PARAMETER;

    nt_semaphore_data_t *sem = calloc(1, sizeof(nt_semaphore_data_t));
    if (!sem)
        return STATUS_UNSUCCESSFUL;

    pthread_mutex_init(&sem->mutex, NULL);
    pthread_cond_init(&sem->cond, NULL);
    sem->count = InitialCount;
    sem->max_count = MaximumCount;

    HANDLE h = handle_alloc(HANDLE_TYPE_SEMAPHORE, -1, sem);
    if (h == INVALID_HANDLE_VALUE) {
        pthread_cond_destroy(&sem->cond);
        pthread_mutex_destroy(&sem->mutex);
        free(sem);
        *SemaphoreHandle = NULL;
        return STATUS_UNSUCCESSFUL;
    }
    *SemaphoreHandle = h;
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtReleaseSemaphore(
    HANDLE SemaphoreHandle,
    LONG ReleaseCount,
    PLONG PreviousCount)
{
    handle_entry_t *entry = handle_lookup(SemaphoreHandle);
    if (!entry || entry->type != HANDLE_TYPE_SEMAPHORE)
        return STATUS_INVALID_HANDLE;

    nt_semaphore_data_t *sem = (nt_semaphore_data_t *)entry->data;
    if (!sem)
        return STATUS_INVALID_HANDLE;
    pthread_mutex_lock(&sem->mutex);

    if (PreviousCount)
        *PreviousCount = sem->count;

    sem->count += ReleaseCount;
    if (sem->count > sem->max_count)
        sem->count = sem->max_count;

    /* Wake exactly one waiter for a single release, otherwise broadcast.
     * The previous N-signal loop could wake 1 real waiter plus consume
     * spurious-wakeup budget on empty queues; broadcast is both faster
     * and lets every sleeper re-check sem->count under the mutex. */
    if (ReleaseCount <= 1)
        pthread_cond_signal(&sem->cond);
    else
        pthread_cond_broadcast(&sem->cond);

    pthread_mutex_unlock(&sem->mutex);
    return STATUS_SUCCESS;
}

/* --- Critical Section (RTL layer) --- */

WINAPI_EXPORT NTSTATUS RtlInitializeCriticalSection(RTL_CRITICAL_SECTION *cs)
{
    if (!cs)
        return STATUS_INVALID_PARAMETER;

    cs_internal_t *internal = calloc(1, sizeof(cs_internal_t));
    if (!internal)
        return STATUS_UNSUCCESSFUL;

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&internal->mutex, &attr);
    pthread_mutexattr_destroy(&attr);

    cs->DebugInfo = internal;
    cs->LockCount = -1;
    cs->RecursionCount = 0;
    cs->OwningThread = NULL;
    cs->LockSemaphore = NULL;
    cs->SpinCount = 0;

    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS RtlInitializeCriticalSectionAndSpinCount(
    RTL_CRITICAL_SECTION *cs, ULONG SpinCount)
{
    NTSTATUS status = RtlInitializeCriticalSection(cs);
    if (status == STATUS_SUCCESS)
        cs->SpinCount = SpinCount;
    return status;
}

WINAPI_EXPORT NTSTATUS RtlInitializeCriticalSectionEx(
    RTL_CRITICAL_SECTION *cs, ULONG SpinCount, ULONG Flags)
{
    (void)Flags;
    return RtlInitializeCriticalSectionAndSpinCount(cs, SpinCount);
}

WINAPI_EXPORT NTSTATUS RtlEnterCriticalSection(RTL_CRITICAL_SECTION *cs)
{
    if (!cs || !cs->DebugInfo)
        return STATUS_INVALID_PARAMETER;

    cs_internal_t *internal = (cs_internal_t *)cs->DebugInfo;
    pthread_mutex_lock(&internal->mutex);
    cs->RecursionCount++;
    cs->LockCount++;
    return STATUS_SUCCESS;
}

WINAPI_EXPORT BOOL RtlTryEnterCriticalSection(RTL_CRITICAL_SECTION *cs)
{
    if (!cs || !cs->DebugInfo)
        return FALSE;

    cs_internal_t *internal = (cs_internal_t *)cs->DebugInfo;
    if (pthread_mutex_trylock(&internal->mutex) == 0) {
        cs->RecursionCount++;
        cs->LockCount++;
        return TRUE;
    }
    return FALSE;
}

WINAPI_EXPORT NTSTATUS RtlLeaveCriticalSection(RTL_CRITICAL_SECTION *cs)
{
    if (!cs || !cs->DebugInfo)
        return STATUS_INVALID_PARAMETER;

    cs_internal_t *internal = (cs_internal_t *)cs->DebugInfo;
    cs->RecursionCount--;
    cs->LockCount--;
    if (cs->RecursionCount == 0)
        cs->OwningThread = NULL;
    pthread_mutex_unlock(&internal->mutex);
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS RtlDeleteCriticalSection(RTL_CRITICAL_SECTION *cs)
{
    if (!cs)
        return STATUS_INVALID_PARAMETER;

    if (cs->DebugInfo) {
        cs_internal_t *internal = (cs_internal_t *)cs->DebugInfo;
        pthread_mutex_destroy(&internal->mutex);
        free(internal);
        cs->DebugInfo = NULL;
    }
    return STATUS_SUCCESS;
}

/* --- SRW Locks (Slim Reader/Writer) --- */

typedef struct {
    pthread_rwlock_t rwlock;
} srw_internal_t;

/*
 * Windows SRWLOCK can be zero-initialized via SRWLOCK_INIT; PE binaries
 * frequently acquire such locks without calling InitializeSRWLock first.
 * Lazily allocate the pthread backing on first use via a double-CAS so
 * concurrent first-acquirers don't leak duplicate internals.
 */
static srw_internal_t *srw_get_or_init(PVOID SRWLock)
{
    srw_internal_t *cur = __atomic_load_n((srw_internal_t **)SRWLock,
                                          __ATOMIC_ACQUIRE);
    if (cur)
        return cur;

    srw_internal_t *new_lock = calloc(1, sizeof(srw_internal_t));
    if (!new_lock)
        return NULL;
    pthread_rwlock_init(&new_lock->rwlock, NULL);

    srw_internal_t *expected = NULL;
    if (__atomic_compare_exchange_n((srw_internal_t **)SRWLock,
                                    &expected, new_lock,
                                    0, __ATOMIC_ACQ_REL,
                                    __ATOMIC_ACQUIRE)) {
        return new_lock;
    }

    /* Lost the race: free our unused struct and use the winner's */
    pthread_rwlock_destroy(&new_lock->rwlock);
    free(new_lock);
    return expected;
}

WINAPI_EXPORT void RtlInitializeSRWLock(PVOID SRWLock)
{
    /* Idempotent: srw_get_or_init will allocate lazily. Explicit init is
     * still supported so callers that do InitializeSRWLock get the backing
     * ready before first acquire. */
    (void)srw_get_or_init(SRWLock);
}

WINAPI_EXPORT void RtlAcquireSRWLockExclusive(PVOID SRWLock)
{
    srw_internal_t *internal = srw_get_or_init(SRWLock);
    if (internal)
        pthread_rwlock_wrlock(&internal->rwlock);
}

WINAPI_EXPORT void RtlReleaseSRWLockExclusive(PVOID SRWLock)
{
    srw_internal_t *internal = __atomic_load_n((srw_internal_t **)SRWLock,
                                                __ATOMIC_ACQUIRE);
    if (internal)
        pthread_rwlock_unlock(&internal->rwlock);
}

WINAPI_EXPORT void RtlAcquireSRWLockShared(PVOID SRWLock)
{
    srw_internal_t *internal = srw_get_or_init(SRWLock);
    if (internal)
        pthread_rwlock_rdlock(&internal->rwlock);
}

WINAPI_EXPORT void RtlReleaseSRWLockShared(PVOID SRWLock)
{
    srw_internal_t *internal = __atomic_load_n((srw_internal_t **)SRWLock,
                                                __ATOMIC_ACQUIRE);
    if (internal)
        pthread_rwlock_unlock(&internal->rwlock);
}

WINAPI_EXPORT BOOL RtlTryAcquireSRWLockExclusive(PVOID SRWLock)
{
    srw_internal_t *internal = srw_get_or_init(SRWLock);
    if (internal)
        return pthread_rwlock_trywrlock(&internal->rwlock) == 0;
    return FALSE;
}

WINAPI_EXPORT BOOL RtlTryAcquireSRWLockShared(PVOID SRWLock)
{
    srw_internal_t *internal = srw_get_or_init(SRWLock);
    if (internal)
        return pthread_rwlock_tryrdlock(&internal->rwlock) == 0;
    return FALSE;
}

/* --- Condition Variables --- */

typedef struct {
    pthread_cond_t cond;
} cv_internal_t;

/* Same zero-init-safe pattern as SRW: CONDITION_VARIABLE_INIT is NULL. */
static cv_internal_t *cv_get_or_init(PVOID ConditionVariable)
{
    cv_internal_t *cur = __atomic_load_n((cv_internal_t **)ConditionVariable,
                                          __ATOMIC_ACQUIRE);
    if (cur)
        return cur;

    cv_internal_t *new_cv = calloc(1, sizeof(cv_internal_t));
    if (!new_cv)
        return NULL;
    pthread_cond_init(&new_cv->cond, NULL);

    cv_internal_t *expected = NULL;
    if (__atomic_compare_exchange_n((cv_internal_t **)ConditionVariable,
                                    &expected, new_cv,
                                    0, __ATOMIC_ACQ_REL,
                                    __ATOMIC_ACQUIRE)) {
        return new_cv;
    }

    pthread_cond_destroy(&new_cv->cond);
    free(new_cv);
    return expected;
}

WINAPI_EXPORT void RtlInitializeConditionVariable(PVOID ConditionVariable)
{
    (void)cv_get_or_init(ConditionVariable);
}

WINAPI_EXPORT NTSTATUS RtlSleepConditionVariableCS(
    PVOID ConditionVariable,
    RTL_CRITICAL_SECTION *CriticalSection,
    PLARGE_INTEGER Timeout)
{
    cv_internal_t *cv = cv_get_or_init(ConditionVariable);
    cs_internal_t *cs = CriticalSection ?
        (cs_internal_t *)CriticalSection->DebugInfo : NULL;

    if (!cv || !cs)
        return STATUS_INVALID_PARAMETER;

    if (Timeout) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        LONGLONG interval = Timeout->QuadPart;
        if (interval < 0) interval = -interval;
        LONGLONG ns = interval * 100;
        ts.tv_sec += ns / 1000000000LL;
        ts.tv_nsec += ns % 1000000000LL;
        if (ts.tv_nsec >= 1000000000LL) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000LL;
        }
        int ret = pthread_cond_timedwait(&cv->cond, &cs->mutex, &ts);
        return ret == 0 ? STATUS_SUCCESS : STATUS_TIMEOUT;
    }

    pthread_cond_wait(&cv->cond, &cs->mutex);
    return STATUS_SUCCESS;
}

WINAPI_EXPORT void RtlWakeConditionVariable(PVOID ConditionVariable)
{
    /* Wake is a no-op if no one ever waited (no backing cv allocated).
     * Use a plain atomic load so we don't allocate on wake-only callsites. */
    cv_internal_t *cv = __atomic_load_n((cv_internal_t **)ConditionVariable,
                                         __ATOMIC_ACQUIRE);
    if (cv)
        pthread_cond_signal(&cv->cond);
}

WINAPI_EXPORT void RtlWakeAllConditionVariable(PVOID ConditionVariable)
{
    cv_internal_t *cv = __atomic_load_n((cv_internal_t **)ConditionVariable,
                                         __ATOMIC_ACQUIRE);
    if (cv)
        pthread_cond_broadcast(&cv->cond);
}
