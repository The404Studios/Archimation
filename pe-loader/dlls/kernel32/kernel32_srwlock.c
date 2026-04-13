/*
 * kernel32_srwlock.c - SRWLock, InitOnce, ConditionVariable
 *
 * Modern Windows synchronization primitives backed by pthreads.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>

#include "common/dll_common.h"
#include "compat/abi_bridge.h"

/* ========== SRWLock ==========
 * Slim Reader/Writer Lock - backed by pthread_rwlock_t.
 * SRWLOCK is a pointer-sized value (8 bytes on x64).
 * We store a pthread_rwlock_t pointer in it.
 */

typedef struct {
    pthread_rwlock_t rwlock;
} srwlock_data_t;

static srwlock_data_t *get_srwlock(void *SRWLock)
{
    void **ptr = (void **)SRWLock;
    if (!*ptr) {
        srwlock_data_t *data = calloc(1, sizeof(srwlock_data_t));
        if (!data) return NULL;
        pthread_rwlock_init(&data->rwlock, NULL);
        /* Atomic CAS to handle race */
        if (!__sync_bool_compare_and_swap(ptr, NULL, data)) {
            pthread_rwlock_destroy(&data->rwlock);
            free(data);
        }
    }
    return (srwlock_data_t *)*ptr;
}

WINAPI_EXPORT void InitializeSRWLock(void *SRWLock)
{
    void **ptr = (void **)SRWLock;
    srwlock_data_t *data = calloc(1, sizeof(srwlock_data_t));
    if (data) {
        pthread_rwlock_init(&data->rwlock, NULL);
        *ptr = data;
    }
}

WINAPI_EXPORT void AcquireSRWLockExclusive(void *SRWLock)
{
    srwlock_data_t *data = get_srwlock(SRWLock);
    if (data) pthread_rwlock_wrlock(&data->rwlock);
}

WINAPI_EXPORT void AcquireSRWLockShared(void *SRWLock)
{
    srwlock_data_t *data = get_srwlock(SRWLock);
    if (data) pthread_rwlock_rdlock(&data->rwlock);
}

WINAPI_EXPORT void ReleaseSRWLockExclusive(void *SRWLock)
{
    srwlock_data_t *data = get_srwlock(SRWLock);
    if (data) pthread_rwlock_unlock(&data->rwlock);
}

WINAPI_EXPORT void ReleaseSRWLockShared(void *SRWLock)
{
    srwlock_data_t *data = get_srwlock(SRWLock);
    if (data) pthread_rwlock_unlock(&data->rwlock);
}

WINAPI_EXPORT BOOL TryAcquireSRWLockExclusive(void *SRWLock)
{
    srwlock_data_t *data = get_srwlock(SRWLock);
    if (!data) return FALSE;
    return pthread_rwlock_trywrlock(&data->rwlock) == 0 ? TRUE : FALSE;
}

WINAPI_EXPORT BOOL TryAcquireSRWLockShared(void *SRWLock)
{
    srwlock_data_t *data = get_srwlock(SRWLock);
    if (!data) return FALSE;
    return pthread_rwlock_tryrdlock(&data->rwlock) == 0 ? TRUE : FALSE;
}

/* ========== InitOnce ==========
 * INIT_ONCE is a pointer-sized value. We use it as a state machine:
 *   0 = not started, 1 = in progress, 2 = completed
 */

#define INIT_ONCE_NOT_STARTED   0
#define INIT_ONCE_IN_PROGRESS   1
#define INIT_ONCE_COMPLETED     2

typedef BOOL (*PINIT_ONCE_FN)(void *InitOnce, PVOID Parameter, PVOID *Context);

WINAPI_EXPORT void InitOnceInitialize(void *InitOnce)
{
    *(volatile long *)InitOnce = INIT_ONCE_NOT_STARTED;
}

WINAPI_EXPORT BOOL InitOnceExecuteOnce(void *InitOnce, PINIT_ONCE_FN InitFn,
                                        PVOID Parameter, PVOID *Context)
{
    volatile long *state = (volatile long *)InitOnce;

    while (1) {
        long cur = __sync_val_compare_and_swap(state, INIT_ONCE_NOT_STARTED, INIT_ONCE_IN_PROGRESS);
        if (cur == INIT_ONCE_COMPLETED)
            return TRUE;
        if (cur == INIT_ONCE_NOT_STARTED) {
            /* We won the race, execute the callback via ABI bridge */
            BOOL result = (BOOL)abi_call_win64_3((void *)InitFn,
                (uint64_t)(uintptr_t)InitOnce,
                (uint64_t)(uintptr_t)Parameter,
                (uint64_t)(uintptr_t)Context);
            if (result) {
                __sync_lock_test_and_set(state, INIT_ONCE_COMPLETED);
                return TRUE;
            } else {
                __sync_lock_test_and_set(state, INIT_ONCE_NOT_STARTED);
                return FALSE;
            }
        }
        /* Another thread is initializing, spin-wait */
        sched_yield();
    }
}

WINAPI_EXPORT BOOL InitOnceBeginInitialize(void *InitOnce, DWORD dwFlags,
                                            BOOL *fPending, PVOID *lpContext)
{
    volatile long *state = (volatile long *)InitOnce;
    (void)lpContext;

    if (dwFlags & 0x2) { /* INIT_ONCE_CHECK_ONLY */
        if (*state == INIT_ONCE_COMPLETED) {
            if (fPending) *fPending = FALSE;
            return TRUE;
        }
        set_last_error(ERROR_GEN_FAILURE);
        return FALSE;
    }

    while (1) {
        long cur = __sync_val_compare_and_swap(state, INIT_ONCE_NOT_STARTED, INIT_ONCE_IN_PROGRESS);
        if (cur == INIT_ONCE_COMPLETED) {
            if (fPending) *fPending = FALSE;
            return TRUE;
        }
        if (cur == INIT_ONCE_NOT_STARTED) {
            if (fPending) *fPending = TRUE;
            return TRUE;
        }
        sched_yield();
    }
}

WINAPI_EXPORT BOOL InitOnceComplete(void *InitOnce, DWORD dwFlags, PVOID lpContext)
{
    volatile long *state = (volatile long *)InitOnce;
    (void)dwFlags;
    (void)lpContext;
    __sync_lock_test_and_set(state, INIT_ONCE_COMPLETED);
    return TRUE;
}

/* ========== ConditionVariable ==========
 * CONDITION_VARIABLE is a pointer-sized value.
 * We store a paired pthread_cond_t + pthread_mutex_t.
 *
 * The mutex is essential: pthread_cond_wait/signal require the waiter
 * and waker to coordinate through the SAME mutex. A stack-local mutex
 * in SleepConditionVariableSRW would cause missed wakeups because the
 * waker (WakeConditionVariable) never holds that mutex.
 */

typedef struct {
    pthread_cond_t  cond;
    pthread_mutex_t mutex;
} condvar_data_t;

static condvar_data_t *get_condvar(void *ConditionVariable)
{
    void **ptr = (void **)ConditionVariable;
    if (!*ptr) {
        condvar_data_t *data = calloc(1, sizeof(condvar_data_t));
        if (!data) return NULL;
        pthread_cond_init(&data->cond, NULL);
        pthread_mutex_init(&data->mutex, NULL);
        if (!__sync_bool_compare_and_swap(ptr, NULL, data)) {
            pthread_cond_destroy(&data->cond);
            pthread_mutex_destroy(&data->mutex);
            free(data);
        }
    }
    return (condvar_data_t *)*ptr;
}

WINAPI_EXPORT void InitializeConditionVariable(void *ConditionVariable)
{
    void **ptr = (void **)ConditionVariable;
    condvar_data_t *data = calloc(1, sizeof(condvar_data_t));
    if (data) {
        pthread_cond_init(&data->cond, NULL);
        pthread_mutex_init(&data->mutex, NULL);
        *ptr = data;
    }
}

WINAPI_EXPORT BOOL SleepConditionVariableCS(void *ConditionVariable,
                                             void *CriticalSection,
                                             DWORD dwMilliseconds)
{
    condvar_data_t *cv = get_condvar(ConditionVariable);
    if (!cv) return FALSE;

    /* CriticalSection contains a pthread_mutex_t at offset 0 (heap_cs_t layout) */
    /* But CRITICAL_SECTION is passed as raw pointer from Windows code.
     * The first pointer-sized field of CRITICAL_SECTION in our impl
     * stores a pointer to heap_cs_t. */
    void **cs_ptr = (void **)CriticalSection;
    /* Our CRITICAL_SECTION: DebugInfo(ptr), LockCount(LONG), RecursionCount(LONG),
     * OwningThread(HANDLE), LockSemaphore(HANDLE), SpinCount(ULONG_PTR)
     * The DebugInfo pointer actually points to our heap_cs_t. */
    typedef struct {
        pthread_mutex_t mutex;
        DWORD owner_thread;
        LONG lock_count;
        LONG recursion_count;
    } heap_cs_t;
    heap_cs_t *hcs = (heap_cs_t *)cs_ptr[0];
    if (!hcs) return FALSE;

    if (dwMilliseconds == 0xFFFFFFFF) { /* INFINITE */
        pthread_cond_wait(&cv->cond, &hcs->mutex);
        return TRUE;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += dwMilliseconds / 1000;
    ts.tv_nsec += (long)(dwMilliseconds % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }

    int rc = pthread_cond_timedwait(&cv->cond, &hcs->mutex, &ts);
    if (rc == ETIMEDOUT) {
        set_last_error(ERROR_TIMEOUT);
        return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL SleepConditionVariableSRW(void *ConditionVariable,
                                              void *SRWLock,
                                              DWORD dwMilliseconds,
                                              ULONG Flags)
{
    condvar_data_t *cv = get_condvar(ConditionVariable);
    srwlock_data_t *srw = get_srwlock(SRWLock);
    if (!cv || !srw) return FALSE;

    /* pthread_cond_wait requires a mutex. We use the per-condvar mutex
     * so that WakeConditionVariable/WakeAllConditionVariable (which
     * lock the same mutex) cannot signal between our unlock-of-SRW and
     * our entry into cond_wait -- eliminating the missed-wakeup race. */
    int shared = (Flags & 0x1); /* CONDITION_VARIABLE_LOCKMODE_SHARED */

    /* 1. Lock the condvar's mutex */
    pthread_mutex_lock(&cv->mutex);

    /* 2. Release the SRW lock (caller held it on entry) */
    pthread_rwlock_unlock(&srw->rwlock);

    /* 3. Wait on the condvar with the condvar's own mutex */
    BOOL result = TRUE;
    if (dwMilliseconds == 0xFFFFFFFF) {
        pthread_cond_wait(&cv->cond, &cv->mutex);
    } else {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += dwMilliseconds / 1000;
        ts.tv_nsec += (long)(dwMilliseconds % 1000) * 1000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }
        int rc = pthread_cond_timedwait(&cv->cond, &cv->mutex, &ts);
        if (rc == ETIMEDOUT) {
            set_last_error(ERROR_TIMEOUT);
            result = FALSE;
        }
    }

    /* 4. Unlock the condvar's mutex before re-acquiring SRW */
    pthread_mutex_unlock(&cv->mutex);

    /* 5. Re-acquire the SRW lock */
    if (shared)
        pthread_rwlock_rdlock(&srw->rwlock);
    else
        pthread_rwlock_wrlock(&srw->rwlock);

    return result;
}

WINAPI_EXPORT void WakeConditionVariable(void *ConditionVariable)
{
    condvar_data_t *cv = get_condvar(ConditionVariable);
    if (cv) {
        pthread_mutex_lock(&cv->mutex);
        pthread_cond_signal(&cv->cond);
        pthread_mutex_unlock(&cv->mutex);
    }
}

WINAPI_EXPORT void WakeAllConditionVariable(void *ConditionVariable)
{
    condvar_data_t *cv = get_condvar(ConditionVariable);
    if (cv) {
        pthread_mutex_lock(&cv->mutex);
        pthread_cond_broadcast(&cv->cond);
        pthread_mutex_unlock(&cv->mutex);
    }
}
