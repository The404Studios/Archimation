/*
 * kernel32_threadpool.c - Windows Thread Pool API
 *
 * Implements CreateThreadpoolWork, SubmitThreadpoolWork, etc.
 * Backed by a pool of N worker pthreads and a work queue.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "common/dll_common.h"
#include "compat/abi_bridge.h"

/* Work callback type: void CALLBACK WorkCallback(PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK) */
typedef void (*PTP_WORK_CALLBACK)(void *Instance, void *Context, void *Work);

typedef struct tp_work_item {
    struct tp_work_item *next;
    PTP_WORK_CALLBACK callback;
    void *context;
    void *work_object;
} tp_work_item_t;

typedef struct {
    PTP_WORK_CALLBACK callback;
    void *context;
    volatile int pending_count;
    pthread_mutex_t count_lock;
    pthread_cond_t count_cond;
} tp_work_t;

/* Global thread pool */
#define TP_MAX_THREADS 8
#define TP_HANDLE_MAGIC 0x54504F4F /* 'TPOO' */

static pthread_t g_tp_threads[TP_MAX_THREADS];
static int g_tp_thread_count = 0;
static int g_tp_initialized = 0;

static tp_work_item_t *g_tp_queue_head = NULL;
static tp_work_item_t *g_tp_queue_tail = NULL;
static pthread_mutex_t g_tp_queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_tp_queue_cond = PTHREAD_COND_INITIALIZER;
static volatile int g_tp_shutdown = 0;

static void *tp_worker_thread(void *arg)
{
    (void)arg;
    while (!g_tp_shutdown) {
        tp_work_item_t *item = NULL;

        pthread_mutex_lock(&g_tp_queue_lock);
        while (!g_tp_queue_head && !g_tp_shutdown)
            pthread_cond_wait(&g_tp_queue_cond, &g_tp_queue_lock);

        if (g_tp_shutdown) {
            pthread_mutex_unlock(&g_tp_queue_lock);
            break;
        }

        item = g_tp_queue_head;
        if (item) {
            g_tp_queue_head = item->next;
            if (!g_tp_queue_head)
                g_tp_queue_tail = NULL;
        }
        pthread_mutex_unlock(&g_tp_queue_lock);

        if (item) {
            /* Execute the work callback via ABI bridge (ms_abi -> sysv_abi) */
            if (item->callback)
                abi_call_win64_3((void *)item->callback,
                    (uint64_t)(uintptr_t)NULL,
                    (uint64_t)(uintptr_t)item->context,
                    (uint64_t)(uintptr_t)item->work_object);

            /* Decrement pending count and signal waiters */
            tp_work_t *work = (tp_work_t *)item->work_object;
            if (work) {
                pthread_mutex_lock(&work->count_lock);
                work->pending_count--;
                if (work->pending_count <= 0)
                    pthread_cond_broadcast(&work->count_cond);
                pthread_mutex_unlock(&work->count_lock);
            }

            free(item);
        }
    }
    return NULL;
}

static void ensure_tp_initialized(void)
{
    if (g_tp_initialized) return;

    pthread_mutex_lock(&g_tp_queue_lock);
    if (!g_tp_initialized) {
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        int nthreads = (int)(ncpu > 0 ? ncpu : 4);
        if (nthreads > TP_MAX_THREADS)
            nthreads = TP_MAX_THREADS;

        for (int i = 0; i < nthreads; i++) {
            if (pthread_create(&g_tp_threads[i], NULL, tp_worker_thread, NULL) == 0)
                g_tp_thread_count++;
        }
        g_tp_initialized = 1;
    }
    pthread_mutex_unlock(&g_tp_queue_lock);
}

WINAPI_EXPORT void *CreateThreadpoolWork(
    PTP_WORK_CALLBACK pfnwk,
    void *pv,
    void *pcbe)
{
    (void)pcbe;
    ensure_tp_initialized();

    tp_work_t *work = calloc(1, sizeof(tp_work_t));
    if (!work) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    work->callback = pfnwk;
    work->context = pv;
    work->pending_count = 0;
    pthread_mutex_init(&work->count_lock, NULL);
    pthread_cond_init(&work->count_cond, NULL);

    return work;
}

WINAPI_EXPORT void SubmitThreadpoolWork(void *pwk)
{
    tp_work_t *work = (tp_work_t *)pwk;
    if (!work) return;

    tp_work_item_t *item = calloc(1, sizeof(tp_work_item_t));
    if (!item) return;

    item->callback = work->callback;
    item->context = work->context;
    item->work_object = work;
    item->next = NULL;

    pthread_mutex_lock(&work->count_lock);
    work->pending_count++;
    pthread_mutex_unlock(&work->count_lock);

    pthread_mutex_lock(&g_tp_queue_lock);
    if (g_tp_queue_tail) {
        g_tp_queue_tail->next = item;
        g_tp_queue_tail = item;
    } else {
        g_tp_queue_head = item;
        g_tp_queue_tail = item;
    }
    pthread_cond_signal(&g_tp_queue_cond);
    pthread_mutex_unlock(&g_tp_queue_lock);
}

WINAPI_EXPORT void WaitForThreadpoolWorkCallbacks(void *pwk, BOOL fCancelPendingCallbacks)
{
    tp_work_t *work = (tp_work_t *)pwk;
    if (!work) return;

    if (fCancelPendingCallbacks) {
        /* Remove pending items from queue for this work object */
        pthread_mutex_lock(&g_tp_queue_lock);
        tp_work_item_t *prev = NULL;
        tp_work_item_t *cur = g_tp_queue_head;
        while (cur) {
            tp_work_item_t *next = cur->next;
            if (cur->work_object == work) {
                if (prev)
                    prev->next = next;
                else
                    g_tp_queue_head = next;
                if (cur == g_tp_queue_tail)
                    g_tp_queue_tail = prev;

                pthread_mutex_lock(&work->count_lock);
                work->pending_count--;
                pthread_mutex_unlock(&work->count_lock);

                free(cur);
            } else {
                prev = cur;
            }
            cur = next;
        }
        pthread_mutex_unlock(&g_tp_queue_lock);
    }

    /* Wait for all pending work to complete */
    pthread_mutex_lock(&work->count_lock);
    while (work->pending_count > 0)
        pthread_cond_wait(&work->count_cond, &work->count_lock);
    pthread_mutex_unlock(&work->count_lock);
}

WINAPI_EXPORT void CloseThreadpoolWork(void *pwk)
{
    tp_work_t *work = (tp_work_t *)pwk;
    if (!work) return;

    pthread_mutex_destroy(&work->count_lock);
    pthread_cond_destroy(&work->count_cond);
    free(work);
}

/* Simple thread pool timer stubs */
WINAPI_EXPORT void *CreateThreadpoolTimer(void *pfnti, void *pv, void *pcbe)
{
    (void)pfnti; (void)pv; (void)pcbe;
    return calloc(1, 64); /* Stub */
}

WINAPI_EXPORT void SetThreadpoolTimer(void *pti, void *pftDueTime,
                                       DWORD msPeriod, DWORD msWindowLength)
{
    (void)pti; (void)pftDueTime; (void)msPeriod; (void)msWindowLength;
}

WINAPI_EXPORT void WaitForThreadpoolTimerCallbacks(void *pti, BOOL fCancelPendingCallbacks)
{
    (void)pti; (void)fCancelPendingCallbacks;
}

WINAPI_EXPORT void CloseThreadpoolTimer(void *pti)
{
    free(pti);
}

/* QueueUserWorkItem - legacy thread pool API */
/* PE-side Windows callback: must be ms_abi. */
typedef DWORD (__attribute__((ms_abi)) *LPTHREAD_START_ROUTINE)(LPVOID);

typedef struct {
    LPTHREAD_START_ROUTINE func;
    PVOID context;
} quwi_data_t;

/* Invoked via abi_call_win64_3 from tp_worker_thread, which requires
 * ms_abi calling convention (args in RCX/RDX/R8, not RDI/RSI/RDX). */
static void __attribute__((ms_abi)) quwi_callback(void *Instance, void *Context, void *Work)
{
    (void)Instance; (void)Work;
    quwi_data_t *data = (quwi_data_t *)Context;
    if (data) {
        abi_call_win64_1((void *)data->func, (uint64_t)(uintptr_t)data->context);
        free(data);
    }
}

WINAPI_EXPORT BOOL QueueUserWorkItem(
    LPTHREAD_START_ROUTINE Function,
    PVOID Context,
    ULONG Flags)
{
    (void)Flags;
    ensure_tp_initialized();

    quwi_data_t *data = calloc(1, sizeof(quwi_data_t));
    if (!data) return FALSE;
    data->func = Function;
    data->context = Context;

    tp_work_item_t *item = calloc(1, sizeof(tp_work_item_t));
    if (!item) { free(data); return FALSE; }

    item->callback = (PTP_WORK_CALLBACK)(void *)quwi_callback;
    item->context = data;
    item->work_object = NULL;
    item->next = NULL;

    pthread_mutex_lock(&g_tp_queue_lock);
    if (g_tp_queue_tail) {
        g_tp_queue_tail->next = item;
        g_tp_queue_tail = item;
    } else {
        g_tp_queue_head = item;
        g_tp_queue_tail = item;
    }
    pthread_cond_signal(&g_tp_queue_cond);
    pthread_mutex_unlock(&g_tp_queue_lock);

    return TRUE;
}
