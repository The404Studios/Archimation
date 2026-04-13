/*
 * kernel32_thread.c - Thread management, TLS, Sleep, Wait*
 *
 * CreateThread, ExitThread, TLS, Sleep, SwitchToThread,
 * WaitForSingleObject, WaitForMultipleObjects.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>
#include <time.h>
#include <sched.h>
#include <errno.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <poll.h>
#include <sys/timerfd.h>
#include <linux/futex.h>
#define gettid() syscall(SYS_gettid)

#include "kernel32_internal.h"
#include "pe/pe_tls.h"
#include "compat/objectd_client.h"

/* DLL notification reasons (matching Windows winnt.h values) */
#ifndef DLL_THREAD_ATTACH
#define DLL_THREAD_ATTACH   2
#endif
#ifndef DLL_THREAD_DETACH
#define DLL_THREAD_DETACH   3
#endif

/* Sentinel used by kernel32_sync.c for broker-backed handles */
#define BROKER_HANDLE_FD_SENTINEL  (-42)

static inline int is_broker_handle(handle_entry_t *entry)
{
    return entry && entry->fd == BROKER_HANDLE_FD_SENTINEL;
}

/* Thread-local storage */
#define TLS_MAX_SLOTS 1088
static pthread_key_t g_tls_keys[TLS_MAX_SLOTS];
static int g_tls_used[TLS_MAX_SLOTS] = {0};
static pthread_mutex_t g_tls_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---------- Per-thread APC (Asynchronous Procedure Call) queue ---------- */
/*
 * Windows APC semantics: QueueUserAPC adds a callback to a target thread's
 * queue, which is drained only when the thread enters an alertable wait
 * (SleepEx with bAlertable=TRUE, WaitForSingleObjectEx with bAlertable=TRUE,
 * etc.).  The callback uses ms_abi calling convention.
 *
 * Because __thread variables are only accessible from the owning thread, we
 * use a global hash table keyed by pthread_t to let QueueUserAPC write to
 * another thread's queue.
 */

typedef void (__attribute__((ms_abi)) *PAPCFUNC)(ULONG_PTR dwParam);

typedef struct apc_entry {
    PAPCFUNC          func;
    ULONG_PTR         data;
    struct apc_entry  *next;
} apc_entry_t;

/* Per-thread APC queue node in the global map */
typedef struct apc_queue {
    pthread_t          owner;
    apc_entry_t       *head;
    pthread_mutex_t    lock;
    struct apc_queue  *next;       /* hash chain */
} apc_queue_t;

#define APC_MAP_BUCKETS 64
static apc_queue_t  *g_apc_map[APC_MAP_BUCKETS];
static pthread_mutex_t g_apc_map_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned apc_hash(pthread_t tid)
{
    return (unsigned)(uintptr_t)tid % APC_MAP_BUCKETS;
}

/* Get (or create) the APC queue for a given pthread_t */
static apc_queue_t *apc_queue_get(pthread_t tid, int create)
{
    unsigned bucket = apc_hash(tid);

    pthread_mutex_lock(&g_apc_map_lock);
    apc_queue_t *q = g_apc_map[bucket];
    while (q) {
        if (pthread_equal(q->owner, tid)) {
            pthread_mutex_unlock(&g_apc_map_lock);
            return q;
        }
        q = q->next;
    }
    if (!create) {
        pthread_mutex_unlock(&g_apc_map_lock);
        return NULL;
    }
    /* Allocate new queue node */
    q = calloc(1, sizeof(apc_queue_t));
    if (!q) {
        pthread_mutex_unlock(&g_apc_map_lock);
        return NULL;
    }
    q->owner = tid;
    q->head = NULL;
    pthread_mutex_init(&q->lock, NULL);
    q->next = g_apc_map[bucket];
    g_apc_map[bucket] = q;
    pthread_mutex_unlock(&g_apc_map_lock);
    return q;
}

/* Enqueue an APC to a thread's queue (called from any thread) */
static int apc_enqueue(pthread_t target, PAPCFUNC func, ULONG_PTR data)
{
    apc_queue_t *q = apc_queue_get(target, 1);
    if (!q) return 0;

    apc_entry_t *entry = malloc(sizeof(apc_entry_t));
    if (!entry) return 0;
    entry->func = func;
    entry->data = data;

    pthread_mutex_lock(&q->lock);
    entry->next = q->head;
    q->head = entry;
    pthread_mutex_unlock(&q->lock);
    return 1;
}

/*
 * Drain all pending APCs for the current thread.
 * Returns the number of APCs executed.
 * Each APC callback is invoked via the ABI bridge (ms_abi convention).
 */
int apc_drain_current(void)
{
    apc_queue_t *q = apc_queue_get(pthread_self(), 0);
    if (!q) return 0;

    /* Detach the entire list under the lock, then execute outside the lock
     * so APC callbacks can themselves call QueueUserAPC without deadlock. */
    pthread_mutex_lock(&q->lock);
    apc_entry_t *list = q->head;
    q->head = NULL;
    pthread_mutex_unlock(&q->lock);

    if (!list) return 0;

    /* The list is in LIFO order (newest first).  Reverse it so APCs execute
     * in FIFO order, matching Windows semantics. */
    apc_entry_t *reversed = NULL;
    while (list) {
        apc_entry_t *next = list->next;
        list->next = reversed;
        reversed = list;
        list = next;
    }

    int count = 0;
    while (reversed) {
        apc_entry_t *cur = reversed;
        reversed = reversed->next;
        abi_call_win64_1((void *)cur->func, (uint64_t)cur->data);
        free(cur);
        count++;
    }
    return count;
}

/* Check if the current thread has any pending APCs (non-destructive) */
int apc_pending_current(void)
{
    apc_queue_t *q = apc_queue_get(pthread_self(), 0);
    if (!q) return 0;
    /* No lock needed for a simple NULL check -- worst case is a brief race
     * where we miss a just-enqueued APC, which will be caught on the next
     * alertable wait iteration. */
    return q->head != NULL;
}

/* Remove and free the APC queue for a given pthread_t.
 * Called during thread exit to prevent memory leaks. */
static void apc_queue_cleanup(pthread_t tid)
{
    unsigned bucket = apc_hash(tid);

    pthread_mutex_lock(&g_apc_map_lock);
    apc_queue_t **pp = &g_apc_map[bucket];
    while (*pp) {
        if (pthread_equal((*pp)->owner, tid)) {
            apc_queue_t *q = *pp;
            *pp = q->next;
            pthread_mutex_unlock(&g_apc_map_lock);

            /* Free any remaining APC entries */
            pthread_mutex_lock(&q->lock);
            apc_entry_t *entry = q->head;
            while (entry) {
                apc_entry_t *next = entry->next;
                free(entry);
                entry = next;
            }
            pthread_mutex_unlock(&q->lock);
            pthread_mutex_destroy(&q->lock);
            free(q);
            return;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&g_apc_map_lock);
}

/* ---------- Internal: compute absolute timespec from ms timeout ---------- */
/* Using CLOCK_REALTIME because pthread_cond_timedwait, pthread_mutex_timedlock,
 * and sem_timedwait all default to CLOCK_REALTIME unless the condvar/mutex was
 * explicitly created with pthread_condattr_setclock(CLOCK_MONOTONIC).  Our
 * thread_data_t.finish_cond, event_data_t.cond, and all other condvars are
 * initialized with PTHREAD_COND_INITIALIZER (which uses CLOCK_REALTIME).
 * Switching them all to CLOCK_MONOTONIC would be the ideal fix (immune to
 * NTP steps / DST jumps) but is invasive.  CLOCK_REALTIME here is correct
 * for the condvar attributes we actually have, at the cost of rare jitter
 * if the system clock is adjusted during a timed wait. */
static void timeout_to_abstime(DWORD ms, struct timespec *ts)
{
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec  += ms / 1000;
    ts->tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) {
        ts->tv_sec++;
        ts->tv_nsec -= 1000000000L;
    }
}

/* ---------- Thread wrapper ---------- */

static void *thread_wrapper(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;

    /* Set up TEB/GS register for this new thread */
    env_setup_thread();

    /* Allocate PE TLS data for this thread (populates TEB TLS slots) */
    pe_tls_alloc_thread();

    /* Per Windows spec, invoke TLS callbacks on thread attach */
    pe_tls_call_callbacks(DLL_THREAD_ATTACH);

    /* If created suspended, wait for resume */
    if (data->suspended) {
        pthread_mutex_lock(&data->suspend_lock);
        while (data->suspended)
            pthread_cond_wait(&data->suspend_cond, &data->suspend_lock);
        pthread_mutex_unlock(&data->suspend_lock);
    }

    LPTHREAD_START_ROUTINE start = data->start_routine;
    LPVOID param = data->parameter;

    /* Call the Windows thread function via ABI bridge */
    DWORD result = (DWORD)abi_call_win64_1((void *)start, (uint64_t)(uintptr_t)param);

    /* Fire FLS callbacks before TLS callbacks (Windows ordering) */
    extern void fls_thread_cleanup(void);
    fls_thread_cleanup();

    /* Per Windows spec, invoke TLS callbacks on thread detach before exit */
    pe_tls_call_callbacks(DLL_THREAD_DETACH);
    pe_tls_free_thread();

    /* Clean up APC queue for this thread to prevent memory leaks */
    apc_queue_cleanup(pthread_self());

    /* Signal completion */
    pthread_mutex_lock(&data->finish_lock);
    data->exit_code = result;
    data->finished = 1;
    pthread_cond_broadcast(&data->finish_cond);
    pthread_mutex_unlock(&data->finish_lock);

    return (void *)(uintptr_t)result;
}

WINAPI_EXPORT HANDLE CreateThread(
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId)
{
    (void)lpThreadAttributes;

    thread_data_t *data = calloc(1, sizeof(thread_data_t));
    if (!data) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    data->start_routine = lpStartAddress;
    data->parameter = lpParameter;
    data->suspended = (dwCreationFlags & CREATE_SUSPENDED) ? 1 : 0;
    data->finished = 0;
    data->exit_code = 0;
    pthread_mutex_init(&data->suspend_lock, NULL);
    pthread_cond_init(&data->suspend_cond, NULL);
    pthread_mutex_init(&data->finish_lock, NULL);
    pthread_cond_init(&data->finish_cond, NULL);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    if (dwStackSize > 0)
        pthread_attr_setstacksize(&attr, dwStackSize);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int ret = pthread_create(&data->pthread, &attr, thread_wrapper, data);
    pthread_attr_destroy(&attr);

    if (ret != 0) {
        free(data);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    if (lpThreadId)
        *lpThreadId = (DWORD)(uintptr_t)data->pthread;

    /* Notify anticheat bridge of thread creation */
    {
        typedef int (*acb_create_fn)(void *);
        acb_create_fn fn = (acb_create_fn)dlsym(RTLD_DEFAULT,
            "anticheat_bridge_on_create_thread");
        if (fn) fn((void *)lpStartAddress);
    }

    return handle_alloc(HANDLE_TYPE_THREAD, -1, data);
}

WINAPI_EXPORT void ExitThread(DWORD dwExitCode)
{
    pthread_exit((void *)(uintptr_t)dwExitCode);
}

WINAPI_EXPORT DWORD ResumeThread(HANDLE hThread)
{
    handle_entry_t *entry = handle_lookup(hThread);
    if (!entry || entry->type != HANDLE_TYPE_THREAD) {
        set_last_error(ERROR_INVALID_HANDLE);
        return (DWORD)-1;
    }

    thread_data_t *data = (thread_data_t *)entry->data;
    if (data && data->suspended) {
        pthread_mutex_lock(&data->suspend_lock);
        data->suspended = 0;
        pthread_cond_signal(&data->suspend_cond);
        pthread_mutex_unlock(&data->suspend_lock);
        return 1; /* Previous suspend count */
    }
    return 0;
}

/* ---------- WaitForSingleObject ---------- */

static DWORD wait_process(process_data_t *proc, DWORD ms)
{
    if (proc->finished)
        return WAIT_OBJECT_0;

    if (ms == 0) {
        /* Non-blocking: check if process exited */
        int status;
        pid_t ret = waitpid(proc->pid, &status, WNOHANG);
        if (ret == proc->pid) {
            proc->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
            proc->finished = 1;
            return WAIT_OBJECT_0;
        }
        return WAIT_TIMEOUT;
    } else if (ms == INFINITE) {
        int status;
        while (1) {
            pid_t ret = waitpid(proc->pid, &status, 0);
            if (ret == proc->pid) {
                proc->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
                proc->finished = 1;
                return WAIT_OBJECT_0;
            }
            if (ret < 0 && errno != EINTR) {
                /* Process may have already been reaped */
                proc->finished = 1;
                proc->exit_code = 0;
                return WAIT_OBJECT_0;
            }
        }
    } else {
        /* Timed wait: poll with WNOHANG + sleep intervals */
        long remaining_ms = (long)ms;
        while (remaining_ms > 0) {
            int status;
            pid_t ret = waitpid(proc->pid, &status, WNOHANG);
            if (ret == proc->pid) {
                proc->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
                proc->finished = 1;
                return WAIT_OBJECT_0;
            }
            long sleep_ms = remaining_ms > 10 ? 10 : remaining_ms;
            struct timespec ts = { 0, sleep_ms * 1000000L };
            nanosleep(&ts, NULL);
            remaining_ms -= sleep_ms;
        }
        return WAIT_TIMEOUT;
    }
}

static DWORD wait_thread(thread_data_t *tdata, DWORD ms)
{
    pthread_mutex_lock(&tdata->finish_lock);
    if (ms == INFINITE) {
        while (!tdata->finished)
            pthread_cond_wait(&tdata->finish_cond, &tdata->finish_lock);
        if (!tdata->joined) {
            tdata->joined = 1;
            pthread_mutex_unlock(&tdata->finish_lock);
            pthread_join(tdata->pthread, NULL);
        } else {
            pthread_mutex_unlock(&tdata->finish_lock);
        }
        return WAIT_OBJECT_0;
    } else {
        if (!tdata->finished) {
            struct timespec ts;
            timeout_to_abstime(ms, &ts);
            pthread_cond_timedwait(&tdata->finish_cond, &tdata->finish_lock, &ts);
        }
        int done = tdata->finished;
        int need_join = done && !tdata->joined;
        if (need_join) tdata->joined = 1;
        pthread_mutex_unlock(&tdata->finish_lock);
        if (need_join) {
            pthread_join(tdata->pthread, NULL);
        }
        return done ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
    }
}

static DWORD wait_event(event_data_t *evt, DWORD ms)
{
    pthread_mutex_lock(&evt->mutex);
    if (ms == INFINITE) {
        while (!evt->signaled)
            pthread_cond_wait(&evt->cond, &evt->mutex);
    } else if (ms > 0) {
        struct timespec ts;
        timeout_to_abstime(ms, &ts);
        while (!evt->signaled) {
            int rc = pthread_cond_timedwait(&evt->cond, &evt->mutex, &ts);
            if (rc == ETIMEDOUT) break;
        }
    }
    /* else ms == 0: just check current state */

    if (evt->signaled) {
        /* Auto-reset events clear after one waiter is released */
        if (!evt->manual_reset)
            evt->signaled = 0;
        pthread_mutex_unlock(&evt->mutex);
        return WAIT_OBJECT_0;
    }
    pthread_mutex_unlock(&evt->mutex);
    return WAIT_TIMEOUT;
}

static DWORD wait_mutex(mutex_data_t *mtx, DWORD ms)
{
    if (ms == INFINITE) {
        pthread_mutex_lock(&mtx->mutex);
        mtx->owner = (DWORD)gettid();
        return WAIT_OBJECT_0;
    } else if (ms == 0) {
        if (pthread_mutex_trylock(&mtx->mutex) == 0) {
            mtx->owner = (DWORD)gettid();
            return WAIT_OBJECT_0;
        }
        return WAIT_TIMEOUT;
    } else {
        struct timespec ts;
        timeout_to_abstime(ms, &ts);
        int rc = pthread_mutex_timedlock(&mtx->mutex, &ts);
        if (rc == 0) {
            mtx->owner = (DWORD)gettid();
            return WAIT_OBJECT_0;
        }
        return WAIT_TIMEOUT;
    }
}

static DWORD wait_semaphore(semaphore_data_t *sem, DWORD ms)
{
    if (ms == INFINITE) {
        while (sem_wait(&sem->sem) == -1 && errno == EINTR)
            ;
        return WAIT_OBJECT_0;
    } else if (ms == 0) {
        if (sem_trywait(&sem->sem) == 0)
            return WAIT_OBJECT_0;
        return WAIT_TIMEOUT;
    } else {
        struct timespec ts;
        timeout_to_abstime(ms, &ts);
        while (1) {
            int rc = sem_timedwait(&sem->sem, &ts);
            if (rc == 0) return WAIT_OBJECT_0;
            if (errno == ETIMEDOUT) return WAIT_TIMEOUT;
            if (errno != EINTR) return WAIT_FAILED;
        }
    }
}

/* ---- Broker-backed futex wait helpers ---- */

static DWORD broker_wait_mutex(shm_mutex_t *m, DWORD ms)
{
    uint32_t pid = (uint32_t)getpid();
    uint32_t tid = (uint32_t)gettid();

    /* Recursive acquisition: same thread owns it */
    if (atomic_load(&m->owner_tid) == tid) {
        atomic_fetch_add(&m->recursion, 1);
        return WAIT_OBJECT_0;
    }

    /* Try CAS: 0 (unlocked) -> pid (locked) */
    struct timespec ts;
    struct timespec *tsp = NULL;
    if (ms != 0xFFFFFFFF) {
        ts.tv_sec  = ms / 1000;
        ts.tv_nsec = (ms % 1000) * 1000000L;
        tsp = &ts;
    }

    for (;;) {
        uint32_t expected = 0;
        if (atomic_compare_exchange_strong(&m->futex_word, &expected, pid)) {
            /* Acquired */
            atomic_store(&m->owner_tid, tid);
            atomic_store(&m->recursion, 1);
            return WAIT_OBJECT_0;
        }
        /* Contended: wait on futex */
        int ret = (int)syscall(SYS_futex, &m->futex_word, FUTEX_WAIT,
                               expected, tsp, NULL, 0);
        if (ret < 0) {
            if (errno == ETIMEDOUT)
                return WAIT_TIMEOUT;
            if (errno != EAGAIN && errno != EINTR)
                return WAIT_FAILED;
        }
    }
}

static DWORD broker_wait_event(shm_event_t *evt, DWORD ms)
{
    struct timespec ts;
    struct timespec *tsp = NULL;
    if (ms != 0xFFFFFFFF) {
        ts.tv_sec  = ms / 1000;
        ts.tv_nsec = (ms % 1000) * 1000000L;
        tsp = &ts;
    }

    for (;;) {
        uint32_t val = atomic_load(&evt->futex_word);
        if (val != 0) {
            /* Signaled */
            if (!evt->manual_reset) {
                /* Auto-reset: CAS to consume the signal; retry if another
                 * thread consumed it first (prevents double-wake). */
                uint32_t one = 1;
                if (!atomic_compare_exchange_strong(&evt->futex_word, &one, 0)) {
                    /* Another thread consumed the signal; re-check */
                    continue;
                }
            }
            return WAIT_OBJECT_0;
        }
        /* Not signaled: wait */
        int ret = (int)syscall(SYS_futex, &evt->futex_word, FUTEX_WAIT,
                               0, tsp, NULL, 0);
        if (ret < 0) {
            if (errno == ETIMEDOUT)
                return WAIT_TIMEOUT;
            if (errno != EAGAIN && errno != EINTR)
                return WAIT_FAILED;
        }
    }
}

static DWORD broker_wait_semaphore(shm_semaphore_t *s, DWORD ms)
{
    struct timespec ts;
    struct timespec *tsp = NULL;
    if (ms != 0xFFFFFFFF) {
        ts.tv_sec  = ms / 1000;
        ts.tv_nsec = (ms % 1000) * 1000000L;
        tsp = &ts;
    }

    for (;;) {
        int32_t val = atomic_load(&s->futex_word);
        if (val > 0) {
            /* Try to decrement */
            if (atomic_compare_exchange_strong(&s->futex_word, &val, val - 1))
                return WAIT_OBJECT_0;
            continue; /* CAS failed, retry */
        }
        /* Zero count: wait */
        int ret = (int)syscall(SYS_futex, &s->futex_word, FUTEX_WAIT,
                               0, tsp, NULL, 0);
        if (ret < 0) {
            if (errno == ETIMEDOUT)
                return WAIT_TIMEOUT;
            if (errno != EAGAIN && errno != EINTR)
                return WAIT_FAILED;
        }
    }
}

static DWORD wait_timer(timer_data_t *td, DWORD ms)
{
    /* timerfd becomes readable when the timer fires.
     * Use poll() to wait with a timeout. */
    struct pollfd pfd = { .fd = td->timerfd, .events = POLLIN };
    int timeout_ms = (ms == INFINITE) ? -1 : (int)ms;

    int ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0) {
        if (errno == EINTR)
            return WAIT_TIMEOUT;  /* Treat interruption as timeout */
        return WAIT_FAILED;
    }
    if (ret == 0)
        return WAIT_TIMEOUT;

    /* Timer fired: consume the expiration count */
    uint64_t expirations;
    ssize_t n = read(td->timerfd, &expirations, sizeof(expirations));
    if (n < 0 && errno != EAGAIN)
        return WAIT_FAILED;

    /* Auto-reset timers: disarm after firing so they don't re-signal */
    if (!td->manual_reset) {
        struct itimerspec zero = {{0,0},{0,0}};
        timerfd_settime(td->timerfd, 0, &zero, NULL);
    }

    return WAIT_OBJECT_0;
}

WINAPI_EXPORT DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
{
    handle_entry_t *entry = handle_lookup(hHandle);
    if (!entry) {
        set_last_error(ERROR_INVALID_HANDLE);
        return WAIT_FAILED;
    }

    /* Broker-backed handles: use futex directly */
    if (is_broker_handle(entry)) {
        switch (entry->type) {
        case HANDLE_TYPE_MUTEX:
            return broker_wait_mutex((shm_mutex_t *)entry->data, dwMilliseconds);
        case HANDLE_TYPE_EVENT:
            return broker_wait_event((shm_event_t *)entry->data, dwMilliseconds);
        case HANDLE_TYPE_SEMAPHORE:
            return broker_wait_semaphore((shm_semaphore_t *)entry->data, dwMilliseconds);
        default:
            break;
        }
    }

    switch (entry->type) {
    case HANDLE_TYPE_THREAD:
        return wait_thread((thread_data_t *)entry->data, dwMilliseconds);
    case HANDLE_TYPE_PROCESS:
        return wait_process((process_data_t *)entry->data, dwMilliseconds);
    case HANDLE_TYPE_EVENT:
        return wait_event((event_data_t *)entry->data, dwMilliseconds);
    case HANDLE_TYPE_MUTEX:
        return wait_mutex((mutex_data_t *)entry->data, dwMilliseconds);
    case HANDLE_TYPE_SEMAPHORE:
        return wait_semaphore((semaphore_data_t *)entry->data, dwMilliseconds);
    case HANDLE_TYPE_TIMER:
        return wait_timer((timer_data_t *)entry->data, dwMilliseconds);
    default:
        /* Pseudo-handles for current process/thread are always signaled */
        if (hHandle == (HANDLE)(intptr_t)-1 || hHandle == (HANDLE)(intptr_t)-2)
            return WAIT_OBJECT_0;
        set_last_error(ERROR_INVALID_HANDLE);
        return WAIT_FAILED;
    }
}

/* ---------- WaitForMultipleObjects ---------- */

/*
 * Check if a single handle is currently signaled (non-blocking).
 * Returns WAIT_OBJECT_0 if signaled, WAIT_TIMEOUT if not, WAIT_FAILED on error.
 */
static DWORD check_handle_signaled(handle_entry_t *entry)
{
    if (!entry) return WAIT_FAILED;

    /* Broker-backed: check futex word directly */
    if (is_broker_handle(entry)) {
        switch (entry->type) {
        case HANDLE_TYPE_MUTEX: {
            shm_mutex_t *m = (shm_mutex_t *)entry->data;
            uint32_t expected = 0;
            if (atomic_compare_exchange_strong(&m->futex_word, &expected,
                                               (uint32_t)getpid())) {
                /* Set owner_tid immediately after successful CAS */
                atomic_store(&m->owner_tid, (uint32_t)gettid());
                atomic_store(&m->recursion, 1);
                return WAIT_OBJECT_0;
            }
            /* Check recursive acquisition */
            if (atomic_load(&m->owner_tid) == (uint32_t)gettid()) {
                atomic_fetch_add(&m->recursion, 1);
                return WAIT_OBJECT_0;
            }
            return WAIT_TIMEOUT;
        }
        case HANDLE_TYPE_EVENT: {
            shm_event_t *evt = (shm_event_t *)entry->data;
            return atomic_load(&evt->futex_word) ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
        }
        case HANDLE_TYPE_SEMAPHORE: {
            shm_semaphore_t *s = (shm_semaphore_t *)entry->data;
            int32_t val = atomic_load(&s->futex_word);
            if (val > 0 && atomic_compare_exchange_strong(&s->futex_word, &val, val - 1))
                return WAIT_OBJECT_0;
            return WAIT_TIMEOUT;
        }
        default:
            return WAIT_FAILED;
        }
    }

    switch (entry->type) {
    case HANDLE_TYPE_THREAD: {
        thread_data_t *td = (thread_data_t *)entry->data;
        pthread_mutex_lock(&td->finish_lock);
        int done = td->finished;
        pthread_mutex_unlock(&td->finish_lock);
        return done ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
    }
    case HANDLE_TYPE_PROCESS: {
        process_data_t *proc = (process_data_t *)entry->data;
        if (proc->finished)
            return WAIT_OBJECT_0;
        int status;
        pid_t ret = waitpid(proc->pid, &status, WNOHANG);
        if (ret == proc->pid) {
            proc->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
            proc->finished = 1;
            return WAIT_OBJECT_0;
        }
        return WAIT_TIMEOUT;
    }
    case HANDLE_TYPE_EVENT: {
        event_data_t *evt = (event_data_t *)entry->data;
        pthread_mutex_lock(&evt->mutex);
        int sig = evt->signaled;
        pthread_mutex_unlock(&evt->mutex);
        return sig ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
    }
    case HANDLE_TYPE_MUTEX:
        return (pthread_mutex_trylock(&((mutex_data_t *)entry->data)->mutex) == 0)
               ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
    case HANDLE_TYPE_SEMAPHORE:
        return (sem_trywait(&((semaphore_data_t *)entry->data)->sem) == 0)
               ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
    case HANDLE_TYPE_TIMER: {
        /* Non-blocking check: poll with 0 timeout */
        timer_data_t *tmr = (timer_data_t *)entry->data;
        struct pollfd pfd = { .fd = tmr->timerfd, .events = POLLIN };
        if (poll(&pfd, 1, 0) > 0) {
            /* Timer fired: consume expiration count */
            uint64_t expirations;
            { ssize_t _unused = read(tmr->timerfd, &expirations, sizeof(expirations)); (void)_unused; }
            /* Auto-reset timers: disarm after firing */
            if (!tmr->manual_reset) {
                struct itimerspec zero = {{0,0},{0,0}};
                timerfd_settime(tmr->timerfd, 0, &zero, NULL);
            }
            return WAIT_OBJECT_0;
        }
        return WAIT_TIMEOUT;
    }
    default:
        return WAIT_FAILED;
    }
}

/*
 * Consume/acquire a handle after it was found to be signaled
 * (auto-reset events, join threads, etc.)
 */
static void acquire_handle(handle_entry_t *entry)
{
    if (!entry) return;

    /* Broker-backed: CAS/futex already acquired in check_handle_signaled */
    if (is_broker_handle(entry)) {
        switch (entry->type) {
        case HANDLE_TYPE_MUTEX: {
            shm_mutex_t *m = (shm_mutex_t *)entry->data;
            atomic_store(&m->owner_tid, (uint32_t)gettid());
            atomic_fetch_add(&m->recursion, 1);
            break;
        }
        case HANDLE_TYPE_EVENT: {
            shm_event_t *evt = (shm_event_t *)entry->data;
            if (!evt->manual_reset) {
                uint32_t one = 1;
                atomic_compare_exchange_strong(&evt->futex_word, &one, 0);
            }
            break;
        }
        case HANDLE_TYPE_SEMAPHORE:
            /* Already decremented in check_handle_signaled */
            break;
        default:
            break;
        }
        return;
    }

    switch (entry->type) {
    case HANDLE_TYPE_THREAD: {
        thread_data_t *td = (thread_data_t *)entry->data;
        pthread_mutex_lock(&td->finish_lock);
        int need_join = !td->joined;
        if (need_join) td->joined = 1;
        pthread_mutex_unlock(&td->finish_lock);
        if (need_join)
            pthread_join(td->pthread, NULL);
        break;
    }
    case HANDLE_TYPE_EVENT: {
        event_data_t *evt = (event_data_t *)entry->data;
        if (!evt->manual_reset) {
            pthread_mutex_lock(&evt->mutex);
            evt->signaled = 0;
            pthread_mutex_unlock(&evt->mutex);
        }
        break;
    }
    case HANDLE_TYPE_MUTEX: {
        mutex_data_t *mtx = (mutex_data_t *)entry->data;
        /* trylock already acquired it in check_handle_signaled */
        mtx->owner = (DWORD)gettid();
        break;
    }
    case HANDLE_TYPE_SEMAPHORE:
        /* trywait already decremented in check_handle_signaled */
        break;
    case HANDLE_TYPE_TIMER: {
        /* Expiration already consumed in check_handle_signaled.
         * Ensure auto-reset timers are disarmed. */
        timer_data_t *tmr = (timer_data_t *)entry->data;
        if (!tmr->manual_reset) {
            struct itimerspec zero = {{0,0},{0,0}};
            timerfd_settime(tmr->timerfd, 0, &zero, NULL);
        }
        break;
    }
    default:
        break;
    }
}

/*
 * Release a handle that was acquired by check_handle_signaled but
 * we no longer need (e.g., during wait-all when not all handles are signaled).
 */
static void release_handle(handle_entry_t *entry)
{
    if (!entry) return;

    /* Broker-backed handles: undo CAS acquisition via atomics + futex wake */
    if (is_broker_handle(entry)) {
        switch (entry->type) {
        case HANDLE_TYPE_MUTEX: {
            shm_mutex_t *m = (shm_mutex_t *)entry->data;
            atomic_store(&m->recursion, 0);
            atomic_store(&m->owner_tid, 0);
            atomic_store(&m->futex_word, 0);
            syscall(SYS_futex, &m->futex_word, FUTEX_WAKE, 1, NULL, NULL, 0);
            break;
        }
        case HANDLE_TYPE_SEMAPHORE: {
            shm_semaphore_t *s = (shm_semaphore_t *)entry->data;
            atomic_fetch_add(&s->futex_word, 1);
            syscall(SYS_futex, &s->futex_word, FUTEX_WAKE, 1, NULL, NULL, 0);
            break;
        }
        default:
            break;
        }
        return;
    }

    switch (entry->type) {
    case HANDLE_TYPE_MUTEX:
        pthread_mutex_unlock(&((mutex_data_t *)entry->data)->mutex);
        break;
    case HANDLE_TYPE_SEMAPHORE:
        sem_post(&((semaphore_data_t *)entry->data)->sem);
        break;
    default:
        break;
    }
}

WINAPI_EXPORT DWORD WaitForMultipleObjects(
    DWORD nCount,
    const HANDLE *lpHandles,
    BOOL bWaitAll,
    DWORD dwMilliseconds)
{
    if (nCount == 0 || nCount > 64 || !lpHandles) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return WAIT_FAILED;
    }

    /* Resolve all handle entries up front */
    handle_entry_t *entries[64];
    for (DWORD i = 0; i < nCount; i++) {
        entries[i] = handle_lookup(lpHandles[i]);
        if (!entries[i]) {
            set_last_error(ERROR_INVALID_HANDLE);
            return WAIT_FAILED;
        }
    }

    struct timespec deadline;
    int has_deadline = (dwMilliseconds != INFINITE);
    if (has_deadline)
        timeout_to_abstime(dwMilliseconds, &deadline);

    unsigned int poll_count = 0;

    while (1) {
        if (bWaitAll) {
            /* Try to acquire all handles atomically */
            int all_signaled = 1;
            DWORD acquired = 0;
            for (DWORD i = 0; i < nCount; i++) {
                DWORD rc = check_handle_signaled(entries[i]);
                if (rc == WAIT_OBJECT_0) {
                    acquired++;
                } else {
                    all_signaled = 0;
                    break;
                }
            }
            if (all_signaled && acquired == nCount) {
                /* All signaled — acquire them */
                for (DWORD i = 0; i < nCount; i++)
                    acquire_handle(entries[i]);
                return WAIT_OBJECT_0;
            }
            /* Release any we acquired */
            for (DWORD i = 0; i < acquired; i++)
                release_handle(entries[i]);
        } else {
            /* Return first signaled handle */
            for (DWORD i = 0; i < nCount; i++) {
                DWORD rc = check_handle_signaled(entries[i]);
                if (rc == WAIT_OBJECT_0) {
                    acquire_handle(entries[i]);
                    return WAIT_OBJECT_0 + i;
                }
            }
        }

        /* Check timeout */
        if (dwMilliseconds == 0)
            return WAIT_TIMEOUT;

        if (has_deadline) {
            struct timespec now;
            clock_gettime(CLOCK_REALTIME, &now);
            if (now.tv_sec > deadline.tv_sec ||
                (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec))
                return WAIT_TIMEOUT;
        }

        /* Adaptive sleep: start at 100us, ramp up to 10ms */
        poll_count++;
        if (poll_count < 10)
            usleep(100);       /* First 1ms: 100us intervals (responsive) */
        else if (poll_count < 100)
            usleep(1000);      /* Next ~100ms: 1ms intervals */
        else
            usleep(10000);     /* After that: 10ms intervals (save CPU) */
    }
}

/* ---------- Thread-Local Storage ---------- */

WINAPI_EXPORT DWORD TlsAlloc(void)
{
    pthread_mutex_lock(&g_tls_lock);

    for (DWORD i = 0; i < TLS_MAX_SLOTS; i++) {
        if (!g_tls_used[i]) {
            if (pthread_key_create(&g_tls_keys[i], NULL) == 0) {
                g_tls_used[i] = 1;
                pthread_mutex_unlock(&g_tls_lock);
                return i;
            }
        }
    }

    pthread_mutex_unlock(&g_tls_lock);
    set_last_error(ERROR_NOT_ENOUGH_MEMORY);
    return 0xFFFFFFFF; /* TLS_OUT_OF_INDEXES */
}

WINAPI_EXPORT BOOL TlsFree(DWORD dwTlsIndex)
{
    if (dwTlsIndex >= TLS_MAX_SLOTS) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    pthread_mutex_lock(&g_tls_lock);
    if (g_tls_used[dwTlsIndex]) {
        pthread_key_delete(g_tls_keys[dwTlsIndex]);
        g_tls_used[dwTlsIndex] = 0;
    }
    pthread_mutex_unlock(&g_tls_lock);
    return TRUE;
}

WINAPI_EXPORT LPVOID TlsGetValue(DWORD dwTlsIndex)
{
    if (dwTlsIndex >= TLS_MAX_SLOTS) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    pthread_mutex_lock(&g_tls_lock);
    if (!g_tls_used[dwTlsIndex]) {
        pthread_mutex_unlock(&g_tls_lock);
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    LPVOID value = pthread_getspecific(g_tls_keys[dwTlsIndex]);
    pthread_mutex_unlock(&g_tls_lock);
    set_last_error(ERROR_SUCCESS);
    return value;
}

WINAPI_EXPORT BOOL TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue)
{
    if (dwTlsIndex >= TLS_MAX_SLOTS) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    pthread_mutex_lock(&g_tls_lock);
    if (!g_tls_used[dwTlsIndex]) {
        pthread_mutex_unlock(&g_tls_lock);
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    pthread_setspecific(g_tls_keys[dwTlsIndex], lpTlsValue);
    pthread_mutex_unlock(&g_tls_lock);
    return TRUE;
}

/* ---------- Sleep ---------- */

WINAPI_EXPORT void Sleep(DWORD dwMilliseconds)
{
    if (dwMilliseconds == 0) {
        sched_yield();
        return;
    }
    if (dwMilliseconds == INFINITE) {
        while (1) pause();
        return;
    }
    /* Use nanosleep to avoid usleep overflow for large values */
    struct timespec req;
    req.tv_sec  = dwMilliseconds / 1000;
    req.tv_nsec = (long)(dwMilliseconds % 1000) * 1000000L;
    while (nanosleep(&req, &req) == -1 && errno == EINTR)
        ;
}

WINAPI_EXPORT DWORD SleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    if (!bAlertable) {
        Sleep(dwMilliseconds);
        return 0;
    }

    /* Alertable sleep: check for pending APCs before and during the wait.
     * If any APCs are dispatched, return WAIT_IO_COMPLETION immediately. */

    /* Check APCs before sleeping (Windows drains before blocking) */
    if (apc_drain_current() > 0)
        return WAIT_IO_COMPLETION;

    if (dwMilliseconds == 0) {
        sched_yield();
        return 0;
    }

    if (dwMilliseconds == 0xFFFFFFFF) {  /* INFINITE */
        /* True infinite alertable sleep: loop forever checking APCs */
        for (;;) {
            struct timespec req = { .tv_sec = 0, .tv_nsec = 10000000L }; /* 10ms */
            nanosleep(&req, NULL);
            if (apc_drain_current() > 0)
                return WAIT_IO_COMPLETION;
        }
    }

    /* Sleep in short intervals, checking for APCs between each.
     * This allows APC delivery with reasonable latency. */
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec  += dwMilliseconds / 1000;
    deadline.tv_nsec += (long)(dwMilliseconds % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }

    while (1) {
        /* Sleep for up to 10ms at a time */
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long remaining_ns = (deadline.tv_sec - now.tv_sec) * 1000000000L
                          + (deadline.tv_nsec - now.tv_nsec);
        if (remaining_ns <= 0)
            break;

        long sleep_ns = remaining_ns > 10000000L ? 10000000L : remaining_ns;
        struct timespec req = { .tv_sec = 0, .tv_nsec = sleep_ns };
        nanosleep(&req, NULL);

        /* Check for APCs after each interval */
        if (apc_drain_current() > 0)
            return WAIT_IO_COMPLETION;
    }
    return 0;
}

WINAPI_EXPORT BOOL SwitchToThread(void)
{
    sched_yield();
    return TRUE;
}

WINAPI_EXPORT DWORD GetThreadId(HANDLE Thread)
{
    /* Current thread pseudo-handle */
    if (Thread == (HANDLE)(intptr_t)-2 || Thread == NULL)
        return (DWORD)gettid();

    /* Look up thread handle and return its TID */
    handle_entry_t *entry = handle_lookup(Thread);
    if (entry && entry->type == HANDLE_TYPE_THREAD) {
        thread_data_t *data = (thread_data_t *)entry->data;
        if (data) {
            /* pthread_t on Linux is typically the TID or LWP id */
            return (DWORD)(uintptr_t)data->pthread;
        }
    }

    /* Fallback: return current thread id */
    return (DWORD)gettid();
}

WINAPI_EXPORT BOOL GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode)
{
    handle_entry_t *entry = handle_lookup(hThread);
    if (!entry || entry->type != HANDLE_TYPE_THREAD) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    thread_data_t *data = (thread_data_t *)entry->data;
    if (!data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    pthread_mutex_lock(&data->finish_lock);
    if (lpExitCode) {
        if (data->finished)
            *lpExitCode = data->exit_code;
        else
            *lpExitCode = 259; /* STILL_ACTIVE */
    }
    pthread_mutex_unlock(&data->finish_lock);
    return TRUE;
}

/* ---------- SuspendThread ---------- */

WINAPI_EXPORT DWORD SuspendThread(HANDLE hThread)
{
    handle_entry_t *entry = handle_lookup(hThread);
    if (!entry || entry->type != HANDLE_TYPE_THREAD) {
        set_last_error(ERROR_INVALID_HANDLE);
        return (DWORD)-1;
    }

    thread_data_t *data = (thread_data_t *)entry->data;
    if (!data) return (DWORD)-1;

    pthread_mutex_lock(&data->suspend_lock);
    DWORD prev_count = data->suspended;
    data->suspended++;
    pthread_mutex_unlock(&data->suspend_lock);

    /* WARNING: SIGSTOP on Linux is process-wide even when sent to a specific
     * thread via tgkill.  There is no true per-thread suspend on Linux without
     * ptrace.  We use tgkill to at least target the correct TID, but the
     * effect is still process-wide.  This is a known limitation. */
    pid_t tid = (pid_t)syscall(SYS_gettid);  /* fallback TID */
    /* Try to get the real TID from pthread internals (Linux-specific) */
    pid_t target_tid = (pid_t)(uintptr_t)data->pthread;
    if (target_tid > 0)
        syscall(SYS_tgkill, getpid(), target_tid, SIGSTOP);
    else
        pthread_kill(data->pthread, SIGSTOP);
    (void)tid;

    return prev_count;
}

/* ---------- Thread Priority ---------- */

WINAPI_EXPORT BOOL SetThreadPriority(HANDLE hThread, int nPriority)
{
    handle_entry_t *entry = handle_lookup(hThread);
    if (!entry || entry->type != HANDLE_TYPE_THREAD) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    thread_data_t *data = (thread_data_t *)entry->data;
    if (!data) return FALSE;

    /* Map Windows priority (-15..+15) to Linux scheduler priority range.
     * Windows: THREAD_PRIORITY_IDLE=-15, LOWEST=-2, BELOW_NORMAL=-1,
     *          NORMAL=0, ABOVE_NORMAL=1, HIGHEST=2, TIME_CRITICAL=15 */
    int policy;
    struct sched_param param;
    pthread_getschedparam(data->pthread, &policy, &param);

    int pmin = sched_get_priority_min(policy);
    int pmax = sched_get_priority_max(policy);
    int range = pmax - pmin;

    /* Clamp nPriority to [-15, 15] and interpolate across the range.
     * (nPriority + 15) maps [-15..+15] to [0..30]. */
    int clamped = nPriority;
    if (clamped > 15) clamped = 15;
    if (clamped < -15) clamped = -15;
    param.sched_priority = pmin + (clamped + 15) * range / 30;

    pthread_setschedparam(data->pthread, policy, &param);
    return TRUE;
}

WINAPI_EXPORT int GetThreadPriority(HANDLE hThread)
{
    (void)hThread;
    return 0; /* THREAD_PRIORITY_NORMAL */
}

/* ---------- Thread Affinity ---------- */

WINAPI_EXPORT DWORD_PTR SetThreadAffinityMask(HANDLE hThread, DWORD_PTR dwThreadAffinityMask)
{
    handle_entry_t *entry = handle_lookup(hThread);
    if (!entry || entry->type != HANDLE_TYPE_THREAD) {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    thread_data_t *data = (thread_data_t *)entry->data;
    if (!data) return 0;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    for (long i = 0; i < ncpu && i < 64; i++) {
        if (dwThreadAffinityMask & (1ULL << i))
            CPU_SET(i, &cpuset);
    }

    DWORD_PTR old_mask = (1ULL << ncpu) - 1; /* Assume all CPUs */
    pthread_setaffinity_np(data->pthread, sizeof(cpuset), &cpuset);
    return old_mask;
}

WINAPI_EXPORT BOOL GetThreadAffinityMask(HANDLE hThread, DWORD_PTR *lpProcessAffinityMask,
                                          DWORD_PTR *lpSystemAffinityMask)
{
    (void)hThread;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    DWORD_PTR mask = (ncpu >= 64) ? ~0ULL : ((1ULL << ncpu) - 1);
    if (lpProcessAffinityMask) *lpProcessAffinityMask = mask;
    if (lpSystemAffinityMask) *lpSystemAffinityMask = mask;
    return TRUE;
}

/* ---------- QueueUserAPC ---------- */

WINAPI_EXPORT DWORD QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData)
{
    if (!pfnAPC) return 0;

    /* Determine target pthread_t from the thread HANDLE */
    pthread_t target;

    /* Pseudo-handle for current thread: (HANDLE)-2 or NULL */
    if (hThread == (HANDLE)(intptr_t)-2 || hThread == NULL) {
        target = pthread_self();
    } else {
        handle_entry_t *entry = handle_lookup(hThread);
        if (!entry || entry->type != HANDLE_TYPE_THREAD) {
            set_last_error(ERROR_INVALID_HANDLE);
            return 0;
        }
        thread_data_t *data = (thread_data_t *)entry->data;
        if (!data) {
            set_last_error(ERROR_INVALID_HANDLE);
            return 0;
        }
        target = data->pthread;
    }

    if (!apc_enqueue(target, pfnAPC, dwData)) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    return 1;
}

/* ---------- Thread naming (SetThreadDescription) ---------- */

WINAPI_EXPORT long SetThreadDescription(HANDLE hThread, const WCHAR *lpThreadDescription)
{
    (void)hThread;
    if (!lpThreadDescription) return 0;

    /* Convert wide to narrow for pthread_setname_np */
    char name[16];
    int i;
    for (i = 0; i < 15 && lpThreadDescription[i]; i++)
        name[i] = (char)(lpThreadDescription[i] & 0x7F);
    name[i] = '\0';

    pthread_setname_np(pthread_self(), name);
    return 0; /* S_OK */
}

/* ---------- Thread Group Affinity (UE5 NUMA-aware threading) ---------- */

typedef struct {
    DWORD_PTR Mask;
    WORD      Group;
    WORD      Reserved[3];
} GROUP_AFFINITY;

WINAPI_EXPORT BOOL SetThreadGroupAffinity(
    HANDLE hThread,
    const GROUP_AFFINITY *GroupAffinity,
    GROUP_AFFINITY *PreviousGroupAffinity)
{
    (void)hThread;

    /* Fill previous with all-CPUs mask if requested */
    if (PreviousGroupAffinity) {
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        PreviousGroupAffinity->Mask = (ncpu >= 64) ? ~0ULL : ((1ULL << ncpu) - 1);
        PreviousGroupAffinity->Group = 0;
        memset(PreviousGroupAffinity->Reserved, 0, sizeof(PreviousGroupAffinity->Reserved));
    }

    /* Apply affinity if we have a valid thread handle */
    if (GroupAffinity) {
        handle_entry_t *entry = handle_lookup(hThread);
        if (entry && entry->type == HANDLE_TYPE_THREAD) {
            thread_data_t *data = (thread_data_t *)entry->data;
            if (data) {
                cpu_set_t cpuset;
                CPU_ZERO(&cpuset);
                long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
                for (long i = 0; i < ncpu && i < 64; i++) {
                    if (GroupAffinity->Mask & (1ULL << i))
                        CPU_SET(i, &cpuset);
                }
                pthread_setaffinity_np(data->pthread, sizeof(cpuset), &cpuset);
            }
        }
    }

    return TRUE;
}

WINAPI_EXPORT BOOL GetThreadGroupAffinity(
    HANDLE hThread,
    GROUP_AFFINITY *GroupAffinity)
{
    (void)hThread;
    if (!GroupAffinity) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    GroupAffinity->Mask = (ncpu >= 64) ? ~0ULL : ((1ULL << ncpu) - 1);
    GroupAffinity->Group = 0;
    memset(GroupAffinity->Reserved, 0, sizeof(GroupAffinity->Reserved));
    return TRUE;
}

/* ---------- Thread naming (SetThreadDescription) ---------- */

WINAPI_EXPORT long GetThreadDescription(HANDLE hThread, WCHAR **ppszThreadDescription)
{
    (void)hThread;
    if (!ppszThreadDescription) return -1;

    char name[16] = {0};
    pthread_getname_np(pthread_self(), name, sizeof(name));

    WCHAR *wide = calloc(strlen(name) + 1, sizeof(WCHAR));
    if (!wide) return -1;
    for (size_t i = 0; name[i]; i++)
        wide[i] = (WCHAR)(unsigned char)name[i];

    *ppszThreadDescription = wide;
    return 0;
}
