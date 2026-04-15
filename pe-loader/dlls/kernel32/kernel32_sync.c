/*
 * kernel32_sync.c - Synchronization primitives
 *
 * Mutex, Event, Semaphore, CriticalSection, Interlocked*.
 *
 * Named objects delegate to the Object Broker (pe-objectd) when it is
 * available, falling back to the local intra-process hash table when not.
 * Broker-backed objects use shared memory + futex for zero-overhead
 * cross-process synchronization.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <errno.h>
#include <stdatomic.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/timerfd.h>
#include <linux/futex.h>
#define gettid() syscall(SYS_gettid)

#include "kernel32_internal.h"
#include "compat/objectd_client.h"

/* ---- Broker-backed handle support ---- */

/* Flags stored in handle_entry_t.fd to identify broker-backed objects.
 * We use negative fd values (real fds are non-negative) to distinguish
 * broker-backed handles from local ones.  The type field still holds
 * HANDLE_TYPE_MUTEX/EVENT/SEMAPHORE; we detect broker backing by
 * checking the fd sentinel. */
#define BROKER_HANDLE_FD_SENTINEL  (-42)

/* Helper: mmap a broker shared memory fd and create a handle. */
static HANDLE broker_mmap_handle(int shm_fd, handle_type_t type)
{
    if (shm_fd < 0)
        return NULL;

    void *shm = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    close(shm_fd);

    if (shm == MAP_FAILED)
        return NULL;

    HANDLE h = handle_alloc(type, BROKER_HANDLE_FD_SENTINEL, shm);
    /* handle_alloc returns INVALID_HANDLE_VALUE on failure, but named-object
     * Create* contract returns NULL on failure. Normalize so callers checking
     * if (h) / if (!h) behave correctly (INVALID_HANDLE_VALUE = -1 is truthy). */
    if (!h || h == INVALID_HANDLE_VALUE) {
        munmap(shm, 4096);
        return NULL;
    }
    return h;
}

/* Helper: check if a handle entry is broker-backed. */
static inline int is_broker_handle(handle_entry_t *entry)
{
    return entry && entry->fd == BROKER_HANDLE_FD_SENTINEL;
}

/* --------------------------------------------------------------------------
 * Named kernel object registry (intra-process)
 *
 * Maps string names to existing HANDLEs so that CreateEvent("foo") followed
 * by OpenEvent("foo") in the same process returns the same object.
 * Cross-process sharing requires a wineserver (future work).
 * -------------------------------------------------------------------------- */

#define NAMED_OBJ_MAX 256

typedef struct {
    char  name[260];
    HANDLE handle;
    int   type;   /* HANDLE_TYPE_* */
} named_obj_entry_t;

static named_obj_entry_t g_named_objs[NAMED_OBJ_MAX];
static int               g_named_obj_count = 0;
static pthread_mutex_t   g_named_obj_lock  = PTHREAD_MUTEX_INITIALIZER;

/* Monotonic generation bumped whenever g_named_objs[] is mutated (append
 * via register or swap-with-last via unregister). TLS last-hit caches
 * compare this under g_named_obj_lock to detect invalidation without
 * per-thread coordination. All inline lookup/register sites in
 * CreateEventA/CreateMutexA/CreateSemaphoreA also bump this counter. */
static volatile unsigned int g_named_obj_gen = 0;

/* TLS last-hit cache for named_obj_lookup(). PE apps routinely call
 * OpenEvent/OpenMutex by the same name in tight loops (e.g. shared-
 * memory heartbeat polling, anti-cheat probe checks). A 1-entry
 * per-thread cache eliminates most lookups without touching the
 * mutation path.
 *
 * Safety: read under g_named_obj_lock. The cached pointer is only
 * used if (tls_gen == g_named_obj_gen) — since both mutations and
 * cache reads happen under the lock, a stale entry cannot be returned. */
static __thread unsigned int tls_no_gen          = (unsigned int)-1;
static __thread char         tls_no_name[260];
static __thread int          tls_no_type         = 0;
static __thread HANDLE       tls_no_hit          = NULL;

static HANDLE named_obj_lookup(const char *name, int type)
{
    if (!name || !name[0]) return NULL;
    pthread_mutex_lock(&g_named_obj_lock);
    if (tls_no_gen == g_named_obj_gen && tls_no_hit &&
        tls_no_type == type &&
        strcasecmp(tls_no_name, name) == 0) {
        HANDLE h = tls_no_hit;
        pthread_mutex_unlock(&g_named_obj_lock);
        return h;
    }
    for (int i = 0; i < g_named_obj_count; i++) {
        if (g_named_objs[i].type == type &&
            strcasecmp(g_named_objs[i].name, name) == 0) {
            HANDLE h = g_named_objs[i].handle;
            tls_no_gen = g_named_obj_gen;
            strncpy(tls_no_name, name, sizeof(tls_no_name) - 1);
            tls_no_name[sizeof(tls_no_name) - 1] = '\0';
            tls_no_type = type;
            tls_no_hit = h;
            pthread_mutex_unlock(&g_named_obj_lock);
            return h;
        }
    }
    pthread_mutex_unlock(&g_named_obj_lock);
    return NULL;
}

static void named_obj_register(const char *name, HANDLE h, int type)
{
    if (!name || !name[0]) return;
    pthread_mutex_lock(&g_named_obj_lock);
    if (g_named_obj_count < NAMED_OBJ_MAX) {
        named_obj_entry_t *e = &g_named_objs[g_named_obj_count++];
        strncpy(e->name, name, sizeof(e->name) - 1);
        e->name[sizeof(e->name) - 1] = '\0';
        e->handle = h;
        e->type = type;
        g_named_obj_gen++;
    }
    pthread_mutex_unlock(&g_named_obj_lock);
}

/* Deregister a named object when its handle is closed.
 * Caller should NOT hold g_named_obj_lock. */
void named_obj_unregister(HANDLE h)
{
    if (!h) return;
    pthread_mutex_lock(&g_named_obj_lock);
    for (int i = 0; i < g_named_obj_count; i++) {
        if (g_named_objs[i].handle == h) {
            /* Swap with last entry to keep array compact */
            g_named_obj_count--;
            if (i < g_named_obj_count)
                g_named_objs[i] = g_named_objs[g_named_obj_count];
            memset(&g_named_objs[g_named_obj_count], 0, sizeof(named_obj_entry_t));
            g_named_obj_gen++;
            break;
        }
    }
    pthread_mutex_unlock(&g_named_obj_lock);
}

/* Forward declarations for W->A delegation */
WINAPI_EXPORT HANDLE OpenSemaphoreA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName);

/* --- Events --- */

WINAPI_EXPORT HANDLE CreateEventA(
    LPSECURITY_ATTRIBUTES lpEventAttributes,
    BOOL bManualReset,
    BOOL bInitialState,
    LPCSTR lpName)
{
    (void)lpEventAttributes;

    /* Named event: try broker first */
    if (lpName && lpName[0]) {
        int shm_fd = -1;
        int ret = objectd_create_event(lpName, bManualReset ? 1 : 0,
                                       bInitialState ? 1 : 0, &shm_fd);
        if (ret == OBJ_STATUS_OK || ret == OBJ_STATUS_ALREADY_EXISTS) {
            if (ret == OBJ_STATUS_ALREADY_EXISTS)
                set_last_error(183); /* ERROR_ALREADY_EXISTS */
            if (shm_fd >= 0) {
                HANDLE h = broker_mmap_handle(shm_fd, HANDLE_TYPE_EVENT);
                if (h) {
                    named_obj_register(lpName, h, HANDLE_TYPE_EVENT);
                    return h;
                }
            }
        }
        /* Broker unavailable or failed: fall through to local */
    }

    /* Hold lock across lookup and register to prevent TOCTOU race */
    if (lpName) {
        pthread_mutex_lock(&g_named_obj_lock);
        for (int i = 0; i < g_named_obj_count; i++) {
            if (g_named_objs[i].type == HANDLE_TYPE_EVENT &&
                strcasecmp(g_named_objs[i].name, lpName) == 0) {
                HANDLE existing = g_named_objs[i].handle;
                pthread_mutex_unlock(&g_named_obj_lock);
                set_last_error(183); /* ERROR_ALREADY_EXISTS */
                return existing;
            }
        }
        /* Still holding lock — create and register atomically */
        event_data_t *evt = calloc(1, sizeof(event_data_t));
        if (!evt) {
            pthread_mutex_unlock(&g_named_obj_lock);
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
        pthread_mutex_init(&evt->mutex, NULL);
        pthread_cond_init(&evt->cond, NULL);
        evt->signaled = bInitialState ? 1 : 0;
        evt->manual_reset = bManualReset ? 1 : 0;
        HANDLE h = handle_alloc(HANDLE_TYPE_EVENT, -1, evt);
        /* handle_alloc returns INVALID_HANDLE_VALUE on failure, but CreateEvent
         * contract returns NULL on failure. Treat both as failure. */
        if (h && h != INVALID_HANDLE_VALUE && g_named_obj_count < NAMED_OBJ_MAX) {
            named_obj_entry_t *e = &g_named_objs[g_named_obj_count++];
            strncpy(e->name, lpName, sizeof(e->name) - 1);
            e->name[sizeof(e->name) - 1] = '\0';
            e->handle = h;
            e->type = HANDLE_TYPE_EVENT;
            g_named_obj_gen++;
        }
        pthread_mutex_unlock(&g_named_obj_lock);
        if (!h || h == INVALID_HANDLE_VALUE) {
            /* handle_alloc failed: destroy pthread primitives and free */
            pthread_mutex_destroy(&evt->mutex);
            pthread_cond_destroy(&evt->cond);
            free(evt);
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
        return h;
    }

    event_data_t *evt = calloc(1, sizeof(event_data_t));
    if (!evt) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    pthread_mutex_init(&evt->mutex, NULL);
    pthread_cond_init(&evt->cond, NULL);
    evt->signaled = bInitialState ? 1 : 0;
    evt->manual_reset = bManualReset ? 1 : 0;

    HANDLE h = handle_alloc(HANDLE_TYPE_EVENT, -1, evt);
    /* handle_alloc returns INVALID_HANDLE_VALUE on failure, but CreateEvent
     * contract returns NULL on failure. Normalize. */
    if (!h || h == INVALID_HANDLE_VALUE) {
        pthread_mutex_destroy(&evt->mutex);
        pthread_cond_destroy(&evt->cond);
        free(evt);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    return h;
}

/* Simple UTF-16 to ASCII converter for named object names.
 * Safety: guard against buflen==0 (buflen-1 underflows to SIZE_MAX, which
 * would otherwise allow an unbounded loop/write if the caller passes 0). */
static const char *wide_to_narrow_name(LPCWSTR wide, char *buf, size_t buflen)
{
    if (!wide || !wide[0] || !buf || buflen == 0) return NULL;
    size_t i;
    for (i = 0; i < buflen - 1 && wide[i]; i++)
        buf[i] = (char)(wide[i] & 0x7F);
    buf[i] = '\0';
    return buf;
}

WINAPI_EXPORT HANDLE CreateEventW(
    LPSECURITY_ATTRIBUTES lpEventAttributes,
    BOOL bManualReset,
    BOOL bInitialState,
    LPCWSTR lpName)
{
    char narrow[260];
    const char *name = wide_to_narrow_name(lpName, narrow, sizeof(narrow));
    return CreateEventA(lpEventAttributes, bManualReset, bInitialState, name);
}

WINAPI_EXPORT BOOL SetEvent(HANDLE hEvent)
{
    handle_entry_t *entry = handle_lookup(hEvent);
    if (!entry || entry->type != HANDLE_TYPE_EVENT) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /* Broker-backed event: set via futex */
    if (is_broker_handle(entry)) {
        shm_event_t *evt = (shm_event_t *)entry->data;
        atomic_store(&evt->futex_word, 1);
        /* Wake all waiters (manual_reset) or one waiter (auto-reset) */
        if (evt->manual_reset)
            syscall(SYS_futex, &evt->futex_word, FUTEX_WAKE, INT32_MAX, NULL, NULL, 0);
        else
            syscall(SYS_futex, &evt->futex_word, FUTEX_WAKE, 1, NULL, NULL, 0);
        return TRUE;
    }

    event_data_t *evt = (event_data_t *)entry->data;
    pthread_mutex_lock(&evt->mutex);
    evt->signaled = 1;
    if (evt->manual_reset)
        pthread_cond_broadcast(&evt->cond);
    else
        pthread_cond_signal(&evt->cond);
    pthread_mutex_unlock(&evt->mutex);
    return TRUE;
}

WINAPI_EXPORT BOOL ResetEvent(HANDLE hEvent)
{
    handle_entry_t *entry = handle_lookup(hEvent);
    if (!entry || entry->type != HANDLE_TYPE_EVENT) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /* Broker-backed event: reset via atomic store */
    if (is_broker_handle(entry)) {
        shm_event_t *evt = (shm_event_t *)entry->data;
        atomic_store(&evt->futex_word, 0);
        return TRUE;
    }

    event_data_t *evt = (event_data_t *)entry->data;
    pthread_mutex_lock(&evt->mutex);
    evt->signaled = 0;
    pthread_mutex_unlock(&evt->mutex);
    return TRUE;
}

/* --- Mutexes --- */

WINAPI_EXPORT HANDLE CreateMutexA(
    LPSECURITY_ATTRIBUTES lpMutexAttributes,
    BOOL bInitialOwner,
    LPCSTR lpName)
{
    (void)lpMutexAttributes;

    /* Named mutex: try broker first */
    if (lpName && lpName[0]) {
        int shm_fd = -1;
        int ret = objectd_create_mutex(lpName, bInitialOwner ? 1 : 0, &shm_fd);
        if (ret == OBJ_STATUS_OK || ret == OBJ_STATUS_ALREADY_EXISTS) {
            if (ret == OBJ_STATUS_ALREADY_EXISTS)
                set_last_error(183); /* ERROR_ALREADY_EXISTS */
            if (shm_fd >= 0) {
                HANDLE h = broker_mmap_handle(shm_fd, HANDLE_TYPE_MUTEX);
                if (h) {
                    /* If initial owner, lock it via futex CAS — only
                     * stomp owner_tid/recursion if the CAS succeeded, otherwise
                     * another process already holds the mutex. */
                    if (bInitialOwner) {
                        handle_entry_t *entry = handle_lookup(h);
                        if (entry) {
                            shm_mutex_t *m = (shm_mutex_t *)entry->data;
                            uint32_t expected = 0;
                            if (atomic_compare_exchange_strong(&m->futex_word,
                                    &expected, (uint32_t)getpid())) {
                                atomic_store(&m->owner_tid, (uint32_t)gettid());
                                atomic_store(&m->recursion, 1);
                            }
                        }
                    }
                    named_obj_register(lpName, h, HANDLE_TYPE_MUTEX);
                    return h;
                }
            }
        }
        /* Broker unavailable or failed: fall through to local */
    }

    /* Hold lock across lookup and register to prevent TOCTOU race */
    if (lpName) {
        pthread_mutex_lock(&g_named_obj_lock);
        for (int i = 0; i < g_named_obj_count; i++) {
            if (g_named_objs[i].type == HANDLE_TYPE_MUTEX &&
                strcasecmp(g_named_objs[i].name, lpName) == 0) {
                HANDLE existing = g_named_objs[i].handle;
                pthread_mutex_unlock(&g_named_obj_lock);
                set_last_error(183); /* ERROR_ALREADY_EXISTS */
                return existing;
            }
        }
        /* Still holding lock — create and register atomically */
        mutex_data_t *mtx = calloc(1, sizeof(mutex_data_t));
        if (!mtx) {
            pthread_mutex_unlock(&g_named_obj_lock);
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&mtx->mutex, &attr);
        pthread_mutexattr_destroy(&attr);
        if (bInitialOwner) {
            pthread_mutex_lock(&mtx->mutex);
            mtx->owner = (DWORD)gettid();
        }
        HANDLE h = handle_alloc(HANDLE_TYPE_MUTEX, -1, mtx);
        /* handle_alloc returns INVALID_HANDLE_VALUE on failure, but CreateMutex
         * contract returns NULL on failure. Treat both as failure. */
        if (h && h != INVALID_HANDLE_VALUE && g_named_obj_count < NAMED_OBJ_MAX) {
            named_obj_entry_t *e = &g_named_objs[g_named_obj_count++];
            strncpy(e->name, lpName, sizeof(e->name) - 1);
            e->name[sizeof(e->name) - 1] = '\0';
            e->handle = h;
            e->type = HANDLE_TYPE_MUTEX;
            g_named_obj_gen++;
        }
        pthread_mutex_unlock(&g_named_obj_lock);
        if (!h || h == INVALID_HANDLE_VALUE) {
            if (bInitialOwner) pthread_mutex_unlock(&mtx->mutex);
            pthread_mutex_destroy(&mtx->mutex);
            free(mtx);
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
        return h;
    }

    /* Unnamed mutex: no locking needed */
    mutex_data_t *mtx = calloc(1, sizeof(mutex_data_t));
    if (!mtx) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&mtx->mutex, &attr);
    pthread_mutexattr_destroy(&attr);

    if (bInitialOwner) {
        pthread_mutex_lock(&mtx->mutex);
        mtx->owner = (DWORD)gettid();
    }

    HANDLE h = handle_alloc(HANDLE_TYPE_MUTEX, -1, mtx);
    /* handle_alloc returns INVALID_HANDLE_VALUE on failure, but CreateMutex
     * contract returns NULL on failure. Normalize. */
    if (!h || h == INVALID_HANDLE_VALUE) {
        if (bInitialOwner) pthread_mutex_unlock(&mtx->mutex);
        pthread_mutex_destroy(&mtx->mutex);
        free(mtx);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    return h;
}

WINAPI_EXPORT HANDLE CreateMutexW(
    LPSECURITY_ATTRIBUTES lpMutexAttributes,
    BOOL bInitialOwner,
    LPCWSTR lpName)
{
    char narrow[260];
    const char *name = wide_to_narrow_name(lpName, narrow, sizeof(narrow));
    return CreateMutexA(lpMutexAttributes, bInitialOwner, name);
}

WINAPI_EXPORT BOOL ReleaseMutex(HANDLE hMutex)
{
    handle_entry_t *entry = handle_lookup(hMutex);
    if (!entry || entry->type != HANDLE_TYPE_MUTEX) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /* Broker-backed mutex: release via futex */
    if (is_broker_handle(entry)) {
        shm_mutex_t *m = (shm_mutex_t *)entry->data;
        int32_t old_rec = atomic_fetch_sub(&m->recursion, 1);
        if (old_rec > 1) {
            /* Recursive unlock: decremented but still held */
        } else {
            /* Full unlock */
            atomic_store(&m->owner_tid, 0);
            atomic_store(&m->futex_word, 0);
            /* Wake one waiter */
            syscall(SYS_futex, &m->futex_word, FUTEX_WAKE, 1, NULL, NULL, 0);
        }
        return TRUE;
    }

    mutex_data_t *mtx = (mutex_data_t *)entry->data;
    mtx->owner = 0;
    pthread_mutex_unlock(&mtx->mutex);
    return TRUE;
}

/* --- Semaphores --- */

WINAPI_EXPORT HANDLE CreateSemaphoreA(
    LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,
    LONG lInitialCount,
    LONG lMaximumCount,
    LPCSTR lpName)
{
    (void)lpSemaphoreAttributes;

    /* Named semaphore: try broker first */
    if (lpName && lpName[0]) {
        int shm_fd = -1;
        int ret = objectd_create_semaphore(lpName, (int)lInitialCount,
                                           (int)lMaximumCount, &shm_fd);
        if (ret == OBJ_STATUS_OK || ret == OBJ_STATUS_ALREADY_EXISTS) {
            if (ret == OBJ_STATUS_ALREADY_EXISTS)
                set_last_error(183); /* ERROR_ALREADY_EXISTS */
            if (shm_fd >= 0) {
                HANDLE h = broker_mmap_handle(shm_fd, HANDLE_TYPE_SEMAPHORE);
                if (h) {
                    named_obj_register(lpName, h, HANDLE_TYPE_SEMAPHORE);
                    return h;
                }
            }
        }
        /* Broker unavailable or failed: fall through to local */
    }

    if (lInitialCount < 0 || lMaximumCount <= 0 || lInitialCount > lMaximumCount) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    /* Hold lock across lookup and register to prevent TOCTOU race */
    if (lpName) {
        pthread_mutex_lock(&g_named_obj_lock);
        for (int i = 0; i < g_named_obj_count; i++) {
            if (g_named_objs[i].type == HANDLE_TYPE_SEMAPHORE &&
                strcasecmp(g_named_objs[i].name, lpName) == 0) {
                HANDLE existing = g_named_objs[i].handle;
                pthread_mutex_unlock(&g_named_obj_lock);
                set_last_error(183); /* ERROR_ALREADY_EXISTS */
                return existing;
            }
        }
        /* Still holding lock — create and register atomically */
        semaphore_data_t *sem = calloc(1, sizeof(semaphore_data_t));
        if (!sem) {
            pthread_mutex_unlock(&g_named_obj_lock);
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
        sem_init(&sem->sem, 0, (unsigned int)lInitialCount);
        sem->max_count = lMaximumCount;
        HANDLE h = handle_alloc(HANDLE_TYPE_SEMAPHORE, -1, sem);
        /* handle_alloc returns INVALID_HANDLE_VALUE on failure, but CreateSemaphore
         * contract returns NULL on failure. Treat both as failure. */
        if (h && h != INVALID_HANDLE_VALUE && g_named_obj_count < NAMED_OBJ_MAX) {
            named_obj_entry_t *e = &g_named_objs[g_named_obj_count++];
            strncpy(e->name, lpName, sizeof(e->name) - 1);
            e->name[sizeof(e->name) - 1] = '\0';
            e->handle = h;
            e->type = HANDLE_TYPE_SEMAPHORE;
            g_named_obj_gen++;
        }
        pthread_mutex_unlock(&g_named_obj_lock);
        if (!h || h == INVALID_HANDLE_VALUE) {
            sem_destroy(&sem->sem);
            free(sem);
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
        return h;
    }

    /* Unnamed semaphore: no locking needed */
    semaphore_data_t *sem = calloc(1, sizeof(semaphore_data_t));
    if (!sem) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    sem_init(&sem->sem, 0, (unsigned int)lInitialCount);
    sem->max_count = lMaximumCount;

    HANDLE h = handle_alloc(HANDLE_TYPE_SEMAPHORE, -1, sem);
    /* handle_alloc returns INVALID_HANDLE_VALUE on failure, but CreateSemaphore
     * contract returns NULL on failure. Normalize. */
    if (!h || h == INVALID_HANDLE_VALUE) {
        sem_destroy(&sem->sem);
        free(sem);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    return h;
}

WINAPI_EXPORT HANDLE CreateSemaphoreW(
    LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,
    LONG lInitialCount,
    LONG lMaximumCount,
    LPCWSTR lpName)
{
    char narrow[260];
    const char *name = wide_to_narrow_name(lpName, narrow, sizeof(narrow));
    return CreateSemaphoreA(lpSemaphoreAttributes, lInitialCount, lMaximumCount, name);
}

WINAPI_EXPORT BOOL ReleaseSemaphore(HANDLE hSemaphore, LONG lReleaseCount, LPLONG lpPreviousCount)
{
    handle_entry_t *entry = handle_lookup(hSemaphore);
    if (!entry || entry->type != HANDLE_TYPE_SEMAPHORE) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /* Broker-backed semaphore: release via CAS loop to prevent overflow */
    if (is_broker_handle(entry)) {
        shm_semaphore_t *s = (shm_semaphore_t *)entry->data;
        int32_t old;
        do {
            old = atomic_load(&s->futex_word);
            if (old + lReleaseCount > s->max_count) {
                set_last_error(ERROR_TOO_MANY_POSTS);
                return FALSE;
            }
        } while (!atomic_compare_exchange_weak(&s->futex_word, &old, old + lReleaseCount));

        if (lpPreviousCount)
            *lpPreviousCount = (LONG)old;
        /* Wake up to lReleaseCount waiters */
        syscall(SYS_futex, &s->futex_word, FUTEX_WAKE,
                (int)lReleaseCount, NULL, NULL, 0);
        return TRUE;
    }

    semaphore_data_t *sem = (semaphore_data_t *)entry->data;

    /* Get current value */
    int cur_val;
    sem_getvalue(&sem->sem, &cur_val);
    if (lpPreviousCount)
        *lpPreviousCount = (LONG)cur_val;

    /* Check overflow against max */
    if ((LONG)cur_val + lReleaseCount > sem->max_count) {
        set_last_error(ERROR_TOO_MANY_POSTS);
        return FALSE;
    }

    for (LONG i = 0; i < lReleaseCount; i++)
        sem_post(&sem->sem);

    return TRUE;
}

/* --- Critical Sections (heap-allocated to avoid overflow) --- */

/*
 * Windows CRITICAL_SECTION is 40 bytes on x86_64.
 * We cannot fit pthread_mutex_t + metadata into 40 bytes, so we
 * heap-allocate the real data and store a pointer in the first
 * 8 bytes of the caller's CRITICAL_SECTION buffer (the DebugInfo field).
 */

static inline heap_cs_t **cs_get_ptr(void *lpCriticalSection)
{
    return (heap_cs_t **)lpCriticalSection;
}

WINAPI_EXPORT void InitializeCriticalSection(void *lpCriticalSection)
{
    heap_cs_t *cs = calloc(1, sizeof(heap_cs_t));
    if (!cs) return;

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&cs->mutex, &attr);
    pthread_mutexattr_destroy(&attr);
    cs->owner_thread = 0;
    cs->lock_count = -1;
    cs->recursion_count = 0;

    /* Store the pointer in the first 8 bytes */
    *cs_get_ptr(lpCriticalSection) = cs;
}

WINAPI_EXPORT BOOL InitializeCriticalSectionAndSpinCount(
    void *lpCriticalSection, DWORD dwSpinCount)
{
    (void)dwSpinCount;
    InitializeCriticalSection(lpCriticalSection);
    return TRUE;
}

WINAPI_EXPORT BOOL InitializeCriticalSectionEx(
    void *lpCriticalSection, DWORD dwSpinCount, DWORD Flags)
{
    (void)dwSpinCount;
    (void)Flags;
    InitializeCriticalSection(lpCriticalSection);
    return TRUE;
}

WINAPI_EXPORT void EnterCriticalSection(void *lpCriticalSection)
{
    heap_cs_t *cs = *cs_get_ptr(lpCriticalSection);
    if (!cs) return;
    pthread_mutex_lock(&cs->mutex);
    cs->owner_thread = (DWORD)gettid();
    cs->recursion_count++;
    cs->lock_count++;
}

WINAPI_EXPORT BOOL TryEnterCriticalSection(void *lpCriticalSection)
{
    heap_cs_t *cs = *cs_get_ptr(lpCriticalSection);
    if (!cs) return FALSE;
    if (pthread_mutex_trylock(&cs->mutex) == 0) {
        cs->owner_thread = (DWORD)gettid();
        cs->recursion_count++;
        cs->lock_count++;
        return TRUE;
    }
    return FALSE;
}

WINAPI_EXPORT void LeaveCriticalSection(void *lpCriticalSection)
{
    heap_cs_t *cs = *cs_get_ptr(lpCriticalSection);
    if (!cs) return;
    cs->recursion_count--;
    cs->lock_count--;
    if (cs->recursion_count == 0)
        cs->owner_thread = 0;
    pthread_mutex_unlock(&cs->mutex);
}

WINAPI_EXPORT void DeleteCriticalSection(void *lpCriticalSection)
{
    heap_cs_t *cs = *cs_get_ptr(lpCriticalSection);
    if (!cs) return;
    pthread_mutex_destroy(&cs->mutex);
    free(cs);
    *cs_get_ptr(lpCriticalSection) = NULL;
}

/* --- Interlocked Operations --- */

WINAPI_EXPORT LONG InterlockedIncrement(LONG volatile *Addend)
{
    return __sync_add_and_fetch(Addend, 1);
}

WINAPI_EXPORT LONG InterlockedDecrement(LONG volatile *Addend)
{
    return __sync_sub_and_fetch(Addend, 1);
}

WINAPI_EXPORT LONG InterlockedExchange(LONG volatile *Target, LONG Value)
{
    return __sync_lock_test_and_set(Target, Value);
}

WINAPI_EXPORT LONG InterlockedCompareExchange(LONG volatile *Destination,
                                               LONG Exchange, LONG Comparand)
{
    return __sync_val_compare_and_swap(Destination, Comparand, Exchange);
}

WINAPI_EXPORT LONGLONG InterlockedCompareExchange64(LONGLONG volatile *Destination,
                                                     LONGLONG Exchange,
                                                     LONGLONG Comparand)
{
    return __sync_val_compare_and_swap(Destination, Comparand, Exchange);
}

/* --- Extended sync functions required by real Windows apps --- */

/* Forward declaration - defined in kernel32_thread.c */
WINAPI_EXPORT DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);

WINAPI_EXPORT HANDLE CreateEventExW(
    LPSECURITY_ATTRIBUTES lpEventAttributes,
    LPCWSTR lpName,
    DWORD dwFlags,
    DWORD dwDesiredAccess)
{
    (void)dwDesiredAccess;
    BOOL bManualReset = (dwFlags & 0x00000001) ? TRUE : FALSE; /* CREATE_EVENT_MANUAL_RESET */
    BOOL bInitialState = (dwFlags & 0x00000002) ? TRUE : FALSE; /* CREATE_EVENT_INITIAL_SET */
    char narrow[260];
    const char *name = wide_to_narrow_name(lpName, narrow, sizeof(narrow));
    return CreateEventA(lpEventAttributes, bManualReset, bInitialState, name);
}

WINAPI_EXPORT DWORD WaitForSingleObjectEx(
    HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable)
{
    if (!bAlertable)
        return WaitForSingleObject(hHandle, dwMilliseconds);

    /* Alertable wait: drain APCs before blocking (Windows semantics) */
    if (apc_drain_current() > 0)
        return WAIT_IO_COMPLETION;

    /* For zero-timeout, just probe + check APCs */
    if (dwMilliseconds == 0) {
        DWORD rc = WaitForSingleObject(hHandle, 0);
        if (rc == WAIT_TIMEOUT && apc_drain_current() > 0)
            return WAIT_IO_COMPLETION;
        return rc;
    }

    /* Timed/infinite alertable wait: poll the handle in short intervals
     * so we can check for incoming APCs between iterations. */
    struct timespec deadline;
    int has_deadline = (dwMilliseconds != INFINITE);
    if (has_deadline) {
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec  += dwMilliseconds / 1000;
        deadline.tv_nsec += (long)(dwMilliseconds % 1000) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000L;
        }
    }

    unsigned int poll_count = 0;
    while (1) {
        /* Try a short non-blocking wait on the handle */
        DWORD rc = WaitForSingleObject(hHandle, 0);
        if (rc == WAIT_OBJECT_0 || rc == WAIT_FAILED)
            return rc;

        /* Check APCs */
        if (apc_drain_current() > 0)
            return WAIT_IO_COMPLETION;

        /* Check timeout */
        if (has_deadline) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long remaining_ns = (deadline.tv_sec - now.tv_sec) * 1000000000L
                              + (deadline.tv_nsec - now.tv_nsec);
            if (remaining_ns <= 0)
                return WAIT_TIMEOUT;
        }

        /* Adaptive sleep between polls (same schedule as WaitForMultipleObjects) */
        poll_count++;
        if (poll_count < 10)
            usleep(100);       /* First 1ms: 100us intervals */
        else if (poll_count < 100)
            usleep(1000);      /* Next ~100ms: 1ms intervals */
        else
            usleep(10000);     /* After that: 10ms intervals */
    }
}

WINAPI_EXPORT HANDLE CreateMutexExW(
    LPSECURITY_ATTRIBUTES lpMutexAttributes,
    LPCWSTR lpName,
    DWORD dwFlags,
    DWORD dwDesiredAccess)
{
    (void)dwDesiredAccess;
    BOOL bInitialOwner = (dwFlags & 0x00000001) ? TRUE : FALSE;
    char narrow[260];
    const char *name = wide_to_narrow_name(lpName, narrow, sizeof(narrow));
    return CreateMutexA(lpMutexAttributes, bInitialOwner, name);
}

WINAPI_EXPORT HANDLE OpenSemaphoreW(
    DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName)
{
    char narrow[260];
    const char *name = wide_to_narrow_name(lpName, narrow, sizeof(narrow));
    return OpenSemaphoreA(dwDesiredAccess, bInheritHandle, name);
}

WINAPI_EXPORT HANDLE CreateSemaphoreExW(
    LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,
    LONG lInitialCount, LONG lMaximumCount,
    LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess)
{
    (void)dwFlags; (void)dwDesiredAccess;
    char narrow[260];
    const char *name = wide_to_narrow_name(lpName, narrow, sizeof(narrow));
    return CreateSemaphoreA(lpSemaphoreAttributes, lInitialCount, lMaximumCount, name);
}

/* --- OpenMutexA/W, OpenEventA/W, OpenSemaphoreA ---
 *
 * Without a wineserver, we cannot look up named objects across processes.
 * Return ERROR_FILE_NOT_FOUND for cross-process lookups.
 * Within the same process, named objects aren't tracked either (same
 * limitation as CreateMutexA ignoring lpName). Apps that rely on named
 * objects for intra-process sync mostly work because they created the
 * object themselves and hold a handle; OpenMutex is only needed when
 * another process wants to share. For now, stub these.
 */

WINAPI_EXPORT HANDLE OpenMutexA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName)
{
    (void)dwDesiredAccess; (void)bInheritHandle;

    /* Try broker first */
    if (lpName && lpName[0]) {
        int shm_fd = -1;
        int ret = objectd_open_object(lpName, OBJ_REQ_CREATE_MUTEX, &shm_fd);
        if (ret == OBJ_STATUS_OK && shm_fd >= 0) {
            HANDLE h = broker_mmap_handle(shm_fd, HANDLE_TYPE_MUTEX);
            if (h) {
                named_obj_register(lpName, h, HANDLE_TYPE_MUTEX);
                return h;
            }
        }
    }

    /* Local fallback */
    HANDLE h = named_obj_lookup(lpName, HANDLE_TYPE_MUTEX);
    if (!h) set_last_error(2); /* ERROR_FILE_NOT_FOUND */
    return h;
}

WINAPI_EXPORT HANDLE OpenMutexW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName)
{
    char narrow[260];
    const char *name = wide_to_narrow_name(lpName, narrow, sizeof(narrow));
    return OpenMutexA(dwDesiredAccess, bInheritHandle, name);
}

WINAPI_EXPORT HANDLE OpenEventA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName)
{
    (void)dwDesiredAccess; (void)bInheritHandle;

    /* Try broker first */
    if (lpName && lpName[0]) {
        int shm_fd = -1;
        int ret = objectd_open_object(lpName, OBJ_REQ_CREATE_EVENT, &shm_fd);
        if (ret == OBJ_STATUS_OK && shm_fd >= 0) {
            HANDLE h = broker_mmap_handle(shm_fd, HANDLE_TYPE_EVENT);
            if (h) {
                named_obj_register(lpName, h, HANDLE_TYPE_EVENT);
                return h;
            }
        }
    }

    /* Local fallback */
    HANDLE h = named_obj_lookup(lpName, HANDLE_TYPE_EVENT);
    if (!h) set_last_error(2);
    return h;
}

WINAPI_EXPORT HANDLE OpenEventW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName)
{
    char narrow[260];
    const char *name = wide_to_narrow_name(lpName, narrow, sizeof(narrow));
    return OpenEventA(dwDesiredAccess, bInheritHandle, name);
}

WINAPI_EXPORT HANDLE OpenSemaphoreA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName)
{
    (void)dwDesiredAccess; (void)bInheritHandle;

    /* Try broker first */
    if (lpName && lpName[0]) {
        int shm_fd = -1;
        int ret = objectd_open_object(lpName, OBJ_REQ_CREATE_SEMAPHORE, &shm_fd);
        if (ret == OBJ_STATUS_OK && shm_fd >= 0) {
            HANDLE h = broker_mmap_handle(shm_fd, HANDLE_TYPE_SEMAPHORE);
            if (h) {
                named_obj_register(lpName, h, HANDLE_TYPE_SEMAPHORE);
                return h;
            }
        }
    }

    /* Local fallback */
    HANDLE h = named_obj_lookup(lpName, HANDLE_TYPE_SEMAPHORE);
    if (!h) set_last_error(2);
    return h;
}

/* --- SignalObjectAndWait --- */

WINAPI_EXPORT DWORD SignalObjectAndWait(HANDLE hObjectToSignal, HANDLE hObjectToWaitOn,
                                         DWORD dwMilliseconds, BOOL bAlertable)
{
    (void)bAlertable;
    /* Signal the first object */
    handle_entry_t *sig_entry = handle_lookup(hObjectToSignal);
    if (sig_entry) {
        /* Broker-backed handles: signal via atomics + futex */
        if (is_broker_handle(sig_entry)) {
            switch (sig_entry->type) {
            case HANDLE_TYPE_EVENT: {
                shm_event_t *evt = (shm_event_t *)sig_entry->data;
                atomic_store(&evt->futex_word, 1);
                if (evt->manual_reset)
                    syscall(SYS_futex, &evt->futex_word, FUTEX_WAKE, INT32_MAX, NULL, NULL, 0);
                else
                    syscall(SYS_futex, &evt->futex_word, FUTEX_WAKE, 1, NULL, NULL, 0);
                break;
            }
            case HANDLE_TYPE_MUTEX: {
                shm_mutex_t *m = (shm_mutex_t *)sig_entry->data;
                int32_t old_rec = atomic_fetch_sub(&m->recursion, 1);
                if (old_rec <= 1) {
                    atomic_store(&m->owner_tid, 0);
                    atomic_store(&m->futex_word, 0);
                    syscall(SYS_futex, &m->futex_word, FUTEX_WAKE, 1, NULL, NULL, 0);
                }
                break;
            }
            case HANDLE_TYPE_SEMAPHORE: {
                shm_semaphore_t *s = (shm_semaphore_t *)sig_entry->data;
                atomic_fetch_add(&s->futex_word, 1);
                syscall(SYS_futex, &s->futex_word, FUTEX_WAKE, 1, NULL, NULL, 0);
                break;
            }
            default: break;
            }
        } else {
            /* Local handles */
            switch (sig_entry->type) {
            case HANDLE_TYPE_EVENT: {
                event_data_t *evt = (event_data_t *)sig_entry->data;
                pthread_mutex_lock(&evt->mutex);
                evt->signaled = 1;
                if (evt->manual_reset)
                    pthread_cond_broadcast(&evt->cond);
                else
                    pthread_cond_signal(&evt->cond);
                pthread_mutex_unlock(&evt->mutex);
                break;
            }
            case HANDLE_TYPE_MUTEX: {
                mutex_data_t *mtx = (mutex_data_t *)sig_entry->data;
                mtx->owner = 0;
                pthread_mutex_unlock(&mtx->mutex);
                break;
            }
            case HANDLE_TYPE_SEMAPHORE:
                sem_post(&((semaphore_data_t *)sig_entry->data)->sem);
                break;
            default: break;
            }
        }
    }

    return WaitForSingleObject(hObjectToWaitOn, dwMilliseconds);
}

/* --- InitializeSListHead --- */
typedef struct {
    ULONGLONG Alignment;
    ULONGLONG Region;
} SLIST_HEADER;

WINAPI_EXPORT void InitializeSListHead(SLIST_HEADER *ListHead)
{
    if (ListHead) memset(ListHead, 0, sizeof(*ListHead));
}

/* ----------------------------------------------------------------
 * RtlCaptureContext - forwarded to canonical ntdll
 *
 * Many Windows executables import this from kernel32.dll.
 * The canonical implementation lives in ntdll (ntdll_exception.c).
 * We forward at runtime via dlsym.
 * ---------------------------------------------------------------- */

WINAPI_EXPORT void WINAPI RtlCaptureContext(void *ContextRecord)
{
    typedef void (WINAPI *fn_t)(void*);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        void *h = dlopen("libpe_ntdll.so", RTLD_LAZY);
        if (h) real_fn = (fn_t)dlsym(h, "RtlCaptureContext");
    }
    if (real_fn) real_fn(ContextRecord);
    else if (ContextRecord) memset(ContextRecord, 0, 1232);
}

typedef struct { BYTE data[1232]; } CONTEXT_K32;
typedef struct {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
} RUNTIME_FUNCTION_K32;

WINAPI_EXPORT RUNTIME_FUNCTION_K32 *RtlLookupFunctionEntry(
    DWORD64 ControlPc, DWORD64 *ImageBase, PVOID HistoryTable)
{
    (void)ControlPc; (void)HistoryTable;
    if (ImageBase) *ImageBase = 0;
    return NULL;
}

WINAPI_EXPORT void *RtlVirtualUnwind(
    DWORD HandlerType, DWORD64 ImageBase, DWORD64 ControlPc,
    RUNTIME_FUNCTION_K32 *FunctionEntry, CONTEXT_K32 *ContextRecord,
    PVOID *HandlerData, DWORD64 *EstablisherFrame, PVOID ContextPointers)
{
    (void)HandlerType; (void)ImageBase; (void)ControlPc;
    (void)FunctionEntry; (void)ContextRecord; (void)HandlerData;
    (void)EstablisherFrame; (void)ContextPointers;
    return NULL;
}

/* __C_specific_handler — mingw imports this from kernel32, MSVC from msvcrt.
 * Minimal SEH handler that returns EXCEPTION_CONTINUE_SEARCH. */
WINAPI_EXPORT int __C_specific_handler(void *ExceptionRecord,
    void *EstablisherFrame, void *ContextRecord, void *DispatcherContext)
{
    (void)ExceptionRecord; (void)EstablisherFrame;
    (void)ContextRecord; (void)DispatcherContext;
    return 0; /* EXCEPTION_CONTINUE_SEARCH */
}

/* --- Waitable Timers ---
 *
 * Backed by Linux timerfd.  The timerfd becomes readable when the timer
 * fires, so WaitForSingleObject can use poll()/read() on the fd directly.
 *
 * Windows LARGE_INTEGER due time:
 *   Negative = relative (in 100-ns units)
 *   Positive = absolute (since 1601-01-01, but we treat as relative from now)
 *   Zero     = signal immediately
 */

typedef void (__attribute__((ms_abi)) *PTIMERAPCROUTINE)(LPVOID, DWORD, DWORD);

WINAPI_EXPORT HANDLE CreateWaitableTimerA(
    LPSECURITY_ATTRIBUTES lpTimerAttributes,
    BOOL bManualReset,
    LPCSTR lpTimerName)
{
    (void)lpTimerAttributes;

    /* Named timer: check local registry first */
    if (lpTimerName && lpTimerName[0]) {
        HANDLE existing = named_obj_lookup(lpTimerName, HANDLE_TYPE_TIMER);
        if (existing) {
            set_last_error(183); /* ERROR_ALREADY_EXISTS */
            return existing;
        }
    }

    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd < 0) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    timer_data_t *data = calloc(1, sizeof(*data));
    if (!data) {
        close(fd);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    data->timerfd = fd;
    data->manual_reset = bManualReset ? 1 : 0;

    /* Store the timerfd as the handle's fd so WaitForSingleObject can poll it */
    HANDLE h = handle_alloc(HANDLE_TYPE_TIMER, fd, data);
    /* handle_alloc returns INVALID_HANDLE_VALUE on failure, but CreateWaitableTimer
     * contract returns NULL on failure. Normalize. */
    if (!h || h == INVALID_HANDLE_VALUE) {
        close(fd);
        free(data);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    if (lpTimerName && lpTimerName[0])
        named_obj_register(lpTimerName, h, HANDLE_TYPE_TIMER);

    return h;
}

WINAPI_EXPORT HANDLE CreateWaitableTimerW(
    LPSECURITY_ATTRIBUTES lpTimerAttributes,
    BOOL bManualReset,
    LPCWSTR lpTimerName)
{
    char narrow[260];
    const char *name = wide_to_narrow_name(lpTimerName, narrow, sizeof(narrow));
    return CreateWaitableTimerA(lpTimerAttributes, bManualReset, name);
}

WINAPI_EXPORT HANDLE CreateWaitableTimerExW(
    LPSECURITY_ATTRIBUTES lpTimerAttributes,
    LPCWSTR lpTimerName,
    DWORD dwFlags,
    DWORD dwDesiredAccess)
{
    (void)dwDesiredAccess;
    /* CREATE_WAITABLE_TIMER_MANUAL_RESET = 0x00000001 */
    BOOL bManualReset = (dwFlags & 0x00000001) ? TRUE : FALSE;
    return CreateWaitableTimerW(lpTimerAttributes, bManualReset, lpTimerName);
}

WINAPI_EXPORT BOOL SetWaitableTimer(
    HANDLE hTimer,
    const LARGE_INTEGER *lpDueTime,
    LONG lPeriod,
    PTIMERAPCROUTINE pfnCompletionRoutine,
    LPVOID lpArgToCompletionRoutine,
    BOOL fResume)
{
    (void)pfnCompletionRoutine;  /* APC completion not supported */
    (void)lpArgToCompletionRoutine;
    (void)fResume;

    handle_entry_t *entry = handle_lookup(hTimer);
    if (!entry || entry->type != HANDLE_TYPE_TIMER || !entry->data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    timer_data_t *td = (timer_data_t *)entry->data;

    struct itimerspec its;
    memset(&its, 0, sizeof(its));

    if (lpDueTime) {
        LONGLONG due = lpDueTime->QuadPart;

        if (due == 0) {
            /* Signal immediately: 1 nanosecond (timerfd rejects 0.0) */
            its.it_value.tv_nsec = 1;
        } else if (due < 0) {
            /* Negative = relative time in 100-ns units */
            LONGLONG ns = (-due) * 100LL;
            its.it_value.tv_sec  = (time_t)(ns / 1000000000LL);
            its.it_value.tv_nsec = (long)(ns % 1000000000LL);
        } else {
            /* Positive = absolute time (100-ns since 1601-01-01).
             * Convert to relative by subtracting "now" in the same epoch.
             * Windows epoch offset: 11644473600 seconds from 1601 to 1970. */
            struct timespec now;
            clock_gettime(CLOCK_REALTIME, &now);
            LONGLONG now_win = ((LONGLONG)now.tv_sec + 11644473600LL) * 10000000LL
                             + (LONGLONG)now.tv_nsec / 100LL;
            LONGLONG delta = due - now_win;
            if (delta <= 0) {
                /* Already in the past: signal immediately */
                its.it_value.tv_nsec = 1;
            } else {
                LONGLONG ns = delta * 100LL;
                its.it_value.tv_sec  = (time_t)(ns / 1000000000LL);
                its.it_value.tv_nsec = (long)(ns % 1000000000LL);
            }
        }
    }

    /* Periodic interval (milliseconds) */
    if (lPeriod > 0) {
        its.it_interval.tv_sec  = lPeriod / 1000;
        its.it_interval.tv_nsec = (lPeriod % 1000) * 1000000L;
    }

    if (timerfd_settime(td->timerfd, 0, &its, NULL) < 0) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return TRUE;
}

WINAPI_EXPORT BOOL CancelWaitableTimer(HANDLE hTimer)
{
    handle_entry_t *entry = handle_lookup(hTimer);
    if (!entry || entry->type != HANDLE_TYPE_TIMER || !entry->data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    timer_data_t *td = (timer_data_t *)entry->data;

    /* Disarm the timer by setting both value and interval to zero */
    struct itimerspec its;
    memset(&its, 0, sizeof(its));

    if (timerfd_settime(td->timerfd, 0, &its, NULL) < 0) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Drain any pending expiration so the fd is no longer readable */
    uint64_t expirations;
    while (read(td->timerfd, &expirations, sizeof(expirations)) > 0)
        ;

    return TRUE;
}

WINAPI_EXPORT HANDLE OpenWaitableTimerA(
    DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpTimerName)
{
    (void)dwDesiredAccess; (void)bInheritHandle;
    HANDLE h = named_obj_lookup(lpTimerName, HANDLE_TYPE_TIMER);
    if (!h) set_last_error(2); /* ERROR_FILE_NOT_FOUND */
    return h;
}

WINAPI_EXPORT HANDLE OpenWaitableTimerW(
    DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpTimerName)
{
    char narrow[260];
    const char *name = wide_to_narrow_name(lpTimerName, narrow, sizeof(narrow));
    return OpenWaitableTimerA(dwDesiredAccess, bInheritHandle, name);
}
