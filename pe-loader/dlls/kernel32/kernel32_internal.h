/*
 * kernel32_internal.h - Shared internal types for kernel32 stub DLL
 *
 * Structures for sync objects and threads that are used by both
 * kernel32_sync.c and kernel32_thread.c (e.g. WaitForSingleObject
 * needs to know the layout of events, mutexes, and semaphores).
 */

#ifndef KERNEL32_INTERNAL_H
#define KERNEL32_INTERNAL_H

#include <pthread.h>
#include <semaphore.h>
#include "common/dll_common.h"
#include "compat/abi_bridge.h"
#include "compat/env_setup.h"

/* ---------- Event ---------- */
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    int             signaled;
    int             manual_reset;
} event_data_t;

/* ---------- Mutex ---------- */
typedef struct {
    pthread_mutex_t mutex;
    DWORD           owner;
} mutex_data_t;

/* ---------- Semaphore ---------- */
typedef struct {
    sem_t  sem;
    LONG   max_count;
} semaphore_data_t;

/* ---------- Critical Section (heap-allocated) ---------- */
typedef struct {
    pthread_mutex_t mutex;
    DWORD           owner_thread;
    LONG            lock_count;
    LONG            recursion_count;
} heap_cs_t;

/* ---------- Process ---------- */
typedef struct {
    pid_t  pid;        /* Linux PID */
    int    exit_code;  /* Exit code once finished */
    int    finished;   /* 1 if process has exited */
} process_data_t;

/* ---------- Waitable Timer ---------- */
typedef struct {
    int  timerfd;        /* Linux timerfd file descriptor */
    int  manual_reset;   /* bManualReset from CreateWaitableTimer */
} timer_data_t;

/* ---------- Thread ---------- */
typedef DWORD (*LPTHREAD_START_ROUTINE)(LPVOID);

typedef struct {
    LPTHREAD_START_ROUTINE start_routine;
    LPVOID parameter;
    int suspended;
    int finished;
    int joined;          /* 1 once pthread_join has been called (prevents double-join) */
    DWORD exit_code;
    pthread_t pthread;
    pthread_mutex_t suspend_lock;
    pthread_cond_t suspend_cond;
    pthread_mutex_t finish_lock;
    pthread_cond_t finish_cond;
} thread_data_t;

/* ---------- APC queue (kernel32_thread.c) ---------- */
/* Drain all pending APCs for the calling thread.  Returns count executed. */
int apc_drain_current(void);
/* Non-destructive check: returns non-zero if APCs are pending. */
int apc_pending_current(void);

#endif /* KERNEL32_INTERNAL_H */
