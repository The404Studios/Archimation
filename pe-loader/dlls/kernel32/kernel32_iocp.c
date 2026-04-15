/*
 * kernel32_iocp.c - I/O Completion Ports with real epoll backend
 *
 * CreateIoCompletionPort, GetQueuedCompletionStatus,
 * PostQueuedCompletionStatus, CancelIo, CancelIoEx,
 * GetOverlappedResult, HasOverlappedIoCompleted.
 *
 * Uses Linux epoll + eventfd for real event-driven I/O completion:
 *   - Each IOCP owns an epoll_fd that monitors associated file descriptors
 *   - An eventfd in the epoll set handles PostQueuedCompletionStatus wakeups
 *   - GetQueuedCompletionStatus blocks on epoll_wait()
 *   - File handles associated via CreateIoCompletionPort are added to epoll
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "common/dll_common.h"

/* ----------------------------------------------------------------
 * Completion port structures
 * ---------------------------------------------------------------- */

#define IOCP_QUEUE_SIZE 4096

typedef struct {
    DWORD      bytes_transferred;
    ULONG_PTR  completion_key;
    LPVOID     overlapped;
    int        is_error;       /* nonzero if this entry represents a failed I/O */
    DWORD      error_code;
} iocp_entry_t;

/* Tracks an fd associated with this completion port */
typedef struct iocp_assoc {
    int            fd;
    ULONG_PTR      completion_key;
    HANDLE         file_handle;
    struct iocp_assoc *next;
} iocp_assoc_t;

typedef struct {
    int             epoll_fd;       /* epoll instance for this IOCP */
    int             event_fd;       /* eventfd for Post wakeups */
    pthread_mutex_t lock;
    iocp_entry_t    queue[IOCP_QUEUE_SIZE];
    int             head;
    int             tail;
    int             count;
    int             closed;
    DWORD           concurrency;
    iocp_assoc_t   *associations;   /* linked list of associated fds */
} iocp_t;

#define MAX_IOCPS 64
static iocp_t *g_iocps[MAX_IOCPS];
static int g_iocp_count = 0;
static pthread_mutex_t g_iocp_global_lock = PTHREAD_MUTEX_INITIALIZER;

/* Sentinel epoll data value to identify the eventfd */
#define IOCP_EVENTFD_SENTINEL 0xFFFFFFFFul

static iocp_t *iocp_from_handle(HANDLE h)
{
    void *data = handle_get_data(h);
    if (data) {
        /* Verify this is actually an IOCP handle */
        handle_entry_t *entry = handle_lookup(h);
        if (entry && entry->type == HANDLE_TYPE_IOCP)
            return (iocp_t *)data;
    }
    return NULL;
}

/* Enqueue a completion entry (caller must hold iocp->lock) */
static int iocp_enqueue_locked(iocp_t *iocp, DWORD bytes, ULONG_PTR key,
                               LPVOID overlapped, int is_error, DWORD error_code)
{
    if (iocp->count >= IOCP_QUEUE_SIZE)
        return -1;

    iocp_entry_t *entry = &iocp->queue[iocp->tail];
    entry->bytes_transferred = bytes;
    entry->completion_key = key;
    entry->overlapped = overlapped;
    entry->is_error = is_error;
    entry->error_code = error_code;
    iocp->tail = (iocp->tail + 1) % IOCP_QUEUE_SIZE;
    iocp->count++;
    return 0;
}

/* Dequeue a completion entry (caller must hold iocp->lock).
 * Returns 0 on success, -1 if queue empty. */
static int iocp_dequeue_locked(iocp_t *iocp, iocp_entry_t *out)
{
    if (iocp->count == 0)
        return -1;

    *out = iocp->queue[iocp->head];
    iocp->head = (iocp->head + 1) % IOCP_QUEUE_SIZE;
    iocp->count--;
    return 0;
}

/* Find the completion key for a given fd */
static ULONG_PTR iocp_find_key_for_fd(iocp_t *iocp, int fd)
{
    for (iocp_assoc_t *a = iocp->associations; a; a = a->next) {
        if (a->fd == fd)
            return a->completion_key;
    }
    return 0;
}

/* ----------------------------------------------------------------
 * CreateIoCompletionPort
 * ---------------------------------------------------------------- */

WINAPI_EXPORT HANDLE CreateIoCompletionPort(
    HANDLE FileHandle,
    HANDLE ExistingCompletionPort,
    ULONG_PTR CompletionKey,
    DWORD NumberOfConcurrentThreads)
{
    if (ExistingCompletionPort) {
        /* Associating a file handle with an existing port */
        iocp_t *iocp = iocp_from_handle(ExistingCompletionPort);
        if (!iocp) {
            set_last_error(ERROR_INVALID_HANDLE);
            return NULL;
        }

        /* If FileHandle is INVALID_HANDLE_VALUE, this is just a validation call */
        if (FileHandle == INVALID_HANDLE_VALUE)
            return ExistingCompletionPort;

        /* Extract the Linux fd from the Win32 handle */
        int fd = handle_get_fd(FileHandle);
        if (fd < 0) {
            /* Not a real fd-backed handle -- still allow association
             * (some apps use IOCP purely as a work queue) */
            return ExistingCompletionPort;
        }

        pthread_mutex_lock(&iocp->lock);

        /* Record the association */
        iocp_assoc_t *assoc = calloc(1, sizeof(iocp_assoc_t));
        if (assoc) {
            assoc->fd = fd;
            assoc->completion_key = CompletionKey;
            assoc->file_handle = FileHandle;
            assoc->next = iocp->associations;
            iocp->associations = assoc;
        }

        /* Add the fd to the epoll set.
         * Use EPOLLIN | EPOLLONESHOT so we get notified once per readiness
         * change -- the app must re-arm after each completion. */
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLONESHOT;
        ev.data.fd = fd;
        if (epoll_ctl(iocp->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            /* EEXIST is OK -- fd was already added (e.g. dup handle) */
            if (errno != EEXIST) {
                /* Non-fatal: the fd might not support epoll (e.g. regular file).
                 * Still allow association for Post/Get work-queue usage. */
            }
        }

        pthread_mutex_unlock(&iocp->lock);
        return ExistingCompletionPort;
    }

    /* ---- Create a new completion port ---- */

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        set_last_error(ERROR_OUTOFMEMORY);
        return NULL;
    }

    int evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (evfd < 0) {
        close(epfd);
        set_last_error(ERROR_OUTOFMEMORY);
        return NULL;
    }

    /* Add the eventfd to the epoll set -- used for Post wakeups */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = (int)IOCP_EVENTFD_SENTINEL;  /* sentinel: marks this as the eventfd */
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, evfd, &ev) < 0) {
        close(evfd);
        close(epfd);
        set_last_error(ERROR_OUTOFMEMORY);
        return NULL;
    }

    pthread_mutex_lock(&g_iocp_global_lock);

    if (g_iocp_count >= MAX_IOCPS) {
        pthread_mutex_unlock(&g_iocp_global_lock);
        close(evfd);
        close(epfd);
        set_last_error(ERROR_OUTOFMEMORY);
        return NULL;
    }

    iocp_t *iocp = calloc(1, sizeof(iocp_t));
    if (!iocp) {
        pthread_mutex_unlock(&g_iocp_global_lock);
        close(evfd);
        close(epfd);
        set_last_error(ERROR_OUTOFMEMORY);
        return NULL;
    }

    pthread_mutex_init(&iocp->lock, NULL);
    iocp->epoll_fd = epfd;
    iocp->event_fd = evfd;
    iocp->concurrency = NumberOfConcurrentThreads;

    g_iocps[g_iocp_count++] = iocp;

    pthread_mutex_unlock(&g_iocp_global_lock);

    HANDLE h = handle_alloc(HANDLE_TYPE_IOCP, -1, iocp);
    if (!h || h == INVALID_HANDLE_VALUE) {
        close(evfd);
        close(epfd);
        /* Remove from g_iocps before freeing, otherwise iteration over the
         * array will read a dangling pointer. */
        pthread_mutex_lock(&g_iocp_global_lock);
        for (int i = 0; i < g_iocp_count; i++) {
            if (g_iocps[i] == iocp) {
                g_iocps[i] = g_iocps[--g_iocp_count];
                g_iocps[g_iocp_count] = NULL;
                break;
            }
        }
        pthread_mutex_unlock(&g_iocp_global_lock);
        pthread_mutex_destroy(&iocp->lock);
        free(iocp);
        set_last_error(ERROR_OUTOFMEMORY);
        return NULL;
    }

    /* If a file handle was specified with the creation call, associate it */
    if (FileHandle != INVALID_HANDLE_VALUE && FileHandle != NULL) {
        CreateIoCompletionPort(FileHandle, h, CompletionKey, 0);
    }

    return h;
}

/* ----------------------------------------------------------------
 * PostQueuedCompletionStatus
 *
 * Enqueues a user-supplied completion packet and wakes a thread
 * blocked in GetQueuedCompletionStatus via the eventfd.
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL PostQueuedCompletionStatus(
    HANDLE CompletionPort,
    DWORD dwNumberOfBytesTransferred,
    ULONG_PTR dwCompletionKey,
    LPOVERLAPPED lpOverlapped)
{
    iocp_t *iocp = iocp_from_handle(CompletionPort);
    if (!iocp) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    pthread_mutex_lock(&iocp->lock);

    if (iocp_enqueue_locked(iocp, dwNumberOfBytesTransferred,
                            dwCompletionKey, lpOverlapped, 0, 0) < 0) {
        pthread_mutex_unlock(&iocp->lock);
        set_last_error(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    pthread_mutex_unlock(&iocp->lock);

    /* Wake one thread blocked in epoll_wait by signaling the eventfd */
    uint64_t val = 1;
    { ssize_t _wr = write(iocp->event_fd, &val, sizeof(val)); (void)_wr; }

    return TRUE;
}

/* ----------------------------------------------------------------
 * GetQueuedCompletionStatus
 *
 * Blocks on epoll_wait(). Wakes for:
 *   1. eventfd readable  -> drain eventfd, dequeue from completion queue
 *   2. associated fd ready -> generate a completion entry for the fd
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL GetQueuedCompletionStatus(
    HANDLE CompletionPort,
    LPDWORD lpNumberOfBytesTransferred,
    ULONG_PTR *lpCompletionKey,
    LPOVERLAPPED *lpOverlapped,
    DWORD dwMilliseconds)
{
    iocp_t *iocp = iocp_from_handle(CompletionPort);
    if (!iocp) {
        if (lpOverlapped) *lpOverlapped = NULL;
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /* Convert Win32 timeout to epoll timeout (ms).
     * INFINITE (0xFFFFFFFF) maps to -1 (block forever).
     * 0 means poll (don't block). */
    int timeout_ms;
    if (dwMilliseconds == INFINITE)
        timeout_ms = -1;
    else
        timeout_ms = (int)dwMilliseconds;

    /*
     * Loop until we get a completion entry or time out.
     * We may need multiple epoll_wait rounds if we get spurious wakes.
     */
    struct timespec start_ts;
    if (timeout_ms > 0)
        clock_gettime(CLOCK_MONOTONIC, &start_ts);

    for (;;) {
        /* First check: is there already a queued entry? */
        pthread_mutex_lock(&iocp->lock);
        if (iocp->closed) {
            pthread_mutex_unlock(&iocp->lock);
            if (lpOverlapped) *lpOverlapped = NULL;
            set_last_error(ERROR_INVALID_HANDLE);
            return FALSE;
        }

        iocp_entry_t entry;
        if (iocp_dequeue_locked(iocp, &entry) == 0) {
            pthread_mutex_unlock(&iocp->lock);
            /* Deliver the completion */
            if (lpNumberOfBytesTransferred)
                *lpNumberOfBytesTransferred = entry.bytes_transferred;
            if (lpCompletionKey)
                *lpCompletionKey = entry.completion_key;
            if (lpOverlapped)
                *lpOverlapped = (LPOVERLAPPED)entry.overlapped;
            if (entry.is_error) {
                set_last_error(entry.error_code);
                return FALSE;
            }
            return TRUE;
        }
        pthread_mutex_unlock(&iocp->lock);

        /* Block on epoll_wait */
        struct epoll_event events[16];
        int nfds = epoll_wait(iocp->epoll_fd, events, 16, timeout_ms);

        if (nfds < 0) {
            if (errno == EINTR)
                continue;  /* interrupted by signal, retry */
            if (lpOverlapped) *lpOverlapped = NULL;
            set_last_error(ERROR_INVALID_HANDLE);
            return FALSE;
        }

        if (nfds == 0) {
            /* Timeout */
            if (lpOverlapped) *lpOverlapped = NULL;
            set_last_error(WAIT_TIMEOUT);
            return FALSE;
        }

        /* Process epoll events */
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == (int)IOCP_EVENTFD_SENTINEL) {
                /* eventfd fired -- drain it. The actual entries are
                 * already in the queue from PostQueuedCompletionStatus. */
                uint64_t val;
                { ssize_t _rd = read(iocp->event_fd, &val, sizeof(val)); (void)_rd; }
            } else {
                /* A real fd became ready -- generate a completion entry.
                 * This is the actual async I/O notification path. */
                int ready_fd = events[i].data.fd;

                pthread_mutex_lock(&iocp->lock);
                ULONG_PTR key = iocp_find_key_for_fd(iocp, ready_fd);

                /* Determine bytes available via a peek.
                 * For sockets/pipes we could use ioctl(FIONREAD),
                 * but for now we report 0 bytes and let the app read. */
                DWORD bytes_avail = 0;

                /* Check for error conditions on the fd */
                int is_err = 0;
                DWORD err_code = 0;
                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                    is_err = 1;
                    err_code = 995; /* ERROR_OPERATION_ABORTED */
                }

                iocp_enqueue_locked(iocp, bytes_avail, key, NULL,
                                    is_err, err_code);
                pthread_mutex_unlock(&iocp->lock);

                /* Re-arm the fd with EPOLLONESHOT so we get the next event */
                struct epoll_event re_ev;
                re_ev.events = EPOLLIN | EPOLLONESHOT;
                re_ev.data.fd = ready_fd;
                epoll_ctl(iocp->epoll_fd, EPOLL_CTL_MOD, ready_fd, &re_ev);
            }
        }

        /* After processing epoll events, loop back to dequeue.
         * Adjust remaining timeout if we have a finite deadline. */
        if (timeout_ms > 0) {
            struct timespec now_ts;
            clock_gettime(CLOCK_MONOTONIC, &now_ts);
            long elapsed_ms = (now_ts.tv_sec - start_ts.tv_sec) * 1000 +
                              (now_ts.tv_nsec - start_ts.tv_nsec) / 1000000;
            timeout_ms = (int)dwMilliseconds - (int)elapsed_ms;
            if (timeout_ms <= 0) {
                /* Time's up -- one more dequeue attempt */
                pthread_mutex_lock(&iocp->lock);
                if (iocp_dequeue_locked(iocp, &entry) == 0) {
                    pthread_mutex_unlock(&iocp->lock);
                    if (lpNumberOfBytesTransferred)
                        *lpNumberOfBytesTransferred = entry.bytes_transferred;
                    if (lpCompletionKey)
                        *lpCompletionKey = entry.completion_key;
                    if (lpOverlapped)
                        *lpOverlapped = (LPOVERLAPPED)entry.overlapped;
                    if (entry.is_error) {
                        set_last_error(entry.error_code);
                        return FALSE;
                    }
                    return TRUE;
                }
                pthread_mutex_unlock(&iocp->lock);
                if (lpOverlapped) *lpOverlapped = NULL;
                set_last_error(WAIT_TIMEOUT);
                return FALSE;
            }
        }
    }
}

/* ----------------------------------------------------------------
 * GetQueuedCompletionStatusEx -- batch dequeue
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL GetQueuedCompletionStatusEx(
    HANDLE CompletionPort,
    LPVOID lpCompletionPortEntries,
    ULONG ulCount,
    PULONG ulNumEntriesRemoved,
    DWORD dwMilliseconds,
    BOOL fAlertable)
{
    (void)fAlertable;

    if (ulCount == 0 || !lpCompletionPortEntries || !ulNumEntriesRemoved) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    typedef struct {
        ULONG_PTR    dwCompletionKey;
        LPOVERLAPPED lpOverlapped;
        ULONG_PTR    Internal;
        DWORD        dwNumberOfBytesTransferred;
    } OVERLAPPED_ENTRY;

    OVERLAPPED_ENTRY *entries = (OVERLAPPED_ENTRY *)lpCompletionPortEntries;

    /* Get the first entry, possibly blocking */
    DWORD bytes;
    ULONG_PTR key;
    LPOVERLAPPED ovl;

    if (!GetQueuedCompletionStatus(CompletionPort, &bytes, &key,
                                   &ovl, dwMilliseconds)) {
        *ulNumEntriesRemoved = 0;
        return FALSE;
    }

    entries[0].dwCompletionKey = key;
    entries[0].lpOverlapped = ovl;
    entries[0].dwNumberOfBytesTransferred = bytes;
    entries[0].Internal = 0;
    ULONG got = 1;

    /* Try to drain more entries without blocking */
    while (got < ulCount) {
        if (!GetQueuedCompletionStatus(CompletionPort, &bytes, &key,
                                       &ovl, 0)) {
            break;  /* no more ready */
        }
        entries[got].dwCompletionKey = key;
        entries[got].lpOverlapped = ovl;
        entries[got].dwNumberOfBytesTransferred = bytes;
        entries[got].Internal = 0;
        got++;
    }

    *ulNumEntriesRemoved = got;
    return TRUE;
}

/* ----------------------------------------------------------------
 * GetOverlappedResult
 * ---------------------------------------------------------------- */

/* WaitForSingleObject declared in kernel32_sync.c (same .so) */
extern __attribute__((ms_abi)) DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);

/* Maximum time (ms) to wait when bWait is TRUE and no hEvent is available.
 * Without an event handle we must poll the Internal field; 5 seconds is a
 * reasonable upper bound before declaring the I/O stuck. */
#define OVERLAPPED_POLL_TIMEOUT_MS 5000
#define OVERLAPPED_POLL_INTERVAL_MS 1

WINAPI_EXPORT BOOL GetOverlappedResult(
    HANDLE hFile,
    LPOVERLAPPED lpOverlapped,
    LPDWORD lpNumberOfBytesTransferred,
    BOOL bWait)
{
    (void)hFile;

    if (!lpOverlapped) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* STATUS_PENDING (NTSTATUS 0x103) — operation still in flight */
    if (lpOverlapped->Internal == (ULONG_PTR)STATUS_PENDING) {
        if (!bWait) {
            /* Caller does not want to wait — report still pending */
            set_last_error(ERROR_IO_INCOMPLETE);
            return FALSE;
        }

        /* Wait for the overlapped event to be signaled by the async worker.
         * If no event was provided, use a timed poll loop on Internal. */
        if (lpOverlapped->hEvent) {
            WaitForSingleObject(lpOverlapped->hEvent, INFINITE);
        } else {
            /* No event handle: poll Internal with short sleeps.
             * Use poll(NULL, 0, ms) as a portable, signal-safe sleep
             * without burning CPU.  Total wait is bounded. */
            int waited_ms = 0;
            while (lpOverlapped->Internal == (ULONG_PTR)STATUS_PENDING &&
                   waited_ms < OVERLAPPED_POLL_TIMEOUT_MS) {
                /* poll(NULL, 0, ms) is a portable, signal-safe sleep */
                poll(NULL, 0, OVERLAPPED_POLL_INTERVAL_MS);
                waited_ms += OVERLAPPED_POLL_INTERVAL_MS;
            }
        }

        /* If still pending after wait, something went wrong */
        if (lpOverlapped->Internal == (ULONG_PTR)STATUS_PENDING) {
            set_last_error(ERROR_IO_INCOMPLETE);
            return FALSE;
        }
    }

    /* Operation completed — check for error */
    if (lpOverlapped->Internal != 0) {
        set_last_error((DWORD)lpOverlapped->Internal);
        if (lpNumberOfBytesTransferred)
            *lpNumberOfBytesTransferred = 0;
        return FALSE;
    }

    if (lpNumberOfBytesTransferred)
        *lpNumberOfBytesTransferred = (DWORD)lpOverlapped->InternalHigh;

    return TRUE;
}

WINAPI_EXPORT BOOL GetOverlappedResultEx(
    HANDLE hFile,
    LPOVERLAPPED lpOverlapped,
    LPDWORD lpNumberOfBytesTransferred,
    DWORD dwMilliseconds,
    BOOL bAlertable)
{
    (void)bAlertable;

    if (!lpOverlapped) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* If still pending and caller specified a timeout, wait on the event */
    if (lpOverlapped->Internal == (ULONG_PTR)STATUS_PENDING && lpOverlapped->hEvent) {
        DWORD wait_result = WaitForSingleObject(lpOverlapped->hEvent,
                                                 dwMilliseconds);
        if (wait_result == WAIT_TIMEOUT) {
            set_last_error(WAIT_TIMEOUT);
            return FALSE;
        }
    }

    /* Fall through to standard result check (bWait=TRUE for final spin) */
    return GetOverlappedResult(hFile, lpOverlapped,
                               lpNumberOfBytesTransferred, TRUE);
}

/* ----------------------------------------------------------------
 * CancelIo / CancelIoEx
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL CancelIo(HANDLE hFile)
{
    (void)hFile;
    return TRUE;
}

WINAPI_EXPORT BOOL CancelIoEx(HANDLE hFile, LPOVERLAPPED lpOverlapped)
{
    (void)hFile;
    (void)lpOverlapped;
    return TRUE;
}

/* ----------------------------------------------------------------
 * CloseIoCompletionPort
 *
 * Marks the port closed, wakes all waiters, cleans up epoll/eventfd.
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL CloseIoCompletionPort(HANDLE CompletionPort)
{
    iocp_t *iocp = iocp_from_handle(CompletionPort);
    if (!iocp) return FALSE;

    pthread_mutex_lock(&iocp->lock);
    iocp->closed = 1;

    /* Remove all associations from the epoll set */
    for (iocp_assoc_t *a = iocp->associations; a; ) {
        epoll_ctl(iocp->epoll_fd, EPOLL_CTL_DEL, a->fd, NULL);
        iocp_assoc_t *next = a->next;
        free(a);
        a = next;
    }
    iocp->associations = NULL;

    pthread_mutex_unlock(&iocp->lock);

    /* Wake all threads blocked in epoll_wait by writing a large value
     * to eventfd, then close the fds. Threads will see closed==1 and exit. */
    uint64_t val = 0xFFFFFFFF;
    { ssize_t _wr = write(iocp->event_fd, &val, sizeof(val)); (void)_wr; }

    /* Give blocked threads a moment, then tear down.
     * Close epoll_fd first -- this makes epoll_wait() return -1/EBADF
     * for any thread still blocked, which they handle via the EINTR/error path. */
    close(iocp->epoll_fd);
    close(iocp->event_fd);
    iocp->epoll_fd = -1;
    iocp->event_fd = -1;

    /* Prevent handle_close() in the CloseHandle wrapper from free()ing iocp
     * while other threads may still deref it (UAF).  Null out the data slot
     * in the handle table entry so handle_close skips the generic free. */
    handle_entry_t *entry = handle_lookup(CompletionPort);
    if (entry)
        entry->data = NULL;

    /* Note: iocp itself is intentionally leaked -- threads may still reference
     * it briefly.  The closed flag tells them to bail out. */
    return TRUE;
}
