/*
 * kernel32_async.c - Overlapped I/O support
 *
 * Provides ReadFileEx/WriteFileEx with completion routines,
 * GetOverlappedResult, CancelIo/CancelIoEx.
 * Uses a worker thread pool for async operations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#include "common/dll_common.h"

/* OVERLAPPED is already defined in windef.h — use it directly */

/* Async work item */
typedef struct async_work {
    HANDLE hFile;
    void *buffer;
    DWORD nBytes;
    OVERLAPPED *overlapped;
    void *completionRoutine;  /* LPOVERLAPPED_COMPLETION_ROUTINE */
    int is_write;
    struct async_work *next;
} async_work_t;

/* Work queue */
static async_work_t *g_work_head = NULL;
static pthread_mutex_t g_work_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_work_cond = PTHREAD_COND_INITIALIZER;
static pthread_t g_worker_thread;
static pthread_once_t g_worker_once = PTHREAD_ONCE_INIT;

static void *async_worker(void *arg)
{
    (void)arg;
    while (1) {
        pthread_mutex_lock(&g_work_lock);
        while (!g_work_head)
            pthread_cond_wait(&g_work_cond, &g_work_lock);

        async_work_t *work = g_work_head;
        g_work_head = work->next;
        pthread_mutex_unlock(&g_work_lock);

        /* Perform the I/O */
        int fd = handle_get_fd(work->hFile);
        ssize_t result = -1;
        if (fd >= 0) {
            if (work->overlapped) {
                off_t offset = (off_t)work->overlapped->Offset |
                               ((off_t)work->overlapped->OffsetHigh << 32);
                if (work->is_write)
                    result = pwrite(fd, work->buffer, work->nBytes, offset);
                else
                    result = pread(fd, work->buffer, work->nBytes, offset);
            } else {
                if (work->is_write)
                    result = write(fd, work->buffer, work->nBytes);
                else
                    result = read(fd, work->buffer, work->nBytes);
            }
        }

        /* Update OVERLAPPED */
        if (work->overlapped) {
            if (result >= 0) {
                work->overlapped->Internal = 0; /* STATUS_SUCCESS / ERROR_SUCCESS */
                work->overlapped->InternalHigh = (ULONG_PTR)result;
            } else {
                work->overlapped->Internal = errno_to_win32_error(errno);
                work->overlapped->InternalHigh = 0;
            }
            /* Signal the event if present */
            if (work->overlapped->hEvent) {
                extern __attribute__((ms_abi)) BOOL SetEvent(HANDLE);
                SetEvent(work->overlapped->hEvent);
            }
        }

        /* Call completion routine if provided */
        if (work->completionRoutine) {
            typedef void (__attribute__((ms_abi)) *LPOVERLAPPED_COMPLETION_ROUTINE)(
                DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered,
                OVERLAPPED *lpOverlapped);
            LPOVERLAPPED_COMPLETION_ROUTINE cb = (LPOVERLAPPED_COMPLETION_ROUTINE)work->completionRoutine;
            DWORD err = (result >= 0) ? 0 : errno_to_win32_error(errno);
            DWORD xferred = (result >= 0) ? (DWORD)result : 0;
            cb(err, xferred, work->overlapped);
        }

        free(work);
    }
    return NULL;
}

static void start_worker(void)
{
    pthread_create(&g_worker_thread, NULL, async_worker, NULL);
    pthread_detach(g_worker_thread);
}

static void ensure_worker(void)
{
    pthread_once(&g_worker_once, start_worker);
}

/* Non-static: called from kernel32_file.c for overlapped ReadFile/WriteFile */
void submit_async(HANDLE hFile, void *buf, DWORD nBytes,
                  OVERLAPPED *ovl, void *completion, int is_write)
{
    ensure_worker();

    async_work_t *work = calloc(1, sizeof(async_work_t));
    if (!work) return;
    work->hFile = hFile;
    work->buffer = buf;
    work->nBytes = nBytes;
    work->overlapped = ovl;
    work->completionRoutine = completion;
    work->is_write = is_write;

    pthread_mutex_lock(&g_work_lock);
    work->next = g_work_head;
    g_work_head = work;
    pthread_cond_signal(&g_work_cond);
    pthread_mutex_unlock(&g_work_lock);
}

WINAPI_EXPORT BOOL ReadFileEx(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                               void *lpOverlapped, void *lpCompletionRoutine)
{
    OVERLAPPED *ovl = (OVERLAPPED *)lpOverlapped;
    if (ovl) {
        ovl->Internal = (ULONG_PTR)STATUS_PENDING;
        ovl->InternalHigh = 0;
    }
    submit_async(hFile, lpBuffer, nNumberOfBytesToRead, ovl, lpCompletionRoutine, 0);
    set_last_error(ERROR_IO_PENDING);
    return TRUE;
}

WINAPI_EXPORT BOOL WriteFileEx(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                                void *lpOverlapped, void *lpCompletionRoutine)
{
    OVERLAPPED *ovl = (OVERLAPPED *)lpOverlapped;
    if (ovl) {
        ovl->Internal = (ULONG_PTR)STATUS_PENDING;
        ovl->InternalHigh = 0;
    }
    submit_async(hFile, (void *)lpBuffer, nNumberOfBytesToWrite, ovl, lpCompletionRoutine, 1);
    set_last_error(ERROR_IO_PENDING);
    return TRUE;
}

/* GetOverlappedResult, GetOverlappedResultEx, CancelIo, CancelIoEx
 * are defined in kernel32_iocp.c — don't duplicate here. */

WINAPI_EXPORT BOOL HasOverlappedIoCompleted(void *lpOverlapped)
{
    OVERLAPPED *ovl = (OVERLAPPED *)lpOverlapped;
    return (ovl && ovl->Internal != (ULONG_PTR)STATUS_PENDING) ? TRUE : FALSE;
}
