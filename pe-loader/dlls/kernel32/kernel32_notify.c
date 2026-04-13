/*
 * kernel32_notify.c - File change notifications via inotify
 *
 * Maps Windows FindFirstChangeNotification / ReadDirectoryChangesW
 * to Linux inotify.
 *
 * Synchronous mode: blocks on inotify read with a timeout, translates
 * events to FILE_NOTIFY_INFORMATION structs.
 *
 * Overlapped mode: spawns a background thread that reads inotify and
 * signals the OVERLAPPED.hEvent when events arrive.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <limits.h>
#include <poll.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>

#include "common/dll_common.h"
#include "kernel32_internal.h"

/* ---- Windows notify filter flags ---- */
#ifndef FILE_NOTIFY_CHANGE_FILE_NAME
#define FILE_NOTIFY_CHANGE_FILE_NAME    0x00000001
#endif
#ifndef FILE_NOTIFY_CHANGE_DIR_NAME
#define FILE_NOTIFY_CHANGE_DIR_NAME     0x00000002
#endif
#ifndef FILE_NOTIFY_CHANGE_ATTRIBUTES
#define FILE_NOTIFY_CHANGE_ATTRIBUTES   0x00000004
#endif
#ifndef FILE_NOTIFY_CHANGE_SIZE
#define FILE_NOTIFY_CHANGE_SIZE         0x00000008
#endif
#ifndef FILE_NOTIFY_CHANGE_LAST_WRITE
#define FILE_NOTIFY_CHANGE_LAST_WRITE   0x00000010
#endif
#ifndef FILE_NOTIFY_CHANGE_SECURITY
#define FILE_NOTIFY_CHANGE_SECURITY     0x00000100
#endif
#ifndef FILE_LIST_DIRECTORY
#define FILE_LIST_DIRECTORY             0x00000001
#endif

/* ---- FILE_NOTIFY_INFORMATION ---- */
typedef struct {
    DWORD NextEntryOffset;
    DWORD Action;
    DWORD FileNameLength;  /* in bytes (UTF-16LE) */
    WCHAR FileName[1];     /* variable length */
} FILE_NOTIFY_INFORMATION;

/* ---- FILE_ACTION_* constants ---- */
#define FILE_ACTION_ADDED            0x00000001
#define FILE_ACTION_REMOVED          0x00000002
#define FILE_ACTION_MODIFIED         0x00000003
#define FILE_ACTION_RENAMED_OLD_NAME 0x00000004
#define FILE_ACTION_RENAMED_NEW_NAME 0x00000005

/* ---- Per-watch data stored in handle_entry_t.data ---- */
typedef struct {
    int      inotify_fd;       /* inotify file descriptor */
    int      watch_fd;         /* inotify watch descriptor */
    char     path[PATH_MAX];   /* Linux path being watched */
    DWORD    filter;           /* Windows notify filter */
    int      watch_subtree;    /* bWatchSubtree */
} notify_data_t;

/* ---- Overlapped async context (for background thread) ---- */
typedef struct {
    int           inotify_fd;
    int           cancel_pipe[2]; /* write end signals cancellation */
    LPVOID        buffer;
    DWORD         buffer_length;
    LPDWORD       bytes_returned;
    LPOVERLAPPED  overlapped;
    DWORD         filter;
} async_notify_ctx_t;

/* ---- Convert Windows filter to inotify mask ---- */
static uint32_t filter_to_inotify(DWORD filter)
{
    uint32_t mask = 0;

    if (filter & FILE_NOTIFY_CHANGE_FILE_NAME)
        mask |= IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO;
    if (filter & FILE_NOTIFY_CHANGE_DIR_NAME)
        mask |= IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_ISDIR;
    if (filter & FILE_NOTIFY_CHANGE_ATTRIBUTES)
        mask |= IN_ATTRIB;
    if (filter & FILE_NOTIFY_CHANGE_SIZE)
        mask |= IN_MODIFY;
    if (filter & FILE_NOTIFY_CHANGE_LAST_WRITE)
        mask |= IN_MODIFY | IN_CLOSE_WRITE;
    if (filter & FILE_NOTIFY_CHANGE_SECURITY)
        mask |= IN_ATTRIB;

    /* If nothing matched, watch everything */
    if (mask == 0)
        mask = IN_ALL_EVENTS;

    return mask;
}

/* ---- Map inotify event mask to FILE_ACTION_* ---- */
static DWORD inotify_mask_to_action(uint32_t mask)
{
    if (mask & IN_CREATE)     return FILE_ACTION_ADDED;
    if (mask & IN_DELETE)     return FILE_ACTION_REMOVED;
    if (mask & IN_MOVED_FROM) return FILE_ACTION_RENAMED_OLD_NAME;
    if (mask & IN_MOVED_TO)   return FILE_ACTION_RENAMED_NEW_NAME;
    if (mask & (IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE))
        return FILE_ACTION_MODIFIED;
    return FILE_ACTION_MODIFIED; /* fallback */
}

/*
 * Convert raw inotify events in event_buf (len bytes) into
 * FILE_NOTIFY_INFORMATION records in out_buf (out_buf_size bytes).
 *
 * Returns the total number of bytes written to out_buf, or 0 if no
 * events had names (inotify can fire nameless events for the watched
 * directory itself, which we skip).
 */
static DWORD translate_inotify_events(const char *event_buf, ssize_t len,
                                      void *out_buf, DWORD out_buf_size)
{
    DWORD offset = 0;
    const char *ptr = event_buf;
    FILE_NOTIFY_INFORMATION *prev_fni = NULL;

    while (ptr < event_buf + len) {
        const struct inotify_event *ev = (const struct inotify_event *)ptr;
        ptr += sizeof(struct inotify_event) + ev->len;

        /* Skip events without a filename (directory-level events) */
        if (ev->len == 0 || ev->name[0] == '\0')
            continue;

        size_t name_len = strlen(ev->name);
        DWORD name_bytes = (DWORD)(name_len * sizeof(WCHAR));
        DWORD entry_size = (DWORD)(offsetof(FILE_NOTIFY_INFORMATION, FileName) + name_bytes);
        /* Align each entry to a DWORD boundary as Windows requires */
        entry_size = (entry_size + 3) & ~3u;

        /* Check we have space */
        if (offset + entry_size > out_buf_size)
            break;

        FILE_NOTIFY_INFORMATION *fni = (FILE_NOTIFY_INFORMATION *)((char *)out_buf + offset);

        fni->Action = inotify_mask_to_action(ev->mask);
        fni->FileNameLength = name_bytes;

        /* Convert filename to UTF-16LE (ASCII subset) */
        for (size_t i = 0; i < name_len; i++)
            fni->FileName[i] = (WCHAR)(unsigned char)ev->name[i];

        fni->NextEntryOffset = entry_size;

        /* Link previous entry to this one */
        if (prev_fni)
            prev_fni->NextEntryOffset = (DWORD)((char *)fni - (char *)prev_fni);

        prev_fni = fni;
        offset += entry_size;
    }

    /* Terminate the chain: last entry has NextEntryOffset = 0 */
    if (prev_fni)
        prev_fni->NextEntryOffset = 0;

    return offset;
}

/* ================================================================
 * FindFirstChangeNotificationA
 * ================================================================ */
WINAPI_EXPORT HANDLE FindFirstChangeNotificationA(LPCSTR path,
                                                   BOOL watchSubtree,
                                                   DWORD filter)
{
    if (!path) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    char linux_path[PATH_MAX];
    if (win_path_to_linux(path, linux_path, sizeof(linux_path)) < 0) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    int ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ifd < 0) {
        set_last_error(errno_to_win32_error(errno));
        return INVALID_HANDLE_VALUE;
    }

    uint32_t mask = filter_to_inotify(filter);
    int wfd = inotify_add_watch(ifd, linux_path, mask);
    if (wfd < 0) {
        set_last_error(errno_to_win32_error(errno));
        close(ifd);
        return INVALID_HANDLE_VALUE;
    }

    notify_data_t *data = calloc(1, sizeof(notify_data_t));
    if (!data) {
        inotify_rm_watch(ifd, wfd);
        close(ifd);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return INVALID_HANDLE_VALUE;
    }

    data->inotify_fd = ifd;
    data->watch_fd = wfd;
    data->filter = filter;
    data->watch_subtree = watchSubtree;
    snprintf(data->path, sizeof(data->path), "%s", linux_path);

    HANDLE h = handle_alloc(HANDLE_TYPE_INOTIFY, ifd, data);
    if (h == INVALID_HANDLE_VALUE || h == NULL) {
        free(data);
        inotify_rm_watch(ifd, wfd);
        close(ifd);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return INVALID_HANDLE_VALUE;
    }

    fprintf(stderr, "[kernel32] FindFirstChangeNotificationA('%s') -> %p\n",
            path, h);
    return h;
}

WINAPI_EXPORT HANDLE FindFirstChangeNotificationW(LPCWSTR path,
                                                   BOOL watchSubtree,
                                                   DWORD filter)
{
    char path_a[PATH_MAX];
    if (path) {
        size_t i = 0;
        while (path[i] && i < sizeof(path_a) - 1) {
            path_a[i] = (char)(path[i] & 0x7F);
            i++;
        }
        path_a[i] = '\0';
    } else {
        path_a[0] = '\0';
    }
    return FindFirstChangeNotificationA(path_a, watchSubtree, filter);
}

/* ================================================================
 * FindNextChangeNotification
 *
 * Re-arms the notification handle. We drain pending inotify events
 * so the next WaitForSingleObject will block until a new change
 * occurs.  The inotify watch itself stays active.
 * ================================================================ */
WINAPI_EXPORT BOOL FindNextChangeNotification(HANDLE hChangeHandle)
{
    handle_entry_t *entry = handle_lookup(hChangeHandle);
    if (!entry || !entry->data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    notify_data_t *data = (notify_data_t *)entry->data;

    /* Drain all pending events from inotify fd */
    char drain[4096];
    while (read(data->inotify_fd, drain, sizeof(drain)) > 0)
        ;

    return TRUE;
}

/* ================================================================
 * FindCloseChangeNotification
 * ================================================================ */
WINAPI_EXPORT BOOL FindCloseChangeNotification(HANDLE hChangeHandle)
{
    handle_entry_t *entry = handle_lookup(hChangeHandle);
    if (!entry || !entry->data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    notify_data_t *data = (notify_data_t *)entry->data;
    if (data->watch_fd >= 0)
        inotify_rm_watch(data->inotify_fd, data->watch_fd);

    free(data);
    entry->data = NULL;

    /* handle_close will close the inotify fd */
    handle_close(hChangeHandle);
    return TRUE;
}

/* ================================================================
 * ReadDirectoryChangesW  (synchronous + overlapped)
 *
 * When called on a regular file HANDLE (i.e. a directory opened via
 * CreateFileA with FILE_LIST_DIRECTORY), we create an ephemeral
 * inotify watch, collect events, and tear it down.
 *
 * When called on an existing inotify HANDLE (from
 * FindFirstChangeNotification), we read directly from it.
 *
 * Overlapped mode: if lpOverlapped != NULL we spawn a detached
 * thread that blocks on inotify and signals lpOverlapped->hEvent
 * when events arrive, then return FALSE with ERROR_IO_PENDING.
 * ================================================================ */

/* Forward-declare SetEvent so we can signal the overlapped event */
extern __attribute__((ms_abi)) BOOL SetEvent(HANDLE);

/*
 * Helper: open an inotify fd + watch for the given directory fd.
 * Returns the inotify fd (>= 0) or -1 on failure.
 * *out_wfd receives the watch descriptor.
 */
static int create_inotify_for_dirfd(int dir_fd, DWORD filter, int *out_wfd)
{
    /* Resolve the directory path via /proc/self/fd */
    char proc_link[64];
    char resolved[PATH_MAX];

    snprintf(proc_link, sizeof(proc_link), "/proc/self/fd/%d", dir_fd);
    ssize_t rlen = readlink(proc_link, resolved, sizeof(resolved) - 1);
    if (rlen <= 0)
        return -1;
    resolved[rlen] = '\0';

    int ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ifd < 0)
        return -1;

    uint32_t mask = filter_to_inotify(filter);
    int wfd = inotify_add_watch(ifd, resolved, mask);
    if (wfd < 0) {
        close(ifd);
        return -1;
    }

    *out_wfd = wfd;
    return ifd;
}

/*
 * Background thread for overlapped ReadDirectoryChangesW.
 * Blocks on inotify, fills the caller's buffer, sets *bytes_returned,
 * and signals the overlapped event.
 */
static void *async_notify_thread(void *arg)
{
    async_notify_ctx_t *ctx = (async_notify_ctx_t *)arg;

    /* Block until inotify fires or cancel_pipe is written to.
     * Use a generous timeout (30 seconds) so we don't spin forever
     * if the caller forgets to cancel. */
    struct pollfd pfds[2];
    pfds[0].fd = ctx->inotify_fd;
    pfds[0].events = POLLIN;
    pfds[1].fd = ctx->cancel_pipe[0];
    pfds[1].events = POLLIN;

    int ret = poll(pfds, 2, 30000);

    DWORD bytes_written = 0;

    if (ret > 0 && (pfds[0].revents & POLLIN)) {
        /* Read inotify events */
        char event_buf[4096];
        ssize_t len = read(ctx->inotify_fd, event_buf, sizeof(event_buf));
        if (len > 0) {
            bytes_written = translate_inotify_events(
                event_buf, len, ctx->buffer, ctx->buffer_length);
        }
    }

    if (ctx->bytes_returned)
        *ctx->bytes_returned = bytes_written;

    /* Signal the overlapped event */
    if (ctx->overlapped && ctx->overlapped->hEvent)
        SetEvent(ctx->overlapped->hEvent);

    /* Fill overlapped Internal fields */
    if (ctx->overlapped) {
        ctx->overlapped->Internal = 0;        /* STATUS_SUCCESS */
        ctx->overlapped->InternalHigh = bytes_written;
    }

    /* Clean up */
    close(ctx->cancel_pipe[0]);
    close(ctx->cancel_pipe[1]);
    close(ctx->inotify_fd);
    free(ctx);
    return NULL;
}

WINAPI_EXPORT BOOL ReadDirectoryChangesW(
    HANDLE hDir,
    LPVOID lpBuffer,
    DWORD nBufferLength,
    BOOL bWatchSubtree,
    DWORD dwNotifyFilter,
    LPDWORD lpBytesReturned,
    LPOVERLAPPED lpOverlapped,
    void *lpCompletionRoutine)  /* LPOVERLAPPED_COMPLETION_ROUTINE */
{
    (void)bWatchSubtree;        /* inotify doesn't recurse easily; noted below */
    (void)lpCompletionRoutine;  /* APC completion not supported */

    if (!lpBuffer || nBufferLength < sizeof(FILE_NOTIFY_INFORMATION)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        if (lpBytesReturned) *lpBytesReturned = 0;
        return FALSE;
    }

    handle_entry_t *entry = handle_lookup(hDir);
    if (!entry) {
        set_last_error(ERROR_INVALID_HANDLE);
        if (lpBytesReturned) *lpBytesReturned = 0;
        return FALSE;
    }

    int ifd = -1;
    int wfd = -1;
    int ephemeral = 0; /* 1 if we created a temporary inotify fd */

    if (entry->data) {
        /*
         * Handle is an inotify handle from FindFirstChangeNotification.
         * Re-use its inotify fd directly.
         */
        notify_data_t *nd = (notify_data_t *)entry->data;
        ifd = nd->inotify_fd;
    } else {
        /*
         * Handle is a regular directory handle opened via CreateFileA.
         * Create an ephemeral inotify watch using the fd from the handle.
         */
        int dir_fd = handle_get_fd(hDir);
        if (dir_fd < 0) {
            set_last_error(ERROR_INVALID_HANDLE);
            if (lpBytesReturned) *lpBytesReturned = 0;
            return FALSE;
        }

        ifd = create_inotify_for_dirfd(dir_fd, dwNotifyFilter, &wfd);
        if (ifd < 0) {
            set_last_error(ERROR_INVALID_PARAMETER);
            if (lpBytesReturned) *lpBytesReturned = 0;
            return FALSE;
        }
        ephemeral = 1;
    }

    /* ------ Overlapped (asynchronous) mode ------ */
    if (lpOverlapped) {
        /*
         * For overlapped mode we need a private inotify fd that the
         * background thread will own and close.  If we got an ephemeral
         * one, transfer ownership; otherwise dup the existing one.
         */
        int async_ifd;
        if (ephemeral) {
            async_ifd = ifd;
            ephemeral = 0; /* thread owns it now */
        } else {
            async_ifd = dup(ifd);
            if (async_ifd < 0) {
                set_last_error(errno_to_win32_error(errno));
                if (lpBytesReturned) *lpBytesReturned = 0;
                return FALSE;
            }
        }

        async_notify_ctx_t *ctx = calloc(1, sizeof(async_notify_ctx_t));
        if (!ctx) {
            close(async_ifd);
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            if (lpBytesReturned) *lpBytesReturned = 0;
            return FALSE;
        }

        if (pipe(ctx->cancel_pipe) < 0) {
            close(async_ifd);
            free(ctx);
            set_last_error(errno_to_win32_error(errno));
            if (lpBytesReturned) *lpBytesReturned = 0;
            return FALSE;
        }

        ctx->inotify_fd = async_ifd;
        ctx->buffer = lpBuffer;
        ctx->buffer_length = nBufferLength;
        ctx->bytes_returned = lpBytesReturned;
        ctx->overlapped = lpOverlapped;
        ctx->filter = dwNotifyFilter;

        /* Mark as pending */
        lpOverlapped->Internal = 0x00000103; /* STATUS_PENDING */
        lpOverlapped->InternalHigh = 0;

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        if (pthread_create(&tid, &attr, async_notify_thread, ctx) != 0) {
            close(ctx->cancel_pipe[0]);
            close(ctx->cancel_pipe[1]);
            close(async_ifd);
            free(ctx);
            pthread_attr_destroy(&attr);
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            if (lpBytesReturned) *lpBytesReturned = 0;
            return FALSE;
        }
        pthread_attr_destroy(&attr);

        if (lpBytesReturned) *lpBytesReturned = 0;
        set_last_error(ERROR_IO_PENDING);
        return FALSE; /* Per Win32 contract: returns FALSE, GetLastError() == ERROR_IO_PENDING */
    }

    /* ------ Synchronous mode ------ */
    /*
     * Block until at least one event arrives.  We use poll() with a
     * 5-second timeout to avoid hanging forever if the directory is
     * quiet.  Real Windows ReadDirectoryChangesW blocks indefinitely,
     * but for PE compat a bounded timeout is safer.
     */
    struct pollfd pfd = { .fd = ifd, .events = POLLIN };
    int ret = poll(&pfd, 1, 5000);

    if (ret <= 0) {
        /* Timeout or error -- no events */
        if (lpBytesReturned) *lpBytesReturned = 0;
        if (ephemeral) {
            if (wfd >= 0) inotify_rm_watch(ifd, wfd);
            close(ifd);
        }
        /* Timeout is not an error in the Win32 sense; return TRUE with 0 bytes */
        return TRUE;
    }

    /* Read raw inotify events */
    char event_buf[4096];
    ssize_t len = read(ifd, event_buf, sizeof(event_buf));
    if (len <= 0) {
        if (lpBytesReturned) *lpBytesReturned = 0;
        if (ephemeral) {
            if (wfd >= 0) inotify_rm_watch(ifd, wfd);
            close(ifd);
        }
        return TRUE;
    }

    /* Translate to FILE_NOTIFY_INFORMATION */
    DWORD total = translate_inotify_events(event_buf, len, lpBuffer, nBufferLength);
    if (lpBytesReturned)
        *lpBytesReturned = total;

    if (ephemeral) {
        if (wfd >= 0) inotify_rm_watch(ifd, wfd);
        close(ifd);
    }

    return TRUE;
}

/* Wide variant -- just forward to the same function since it takes HANDLE */
WINAPI_EXPORT BOOL ReadDirectoryChangesExW(
    HANDLE hDir,
    LPVOID lpBuffer,
    DWORD nBufferLength,
    BOOL bWatchSubtree,
    DWORD dwNotifyFilter,
    LPDWORD lpBytesReturned,
    LPOVERLAPPED lpOverlapped,
    void *lpCompletionRoutine,
    DWORD ReadDirectoryNotifyInformationClass)
{
    (void)ReadDirectoryNotifyInformationClass; /* ExtendedFileIdBothDirectoryInfo etc. */
    return ReadDirectoryChangesW(hDir, lpBuffer, nBufferLength, bWatchSubtree,
                                 dwNotifyFilter, lpBytesReturned,
                                 lpOverlapped, lpCompletionRoutine);
}
