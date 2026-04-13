/*
 * kernel32_file.c - File I/O stubs
 *
 * CreateFileA/W, ReadFile, WriteFile, CloseHandle, SetFilePointer,
 * GetFileSize, DeleteFileA, CreateDirectoryA, etc.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/statvfs.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <utime.h>
#include <pthread.h>
#include <limits.h>

#include "common/dll_common.h"
#include "kernel32_internal.h"
#include "compat/trust_gate.h"

/* ---------- FILE_FLAG_DELETE_ON_CLOSE support ---------- */

#ifndef FILE_FLAG_DELETE_ON_CLOSE
#define FILE_FLAG_DELETE_ON_CLOSE 0x04000000
#endif

/*
 * Small hash table mapping fd -> path for delete-on-close files.
 * On CloseHandle, if the fd is found here, we unlink() the path.
 */
#define DOC_TABLE_SIZE 64

typedef struct doc_entry {
    int   fd;       /* -1 = empty slot */
    char *path;     /* strdup'd Linux path; freed on removal */
    struct doc_entry *next;
} doc_entry_t;

static doc_entry_t *doc_buckets[DOC_TABLE_SIZE];
static pthread_mutex_t doc_lock = PTHREAD_MUTEX_INITIALIZER;

static void doc_register(int fd, const char *path)
{
    unsigned bucket = (unsigned)fd % DOC_TABLE_SIZE;
    doc_entry_t *e = malloc(sizeof(doc_entry_t));
    if (!e) return;
    e->fd = fd;
    e->path = strdup(path);
    if (!e->path) {
        free(e);
        return;
    }
    pthread_mutex_lock(&doc_lock);
    e->next = doc_buckets[bucket];
    doc_buckets[bucket] = e;
    pthread_mutex_unlock(&doc_lock);
}

/* Remove entry for fd and return the path (caller must free), or NULL */
static char *doc_remove(int fd)
{
    unsigned bucket = (unsigned)fd % DOC_TABLE_SIZE;
    char *path = NULL;

    pthread_mutex_lock(&doc_lock);
    doc_entry_t **pp = &doc_buckets[bucket];
    while (*pp) {
        if ((*pp)->fd == fd) {
            doc_entry_t *victim = *pp;
            *pp = victim->next;
            path = victim->path;
            free(victim);
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&doc_lock);
    return path;
}

/* ================================================================
 * Share-mode tracking table
 *
 * Windows CreateFile enforces share modes: if process A opens a file
 * with dwShareMode=0, process B cannot open the same file at all.
 * FILE_SHARE_READ / _WRITE / _DELETE selectively allow concurrent
 * access.  We track open files by canonical path in a simple hash
 * table and use flock() as the underlying OS enforcement mechanism.
 * ================================================================ */

#define SHARE_TABLE_SIZE 256

typedef struct share_entry {
    char             path[PATH_MAX]; /* canonical (realpath) path     */
    DWORD            share_mode;     /* OR of FILE_SHARE_* flags      */
    DWORD            access_mode;    /* OR of GENERIC_READ/WRITE      */
    int              open_count;     /* number of open handles        */
    struct share_entry *next;        /* hash chain                    */
} share_entry_t;

static share_entry_t *g_share_table[SHARE_TABLE_SIZE];
static pthread_mutex_t g_share_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned int share_hash(const char *s)
{
    unsigned int h = 5381;
    while (*s)
        h = h * 33 + (unsigned char)*s++;
    return h % SHARE_TABLE_SIZE;
}

/* Find a share entry for the given canonical path.
 * Caller must hold g_share_lock. */
static share_entry_t *share_lookup(const char *canon)
{
    unsigned int idx = share_hash(canon);
    share_entry_t *e = g_share_table[idx];
    while (e) {
        if (strcmp(e->path, canon) == 0)
            return e;
        e = e->next;
    }
    return NULL;
}

/*
 * Check whether a new open (with desired_access / desired_share)
 * conflicts with an existing share entry.
 *
 * Windows rules:
 *   - If the file is already open, the NEW caller's desired access
 *     must be permitted by the EXISTING opener's share_mode.
 *   - Conversely, the existing opener's access must be permitted by
 *     the NEW caller's share_mode.
 *
 * Returns 0 on success (compatible), or ERROR_SHARING_VIOLATION.
 */
static DWORD share_check_conflict(const share_entry_t *existing,
                                  DWORD desired_access,
                                  DWORD desired_share)
{
    /* 1) Does the existing opener's share_mode allow the new access? */
    if ((desired_access & GENERIC_READ) &&
        !(existing->share_mode & FILE_SHARE_READ))
        return ERROR_SHARING_VIOLATION;

    if ((desired_access & GENERIC_WRITE) &&
        !(existing->share_mode & FILE_SHARE_WRITE))
        return ERROR_SHARING_VIOLATION;

    /* 2) Does the new caller's share_mode allow the existing access? */
    if ((existing->access_mode & GENERIC_READ) &&
        !(desired_share & FILE_SHARE_READ))
        return ERROR_SHARING_VIOLATION;

    if ((existing->access_mode & GENERIC_WRITE) &&
        !(desired_share & FILE_SHARE_WRITE))
        return ERROR_SHARING_VIOLATION;

    return 0; /* compatible */
}

/*
 * Register an open in the share table.  Call AFTER the file has been
 * successfully opened.  Caller must hold g_share_lock.
 */
static void share_register(const char *canon, DWORD access, DWORD share)
{
    share_entry_t *e = share_lookup(canon);
    if (e) {
        /* Merge: widen the access bitmap, narrow the share mask */
        e->access_mode |= access;
        e->share_mode  &= share;
        e->open_count++;
    } else {
        e = (share_entry_t *)calloc(1, sizeof(*e));
        if (!e) return;
        strncpy(e->path, canon, PATH_MAX - 1);
        e->access_mode = access;
        e->share_mode  = share;
        e->open_count  = 1;

        unsigned int idx = share_hash(canon);
        e->next = g_share_table[idx];
        g_share_table[idx] = e;
    }
}

/*
 * Unregister one open from the share table.
 * Called from CloseHandle for file handles.
 */
static void share_table_release(int fd)
{
    /* Resolve the file's canonical path from /proc/self/fd/<fd> */
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);

    char canon[PATH_MAX];
    ssize_t len = readlink(proc_path, canon, sizeof(canon) - 1);
    if (len <= 0)
        return;
    canon[len] = '\0';

    pthread_mutex_lock(&g_share_lock);

    unsigned int idx = share_hash(canon);
    share_entry_t **pp = &g_share_table[idx];
    while (*pp) {
        if (strcmp((*pp)->path, canon) == 0) {
            share_entry_t *e = *pp;
            e->open_count--;
            if (e->open_count <= 0) {
                *pp = e->next;
                free(e);
            }
            break;
        }
        pp = &(*pp)->next;
    }

    pthread_mutex_unlock(&g_share_lock);
}

/*
 * Check whether a file is currently open with share modes that
 * forbid deletion.  Used by DeleteFileA.
 * Returns 0 if deletion is allowed, ERROR_SHARING_VIOLATION otherwise.
 */
static DWORD share_check_delete(const char *linux_path)
{
    char canon[PATH_MAX];
    const char *key = linux_path;
    if (realpath(linux_path, canon))
        key = canon;

    DWORD result = 0;

    pthread_mutex_lock(&g_share_lock);
    share_entry_t *e = share_lookup(key);
    if (e && e->open_count > 0 && !(e->share_mode & FILE_SHARE_DELETE))
        result = ERROR_SHARING_VIOLATION;
    pthread_mutex_unlock(&g_share_lock);

    return result;
}

WINAPI_EXPORT HANDLE CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    (void)lpSecurityAttributes;
    (void)hTemplateFile;

    if (!lpFileName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    /* Trust gate: check FILE_WRITE for write access, FILE_READ otherwise */
    if (dwDesiredAccess & GENERIC_WRITE) {
        TRUST_CHECK_ARG_RET(TRUST_GATE_FILE_WRITE, "CreateFileA", lpFileName,
                            INVALID_HANDLE_VALUE);
    } else {
        TRUST_CHECK_ARG_RET(TRUST_GATE_FILE_READ, "CreateFileA", lpFileName,
                            INVALID_HANDLE_VALUE);
    }

    char linux_path[4096];
    win_path_to_linux(lpFileName, linux_path, sizeof(linux_path));

    /*
     * Resolve canonical path for share-mode tracking.
     * For files that don't exist yet (CREATE_NEW / CREATE_ALWAYS /
     * OPEN_ALWAYS), realpath will fail; we fall back to linux_path.
     */
    char canon[PATH_MAX];
    const char *share_key = linux_path;
    if (realpath(linux_path, canon))
        share_key = canon;

    /* ---- Share-mode conflict check ---- */
    pthread_mutex_lock(&g_share_lock);
    share_entry_t *existing = share_lookup(share_key);
    if (existing && existing->open_count > 0) {
        DWORD conflict = share_check_conflict(existing,
                                              dwDesiredAccess,
                                              dwShareMode);
        if (conflict) {
            pthread_mutex_unlock(&g_share_lock);
            set_last_error(ERROR_SHARING_VIOLATION);
            return INVALID_HANDLE_VALUE;
        }
    }
    pthread_mutex_unlock(&g_share_lock);

    int flags = 0;
    mode_t mode = 0644;

    /* Access flags */
    if ((dwDesiredAccess & GENERIC_READ) && (dwDesiredAccess & GENERIC_WRITE))
        flags = O_RDWR;
    else if (dwDesiredAccess & GENERIC_WRITE)
        flags = O_WRONLY;
    else
        flags = O_RDONLY;

    /*
     * Check whether file exists BEFORE open(), so CREATE_ALWAYS and
     * OPEN_ALWAYS can set ERROR_ALREADY_EXISTS (183) per Win32 contract.
     */
    struct stat pre_stat;
    int file_existed = (stat(linux_path, &pre_stat) == 0);

    /* Creation disposition */
    switch (dwCreationDisposition) {
    case CREATE_NEW:        flags |= O_CREAT | O_EXCL; break;
    case CREATE_ALWAYS:     flags |= O_CREAT | O_TRUNC; break;
    case OPEN_EXISTING:     break;
    case OPEN_ALWAYS:       flags |= O_CREAT; break;
    case TRUNCATE_EXISTING: flags |= O_TRUNC; break;
    }

    /* FILE_FLAG_OVERLAPPED: open with O_NONBLOCK so reads/writes don't block */
    if (dwFlagsAndAttributes & FILE_FLAG_OVERLAPPED)
        flags |= O_NONBLOCK;

    int fd = open(linux_path, flags, mode);
    if (fd < 0) {
        set_last_error(errno_to_win32_error(errno));
        return INVALID_HANDLE_VALUE;
    }

    /*
     * Win32 contract: CREATE_ALWAYS and OPEN_ALWAYS succeed but set
     * last-error to ERROR_ALREADY_EXISTS (183) when the file existed.
     * Many programs (installers, updaters) check GetLastError() after
     * these calls to distinguish "created new" vs "opened existing".
     */
    if (file_existed &&
        (dwCreationDisposition == CREATE_ALWAYS ||
         dwCreationDisposition == OPEN_ALWAYS)) {
        set_last_error(ERROR_ALREADY_EXISTS);
    } else {
        set_last_error(0);
    }

    /*
     * Apply flock() for OS-level enforcement:
     *   - Exclusive access (no share write) -> LOCK_EX
     *   - Shared access (share read+write)  -> LOCK_SH
     * Use LOCK_NB so we don't block; if it fails, another process
     * holds a conflicting lock.
     */
    if (dwShareMode == 0 ||
        (!(dwShareMode & FILE_SHARE_WRITE) && (dwDesiredAccess & GENERIC_WRITE))) {
        if (flock(fd, LOCK_EX | LOCK_NB) < 0 && errno == EWOULDBLOCK) {
            close(fd);
            set_last_error(ERROR_SHARING_VIOLATION);
            return INVALID_HANDLE_VALUE;
        }
    } else {
        if (flock(fd, LOCK_SH | LOCK_NB) < 0 && errno == EWOULDBLOCK) {
            close(fd);
            set_last_error(ERROR_SHARING_VIOLATION);
            return INVALID_HANDLE_VALUE;
        }
    }

    /*
     * For files created just now, re-resolve the canonical path
     * so the share table key is stable across future opens.
     */
    if (share_key == linux_path && realpath(linux_path, canon))
        share_key = canon;

    /* Register in the share table */
    pthread_mutex_lock(&g_share_lock);
    share_register(share_key, dwDesiredAccess, dwShareMode);
    pthread_mutex_unlock(&g_share_lock);

    /* Track files opened with FILE_FLAG_DELETE_ON_CLOSE */
    if (dwFlagsAndAttributes & FILE_FLAG_DELETE_ON_CLOSE)
        doc_register(fd, linux_path);

    /* Track overlapped flag in the handle table */
    unsigned int hflags = 0;
    if (dwFlagsAndAttributes & FILE_FLAG_OVERLAPPED)
        hflags |= HANDLE_FLAG_OVERLAPPED;

    return handle_alloc_flags(HANDLE_TYPE_FILE, fd, NULL, hflags);
}

WINAPI_EXPORT HANDLE CreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    if (!lpFileName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    /* Convert wide string (UTF-16LE) to narrow (UTF-8) */
    char narrow[4096];
    utf16_to_utf8(lpFileName, -1, narrow, sizeof(narrow));

    return CreateFileA(narrow, dwDesiredAccess, dwShareMode,
                       lpSecurityAttributes, dwCreationDisposition,
                       dwFlagsAndAttributes, hTemplateFile);
}

/* Defined in kernel32_async.c — submits work to the async I/O thread pool */
extern void submit_async(HANDLE hFile, void *buf, DWORD nBytes,
                         OVERLAPPED *ovl, void *completion, int is_write);

WINAPI_EXPORT BOOL ReadFile(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped)
{
    int fd = handle_get_fd(hFile);
    if (fd < 0) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /*
     * Overlapped path: if the handle was opened with FILE_FLAG_OVERLAPPED
     * and the caller provided an OVERLAPPED structure, dispatch the read
     * to the async worker thread and return ERROR_IO_PENDING.
     */
    if (lpOverlapped && handle_is_overlapped(hFile)) {
        lpOverlapped->Internal = (ULONG_PTR)STATUS_PENDING;
        lpOverlapped->InternalHigh = 0;
        if (lpNumberOfBytesRead)
            *lpNumberOfBytesRead = 0;
        submit_async(hFile, lpBuffer, nNumberOfBytesToRead,
                     lpOverlapped, NULL, 0);
        set_last_error(ERROR_IO_PENDING);
        return FALSE;  /* Win32 convention: returns FALSE with ERROR_IO_PENDING */
    }

    /* Synchronous path */
    ssize_t n;
    if (lpOverlapped) {
        /* Non-overlapped handle but caller passed OVERLAPPED: use pread */
        off_t offset = (off_t)lpOverlapped->Offset |
                       ((off_t)lpOverlapped->OffsetHigh << 32);
        n = pread(fd, lpBuffer, nNumberOfBytesToRead, offset);
    } else {
        n = read(fd, lpBuffer, nNumberOfBytesToRead);
    }

    if (n < 0) {
        set_last_error(errno_to_win32_error(errno));
        if (lpNumberOfBytesRead) *lpNumberOfBytesRead = 0;
        if (lpOverlapped) {
            lpOverlapped->Internal = errno_to_win32_error(errno);
            lpOverlapped->InternalHigh = 0;
        }
        return FALSE;
    }

    if (lpNumberOfBytesRead)
        *lpNumberOfBytesRead = (DWORD)n;
    if (lpOverlapped) {
        lpOverlapped->Internal = 0;
        lpOverlapped->InternalHigh = (ULONG_PTR)n;
    }

    return TRUE;
}

WINAPI_EXPORT BOOL WriteFile(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped)
{
    int fd = handle_get_fd(hFile);
    if (fd < 0) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /*
     * Overlapped path: dispatch to async worker if the handle was opened
     * with FILE_FLAG_OVERLAPPED and an OVERLAPPED structure is provided.
     */
    if (lpOverlapped && handle_is_overlapped(hFile)) {
        lpOverlapped->Internal = (ULONG_PTR)STATUS_PENDING;
        lpOverlapped->InternalHigh = 0;
        if (lpNumberOfBytesWritten)
            *lpNumberOfBytesWritten = 0;
        submit_async(hFile, (void *)lpBuffer, nNumberOfBytesToWrite,
                     lpOverlapped, NULL, 1);
        set_last_error(ERROR_IO_PENDING);
        return FALSE;  /* Win32 convention: returns FALSE with ERROR_IO_PENDING */
    }

    /* Synchronous path */
    ssize_t n;
    if (lpOverlapped) {
        off_t offset = (off_t)lpOverlapped->Offset |
                       ((off_t)lpOverlapped->OffsetHigh << 32);
        n = pwrite(fd, lpBuffer, nNumberOfBytesToWrite, offset);
    } else {
        n = write(fd, lpBuffer, nNumberOfBytesToWrite);
    }

    if (n < 0) {
        set_last_error(errno_to_win32_error(errno));
        if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = 0;
        if (lpOverlapped) {
            lpOverlapped->Internal = errno_to_win32_error(errno);
            lpOverlapped->InternalHigh = 0;
        }
        return FALSE;
    }

    if (lpNumberOfBytesWritten)
        *lpNumberOfBytesWritten = (DWORD)n;
    if (lpOverlapped) {
        lpOverlapped->Internal = 0;
        lpOverlapped->InternalHigh = (ULONG_PTR)n;
    }

    return TRUE;
}

/* Defined in kernel32_sync.c — deregisters named objects on close */
extern void named_obj_unregister(HANDLE h);

WINAPI_EXPORT BOOL CloseHandle(HANDLE hObject)
{
    /* Deregister from named object table before closing */
    named_obj_unregister(hObject);

    /*
     * Type-specific cleanup before handle_close() frees the data pointer.
     * handle_close() only knows about fd and generic free(); we need to
     * clean up type-specific resources (pthread, mutexes, condvars, etc.).
     */
    handle_entry_t *entry = handle_lookup(hObject);
    if (entry && entry->ref_count <= 1) {
        if (entry->type == HANDLE_TYPE_THREAD && entry->data) {
            thread_data_t *td = (thread_data_t *)entry->data;
            pthread_mutex_lock(&td->finish_lock);
            if (!td->joined) {
                td->joined = 1;
                if (td->finished) {
                    pthread_mutex_unlock(&td->finish_lock);
                    pthread_join(td->pthread, NULL);
                } else {
                    /* Thread still running: detach so it doesn't leak */
                    pthread_detach(td->pthread);
                    pthread_mutex_unlock(&td->finish_lock);
                }
            } else {
                pthread_mutex_unlock(&td->finish_lock);
            }
            pthread_mutex_destroy(&td->finish_lock);
            pthread_cond_destroy(&td->finish_cond);
            pthread_mutex_destroy(&td->suspend_lock);
            pthread_cond_destroy(&td->suspend_cond);
        } else if (entry->type == HANDLE_TYPE_EVENT && entry->data) {
            event_data_t *evt = (event_data_t *)entry->data;
            pthread_mutex_destroy(&evt->mutex);
            pthread_cond_destroy(&evt->cond);
        } else if (entry->type == HANDLE_TYPE_MUTEX && entry->data) {
            mutex_data_t *mtx = (mutex_data_t *)entry->data;
            pthread_mutex_destroy(&mtx->mutex);
        } else if (entry->type == HANDLE_TYPE_SEMAPHORE && entry->data) {
            semaphore_data_t *sem_d = (semaphore_data_t *)entry->data;
            sem_destroy(&sem_d->sem);
        } else if (entry->type == HANDLE_TYPE_TIMER && entry->data) {
            timer_data_t *tmr = (timer_data_t *)entry->data;
            close(tmr->timerfd);
            tmr->timerfd = -1; /* Prevent handle_close from closing again */
            entry->fd = -1;
        } else if (entry->type == HANDLE_TYPE_IOCP && entry->data) {
            /* Delegate to CloseIoCompletionPort for full IOCP teardown */
            extern BOOL CloseIoCompletionPort(HANDLE);
            CloseIoCompletionPort(hObject);
        }
    }

    /*
     * Release share-mode tracking and delete-on-close BEFORE closing
     * the fd, since we need the fd to resolve the canonical path via
     * /proc/self/fd/<fd>.
     */
    int fd = handle_get_fd(hObject);
    if (fd >= 0) {
        /* Release share-mode entry (flock is released automatically on close) */
        share_table_release(fd);

        /* FILE_FLAG_DELETE_ON_CLOSE: unlink the file before closing the fd */
        char *doc_path = doc_remove(fd);
        if (doc_path) {
            unlink(doc_path);
            free(doc_path);
        }
    }

    if (handle_close(hObject) < 0) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT DWORD SetFilePointer(
    HANDLE hFile,
    LONG lDistanceToMove,
    LONG *lpDistanceToMoveHigh,
    DWORD dwMoveMethod)
{
    int fd = handle_get_fd(hFile);
    if (fd < 0) {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0xFFFFFFFF;
    }

    int whence;
    switch (dwMoveMethod) {
    case 0: whence = SEEK_SET; break; /* FILE_BEGIN */
    case 1: whence = SEEK_CUR; break; /* FILE_CURRENT */
    case 2: whence = SEEK_END; break; /* FILE_END */
    default: whence = SEEK_SET; break;
    }

    off_t offset = (off_t)lDistanceToMove;
    if (lpDistanceToMoveHigh)
        offset |= ((off_t)*lpDistanceToMoveHigh) << 32;

    off_t result = lseek(fd, offset, whence);
    if (result < 0) {
        set_last_error(errno_to_win32_error(errno));
        return 0xFFFFFFFF;
    }

    if (lpDistanceToMoveHigh)
        *lpDistanceToMoveHigh = (LONG)(result >> 32);

    set_last_error(0); /* NO_ERROR on success */
    return (DWORD)(result & 0xFFFFFFFF);
}

WINAPI_EXPORT BOOL SetFilePointerEx(
    HANDLE hFile,
    LARGE_INTEGER liDistanceToMove,
    PLARGE_INTEGER lpNewFilePointer,
    DWORD dwMoveMethod)
{
    int fd = handle_get_fd(hFile);
    if (fd < 0) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    int whence;
    switch (dwMoveMethod) {
    case 0: whence = SEEK_SET; break;
    case 1: whence = SEEK_CUR; break;
    case 2: whence = SEEK_END; break;
    default: whence = SEEK_SET; break;
    }

    off_t result = lseek(fd, (off_t)liDistanceToMove.QuadPart, whence);
    if (result < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    if (lpNewFilePointer)
        lpNewFilePointer->QuadPart = result;

    return TRUE;
}

WINAPI_EXPORT DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)
{
    int fd = handle_get_fd(hFile);
    if (fd < 0) {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0xFFFFFFFF;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return 0xFFFFFFFF;
    }

    if (lpFileSizeHigh)
        *lpFileSizeHigh = (DWORD)(st.st_size >> 32);

    return (DWORD)(st.st_size & 0xFFFFFFFF);
}

WINAPI_EXPORT BOOL GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize)
{
    int fd = handle_get_fd(hFile);
    if (fd < 0) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    if (lpFileSize)
        lpFileSize->QuadPart = st.st_size;

    return TRUE;
}

WINAPI_EXPORT DWORD GetFileType(HANDLE hFile)
{
    int fd = handle_get_fd(hFile);
    if (fd < 0) return 0; /* FILE_TYPE_UNKNOWN */

    struct stat st;
    if (fstat(fd, &st) < 0) return 0;

    set_last_error(0); /* NO_ERROR - required by GetFileType contract */

    if (S_ISREG(st.st_mode)) return 1;  /* FILE_TYPE_DISK */
    if (S_ISCHR(st.st_mode)) return 2;  /* FILE_TYPE_CHAR */
    if (S_ISFIFO(st.st_mode)) return 3; /* FILE_TYPE_PIPE */
    return 0;
}

WINAPI_EXPORT BOOL FlushFileBuffers(HANDLE hFile)
{
    int fd = handle_get_fd(hFile);
    if (fd < 0) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    if (fsync(fd) != 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL DeleteFileA(LPCSTR lpFileName)
{
    TRUST_CHECK_ARG(TRUST_GATE_FILE_WRITE, "DeleteFileA", lpFileName);

    char linux_path[4096];
    win_path_to_linux(lpFileName, linux_path, sizeof(linux_path));

    /* Check if the file is open without FILE_SHARE_DELETE */
    DWORD share_err = share_check_delete(linux_path);
    if (share_err) {
        set_last_error(share_err);
        return FALSE;
    }

    if (unlink(linux_path) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName)
{
    TRUST_CHECK_ARG(TRUST_GATE_FILE_WRITE, "MoveFileA", lpExistingFileName);

    char src[4096], dst[4096];
    win_path_to_linux(lpExistingFileName, src, sizeof(src));
    win_path_to_linux(lpNewFileName, dst, sizeof(dst));

    if (rename(src, dst) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL CopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists)
{
    char src[4096], dst[4096];
    win_path_to_linux(lpExistingFileName, src, sizeof(src));
    win_path_to_linux(lpNewFileName, dst, sizeof(dst));

    int src_fd = open(src, O_RDONLY);
    if (src_fd < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    int dst_flags = O_WRONLY | O_CREAT | (bFailIfExists ? O_EXCL : O_TRUNC);
    int dst_fd = open(dst, dst_flags, 0644);
    if (dst_fd < 0) {
        close(src_fd);
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    char buf[65536];
    ssize_t n;
    while ((n = read(src_fd, buf, sizeof(buf))) > 0) {
        if (write(dst_fd, buf, n) != n) {
            close(src_fd);
            close(dst_fd);
            set_last_error(errno_to_win32_error(errno));
            return FALSE;
        }
    }

    close(src_fd);
    close(dst_fd);
    return TRUE;
}

WINAPI_EXPORT BOOL CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    (void)lpSecurityAttributes;
    char linux_path[4096];
    win_path_to_linux(lpPathName, linux_path, sizeof(linux_path));

    if (mkdir(linux_path, 0755) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL RemoveDirectoryA(LPCSTR lpPathName)
{
    char linux_path[4096];
    win_path_to_linux(lpPathName, linux_path, sizeof(linux_path));

    if (rmdir(linux_path) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT DWORD GetFileAttributesA(LPCSTR lpFileName)
{
    char linux_path[4096];
    win_path_to_linux(lpFileName, linux_path, sizeof(linux_path));

    struct stat st;
    if (stat(linux_path, &st) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return 0xFFFFFFFF; /* INVALID_FILE_ATTRIBUTES */
    }

    DWORD attrs = 0;
    if (S_ISDIR(st.st_mode))
        attrs |= FILE_ATTRIBUTE_DIRECTORY;
    else
        attrs |= FILE_ATTRIBUTE_NORMAL;

    if (!(st.st_mode & S_IWUSR))
        attrs |= FILE_ATTRIBUTE_READONLY;

    return attrs;
}

/* Path functions (GetCurrentDirectoryA, SetCurrentDirectoryA, GetTempPathA,
 * GetFullPathNameA) are now in kernel32_path.c */

/* ---------- FILETIME conversion helpers ---------- */
#define FILETIME_UNIX_DIFF 116444736000000000ULL

static void timespec_to_filetime(const struct timespec *ts, FILETIME *ft)
{
    uint64_t ticks = ((uint64_t)ts->tv_sec * 10000000ULL) +
                     (ts->tv_nsec / 100) + FILETIME_UNIX_DIFF;
    ft->dwLowDateTime = (DWORD)(ticks & 0xFFFFFFFF);
    ft->dwHighDateTime = (DWORD)(ticks >> 32);
}

static void filetime_to_timespec(const FILETIME *ft, struct timespec *ts)
{
    uint64_t ticks = ((uint64_t)ft->dwHighDateTime << 32) | ft->dwLowDateTime;
    ticks -= FILETIME_UNIX_DIFF;
    ts->tv_sec = ticks / 10000000ULL;
    ts->tv_nsec = (ticks % 10000000ULL) * 100;
}

/* ---------- SetEndOfFile ---------- */

WINAPI_EXPORT BOOL SetEndOfFile(HANDLE hFile)
{
    int fd = handle_get_fd(hFile);
    if (fd < 0) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    off_t pos = lseek(fd, 0, SEEK_CUR);
    if (pos < 0 || ftruncate(fd, pos) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }
    return TRUE;
}

/* ---------- LockFile / UnlockFile ---------- */

WINAPI_EXPORT BOOL LockFile(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh,
                             DWORD nNumberOfBytesToLockLow, DWORD nNumberOfBytesToLockHigh)
{
    int fd = handle_get_fd(hFile);
    if (fd < 0) return FALSE;

    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = ((off_t)dwFileOffsetHigh << 32) | dwFileOffsetLow;
    fl.l_len = ((off_t)nNumberOfBytesToLockHigh << 32) | nNumberOfBytesToLockLow;

    if (fcntl(fd, F_SETLK, &fl) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL LockFileEx(HANDLE hFile, DWORD dwFlags, DWORD dwReserved,
                               DWORD nNumberOfBytesToLockLow, DWORD nNumberOfBytesToLockHigh,
                               LPOVERLAPPED lpOverlapped)
{
    (void)dwReserved; (void)lpOverlapped;
    int fd = handle_get_fd(hFile);
    if (fd < 0) return FALSE;

    struct flock fl;
    fl.l_type = (dwFlags & 0x2) ? F_WRLCK : F_RDLCK; /* LOCKFILE_EXCLUSIVE_LOCK */
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = ((off_t)nNumberOfBytesToLockHigh << 32) | nNumberOfBytesToLockLow;

    int cmd = (dwFlags & 0x1) ? F_SETLK : F_SETLKW; /* LOCKFILE_FAIL_IMMEDIATELY */
    if (fcntl(fd, cmd, &fl) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL UnlockFile(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh,
                               DWORD nNumberOfBytesToUnlockLow, DWORD nNumberOfBytesToUnlockHigh)
{
    int fd = handle_get_fd(hFile);
    if (fd < 0) return FALSE;

    struct flock fl;
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = ((off_t)dwFileOffsetHigh << 32) | dwFileOffsetLow;
    fl.l_len = ((off_t)nNumberOfBytesToUnlockHigh << 32) | nNumberOfBytesToUnlockLow;

    fcntl(fd, F_SETLK, &fl);
    return TRUE;
}

WINAPI_EXPORT BOOL UnlockFileEx(HANDLE hFile, DWORD dwReserved,
                                 DWORD nNumberOfBytesToUnlockLow, DWORD nNumberOfBytesToUnlockHigh,
                                 LPOVERLAPPED lpOverlapped)
{
    (void)dwReserved; (void)lpOverlapped;
    return UnlockFile(hFile, 0, 0, nNumberOfBytesToUnlockLow, nNumberOfBytesToUnlockHigh);
}

/* ---------- GetFileInformationByHandle ---------- */

typedef struct {
    DWORD    dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD    dwVolumeSerialNumber;
    DWORD    nFileSizeHigh;
    DWORD    nFileSizeLow;
    DWORD    nNumberOfLinks;
    DWORD    nFileIndexHigh;
    DWORD    nFileIndexLow;
} BY_HANDLE_FILE_INFORMATION;

WINAPI_EXPORT BOOL GetFileInformationByHandle(HANDLE hFile,
                                               BY_HANDLE_FILE_INFORMATION *lpFileInformation)
{
    int fd = handle_get_fd(hFile);
    if (fd < 0 || !lpFileInformation) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    memset(lpFileInformation, 0, sizeof(*lpFileInformation));

    if (S_ISDIR(st.st_mode))
        lpFileInformation->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
    else
        lpFileInformation->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
    if (!(st.st_mode & S_IWUSR))
        lpFileInformation->dwFileAttributes |= FILE_ATTRIBUTE_READONLY;

    struct timespec ts;
    ts.tv_sec = st.st_ctime; ts.tv_nsec = 0;
    timespec_to_filetime(&ts, &lpFileInformation->ftCreationTime);
    ts.tv_sec = st.st_atime;
    timespec_to_filetime(&ts, &lpFileInformation->ftLastAccessTime);
    ts.tv_sec = st.st_mtime;
    timespec_to_filetime(&ts, &lpFileInformation->ftLastWriteTime);

    lpFileInformation->dwVolumeSerialNumber = (DWORD)st.st_dev;
    lpFileInformation->nFileSizeHigh = (DWORD)(st.st_size >> 32);
    lpFileInformation->nFileSizeLow = (DWORD)(st.st_size & 0xFFFFFFFF);
    lpFileInformation->nNumberOfLinks = (DWORD)st.st_nlink;
    lpFileInformation->nFileIndexHigh = (DWORD)(st.st_ino >> 32);
    lpFileInformation->nFileIndexLow = (DWORD)(st.st_ino & 0xFFFFFFFF);

    return TRUE;
}

/* ---------- GetFileTime / SetFileTime ---------- */

WINAPI_EXPORT BOOL GetFileTime(HANDLE hFile, FILETIME *lpCreationTime,
                                FILETIME *lpLastAccessTime, FILETIME *lpLastWriteTime)
{
    int fd = handle_get_fd(hFile);
    if (fd < 0) return FALSE;

    struct stat st;
    if (fstat(fd, &st) < 0) return FALSE;

    struct timespec ts;
    if (lpCreationTime) {
        ts.tv_sec = st.st_ctime; ts.tv_nsec = 0;
        timespec_to_filetime(&ts, lpCreationTime);
    }
    if (lpLastAccessTime) {
        ts.tv_sec = st.st_atime; ts.tv_nsec = 0;
        timespec_to_filetime(&ts, lpLastAccessTime);
    }
    if (lpLastWriteTime) {
        ts.tv_sec = st.st_mtime; ts.tv_nsec = 0;
        timespec_to_filetime(&ts, lpLastWriteTime);
    }
    return TRUE;
}

WINAPI_EXPORT BOOL SetFileTime(HANDLE hFile, const FILETIME *lpCreationTime,
                                const FILETIME *lpLastAccessTime,
                                const FILETIME *lpLastWriteTime)
{
    int fd = handle_get_fd(hFile);
    if (fd < 0) return FALSE;

    (void)lpCreationTime; /* Linux doesn't support setting creation time */

    struct timespec times[2];
    struct stat st;
    fstat(fd, &st);

    times[0].tv_sec = st.st_atime;
    times[0].tv_nsec = 0;
    times[1].tv_sec = st.st_mtime;
    times[1].tv_nsec = 0;

    if (lpLastAccessTime)
        filetime_to_timespec(lpLastAccessTime, &times[0]);
    if (lpLastWriteTime)
        filetime_to_timespec(lpLastWriteTime, &times[1]);

    futimens(fd, times);
    return TRUE;
}

/* ---------- GetFileAttributesExA/W ---------- */

typedef struct {
    DWORD    dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD    nFileSizeHigh;
    DWORD    nFileSizeLow;
} WIN32_FILE_ATTRIBUTE_DATA;

WINAPI_EXPORT BOOL GetFileAttributesExA(LPCSTR lpFileName, int fInfoLevelId,
                                         LPVOID lpFileInformation)
{
    (void)fInfoLevelId;
    if (!lpFileName || !lpFileInformation) return FALSE;

    char linux_path[4096];
    win_path_to_linux(lpFileName, linux_path, sizeof(linux_path));

    struct stat st;
    if (stat(linux_path, &st) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    WIN32_FILE_ATTRIBUTE_DATA *data = (WIN32_FILE_ATTRIBUTE_DATA *)lpFileInformation;
    memset(data, 0, sizeof(*data));

    if (S_ISDIR(st.st_mode))
        data->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
    else
        data->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
    if (!(st.st_mode & S_IWUSR))
        data->dwFileAttributes |= FILE_ATTRIBUTE_READONLY;

    struct timespec ts;
    ts.tv_sec = st.st_ctime; ts.tv_nsec = 0;
    timespec_to_filetime(&ts, &data->ftCreationTime);
    ts.tv_sec = st.st_atime;
    timespec_to_filetime(&ts, &data->ftLastAccessTime);
    ts.tv_sec = st.st_mtime;
    timespec_to_filetime(&ts, &data->ftLastWriteTime);

    data->nFileSizeHigh = (DWORD)(st.st_size >> 32);
    data->nFileSizeLow = (DWORD)(st.st_size & 0xFFFFFFFF);

    return TRUE;
}

WINAPI_EXPORT BOOL GetFileAttributesExW(LPCWSTR lpFileName, int fInfoLevelId,
                                         LPVOID lpFileInformation)
{
    char narrow[4096];
    utf16_to_utf8(lpFileName, -1, narrow, sizeof(narrow));
    return GetFileAttributesExA(narrow, fInfoLevelId, lpFileInformation);
}

WINAPI_EXPORT DWORD GetFileAttributesW(LPCWSTR lpFileName)
{
    char narrow[4096];
    utf16_to_utf8(lpFileName, -1, narrow, sizeof(narrow));
    return GetFileAttributesA(narrow);
}

WINAPI_EXPORT BOOL SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes)
{
    char linux_path[4096];
    win_path_to_linux(lpFileName, linux_path, sizeof(linux_path));

    struct stat st;
    if (stat(linux_path, &st) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    mode_t mode = st.st_mode;
    if (dwFileAttributes & FILE_ATTRIBUTE_READONLY)
        mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
    else
        mode |= S_IWUSR;

    chmod(linux_path, mode);
    return TRUE;
}

/* ---------- DeleteFileW, MoveFileW, CopyFileW ---------- */

WINAPI_EXPORT BOOL DeleteFileW(LPCWSTR lpFileName)
{
    char narrow[4096];
    utf16_to_utf8(lpFileName, -1, narrow, sizeof(narrow));
    return DeleteFileA(narrow);
}

WINAPI_EXPORT BOOL MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName)
{
    char src[4096], dst[4096];
    utf16_to_utf8(lpExistingFileName, -1, src, sizeof(src));
    utf16_to_utf8(lpNewFileName, -1, dst, sizeof(dst));
    return MoveFileA(src, dst);
}

WINAPI_EXPORT BOOL MoveFileExA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, DWORD dwFlags)
{
    (void)dwFlags; /* MOVEFILE_REPLACE_EXISTING etc handled by rename() */
    return MoveFileA(lpExistingFileName, lpNewFileName);
}

WINAPI_EXPORT BOOL CreateDirectoryW(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    char narrow[4096];
    utf16_to_utf8(lpPathName, -1, narrow, sizeof(narrow));
    return CreateDirectoryA(narrow, lpSecurityAttributes);
}

/* ---------- GetDiskFreeSpaceExA ---------- */

WINAPI_EXPORT BOOL GetDiskFreeSpaceExA(LPCSTR lpDirectoryName,
                                        ULARGE_INTEGER *lpFreeBytesAvailableToCaller,
                                        ULARGE_INTEGER *lpTotalNumberOfBytes,
                                        ULARGE_INTEGER *lpTotalNumberOfFreeBytes)
{
    const char *path = lpDirectoryName ? lpDirectoryName : "/";
    char linux_path[4096];
    win_path_to_linux(path, linux_path, sizeof(linux_path));

    struct statvfs st;
    if (statvfs(linux_path, &st) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    if (lpFreeBytesAvailableToCaller)
        lpFreeBytesAvailableToCaller->QuadPart = (uint64_t)st.f_bavail * st.f_bsize;
    if (lpTotalNumberOfBytes)
        lpTotalNumberOfBytes->QuadPart = (uint64_t)st.f_blocks * st.f_bsize;
    if (lpTotalNumberOfFreeBytes)
        lpTotalNumberOfFreeBytes->QuadPart = (uint64_t)st.f_bfree * st.f_bsize;

    return TRUE;
}

/* ---------- GetDiskFreeSpaceA ---------- */

WINAPI_EXPORT BOOL GetDiskFreeSpaceA(LPCSTR lpRootPathName,
                                      LPDWORD lpSectorsPerCluster,
                                      LPDWORD lpBytesPerSector,
                                      LPDWORD lpNumberOfFreeClusters,
                                      LPDWORD lpTotalNumberOfClusters)
{
    const char *path = lpRootPathName ? lpRootPathName : "/";
    char linux_path[4096];
    win_path_to_linux(path, linux_path, sizeof(linux_path));

    struct statvfs st;
    if (statvfs(linux_path, &st) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    if (lpSectorsPerCluster) *lpSectorsPerCluster = 8;
    if (lpBytesPerSector) *lpBytesPerSector = 512;
    if (lpNumberOfFreeClusters) *lpNumberOfFreeClusters = (DWORD)(st.f_bavail / 8);
    if (lpTotalNumberOfClusters) *lpTotalNumberOfClusters = (DWORD)(st.f_blocks / 8);
    return TRUE;
}

/* ---------- GetVolumeInformationA ---------- */

WINAPI_EXPORT BOOL GetVolumeInformationA(LPCSTR lpRootPathName,
                                          LPSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
                                          LPDWORD lpVolumeSerialNumber,
                                          LPDWORD lpMaximumComponentLength,
                                          LPDWORD lpFileSystemFlags,
                                          LPSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize)
{
    (void)lpRootPathName;
    if (lpVolumeNameBuffer && nVolumeNameSize > 0)
        snprintf(lpVolumeNameBuffer, nVolumeNameSize, "Linux");
    if (lpVolumeSerialNumber) *lpVolumeSerialNumber = 0x12345678;
    if (lpMaximumComponentLength) *lpMaximumComponentLength = 255;
    if (lpFileSystemFlags) *lpFileSystemFlags = 0x00000003; /* FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES */
    if (lpFileSystemNameBuffer && nFileSystemNameSize > 0)
        snprintf(lpFileSystemNameBuffer, nFileSystemNameSize, "ext4");
    return TRUE;
}

/* ---------- DeviceIoControl (stub) ---------- */

WINAPI_EXPORT BOOL DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode,
                                    LPVOID lpInBuffer, DWORD nInBufferSize,
                                    LPVOID lpOutBuffer, DWORD nOutBufferSize,
                                    LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped)
{
    (void)hDevice; (void)dwIoControlCode; (void)lpInBuffer; (void)nInBufferSize;
    (void)lpOutBuffer; (void)nOutBufferSize; (void)lpOverlapped;
    if (lpBytesReturned) *lpBytesReturned = 0;
    set_last_error(ERROR_NOT_SUPPORTED);
    return FALSE;
}

/* ---------- GetFinalPathNameByHandleA ---------- */

/* ---------- GetTempFileNameA ---------- */

WINAPI_EXPORT UINT GetTempFileNameA(LPCSTR lpPathName, LPCSTR lpPrefixString,
                                     UINT uUnique, LPSTR lpTempFileName)
{
    if (!lpPathName || !lpTempFileName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    char linux_path[4096];
    win_path_to_linux(lpPathName, linux_path, sizeof(linux_path));

    const char *prefix = lpPrefixString ? lpPrefixString : "tmp";

    if (uUnique != 0) {
        /* Caller supplied the unique value; just format the name */
        snprintf(lpTempFileName, 260, "%s/%s%04X.tmp",
                 linux_path, prefix, uUnique & 0xFFFF);
        return uUnique;
    }

    /* Generate a unique temp file using mkstemp */
    char pattern[4096];
    snprintf(pattern, sizeof(pattern), "%s/%sXXXXXX.tmp", linux_path, prefix);

    int fd = mkstemps(pattern, 4); /* 4 = strlen(".tmp") */
    if (fd < 0) {
        /* Fallback: use PID + counter */
        static unsigned int counter = 0;
        uUnique = (unsigned int)getpid() ^ (++counter);
        snprintf(lpTempFileName, 260, "%s/%s%04X.tmp",
                 linux_path, prefix, uUnique & 0xFFFF);
        return uUnique & 0xFFFF;
    }

    close(fd);
    strncpy(lpTempFileName, pattern, 260);
    lpTempFileName[259] = '\0';

    /* Extract unique number from the generated filename */
    return (UINT)(getpid() & 0xFFFF);
}

/* ---------- GetFinalPathNameByHandleA ---------- */

WINAPI_EXPORT DWORD GetFinalPathNameByHandleA(HANDLE hFile, LPSTR lpszFilePath,
                                               DWORD cchFilePath, DWORD dwFlags)
{
    (void)dwFlags;
    int fd = handle_get_fd(hFile);
    if (fd < 0) return 0;

    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);

    char real_path[4096];
    ssize_t len = readlink(proc_path, real_path, sizeof(real_path) - 1);
    if (len < 0) return 0;
    real_path[len] = '\0';

    if (lpszFilePath && cchFilePath > 0) {
        strncpy(lpszFilePath, real_path, cchFilePath - 1);
        lpszFilePath[cchFilePath - 1] = '\0';
    }
    return (DWORD)len;
}
