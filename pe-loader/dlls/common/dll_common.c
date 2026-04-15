/*
 * dll_common.c - Shared infrastructure for Win32 stub libraries
 *
 * Handle table, error code management, and path translation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "dll_common.h"
#include "compat/env_setup.h"

/* Handle table with freelist for O(1) allocation */
static handle_entry_t g_handles[MAX_HANDLES];
static pthread_mutex_t g_handle_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t g_handle_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static int g_handle_initialized = 0;
static int g_freelist[MAX_HANDLES]; /* Stack of free indices */
static int g_freelist_top = 0;     /* Top of stack (next free slot) */

/*
 * Per-type destructor table.  DLLs owning a handle type register a dtor
 * via handle_register_dtor(); handle_close() consults this table before
 * defaulting to generic free(data).  Sized to cover all HANDLE_TYPE_*
 * values (enum range + #define range, max currently HANDLE_TYPE_IOCP=25).
 */
#define HANDLE_DTOR_SLOTS 64
static handle_dtor_t g_dtors[HANDLE_DTOR_SLOTS];

/* Fallback per-thread error for early init before TEB is ready */
static __thread DWORD tls_last_error_fallback = 0;

/* PE compat prefix (lazily initialized) */
static char g_pe_compat_prefix[PATH_MAX] = {0};

/* Internal init - static to avoid PLT interposition by the loader binary.
 * When the loader binary exports its own handle_table_init() via -rdynamic,
 * ELF PLT calls from within this .so would resolve to the loader's version
 * instead of this one.  Using a static function ensures we always call
 * our own copy. */
static pthread_once_t g_handle_init_once = PTHREAD_ONCE_INIT;

static void handle_table_do_init(void)
{
    memset(g_handles, 0, sizeof(g_handles));

    /* Build freelist: push slots 3..MAX_HANDLES-1 (reverse order so 3 is popped first) */
    g_freelist_top = 0;
    for (int i = MAX_HANDLES - 1; i >= 3; i--) {
        g_freelist[g_freelist_top++] = i;
    }

    /* Reserve slots 0-2 for standard handles (stdin, stdout, stderr) */
    g_handles[0].type = HANDLE_TYPE_CONSOLE;
    g_handles[0].fd = STDIN_FILENO;
    g_handles[0].ref_count = 1;

    g_handles[1].type = HANDLE_TYPE_CONSOLE;
    g_handles[1].fd = STDOUT_FILENO;
    g_handles[1].ref_count = 1;

    g_handles[2].type = HANDLE_TYPE_CONSOLE;
    g_handles[2].fd = STDERR_FILENO;
    g_handles[2].ref_count = 1;

    /* Release-store so other threads that see g_handle_initialized=1 also
     * see the freelist + std-handle writes above. */
    __atomic_store_n(&g_handle_initialized, 1, __ATOMIC_RELEASE);
}

static void handle_table_init_internal(void)
{
    /* Fast path: already initialized.  Acquire-load pairs with the
     * release-store inside handle_table_do_init() so callers who see 1
     * also see all the slot/freelist writes. */
    if (__atomic_load_n(&g_handle_initialized, __ATOMIC_ACQUIRE))
        return;
    pthread_once(&g_handle_init_once, handle_table_do_init);
}

/* Public entry point - exported for dlsym() from loader_init.c */
void handle_table_init(void)
{
    handle_table_init_internal();
}

HANDLE handle_alloc_flags(handle_type_t type, int fd, void *data, unsigned int flags)
{
    handle_table_init_internal();

    pthread_rwlock_wrlock(&g_handle_rwlock);
    pthread_mutex_lock(&g_handle_lock);

    /* O(1) allocation from freelist */
    if (g_freelist_top > 0) {
        int i = g_freelist[--g_freelist_top];
        g_handles[i].type = type;
        g_handles[i].fd = fd;
        g_handles[i].data = data;
        g_handles[i].ref_count = 1;
        g_handles[i].flags = flags;
        pthread_mutex_unlock(&g_handle_lock);
        pthread_rwlock_unlock(&g_handle_rwlock);
        return (HANDLE)(uintptr_t)((i << 2) | 0x3);
    }

    pthread_mutex_unlock(&g_handle_lock);
    pthread_rwlock_unlock(&g_handle_rwlock);
    return INVALID_HANDLE_VALUE;
}

HANDLE handle_alloc(handle_type_t type, int fd, void *data)
{
    return handle_alloc_flags(type, fd, data, 0);
}

static int handle_to_index(HANDLE h);  /* forward declaration */

int handle_is_overlapped(HANDLE h)
{
    int idx = handle_to_index(h);
    if (idx < 0)
        return 0;
    pthread_rwlock_rdlock(&g_handle_rwlock);
    int result = (g_handles[idx].type != HANDLE_TYPE_INVALID &&
                  (g_handles[idx].flags & HANDLE_FLAG_OVERLAPPED)) ? 1 : 0;
    pthread_rwlock_unlock(&g_handle_rwlock);
    return result;
}

int handle_is_dup(HANDLE h)
{
    int idx = handle_to_index(h);
    if (idx < 0)
        return 0;
    pthread_rwlock_rdlock(&g_handle_rwlock);
    int result = (g_handles[idx].type != HANDLE_TYPE_INVALID &&
                  (g_handles[idx].flags & HANDLE_FLAG_DUP)) ? 1 : 0;
    pthread_rwlock_unlock(&g_handle_rwlock);
    return result;
}

/*
 * handle_register_dtor - register a per-type destructor.
 *
 * Called by owning DLLs (e.g. kernel32) at library-load time via a
 * constructor.  The destructor is invoked by handle_close() on the last
 * reference, with locks released and the slot already reclaimed, for
 * non-HANDLE_FLAG_DUP handles of the given type.  The destructor is
 * responsible for destroying embedded pthread primitives and free()ing
 * entry->data.  Registration is last-writer-wins; in practice each type
 * is registered exactly once.
 */
void handle_register_dtor(handle_type_t type, handle_dtor_t fn)
{
    if ((int)type < 0 || (int)type >= HANDLE_DTOR_SLOTS)
        return;
    __atomic_store_n(&g_dtors[type], fn, __ATOMIC_RELEASE);
}

static handle_dtor_t handle_get_dtor(handle_type_t type)
{
    if ((int)type < 0 || (int)type >= HANDLE_DTOR_SLOTS)
        return NULL;
    return __atomic_load_n(&g_dtors[type], __ATOMIC_ACQUIRE);
}

static int handle_to_index(HANDLE h)
{
    uintptr_t val = (uintptr_t)h;
    if ((val & 0x3) != 0x3)
        return -1;
    int idx = (int)(val >> 2);
    if (idx < 0 || idx >= MAX_HANDLES)
        return -1;
    return idx;
}

/*
 * handle_lookup - return a pointer to the handle table entry.
 *
 * WARNING: TOCTOU race -- the returned pointer references the global
 * g_handles[] array directly.  If another thread calls handle_close()
 * after this function returns, the entry may be invalidated or reused.
 * Callers that only need the data pointer should prefer handle_get_data().
 * This function is kept for backward compatibility with the many existing
 * call sites that access type/fd/flags.
 */
handle_entry_t *handle_lookup(HANDLE h)
{
    int idx = handle_to_index(h);
    if (idx < 0)
        return NULL;
    pthread_rwlock_rdlock(&g_handle_rwlock);
    if (g_handles[idx].type == HANDLE_TYPE_INVALID) {
        pthread_rwlock_unlock(&g_handle_rwlock);
        return NULL;
    }
    handle_entry_t *entry = &g_handles[idx];
    pthread_rwlock_unlock(&g_handle_rwlock);
    return entry;
}

/*
 * handle_get_data - safely extract the data pointer under the read lock.
 *
 * Returns the void *data field for the given HANDLE, or NULL if the
 * handle is invalid.  The data pointer itself may still be freed by a
 * concurrent handle_close(), but this is safer than returning a pointer
 * into g_handles[] (which can be memset to zero and reused).
 */
void *handle_get_data(HANDLE h)
{
    int idx = handle_to_index(h);
    if (idx < 0)
        return NULL;
    pthread_rwlock_rdlock(&g_handle_rwlock);
    if (g_handles[idx].type == HANDLE_TYPE_INVALID) {
        pthread_rwlock_unlock(&g_handle_rwlock);
        return NULL;
    }
    void *data = g_handles[idx].data;
    pthread_rwlock_unlock(&g_handle_rwlock);
    return data;
}

int handle_close(HANDLE h)
{
    int idx = handle_to_index(h);
    if (idx < 0)
        return -1;

    pthread_rwlock_wrlock(&g_handle_rwlock);
    pthread_mutex_lock(&g_handle_lock);

    if (g_handles[idx].type == HANDLE_TYPE_INVALID) {
        pthread_mutex_unlock(&g_handle_lock);
        pthread_rwlock_unlock(&g_handle_rwlock);
        return -1;
    }

    /* Snapshot for post-lock cleanup (dtor or generic free) so we can run
     * potentially-blocking destructors (pthread_mutex_destroy, close()) with
     * the handle table locks released.  The slot is cleared under the lock
     * either way, so no other thread can observe the entry mid-destroy. */
    handle_entry_t snapshot = {0};
    int do_cleanup = 0;

    g_handles[idx].ref_count--;
    if (g_handles[idx].ref_count <= 0) {
        /* CloseHandle on a std handle (stdin/stdout/stderr = slots 0/1/2)
         * must be a no-op on Windows -- standard handles persist for the
         * lifetime of the process and other kernel32 code paths still use
         * GetStdHandle() to obtain them.  Clamp ref_count at 1, skip the
         * memset/freelist push, and skip cleanup so the fd stays alive
         * and the slot never gets reallocated to something else. */
        if (idx < 3) {
            g_handles[idx].ref_count = 1;
        } else {
            snapshot = g_handles[idx];
            do_cleanup = 1;
            memset(&g_handles[idx], 0, sizeof(handle_entry_t));
            /* Return slot to freelist for O(1) reuse */
            if (g_freelist_top < MAX_HANDLES) {
                g_freelist[g_freelist_top++] = idx;
            }
        }
    }

    pthread_mutex_unlock(&g_handle_lock);
    pthread_rwlock_unlock(&g_handle_rwlock);

    if (do_cleanup) {
        /*
         * HANDLE_FLAG_DUP: this slot was a duplicate (e.g. NtDuplicateObject)
         * that borrowed its fd/data from another slot.  The original owner
         * will close the fd, destroy pthread primitives, and free the data.
         * Doing any of that here would cause double-free / UAF / premature
         * fd close on the original.  Just reclaim the slot and return.
         */
        if (snapshot.flags & HANDLE_FLAG_DUP)
            return 0;

        /* Owning close path: run fd/data cleanup.  Order: fd close first so
         * destructors that also stash an fd see a consistent view. */
        if (snapshot.fd >= 0 && idx >= 3) {
            close(snapshot.fd);
        }

        /* Broker-backed shared-memory page uses munmap instead of free. */
        if (snapshot.fd == -42 && snapshot.data) {
            munmap(snapshot.data, 4096);
            return 0;
        }

        if (snapshot.data) {
            /* Type-specific destructor takes priority over generic free() so
             * pthread/sem primitives inside type-specific structs are torn
             * down properly.  The destructor OWNS the free() of snapshot.data.
             * If no destructor is registered, fall back to generic free(). */
            handle_dtor_t dtor = handle_get_dtor(snapshot.type);
            if (dtor)
                dtor(&snapshot);
            else
                free(snapshot.data);
        }
    }

    return 0;
}

int handle_get_fd(HANDLE h)
{
    int idx = handle_to_index(h);
    if (idx < 0)
        return -1;
    pthread_rwlock_rdlock(&g_handle_rwlock);
    int fd = -1;
    if (g_handles[idx].type != HANDLE_TYPE_INVALID)
        fd = g_handles[idx].fd;
    pthread_rwlock_unlock(&g_handle_rwlock);
    return fd;
}

HANDLE get_std_handle(DWORD std_handle_id)
{
    handle_table_init_internal();

    switch (std_handle_id) {
    case STD_INPUT_HANDLE:
        return (HANDLE)(uintptr_t)((0 << 2) | 0x3);
    case STD_OUTPUT_HANDLE:
        return (HANDLE)(uintptr_t)((1 << 2) | 0x3);
    case STD_ERROR_HANDLE:
        return (HANDLE)(uintptr_t)((2 << 2) | 0x3);
    default:
        return INVALID_HANDLE_VALUE;
    }
}

void set_last_error(DWORD error)
{
    /* Write to TEB.LastErrorValue (the real Windows error store) */
    env_set_last_error(error);
    /* Also keep fallback in case TEB isn't set up yet */
    tls_last_error_fallback = error;
}

DWORD get_last_error(void)
{
    /* Read from TEB if available, else fallback */
    void *teb = env_get_teb();
    if (teb)
        return env_get_last_error();
    return tls_last_error_fallback;
}

DWORD errno_to_win32_error(int err)
{
    switch (err) {
    case 0:         return ERROR_SUCCESS;
    case ENOENT:    return ERROR_FILE_NOT_FOUND;
    case EACCES:    return ERROR_ACCESS_DENIED;
    case EPERM:     return ERROR_ACCESS_DENIED;
    case EEXIST:    return ERROR_FILE_EXISTS;
    case ENOMEM:    return ERROR_NOT_ENOUGH_MEMORY;
    case EINVAL:    return ERROR_INVALID_PARAMETER;
    case EBADF:     return ERROR_INVALID_HANDLE;
    case ENOTEMPTY: return ERROR_PATH_NOT_FOUND;
    case EMFILE:    return ERROR_NOT_ENOUGH_MEMORY;
    case ENFILE:    return ERROR_NOT_ENOUGH_MEMORY;
    case ENOSPC:    return ERROR_OUTOFMEMORY;
    case EPIPE:     return ERROR_BROKEN_PIPE;
    case EBUSY:     return ERROR_SHARING_VIOLATION;
    default:        return ERROR_INVALID_FUNCTION;
    }
}

int win32_error_to_errno(DWORD err)
{
    switch (err) {
    case ERROR_SUCCESS:             return 0;
    case ERROR_FILE_NOT_FOUND:      return ENOENT;
    case ERROR_PATH_NOT_FOUND:      return ENOENT;
    case ERROR_ACCESS_DENIED:       return EACCES;
    case ERROR_FILE_EXISTS:         return EEXIST;
    case ERROR_ALREADY_EXISTS:      return EEXIST;
    case ERROR_NOT_ENOUGH_MEMORY:   return ENOMEM;
    case ERROR_OUTOFMEMORY:         return ENOMEM;
    case ERROR_INVALID_PARAMETER:   return EINVAL;
    case ERROR_INVALID_HANDLE:      return EBADF;
    case ERROR_BROKEN_PIPE:         return EPIPE;
    default:                        return EINVAL;
    }
}

const char *get_pe_compat_prefix(void)
{
    if (g_pe_compat_prefix[0] == '\0') {
        const char *home = getenv("HOME");
        if (home) {
            snprintf(g_pe_compat_prefix, sizeof(g_pe_compat_prefix),
                     "%s/.pe-compat", home);
        } else {
            snprintf(g_pe_compat_prefix, sizeof(g_pe_compat_prefix),
                     "/tmp/.pe-compat");
        }
    }
    return g_pe_compat_prefix;
}

int win_path_to_linux(const char *win_path, char *linux_path, size_t size)
{
    if (!win_path || !linux_path || size == 0)
        return -1;

    const char *p = win_path;

    /* Strip \\?\ long path prefix */
    if (p[0] == '\\' && p[1] == '\\' && p[2] == '?' && p[3] == '\\') {
        p += 4;
    }

    /* Handle special device names */
    if (strcasecmp(p, "NUL") == 0 || strcasecmp(p, "NUL:") == 0) {
        strncpy(linux_path, "/dev/null", size - 1);
        linux_path[size - 1] = '\0';
        return 0;
    }
    if (strcasecmp(p, "CON") == 0) {
        strncpy(linux_path, "/dev/tty", size - 1);
        linux_path[size - 1] = '\0';
        return 0;
    }
    if (strcasecmp(p, "PRN") == 0 || strcasecmp(p, "AUX") == 0) {
        strncpy(linux_path, "/dev/null", size - 1);
        linux_path[size - 1] = '\0';
        return 0;
    }
    /* COM1-COM9 -> /dev/null (no real serial ports in PE compat) */
    if ((strncasecmp(p, "COM", 3) == 0) && p[3] >= '1' && p[3] <= '9' &&
        (p[4] == '\0' || p[4] == ':')) {
        strncpy(linux_path, "/dev/null", size - 1);
        linux_path[size - 1] = '\0';
        return 0;
    }
    /* LPT1-LPT9 -> /dev/null (no parallel ports) */
    if ((strncasecmp(p, "LPT", 3) == 0) && p[3] >= '1' && p[3] <= '9' &&
        (p[4] == '\0' || p[4] == ':')) {
        strncpy(linux_path, "/dev/null", size - 1);
        linux_path[size - 1] = '\0';
        return 0;
    }

    /* Handle UNC paths: \\server\share\path -> /mnt/share/path */
    if (p[0] == '\\' && p[1] == '\\') {
        const char *server_start = p + 2;
        const char *share_start = strchr(server_start, '\\');
        if (share_start) {
            share_start++;
            const char *path_start = strchr(share_start, '\\');
            size_t share_len = path_start ? (size_t)(path_start - share_start) : strlen(share_start);
            char share[256];
            if (share_len >= sizeof(share)) share_len = sizeof(share) - 1;
            memcpy(share, share_start, share_len);
            share[share_len] = '\0';

            if (path_start) {
                snprintf(linux_path, size, "/mnt/%s%s", share, path_start);
            } else {
                snprintf(linux_path, size, "/mnt/%s", share);
            }
        } else {
            snprintf(linux_path, size, "/mnt/%s", server_start);
        }
        for (char *c = linux_path; *c; c++) {
            if (*c == '\\') *c = '/';
        }
        return 0;
    }

    /* Handle drive letter paths: C:\path -> ~/.pe-compat/drives/c/path */
    if (isalpha(p[0]) && p[1] == ':') {
        char drive = tolower(p[0]);
        const char *rest = p + 2;

        snprintf(linux_path, size, "%s/drives/%c%s",
                 get_pe_compat_prefix(), drive, rest);

        /* Convert backslashes to forward slashes */
        for (char *c = linux_path; *c; c++) {
            if (*c == '\\')
                *c = '/';
        }

        /* Try case-insensitive fallback if exact path doesn't exist */
        struct stat st;
        if (stat(linux_path, &st) != 0) {
            char resolved[PATH_MAX];
            if (casefold_resolve(linux_path, resolved, sizeof(resolved)) == 0) {
                snprintf(linux_path, size, "%s", resolved);
            }
        }
        return 0;
    }

    /* Relative path: just convert backslashes */
    strncpy(linux_path, p, size - 1);
    linux_path[size - 1] = '\0';
    for (char *c = linux_path; *c; c++) {
        if (*c == '\\')
            *c = '/';
    }

    /* Try case-insensitive fallback for relative paths too */
    struct stat st;
    if (stat(linux_path, &st) != 0) {
        char resolved[PATH_MAX];
        if (casefold_resolve(linux_path, resolved, sizeof(resolved)) == 0) {
            snprintf(linux_path, size, "%s", resolved);
        }
    }

    return 0;
}
