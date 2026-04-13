/*
 * objectd_handles.c - Handle table for pe-objectd
 *
 * The registry.c code uses handle_alloc/handle_lookup/handle_close from
 * dll_common.h.  Since objectd links registry.c directly (not via the
 * pe-loader runtime), we provide a standalone handle table implementation
 * here.  This is a simplified version of the pe-loader handle table.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>

#include "common/dll_common.h"

/* --------------------------------------------------------------------------
 * Handle table storage
 * -------------------------------------------------------------------------- */

static handle_entry_t g_handles[MAX_HANDLES];
static volatile int   g_handle_inited = 0;  /* Atomic via __atomic builtins */
static pthread_mutex_t g_handle_lock = PTHREAD_MUTEX_INITIALIZER;

/* Handle values start at 0x100 to avoid conflicts with predefined HKEYs */
#define HANDLE_BASE 0x100

void handle_table_init(void)
{
    pthread_mutex_lock(&g_handle_lock);
    if (!__atomic_load_n(&g_handle_inited, __ATOMIC_ACQUIRE)) {
        memset(g_handles, 0, sizeof(g_handles));
        __atomic_store_n(&g_handle_inited, 1, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&g_handle_lock);
}

static int handle_to_index(HANDLE h)
{
    uintptr_t val = (uintptr_t)h;
    if (val < HANDLE_BASE)
        return -1;
    int idx = (int)(val - HANDLE_BASE);
    if (idx < 0 || idx >= MAX_HANDLES)
        return -1;
    return idx;
}

/*
 * Reclaim handle slots whose ref_count has dropped to zero or below
 * but were not properly cleaned up (e.g., due to abrupt client disconnect).
 * Caller must hold g_handle_lock.
 * Returns number of slots reclaimed.
 */
static int handle_cleanup_stale(void)
{
    int cleaned = 0;
    for (int i = 0; i < MAX_HANDLES; i++) {
        if (g_handles[i].type != HANDLE_TYPE_INVALID && g_handles[i].ref_count <= 0) {
            if (g_handles[i].data) {
                free(g_handles[i].data);
                g_handles[i].data = NULL;
            }
            if (g_handles[i].fd >= 0) {
                close(g_handles[i].fd);
            }
            memset(&g_handles[i], 0, sizeof(g_handles[i]));
            g_handles[i].type = HANDLE_TYPE_INVALID;
            g_handles[i].fd = -1;
            cleaned++;
        }
    }
    if (cleaned > 0) {
        fprintf(stderr, "[objectd] handle_cleanup_stale: reclaimed %d stale handles\n",
                cleaned);
    }
    return cleaned;
}

HANDLE handle_alloc(handle_type_t type, int fd, void *data)
{
    if (!__atomic_load_n(&g_handle_inited, __ATOMIC_ACQUIRE))
        handle_table_init();

    pthread_mutex_lock(&g_handle_lock);
    for (int i = 0; i < MAX_HANDLES; i++) {
        if (g_handles[i].type == HANDLE_TYPE_INVALID) {
            g_handles[i].type = type;
            g_handles[i].fd = fd;
            g_handles[i].data = data;
            g_handles[i].ref_count = 1;
            pthread_mutex_unlock(&g_handle_lock);
            return (HANDLE)(uintptr_t)(i + HANDLE_BASE);
        }
    }

    /* Table full -- try to reclaim stale entries before giving up */
    int cleaned = handle_cleanup_stale();
    if (cleaned > 0) {
        /* Retry allocation after cleanup */
        for (int i = 0; i < MAX_HANDLES; i++) {
            if (g_handles[i].type == HANDLE_TYPE_INVALID) {
                g_handles[i].type = type;
                g_handles[i].fd = fd;
                g_handles[i].data = data;
                g_handles[i].ref_count = 1;
                pthread_mutex_unlock(&g_handle_lock);
                return (HANDLE)(uintptr_t)(i + HANDLE_BASE);
            }
        }
    }

    pthread_mutex_unlock(&g_handle_lock);
    fprintf(stderr, "[objectd] handle_alloc: table full (%d handles, %d stale reclaimed)\n",
            MAX_HANDLES, cleaned);
    return INVALID_HANDLE_VALUE;
}

/*
 * Returns a COPY of the handle entry so the caller does not hold a pointer
 * into the table after the lock is released.  Returns a heap-allocated copy
 * that the caller must free, or NULL if not found.
 */
handle_entry_t *handle_lookup(HANDLE h)
{
    if (!__atomic_load_n(&g_handle_inited, __ATOMIC_ACQUIRE))
        handle_table_init();

    int idx = handle_to_index(h);
    if (idx < 0)
        return NULL;

    handle_entry_t *copy = NULL;
    pthread_mutex_lock(&g_handle_lock);
    if (g_handles[idx].type != HANDLE_TYPE_INVALID) {
        copy = malloc(sizeof(handle_entry_t));
        if (copy)
            *copy = g_handles[idx];
    }
    pthread_mutex_unlock(&g_handle_lock);
    return copy;
}

int handle_close(HANDLE h)
{
    if (!__atomic_load_n(&g_handle_inited, __ATOMIC_ACQUIRE))
        return -1;

    int idx = handle_to_index(h);
    if (idx < 0)
        return -1;

    pthread_mutex_lock(&g_handle_lock);
    if (g_handles[idx].type == HANDLE_TYPE_INVALID) {
        pthread_mutex_unlock(&g_handle_lock);
        return -1;
    }

    g_handles[idx].ref_count--;
    if (g_handles[idx].ref_count <= 0) {
        if (g_handles[idx].data) {
            free(g_handles[idx].data);
            g_handles[idx].data = NULL;
        }
        if (g_handles[idx].fd >= 0) {
            close(g_handles[idx].fd);
        }
        memset(&g_handles[idx], 0, sizeof(handle_entry_t));
        g_handles[idx].fd = -1;  /* 0 is a valid fd (stdin); use -1 for "none" */
    }
    pthread_mutex_unlock(&g_handle_lock);
    return 0;
}

int handle_get_fd(HANDLE h)
{
    handle_entry_t *entry = handle_lookup(h);
    if (!entry) return -1;
    int fd = entry->fd;
    free(entry);  /* handle_lookup returns a heap-allocated copy */
    return fd;
}

/* --------------------------------------------------------------------------
 * Error code stubs (registry.c doesn't use these, but dll_common.h
 * declares them so the linker may need them from other translation units)
 * -------------------------------------------------------------------------- */

static __thread DWORD tls_last_error = 0;

void set_last_error(DWORD error)
{
    tls_last_error = error;
}

DWORD get_last_error(void)
{
    return tls_last_error;
}

DWORD errno_to_win32_error(int err)
{
    (void)err;
    return 0;
}

int win32_error_to_errno(DWORD err)
{
    (void)err;
    return 0;
}

int win_path_to_linux(const char *win_path, char *linux_path, size_t size)
{
    (void)win_path;
    (void)linux_path;
    (void)size;
    return -1;
}

const char *get_pe_compat_prefix(void)
{
    static char prefix[4096] = {0};
    if (!prefix[0]) {
        const char *home = getenv("HOME");
        if (!home) home = "/tmp";
        snprintf(prefix, sizeof(prefix), "%s/.pe-compat", home);
    }
    return prefix;
}

int casefold_resolve(const char *path, char *resolved, size_t size)
{
    if (!path || !resolved) return -1;
    strncpy(resolved, path, size - 1);
    resolved[size - 1] = '\0';
    return 0;
}

void casefold_cache_flush(void) {}

HANDLE get_std_handle(DWORD std_handle_id)
{
    (void)std_handle_id;
    return INVALID_HANDLE_VALUE;
}
