/*
 * objectd_namespace.c - Device namespace for pe-objectd
 *
 * Maintains a table mapping Windows device paths to Linux paths or
 * broker-managed devices.  Provides resolve, create_symlink,
 * delete_symlink, and enumerate operations.
 *
 * Default entries are populated on init:
 *   \Device\Null         -> /dev/null
 *   \Device\KsecDD       -> /dev/urandom
 *   \DosDevices\C:       -> /
 *   \DosDevices\Z:       -> $HOME
 *   \??\PIPE\            -> /tmp/pe-compat/pipes/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "objectd_protocol.h"
#include "objectd_namespace.h"

/* --------------------------------------------------------------------------
 * Namespace table
 * -------------------------------------------------------------------------- */

#define MAX_NS_ENTRIES 512

static ns_entry_t   g_ns_table[MAX_NS_ENTRIES];
static int           g_ns_count = 0;
static pthread_mutex_t g_ns_lock = PTHREAD_MUTEX_INITIALIZER;

/* --------------------------------------------------------------------------
 * Internal helpers (caller must hold g_ns_lock)
 * -------------------------------------------------------------------------- */

/* Reject paths containing ".." components to prevent path traversal attacks */
static int path_has_dotdot(const char *path)
{
    const char *p = path;
    while ((p = strstr(p, "..")) != NULL) {
        /* Check that ".." is bounded by separators or string edges */
        int at_start = (p == path);
        int prev_sep = (p > path && (*(p - 1) == '\\' || *(p - 1) == '/'));
        int next_end = (p[2] == '\0' || p[2] == '\\' || p[2] == '/');
        if ((at_start || prev_sep) && next_end)
            return 1;
        p += 2;
    }
    return 0;
}

/* Case-insensitive prefix match for Windows paths */
static int win_path_prefix_match(const char *path, const char *prefix)
{
    while (*prefix) {
        char a = *path;
        char b = *prefix;
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a == '/') a = '\\';
        if (b == '/') b = '\\';
        if (a != b) return 0;
        path++;
        prefix++;
    }
    return 1;
}

/* Case-insensitive exact match */
static int win_path_eq(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca == '/') ca = '\\';
        if (cb == '/') cb = '\\';
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return *a == *b;
}

/* Find entry by exact win_path match. Returns index or -1. */
static int find_entry_locked(const char *win_path)
{
    for (int i = 0; i < g_ns_count; i++) {
        if (win_path_eq(g_ns_table[i].win_path, win_path))
            return i;
    }
    return -1;
}

/* Add an entry. Returns 0 on success, -1 if full. */
static int add_entry_locked(const char *win_path, const char *linux_path,
                            int is_symlink)
{
    if (g_ns_count >= MAX_NS_ENTRIES)
        return -1;

    ns_entry_t *e = &g_ns_table[g_ns_count];
    strncpy(e->win_path, win_path, sizeof(e->win_path) - 1);
    e->win_path[sizeof(e->win_path) - 1] = '\0';
    strncpy(e->linux_path, linux_path, sizeof(e->linux_path) - 1);
    e->linux_path[sizeof(e->linux_path) - 1] = '\0';
    e->is_symlink = is_symlink;
    g_ns_count++;
    return 0;
}

/* --------------------------------------------------------------------------
 * Init / Shutdown
 * -------------------------------------------------------------------------- */

void namespace_init(void)
{
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";

    pthread_mutex_lock(&g_ns_lock);

    g_ns_count = 0;
    memset(g_ns_table, 0, sizeof(g_ns_table));

    /* Device entries */
    add_entry_locked("\\Device\\Null",      "/dev/null",         0);
    add_entry_locked("\\Device\\KsecDD",    "/dev/urandom",      0);
    add_entry_locked("\\Device\\Afd",       "/dev/null",         0);
    add_entry_locked("\\Device\\NamedPipe", "/tmp/pe-compat/pipes/", 0);

    /* DOS device symlinks */
    add_entry_locked("\\DosDevices\\C:",    "/",                 1);

    char zbuf[512];
    snprintf(zbuf, sizeof(zbuf), "%s", home);
    add_entry_locked("\\DosDevices\\Z:",    zbuf,                1);

    /* NT object manager paths */
    add_entry_locked("\\??\\C:",            "/",                 1);
    add_entry_locked("\\??\\Z:",            zbuf,                1);

    char pipebuf[512];
    snprintf(pipebuf, sizeof(pipebuf), "/tmp/pe-compat/pipes/");
    add_entry_locked("\\??\\PIPE\\",        pipebuf,             1);

    /* Global namespace */
    add_entry_locked("\\BaseNamedObjects",  "/dev/shm",          0);
    add_entry_locked("\\Sessions\\1\\BaseNamedObjects", "/dev/shm", 0);

    pthread_mutex_unlock(&g_ns_lock);

    fprintf(stderr, "[objectd] Device namespace initialized (%d entries)\n",
            g_ns_count);
}

void namespace_shutdown(void)
{
    pthread_mutex_lock(&g_ns_lock);
    g_ns_count = 0;
    memset(g_ns_table, 0, sizeof(g_ns_table));
    pthread_mutex_unlock(&g_ns_lock);
    fprintf(stderr, "[objectd] Device namespace shut down\n");
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

int namespace_resolve(const char *win_path, char *linux_path, size_t linux_path_size)
{
    if (!win_path || !linux_path)
        return -1;

    /* Reject path traversal via ".." components */
    if (path_has_dotdot(win_path))
        return -1;

    pthread_mutex_lock(&g_ns_lock);

    /* Try exact match first */
    int idx = find_entry_locked(win_path);
    if (idx >= 0) {
        strncpy(linux_path, g_ns_table[idx].linux_path,
                linux_path_size - 1);
        linux_path[linux_path_size - 1] = '\0';
        pthread_mutex_unlock(&g_ns_lock);
        return 0;
    }

    /*
     * Try prefix match: find the longest matching prefix.
     * E.g., \DosDevices\C:\Windows -> / + Windows
     */
    int best = -1;
    size_t best_len = 0;
    for (int i = 0; i < g_ns_count; i++) {
        size_t plen = strlen(g_ns_table[i].win_path);
        if (plen > best_len && win_path_prefix_match(win_path, g_ns_table[i].win_path)) {
            best = i;
            best_len = plen;
        }
    }

    if (best >= 0) {
        const char *remainder = win_path + best_len;
        /* Skip leading separator */
        while (*remainder == '\\' || *remainder == '/')
            remainder++;

        if (remainder[0] == '\0') {
            strncpy(linux_path, g_ns_table[best].linux_path,
                    linux_path_size - 1);
        } else {
            const char *base = g_ns_table[best].linux_path;
            size_t base_len = strlen(base);
            /* Avoid double slash */
            if (base_len > 0 && base[base_len - 1] == '/')
                snprintf(linux_path, linux_path_size, "%s%s", base, remainder);
            else
                snprintf(linux_path, linux_path_size, "%s/%s", base, remainder);
        }
        linux_path[linux_path_size - 1] = '\0';

        /* Convert remaining backslashes */
        for (char *p = linux_path; *p; p++) {
            if (*p == '\\') *p = '/';
        }

        pthread_mutex_unlock(&g_ns_lock);
        return 0;
    }

    pthread_mutex_unlock(&g_ns_lock);
    return -1;
}

int namespace_create_symlink(const char *link_name, const char *target)
{
    if (!link_name || !target)
        return -1;

    /* Reject path traversal via ".." components */
    if (path_has_dotdot(link_name) || path_has_dotdot(target))
        return -1;

    pthread_mutex_lock(&g_ns_lock);

    /* Check for existing entry */
    int idx = find_entry_locked(link_name);
    if (idx >= 0) {
        /* Update existing entry */
        strncpy(g_ns_table[idx].linux_path, target,
                sizeof(g_ns_table[idx].linux_path) - 1);
        g_ns_table[idx].linux_path[sizeof(g_ns_table[idx].linux_path) - 1] = '\0';
        g_ns_table[idx].is_symlink = 1;
        pthread_mutex_unlock(&g_ns_lock);
        fprintf(stderr, "[objectd] Updated namespace symlink: %s -> %s\n",
                link_name, target);
        return 0;
    }

    /* Create new entry */
    int ret = add_entry_locked(link_name, target, 1);
    pthread_mutex_unlock(&g_ns_lock);

    if (ret == 0) {
        fprintf(stderr, "[objectd] Created namespace symlink: %s -> %s\n",
                link_name, target);
    } else {
        fprintf(stderr, "[objectd] Namespace table full, cannot create %s\n",
                link_name);
    }
    return ret;
}

int namespace_delete_symlink(const char *link_name)
{
    if (!link_name)
        return -1;

    pthread_mutex_lock(&g_ns_lock);

    int idx = find_entry_locked(link_name);
    if (idx < 0) {
        pthread_mutex_unlock(&g_ns_lock);
        return -1;
    }

    /* Only allow deleting symlinks, not base devices */
    if (!g_ns_table[idx].is_symlink) {
        pthread_mutex_unlock(&g_ns_lock);
        fprintf(stderr, "[objectd] Cannot delete non-symlink entry: %s\n",
                link_name);
        return -1;
    }

    /* Remove by shifting remaining entries down */
    fprintf(stderr, "[objectd] Deleted namespace symlink: %s\n", link_name);
    for (int i = idx; i < g_ns_count - 1; i++)
        g_ns_table[i] = g_ns_table[i + 1];
    g_ns_count--;
    memset(&g_ns_table[g_ns_count], 0, sizeof(ns_entry_t));

    pthread_mutex_unlock(&g_ns_lock);
    return 0;
}

int namespace_enumerate(const char *prefix, ns_entry_t *out, int max_entries,
                        int *out_count)
{
    if (!out || !out_count)
        return -1;

    pthread_mutex_lock(&g_ns_lock);

    int count = 0;
    for (int i = 0; i < g_ns_count && count < max_entries; i++) {
        if (!prefix || prefix[0] == '\0' ||
            win_path_prefix_match(g_ns_table[i].win_path, prefix)) {
            out[count] = g_ns_table[i];
            count++;
        }
    }

    *out_count = count;
    pthread_mutex_unlock(&g_ns_lock);
    return 0;
}

/* --------------------------------------------------------------------------
 * Wire protocol handler
 * -------------------------------------------------------------------------- */

int objectd_namespace_handle(uint8_t req_type, const void *payload,
                             uint16_t payload_len, uint64_t sequence,
                             void *resp_buf, size_t resp_buf_size,
                             size_t *resp_len)
{
    objectd_response_t *resp = (objectd_response_t *)resp_buf;
    uint8_t *resp_data = (uint8_t *)resp_buf + sizeof(objectd_response_t);
    size_t resp_data_max = resp_buf_size - sizeof(objectd_response_t);

    /* Initialize response header */
    memset(resp, 0, sizeof(*resp));
    resp->magic    = OBJECTD_MAGIC;
    resp->version  = OBJECTD_VERSION;
    resp->sequence = sequence;
    resp->shm_fd   = -1;
    resp->status   = OBJ_STATUS_OK;
    resp->payload_len = 0;

    switch (req_type) {

    case OBJ_REQ_NS_RESOLVE: {
        if (payload_len < sizeof(ns_resolve_payload_t)) {
            resp->status = OBJ_STATUS_INVALID;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }
        const ns_resolve_payload_t *p = (const ns_resolve_payload_t *)payload;
        char linux_path[512];

        if (namespace_resolve(p->path, linux_path, sizeof(linux_path)) < 0) {
            resp->status = OBJ_STATUS_NOT_FOUND;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }

        uint32_t path_len = (uint32_t)strlen(linux_path);
        ns_resolve_response_t nr;
        nr.path_len = path_len;

        size_t needed = sizeof(nr) + path_len + 1;
        if (needed <= resp_data_max) {
            memcpy(resp_data, &nr, sizeof(nr));
            memcpy(resp_data + sizeof(nr), linux_path, path_len + 1);
            resp->payload_len = (uint16_t)needed;
        } else {
            resp->status = OBJ_STATUS_NO_MEMORY;
        }

        *resp_len = sizeof(objectd_response_t) + resp->payload_len;
        return 0;
    }

    case OBJ_REQ_NS_CREATE_LINK: {
        if (payload_len < sizeof(ns_link_payload_t)) {
            resp->status = OBJ_STATUS_INVALID;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }
        const ns_link_payload_t *p = (const ns_link_payload_t *)payload;

        if (namespace_create_symlink(p->link_name, p->target) < 0)
            resp->status = OBJ_STATUS_FULL;

        *resp_len = sizeof(objectd_response_t);
        return 0;
    }

    case OBJ_REQ_NS_DELETE_LINK: {
        if (payload_len < sizeof(ns_resolve_payload_t)) {
            resp->status = OBJ_STATUS_INVALID;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }
        const ns_resolve_payload_t *p = (const ns_resolve_payload_t *)payload;

        if (namespace_delete_symlink(p->path) < 0)
            resp->status = OBJ_STATUS_NOT_FOUND;

        *resp_len = sizeof(objectd_response_t);
        return 0;
    }

    case OBJ_REQ_NS_ENUMERATE: {
        const char *prefix = NULL;
        if (payload_len >= sizeof(ns_resolve_payload_t)) {
            const ns_resolve_payload_t *p =
                (const ns_resolve_payload_t *)payload;
            if (p->path[0]) prefix = p->path;
        }

        ns_entry_t entries[64];
        int count = 0;
        namespace_enumerate(prefix, entries, 64, &count);

        /* Build response: ns_enumerate_response_t + entries */
        ns_enumerate_response_t ne;
        ne.count = (uint32_t)count;

        size_t offset = sizeof(ne);
        uint8_t tmp_buf[8192];
        memcpy(tmp_buf, &ne, sizeof(ne));

        for (int i = 0; i < count; i++) {
            uint32_t nlen = (uint32_t)strlen(entries[i].win_path);
            uint32_t tlen = (uint32_t)strlen(entries[i].linux_path);

            /* Check actual entry size before writing */
            if (offset + 4 + nlen + 1 + 4 + tlen + 1 > sizeof(tmp_buf))
                break;

            memcpy(tmp_buf + offset, &nlen, sizeof(nlen));
            offset += sizeof(nlen);
            memcpy(tmp_buf + offset, entries[i].win_path, nlen + 1);
            offset += nlen + 1;
            memcpy(tmp_buf + offset, &tlen, sizeof(tlen));
            offset += sizeof(tlen);
            memcpy(tmp_buf + offset, entries[i].linux_path, tlen + 1);
            offset += tlen + 1;
        }

        if (offset <= resp_data_max) {
            memcpy(resp_data, tmp_buf, offset);
            resp->payload_len = (uint16_t)offset;
        } else {
            resp->status = OBJ_STATUS_NO_MEMORY;
        }

        *resp_len = sizeof(objectd_response_t) + resp->payload_len;
        return 0;
    }

    default:
        fprintf(stderr, "[objectd] Unknown namespace request type 0x%02x\n",
                req_type);
        resp->status = OBJ_STATUS_INVALID;
        *resp_len = sizeof(objectd_response_t);
        return -1;
    }
}
