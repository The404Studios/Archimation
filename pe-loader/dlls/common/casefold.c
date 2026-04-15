/*
 * casefold.c - Case-insensitive file path resolver
 *
 * Windows FS is case-insensitive. Games mix case constantly.
 * This module walks each path component using opendir()+readdir()+strcasecmp()
 * to find the real file, with an LRU hash cache to avoid repeated readdir().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pthread.h>
#include <limits.h>

/* LRU cache: maps (dir_path + component) -> real_name */
#define CASEFOLD_CACHE_SIZE 256
#define CASEFOLD_KEY_MAX    512

typedef struct casefold_entry {
    char key[CASEFOLD_KEY_MAX];      /* "dir_path\0component" */
    char real_name[NAME_MAX];         /* actual filename on disk */
    unsigned int hits;
    int valid;
} casefold_entry_t;

static casefold_entry_t g_cache[CASEFOLD_CACHE_SIZE];
static pthread_mutex_t g_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile unsigned int g_cache_gen = 0;

/* TLS last-hit bypass: hot file-open paths repeatedly resolve the same
 * (dir, component) pairs. Full hash+mutex+strcmp is expensive per call;
 * a 1-entry per-thread cache makes the fast path nearly free.
 *
 * Invalidated when g_cache_gen bumps (from casefold_cache_flush). */
static __thread unsigned int tls_cf_gen = (unsigned int)-1;
static __thread char tls_cf_dir[PATH_MAX];
static __thread char tls_cf_comp_lc[NAME_MAX];
static __thread char tls_cf_real[NAME_MAX];
static __thread int  tls_cf_valid = 0;

/* djb2 hash */
static unsigned int cache_hash(const char *dir, const char *component)
{
    unsigned int h = 5381;
    for (const char *p = dir; *p; p++)
        h = ((h << 5) + h) + (unsigned char)*p;
    h = ((h << 5) + h) + 0; /* separator */
    for (const char *p = component; *p; p++)
        h = ((h << 5) + h) + (unsigned char)(*p >= 'A' && *p <= 'Z' ? *p + 32 : *p);
    return h % CASEFOLD_CACHE_SIZE;
}

static int cache_lookup(const char *dir, const char *component, char *out, size_t out_size)
{
    /* TLS last-hit fast path (no lock, no hash). */
    if (tls_cf_valid && tls_cf_gen == g_cache_gen) {
        if (strcmp(tls_cf_dir, dir) == 0 &&
            strcasecmp(tls_cf_comp_lc, component) == 0) {
            snprintf(out, out_size, "%s", tls_cf_real);
            return 1;
        }
    }

    unsigned int idx = cache_hash(dir, component);
    pthread_mutex_lock(&g_cache_lock);
    casefold_entry_t *e = &g_cache[idx];
    if (e->valid) {
        /* Verify key matches (check dir + component) */
        size_t dir_len = strlen(dir);
        if (strncmp(e->key, dir, dir_len) == 0 && e->key[dir_len] == '\0' &&
            strcasecmp(e->key + dir_len + 1, component) == 0) {
            e->hits++;
            snprintf(out, out_size, "%s", e->real_name);
            /* Populate TLS cache under the lock so we read a consistent
             * real_name without racing a concurrent insert. */
            if (strlen(dir) < sizeof(tls_cf_dir) &&
                strlen(component) < sizeof(tls_cf_comp_lc)) {
                strncpy(tls_cf_dir, dir, sizeof(tls_cf_dir) - 1);
                tls_cf_dir[sizeof(tls_cf_dir) - 1] = '\0';
                strncpy(tls_cf_comp_lc, component, sizeof(tls_cf_comp_lc) - 1);
                tls_cf_comp_lc[sizeof(tls_cf_comp_lc) - 1] = '\0';
                strncpy(tls_cf_real, e->real_name, sizeof(tls_cf_real) - 1);
                tls_cf_real[sizeof(tls_cf_real) - 1] = '\0';
                tls_cf_gen = g_cache_gen;
                tls_cf_valid = 1;
            }
            pthread_mutex_unlock(&g_cache_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_cache_lock);
    return 0;
}

static void cache_insert(const char *dir, const char *component, const char *real_name)
{
    unsigned int idx = cache_hash(dir, component);
    pthread_mutex_lock(&g_cache_lock);
    casefold_entry_t *e = &g_cache[idx];
    size_t dir_len = strlen(dir);
    if (dir_len + 1 + strlen(component) < CASEFOLD_KEY_MAX) {
        memcpy(e->key, dir, dir_len);
        e->key[dir_len] = '\0';
        strncpy(e->key + dir_len + 1, component, CASEFOLD_KEY_MAX - dir_len - 2);
        e->key[CASEFOLD_KEY_MAX - 1] = '\0';
        snprintf(e->real_name, sizeof(e->real_name), "%s", real_name);
        e->hits = 1;
        e->valid = 1;
    }
    if (dir_len < sizeof(tls_cf_dir) && strlen(component) < sizeof(tls_cf_comp_lc) &&
        strlen(real_name) < sizeof(tls_cf_real)) {
        strncpy(tls_cf_dir, dir, sizeof(tls_cf_dir) - 1);
        tls_cf_dir[sizeof(tls_cf_dir) - 1] = '\0';
        strncpy(tls_cf_comp_lc, component, sizeof(tls_cf_comp_lc) - 1);
        tls_cf_comp_lc[sizeof(tls_cf_comp_lc) - 1] = '\0';
        strncpy(tls_cf_real, real_name, sizeof(tls_cf_real) - 1);
        tls_cf_real[sizeof(tls_cf_real) - 1] = '\0';
        tls_cf_gen = g_cache_gen;
        tls_cf_valid = 1;
    }
    pthread_mutex_unlock(&g_cache_lock);
}

/*
 * casefold_resolve - Resolve a path case-insensitively
 *
 * @path:     The path to resolve (Linux-style, forward slashes)
 * @resolved: Output buffer for the resolved path
 * @size:     Size of output buffer
 *
 * Returns 0 on success, -1 if no match found.
 *
 * Algorithm: walk each component of the path. For each component,
 * first try exact match (stat). If that fails, opendir the parent
 * and scan for a case-insensitive match.
 */
int casefold_resolve(const char *path, char *resolved, size_t size)
{
    if (!path || !resolved || size == 0)
        return -1;

    /* Absolute path: start from root */
    char built[PATH_MAX];
    const char *p = path;

    if (*p == '/') {
        built[0] = '/';
        built[1] = '\0';
        p++;
    } else {
        built[0] = '.';
        built[1] = '\0';
    }

    /* Skip leading slashes */
    while (*p == '/') p++;

    if (*p == '\0') {
        snprintf(resolved, size, "%s", built);
        return 0;
    }

    while (*p) {
        /* Extract next component */
        const char *slash = strchr(p, '/');
        size_t comp_len = slash ? (size_t)(slash - p) : strlen(p);

        if (comp_len == 0) {
            p = slash + 1;
            continue;
        }

        char component[NAME_MAX];
        if (comp_len >= sizeof(component))
            return -1;
        memcpy(component, p, comp_len);
        component[comp_len] = '\0';

        /* Handle . and .. directly */
        if (strcmp(component, ".") == 0) {
            p = slash ? slash + 1 : p + comp_len;
            continue;
        }
        if (strcmp(component, "..") == 0) {
            /* Go up one level */
            char *last_slash = strrchr(built, '/');
            if (last_slash && last_slash != built)
                *last_slash = '\0';
            p = slash ? slash + 1 : p + comp_len;
            continue;
        }

        /* Try exact match first (fast path) */
        char try_path[PATH_MAX];
        snprintf(try_path, sizeof(try_path), "%s/%s",
                 (built[0] == '/' && built[1] == '\0') ? "" : built, component);

        struct stat st;
        if (stat(try_path, &st) == 0) {
            snprintf(built, sizeof(built), "%s", try_path);
            p = slash ? slash + 1 : p + comp_len;
            continue;
        }

        /* Check cache */
        char cached_name[NAME_MAX];
        if (cache_lookup(built, component, cached_name, sizeof(cached_name))) {
            snprintf(try_path, sizeof(try_path), "%s/%s",
                     (built[0] == '/' && built[1] == '\0') ? "" : built, cached_name);
            if (stat(try_path, &st) == 0) {
                snprintf(built, sizeof(built), "%s", try_path);
                p = slash ? slash + 1 : p + comp_len;
                continue;
            }
        }

        /* Case-insensitive scan */
        DIR *dir = opendir(built[0] ? built : ".");
        if (!dir)
            return -1;

        int found = 0;
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (strcasecmp(ent->d_name, component) == 0) {
                cache_insert(built, component, ent->d_name);
                /* Avoid snprintf aliasing (built is both src and dst) */
                char next_built[PATH_MAX];
                snprintf(next_built, sizeof(next_built), "%s/%s",
                         (built[0] == '/' && built[1] == '\0') ? "" : built, ent->d_name);
                snprintf(built, sizeof(built), "%s", next_built);
                found = 1;
                break;
            }
        }
        closedir(dir);

        if (!found)
            return -1;

        p = slash ? slash + 1 : p + comp_len;
    }

    snprintf(resolved, size, "%s", built);
    return 0;
}

/* Flush the casefold cache (e.g., after file creation) */
void casefold_cache_flush(void)
{
    pthread_mutex_lock(&g_cache_lock);
    memset(g_cache, 0, sizeof(g_cache));
    g_cache_gen++;
    pthread_mutex_unlock(&g_cache_lock);
}
