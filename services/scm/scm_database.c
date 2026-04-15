/*
 * scm_database.c - Service database management
 *
 * Load/save/query service configurations from the on-disk database
 * at /var/lib/pe-compat/services/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>

#include "scm.h"
#include "pe/xxh3_compat.h"

static service_entry_t g_services[MAX_SERVICES];
static int g_service_count = 0;

/*
 * O(1) name lookup: small open-addressing hash table mapping lowercase
 * service name -> index into g_services[].  Sized at 2x MAX_SERVICES to
 * keep load factor under 0.5 and preserve probe-length bounds.
 *
 * Concurrency: callers of scm_db_* already hold g_lock; no internal lock
 * needed here.  Both -1 (empty) and -2 (tombstone) are reserved sentinels.
 *
 * Hash: xxh32_lower() (see pe-loader/include/pe/xxh3_compat.h).  Replaced
 * the former djb2 with a proper avalanche-tested hash:
 *   - djb2 leaves clumps of sequential service names ("foo1","foo2",...)
 *     in adjacent buckets -- common in real deployments.
 *   - xxh32's final mul/shift/xor cascade kills that clustering, keeping
 *     probe chains short even at higher load factors.
 *   - Pure scalar, P4-safe (no SIMD).
 * Speed difference is a wash at this table size; the win is distribution
 * quality and future-proofing for larger MAX_SERVICES values.
 */
#define SCM_HASH_BUCKETS (MAX_SERVICES * 2)
#define SCM_HASH_EMPTY     -1
#define SCM_HASH_TOMBSTONE -2
#define SCM_HASH_SEED      0x5C9E1ABEU  /* arbitrary -- bake once, forever */
static int g_scm_hash[SCM_HASH_BUCKETS];
static int g_scm_hash_initialized = 0;

static unsigned int scm_hash_name(const char *name)
{
    /* Case-insensitive xxh32.  Folds ASCII 'A'..'Z' to lowercase inside
     * the hash loop so callers don't need to pre-lowercase. */
    return xxh32_lower(name, SCM_HASH_SEED) % SCM_HASH_BUCKETS;
}

static void scm_hash_init(void)
{
    for (int i = 0; i < SCM_HASH_BUCKETS; i++)
        g_scm_hash[i] = SCM_HASH_EMPTY;
    g_scm_hash_initialized = 1;
}

static void scm_hash_insert(const char *name, int idx)
{
    if (!g_scm_hash_initialized) scm_hash_init();
    unsigned int bucket = scm_hash_name(name);
    for (unsigned int step = 0; step < SCM_HASH_BUCKETS; step++) {
        unsigned int probe = (bucket + step) % SCM_HASH_BUCKETS;
        if (g_scm_hash[probe] == SCM_HASH_EMPTY ||
            g_scm_hash[probe] == SCM_HASH_TOMBSTONE) {
            g_scm_hash[probe] = idx;
            return;
        }
    }
    /* Table full - should never happen at 50% load; fall back to linear scan */
    fprintf(stderr, "[scm_db] hash table saturated inserting '%s'\n", name);
}

static int scm_hash_find(const char *name)
{
    if (!g_scm_hash_initialized) return -1;
    if (!name || !name[0]) return -1;
    unsigned int bucket = scm_hash_name(name);
    for (unsigned int step = 0; step < SCM_HASH_BUCKETS; step++) {
        unsigned int probe = (bucket + step) % SCM_HASH_BUCKETS;
        int idx = g_scm_hash[probe];
        if (idx == SCM_HASH_EMPTY) return -1;
        if (idx == SCM_HASH_TOMBSTONE) continue;
        if (idx >= 0 && idx < g_service_count &&
            strcasecmp(g_services[idx].name, name) == 0) {
            return idx;
        }
    }
    return -1;
}

/* Rebuild the hash table from scratch using current g_services[] contents.
 * Called after delete_service() shuffles the table via memmove().
 * A targeted "remove by name" is not needed because memmove renumbers
 * every index >= removed_slot; a rebuild is simpler and always correct. */
static void scm_hash_rebuild(void)
{
    scm_hash_init();
    for (int i = 0; i < g_service_count; i++)
        scm_hash_insert(g_services[i].name, i);
}

static void ensure_db_dir(void)
{
    mkdir("/var/lib/pe-compat", 0755);
    mkdir(SCM_DB_PATH, 0755);
}

/* Parse a .svc config file into a service entry */
static int parse_service_file(const char *filepath, service_entry_t *svc)
{
    FILE *f = fopen(filepath, "r");
    if (!f) return -1;

    memset(svc, 0, sizeof(*svc));
    svc->state = SERVICE_STOPPED;
    svc->start_type = SERVICE_DEMAND_START;
    svc->type = SERVICE_WIN32_OWN_PROCESS;
    svc->restart_policy = RESTART_ON_FAILURE;

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        /* Remove newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        nl = strchr(line, '\r');
        if (nl) *nl = '\0';

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;

        if (strcmp(key, "name") == 0)
            strncpy(svc->name, val, sizeof(svc->name) - 1);
        else if (strcmp(key, "display_name") == 0 || strcmp(key, "display") == 0)
            strncpy(svc->display_name, val, sizeof(svc->display_name) - 1);
        else if (strcmp(key, "binary_path") == 0 || strcmp(key, "binary") == 0)
            strncpy(svc->binary_path, val, sizeof(svc->binary_path) - 1);
        else if (strcmp(key, "type") == 0)
            svc->type = atoi(val);
        else if (strcmp(key, "start_type") == 0 || strcmp(key, "start") == 0)
            svc->start_type = atoi(val);
        else if (strcmp(key, "dependencies") == 0 || strcmp(key, "depends") == 0)
            strncpy(svc->dependencies, val, sizeof(svc->dependencies) - 1);
        else if (strcmp(key, "restart_policy") == 0)
            svc->restart_policy = atoi(val);
        else if (strcmp(key, "restart_delay_ms") == 0)
            svc->restart_delay_ms = atoi(val);
        else if (strcmp(key, "max_restarts") == 0)
            svc->max_restarts = atoi(val);
    }

    /* Apply defaults for restart policy if not set */
    if (svc->restart_delay_ms == 0)
        svc->restart_delay_ms = DEFAULT_RESTART_DELAY_MS;
    if (svc->max_restarts == 0)
        svc->max_restarts = DEFAULT_MAX_RESTARTS;

    fclose(f);
    svc->loaded = 1;
    return 0;
}

int scm_db_load(void)
{
    ensure_db_dir();
    g_service_count = 0;
    scm_hash_init();

    DIR *d = opendir(SCM_DB_PATH);
    if (!d) return -1;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && g_service_count < MAX_SERVICES) {
        /* Only process .svc files */
        const char *ext = strrchr(ent->d_name, '.');
        if (!ext || strcmp(ext, ".svc") != 0)
            continue;

        char filepath[4096];
        snprintf(filepath, sizeof(filepath), "%s/%s", SCM_DB_PATH, ent->d_name);

        if (parse_service_file(filepath, &g_services[g_service_count]) == 0) {
            fprintf(stderr, "[scm_db] Loaded service: %s (type=%d, start=%d)\n",
                    g_services[g_service_count].name,
                    g_services[g_service_count].type,
                    g_services[g_service_count].start_type);
            scm_hash_insert(g_services[g_service_count].name,
                            g_service_count);
            g_service_count++;
        }
    }

    closedir(d);
    fprintf(stderr, "[scm_db] Loaded %d services\n", g_service_count);
    return g_service_count;
}

/* Validate service name: only allow [a-zA-Z0-9_\-.] to prevent path injection */
static int validate_service_name(const char *name) {
    if (!name || !name[0]) return 0;
    for (const char *p = name; *p; p++) {
        if (!(*p >= 'a' && *p <= 'z') && !(*p >= 'A' && *p <= 'Z') &&
            !(*p >= '0' && *p <= '9') && *p != '_' && *p != '-' && *p != '.') {
            return 0;
        }
    }
    return 1;
}

int scm_db_save_service(const service_entry_t *svc)
{
    if (!validate_service_name(svc->name)) {
        fprintf(stderr, "[scm_db] Invalid service name for save: '%s'\n",
                svc->name ? svc->name : "(null)");
        return -1;
    }

    ensure_db_dir();

    char filepath[4096];
    snprintf(filepath, sizeof(filepath), "%s/%s.svc", SCM_DB_PATH, svc->name);

    FILE *f = fopen(filepath, "w");
    if (!f) return -1;

    fprintf(f, "name=%s\n", svc->name);
    if (svc->display_name[0])
        fprintf(f, "display_name=%s\n", svc->display_name);
    fprintf(f, "type=%d\n", svc->type);
    fprintf(f, "start_type=%d\n", svc->start_type);
    if (svc->binary_path[0])
        fprintf(f, "binary_path=%s\n", svc->binary_path);
    if (svc->dependencies[0])
        fprintf(f, "dependencies=%s\n", svc->dependencies);
    if (svc->restart_policy != RESTART_NEVER)
        fprintf(f, "restart_policy=%d\n", svc->restart_policy);
    if (svc->restart_delay_ms != DEFAULT_RESTART_DELAY_MS)
        fprintf(f, "restart_delay_ms=%d\n", svc->restart_delay_ms);
    if (svc->max_restarts != DEFAULT_MAX_RESTARTS)
        fprintf(f, "max_restarts=%d\n", svc->max_restarts);

    fclose(f);
    return 0;
}

int scm_db_delete_service(const char *name)
{
    if (!validate_service_name(name)) {
        fprintf(stderr, "[scm_db] Invalid service name for delete: '%s'\n",
                name ? name : "(null)");
        return -1;
    }

    /* Stop the service if it is still running/pending to avoid leaking
     * a child PID or racing with an in-flight start. Also cover
     * START_PENDING -- a parallel start may have already spawned a child
     * and assigned a pid but not yet transitioned to RUNNING. */
    for (int i = 0; i < g_service_count; i++) {
        if (strcmp(g_services[i].name, name) != 0) continue;
        int s = g_services[i].state;
        if ((s == SERVICE_RUNNING || s == SERVICE_START_PENDING ||
             s == SERVICE_PAUSED) && g_services[i].pid > 0) {
            fprintf(stderr, "[scm_db] Stopping service '%s' (state=%d) before delete\n",
                    name, s);
            g_services[i].manually_stopped = 1;
            g_services[i].crash_handled = 1;
            pid_t pid = g_services[i].pid;
            if (kill(pid, SIGTERM) == 0) {
                /* Brief wait for graceful exit */
                for (int w = 0; w < 10; w++) {
                    if (kill(pid, 0) != 0) break;
                    usleep(100000);
                }
                if (kill(pid, 0) == 0)
                    kill(pid, SIGKILL);
                /* Reap: retry briefly so we don't leave a zombie if the
                 * signal hasn't been delivered+processed yet. */
                for (int w = 0; w < 5; w++) {
                    pid_t r = waitpid(pid, NULL, WNOHANG);
                    if (r > 0 || (r < 0 && errno == ECHILD)) break;
                    usleep(20000);
                }
            }
            g_services[i].state = SERVICE_STOPPED;
            g_services[i].pid = 0;
        }
        break;
    }

    char filepath[4096];
    snprintf(filepath, sizeof(filepath), "%s/%s.svc", SCM_DB_PATH, name);

    if (unlink(filepath) < 0)
        return -1;

    /* Remove status file */
    char status_path[4096];
    snprintf(status_path, sizeof(status_path), "%s/%s.status", SCM_RUN_PATH, name);
    unlink(status_path);

    /* Remove from in-memory list.  memmove() shifts indices, so the hash
     * table (which stores indices) becomes stale -- rebuild after. */
    for (int i = 0; i < g_service_count; i++) {
        if (strcmp(g_services[i].name, name) == 0) {
            memmove(&g_services[i], &g_services[i + 1],
                    (g_service_count - i - 1) * sizeof(service_entry_t));
            g_service_count--;
            scm_hash_rebuild();
            break;
        }
    }

    return 0;
}

service_entry_t *scm_db_find(const char *name)
{
    /* Hot path: SCM API callers invoke this on every command.  The hash
     * table gives O(1) average lookup; fall back to linear scan if the
     * hash has not been initialized (e.g. mid-load). */
    int idx = scm_hash_find(name);
    if (idx >= 0 && idx < g_service_count)
        return &g_services[idx];

    if (!g_scm_hash_initialized) {
        for (int i = 0; i < g_service_count; i++) {
            if (strcasecmp(g_services[i].name, name) == 0)
                return &g_services[i];
        }
    }
    return NULL;
}

int scm_db_count(void)
{
    return g_service_count;
}

service_entry_t *scm_db_get(int index)
{
    if (index < 0 || index >= g_service_count)
        return NULL;
    return &g_services[index];
}

int scm_db_install(const char *name, const char *display_name,
                   const char *binary_path, int type, int start_type,
                   const char *dependencies)
{
    /* Validate name BEFORE any state mutation so a reject never leaves
     * a partial entry in g_services[g_service_count]. */
    if (!validate_service_name(name)) {
        fprintf(stderr, "[scm_db] Invalid service name: '%s'\n",
                name ? name : "(null)");
        return -3;
    }

    if (scm_db_find(name))
        return -1; /* Already exists */

    if (g_service_count >= MAX_SERVICES)
        return -2;

    service_entry_t *svc = &g_services[g_service_count];
    memset(svc, 0, sizeof(*svc));

    strncpy(svc->name, name, sizeof(svc->name) - 1);
    if (display_name)
        strncpy(svc->display_name, display_name, sizeof(svc->display_name) - 1);
    if (binary_path)
        strncpy(svc->binary_path, binary_path, sizeof(svc->binary_path) - 1);
    svc->type = type;
    svc->start_type = start_type;
    svc->state = SERVICE_STOPPED;
    svc->restart_policy = RESTART_ON_FAILURE;
    svc->restart_delay_ms = DEFAULT_RESTART_DELAY_MS;
    svc->max_restarts = DEFAULT_MAX_RESTARTS;
    if (dependencies)
        strncpy(svc->dependencies, dependencies, sizeof(svc->dependencies) - 1);
    svc->loaded = 1;

    /* Persist to disk BEFORE committing the in-memory count.  If save fails
     * (e.g., no disk space), the in-memory table stays consistent with disk. */
    int sr = scm_db_save_service(svc);
    if (sr != 0) {
        memset(svc, 0, sizeof(*svc));
        return sr;
    }

    scm_hash_insert(svc->name, g_service_count);
    g_service_count++;
    return 0;
}
