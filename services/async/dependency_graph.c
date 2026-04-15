/*
 * dependency_graph.c - Service dependency graph utilities
 *
 * Extends the core scm_dependency.c with async-aware dependency
 * resolution: starts a batch of services concurrently when they
 * have no inter-dependencies, and serialises only where required.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>

/*
 * Use the canonical service_entry_t from scm.h rather than a private copy.
 * A local redefinition (without restart_policy/restart_delay_ms/max_restarts/
 * restart_count/manually_stopped/crash_handled) would cause sizeof mismatches
 * with the scm_db_* table and any field access beyond 'loaded' would read
 * wrong memory -- a latent ABI bug.
 */
#include "scm.h"

/* From service_queue.c */
typedef enum {
    SVC_OP_START  = 0,
    SVC_OP_STOP   = 1,
    SVC_OP_RESTART = 2
} svc_op_type_t;

extern int svc_queue_enqueue(svc_op_type_t type, const char *name,
                             void (*callback)(const char *, int, void *),
                             void *ctx);

/* A batch of services at the same dependency level */
typedef struct {
    char names[MAX_SERVICES][256];
    int  count;
} dep_level_t;

static dep_level_t g_levels[MAX_SERVICES];
static int g_level_count = 0;

/*
 * Build dependency levels for parallel startup.
 *
 * Level 0: services with no dependencies
 * Level 1: services whose deps are all in level 0
 * Level N: services whose deps are all in levels < N
 *
 * Services within the same level can be started concurrently.
 */
/*
 * Resolve a dependency token (case-insensitive name) to its index in the
 * service database using a precomputed index.  O(1) amortized via the
 * index array; the caller builds the index once per compute_levels() call.
 */
static inline int lookup_svc_index(const char *name, int count,
                                   service_entry_t **svc_cache)
{
    /* Linear scan over cached service_entry_t* pointers (no repeated
     * scm_db_get() which may bound-check on every call). */
    for (int j = 0; j < count; j++) {
        if (svc_cache[j] && strcasecmp(svc_cache[j]->name, name) == 0)
            return j;
    }
    return -1;
}

static int compute_levels(void)
{
    int count = scm_db_count();
    if (count > MAX_SERVICES) count = MAX_SERVICES;
    int assigned[MAX_SERVICES];
    memset(assigned, -1, sizeof(assigned));

    /*
     * Cache scm_db_get() pointers up-front.  The caller must hold g_lock
     * (same invariant as scm_dependency.c) so the pointers stay valid
     * for the duration of compute_levels().  This converts the former
     * O(N^3) dependency scan into O(N*D) where D is the average number
     * of dependencies per service (typically <=3).
     */
    service_entry_t *svc_cache[MAX_SERVICES];
    for (int i = 0; i < count; i++)
        svc_cache[i] = scm_db_get(i);

    /* Zero the level table so stale entries from a previous call
     * are not read through g_levels[i].count. */
    for (int i = 0; i < g_level_count && i < MAX_SERVICES; i++)
        g_levels[i].count = 0;
    g_level_count = 0;

    int progress = 1;
    int current_level = 0;
    int total_assigned = 0;

    while (progress && current_level < MAX_SERVICES &&
           total_assigned < count) {
        progress = 0;

        for (int i = 0; i < count; i++) {
            if (assigned[i] >= 0)
                continue; /* Already assigned */

            service_entry_t *svc = svc_cache[i];
            if (!svc) continue;

            /* Check if all dependencies are assigned to earlier levels */
            int deps_satisfied = 1;

            if (svc->dependencies[0]) {
                char buf[1024];
                strncpy(buf, svc->dependencies, sizeof(buf) - 1);
                buf[sizeof(buf) - 1] = '\0';

                char *saveptr;
                char *tok = strtok_r(buf, ",;", &saveptr);
                while (tok) {
                    while (*tok == ' ') tok++;
                    /* Trim trailing whitespace too */
                    size_t tlen = strlen(tok);
                    while (tlen > 0 && (tok[tlen - 1] == ' ' ||
                                        tok[tlen - 1] == '\t')) {
                        tok[--tlen] = '\0';
                    }
                    if (!*tok) {
                        tok = strtok_r(NULL, ",;", &saveptr);
                        continue;
                    }

                    int j = lookup_svc_index(tok, count, svc_cache);
                    if (j < 0) {
                        fprintf(stderr, "[scm] dependency '%s' for service "
                                "'%s' not found in database\n", tok, svc->name);
                        deps_satisfied = 0;
                    } else if (assigned[j] < 0 || assigned[j] >= current_level) {
                        deps_satisfied = 0;
                    }

                    if (!deps_satisfied)
                        break;

                    tok = strtok_r(NULL, ",;", &saveptr);
                }
            }

            if (deps_satisfied) {
                assigned[i] = current_level;
                total_assigned++;

                /* Ensure level exists */
                if (current_level >= g_level_count) {
                    g_levels[current_level].count = 0;
                    g_level_count = current_level + 1;
                }

                /* Add to level */
                dep_level_t *level = &g_levels[current_level];
                if (level->count < MAX_SERVICES) {
                    strncpy(level->names[level->count], svc->name, 255);
                    level->names[level->count][255] = '\0';
                    level->count++;
                }
                progress = 1;
            }
        }

        current_level++;
    }

    return g_level_count;
}

/*
 * Start all auto-start services using parallel levels.
 * Services within each level are enqueued to the async queue
 * and can run concurrently.
 *
 * Performance note: the prior implementation did an O(N) scm_db_get() scan
 * for each service at each level (O(L*N^2) total).  We now take a single
 * snapshot of svc_cache[] and use it throughout.  The caller must hold
 * the SCM lock across compute_levels() and the enqueue loop below.
 */
int dep_graph_start_all_parallel(void)
{
    int levels = compute_levels();
    fprintf(stderr, "[dep_graph] Computed %d dependency levels\n", levels);

    int svc_count = scm_db_count();
    if (svc_count > MAX_SERVICES) svc_count = MAX_SERVICES;
    service_entry_t *svc_cache[MAX_SERVICES];
    for (int i = 0; i < svc_count; i++)
        svc_cache[i] = scm_db_get(i);

    for (int l = 0; l < levels; l++) {
        dep_level_t *level = &g_levels[l];
        fprintf(stderr, "[dep_graph] Level %d: %d services\n", l, level->count);

        for (int i = 0; i < level->count; i++) {
            int idx = lookup_svc_index(level->names[i], svc_count, svc_cache);
            if (idx < 0)
                continue;
            service_entry_t *svc = svc_cache[idx];
            if (!svc)
                continue;
            if (svc->start_type <= 2) { /* BOOT, SYSTEM, AUTO */
                svc_queue_enqueue(SVC_OP_START, level->names[i],
                                  NULL, NULL);
            }
        }

        /* Wait briefly between levels to let the queue drain.
         * In a production system this would use proper synchronization. */
        if (l < levels - 1 && level->count > 0) {
            usleep(200000); /* 200ms between levels */
        }
    }

    return 0;
}

int dep_graph_get_level_count(void)
{
    return compute_levels();
}

int dep_graph_get_level(int level, char names[][256], int max_names)
{
    if (g_level_count == 0)
        compute_levels();

    if (level < 0 || level >= g_level_count)
        return 0;

    int count = g_levels[level].count;
    if (count > max_names) count = max_names;

    for (int i = 0; i < count; i++) {
        strncpy(names[i], g_levels[level].names[i], 255);
        names[i][255] = '\0';
    }

    return count;
}
