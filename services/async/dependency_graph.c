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

#define MAX_SERVICES 256

/* External declarations from scm modules */
extern int scm_db_count(void);

typedef struct {
    char    name[256];
    char    display_name[256];
    char    binary_path[4096];
    int     type;
    int     start_type;
    int     state;
    char    dependencies[1024];
    int     pid;
    int     loaded;
} service_entry_t;

extern service_entry_t *scm_db_get(int index);
extern int scm_start_service(const char *name);

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
static int compute_levels(void)
{
    int count = scm_db_count();
    int assigned[MAX_SERVICES];
    memset(assigned, -1, sizeof(assigned));
    g_level_count = 0;

    int progress = 1;
    int current_level = 0;

    while (progress && current_level < MAX_SERVICES) {
        progress = 0;

        for (int i = 0; i < count; i++) {
            if (assigned[i] >= 0)
                continue; /* Already assigned */

            service_entry_t *svc = scm_db_get(i);
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

                    /* Find this dependency */
                    int found = 0;
                    for (int j = 0; j < count; j++) {
                        service_entry_t *dep = scm_db_get(j);
                        if (dep && strcasecmp(dep->name, tok) == 0) {
                            if (assigned[j] < 0 || assigned[j] >= current_level) {
                                deps_satisfied = 0;
                            }
                            found = 1;
                            break;
                        }
                    }

                    /* Unknown dependency - treat as NOT satisfied */
                    if (!found) {
                        fprintf(stderr, "[scm] dependency '%s' for service '%s' not found in database\n",
                                tok, svc->name);
                        deps_satisfied = 0;
                    }

                    if (!deps_satisfied)
                        break;

                    tok = strtok_r(NULL, ",;", &saveptr);
                }
            }

            if (deps_satisfied) {
                assigned[i] = current_level;

                /* Ensure level exists */
                if (current_level >= g_level_count) {
                    g_levels[current_level].count = 0;
                    g_level_count = current_level + 1;
                }

                /* Add to level */
                dep_level_t *level = &g_levels[current_level];
                if (level->count < MAX_SERVICES) {
                    strncpy(level->names[level->count], svc->name, 255);
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
 */
int dep_graph_start_all_parallel(void)
{
    int levels = compute_levels();
    fprintf(stderr, "[dep_graph] Computed %d dependency levels\n", levels);

    for (int l = 0; l < levels; l++) {
        dep_level_t *level = &g_levels[l];
        fprintf(stderr, "[dep_graph] Level %d: %d services\n", l, level->count);

        for (int i = 0; i < level->count; i++) {
            /* Check if this is an auto-start service */
            int svc_count = scm_db_count();
            for (int j = 0; j < svc_count; j++) {
                service_entry_t *svc = scm_db_get(j);
                if (svc && strcasecmp(svc->name, level->names[i]) == 0) {
                    if (svc->start_type <= 2) { /* BOOT, SYSTEM, AUTO */
                        svc_queue_enqueue(SVC_OP_START, level->names[i],
                                          NULL, NULL);
                    }
                    break;
                }
            }
        }

        /* Wait briefly between levels to let the queue drain */
        /* In a production system this would use proper synchronization */
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
