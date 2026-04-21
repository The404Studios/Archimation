/*
 * scm_dependency.c - Service dependency resolution
 *
 * Topological sort for service dependencies.
 * When starting a service, all its dependencies must start first.
 * When stopping, dependent services must stop first.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "scm.h"
#include "scm_event.h"

/* Dependency graph node */
typedef struct {
    char name[256];
    int  dep_count;
    int  deps[64]; /* Indices into the topo_nodes array */
    int  visited;  /* 0=unvisited, 1=in-progress, 2=done */
    int  order;    /* Topological order (lower = start first) */
} dep_node_t;

/*
 * Global mutable state -- NOT thread-safe on its own.
 * All callers must hold g_lock before calling any function in this file.
 */
static dep_node_t g_nodes[MAX_SERVICES];
static int g_node_count = 0;
static int g_order_counter = 0;

/* Name -> g_nodes[] index hash built once per build_graph() call.
 * Eliminates the O(N) scan inside parse_deps for every dependency token. */
#define DEP_HASH_BUCKETS (MAX_SERVICES * 2)
static int g_dep_hash[DEP_HASH_BUCKETS];

static unsigned int dep_hash_name(const char *name)
{
    unsigned int h = 5381;
    while (*name) {
        unsigned char c = (unsigned char)*name++;
        if (c >= 'A' && c <= 'Z') c += 32;
        h = ((h << 5) + h) + c;
    }
    return h % DEP_HASH_BUCKETS;
}

static void dep_hash_rebuild(void)
{
    for (int i = 0; i < DEP_HASH_BUCKETS; i++)
        g_dep_hash[i] = -1;
    for (int i = 0; i < g_node_count; i++) {
        unsigned int bucket = dep_hash_name(g_nodes[i].name);
        for (unsigned int step = 0; step < DEP_HASH_BUCKETS; step++) {
            unsigned int probe = (bucket + step) % DEP_HASH_BUCKETS;
            if (g_dep_hash[probe] == -1) {
                g_dep_hash[probe] = i;
                break;
            }
        }
    }
}

static int dep_hash_lookup(const char *name)
{
    unsigned int bucket = dep_hash_name(name);
    for (unsigned int step = 0; step < DEP_HASH_BUCKETS; step++) {
        unsigned int probe = (bucket + step) % DEP_HASH_BUCKETS;
        int idx = g_dep_hash[probe];
        if (idx == -1)
            return -1;
        if (idx >= 0 && idx < g_node_count &&
            strcasecmp(g_nodes[idx].name, name) == 0) {
            return idx;
        }
    }
    return -1;
}

/* Parse comma/semicolon-separated dependency list */
static void parse_deps(const char *dep_str, dep_node_t *node)
{
    if (!dep_str || !dep_str[0])
        return;

    char buf[1024];
    strncpy(buf, dep_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr;
    char *token = strtok_r(buf, ",;", &saveptr);

    while (token && node->dep_count < 64) {
        /* Trim whitespace */
        while (*token == ' ') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ') *end-- = '\0';

        if (*token) {
            /* O(1) average hash lookup */
            int idx = dep_hash_lookup(token);
            if (idx >= 0)
                node->deps[node->dep_count++] = idx;
        }

        token = strtok_r(NULL, ",;", &saveptr);
    }
}

/* Build the dependency graph from the service database */
static void build_graph(void)
{
    g_node_count = 0;
    int count = scm_db_count();

    /* First pass: create nodes */
    for (int i = 0; i < count && g_node_count < MAX_SERVICES; i++) {
        service_entry_t *svc = scm_db_get(i);
        if (!svc) continue;

        strncpy(g_nodes[g_node_count].name, svc->name, sizeof(g_nodes[g_node_count].name) - 1);
        g_nodes[g_node_count].name[sizeof(g_nodes[g_node_count].name) - 1] = '\0';
        g_nodes[g_node_count].dep_count = 0;
        g_nodes[g_node_count].visited = 0;
        g_nodes[g_node_count].order = -1;
        g_node_count++;
    }

    /* Build the name -> index hash once so parse_deps becomes O(1) per
     * dependency token rather than O(N). */
    dep_hash_rebuild();

    /* Second pass: resolve dependencies */
    for (int i = 0; i < count && i < g_node_count; i++) {
        service_entry_t *svc = scm_db_get(i);
        if (!svc) continue;
        parse_deps(svc->dependencies, &g_nodes[i]);
    }
}

/* DFS topological sort */
static int topo_dfs(int idx)
{
    if (idx < 0 || idx >= g_node_count)
        return -1;
    if (g_nodes[idx].visited == 2)
        return 0; /* Already processed */
    if (g_nodes[idx].visited == 1) {
        fprintf(stderr, "[scm_dep] Circular dependency detected at: %s\n",
                g_nodes[idx].name);
        return -1; /* Cycle */
    }

    g_nodes[idx].visited = 1;

    /* Visit all dependencies first */
    for (int i = 0; i < g_nodes[idx].dep_count; i++) {
        int dep_idx = g_nodes[idx].deps[i];
        if (topo_dfs(dep_idx) < 0)
            return -1;
    }

    g_nodes[idx].visited = 2;
    g_nodes[idx].order = g_order_counter++;
    return 0;
}

/* Get the start order for all services */
int scm_resolve_dependencies(char **order, int *order_count)
{
    build_graph();
    g_order_counter = 0;

    /* Reset visited flags */
    for (int i = 0; i < g_node_count; i++) {
        g_nodes[i].visited = 0;
        g_nodes[i].order = -1;
    }

    /* Run DFS from each unvisited node */
    for (int i = 0; i < g_node_count; i++) {
        if (g_nodes[i].visited == 0) {
            if (topo_dfs(i) < 0)
                return -1;
        }
    }

    /* Build ordered name list (sorted by order field) */
    *order_count = g_node_count;
    for (int i = 0; i < g_node_count; i++) {
        if (g_nodes[i].order >= 0 && g_nodes[i].order < MAX_SERVICES && g_nodes[i].order < *order_count)
            order[g_nodes[i].order] = g_nodes[i].name;
    }

    return 0;
}

/* Start a service with its dependencies */
int scm_start_with_deps(const char *name)
{
    build_graph();

    /* O(1) hash lookup (built by build_graph) */
    int target = dep_hash_lookup(name);

    if (target < 0) {
        fprintf(stderr, "[scm_dep] Service not found: %s\n", name);
        return -1;
    }

    /* Collect all dependencies (transitive closure) */
    char *start_order[MAX_SERVICES];
    memset(start_order, 0, sizeof(start_order));
    int start_count;

    /* Reset visited */
    for (int i = 0; i < g_node_count; i++)
        g_nodes[i].visited = 0;

    /* DFS to collect deps */
    g_order_counter = 0;
    if (topo_dfs(target) < 0) {
        fprintf(stderr, "[scm_dep] Failed to resolve dependencies for: %s\n", name);
        return -1;
    }

    /* Collect ordered nodes */
    for (int i = 0; i < g_node_count; i++) {
        if (g_nodes[i].order >= 0 && g_nodes[i].order < MAX_SERVICES && g_nodes[i].order < g_node_count)
            start_order[g_nodes[i].order] = g_nodes[i].name;
    }
    start_count = g_order_counter;

    /* Start in order (dependencies first).
     * This function is the user-initiated entry point: zero restart_count
     * and clear manually_stopped so prior lockouts don't block a fresh
     * manual start. The SIGCHLD/health-monitor restart path calls
     * scm_start_service() directly and must NOT reset these. */
    for (int i = 0; i < start_count; i++) {
        if (!start_order[i]) continue;  /* Skip gaps in order sequence */
        service_entry_t *svc = scm_db_find(start_order[i]);
        if (svc) {
            svc->restart_count = 0;
            svc->manually_stopped = 0;
        }
        fprintf(stderr, "[scm_dep] Starting dependency [%d/%d]: %s\n",
                i + 1, start_count, start_order[i]);
        int ret = scm_start_service(start_order[i]);
        if (ret < 0) {
            fprintf(stderr, "[scm_dep] Failed to start dependency: %s\n",
                    start_order[i]);
            scm_event_emit(SVC_EVT_DEPENDENCY_FAIL, 0, name, -1, 0);
            return -1;
        }
    }

    return 0;
}

/* Stop a service and all services that depend on it (with depth limit).
 *
 * The graph is only built at depth==0; recursive calls must not rebuild it
 * because build_graph() resets g_nodes[] (wiping visited state and shifting
 * indices) and would corrupt the outer iteration. We also copy the dependent
 * names into a local buffer before recursing, because scm_stop_service
 * temporarily drops g_lock (see scm_api.c) and another thread could call
 * scm_db_delete_service which memmoves g_services[] and invalidates any
 * service_entry_t pointer we still hold. Names are safer than indices. */
/* Per-call visited set so a diamond dependency (A depends on B and C,
 * both of which depend on X) doesn't double-stop X and emit duplicate
 * SVC_EVT_STOP events. Passed through the recursion. NULL at depth 0. */
static int stop_with_deps_impl(const char *name, int depth,
                               char (*stopped)[256], int *stopped_count,
                               int stopped_cap)
{
    if (depth > 16) {
        fprintf(stderr, "[scm_dep] Max recursion depth reached stopping: %s\n", name);
        return -1;
    }

    /* De-dupe: already stopped this name via another branch? */
    if (stopped && stopped_count) {
        for (int q = 0; q < *stopped_count; q++) {
            if (strcmp(stopped[q], name) == 0)
                return 0;
        }
    }

    if (depth == 0)
        build_graph();

    fprintf(stderr, "[scm_dep] Stopping service and dependents: %s\n", name);

    int target = dep_hash_lookup(name);
    if (target < 0) return -1;

    /* Snapshot dependent names before recursing -- the recursive stop drops
     * g_lock and the graph can become stale. */
    char dependent_names[MAX_SERVICES][256];
    int dependent_count = 0;
    for (int i = 0; i < g_node_count && dependent_count < MAX_SERVICES; i++) {
        for (int j = 0; j < g_nodes[i].dep_count; j++) {
            if (g_nodes[i].deps[j] == target) {
                strncpy(dependent_names[dependent_count],
                        g_nodes[i].name,
                        sizeof(dependent_names[0]) - 1);
                dependent_names[dependent_count][sizeof(dependent_names[0]) - 1] = '\0';
                dependent_count++;
                break;
            }
        }
    }

    for (int k = 0; k < dependent_count; k++)
        stop_with_deps_impl(dependent_names[k], depth + 1,
                            stopped, stopped_count, stopped_cap);

    int rc = scm_stop_service(name);
    if (stopped && stopped_count && *stopped_count < stopped_cap) {
        strncpy(stopped[*stopped_count], name, 255);
        stopped[*stopped_count][255] = '\0';
        (*stopped_count)++;
    }
    return rc;
}

int scm_stop_with_deps(const char *name)
{
    char stopped[MAX_SERVICES][256];
    int stopped_count = 0;
    return stop_with_deps_impl(name, 0, stopped, &stopped_count, MAX_SERVICES);
}

/*
 * Start all auto-start services sequentially by dependency depth.
 * Services at the same depth could theoretically start concurrently,
 * but fork()+shared service_entry_t makes threading unsafe without
 * deep locking changes.  Sequential start is safe and fast enough
 * for the one-time startup path.
 */
int scm_parallel_auto_start(void)
{
    int count = 0;
    int depth[MAX_SERVICES];
    int failed[MAX_SERVICES];    /* 1 = this service (or a transitive dep) failed */
    int max_depth = 0;
    int i, d;

    /* Get the topological order first */
    build_graph();
    g_order_counter = 0;

    for (i = 0; i < g_node_count; i++) {
        g_nodes[i].visited = 0;
        g_nodes[i].order = -1;
        failed[i] = 0;
    }

    int svc_count = scm_db_count();
    for (i = 0; i < svc_count && i < g_node_count; i++) {
        service_entry_t *svc = scm_db_get(i);
        /* Only auto-start user-mode services. BOOT_START and SYSTEM_START
         * are for kernel drivers loaded by the boot loader or kernel init,
         * not services that the SCM should fork. */
        if (svc && svc->start_type == SERVICE_AUTO_START) {
            if (topo_dfs(i) < 0) {
                fprintf(stderr, "[scm_dep] Circular dependency detected involving '%s'\n", g_nodes[i].name);
            }
        }
    }

    /* Count services to start (those with assigned topo order) */
    for (i = 0; i < g_node_count; i++) {
        if (g_nodes[i].order >= 0 && g_nodes[i].order < MAX_SERVICES)
            count++;
    }

    if (count == 0) return 0;

    /* Compute dependency depth for each node (longest path from root) */
    for (i = 0; i < g_node_count; i++)
        depth[i] = 0;

    /* Build order -> node_idx reverse map to avoid the O(N^2) scan when
     * computing longest-path depths.  g_nodes[].order is dense in [0,count)
     * because DFS assigns consecutive values via g_order_counter. */
    int order_to_node[MAX_SERVICES];
    for (i = 0; i < MAX_SERVICES; i++) order_to_node[i] = -1;
    for (i = 0; i < g_node_count; i++) {
        int ord = g_nodes[i].order;
        if (ord >= 0 && ord < MAX_SERVICES)
            order_to_node[ord] = i;
    }

    /* For each service in topological order, its depth = max(dep depths) + 1 */
    for (i = 0; i < count; i++) {
        int node_idx = order_to_node[i];
        if (node_idx < 0) continue;

        int max_dep_depth = -1;
        for (int j = 0; j < g_nodes[node_idx].dep_count; j++) {
            int dep_idx = g_nodes[node_idx].deps[j];
            if (dep_idx >= 0 && dep_idx < g_node_count &&
                depth[dep_idx] > max_dep_depth)
                max_dep_depth = depth[dep_idx];
        }
        depth[node_idx] = max_dep_depth + 1;
        if (depth[node_idx] > max_depth)
            max_depth = depth[node_idx];
    }

    /* Start services sequentially by depth level.  Propagate failure: if any
     * dep of a service failed to start, mark this service failed and skip it
     * rather than silently starting a service with missing prerequisites. */
    for (d = 0; d <= max_depth; d++) {
        int batch_count = 0;

        fprintf(stderr, "[scm_dep] Starting depth %d services:\n", d);

        for (i = 0; i < g_node_count; i++) {
            if (g_nodes[i].order < 0 || depth[i] != d)
                continue;

            /* If any dep is failed, skip this service */
            int dep_failed = 0;
            for (int j = 0; j < g_nodes[i].dep_count; j++) {
                int dep_idx = g_nodes[i].deps[j];
                if (dep_idx >= 0 && dep_idx < g_node_count && failed[dep_idx]) {
                    dep_failed = 1;
                    break;
                }
            }
            if (dep_failed) {
                fprintf(stderr, "[scm_dep]   SKIP '%s' (dependency failed)\n",
                        g_nodes[i].name);
                failed[i] = 1;
                scm_event_emit(SVC_EVT_DEPENDENCY_FAIL, 0,
                               g_nodes[i].name, -1, 0);
                continue;
            }

            fprintf(stderr, "[scm_dep]   Starting: %s\n", g_nodes[i].name);
            int delayed_ms = 0;
            {
                service_entry_t *svc = scm_db_find(g_nodes[i].name);
                if (svc) {
                    svc->restart_count = 0;
                    svc->manually_stopped = 0;
                    delayed_ms = svc->delayed_start_ms;
                }
            }
            /* S74: delayed auto-start.  Instead of starting immediately,
             * arm a detached timer; the service will fire after delay_ms
             * (default 120s, matching Windows DELAYED_AUTO_START). */
            if (delayed_ms > 0) {
                fprintf(stderr, "[scm_dep]   Deferring '%s' by %dms (delayed auto-start)\n",
                        g_nodes[i].name, delayed_ms);
                scm_schedule_delayed_start(g_nodes[i].name, delayed_ms);
                batch_count++;
                continue;
            }
            int ret = scm_start_service(g_nodes[i].name);
            if (ret < 0) {
                fprintf(stderr, "[scm_dep]   FAILED: %s\n", g_nodes[i].name);
                failed[i] = 1;
                scm_event_emit(SVC_EVT_DEPENDENCY_FAIL, 0,
                               g_nodes[i].name, -1, 0);
            }
            batch_count++;
        }

        if (batch_count > 0) {
            fprintf(stderr, "[scm_dep] Depth %d: %d service(s) started\n",
                    d, batch_count);
        }
    }

    return 0;
}

/* Get auto-start services in dependency order */
int scm_get_auto_start_order(char **order, int *count)
{
    build_graph();
    g_order_counter = 0;

    for (int i = 0; i < g_node_count; i++) {
        g_nodes[i].visited = 0;
        g_nodes[i].order = -1;
    }

    /* Only include auto-start user-mode services (not BOOT_START/SYSTEM_START
     * which are for kernel drivers). */
    int svc_count = scm_db_count();
    for (int i = 0; i < svc_count && i < g_node_count; i++) {
        service_entry_t *svc = scm_db_get(i);
        if (svc && svc->start_type == SERVICE_AUTO_START) {
            if (topo_dfs(i) < 0) {
                fprintf(stderr, "[scm_dep] Circular dependency detected involving '%s'\n", g_nodes[i].name);
            }
        }
    }

    *count = 0;
    for (int i = 0; i < g_node_count; i++) {
        if (g_nodes[i].order >= 0 && g_nodes[i].order < MAX_SERVICES) {
            order[g_nodes[i].order] = g_nodes[i].name;
            (*count)++;
        }
    }

    return 0;
}
