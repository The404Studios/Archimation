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
            /* Find the index of this dependency */
            for (int i = 0; i < g_node_count; i++) {
                if (strcasecmp(g_nodes[i].name, token) == 0) {
                    node->deps[node->dep_count++] = i;
                    break;
                }
            }
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
        g_nodes[g_node_count].dep_count = 0;
        g_nodes[g_node_count].visited = 0;
        g_nodes[g_node_count].order = -1;
        g_node_count++;
    }

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

    /* Find the target node */
    int target = -1;
    for (int i = 0; i < g_node_count; i++) {
        if (strcasecmp(g_nodes[i].name, name) == 0) {
            target = i;
            break;
        }
    }

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

    /* Start in order (dependencies first) */
    for (int i = 0; i < start_count; i++) {
        if (!start_order[i]) continue;  /* Skip gaps in order sequence */
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

/* Stop a service and all services that depend on it (with depth limit) */
static int stop_with_deps_impl(const char *name, int depth)
{
    if (depth > 16) {
        fprintf(stderr, "[scm_dep] Max recursion depth reached stopping: %s\n", name);
        return -1;
    }

    build_graph();

    /* Find all services that depend on 'name' (reverse deps) */
    fprintf(stderr, "[scm_dep] Stopping service and dependents: %s\n", name);

    /* First pass: find dependents */
    int target = -1;
    for (int i = 0; i < g_node_count; i++) {
        if (strcasecmp(g_nodes[i].name, name) == 0) {
            target = i;
            break;
        }
    }

    if (target < 0) return -1;

    /* Stop dependents first (reverse order) */
    for (int i = 0; i < g_node_count; i++) {
        for (int j = 0; j < g_nodes[i].dep_count; j++) {
            if (g_nodes[i].deps[j] == target) {
                /* This service depends on target - stop it first */
                stop_with_deps_impl(g_nodes[i].name, depth + 1);
                break;
            }
        }
    }

    /* Now stop the target */
    return scm_stop_service(name);
}

int scm_stop_with_deps(const char *name)
{
    return stop_with_deps_impl(name, 0);
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
    char *order[MAX_SERVICES];
    int count = 0;
    int depth[MAX_SERVICES];
    int max_depth = 0;
    int i, d;

    /* Get the topological order first */
    build_graph();
    g_order_counter = 0;

    for (i = 0; i < g_node_count; i++) {
        g_nodes[i].visited = 0;
        g_nodes[i].order = -1;
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

    /* Collect services to start */
    memset(order, 0, sizeof(order));
    count = 0;
    for (i = 0; i < g_node_count; i++) {
        if (g_nodes[i].order >= 0 && g_nodes[i].order < MAX_SERVICES) {
            order[g_nodes[i].order] = g_nodes[i].name;
            count++;
        }
    }

    if (count == 0) return 0;
    (void)order;  /* populated for possible future use; suppress unused warning */

    /* Compute dependency depth for each node (longest path from root) */
    for (i = 0; i < g_node_count; i++)
        depth[i] = 0;

    /* For each service in topological order, its depth = max(dep depths) + 1 */
    for (i = 0; i < count; i++) {
        int node_idx = -1;
        for (int j = 0; j < g_node_count; j++) {
            if (g_nodes[j].order == i) { node_idx = j; break; }
        }
        if (node_idx < 0) continue;

        int max_dep_depth = -1;
        for (int j = 0; j < g_nodes[node_idx].dep_count; j++) {
            int dep_idx = g_nodes[node_idx].deps[j];
            if (depth[dep_idx] > max_dep_depth)
                max_dep_depth = depth[dep_idx];
        }
        depth[node_idx] = max_dep_depth + 1;
        if (depth[node_idx] > max_depth)
            max_depth = depth[node_idx];
    }

    /* Start services sequentially by depth level */
    for (d = 0; d <= max_depth; d++) {
        int batch_count = 0;

        fprintf(stderr, "[scm_dep] Starting depth %d services:\n", d);

        for (i = 0; i < g_node_count; i++) {
            if (g_nodes[i].order >= 0 && depth[i] == d) {
                fprintf(stderr, "[scm_dep]   Starting: %s\n", g_nodes[i].name);
                int ret = scm_start_service(g_nodes[i].name);
                if (ret < 0) {
                    fprintf(stderr, "[scm_dep]   FAILED: %s\n", g_nodes[i].name);
                    scm_event_emit(SVC_EVT_DEPENDENCY_FAIL, 0,
                                   g_nodes[i].name, -1, 0);
                }
                batch_count++;
            }
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
