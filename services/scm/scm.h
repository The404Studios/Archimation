/*
 * scm.h - Service Control Manager shared header
 *
 * Canonical type definitions and function declarations used by all
 * SCM compilation units: scm_daemon, scm_database, scm_api, scm_dependency.
 */

#ifndef SCM_H
#define SCM_H

#include <sys/types.h>

#define SCM_DB_PATH     "/var/lib/pe-compat/services"
#define SCM_RUN_PATH    "/run/pe-compat/services"
#define SCM_SOCKET_PATH "/run/pe-compat/scm.sock"
#define MAX_SERVICES    256

/* Service types (matches Windows SERVICE_* constants) */
#define SERVICE_KERNEL_DRIVER       0x00000001
#define SERVICE_FILE_SYSTEM_DRIVER  0x00000002
#define SERVICE_WIN32_OWN_PROCESS   0x00000010
#define SERVICE_WIN32_SHARE_PROCESS 0x00000020
#define SERVICE_INTERACTIVE_PROCESS 0x00000100

/* Service start types */
#define SERVICE_BOOT_START      0
#define SERVICE_SYSTEM_START    1
#define SERVICE_AUTO_START      2
#define SERVICE_DEMAND_START    3
#define SERVICE_DISABLED        4

/* Service states */
#define SERVICE_STOPPED         1
#define SERVICE_START_PENDING   2
#define SERVICE_STOP_PENDING    3
#define SERVICE_RUNNING         4
#define SERVICE_CONTINUE_PENDING 5
#define SERVICE_PAUSE_PENDING   6
#define SERVICE_PAUSED          7

/* Restart policies */
#define RESTART_NEVER       0   /* Never auto-restart */
#define RESTART_ON_FAILURE  1   /* Restart only on non-zero exit */
#define RESTART_ALWAYS      2   /* Always restart (unless explicitly stopped) */

#define DEFAULT_RESTART_DELAY_MS    5000
#define DEFAULT_MAX_RESTARTS        3

/* Canonical service entry - used everywhere */
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
    /* Restart policy */
    int     restart_policy;     /* RESTART_NEVER, RESTART_ON_FAILURE, RESTART_ALWAYS */
    int     restart_delay_ms;   /* Delay before restart in milliseconds */
    int     max_restarts;       /* Maximum consecutive restarts (0 = unlimited) */
    int     restart_count;      /* Current consecutive restart count (reset on manual start) */
    int     manually_stopped;   /* Set when user explicitly stops the service */
    int     crash_handled;      /* Flag to prevent double-handling between SIGCHLD reaper and health monitor */
} service_entry_t;

/* --- scm_daemon.c shared state --- */
#include <pthread.h>
extern pthread_mutex_t g_lock;

/* --- scm_database.c --- */
int              scm_db_load(void);
int              scm_db_save_service(const service_entry_t *svc);
int              scm_db_delete_service(const char *name);
service_entry_t *scm_db_find(const char *name);
int              scm_db_count(void);
service_entry_t *scm_db_get(int index);
int              scm_db_install(const char *name, const char *display_name,
                                const char *binary_path, int type,
                                int start_type, const char *dependencies);

/* --- scm_api.c --- */
int scm_start_service(const char *name);
int scm_stop_service(const char *name);
int scm_query_service(const char *name, int *state, int *pid);
int scm_list_services(void);

/* --- scm_dependency.c --- */
int scm_resolve_dependencies(char **order, int *order_count);
int scm_start_with_deps(const char *name);
int scm_stop_with_deps(const char *name);
int scm_get_auto_start_order(char **order, int *count);
int scm_parallel_auto_start(void);

#endif /* SCM_H */
