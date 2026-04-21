/*
 * scm.h - Service Control Manager shared header
 *
 * Canonical type definitions and function declarations used by all
 * SCM compilation units: scm_daemon, scm_database, scm_api, scm_dependency.
 */

#ifndef SCM_H
#define SCM_H

#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>

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

/*
 * Windows SCM failure-action types (SC_ACTION_TYPE).  Zero = NONE so
 * a memset(0) service_entry_t is a correctly-disabled failure-action
 * list with no user-visible behavior change.
 */
#define SC_ACTION_NONE          0
#define SC_ACTION_RESTART       1
#define SC_ACTION_REBOOT        2
#define SC_ACTION_RUN_COMMAND   3

#define SCM_FAIL_ACTION_COUNT   3   /* Windows SCM exposes exactly 3 ordered actions */

/*
 * Delayed auto-start: Windows SERVICE_AUTO_START with delayed flag runs
 * the start ~120s after boot so non-critical services don't compete
 * with login.  We keep the default in ms so tests can override.
 */
#define DEFAULT_DELAYED_START_MS    120000   /* 120s, Windows default */

/*
 * SERVICE_NOTIFY mask bits.  Clients OR these when they subscribe so
 * the daemon only fans out the transitions they care about.  Bit layout
 * matches Windows SERVICE_NOTIFY_* values, masked to our known states.
 */
#define SVC_NOTIFY_STOPPED         0x00000001
#define SVC_NOTIFY_START_PENDING   0x00000002
#define SVC_NOTIFY_STOP_PENDING    0x00000004
#define SVC_NOTIFY_RUNNING         0x00000008
#define SVC_NOTIFY_PAUSED          0x00000020
#define SVC_NOTIFY_ALL             0x0000003F

/* Single failure action entry (matches SC_ACTION).  delay_ms is the
 * delay between this action firing and the next, in ms. */
typedef struct {
    int     type;               /* SC_ACTION_* (0 = NONE = unused slot) */
    int     delay_ms;           /* Delay before next action in list */
} scm_fail_action_t;

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
    /* ---- S74 additions (see docs in scm.h comments) ------------------- */
    /* Delayed auto-start: non-zero = honor SERVICE_AUTO_START + delay.
     * Unit is ms of boot-delay; 0 = no delay (standard auto-start).  The
     * zero default is feature-off so memset(0) entries keep Windows-style
     * immediate start semantics. */
    int     delayed_start_ms;
    int     delayed_start_pending;  /* 1 while the auto-start timer is armed */
    /* Windows SCM failure actions: ordered list consulted by restart_count.
     * When non-empty, takes precedence over simple restart_policy. */
    scm_fail_action_t fail_actions[SCM_FAIL_ACTION_COUNT];
    int     fail_reset_period_sec;  /* Seconds of stability → restart_count=0 */
    int     fail_cooldown_ms;       /* Minimum gap between fires (de-jitter) */
    long    last_failure_time;      /* time() of last crash, for reset-period */
    long    last_action_time;       /* time() of last fired action, for cooldown */
    char    fail_command[1024];     /* Shell command for SC_ACTION_RUN_COMMAND */
} service_entry_t;

/* --- scm_api.c new wire handlers / shared helpers --- */
int scm_set_failure_actions(const char *name,
                            const scm_fail_action_t actions[SCM_FAIL_ACTION_COUNT],
                            int reset_period_sec, int cooldown_ms,
                            const char *run_command);
int scm_get_failure_actions(const char *name,
                            scm_fail_action_t actions_out[SCM_FAIL_ACTION_COUNT],
                            int *reset_period_sec, int *cooldown_ms,
                            char *run_command_out, size_t run_command_sz);

/* SERVICE_NOTIFY: subscribe via a writable fd.  SCM fans out one line
 * of "state=<n> name=<s>\n" text per transition that matches mask.
 * Returns a subscription id >= 0 or -1 on error.  The fd is dup'd; the
 * caller can close theirs. */
int scm_notify_subscribe(const char *service_name, uint32_t mask, int fd);
int scm_notify_unsubscribe(int sub_id);
/* Called by lifecycle code on every observable state change.  Fans out
 * to matching subscribers; safe to call with g_lock held. */
void scm_notify_fanout(const char *service_name, int new_state);
/* Called by handle_service_crash to run the per-service failure-action
 * list (if any).  Returns 1 if an action dictated a restart (caller
 * schedules), 0 if the service stays stopped. */
int scm_run_failure_actions(service_entry_t *svc, int exit_code,
                            char *restart_name, size_t restart_sz,
                            int *delay_ms_out);
/* Called from parallel_auto_start when a service has delayed_start_ms
 * set.  Arms a detached timer thread that calls scm_start_with_deps
 * after the delay expires (and the service is still eligible). */
void scm_schedule_delayed_start(const char *service_name, int delay_ms);

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
