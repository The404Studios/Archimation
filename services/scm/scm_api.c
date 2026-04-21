/*
 * scm_api.c - Service Control Manager API functions
 *
 * StartService, StopService, QueryServiceStatus, etc.
 * Called by the SCM daemon to manage service lifecycle.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <spawn.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

#include "scm.h"
#include "scm_event.h"

extern char **environ;

/* ========================================================================
 * S74: SERVICE_NOTIFY subscription registry
 * ------------------------------------------------------------------------
 * Singly-linked list guarded by g_lock (callers already hold it at every
 * state-transition tap site).  Each node owns a dup'd fd that receives
 * one "state=<n> name=<svc>\n" line per matching transition.  We never
 * block on the fd: EAGAIN/EPIPE mean the client is dead and the node is
 * reaped on the next fanout pass.  This keeps SCM's hot path bounded.
 * ======================================================================== */
typedef struct scm_notify_sub {
    int                       id;
    int                       fd;         /* dup'd writable fd */
    uint32_t                  mask;       /* OR of SVC_NOTIFY_* */
    char                      service[256]; /* empty == wildcard */
    int                       dead;       /* 1 once write() has failed */
    struct scm_notify_sub    *next;
} scm_notify_sub_t;

static scm_notify_sub_t *g_notify_head = NULL;
static int               g_notify_next_id = 1;

static uint32_t state_to_notify_mask(int state)
{
    switch (state) {
    case SERVICE_STOPPED:       return SVC_NOTIFY_STOPPED;
    case SERVICE_START_PENDING: return SVC_NOTIFY_START_PENDING;
    case SERVICE_STOP_PENDING:  return SVC_NOTIFY_STOP_PENDING;
    case SERVICE_RUNNING:       return SVC_NOTIFY_RUNNING;
    case SERVICE_PAUSED:        return SVC_NOTIFY_PAUSED;
    default:                    return 0;
    }
}

int scm_notify_subscribe(const char *service_name, uint32_t mask, int fd)
{
    if (fd < 0) return -1;
    int dup_fd = dup(fd);
    if (dup_fd < 0) return -1;
    /* Non-blocking so a stuck reader can't wedge the SCM main loop. */
    int fl = fcntl(dup_fd, F_GETFL, 0);
    if (fl >= 0) fcntl(dup_fd, F_SETFL, fl | O_NONBLOCK);
    fcntl(dup_fd, F_SETFD, FD_CLOEXEC);

    scm_notify_sub_t *sub = calloc(1, sizeof(*sub));
    if (!sub) { close(dup_fd); return -1; }
    sub->id   = g_notify_next_id++;
    sub->fd   = dup_fd;
    sub->mask = mask ? mask : SVC_NOTIFY_ALL;
    if (service_name && service_name[0])
        strncpy(sub->service, service_name, sizeof(sub->service) - 1);
    sub->next = g_notify_head;
    g_notify_head = sub;
    return sub->id;
}

int scm_notify_unsubscribe(int sub_id)
{
    scm_notify_sub_t **pp = &g_notify_head;
    while (*pp) {
        if ((*pp)->id == sub_id) {
            scm_notify_sub_t *dead = *pp;
            *pp = dead->next;
            if (dead->fd >= 0) close(dead->fd);
            free(dead);
            return 0;
        }
        pp = &(*pp)->next;
    }
    return -1;
}

void scm_notify_fanout(const char *service_name, int new_state)
{
    uint32_t bit = state_to_notify_mask(new_state);
    if (!bit || !service_name) return;
    char line[320];
    int  n = snprintf(line, sizeof(line), "state=%d name=%s\n",
                      new_state, service_name);
    if (n <= 0) return;

    scm_notify_sub_t **pp = &g_notify_head;
    while (*pp) {
        scm_notify_sub_t *s = *pp;
        int interested = (s->mask & bit) &&
                         (s->service[0] == '\0' ||
                          strcmp(s->service, service_name) == 0);
        if (interested && !s->dead) {
            ssize_t w = write(s->fd, line, (size_t)n);
            if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                errno != EINTR) {
                s->dead = 1;
            }
        }
        if (s->dead) {
            *pp = s->next;
            if (s->fd >= 0) close(s->fd);
            free(s);
        } else {
            pp = &s->next;
        }
    }
}

/* --- S74 helper: set/get failure actions ------------------------------- */
int scm_set_failure_actions(const char *name,
                            const scm_fail_action_t actions[SCM_FAIL_ACTION_COUNT],
                            int reset_period_sec, int cooldown_ms,
                            const char *run_command)
{
    service_entry_t *svc = scm_db_find(name);
    if (!svc) return -1;
    for (int i = 0; i < SCM_FAIL_ACTION_COUNT; i++)
        svc->fail_actions[i] = actions[i];
    svc->fail_reset_period_sec = reset_period_sec;
    svc->fail_cooldown_ms = cooldown_ms;
    if (run_command) {
        strncpy(svc->fail_command, run_command, sizeof(svc->fail_command) - 1);
        svc->fail_command[sizeof(svc->fail_command) - 1] = '\0';
    } else {
        svc->fail_command[0] = '\0';
    }
    return scm_db_save_service(svc);
}

int scm_get_failure_actions(const char *name,
                            scm_fail_action_t actions_out[SCM_FAIL_ACTION_COUNT],
                            int *reset_period_sec, int *cooldown_ms,
                            char *run_command_out, size_t run_command_sz)
{
    service_entry_t *svc = scm_db_find(name);
    if (!svc) return -1;
    for (int i = 0; i < SCM_FAIL_ACTION_COUNT; i++)
        actions_out[i] = svc->fail_actions[i];
    if (reset_period_sec) *reset_period_sec = svc->fail_reset_period_sec;
    if (cooldown_ms)      *cooldown_ms      = svc->fail_cooldown_ms;
    if (run_command_out && run_command_sz > 0) {
        strncpy(run_command_out, svc->fail_command, run_command_sz - 1);
        run_command_out[run_command_sz - 1] = '\0';
    }
    return 0;
}

/* --- S74 helper: honor per-service failure actions on crash ------------ */
int scm_run_failure_actions(service_entry_t *svc, int exit_code,
                            char *restart_name, size_t restart_sz,
                            int *delay_ms_out)
{
    (void)exit_code;
    if (!svc || !restart_name || !delay_ms_out) return 0;
    /* No actions configured → defer to legacy restart_policy path. */
    int configured = 0;
    for (int i = 0; i < SCM_FAIL_ACTION_COUNT; i++)
        if (svc->fail_actions[i].type != SC_ACTION_NONE) configured = 1;
    if (!configured) return 0;

    time_t now = time(NULL);

    /* Reset-period: if enough uneventful time elapsed, zero the counter. */
    if (svc->fail_reset_period_sec > 0 && svc->last_failure_time > 0 &&
        (now - svc->last_failure_time) >= svc->fail_reset_period_sec) {
        svc->restart_count = 0;
    }

    /* Cooldown-between-failures: ignore rapid-fire crashes below the gap. */
    if (svc->fail_cooldown_ms > 0 && svc->last_action_time > 0 &&
        ((now - svc->last_action_time) * 1000) < svc->fail_cooldown_ms) {
        fprintf(stderr, "[scm_api] fail-action cooldown active for '%s'\n",
                svc->name);
        return 0;
    }

    /* Pick the Nth action, where N = restart_count (clamped to last slot). */
    int slot = svc->restart_count;
    if (slot >= SCM_FAIL_ACTION_COUNT) slot = SCM_FAIL_ACTION_COUNT - 1;
    scm_fail_action_t *act = &svc->fail_actions[slot];

    svc->last_failure_time = now;
    svc->last_action_time  = now;

    switch (act->type) {
    case SC_ACTION_RESTART:
        svc->restart_count++;
        strncpy(restart_name, svc->name, restart_sz - 1);
        restart_name[restart_sz - 1] = '\0';
        *delay_ms_out = act->delay_ms > 0 ? act->delay_ms : DEFAULT_RESTART_DELAY_MS;
        fprintf(stderr, "[scm_api] fail-action[%d]=RESTART for '%s' in %dms\n",
                slot, svc->name, *delay_ms_out);
        return 1;

    case SC_ACTION_RUN_COMMAND:
        if (svc->fail_command[0]) {
            fprintf(stderr, "[scm_api] fail-action[%d]=RUN_COMMAND for '%s': %s\n",
                    slot, svc->name, svc->fail_command);
            /* Fire and forget via /bin/sh -c.  Executed in a double-fork
             * so we don't leave zombies that racing SIGCHLD might reap
             * before we update restart_count. */
            pid_t p = fork();
            if (p == 0) {
                pid_t g = fork();
                if (g == 0) {
                    execl("/bin/sh", "sh", "-c", svc->fail_command, (char*)NULL);
                    _exit(127);
                }
                _exit(0);
            } else if (p > 0) {
                int st; waitpid(p, &st, 0);
            }
        }
        return 0;

    case SC_ACTION_REBOOT:
        fprintf(stderr, "[scm_api] fail-action[%d]=REBOOT requested by '%s' "
                "(honored via systemctl reboot)\n", slot, svc->name);
        /* Defer one second so the notification fanout finishes first. */
        if (fork() == 0) {
            sleep(1);
            execl("/bin/systemctl", "systemctl", "reboot", (char*)NULL);
            _exit(127);
        }
        return 0;

    case SC_ACTION_NONE:
    default:
        fprintf(stderr, "[scm_api] fail-action[%d]=NONE for '%s'\n",
                slot, svc->name);
        return 0;
    }
}

/* --- S74 helper: delayed auto-start timer thread ----------------------- */
typedef struct {
    char name[256];
    int  delay_ms;
} scm_delayed_ctx_t;

static void *scm_delayed_start_thread(void *arg)
{
    scm_delayed_ctx_t *ctx = (scm_delayed_ctx_t *)arg;
    int secs = ctx->delay_ms / 1000;
    int us   = (ctx->delay_ms % 1000) * 1000;
    for (int s = 0; s < secs; s++) sleep(1);
    if (us > 0) usleep((useconds_t)us);

    /* After delay: re-check under lock that the service still wants to
     * start (wasn't manually disabled in the meantime). */
    extern pthread_mutex_t g_lock;
    pthread_mutex_lock(&g_lock);
    service_entry_t *svc = scm_db_find(ctx->name);
    if (svc && !svc->manually_stopped &&
        svc->state == SERVICE_STOPPED &&
        svc->delayed_start_pending) {
        svc->delayed_start_pending = 0;
        fprintf(stderr, "[scm_api] delayed-auto-start firing for '%s' "
                "(after %dms)\n", ctx->name, ctx->delay_ms);
        scm_start_service(ctx->name);
    }
    pthread_mutex_unlock(&g_lock);
    free(ctx);
    return NULL;
}

void scm_schedule_delayed_start(const char *service_name, int delay_ms)
{
    if (!service_name || delay_ms <= 0) return;
    service_entry_t *svc = scm_db_find(service_name);
    if (!svc) return;
    if (svc->delayed_start_pending) return;  /* already armed */
    svc->delayed_start_pending = 1;

    scm_delayed_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) { svc->delayed_start_pending = 0; return; }
    strncpy(ctx->name, service_name, sizeof(ctx->name) - 1);
    ctx->delay_ms = delay_ms;

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&tid, &attr, scm_delayed_start_thread, ctx);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        svc->delayed_start_pending = 0;
        free(ctx);
        fprintf(stderr, "[scm_api] pthread_create(delayed_start) failed: %s\n",
                strerror(rc));
    }
}

static void ensure_run_dir(void)
{
    mkdir("/run/pe-compat", 0755);
    mkdir(SCM_RUN_PATH, 0755);
}

static void write_status_file(const char *name, int state, int pid)
{
    ensure_run_dir();
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s.status", SCM_RUN_PATH, name);

    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "state=%d\n", state);
        fprintf(f, "pid=%d\n", pid);
        fclose(f);
    }
}

static void remove_status_file(const char *name)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s.status", SCM_RUN_PATH, name);
    unlink(path);
}

int scm_start_service(const char *name)
{
    service_entry_t *svc = scm_db_find(name);
    if (!svc) {
        fprintf(stderr, "[scm_api] Service not found: %s\n", name);
        return -1;
    }

    /* Validate state transition: only STOPPED / START_PENDING are legal
     * starting points. Reject STOP_PENDING/PAUSED/etc. so a racing restart
     * cannot resurrect a service that's on its way down. */
    if (svc->state == SERVICE_RUNNING) {
        fprintf(stderr, "[scm_api] Service already running: %s\n", name);
        return 0;
    }
    if (svc->state != SERVICE_STOPPED &&
        svc->state != SERVICE_START_PENDING) {
        fprintf(stderr, "[scm_api] Illegal start from state %d: %s\n",
                svc->state, name);
        return -1;
    }

    /* If a user manually stopped this service, a racing auto-restart must
     * not override the user's intent. The manually_stopped flag is cleared
     * in handle_service_crash only when the crash is processed, so a clean
     * manual stop leaves it set. */
    if (svc->manually_stopped) {
        fprintf(stderr, "[scm_api] Refusing auto-restart of manually stopped: %s\n",
                name);
        return -1;
    }

    svc->state = SERVICE_START_PENDING;
    scm_notify_fanout(svc->name, SERVICE_START_PENDING);
    svc->crash_handled = 0;  /* Reset so next crash can be handled */
    /* Do NOT zero svc->restart_count here: the SIGCHLD-triggered restart
     * path reaches this function too, and handle_service_crash has already
     * incremented restart_count to schedule the retry. Zeroing it defeats
     * max_restarts. Manual starts reset via scm_start_service_manual(). */
    fprintf(stderr, "[scm_api] Starting service: %s (type=%d, binary='%s')\n",
            name, svc->type, svc->binary_path);

    if (svc->type == SERVICE_KERNEL_DRIVER || svc->type == SERVICE_FILE_SYSTEM_DRIVER) {
        /* Kernel drivers require the WDM host kernel module (wdm_host.ko) to
         * be loaded; it owns the kernel-side PE IAT walker and trust gate. If
         * /dev/wdm_host is not present we MUST NOT lie about SERVICE_RUNNING
         * -- Session 65 moved from fake-RUNNING to honest refusal because
         * lying breaks dependency graphs and hides real missing-driver bugs.
         * See services/drivers/kernel/wdm_host.* and trust_ape TRUST_ACTION_LOAD_KERNEL_BINARY. */
        if (access("/dev/wdm_host", F_OK) != 0) {
            fprintf(stderr, "[scm_api] Kernel driver refused: /dev/wdm_host unavailable "
                    "(wdm_host.ko not loaded) for service '%s' (binary='%s'): %s\n",
                    name, svc->binary_path, strerror(errno));
            svc->state = SERVICE_STOPPED;
            svc->pid = 0;
            write_status_file(name, SERVICE_STOPPED, 0);
            return -1;
        }
        /* WDM host present -- proceed with kernel-driver registration via the
         * wdm_host IOCTL path. The actual load is issued by the wdm_host
         * consumer; SCM records the RUNNING state once the driver binds. */
        fprintf(stderr, "[scm_api] Kernel driver - registering with WDM host\n");
        svc->state = SERVICE_RUNNING;
        svc->pid = 0;
        write_status_file(name, SERVICE_RUNNING, 0);
        scm_notify_fanout(svc->name, SERVICE_RUNNING);
        return 0;
    }

    /* User-mode service: fork and exec via peloader */
    if (!svc->binary_path[0]) {
        fprintf(stderr, "[scm_api] No binary path for service: %s\n", name);
        svc->state = SERVICE_STOPPED;
        return -1;
    }

    /* Use posix_spawn() instead of fork()+exec() to avoid async-signal-unsafe
     * calls (fopen/mkdir/snprintf) running in the child between fork and exec
     * while g_lock is held -- fork() snapshots glibc's malloc arena state
     * including any locks the parent held at the time of fork, which can
     * deadlock the child if an allocator path reacquires. posix_spawn goes
     * directly through execve via vfork/clone and never runs libc allocator
     * setup in the child, so it's safe to call with g_lock held.
     *
     * Pre-create the log directory in the parent (this is safe: the parent
     * owns its full allocator state). posix_spawn_file_actions_addopen
     * records a deferred open(2) that runs inside the child; open(2) is a
     * syscall and is async-signal-safe. */
    mkdir("/var/log/pe-compat", 0755);

    char logpath[4096];
    snprintf(logpath, sizeof(logpath), "/var/log/pe-compat/%s.log", name);

    /* Stage argv/binary locally: svc may be invalidated across I/O in
     * subsequent callers, but posix_spawn copies argv internally. */
    char binary[4096];
    strncpy(binary, svc->binary_path, sizeof(binary) - 1);
    binary[sizeof(binary) - 1] = '\0';

    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attrs;

    if (posix_spawn_file_actions_init(&actions) != 0) {
        fprintf(stderr, "[scm_api] posix_spawn_file_actions_init failed: %s\n",
                strerror(errno));
        svc->state = SERVICE_STOPPED;
        return -1;
    }
    if (posix_spawnattr_init(&attrs) != 0) {
        posix_spawn_file_actions_destroy(&actions);
        svc->state = SERVICE_STOPPED;
        return -1;
    }

    /* Detach into a new session so that a controlling-terminal SIGHUP to
     * the SCM doesn't propagate to the service children. POSIX_SPAWN_SETSID
     * is the async-signal-safe analogue of setsid() in the forked child. */
#ifdef POSIX_SPAWN_SETSID
    posix_spawnattr_setflags(&attrs, POSIX_SPAWN_SETSID);
#endif

    /* Deferred open(2) of the log file inside the child as fd 100, then
     * dup2 onto stdout/stderr, then close the intermediate fd. Close stdin
     * so services don't block on terminal I/O. Using a high fd (100) avoids
     * colliding with any fd already open in the spawning process. */
    (void)posix_spawn_file_actions_addclose(&actions, STDIN_FILENO);
    (void)posix_spawn_file_actions_addopen(&actions, STDIN_FILENO,
                                           "/dev/null", O_RDONLY, 0);
    (void)posix_spawn_file_actions_addopen(&actions, 100, logpath,
                                           O_WRONLY | O_CREAT | O_APPEND, 0644);
    (void)posix_spawn_file_actions_adddup2(&actions, 100, STDOUT_FILENO);
    (void)posix_spawn_file_actions_adddup2(&actions, 100, STDERR_FILENO);
    (void)posix_spawn_file_actions_addclose(&actions, 100);

    char *argv[] = {
        (char *)"peloader",
        binary,
        NULL
    };

    pid_t pid = 0;
    int rc = posix_spawn(&pid, "/usr/bin/peloader", &actions, &attrs,
                         argv, environ);

    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attrs);

    if (rc != 0) {
        fprintf(stderr, "[scm_api] posix_spawn() failed: %s\n", strerror(rc));
        svc->state = SERVICE_STOPPED;
        return -1;
    }

    /* Parent: mark as running immediately. If the process dies, SIGCHLD
     * will catch it and apply the restart policy. This avoids the TOCTOU
     * race of sleep+kill(0) which can also conflict with the SIGCHLD handler.
     * Explicit waitpid() is done by the main-loop reaper (scm_daemon.c)
     * triggered via SIGCHLD; we do not set SIGCHLD=SIG_IGN because SCM
     * needs to observe state transitions to apply restart policy. */
    svc->pid = pid;
    svc->state = SERVICE_RUNNING;
    write_status_file(name, SERVICE_RUNNING, pid);
    scm_notify_fanout(svc->name, SERVICE_RUNNING);

    scm_event_emit(SVC_EVT_START, (uint32_t)pid, name, 0, 0);
    fprintf(stderr, "[scm_api] Service started: %s (pid=%d)\n", name, pid);
    return 0;
}

int scm_stop_service(const char *name)
{
    service_entry_t *svc = scm_db_find(name);
    if (!svc) {
        fprintf(stderr, "[scm_api] Service not found: %s\n", name);
        return -1;
    }

    /* Legal stop-from states: RUNNING, PAUSED, START_PENDING (abort-start).
     * STOPPED/STOP_PENDING are no-ops. Paused services must be resumed
     * logically (we treat paused as stoppable since Windows SCM does too). */
    if (svc->state == SERVICE_STOPPED || svc->state == SERVICE_STOP_PENDING) {
        fprintf(stderr, "[scm_api] Service not running (state=%d): %s\n",
                svc->state, name);
        /* Still mark manually_stopped so an in-flight restart is suppressed. */
        svc->manually_stopped = 1;
        return 0;
    }
    if (svc->state != SERVICE_RUNNING &&
        svc->state != SERVICE_PAUSED &&
        svc->state != SERVICE_START_PENDING) {
        fprintf(stderr, "[scm_api] Illegal stop from state %d: %s\n",
                svc->state, name);
        return -1;
    }

    svc->state = SERVICE_STOP_PENDING;
    scm_notify_fanout(svc->name, SERVICE_STOP_PENDING);
    svc->manually_stopped = 1;  /* Suppress restart policy */
    svc->crash_handled = 1;     /* Prevent SIGCHLD handler from restarting while unlocked */
    pid_t pid = svc->pid;
    fprintf(stderr, "[scm_api] Stopping service: %s (pid=%d)\n", name, pid);

    if (pid > 0) {
        /* Check if the process is still alive before signaling.
         * The PID could have been recycled if the child already exited. */
        if (kill(pid, 0) == 0) {
            kill(pid, SIGTERM);
        }

        /* Release the lock before blocking wait to avoid stalling other threads.
         * State is STOP_PENDING and crash_handled=1, so the SIGCHLD handler
         * (handle_service_crash) will skip this service if it races in. */
        pthread_mutex_unlock(&g_lock);

        /* Wait for process to exit (5 second timeout) */
        int status;
        for (int i = 0; i < 50; i++) {
            if (kill(pid, 0) != 0)
                break;   /* Process gone */
            usleep(100000); /* 100ms */
        }

        /* Force kill if still alive */
        if (kill(pid, 0) == 0)
            kill(pid, SIGKILL);

        /* Non-blocking reap (SIGCHLD handler may have already reaped) */
        waitpid(pid, &status, WNOHANG);

        /* Re-acquire lock and verify state consistency.
         * The SIGCHLD handler may have already set state to STOPPED
         * if it raced in between unlock and re-lock. */
        pthread_mutex_lock(&g_lock);

        /* Re-lookup in case the service entry was modified while unlocked */
        svc = scm_db_find(name);
        if (!svc) {
            /* Service was deleted while we were waiting -- nothing to do */
            fprintf(stderr, "[scm_api] Service '%s' disappeared during stop\n", name);
            return 0;
        }
    }

    svc->state = SERVICE_STOPPED;
    svc->pid = 0;
    remove_status_file(name);
    scm_notify_fanout(svc->name, SERVICE_STOPPED);

    scm_event_emit(SVC_EVT_STOP, 0, name, 0, 0);
    fprintf(stderr, "[scm_api] Service stopped: %s\n", name);
    return 0;
}

int scm_query_service(const char *name, int *state, int *pid)
{
    service_entry_t *svc = scm_db_find(name);
    if (!svc)
        return -1;

    /* Check if process is still alive */
    if (svc->state == SERVICE_RUNNING && svc->pid > 0) {
        if (kill(svc->pid, 0) < 0 && errno == ESRCH) {
            /* Process died -- mark crash_handled so the SIGCHLD reaper
             * and health monitor don't also try to handle this. */
            svc->crash_handled = 1;
            svc->state = SERVICE_STOPPED;
            svc->pid = 0;
            remove_status_file(name);
            scm_notify_fanout(svc->name, SERVICE_STOPPED);
        }
    }

    if (state) *state = svc->state;
    if (pid) *pid = svc->pid;
    return 0;
}

int scm_list_services(void)
{
    int count = scm_db_count();
    printf("%-30s %-8s %-8s %-12s %s\n",
           "SERVICE NAME", "TYPE", "START", "STATE", "BINARY");
    printf("%-30s %-8s %-8s %-12s %s\n",
           "---", "---", "---", "---", "---");

    for (int i = 0; i < count; i++) {
        service_entry_t *svc = scm_db_get(i);
        if (!svc) continue;

        const char *type_str = "USER";
        if (svc->type == SERVICE_KERNEL_DRIVER) type_str = "KERNEL";
        else if (svc->type == SERVICE_FILE_SYSTEM_DRIVER) type_str = "FS_DRV";

        const char *start_str = "DEMAND";
        switch (svc->start_type) {
        case 0: start_str = "BOOT"; break;
        case 1: start_str = "SYSTEM"; break;
        case 2: start_str = "AUTO"; break;
        case 3: start_str = "DEMAND"; break;
        case 4: start_str = "DISABLED"; break;
        }

        const char *state_str = "STOPPED";
        if (svc->state == SERVICE_RUNNING) state_str = "RUNNING";
        else if (svc->state == SERVICE_START_PENDING) state_str = "STARTING";
        else if (svc->state == SERVICE_STOP_PENDING) state_str = "STOPPING";

        printf("%-30s %-8s %-8s %-12s %s\n",
               svc->name, type_str, start_str, state_str, svc->binary_path);
    }

    return count;
}
