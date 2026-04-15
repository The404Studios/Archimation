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

#include "scm.h"
#include "scm_event.h"

extern char **environ;

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
    svc->crash_handled = 0;  /* Reset so next crash can be handled */
    /* Do NOT zero svc->restart_count here: the SIGCHLD-triggered restart
     * path reaches this function too, and handle_service_crash has already
     * incremented restart_count to schedule the retry. Zeroing it defeats
     * max_restarts. Manual starts reset via scm_start_service_manual(). */
    fprintf(stderr, "[scm_api] Starting service: %s (type=%d, binary='%s')\n",
            name, svc->type, svc->binary_path);

    if (svc->type == SERVICE_KERNEL_DRIVER || svc->type == SERVICE_FILE_SYSTEM_DRIVER) {
        /* Kernel drivers: handled by the WDM host module */
        fprintf(stderr, "[scm_api] Kernel driver - registering with WDM host\n");
        svc->state = SERVICE_RUNNING;
        svc->pid = 0;
        write_status_file(name, SERVICE_RUNNING, 0);
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
