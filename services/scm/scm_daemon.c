/*
 * scm_daemon.c - Windows Service Control Manager emulation daemon
 *
 * Manages Windows service lifecycle:
 * - Install/uninstall services
 * - Start/stop services (with dependency resolution)
 * - Query service status
 * - Health monitoring (background thread detects crashed services)
 * - Event emission to the AI cortex via /run/pe-compat/events.sock
 * - Linux systemd service bridge (transparent fallback for native services)
 *
 * Services are registered in a database at /var/lib/pe-compat/services/
 * Each service has a .svc config file describing its properties.
 *
 * Listens on a Unix domain socket at /run/pe-compat/scm.sock for
 * commands from the sc CLI tool and the advapi32 service API.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <ctype.h>
#include <strings.h>
#include <stdatomic.h>

#include "scm.h"
#include "scm_event.h"

#define SCM_LOG_PREFIX "[scm] "
#define MAX_CLIENTS 16
#define CMD_BUFSIZE 4096

#define HEALTH_CHECK_INTERVAL_SEC  5
#define HEALTH_MAX_BACKOFF_SEC     60

pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_sigchld_pending = 0;
static pthread_t g_health_thread;
static int g_health_thread_started = 0;

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static void sigchld_handler(int sig)
{
    (void)sig;
    g_sigchld_pending = 1;
}

/* ========================================================================
 * Service crash handler (shared by SIGCHLD reaper and health monitor)
 * ======================================================================== */

/*
 * Handle a service that has crashed or exited unexpectedly.
 * Must be called with g_lock held.
 * Returns the name of the service to restart (caller restarts outside lock),
 * or sets restart_name[0] = '\0' if no restart is needed.
 */
static void handle_service_crash(service_entry_t *svc, int exit_code,
                                 char *restart_name, size_t restart_sz,
                                 int *delay_ms_out)
{
    restart_name[0] = '\0';
    *delay_ms_out = 0;

    /* Prevent double-handling between SIGCHLD reaper and health monitor */
    if (svc->crash_handled) {
        return;
    }
    svc->crash_handled = 1;

    fprintf(stderr, SCM_LOG_PREFIX "Service '%s' (pid=%d) exited with status %d\n",
            svc->name, svc->pid, exit_code);

    /* Emit crash event */
    scm_event_emit(SVC_EVT_CRASH, (uint32_t)svc->pid, svc->name,
                   (int32_t)exit_code, (uint32_t)svc->restart_count);

    svc->state = SERVICE_STOPPED;
    svc->pid = 0;

    /* Clear the on-disk status file so `sc query` reflects reality
     * instead of stale RUNNING with a defunct pid. */
    {
        char status_path[4096];
        snprintf(status_path, sizeof(status_path),
                 "%s/%s.status", SCM_RUN_PATH, svc->name);
        unlink(status_path);
    }

    /* Check restart policy */
    int should_restart = 0;
    if (svc->manually_stopped) {
        /* User explicitly stopped -- never restart */
        svc->manually_stopped = 0;
    } else if (svc->restart_policy == RESTART_ALWAYS) {
        should_restart = 1;
    } else if (svc->restart_policy == RESTART_ON_FAILURE && exit_code != 0) {
        should_restart = 1;
    }

    /* Check max_restarts limit */
    if (should_restart && svc->max_restarts > 0 &&
        svc->restart_count >= svc->max_restarts) {
        fprintf(stderr, SCM_LOG_PREFIX "Service '%s' hit max restarts (%d), "
                "not restarting\n", svc->name, svc->max_restarts);
        scm_event_emit(SVC_EVT_STOP, 0, svc->name, (int32_t)exit_code,
                       (uint32_t)svc->restart_count);
        /* Do NOT reset restart_count here -- leave it at max so the service
         * stays locked out until a manual start (which resets restart_count). */
        should_restart = 0;
    }

    if (should_restart) {
        svc->restart_count++;

        /* Exponential backoff: base_delay * 2^(restart_count-1)
         * Capped at HEALTH_MAX_BACKOFF_SEC seconds */
        int base_ms = svc->restart_delay_ms > 0 ?
            svc->restart_delay_ms : DEFAULT_RESTART_DELAY_MS;
        int backoff_shift = svc->restart_count - 1;
        if (backoff_shift > 6) backoff_shift = 6;  /* Cap at 64x base */
        int delay = base_ms * (1 << backoff_shift);
        if (delay > HEALTH_MAX_BACKOFF_SEC * 1000)
            delay = HEALTH_MAX_BACKOFF_SEC * 1000;

        *delay_ms_out = delay;
        strncpy(restart_name, svc->name, restart_sz - 1);
        restart_name[restart_sz - 1] = '\0';

        fprintf(stderr, SCM_LOG_PREFIX "Restarting '%s' in %dms "
                "(attempt %d, exponential backoff)\n",
                svc->name, delay, svc->restart_count);

        scm_event_emit(SVC_EVT_RESTART, 0, svc->name, (int32_t)exit_code,
                       (uint32_t)svc->restart_count);
    }
}

/* ========================================================================
 * SIGCHLD reaper: reap exited children and trigger restart policy
 * ======================================================================== */

static void reap_and_restart(void)
{
    int status;
    pid_t pid;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        char restart_name[256] = {0};
        int delay_ms = 0;

        pthread_mutex_lock(&g_lock);

        /* Find the service that owned this pid */
        int count = scm_db_count();
        for (int i = 0; i < count; i++) {
            service_entry_t *svc = scm_db_get(i);
            if (!svc || svc->pid != pid)
                continue;

            handle_service_crash(svc, exit_code, restart_name,
                                 sizeof(restart_name), &delay_ms);
            break;
        }

        pthread_mutex_unlock(&g_lock);

        /* Restart outside the lock to avoid fork-with-mutex UB */
        if (restart_name[0]) {
            usleep((useconds_t)delay_ms * 1000);
            pthread_mutex_lock(&g_lock);
            scm_start_service(restart_name);
            pthread_mutex_unlock(&g_lock);
        }
    }
}

/* ========================================================================
 * Health monitor thread
 * ======================================================================== */

/*
 * Background thread that periodically checks if services marked as RUNNING
 * are still alive.  This catches cases where a child exits without us
 * receiving SIGCHLD (e.g., PID reuse race, or signal delivered during
 * handler execution).
 */
static void *health_monitor_thread(void *arg)
{
    (void)arg;

    fprintf(stderr, SCM_LOG_PREFIX "Health monitor started "
            "(interval=%ds)\n", HEALTH_CHECK_INTERVAL_SEC);

    while (g_running) {
        /* Sleep in small increments so we respond quickly to shutdown */
        for (int s = 0; s < HEALTH_CHECK_INTERVAL_SEC && g_running; s++)
            sleep(1);

        if (!g_running)
            break;

        /* Snapshot services that need restart while holding the lock */
        char restart_names[MAX_SERVICES][260];
        int restart_delays[MAX_SERVICES];
        int restart_count = 0;

        pthread_mutex_lock(&g_lock);

        int count = scm_db_count();
        for (int i = 0; i < count; i++) {
            service_entry_t *svc = scm_db_get(i);
            if (!svc || svc->state != SERVICE_RUNNING || svc->pid <= 0)
                continue;

            /* Check if the PID is still alive */
            if (kill(svc->pid, 0) != 0 && errno == ESRCH) {
                fprintf(stderr, SCM_LOG_PREFIX "Health check: '%s' (pid=%d) "
                        "is dead (detected by monitor)\n",
                        svc->name, svc->pid);

                /* Try to reap the zombie (may already be reaped by SIGCHLD) */
                int status = 0;
                pid_t w = waitpid(svc->pid, &status, WNOHANG);
                int exit_code = -1;
                if (w > 0 && WIFEXITED(status))
                    exit_code = WEXITSTATUS(status);

                char rname[256] = {0};
                int delay_ms = 0;

                handle_service_crash(svc, exit_code, rname,
                                     sizeof(rname), &delay_ms);

                /* Collect for restart outside the lock */
                if (rname[0] && restart_count < MAX_SERVICES) {
                    strncpy(restart_names[restart_count], rname, 259);
                    restart_names[restart_count][259] = '\0';
                    restart_delays[restart_count] = delay_ms;
                    restart_count++;
                }
            }
        }

        pthread_mutex_unlock(&g_lock);

        /* Now restart outside the lock to avoid fork-with-mutex UB */
        for (int i = 0; i < restart_count; i++) {
            usleep((useconds_t)restart_delays[i] * 1000);
            pthread_mutex_lock(&g_lock);
            scm_start_service(restart_names[i]);
            pthread_mutex_unlock(&g_lock);
        }
    }

    fprintf(stderr, SCM_LOG_PREFIX "Health monitor stopped\n");
    return NULL;
}

/* ========================================================================
 * Linux systemd service bridge
 * ======================================================================== */

/*
 * Well-known Linux services that Windows programs might reference.
 * Maps Windows service name -> systemd unit name.
 */
static const struct {
    const char *win_name;
    const char *linux_unit;
} g_linux_service_map[] = {
    { "NetworkManager",    "NetworkManager.service"    },
    { "Dhcp",             "dhcpcd.service"            },
    { "Dnscache",         "systemd-resolved.service"  },
    { "EventLog",         "systemd-journald.service"  },
    { "PlugPlay",         "systemd-udevd.service"     },
    { "AudioSrv",         "pipewire.service"          },
    { "Audiosrv",         "pipewire.service"          },
    { "Spooler",          "cups.service"              },
    { "W32Time",          "systemd-timesyncd.service" },
    { "Wlansvc",          "wpa_supplicant.service"    },
    { "LanmanServer",     "smb.service"               },
    { "LanmanWorkstation","smb.service"               },
    { "RpcSs",            "dbus.service"              },
    { "Schedule",         "cronie.service"            },
    { "Winmgmt",         "dbus.service"              },
    { "BITS",            "systemd-networkd.service"   },
    { "wuauserv",        "pacman"                     },
    { NULL, NULL }
};

/*
 * Check if a name refers to a Linux systemd service (either via the
 * well-known mapping table, or by checking if a systemd unit exists).
 * Returns the systemd unit name, or NULL if not a Linux service.
 */
static const char *linux_service_lookup(const char *name)
{
    /* First check the well-known mapping table */
    for (int i = 0; g_linux_service_map[i].win_name; i++) {
        if (strcasecmp(name, g_linux_service_map[i].win_name) == 0)
            return g_linux_service_map[i].linux_unit;
    }

    /* Check if it looks like a systemd unit name already (contains ".service") */
    if (strstr(name, ".service") || strstr(name, ".socket") ||
        strstr(name, ".timer"))
        return name;

    return NULL;
}

/*
 * Validate a service/unit name: only allow [a-zA-Z0-9._-@] to prevent
 * shell injection when the name is passed to popen().
 */
static int validate_service_name(const char *name)
{
    if (!name || !*name)
        return 0;
    for (const char *p = name; *p; p++) {
        if (!(*p >= 'a' && *p <= 'z') && !(*p >= 'A' && *p <= 'Z') &&
            !(*p >= '0' && *p <= '9') && *p != '.' && *p != '_' &&
            *p != '-' && *p != '@')
            return 0;
    }
    return 1;
}

/*
 * Query a Linux systemd service.
 * Fills in a service_status response for the caller.
 * Returns 0 on success, -1 if the service does not exist or systemctl fails.
 */
static int scm_query_linux_service(const char *unit_name, int *state_out,
                                   int *pid_out, char *display_out,
                                   size_t display_sz)
{
    char cmd[512];
    char line[256];
    FILE *fp;

    /* Reject names with shell-unsafe characters */
    if (!validate_service_name(unit_name))
        return -1;

    /* Check if the service is active */
    snprintf(cmd, sizeof(cmd), "systemctl is-active '%s' 2>/dev/null", unit_name);
    fp = popen(cmd, "r");
    if (!fp)
        return -1;

    int active = 0;
    if (fgets(line, sizeof(line), fp)) {
        /* Strip newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        if (strcmp(line, "active") == 0 || strcmp(line, "reloading") == 0)
            active = 1;
        else if (strcmp(line, "activating") == 0)
            active = 2;  /* START_PENDING */
        else if (strcmp(line, "deactivating") == 0)
            active = 3;  /* STOP_PENDING */
    }
    {
        int pc_ret = pclose(fp);
        if (pc_ret < 0)
            fprintf(stderr, SCM_LOG_PREFIX "Warning: pclose(is-active) failed for '%s': %s\n",
                    unit_name, strerror(errno));
    }

    /* Map to Windows service states */
    switch (active) {
    case 1:  *state_out = SERVICE_RUNNING; break;
    case 2:  *state_out = SERVICE_START_PENDING; break;
    case 3:  *state_out = SERVICE_STOP_PENDING; break;
    default: *state_out = SERVICE_STOPPED; break;
    }

    /* Get the MainPID */
    *pid_out = 0;
    snprintf(cmd, sizeof(cmd),
             "systemctl show '%s' -p MainPID --value 2>/dev/null", unit_name);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            *pid_out = atoi(line);
        }
        int pc_ret = pclose(fp);
        if (pc_ret < 0)
            fprintf(stderr, SCM_LOG_PREFIX "Warning: pclose(MainPID) failed for '%s': %s\n",
                    unit_name, strerror(errno));
    }

    /* Get the description for display_name */
    if (display_out && display_sz > 0) {
        display_out[0] = '\0';
        snprintf(cmd, sizeof(cmd),
                 "systemctl show '%s' -p Description --value 2>/dev/null",
                 unit_name);
        fp = popen(cmd, "r");
        if (fp) {
            if (fgets(line, sizeof(line), fp)) {
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                strncpy(display_out, line, display_sz - 1);
                display_out[display_sz - 1] = '\0';
            }
            int pc_ret = pclose(fp);
            if (pc_ret < 0)
                fprintf(stderr, SCM_LOG_PREFIX "Warning: pclose(Description) failed for '%s': %s\n",
                        unit_name, strerror(errno));
        }
    }

    return 0;
}

/* ========================================================================
 * Directory setup
 * ======================================================================== */

static void ensure_directories(void)
{
    mkdir("/var/lib/pe-compat", 0755);
    mkdir(SCM_DB_PATH, 0755);
    mkdir("/run/pe-compat", 0755);
    mkdir(SCM_RUN_PATH, 0755);
}

/* ========================================================================
 * Command processing
 * ======================================================================== */

/*
 * Escape double quotes and backslashes for safe JSON string interpolation.
 */
static void json_escape(const char *src, char *dst, size_t dst_size)
{
    if (dst_size < 3) { if (dst_size > 0) dst[0] = '\0'; return; }
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dst_size - 3; i++) {
        if (src[i] == '"' || src[i] == '\\')
            dst[j++] = '\\';
        dst[j++] = src[i];
    }
    dst[j] = '\0';
}

/*
 * Format a response as a simple JSON-ish line for the client.
 * Returns bytes written to buf.
 */
static int format_response(char *buf, size_t bufsz, const char *status,
                           const char *message)
{
    int n = snprintf(buf, bufsz, "{\"status\":\"%s\",\"message\":\"%s\"}\n",
                     status, message);
    return (n >= (int)bufsz) ? (int)bufsz - 1 : n;
}

/*
 * Process a command and write the response into resp_buf.
 * Commands are newline-delimited text: "action name [extra...]"
 */
static int process_command(const char *cmd, char *resp_buf, size_t resp_sz)
{
    char action[64], name[256], extra[1024];
    memset(extra, 0, sizeof(extra));
    int n = sscanf(cmd, "%63s %255s %1023[^\n]", action, name, extra);
    if (n < 1) return format_response(resp_buf, resp_sz, "error", "empty command");

    pthread_mutex_lock(&g_lock);
    int len = 0;

    if (strcmp(action, "start") == 0 && n >= 2) {
        int ret = scm_start_with_deps(name);
        if (ret == 0) {
            scm_event_emit(SVC_EVT_START, 0, name, 0, 0);
            len = format_response(resp_buf, resp_sz, "ok", "service started");
        } else {
            len = format_response(resp_buf, resp_sz, "error", "failed to start service");
        }

    } else if (strcmp(action, "stop") == 0 && n >= 2) {
        int ret = scm_stop_with_deps(name);
        if (ret == 0) {
            scm_event_emit(SVC_EVT_STOP, 0, name, 0, 0);
            len = format_response(resp_buf, resp_sz, "ok", "service stopped");
        } else {
            len = format_response(resp_buf, resp_sz, "error", "failed to stop service");
        }

    } else if (strcmp(action, "status") == 0 && n >= 2) {
        int state = 0, pid = 0;

        /* Try Windows service database first */
        char esc_name[512];
        json_escape(name, esc_name, sizeof(esc_name));
        if (scm_query_service(name, &state, &pid) == 0) {
            const char *state_str;
            switch (state) {
            case SERVICE_STOPPED:       state_str = "STOPPED"; break;
            case SERVICE_RUNNING:       state_str = "RUNNING"; break;
            case SERVICE_START_PENDING: state_str = "START_PENDING"; break;
            case SERVICE_STOP_PENDING:  state_str = "STOP_PENDING"; break;
            case SERVICE_PAUSED:        state_str = "PAUSED"; break;
            default:                    state_str = "UNKNOWN"; break;
            }
            len = snprintf(resp_buf, resp_sz,
                           "{\"status\":\"ok\",\"service\":\"%s\","
                           "\"state\":\"%s\",\"pid\":%d}\n",
                           esc_name, state_str, pid);
        } else {
            /* Fall back to Linux systemd bridge */
            const char *unit = linux_service_lookup(name);
            if (unit && scm_query_linux_service(unit, &state, &pid,
                                                NULL, 0) == 0) {
                const char *state_str;
                switch (state) {
                case SERVICE_STOPPED:       state_str = "STOPPED"; break;
                case SERVICE_RUNNING:       state_str = "RUNNING"; break;
                case SERVICE_START_PENDING: state_str = "START_PENDING"; break;
                case SERVICE_STOP_PENDING:  state_str = "STOP_PENDING"; break;
                default:                    state_str = "UNKNOWN"; break;
                }
                char esc_unit[512];
                json_escape(unit, esc_unit, sizeof(esc_unit));
                len = snprintf(resp_buf, resp_sz,
                               "{\"status\":\"ok\",\"service\":\"%s\","
                               "\"state\":\"%s\",\"pid\":%d,"
                               "\"source\":\"systemd\",\"unit\":\"%s\"}\n",
                               esc_name, state_str, pid, esc_unit);
            } else {
                len = format_response(resp_buf, resp_sz, "error",
                                      "service not found");
            }
        }

    } else if (strcmp(action, "install") == 0 && n >= 3) {
        /* extra = "<binary_path> [type] [start_type]"  -- sc.c packs optional
         * type/start_type at the end.  Default to WIN32_OWN_PROCESS /
         * DEMAND_START when not supplied. */
        char bin_path[2048] = {0};
        int inst_type = SERVICE_WIN32_OWN_PROCESS;
        int inst_start = SERVICE_DEMAND_START;
        int parsed = sscanf(extra, "%2047s %d %d",
                            bin_path, &inst_type, &inst_start);
        if (parsed < 1 || !bin_path[0]) {
            len = format_response(resp_buf, resp_sz, "error",
                                  "missing binary path");
        } else {
            int ret = scm_db_install(name, name, bin_path,
                                     inst_type, inst_start, NULL);
            if (ret == 0) {
                scm_event_emit(SVC_EVT_INSTALL, 0, name, 0, 0);
                len = format_response(resp_buf, resp_sz, "ok",
                                      "service installed");
            } else if (ret == -1) {
                len = format_response(resp_buf, resp_sz, "error",
                                      "service already exists");
            } else if (ret == -3) {
                len = format_response(resp_buf, resp_sz, "error",
                                      "invalid service name");
            } else {
                len = format_response(resp_buf, resp_sz, "error",
                                      "install failed");
            }
        }

    } else if (strcmp(action, "delete") == 0 && n >= 2) {
        /* Stop-delete race: if another thread is in scm_stop_service for the
         * same name, it temporarily drops g_lock while waiting on the child.
         * The delete path already handles a running service (see
         * scm_db_delete_service which signals and waits).  The re-lookup in
         * scm_stop_service after re-lock guards against use-after-free. */
        if (!scm_db_find(name)) {
            len = format_response(resp_buf, resp_sz, "error",
                                  "service not found");
        } else {
            int dr = scm_db_delete_service(name);
            if (dr == 0) {
                scm_event_emit(SVC_EVT_STOP, 0, name, 0, 0);
                len = format_response(resp_buf, resp_sz, "ok",
                                      "service deleted");
            } else {
                len = format_response(resp_buf, resp_sz, "error",
                                      "delete failed");
            }
        }

    } else if (strcmp(action, "list") == 0) {
        /* Build a JSON array of services.  Guard against undersized
         * resp_sz to prevent size_t underflow in headroom calculations. */
        const size_t headroom = 200;
        int count = scm_db_count();
        len = snprintf(resp_buf, resp_sz, "{\"status\":\"ok\",\"services\":[");
        if (len < 0 || (size_t)len >= resp_sz) len = (int)resp_sz - 1;
        for (int i = 0; i < count && resp_sz > headroom &&
                        (size_t)len < resp_sz - headroom; i++) {
            service_entry_t *svc = scm_db_get(i);
            if (!svc) continue;
            const char *state_str = "STOPPED";
            if (svc->state == SERVICE_RUNNING) state_str = "RUNNING";
            else if (svc->state == SERVICE_START_PENDING) state_str = "STARTING";

            char esc_svc_name[512];
            json_escape(svc->name, esc_svc_name, sizeof(esc_svc_name));

            if (i > 0 && resp_sz > headroom &&
                (size_t)len < resp_sz - headroom) {
                resp_buf[len++] = ',';
            }
            int w = snprintf(resp_buf + len, resp_sz - len,
                             "{\"name\":\"%s\",\"state\":\"%s\",\"type\":%d,"
                             "\"start_type\":%d,\"pid\":%d}",
                             esc_svc_name, state_str, svc->type,
                             svc->start_type, svc->pid);
            /* Clamp: snprintf returns "would have written" on truncation.
             * Do not let len advance past the buffer. */
            if (w < 0) break;
            if ((size_t)w >= resp_sz - len) {
                len = (int)resp_sz - 1;
                break;
            }
            len += w;
        }
        if ((size_t)len < resp_sz) {
            int w = snprintf(resp_buf + len, resp_sz - len, "]}\n");
            if (w > 0) {
                if ((size_t)w >= resp_sz - len)
                    len = (int)resp_sz - 1;
                else
                    len += w;
            }
        }

    } else if (strcmp(action, "ping") == 0) {
        len = format_response(resp_buf, resp_sz, "ok", "pong");

    } else {
        len = format_response(resp_buf, resp_sz, "error", "unknown command");
    }

    pthread_mutex_unlock(&g_lock);
    return len;
}

/* ========================================================================
 * Socket / client handling
 * ======================================================================== */

static int create_listen_socket(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror(SCM_LOG_PREFIX "socket()");
        return -1;
    }

    /* Remove stale socket */
    unlink(SCM_SOCKET_PATH);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SCM_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror(SCM_LOG_PREFIX "bind()");
        close(fd);
        return -1;
    }

    /* Allow all users to connect */
    chmod(SCM_SOCKET_PATH, 0666);

    if (listen(fd, MAX_CLIENTS) < 0) {
        perror(SCM_LOG_PREFIX "listen()");
        close(fd);
        return -1;
    }

    /* Non-blocking so we can check g_running */
    fcntl(fd, F_SETFL, O_NONBLOCK);

    /* Prevent leaking fd to child processes */
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    return fd;
}

static void handle_client(int client_fd)
{
    /* Prevent leaking the client socket into service children forked by
     * process_command() -> scm_start_with_deps() -> scm_start_service(). */
    fcntl(client_fd, F_SETFD, FD_CLOEXEC);

    /*
     * Install 2-second send/recv timeouts on the client socket so a
     * slow/hung client cannot stall the SCM main loop indefinitely
     * (the main loop also drives SIGCHLD-triggered restart policy).
     * SO_RCVTIMEO/SO_SNDTIMEO apply to blocking read()/write() syscalls.
     */
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    (void)setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    char buf[CMD_BUFSIZE];
    ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    buf[n] = '\0';

    /* Strip trailing newline */
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        buf[--n] = '\0';

    char resp[CMD_BUFSIZE * 2];
    int resp_len = process_command(buf, resp, sizeof(resp));

    if (resp_len > 0) {
        ssize_t total = 0;
        while (total < resp_len) {
            ssize_t wn = write(client_fd, resp + total, resp_len - total);
            if (wn < 0) {
                /* EAGAIN after SO_SNDTIMEO = hung client; abandon */
                if (errno == EAGAIN || errno == EWOULDBLOCK ||
                    errno == EPIPE || errno == ECONNRESET)
                    break;
                if (errno == EINTR)
                    continue;
                break;
            }
            if (wn == 0) break;
            total += (size_t)wn;
        }
    }

    close(client_fd);
}

/* ========================================================================
 * main
 * ======================================================================== */

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf(SCM_LOG_PREFIX "Windows Service Control Manager starting...\n");

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGCHLD, sigchld_handler); /* Reap children and apply restart policy */

    ensure_directories();

    /* Initialize event emission to cortex */
    scm_event_init();

    /* Load service database */
    int count = scm_db_load();
    printf(SCM_LOG_PREFIX "Loaded %d services\n", count < 0 ? 0 : count);

    /* Auto-start services in parallel dependency batches */
    printf(SCM_LOG_PREFIX "Auto-starting services (parallel by dependency depth)...\n");
    pthread_mutex_lock(&g_lock);
    scm_parallel_auto_start();
    pthread_mutex_unlock(&g_lock);
    printf(SCM_LOG_PREFIX "Auto-start complete\n");

    /* Start the health monitor thread */
    if (pthread_create(&g_health_thread, NULL, health_monitor_thread, NULL) == 0) {
        g_health_thread_started = 1;
        printf(SCM_LOG_PREFIX "Health monitor thread started\n");
    } else {
        fprintf(stderr, SCM_LOG_PREFIX "WARNING: Failed to start health monitor thread\n");
    }

    /* Create listening socket */
    int listen_fd = create_listen_socket();
    if (listen_fd < 0) {
        fprintf(stderr, SCM_LOG_PREFIX "Failed to create socket, exiting.\n");
        g_running = 0;
        if (g_health_thread_started)
            pthread_join(g_health_thread, NULL);
        scm_event_shutdown();
        return 1;
    }

    printf(SCM_LOG_PREFIX "SCM ready. Listening on %s\n", SCM_SOCKET_PATH);

    /* Main loop: accept and handle clients */
    while (g_running) {
        /* Check for exited children (restart policy) */
        if (g_sigchld_pending) {
            g_sigchld_pending = 0;
            reap_and_restart();
        }

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listen_fd, &readfds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int ret = select(listen_fd + 1, &readfds, NULL, NULL, &tv);

        if (ret < 0 && errno == EINTR)
            continue;

        if (ret > 0 && FD_ISSET(listen_fd, &readfds)) {
            int client_fd = accept(listen_fd, NULL, NULL);
            if (client_fd >= 0)
                handle_client(client_fd);
        }
    }

    /* Cleanup */
    close(listen_fd);
    unlink(SCM_SOCKET_PATH);

    /* Stop health monitor thread */
    if (g_health_thread_started) {
        printf(SCM_LOG_PREFIX "Waiting for health monitor to stop...\n");
        pthread_join(g_health_thread, NULL);
    }

    /* Stop all running services */
    printf(SCM_LOG_PREFIX "Stopping all services...\n");
    pthread_mutex_lock(&g_lock);
    int total = scm_db_count();
    for (int i = 0; i < total; i++) {
        service_entry_t *svc = scm_db_get(i);
        if (svc && svc->state == SERVICE_RUNNING) {
            scm_event_emit(SVC_EVT_STOP, (uint32_t)svc->pid, svc->name, 0, 0);
            scm_stop_service(svc->name);
        }
    }
    pthread_mutex_unlock(&g_lock);

    /* Shut down event emission */
    scm_event_shutdown();

    printf(SCM_LOG_PREFIX "SCM shutdown complete\n");
    return 0;
}
