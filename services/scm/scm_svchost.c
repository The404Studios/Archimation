/*
 * scm_svchost.c - Windows-style svchost grouping for SCM
 *
 * Implements Windows SERVICE_WIN32_SHARE_PROCESS semantics: services
 * tagged with the same `service_group` field are co-hosted in a single
 * peloader process invoked as `peloader --svchost --group NAME --ipc-fd 3`.
 * Each in-host service is loaded/controlled via a per-host AF_UNIX
 * socket using length-prefixed JSON (LP-JSON):
 *
 *   wire:  | uint32_t big-endian length | <length> bytes of JSON |
 *
 *   ops:   {"op":"load","service":"<name>","path":"<exe>"}
 *          {"op":"control","service":"<name>","code":<int>}
 *          {"op":"release","service":"<name>"}
 *          {"op":"shutdown"}
 *          {"op":"status","service":"<name>","state":"<str>","pid":<int>}
 *          {"op":"ack","ok":true|false,"err":"<str>"}
 *
 * The SCM only sends, receives an ack, and closes when the group goes
 * empty. The ack carries no service state -- the host emits asynchronous
 * status updates which the SCM may or may not consume (current cut: SCM
 * trusts the ack, lets SIGCHLD detect host crashes).
 *
 * Concurrency: every entry point assumes the caller holds g_lock (same
 * contract as scm_api.c). The svchost group list is only mutated under
 * that lock so no separate mutex is required here.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdint.h>
#include <arpa/inet.h>      /* htonl/ntohl */
#include <poll.h>

#include "scm.h"
#include "scm_event.h"

extern char **environ;

/* ------------------------------------------------------------------ */
/* svchost group bookkeeping                                          */
/* ------------------------------------------------------------------ */

#define SVCHOST_MAX_PER_GROUP   32
#define SVCHOST_RECV_TIMEOUT_MS 3000

typedef struct svchost_group {
    char    name[64];
    pid_t   host_pid;
    int     ipc_fd;             /* SCM end of AF_UNIX socketpair */
    char   *services[SVCHOST_MAX_PER_GROUP];   /* heap-strdup'd names */
    int     service_count;
    struct svchost_group *next;
} svchost_group_t;

static svchost_group_t *g_svchost_groups = NULL;

static svchost_group_t *find_group(const char *name)
{
    for (svchost_group_t *g = g_svchost_groups; g; g = g->next) {
        if (strcmp(g->name, name) == 0)
            return g;
    }
    return NULL;
}

static svchost_group_t *find_group_by_pid(pid_t pid)
{
    for (svchost_group_t *g = g_svchost_groups; g; g = g->next) {
        if (g->host_pid == pid)
            return g;
    }
    return NULL;
}

static int group_has_service(svchost_group_t *g, const char *svc)
{
    for (int i = 0; i < g->service_count; i++) {
        if (g->services[i] && strcmp(g->services[i], svc) == 0)
            return i;
    }
    return -1;
}

static void group_add_service(svchost_group_t *g, const char *svc)
{
    if (g->service_count >= SVCHOST_MAX_PER_GROUP) {
        fprintf(stderr, "[svchost] group '%s' full (%d services)\n",
                g->name, g->service_count);
        return;
    }
    g->services[g->service_count++] = strdup(svc);
}

static void group_remove_service(svchost_group_t *g, const char *svc)
{
    int idx = group_has_service(g, svc);
    if (idx < 0) return;
    free(g->services[idx]);
    /* Keep the array dense */
    for (int i = idx; i < g->service_count - 1; i++)
        g->services[i] = g->services[i + 1];
    g->services[g->service_count - 1] = NULL;
    g->service_count--;
}

/* Unlink + free a group from the global list. Closes ipc_fd. The host
 * pid is NOT killed here -- callers decide whether to SIGTERM first. */
static void group_destroy(svchost_group_t *g)
{
    if (!g) return;
    if (g_svchost_groups == g) {
        g_svchost_groups = g->next;
    } else {
        for (svchost_group_t *prev = g_svchost_groups; prev; prev = prev->next) {
            if (prev->next == g) { prev->next = g->next; break; }
        }
    }
    if (g->ipc_fd >= 0) close(g->ipc_fd);
    for (int i = 0; i < g->service_count; i++) {
        free(g->services[i]);
        g->services[i] = NULL;
    }
    free(g);
}

/* ------------------------------------------------------------------ */
/* LP-JSON wire helpers                                               */
/* ------------------------------------------------------------------ */

static int send_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    size_t left = n;
    while (left > 0) {
        ssize_t w = send(fd, p, left, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += w;
        left -= (size_t)w;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t n, int timeout_ms)
{
    uint8_t *p = buf;
    size_t left = n;
    while (left > 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0) return -1;     /* timeout or error */
        ssize_t r = recv(fd, p, left, 0);
        if (r == 0) return -1;       /* peer closed */
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += r;
        left -= (size_t)r;
    }
    return 0;
}

/* Send a JSON message with a 4-byte big-endian length prefix.
 * msg is NUL-terminated; the NUL is NOT sent. */
static int svchost_send_msg(int fd, const char *msg)
{
    size_t n = strlen(msg);
    if (n > (1u << 20)) return -1;     /* 1 MiB sanity cap */
    uint32_t hdr = htonl((uint32_t)n);
    if (send_all(fd, &hdr, 4) < 0) return -1;
    if (n && send_all(fd, msg, n) < 0) return -1;
    return 0;
}

/* Receive a JSON message into a caller-provided buffer (sz includes
 * room for the trailing NUL). Returns payload length on success, -1 on
 * error. */
static int svchost_recv_msg(int fd, char *out, size_t sz, int timeout_ms)
{
    uint32_t hdr_n;
    if (recv_all(fd, &hdr_n, 4, timeout_ms) < 0) return -1;
    uint32_t n = ntohl(hdr_n);
    if (sz == 0) return -1;
    /* prevent uint32_t wrap: 0xFFFFFFFF+1 == 0 */
    if (n >= sz) return -1;
    if (n > 0 && recv_all(fd, out, n, timeout_ms) < 0) return -1;
    out[n] = '\0';
    return (int)n;
}

/* Send a JSON op and read back an ack. Returns 0 if ack contains
 * "\"ok\":true", -1 otherwise. */
static int svchost_send_and_ack(int fd, const char *msg)
{
    if (svchost_send_msg(fd, msg) < 0) return -1;
    char ack[512];
    int rn = svchost_recv_msg(fd, ack, sizeof(ack), SVCHOST_RECV_TIMEOUT_MS);
    if (rn < 0) return -1;
    /* Tiny grep -- the host ack is always tightly formatted */
    if (strstr(ack, "\"ok\":true") != NULL) return 0;
    fprintf(stderr, "[svchost] negative ack: %s\n", ack);
    return -1;
}

/* ------------------------------------------------------------------ */
/* Host process spawn                                                 */
/* ------------------------------------------------------------------ */

/*
 * Spawn /usr/bin/peloader --svchost --group <name> --ipc-fd 3, with the
 * child end of the socketpair dup'd onto fd 3. SCM keeps sv[0]; child
 * owns sv[1] (which becomes fd 3 inside the child).
 *
 * Mirrors scm_api.c's posix_spawn defaults: SETSID, log fd 100 -> stdout/
 * stderr, /dev/null on stdin. Adding a deferred dup2 of sv[1] -> 3 is the
 * only divergence.
 */
static int spawn_host_process(svchost_group_t *g)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        fprintf(stderr, "[svchost] socketpair: %s\n", strerror(errno));
        return -1;
    }
    /* Make SCM end CLOEXEC + non-blocking for poll cleanliness. */
    int fl = fcntl(sv[0], F_GETFL, 0);
    if (fl >= 0) fcntl(sv[0], F_SETFL, fl | O_NONBLOCK);
    fcntl(sv[0], F_SETFD, FD_CLOEXEC);

    mkdir("/var/log/pe-compat", 0755);
    char logpath[256];
    snprintf(logpath, sizeof(logpath),
             "/var/log/pe-compat/svchost-%s.log", g->name);

    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attrs;
    if (posix_spawn_file_actions_init(&actions) != 0) {
        close(sv[0]); close(sv[1]);
        return -1;
    }
    if (posix_spawnattr_init(&attrs) != 0) {
        posix_spawn_file_actions_destroy(&actions);
        close(sv[0]); close(sv[1]);
        return -1;
    }

#ifdef POSIX_SPAWN_SETSID
    posix_spawnattr_setflags(&attrs, POSIX_SPAWN_SETSID);
#endif

    /* Move the child end of the socketpair to fd 3. The deferred dup2
     * runs inside the child after exec setup; closing sv[0] in the
     * child stops the SCM end from being inherited. */
    posix_spawn_file_actions_addclose(&actions, sv[0]);
    posix_spawn_file_actions_adddup2(&actions, sv[1], 3);
    posix_spawn_file_actions_addclose(&actions, sv[1]);

    /* Standard stdio reroute */
    posix_spawn_file_actions_addclose(&actions, STDIN_FILENO);
    posix_spawn_file_actions_addopen(&actions, STDIN_FILENO,
                                     "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&actions, 100, logpath,
                                     O_WRONLY | O_CREAT | O_APPEND, 0644);
    posix_spawn_file_actions_adddup2(&actions, 100, STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, 100, STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, 100);

    char *argv[] = {
        (char *)"peloader",
        (char *)"--svchost",
        (char *)"--group", g->name,
        (char *)"--ipc-fd", (char *)"3",
        NULL
    };

    pid_t pid = 0;
    int rc = posix_spawn(&pid, "/usr/bin/peloader", &actions, &attrs,
                         argv, environ);

    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attrs);

    if (rc != 0) {
        fprintf(stderr, "[svchost] posix_spawn: %s\n", strerror(rc));
        close(sv[0]); close(sv[1]);
        return -1;
    }

    close(sv[1]);                /* child owns it now */
    g->host_pid = pid;
    g->ipc_fd   = sv[0];

    fprintf(stderr, "[svchost] spawned host group='%s' pid=%d fd=%d\n",
            g->name, pid, sv[0]);
    return 0;
}

static svchost_group_t *get_or_create_group(const char *name)
{
    svchost_group_t *g = find_group(name);
    if (g) return g;

    g = calloc(1, sizeof(*g));
    if (!g) return NULL;
    strncpy(g->name, name, sizeof(g->name) - 1);
    g->host_pid = -1;
    g->ipc_fd = -1;
    g->next = g_svchost_groups;
    g_svchost_groups = g;

    if (spawn_host_process(g) != 0) {
        group_destroy(g);
        return NULL;
    }
    return g;
}

/* ------------------------------------------------------------------ */
/* JSON escaping helpers (we control the inputs but be defensive)     */
/* ------------------------------------------------------------------ */

static void json_escape_into(const char *in, char *out, size_t out_sz)
{
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 2 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '\\' || c == '"') {
            if (o + 2 >= out_sz) break;
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c < 0x20) {
            /* escape control bytes as \uXXXX -- need 6 bytes plus NUL */
            if (o + 6 >= out_sz) break;
            int w = snprintf(out + o, out_sz - o, "\\u%04x", (unsigned)c);
            if (w < 0) break;
            o += (size_t)w;
            continue;
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

int scm_svchost_load_service(service_entry_t *svc)
{
    if (!svc || !svc->service_group[0]) return -1;

    svchost_group_t *g = get_or_create_group(svc->service_group);
    if (!g) {
        fprintf(stderr, "[svchost] no host for group '%s'\n",
                svc->service_group);
        return -1;
    }

    /* Idempotent: if already attached, just resend the load (host may
     * have restarted under us). */
    if (group_has_service(g, svc->name) < 0)
        group_add_service(g, svc->name);

    char esc_name[256], esc_path[4200];
    json_escape_into(svc->name, esc_name, sizeof(esc_name));
    json_escape_into(svc->binary_path, esc_path, sizeof(esc_path));

    char msg[5120];
    int n = snprintf(msg, sizeof(msg),
                     "{\"op\":\"load\",\"service\":\"%s\",\"path\":\"%s\"}",
                     esc_name, esc_path);
    if (n <= 0 || (size_t)n >= sizeof(msg)) return -1;

    if (svchost_send_and_ack(g->ipc_fd, msg) != 0) {
        fprintf(stderr, "[svchost] load failed for '%s' in group '%s'\n",
                svc->name, g->name);
        group_remove_service(g, svc->name);
        /* If we just spawned the host for this single service and it
         * already refuses our load, tear it down to avoid stranding it. */
        if (g->service_count == 0) {
            kill(g->host_pid, SIGTERM);
            /* host_pid stays in g until SIGCHLD reaper notices. */
        }
        return -1;
    }

    /* Account the host pid against the service so the reaper finds us. */
    svc->pid   = g->host_pid;
    svc->state = SERVICE_RUNNING;

    scm_event_emit(SVC_EVT_START, (uint32_t)svc->pid, svc->name, 0, 0);
    fprintf(stderr, "[svchost] loaded '%s' in group '%s' (host_pid=%d)\n",
            svc->name, g->name, g->host_pid);
    return 0;
}

int scm_svchost_control_service(service_entry_t *svc, int control_code)
{
    if (!svc || !svc->service_group[0]) return -1;
    svchost_group_t *g = find_group(svc->service_group);
    if (!g || g->ipc_fd < 0) return -1;

    char esc_name[256];
    json_escape_into(svc->name, esc_name, sizeof(esc_name));

    char msg[512];
    int n = snprintf(msg, sizeof(msg),
                     "{\"op\":\"control\",\"service\":\"%s\",\"code\":%d}",
                     esc_name, control_code);
    if (n <= 0 || (size_t)n >= sizeof(msg)) return -1;

    return svchost_send_and_ack(g->ipc_fd, msg);
}

int scm_svchost_release_service(service_entry_t *svc)
{
    if (!svc || !svc->service_group[0]) return -1;
    svchost_group_t *g = find_group(svc->service_group);
    if (!g) return 0;       /* already gone */

    char esc_name[256];
    json_escape_into(svc->name, esc_name, sizeof(esc_name));

    char msg[512];
    snprintf(msg, sizeof(msg),
             "{\"op\":\"release\",\"service\":\"%s\"}", esc_name);

    /* Best-effort: if the host is dead the ack will fail; that's fine,
     * we still want to drop the local accounting. */
    (void)svchost_send_and_ack(g->ipc_fd, msg);

    group_remove_service(g, svc->name);
    svc->state = SERVICE_STOPPED;
    svc->pid = 0;

    if (g->service_count == 0) {
        fprintf(stderr, "[svchost] group '%s' empty, shutting down host pid=%d\n",
                g->name, g->host_pid);
        const char *bye = "{\"op\":\"shutdown\"}";
        (void)svchost_send_msg(g->ipc_fd, bye);
        /* SIGTERM as belt-and-braces; the reaper will clean up. */
        if (g->host_pid > 0) kill(g->host_pid, SIGTERM);
    }
    return 0;
}

int scm_svchost_handle_host_exit(int pid, int exit_code)
{
    svchost_group_t *g = find_group_by_pid((pid_t)pid);
    if (!g) return 0;       /* not a host */

    fprintf(stderr, "[svchost] host group='%s' pid=%d exited (code=%d)\n",
            g->name, pid, exit_code);

    /* Mark every still-attached service as STOPPED. The SCM's existing
     * crash policy then runs against each: services with RESTART_ALWAYS
     * or RESTART_ON_FAILURE will be re-armed via the health monitor's
     * deferred-restart path. We don't directly call handle_service_crash
     * here to avoid coupling -- scm_daemon.c's reaper already calls it
     * for the matching pid (svc->pid was set to host_pid at load time),
     * but only ONCE. To handle the rest, walk every service tagged with
     * this group and apply the same accounting. */
    int count = scm_db_count();
    for (int i = 0; i < count; i++) {
        service_entry_t *svc = scm_db_get(i);
        if (!svc) continue;
        if (strcmp(svc->service_group, g->name) != 0) continue;
        if (svc->pid != (pid_t)pid) continue;     /* untouched by reaper */
        /* Defer restart accounting to the existing reaper for the match
         * the SIGCHLD loop already processed; here we just mop up the
         * peers that share the host. */
        svc->state = SERVICE_STOPPED;
        svc->pid = 0;
        /* If the user didn't manually stop and policy says restart,
         * prime pending_restart so the health monitor picks it up. */
        if (!svc->manually_stopped &&
            (svc->restart_policy == RESTART_ALWAYS ||
             svc->restart_policy == RESTART_ON_FAILURE)) {
            svc->pending_restart = 1;
            svc->restart_deadline_ns = 0;     /* fire immediately */
            svc->restart_count++;
        }
    }

    group_destroy(g);
    return 1;
}

void scm_svchost_shutdown_all(void)
{
    /* Walk + destroy. We can't snapshot the list because group_destroy
     * mutates g_svchost_groups; just keep popping the head. */
    while (g_svchost_groups) {
        svchost_group_t *g = g_svchost_groups;
        const char *bye = "{\"op\":\"shutdown\"}";
        (void)svchost_send_msg(g->ipc_fd, bye);
        if (g->host_pid > 0) {
            kill(g->host_pid, SIGTERM);
            /* Brief reap window; SIGCHLD reaper will catch any straggler. */
            for (int w = 0; w < 20; w++) {
                if (kill(g->host_pid, 0) != 0) break;
                usleep(100000);
            }
            if (kill(g->host_pid, 0) == 0) kill(g->host_pid, SIGKILL);
            int status;
            waitpid(g->host_pid, &status, WNOHANG);
        }
        group_destroy(g);
    }
}
