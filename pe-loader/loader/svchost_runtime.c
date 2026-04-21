/*
 * svchost_runtime.c - peloader --svchost host process
 *
 * Activated by main.c when peloader is invoked as
 *     peloader --svchost --group <name> --ipc-fd <fd>
 *
 * Reads length-prefixed JSON commands from the SCM control socket
 * (inherited as <fd>) and starts/stops/queries the PE services that
 * belong to this group. Each loaded service runs as a CHILD peloader
 * process spawned from this host -- a pragmatic compromise that lets
 * us preserve the existing single-PE-per-process loader code path
 * untouched while still presenting the Windows-svchost contract to
 * the SCM (one persistent host PID per group, control-channel IPC for
 * all start/stop/control routing).
 *
 * Wire protocol (matches services/scm/scm_svchost.c):
 *   uint32_t big-endian length | <length> bytes JSON
 *
 * Inbound ops:
 *   {"op":"load",   "service":"<name>", "path":"<exe-path>"}
 *   {"op":"control","service":"<name>", "code":<int>}      // SERVICE_CONTROL_*
 *   {"op":"release","service":"<name>"}
 *   {"op":"shutdown"}
 *
 * Outbound:
 *   {"op":"ack","ok":true}                                  // success
 *   {"op":"ack","ok":false,"err":"<reason>"}                // failure
 *   {"op":"status","service":"<name>","state":"<str>","pid":<int>}  // async
 *
 * The host stays alive until either {"op":"shutdown"} arrives, the
 * SCM closes the socket, or the last hosted service is released.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <poll.h>

extern char **environ;

#define SVCH_MAX_SERVICES   32
#define SVCH_MAX_NAME       128
#define SVCH_MAX_PATH       4096
#define SVCH_MSG_MAX        65536

typedef struct {
    char  name[SVCH_MAX_NAME];
    char  path[SVCH_MAX_PATH];
    pid_t pid;          /* child peloader serving this service */
    int   in_use;
} svch_entry_t;

static svch_entry_t g_svc[SVCH_MAX_SERVICES];
static int          g_svc_count = 0;

static svch_entry_t *svch_find(const char *name)
{
    for (int i = 0; i < SVCH_MAX_SERVICES; i++) {
        if (g_svc[i].in_use && strcmp(g_svc[i].name, name) == 0)
            return &g_svc[i];
    }
    return NULL;
}

static svch_entry_t *svch_alloc(const char *name)
{
    svch_entry_t *e = svch_find(name);
    if (e) return e;
    for (int i = 0; i < SVCH_MAX_SERVICES; i++) {
        if (!g_svc[i].in_use) {
            memset(&g_svc[i], 0, sizeof(g_svc[i]));
            strncpy(g_svc[i].name, name, sizeof(g_svc[i].name) - 1);
            g_svc[i].in_use = 1;
            g_svc_count++;
            return &g_svc[i];
        }
    }
    return NULL;
}

static void svch_free(svch_entry_t *e)
{
    if (!e || !e->in_use) return;
    e->in_use = 0;
    g_svc_count--;
}

/* ------------------------------------------------------------------ */
/* IO                                                                 */
/* ------------------------------------------------------------------ */

static int io_send_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    size_t left = n;
    while (left > 0) {
        ssize_t w = send(fd, p, left, MSG_NOSIGNAL);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        p += w; left -= (size_t)w;
    }
    return 0;
}

static int io_recv_all(int fd, void *buf, size_t n, int timeout_ms)
{
    uint8_t *p = buf;
    size_t left = n;
    while (left > 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0) return -1;
        ssize_t r = recv(fd, p, left, 0);
        if (r == 0) return -1;
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        p += r; left -= (size_t)r;
    }
    return 0;
}

static int svch_send_msg(int fd, const char *msg)
{
    size_t n = strlen(msg);
    if (n > SVCH_MSG_MAX) return -1;
    uint32_t hdr = htonl((uint32_t)n);
    if (io_send_all(fd, &hdr, 4) < 0) return -1;
    if (n && io_send_all(fd, msg, n) < 0) return -1;
    return 0;
}

static int svch_send_ack(int fd, int ok, const char *err)
{
    char buf[256];
    if (ok) {
        snprintf(buf, sizeof(buf), "{\"op\":\"ack\",\"ok\":true}");
    } else {
        char esc[160];
        size_t o = 0;
        for (size_t i = 0; err && err[i] && o + 2 < sizeof(esc); i++) {
            if (err[i] == '"' || err[i] == '\\') esc[o++] = '\\';
            esc[o++] = err[i];
        }
        esc[o] = '\0';
        snprintf(buf, sizeof(buf),
                 "{\"op\":\"ack\",\"ok\":false,\"err\":\"%s\"}", esc);
    }
    return svch_send_msg(fd, buf);
}

/* Receive a single LP-JSON message into out (NUL-terminated). Returns
 * payload length or -1 on error/EOF. -2 means timeout (no data yet). */
static int svch_recv_msg(int fd, char *out, size_t sz, int timeout_ms)
{
    uint32_t hdr_n;
    /* First do a non-blocking poll so we can interleave with reaping. */
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr == 0) return -2;
    if (pr < 0) return -1;
    if (io_recv_all(fd, &hdr_n, 4, 1000) < 0) return -1;
    uint32_t n = ntohl(hdr_n);
    if (sz == 0) return -1;
    /* prevent uint32_t wrap: 0xFFFFFFFF+1 == 0 */
    if (n >= sz) return -1;
    if (n > 0 && io_recv_all(fd, out, n, 5000) < 0) return -1;
    out[n] = '\0';
    return (int)n;
}

/* ------------------------------------------------------------------ */
/* Tiny JSON field extractor                                          */
/* ------------------------------------------------------------------ */

/*
 * Pull a string value out of {"key":"value", ...}. Naive but adequate
 * for the strict format we control on the wire. Writes up to out_sz-1
 * bytes plus NUL. Returns 0 on success, -1 if key not found.
 */
static int json_get_str(const char *json, const char *key,
                        char *out, size_t out_sz)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p && (*p == ' ' || *p == ':')) p++;
    if (*p != '"') return -1;
    p++;
    size_t o = 0;
    while (*p && *p != '"' && o + 1 < out_sz) {
        if (*p == '\\' && p[1]) { out[o++] = p[1]; p += 2; continue; }
        out[o++] = *p++;
    }
    out[o] = '\0';
    return 0;
}

static int json_get_int(const char *json, const char *key, int *out)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p && (*p == ' ' || *p == ':')) p++;
    char *end = NULL;
    long v = strtol(p, &end, 10);
    if (end == p) return -1;
    *out = (int)v;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Op handlers                                                        */
/* ------------------------------------------------------------------ */

/*
 * Spawn a child peloader for the given service .exe. We deliberately
 * fork+exec a fresh peloader (without --svchost) instead of trying to
 * load the PE inline -- that lets us reuse the existing single-PE-per-
 * process loader code path verbatim while still giving SCM a single
 * persistent host PID per group. A future iteration can move toward
 * true in-process loading; the IPC contract is unchanged.
 */
static int svch_spawn_child(svch_entry_t *e)
{
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attrs;
    if (posix_spawn_file_actions_init(&actions) != 0) return -1;
    if (posix_spawnattr_init(&attrs) != 0) {
        posix_spawn_file_actions_destroy(&actions);
        return -1;
    }
    /* New session so a SIGHUP to the host doesn't propagate to the
     * service children. */
#ifdef POSIX_SPAWN_SETSID
    posix_spawnattr_setflags(&attrs, POSIX_SPAWN_SETSID);
#endif
    /* Children inherit our stdio (which is the per-host log file); they
     * do not need our IPC socket. */

    char *argv[] = {
        (char *)"peloader",
        e->path,
        NULL
    };
    pid_t pid = 0;
    int rc = posix_spawn(&pid, "/usr/bin/peloader", &actions, &attrs,
                         argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attrs);
    if (rc != 0) {
        fprintf(stderr, "[svchost-host] spawn '%s' failed: %s\n",
                e->name, strerror(rc));
        return -1;
    }
    e->pid = pid;
    fprintf(stderr, "[svchost-host] loaded '%s' pid=%d path=%s\n",
            e->name, pid, e->path);
    return 0;
}

static int handle_load(int fd, const char *json)
{
    char name[SVCH_MAX_NAME], path[SVCH_MAX_PATH];
    if (json_get_str(json, "service", name, sizeof(name)) != 0 ||
        json_get_str(json, "path", path, sizeof(path)) != 0) {
        return svch_send_ack(fd, 0, "missing service/path");
    }
    svch_entry_t *e = svch_alloc(name);
    if (!e) return svch_send_ack(fd, 0, "host full");
    if (e->pid > 0) {
        /* Already running (idempotent re-load) -- ack OK */
        return svch_send_ack(fd, 1, NULL);
    }
    strncpy(e->path, path, sizeof(e->path) - 1);
    if (svch_spawn_child(e) != 0) {
        svch_free(e);
        return svch_send_ack(fd, 0, "spawn failed");
    }
    return svch_send_ack(fd, 1, NULL);
}

static int handle_control(int fd, const char *json)
{
    char name[SVCH_MAX_NAME];
    int code = 0;
    if (json_get_str(json, "service", name, sizeof(name)) != 0 ||
        json_get_int(json, "code", &code) != 0) {
        return svch_send_ack(fd, 0, "missing service/code");
    }
    svch_entry_t *e = svch_find(name);
    if (!e || e->pid <= 0) return svch_send_ack(fd, 0, "no such service");

    /* SERVICE_CONTROL_STOP=1, SERVICE_CONTROL_PAUSE=2, SERVICE_CONTROL_CONTINUE=3,
     * SERVICE_CONTROL_INTERROGATE=4, SERVICE_CONTROL_SHUTDOWN=5.
     * We only signal STOP/SHUTDOWN explicitly; the rest are silently OK'd. */
    if (code == 1 /* STOP */ || code == 5 /* SHUTDOWN */) {
        if (kill(e->pid, SIGTERM) != 0 && errno != ESRCH) {
            return svch_send_ack(fd, 0, strerror(errno));
        }
    }
    return svch_send_ack(fd, 1, NULL);
}

static int handle_release(int fd, const char *json)
{
    char name[SVCH_MAX_NAME];
    if (json_get_str(json, "service", name, sizeof(name)) != 0)
        return svch_send_ack(fd, 0, "missing service");
    svch_entry_t *e = svch_find(name);
    if (!e) return svch_send_ack(fd, 1, NULL);   /* already gone */
    if (e->pid > 0) {
        /* Best-effort kill if still alive */
        if (kill(e->pid, 0) == 0) {
            kill(e->pid, SIGTERM);
            for (int i = 0; i < 20; i++) {
                if (kill(e->pid, 0) != 0) break;
                usleep(50000);
            }
            if (kill(e->pid, 0) == 0) kill(e->pid, SIGKILL);
        }
        int status;
        waitpid(e->pid, &status, WNOHANG);
    }
    svch_free(e);
    return svch_send_ack(fd, 1, NULL);
}

/* Drain any reaped children and emit async status updates. */
static void reap_children(int fd)
{
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        for (int i = 0; i < SVCH_MAX_SERVICES; i++) {
            if (!g_svc[i].in_use || g_svc[i].pid != pid) continue;
            char esc[SVCH_MAX_NAME * 2];
            size_t o = 0;
            for (size_t k = 0; g_svc[i].name[k] && o + 2 < sizeof(esc); k++) {
                if (g_svc[i].name[k] == '"' || g_svc[i].name[k] == '\\')
                    esc[o++] = '\\';
                esc[o++] = g_svc[i].name[k];
            }
            esc[o] = '\0';
            char buf[512];
            snprintf(buf, sizeof(buf),
                     "{\"op\":\"status\",\"service\":\"%s\","
                     "\"state\":\"STOPPED\",\"pid\":%d,\"exit\":%d}",
                     esc, (int)pid, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            (void)svch_send_msg(fd, buf);
            g_svc[i].pid = 0;
            break;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Entry point                                                        */
/* ------------------------------------------------------------------ */

/*
 * Run the svchost host loop. Returns the exit code peloader should
 * propagate. Never returns until the SCM closes the socket, sends
 * shutdown, or our last child exits + the SCM declines to feed us
 * a new one.
 */
int pe_svchost_run(const char *group, int ipc_fd)
{
    fprintf(stderr, "[svchost-host] start group='%s' ipc_fd=%d pid=%d\n",
            group ? group : "(null)", ipc_fd, getpid());

    if (ipc_fd < 0) {
        fprintf(stderr, "[svchost-host] invalid ipc_fd\n");
        return 2;
    }

    /* Reap children via SIGCHLD wakeups, but we never block longer
     * than 500ms on poll() so we always get a chance to run reapers. */
    signal(SIGPIPE, SIG_IGN);

    char msgbuf[SVCH_MSG_MAX];
    int shutdown_requested = 0;

    while (!shutdown_requested) {
        int rn = svch_recv_msg(ipc_fd, msgbuf, sizeof(msgbuf), 500);
        if (rn == -1) {
            /* SCM hung up -- shut down */
            fprintf(stderr, "[svchost-host] SCM closed socket, exiting\n");
            break;
        }
        if (rn == -2) {
            /* No message yet; just reap and loop */
            reap_children(ipc_fd);
            continue;
        }

        char op[32] = {0};
        if (json_get_str(msgbuf, "op", op, sizeof(op)) != 0) {
            (void)svch_send_ack(ipc_fd, 0, "missing op");
            continue;
        }

        if (strcmp(op, "load") == 0) {
            handle_load(ipc_fd, msgbuf);
        } else if (strcmp(op, "control") == 0) {
            handle_control(ipc_fd, msgbuf);
        } else if (strcmp(op, "release") == 0) {
            handle_release(ipc_fd, msgbuf);
            /* Auto-exit when the last service is released? No -- the
             * SCM explicitly sends shutdown when it wants us gone. */
        } else if (strcmp(op, "shutdown") == 0) {
            (void)svch_send_ack(ipc_fd, 1, NULL);
            shutdown_requested = 1;
        } else {
            (void)svch_send_ack(ipc_fd, 0, "unknown op");
        }
        reap_children(ipc_fd);
    }

    /* Final cleanup: SIGTERM + reap every still-running child */
    for (int i = 0; i < SVCH_MAX_SERVICES; i++) {
        if (g_svc[i].in_use && g_svc[i].pid > 0) {
            kill(g_svc[i].pid, SIGTERM);
        }
    }
    for (int w = 0; w < 30; w++) {
        int alive = 0;
        for (int i = 0; i < SVCH_MAX_SERVICES; i++) {
            if (g_svc[i].in_use && g_svc[i].pid > 0 &&
                kill(g_svc[i].pid, 0) == 0) {
                alive = 1;
                break;
            }
        }
        if (!alive) break;
        usleep(100000);
    }
    /* Force kill stragglers */
    for (int i = 0; i < SVCH_MAX_SERVICES; i++) {
        if (g_svc[i].in_use && g_svc[i].pid > 0 &&
            kill(g_svc[i].pid, 0) == 0) {
            kill(g_svc[i].pid, SIGKILL);
        }
    }
    /* Final reap */
    int st;
    while (waitpid(-1, &st, WNOHANG) > 0) { /* drain */ }

    close(ipc_fd);
    fprintf(stderr, "[svchost-host] exit group='%s'\n", group ? group : "");
    return 0;
}
