/*
 * cortex_cmd.c - PE Loader client for the AI Cortex command channel
 *
 * Implements the request/response protocol over a Unix stream socket
 * at /run/pe-compat/cortex-cmd.sock.  The primary operation is the
 * PE load approval handshake: before loading a PE binary, the loader
 * sends a request and waits (with timeout) for the cortex verdict.
 *
 * Design constraints:
 *   - NEVER block indefinitely.  Every I/O has a timeout.
 *   - If the cortex is not running, fall back to permissive defaults.
 *   - The connection is short-lived: connect, send, recv, close.
 *   - Thread-safe: each call opens its own connection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <poll.h>
#include <time.h>

#include "compat/cortex_cmd.h"

/* No global fd -- each call uses a local fd for thread safety. */

/* ========================================================================
 * Internal helpers
 * ======================================================================== */

/*
 * Set a file descriptor to non-blocking mode.
 * Returns 0 on success, -1 on error.
 */
static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/*
 * Fill a cortex_pe_load_response_t with permissive defaults.
 * Used as fallback when the cortex is unreachable.
 */
static void fill_default_response(cortex_pe_load_response_t *resp)
{
    memset(resp, 0, sizeof(*resp));
    resp->magic        = CORTEX_CMD_MAGIC;
    resp->cmd_type     = CORTEX_CMD_PE_LOAD_RESPONSE;
    resp->verdict      = CORTEX_VERDICT_ALLOW;
    resp->token_budget = 1000;       /* Default token budget */
    resp->capabilities = 0xFFFFFFFF; /* All capabilities */
    resp->priority     = 0;          /* Normal priority */
}

/*
 * Get current monotonic time in milliseconds.
 */
static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*
 * Send exactly `len` bytes on `fd`, respecting a timeout.
 * Decrements remaining timeout each iteration to avoid unbounded waits.
 * Returns 0 on success, -1 on error/timeout.
 */
static int send_full(int fd, const void *buf, size_t len, int timeout_ms)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    int64_t deadline = now_ms() + timeout_ms;

    while (sent < len) {
        int remaining = (int)(deadline - now_ms());
        if (remaining <= 0)
            return -1;  /* Timeout */

        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int pr = poll(&pfd, 1, remaining);
        if (pr <= 0)
            return -1;  /* Timeout or error */

        ssize_t n = send(fd, p + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

/*
 * Receive exactly `len` bytes on `fd`, respecting a timeout.
 * Decrements remaining timeout each iteration to avoid unbounded waits.
 * Returns 0 on success, -1 on error/timeout/short read.
 */
static int recv_full(int fd, void *buf, size_t len, int timeout_ms)
{
    uint8_t *p = (uint8_t *)buf;
    size_t received = 0;
    int64_t deadline = now_ms() + timeout_ms;

    while (received < len) {
        int remaining = (int)(deadline - now_ms());
        if (remaining <= 0)
            return -1;  /* Timeout */

        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, remaining);
        if (pr <= 0)
            return -1;  /* Timeout or error */

        ssize_t n = recv(fd, p + received, len - received, 0);
        if (n <= 0) {
            if (n < 0 && (errno == EINTR || errno == EAGAIN))
                continue;
            return -1;  /* EOF or error */
        }
        received += (size_t)n;
    }
    return 0;
}

/* ========================================================================
 * Public API
 * ======================================================================== */

int cortex_cmd_connect(int timeout_ms)
{
    struct stat st;
    int fd, rc;
    struct sockaddr_un addr;

    /* Fast path: if the socket file does not exist, cortex is not running */
    if (stat(CORTEX_CMD_SOCK, &st) < 0)
        return -1;

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    if (set_nonblock(fd) < 0) {
        close(fd);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CORTEX_CMD_SOCK, sizeof(addr.sun_path) - 1);

    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    if (rc < 0) {
        /* EINPROGRESS: wait for connection to complete */
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0) {
            close(fd);
            return -1;
        }

        /* Check for connection error */
        int err = 0;
        socklen_t errlen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0) {
            close(fd);
            return -1;
        }
    }

    return fd;
}

void cortex_cmd_disconnect_fd(int fd)
{
    if (fd >= 0)
        close(fd);
}

int cortex_request_pe_load(const char *exe_path, uint32_t subsystem,
                            uint32_t import_count,
                            cortex_pe_load_response_t *response)
{
    int fd, rc;

    if (!exe_path || !response)
        return -1;

    /* Always fill defaults first -- if anything fails, caller gets sane values */
    fill_default_response(response);

    /* Connect with 500ms timeout (returns a local fd, no global state) */
    fd = cortex_cmd_connect(500);
    if (fd < 0) {
        /* Cortex not running -- graceful degradation */
        return -1;
    }

    /* Build the request */
    cortex_pe_load_request_t req;
    memset(&req, 0, sizeof(req));
    req.magic        = CORTEX_CMD_MAGIC;
    req.cmd_type     = CORTEX_CMD_PE_LOAD_REQUEST;
    req.pid          = (uint32_t)getpid();
    req.uid          = (uint32_t)getuid();
    strncpy(req.exe_path, exe_path, sizeof(req.exe_path) - 1);
    req.subsystem    = subsystem;
    req.import_count = import_count;

    /* Send request with 1-second timeout */
    rc = send_full(fd, &req, sizeof(req), 1000);
    if (rc < 0) {
        cortex_cmd_disconnect_fd(fd);
        return -1;
    }

    /* Read response with 2-second timeout */
    cortex_pe_load_response_t resp;
    rc = recv_full(fd, &resp, sizeof(resp), 2000);
    cortex_cmd_disconnect_fd(fd);

    if (rc < 0)
        return -1;

    /* Validate magic and command type */
    if (resp.magic != CORTEX_CMD_MAGIC ||
        resp.cmd_type != CORTEX_CMD_PE_LOAD_RESPONSE) {
        return -1;
    }

    /* Force null-terminate deny_reason -- wire data may not be terminated */
    resp.deny_reason[sizeof(resp.deny_reason) - 1] = '\0';

    /* Success -- copy valid response to caller */
    memcpy(response, &resp, sizeof(resp));
    return 0;
}
