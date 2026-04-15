/*
 * objectd_main.c - Object broker daemon (pe-objectd) entry point
 *
 * Provides cross-process Windows shared state for PE processes:
 *   - Named synchronization objects (mutex, event, semaphore)
 *   - Registry hosting (file-backed tree)
 *   - Device namespace (\Device\*, \DosDevices\*)
 *
 * Architecture:
 *   - Unix domain socket at /run/pe-compat/objects.sock
 *   - epoll-based multiplexed client handling (no thread per client)
 *   - Request/response protocol (objectd_protocol.h)
 *   - Named objects backed by POSIX shared memory + futex
 *
 * Logging: stderr (systemd captures this via journal)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "objectd_protocol.h"
#include "objectd_objects.h"
#include "objectd_namespace.h"
#include "objectd_shm.h"

/* Forward declarations for registry module */
extern void objectd_registry_init(void);
extern int objectd_registry_handle(uint8_t req_type, const void *payload,
                                   uint16_t payload_len, uint32_t pid,
                                   uint64_t sequence,
                                   void *resp_buf, size_t resp_buf_size,
                                   size_t *resp_len);
/* From pe-loader/registry/registry.c — used for disconnect cleanup of
 * registry HKEYs that clients opened but never closed.  Takes HKEY
 * (typedef void*); int32_t return is treated as ignored.
 * The signature is declared loosely to avoid pulling in all of win32. */
extern int32_t registry_close_key(void *hKey);

/* --------------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------------- */

#define MAX_CLIENTS        256
#define MAX_EVENTS         64
#define RECV_BUF_SIZE      16384
#define RESP_BUF_SIZE      16384
#define MAX_CLIENT_HANDLES 512   /* Max open object handles per client */
#define MAX_CLIENT_HKEYS   256   /* Max open registry HKEYs per client */

/* --------------------------------------------------------------------------
 * Global state
 * -------------------------------------------------------------------------- */

static volatile sig_atomic_t g_running = 1;
static int g_listen_fd = -1;
static int g_epoll_fd  = -1;

/* Per-client state for partial reads and handle tracking */
typedef struct {
    int      fd;
    int      active;
    pid_t    verified_pid;  /* Kernel-verified PID via SCM_CREDENTIALS (0 = unknown) */
    uint8_t  recv_buf[RECV_BUF_SIZE];
    size_t   recv_pos;   /* Bytes accumulated in recv_buf */

    /*
     * Per-client handle tracking for leak cleanup on disconnect.
     * Each entry is a broker-side object index (handle) that this client
     * holds a reference to.  Duplicate entries are allowed -- a client
     * that opens the same object twice gets two entries, matching the
     * two ref_count increments.
     */
    uint32_t obj_handles[MAX_CLIENT_HANDLES];
    int      obj_handle_count;

    /*
     * Per-client registry HKEY tracking for leak cleanup on disconnect.
     * Each entry is a non-predefined HKEY value returned by a prior
     * OBJ_REQ_REG_OPEN or OBJ_REQ_REG_CREATE.  Closed via
     * registry_close_key() on disconnect.  Predefined HKEYs (>= 0x80000000
     * special values) must never be tracked or auto-closed.
     */
    uint64_t hkey_handles[MAX_CLIENT_HKEYS];
    int      hkey_handle_count;
} client_state_t;

static client_state_t g_clients[MAX_CLIENTS];

/*
 * fd -> client slot direct index.  Eliminates the linear scan of
 * find_client_by_fd() on every epoll event -- on a busy broker with
 * hundreds of open games, the scan dominated event dispatch.
 *
 * Bounded by the system RLIMIT_NOFILE; we cap at 8192 which covers all
 * practical fd numbers for a broker process that has at most MAX_CLIENTS
 * (256) connections plus ~20 internal fds.  Out-of-range fds fall back
 * to the linear scan.
 */
#define FD_INDEX_SIZE 8192
static int g_fd_to_slot[FD_INDEX_SIZE];  /* -1 = not tracked */

static void fd_index_init(void)
{
    for (int i = 0; i < FD_INDEX_SIZE; i++)
        g_fd_to_slot[i] = -1;
}

static inline void fd_index_set(int fd, int slot)
{
    if (fd >= 0 && fd < FD_INDEX_SIZE)
        g_fd_to_slot[fd] = slot;
}

static inline void fd_index_clear(int fd)
{
    if (fd >= 0 && fd < FD_INDEX_SIZE)
        g_fd_to_slot[fd] = -1;
}

/* --------------------------------------------------------------------------
 * Signal handlers
 * -------------------------------------------------------------------------- */

static void sig_handler(int sig)
{
    if (sig == SIGTERM || sig == SIGINT)
        g_running = 0;
}

static void sigchld_handler(int sig)
{
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
}

/* --------------------------------------------------------------------------
 * Socket helpers
 * -------------------------------------------------------------------------- */

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/*
 * Send a response, optionally passing a file descriptor via SCM_RIGHTS.
 * If shm_fd >= 0, it is sent as ancillary data.
 */
static int send_response(int client_fd, const void *resp_buf, size_t resp_len,
                         int shm_fd)
{
    struct iovec iov;
    iov.iov_base = (void *)resp_buf;
    iov.iov_len  = resp_len;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov    = &iov;
    msg.msg_iovlen = 1;

    /* Ancillary data for SCM_RIGHTS fd passing */
    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    if (shm_fd >= 0) {
        msg.msg_control    = cmsg_buf;
        msg.msg_controllen = sizeof(cmsg_buf);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type  = SCM_RIGHTS;
        cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &shm_fd, sizeof(int));
    }

    size_t total_len = resp_len;
    size_t total_sent = 0;

    while (total_sent < total_len) {
        ssize_t sent = sendmsg(client_fd, &msg, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR)
                continue;
            if (errno != EPIPE && errno != ECONNRESET)
                fprintf(stderr, "[objectd] sendmsg failed: %s\n", strerror(errno));
            return -1;
        }

        total_sent += (size_t)sent;
        if (total_sent >= total_len)
            break;

        /* Advance iov past already-sent bytes for short writes */
        iov.iov_base = (char *)iov.iov_base + sent;
        iov.iov_len -= (size_t)sent;

        /* Only pass ancillary fd on the first sendmsg; clear for retries */
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * Payload sanitization
 * -------------------------------------------------------------------------- */

static void ensure_null_term(char *buf, size_t size)
{
    buf[size - 1] = '\0';
}

/* --------------------------------------------------------------------------
 * Per-client handle tracking helpers
 * -------------------------------------------------------------------------- */

/*
 * Record that this client now holds a reference to the given object handle.
 * Called after a successful create or open.
 */
static void client_track_handle(client_state_t *cl, uint32_t handle)
{
    if (!cl)
        return;
    if (cl->obj_handle_count >= MAX_CLIENT_HANDLES) {
        fprintf(stderr, "[objectd] Client fd=%d exceeded max handle tracking "
                "(%d), handle %u will NOT be auto-released on disconnect\n",
                cl->fd, MAX_CLIENT_HANDLES, handle);
        return;
    }
    cl->obj_handles[cl->obj_handle_count++] = handle;
}

/*
 * Remove one entry for the given handle from this client's tracking list.
 * Called after a successful close.  Only removes the first match, so if
 * the client opened the same object twice, closing once still leaves one
 * tracked reference.
 */
static void client_untrack_handle(client_state_t *cl, uint32_t handle)
{
    if (!cl)
        return;
    for (int i = 0; i < cl->obj_handle_count; i++) {
        if (cl->obj_handles[i] == handle) {
            /* Swap with last element and shrink */
            cl->obj_handles[i] = cl->obj_handles[cl->obj_handle_count - 1];
            cl->obj_handle_count--;
            return;
        }
    }
    /* Not found -- client closed a handle it didn't open through us, or
     * the tracking list overflowed earlier.  Not fatal. */
}

/*
 * Predefined HKEYs are well-known values that are shared by the whole
 * process and must never be closed via registry_close_key().  They sit
 * in the top of the 32-bit address space (e.g., 0x80000000+).
 */
static int hkey_is_predefined(uint64_t hk)
{
    return (hk >= 0x80000000ULL && hk < 0x80000100ULL) || hk == 0;
}

static void client_track_hkey(client_state_t *cl, uint64_t hkey)
{
    if (!cl || hkey_is_predefined(hkey))
        return;
    if (cl->hkey_handle_count >= MAX_CLIENT_HKEYS) {
        fprintf(stderr, "[objectd] Client fd=%d exceeded max hkey tracking "
                "(%d), HKEY 0x%llx will NOT be auto-closed on disconnect\n",
                cl->fd, MAX_CLIENT_HKEYS, (unsigned long long)hkey);
        return;
    }
    cl->hkey_handles[cl->hkey_handle_count++] = hkey;
}

static void client_untrack_hkey(client_state_t *cl, uint64_t hkey)
{
    if (!cl)
        return;
    for (int i = 0; i < cl->hkey_handle_count; i++) {
        if (cl->hkey_handles[i] == hkey) {
            cl->hkey_handles[i] = cl->hkey_handles[cl->hkey_handle_count - 1];
            cl->hkey_handle_count--;
            return;
        }
    }
}

/* --------------------------------------------------------------------------
 * Request dispatch
 * -------------------------------------------------------------------------- */

static void handle_object_request(client_state_t *cl,
                                  const objectd_request_t *req,
                                  const void *payload, uint16_t payload_len)
{
    uint8_t resp_buf[RESP_BUF_SIZE];
    objectd_response_t *resp = (objectd_response_t *)resp_buf;
    size_t resp_len = sizeof(objectd_response_t);
    int shm_fd = -1;

    /* Initialize response */
    memset(resp, 0, sizeof(*resp));
    resp->magic    = OBJECTD_MAGIC;
    resp->version  = OBJECTD_VERSION;
    resp->sequence = req->sequence;
    resp->shm_fd   = -1;
    resp->status   = OBJ_STATUS_OK;

    switch (req->request_type) {

    /* --- Named object operations --- */
    case OBJ_REQ_CREATE_MUTEX:
    case OBJ_REQ_CREATE_EVENT:
    case OBJ_REQ_CREATE_SEMAPHORE: {
        if (payload_len < sizeof(obj_create_payload_t)) {
            resp->status = OBJ_STATUS_INVALID;
            break;
        }
        obj_create_payload_t *p = (obj_create_payload_t *)payload;
        ensure_null_term(p->name, sizeof(p->name));
        uint8_t obj_type;
        switch (req->request_type) {
        case OBJ_REQ_CREATE_MUTEX:     obj_type = OBJ_TYPE_MUTEX;     break;
        case OBJ_REQ_CREATE_EVENT:     obj_type = OBJ_TYPE_EVENT;     break;
        case OBJ_REQ_CREATE_SEMAPHORE: obj_type = OBJ_TYPE_SEMAPHORE; break;
        default: obj_type = 0; break;
        }

        uint8_t status;
        int idx = objects_create(p->name, obj_type, p->initial_state,
                                 p->manual_reset, p->max_count,
                                 req->pid, &status, &shm_fd);
        resp->status = status;
        if (idx >= 0) {
            resp->handle = (uint32_t)idx;
            client_track_handle(cl, (uint32_t)idx);
        }
        break;
    }

    case OBJ_REQ_OPEN: {
        if (payload_len < sizeof(obj_open_payload_t)) {
            resp->status = OBJ_STATUS_INVALID;
            break;
        }
        obj_open_payload_t *p = (obj_open_payload_t *)payload;
        ensure_null_term(p->name, sizeof(p->name));
        uint8_t status;
        int idx = objects_open(p->name, p->type, &status, &shm_fd);
        resp->status = status;
        if (idx >= 0) {
            resp->handle = (uint32_t)idx;
            client_track_handle(cl, (uint32_t)idx);
        }
        break;
    }

    case OBJ_REQ_CLOSE: {
        if (payload_len < sizeof(obj_close_payload_t)) {
            resp->status = OBJ_STATUS_INVALID;
            break;
        }
        const obj_close_payload_t *p = (const obj_close_payload_t *)payload;

        /* Verify the client actually holds this handle before closing.
         * Without this check, any client could send CLOSE for any handle
         * and drop refs on objects it does not own, causing premature
         * destruction and potential use-after-free in peer clients. */
        int owns = 0;
        for (int ci = 0; ci < cl->obj_handle_count; ci++) {
            if (cl->obj_handles[ci] == p->handle) { owns = 1; break; }
        }
        if (!owns) {
            fprintf(stderr, "[objectd] Client fd=%d pid=%d attempted to close "
                    "unowned handle %u; rejecting\n",
                    cl->fd, (int)cl->verified_pid, p->handle);
            resp->status = OBJ_STATUS_INVALID;
            break;
        }

        uint8_t status;
        objects_close(p->handle, &status);
        resp->status = status;
        if (status == OBJ_STATUS_OK)
            client_untrack_handle(cl, p->handle);
        break;
    }

    /* --- Registry operations --- */
    case OBJ_REQ_REG_OPEN:
    case OBJ_REQ_REG_CREATE: {
        if (payload_len >= sizeof(reg_open_payload_t)) {
            reg_open_payload_t *rp = (reg_open_payload_t *)payload;
            ensure_null_term(rp->subkey, sizeof(rp->subkey));
        }
        objectd_registry_handle(req->request_type, payload, payload_len,
                                req->pid, req->sequence,
                                resp_buf, sizeof(resp_buf), &resp_len);
        /* Track the returned HKEY so it gets closed on client disconnect.
         * The 64-bit value lives at the start of the response payload. */
        objectd_response_t *r = (objectd_response_t *)resp_buf;
        if (r->status == OBJ_STATUS_OK &&
            r->payload_len >= sizeof(uint64_t) &&
            resp_len >= sizeof(objectd_response_t) + sizeof(uint64_t)) {
            uint64_t hk_val;
            memcpy(&hk_val, (uint8_t *)resp_buf + sizeof(objectd_response_t),
                   sizeof(hk_val));
            client_track_hkey(cl, hk_val);
        }
        send_response(cl->fd, resp_buf, resp_len, -1);
        return;
    }
    case OBJ_REQ_REG_SET_VALUE: {
        if (payload_len >= sizeof(reg_set_value_payload_t)) {
            reg_set_value_payload_t *rp = (reg_set_value_payload_t *)payload;
            ensure_null_term(rp->name, sizeof(rp->name));
        }
        objectd_registry_handle(req->request_type, payload, payload_len,
                                req->pid, req->sequence,
                                resp_buf, sizeof(resp_buf), &resp_len);
        send_response(cl->fd, resp_buf, resp_len, -1);
        return;
    }
    case OBJ_REQ_REG_GET_VALUE: {
        if (payload_len >= sizeof(reg_get_value_payload_t)) {
            reg_get_value_payload_t *rp = (reg_get_value_payload_t *)payload;
            ensure_null_term(rp->name, sizeof(rp->name));
            ensure_null_term(rp->subkey, sizeof(rp->subkey));
        }
        objectd_registry_handle(req->request_type, payload, payload_len,
                                req->pid, req->sequence,
                                resp_buf, sizeof(resp_buf), &resp_len);
        send_response(cl->fd, resp_buf, resp_len, -1);
        return;
    }
    case OBJ_REQ_REG_DELETE_KEY:
    case OBJ_REQ_REG_DELETE_VALUE: {
        if (payload_len >= sizeof(reg_delete_payload_t)) {
            reg_delete_payload_t *rp = (reg_delete_payload_t *)payload;
            ensure_null_term(rp->name, sizeof(rp->name));
        }
        objectd_registry_handle(req->request_type, payload, payload_len,
                                req->pid, req->sequence,
                                resp_buf, sizeof(resp_buf), &resp_len);
        send_response(cl->fd, resp_buf, resp_len, -1);
        return;
    }
    case OBJ_REQ_REG_CLOSE:
    case OBJ_REQ_REG_ENUM_KEY:
    case OBJ_REQ_REG_ENUM_VALUE: {
        /* These payloads contain no string fields needing null-termination */
        objectd_registry_handle(req->request_type, payload, payload_len,
                                req->pid, req->sequence,
                                resp_buf, sizeof(resp_buf), &resp_len);
        /* Untrack HKEY on successful REG_CLOSE so the disconnect sweep
         * doesn't try to close it a second time. */
        if (req->request_type == OBJ_REQ_REG_CLOSE &&
            payload_len >= sizeof(uint64_t)) {
            objectd_response_t *r = (objectd_response_t *)resp_buf;
            if (r->status == OBJ_STATUS_OK) {
                uint64_t hk_val;
                memcpy(&hk_val, payload, sizeof(hk_val));
                client_untrack_hkey(cl, hk_val);
            }
        }
        send_response(cl->fd, resp_buf, resp_len, -1);
        return;
    }

    /* --- Namespace operations --- */
    case OBJ_REQ_NS_RESOLVE:
    case OBJ_REQ_NS_DELETE_LINK:
    case OBJ_REQ_NS_ENUMERATE: {
        if (payload_len >= sizeof(ns_resolve_payload_t)) {
            ns_resolve_payload_t *np = (ns_resolve_payload_t *)payload;
            ensure_null_term(np->path, sizeof(np->path));
        }
        objectd_namespace_handle(req->request_type, payload, payload_len,
                                 req->sequence,
                                 resp_buf, sizeof(resp_buf), &resp_len);
        send_response(cl->fd, resp_buf, resp_len, -1);
        return;
    }
    case OBJ_REQ_NS_CREATE_LINK: {
        if (payload_len >= sizeof(ns_link_payload_t)) {
            ns_link_payload_t *np = (ns_link_payload_t *)payload;
            ensure_null_term(np->link_name, sizeof(np->link_name));
            ensure_null_term(np->target, sizeof(np->target));
        }
        objectd_namespace_handle(req->request_type, payload, payload_len,
                                 req->sequence,
                                 resp_buf, sizeof(resp_buf), &resp_len);
        send_response(cl->fd, resp_buf, resp_len, -1);
        return;
    }

    default:
        fprintf(stderr, "[objectd] Unknown request type 0x%02x from pid %u "
                "(verified)\n", req->request_type, req->pid);
        resp->status = OBJ_STATUS_INVALID;
        break;
    }

    /*
     * Send response (possibly with shm_fd via SCM_RIGHTS).
     * The shm_fd here is the broker's own fd for the shared memory region;
     * it remains open in the object table regardless of whether the send
     * succeeds.  SCM_RIGHTS causes the kernel to dup the fd into the
     * client's fd table, so no broker-side fd is leaked on send failure.
     */
    resp->shm_fd = (shm_fd >= 0) ? 0 : -1;  /* Client sees 0 if fd is being passed */
    send_response(cl->fd, resp_buf, resp_len, shm_fd);
}

/* --------------------------------------------------------------------------
 * Client I/O
 * -------------------------------------------------------------------------- */

static client_state_t *find_client_slot(void)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_clients[i].active)
            return &g_clients[i];
    }
    return NULL;
}

static client_state_t *find_client_by_fd(int fd)
{
    /* O(1) fast path via fd index */
    if (fd >= 0 && fd < FD_INDEX_SIZE) {
        int slot = g_fd_to_slot[fd];
        if (slot >= 0 && slot < MAX_CLIENTS &&
            g_clients[slot].active && g_clients[slot].fd == fd)
            return &g_clients[slot];
    }
    /* Fallback linear scan for fds outside the index range */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].active && g_clients[i].fd == fd)
            return &g_clients[i];
    }
    return NULL;
}

static void client_disconnect(client_state_t *cl)
{
    if (!cl || !cl->active)
        return;

    /*
     * Release all object handles this client still holds.  This prevents
     * named objects from leaking when a PE process crashes or exits
     * without properly closing its handles.
     */
    if (cl->obj_handle_count > 0) {
        fprintf(stderr, "[objectd] Client fd=%d pid=%d disconnecting with "
                "%d leaked handle(s), releasing...\n",
                cl->fd, (int)cl->verified_pid, cl->obj_handle_count);
        for (int i = 0; i < cl->obj_handle_count; i++) {
            uint8_t status;
            objects_close(cl->obj_handles[i], &status);
            if (status != OBJ_STATUS_OK) {
                fprintf(stderr, "[objectd]   handle %u: release failed "
                        "(status=0x%02x)\n", cl->obj_handles[i], status);
            }
        }
        cl->obj_handle_count = 0;
    }

    /*
     * Release all registry HKEYs this client opened but never closed.
     * Without this the underlying handle_entry_t and reg_key_data_t
     * allocations leak on every PE process that crashes.
     */
    if (cl->hkey_handle_count > 0) {
        fprintf(stderr, "[objectd] Client fd=%d pid=%d disconnecting with "
                "%d leaked HKEY(s), closing...\n",
                cl->fd, (int)cl->verified_pid, cl->hkey_handle_count);
        for (int i = 0; i < cl->hkey_handle_count; i++) {
            if (hkey_is_predefined(cl->hkey_handles[i]))
                continue;
            registry_close_key((void *)(uintptr_t)cl->hkey_handles[i]);
        }
        cl->hkey_handle_count = 0;
    }

    fprintf(stderr, "[objectd] Client disconnected (fd=%d, pid=%d)\n",
            cl->fd, (int)cl->verified_pid);
    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, cl->fd, NULL);
    fd_index_clear(cl->fd);
    close(cl->fd);
    cl->fd = -1;
    cl->active = 0;
    cl->recv_pos = 0;
    cl->verified_pid = 0;
}

static void client_on_data(client_state_t *cl)
{
    /* EPOLLET: must drain all available data in a loop until EAGAIN */
    for (;;) {
        /*
         * Use recvmsg() with SCM_CREDENTIALS to receive the kernel-verified
         * PID of the sending process.  SO_PASSCRED is set on the listen
         * socket, so the kernel attaches credentials as ancillary data on
         * every message.  We extract the PID once (on the first successful
         * recvmsg that carries credentials) and cache it in cl->verified_pid.
         */
        struct iovec iov;
        iov.iov_base = cl->recv_buf + cl->recv_pos;
        iov.iov_len  = sizeof(cl->recv_buf) - cl->recv_pos;

        /* Ancillary buffer sized for SCM_CREDENTIALS */
        char cmsg_buf[CMSG_SPACE(sizeof(struct ucred))];

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov        = &iov;
        msg.msg_iovlen     = 1;
        msg.msg_control    = cmsg_buf;
        msg.msg_controllen = sizeof(cmsg_buf);

        ssize_t n = recvmsg(cl->fd, &msg, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;  /* Interrupted by signal, retry immediately */
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;  /* Done for now */
            /* Real error */
            client_disconnect(cl);
            return;
        }
        if (n == 0) {
            client_disconnect(cl);
            return;
        }

        /* Extract kernel-verified PID from SCM_CREDENTIALS if present */
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
             cmsg != NULL;
             cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET &&
                cmsg->cmsg_type  == SCM_CREDENTIALS &&
                cmsg->cmsg_len   >= CMSG_LEN(sizeof(struct ucred))) {
                struct ucred cred;
                memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));
                if (cred.pid > 0) {
                    if (cl->verified_pid == 0) {
                        fprintf(stderr,
                                "[objectd] Client fd=%d verified pid=%d uid=%d gid=%d\n",
                                cl->fd, (int)cred.pid,
                                (int)cred.uid, (int)cred.gid);
                    }
                    cl->verified_pid = cred.pid;
                }
            }
        }

        cl->recv_pos += (size_t)n;

        /* Process complete messages */
        while (cl->recv_pos >= sizeof(objectd_request_t)) {
            objectd_request_t *req = (objectd_request_t *)cl->recv_buf;

            /* Validate magic */
            if (req->magic != OBJECTD_MAGIC) {
                fprintf(stderr, "[objectd] Bad magic 0x%08x from fd=%d, dropping\n",
                        req->magic, cl->fd);
                client_disconnect(cl);
                return;
            }

            /* Guard against integer overflow in payload_len */
            if (req->payload_len > RECV_BUF_SIZE - sizeof(objectd_request_t)) {
                fprintf(stderr, "[objectd] payload_len %u overflows buffer on fd=%d, dropping\n",
                        req->payload_len, cl->fd);
                client_disconnect(cl);
                return;
            }

            /* Check if full message has arrived */
            size_t msg_len = sizeof(objectd_request_t) + req->payload_len;
            if (cl->recv_pos < msg_len)
                break;  /* Wait for more data */

            /*
             * Override self-reported PID with kernel-verified PID.
             * The req->pid field in the wire protocol is client-supplied and
             * spoofable.  If we have a verified PID from SCM_CREDENTIALS,
             * use that instead.  Log a warning if they differ (could indicate
             * a bug or a spoofing attempt).
             */
            if (cl->verified_pid > 0) {
                if (req->pid != 0 && req->pid != (uint32_t)cl->verified_pid) {
                    fprintf(stderr,
                            "[objectd] PID mismatch on fd=%d: "
                            "reported=%u verified=%d (using verified)\n",
                            cl->fd, req->pid, (int)cl->verified_pid);
                }
                req->pid = (uint32_t)cl->verified_pid;
            }

            /* Extract payload pointer */
            const void *payload = cl->recv_buf + sizeof(objectd_request_t);

            /* Dispatch */
            handle_object_request(cl, req, payload, req->payload_len);

            /* handle_object_request may have disconnected the client
             * (e.g. send failure) -- bail out if so */
            if (!cl->active)
                return;

            /* Shift remaining data to front of buffer */
            size_t remaining = cl->recv_pos - msg_len;
            if (remaining > 0)
                memmove(cl->recv_buf, cl->recv_buf + msg_len, remaining);
            cl->recv_pos = remaining;
        }

        /* Overflow protection */
        if (cl->recv_pos >= sizeof(cl->recv_buf)) {
            fprintf(stderr, "[objectd] Client fd=%d recv buffer overflow, dropping\n",
                    cl->fd);
            client_disconnect(cl);
            return;
        }
    }
}

/* --------------------------------------------------------------------------
 * Daemon setup
 * -------------------------------------------------------------------------- */

static int create_listen_socket(void)
{
    struct sockaddr_un addr;
    int fd;

    /* Create runtime directory */
    if (mkdir(OBJECTD_RUNDIR, 0755) < 0 && errno != EEXIST) {
        fprintf(stderr, "[objectd] Failed to create %s: %s\n",
                OBJECTD_RUNDIR, strerror(errno));
        return -1;
    }

    /* Remove stale socket file */
    unlink(OBJECTD_SOCK);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "[objectd] socket() failed: %s\n", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, OBJECTD_SOCK, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[objectd] bind(%s) failed: %s\n",
                OBJECTD_SOCK, strerror(errno));
        close(fd);
        return -1;
    }

    /*
     * Restrict socket to owner + group.  Production should create a dedicated
     * "pe-compat" group and add permitted users to it.
     */
    chmod(OBJECTD_SOCK, 0770);

    if (listen(fd, 32) < 0) {
        fprintf(stderr, "[objectd] listen() failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /*
     * Enable SO_PASSCRED on the listen socket so the kernel attaches
     * SCM_CREDENTIALS ancillary data to every recvmsg() on accepted
     * connections.  This lets us verify client PIDs instead of trusting
     * the self-reported pid field in the request header.
     */
    int optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) < 0) {
        fprintf(stderr, "[objectd] setsockopt(SO_PASSCRED) failed: %s\n",
                strerror(errno));
        /* Non-fatal: fall back to self-reported PID */
    }

    if (set_nonblocking(fd) < 0) {
        fprintf(stderr, "[objectd] set_nonblocking() failed: %s\n",
                strerror(errno));
        close(fd);
        return -1;
    }

    fprintf(stderr, "[objectd] Listening on %s\n", OBJECTD_SOCK);
    return fd;
}

static void accept_new_client(void)
{
    struct sockaddr_un client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_fd;

    client_fd = accept(g_listen_fd, (struct sockaddr *)&client_addr, &addr_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            fprintf(stderr, "[objectd] accept() failed: %s\n", strerror(errno));
        return;
    }

    if (set_nonblocking(client_fd) < 0) {
        fprintf(stderr, "[objectd] set_nonblocking(client) failed\n");
        close(client_fd);
        return;
    }

    client_state_t *cl = find_client_slot();
    if (!cl) {
        fprintf(stderr, "[objectd] Max clients reached, rejecting fd=%d\n",
                client_fd);
        close(client_fd);
        return;
    }

    cl->fd = client_fd;
    cl->active = 1;
    cl->recv_pos = 0;
    cl->verified_pid = 0;
    cl->obj_handle_count = 0;
    cl->hkey_handle_count = 0;

    /* Record in fd index for O(1) lookup during event dispatch */
    fd_index_set(client_fd, (int)(cl - g_clients));

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = client_fd;
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
        fprintf(stderr, "[objectd] epoll_ctl(ADD) failed: %s\n",
                strerror(errno));
        fd_index_clear(client_fd);
        cl->active = 0;
        close(client_fd);
        return;
    }

    fprintf(stderr, "[objectd] New client connected (fd=%d)\n", client_fd);
}

/* --------------------------------------------------------------------------
 * Main event loop
 * -------------------------------------------------------------------------- */

static void event_loop(void)
{
    struct epoll_event events[MAX_EVENTS];

    fprintf(stderr, "[objectd] Entering event loop\n");

    while (g_running) {
        int nfds = epoll_wait(g_epoll_fd, events, MAX_EVENTS, 1000);
        if (nfds < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "[objectd] epoll_wait() failed: %s\n",
                    strerror(errno));
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == g_listen_fd) {
                /* New connection */
                accept_new_client();
            } else {
                /* Client data or disconnect */
                client_state_t *cl = find_client_by_fd(events[i].data.fd);
                if (!cl) {
                    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL,
                              events[i].data.fd, NULL);
                    close(events[i].data.fd);
                    continue;
                }

                if (events[i].events & (EPOLLHUP | EPOLLERR)) {
                    client_disconnect(cl);
                } else if (events[i].events & EPOLLIN) {
                    client_on_data(cl);
                }
            }
        }
    }

    fprintf(stderr, "[objectd] Event loop exited\n");
}

/* --------------------------------------------------------------------------
 * Cleanup
 * -------------------------------------------------------------------------- */

static void cleanup(void)
{
    fprintf(stderr, "[objectd] Shutting down...\n");

    /* Close all clients */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].active)
            client_disconnect(&g_clients[i]);
    }

    /* Destroy subsystems */
    objects_shutdown();
    namespace_shutdown();

    /* Close listen socket and epoll */
    if (g_epoll_fd >= 0)
        close(g_epoll_fd);
    if (g_listen_fd >= 0)
        close(g_listen_fd);

    /* Remove socket file */
    unlink(OBJECTD_SOCK);

    fprintf(stderr, "[objectd] Clean shutdown complete\n");
}

/* --------------------------------------------------------------------------
 * Entry point
 * -------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    fprintf(stderr, "[objectd] pe-objectd starting (pid=%d)\n", getpid());

    /* Set up signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    signal(SIGPIPE, SIG_IGN);

    /* Initialize client table and fd->slot direct index */
    memset(g_clients, 0, sizeof(g_clients));
    fd_index_init();

    /* Initialize subsystems */
    objects_init();
    namespace_init();
    objectd_registry_init();

    /* Create listen socket */
    g_listen_fd = create_listen_socket();
    if (g_listen_fd < 0) {
        fprintf(stderr, "[objectd] Failed to create listen socket, exiting\n");
        return 1;
    }

    /* Create epoll instance */
    g_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epoll_fd < 0) {
        fprintf(stderr, "[objectd] epoll_create1() failed: %s\n",
                strerror(errno));
        close(g_listen_fd);
        return 1;
    }

    /* Add listen socket to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = g_listen_fd;
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_listen_fd, &ev) < 0) {
        fprintf(stderr, "[objectd] epoll_ctl(listen) failed: %s\n",
                strerror(errno));
        close(g_epoll_fd);
        close(g_listen_fd);
        return 1;
    }

    fprintf(stderr, "[objectd] Ready. Objects: %d, Namespace initialized, "
            "Registry loaded\n", objects_active_count());

    /* Run */
    event_loop();
    cleanup();

    return 0;
}
