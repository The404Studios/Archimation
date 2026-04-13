/*
 * objectd_client.c - Client library for pe-objectd (Object Broker)
 *
 * Connects to the broker daemon via Unix domain socket and provides
 * named object, registry, and namespace operations.
 *
 * Graceful degradation: if the broker socket is not available, all
 * functions return error status so callers fall back to local impls.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <stdatomic.h>
#include <stdint.h>

#include "compat/objectd_client.h"

/* ---- Connection state ---- */

static int              g_objectd_fd        = -1;
static _Atomic int      g_objectd_available = 0;  /* Atomic: read without lock in objectd_available() */
static pthread_mutex_t  g_objectd_lock      = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint_fast64_t g_sequence      = 0;

/* ---- Internal helpers ---- */

/*
 * Fill a request header with common fields.
 */
static void fill_request(objectd_request_t *req, uint8_t type,
                         uint16_t payload_len)
{
    memset(req, 0, sizeof(*req));
    req->magic        = OBJECTD_MAGIC;
    req->version      = OBJECTD_VERSION;
    req->request_type = type;
    req->pid          = (uint32_t)getpid();
    req->payload_len  = payload_len;
    req->sequence     = atomic_fetch_add(&g_sequence, 1);
}

/*
 * Send request header + payload, receive response header + optional payload.
 *
 * Uses recvmsg() to receive SCM_RIGHTS ancillary data (file descriptor
 * passed from the broker for shared memory pages).
 *
 * Parameters:
 *   req          - request header (already filled)
 *   req_payload  - request payload bytes (may be NULL if payload_len == 0)
 *   resp         - output response header
 *   resp_payload - buffer for response payload (may be NULL)
 *   resp_payload_max - size of resp_payload buffer
 *   fd_out       - if non-NULL, receives a file descriptor from SCM_RIGHTS
 *
 * Returns 0 on success, -1 on I/O error.
 */
static int objectd_send_recv(const objectd_request_t *req,
                             const void *req_payload,
                             objectd_response_t *resp,
                             void *resp_payload, uint32_t resp_payload_max,
                             int *fd_out)
{
    if (g_objectd_fd < 0)
        return -1;

    /* ---- Send request ---- */
    /* Send header */
    const uint8_t *p = (const uint8_t *)req;
    uint32_t remaining = sizeof(*req);
    while (remaining > 0) {
        ssize_t n = send(g_objectd_fd, p, remaining, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
                usleep(100);  /* Avoid busy-spin on transient EAGAIN */
                continue;
            }
            goto io_fail;
        }
        p += n;
        remaining -= (uint32_t)n;
    }

    /* Send payload if present */
    if (req_payload && req->payload_len > 0) {
        p = (const uint8_t *)req_payload;
        remaining = req->payload_len;
        while (remaining > 0) {
            ssize_t n = send(g_objectd_fd, p, remaining, MSG_NOSIGNAL);
            if (n <= 0) {
                if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
                    usleep(100);
                    continue;
                }
                goto io_fail;
            }
            p += n;
            remaining -= (uint32_t)n;
        }
    }

    /* ---- Receive response with SCM_RIGHTS ---- */
    {
        struct iovec iov[2];
        int iov_count = 1;

        /* First iov: response header */
        iov[0].iov_base = resp;
        iov[0].iov_len  = sizeof(*resp);

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov    = iov;
        msg.msg_iovlen = iov_count;

        /* Ancillary data buffer for SCM_RIGHTS (one fd) */
        char cmsg_buf[CMSG_SPACE(sizeof(int))];
        memset(cmsg_buf, 0, sizeof(cmsg_buf));
        msg.msg_control    = cmsg_buf;
        msg.msg_controllen = sizeof(cmsg_buf);

        /* Receive header + ancillary */
        ssize_t total = 0;
        while (total < (ssize_t)sizeof(*resp)) {
            /* Re-adjust iov for partial reads */
            iov[0].iov_base = (uint8_t *)resp + total;
            iov[0].iov_len  = sizeof(*resp) - (size_t)total;
            msg.msg_iov    = iov;
            msg.msg_iovlen = 1;
            /* Only look for ancillary data on first recvmsg */
            if (total > 0) {
                msg.msg_control    = NULL;
                msg.msg_controllen = 0;
            }

            ssize_t n = recvmsg(g_objectd_fd, &msg, 0);
            if (n <= 0) {
                if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
                    usleep(100);
                    continue;
                }
                goto io_fail;
            }
            total += n;

            /* Extract fd from ancillary data on first successful recv */
            if (fd_out && msg.msg_controllen > 0) {
                struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
                while (cmsg) {
                    if (cmsg->cmsg_level == SOL_SOCKET &&
                        cmsg->cmsg_type  == SCM_RIGHTS &&
                        cmsg->cmsg_len   == CMSG_LEN(sizeof(int))) {
                        memcpy(fd_out, CMSG_DATA(cmsg), sizeof(int));
                    }
                    cmsg = CMSG_NXTHDR(&msg, cmsg);
                }
            }
        }

        /* Validate response header */
        if (resp->magic != OBJECTD_MAGIC) {
            goto io_fail;
        }

        /* Receive response payload if present */
        if (resp->payload_len > 0 && resp_payload && resp_payload_max > 0) {
            uint32_t to_read = resp->payload_len;
            if (to_read > resp_payload_max)
                to_read = resp_payload_max;

            uint8_t *dst = (uint8_t *)resp_payload;
            uint32_t got = 0;
            while (got < to_read) {
                ssize_t n = recv(g_objectd_fd, dst + got, to_read - got, 0);
                if (n <= 0) {
                    if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
                        usleep(100);
                        continue;
                    }
                    goto io_fail;
                }
                got += (uint32_t)n;
            }

            /* Drain any remaining payload bytes we can't fit */
            uint32_t excess = resp->payload_len - to_read;
            while (excess > 0) {
                char trash[512];
                uint32_t chunk = excess > sizeof(trash) ? sizeof(trash) : excess;
                ssize_t n = recv(g_objectd_fd, trash, chunk, 0);
                if (n <= 0) {
                    if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
                        usleep(100);
                        continue;
                    }
                    goto io_fail;
                }
                excess -= (uint32_t)n;
            }
        } else if (resp->payload_len > 0) {
            /* Caller doesn't want payload, drain it */
            uint32_t excess = resp->payload_len;
            while (excess > 0) {
                char trash[512];
                uint32_t chunk = excess > sizeof(trash) ? sizeof(trash) : excess;
                ssize_t n = recv(g_objectd_fd, trash, chunk, 0);
                if (n <= 0) {
                    if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
                        usleep(100);
                        continue;
                    }
                    goto io_fail;
                }
                excess -= (uint32_t)n;
            }
        }
    }

    return 0;

io_fail:
    /* Close any SCM_RIGHTS fd we received before failing */
    if (fd_out && *fd_out >= 0) {
        close(*fd_out);
        *fd_out = -1;
    }
    /* Connection broken; mark broker as unavailable */
    close(g_objectd_fd);
    g_objectd_fd = -1;
    atomic_store(&g_objectd_available, 0);
    return -1;
}

/* ---- Public API: connection management ---- */

int objectd_connect(void)
{
    pthread_mutex_lock(&g_objectd_lock);

    if (g_objectd_fd >= 0) {
        /* Already connected */
        pthread_mutex_unlock(&g_objectd_lock);
        return 0;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        atomic_store(&g_objectd_available, 0);
        pthread_mutex_unlock(&g_objectd_lock);
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, OBJECTD_SOCK, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        atomic_store(&g_objectd_available, 0);
        pthread_mutex_unlock(&g_objectd_lock);
        return -1;
    }

    g_objectd_fd = fd;
    atomic_store(&g_objectd_available, 1);

    pthread_mutex_unlock(&g_objectd_lock);
    return 0;
}

void objectd_disconnect(void)
{
    pthread_mutex_lock(&g_objectd_lock);

    if (g_objectd_fd >= 0) {
        close(g_objectd_fd);
        g_objectd_fd = -1;
    }
    atomic_store(&g_objectd_available, 0);

    pthread_mutex_unlock(&g_objectd_lock);
}

int objectd_available(void)
{
    /* Atomic read without lock for fast-path check */
    if (atomic_load(&g_objectd_available))
        return 1;

    /* Try lazy connect on first call (connect takes the lock internally) */
    objectd_connect();
    return atomic_load(&g_objectd_available);
}

/* ---- Named object operations ---- */

int objectd_create_mutex(const char *name, int initial_owner, int *shm_fd_out)
{
    if (!objectd_available())
        return OBJ_STATUS_IO_ERROR;

    objectd_request_t req;
    obj_create_payload_t payload;

    memset(&payload, 0, sizeof(payload));
    if (name)
        strncpy(payload.name, name, sizeof(payload.name) - 1);
    payload.initial_state = initial_owner;

    fill_request(&req, OBJ_REQ_CREATE_MUTEX, sizeof(payload));

    objectd_response_t resp;
    memset(&resp, 0, sizeof(resp));
    if (shm_fd_out) *shm_fd_out = -1;

    pthread_mutex_lock(&g_objectd_lock);
    int ret = objectd_send_recv(&req, &payload, &resp, NULL, 0, shm_fd_out);
    pthread_mutex_unlock(&g_objectd_lock);

    if (ret < 0)
        return OBJ_STATUS_IO_ERROR;

    return resp.status;
}

int objectd_create_event(const char *name, int manual_reset,
                         int initial_state, int *shm_fd_out)
{
    if (!objectd_available())
        return OBJ_STATUS_IO_ERROR;

    objectd_request_t req;
    obj_create_payload_t payload;

    memset(&payload, 0, sizeof(payload));
    if (name)
        strncpy(payload.name, name, sizeof(payload.name) - 1);
    payload.initial_state = initial_state;
    payload.manual_reset  = manual_reset;

    fill_request(&req, OBJ_REQ_CREATE_EVENT, sizeof(payload));

    objectd_response_t resp;
    memset(&resp, 0, sizeof(resp));
    if (shm_fd_out) *shm_fd_out = -1;

    pthread_mutex_lock(&g_objectd_lock);
    int ret = objectd_send_recv(&req, &payload, &resp, NULL, 0, shm_fd_out);
    pthread_mutex_unlock(&g_objectd_lock);

    if (ret < 0)
        return OBJ_STATUS_IO_ERROR;

    return resp.status;
}

int objectd_create_semaphore(const char *name, int initial, int max,
                             int *shm_fd_out)
{
    if (!objectd_available())
        return OBJ_STATUS_IO_ERROR;

    objectd_request_t req;
    obj_create_payload_t payload;

    memset(&payload, 0, sizeof(payload));
    if (name)
        strncpy(payload.name, name, sizeof(payload.name) - 1);
    payload.initial_state = initial;
    payload.max_count     = max;

    fill_request(&req, OBJ_REQ_CREATE_SEMAPHORE, sizeof(payload));

    objectd_response_t resp;
    memset(&resp, 0, sizeof(resp));
    if (shm_fd_out) *shm_fd_out = -1;

    pthread_mutex_lock(&g_objectd_lock);
    int ret = objectd_send_recv(&req, &payload, &resp, NULL, 0, shm_fd_out);
    pthread_mutex_unlock(&g_objectd_lock);

    if (ret < 0)
        return OBJ_STATUS_IO_ERROR;

    return resp.status;
}

int objectd_open_object(const char *name, int type, int *shm_fd_out)
{
    if (!objectd_available())
        return OBJ_STATUS_IO_ERROR;

    objectd_request_t req;
    obj_open_payload_t payload;

    memset(&payload, 0, sizeof(payload));
    if (name)
        strncpy(payload.name, name, sizeof(payload.name) - 1);
    payload.type = (uint8_t)type;

    fill_request(&req, OBJ_REQ_OPEN, sizeof(payload));

    objectd_response_t resp;
    memset(&resp, 0, sizeof(resp));
    if (shm_fd_out) *shm_fd_out = -1;

    pthread_mutex_lock(&g_objectd_lock);
    int ret = objectd_send_recv(&req, &payload, &resp, NULL, 0, shm_fd_out);
    pthread_mutex_unlock(&g_objectd_lock);

    if (ret < 0)
        return OBJ_STATUS_IO_ERROR;

    return resp.status;
}

int objectd_close_object(uint32_t broker_handle)
{
    if (!objectd_available())
        return OBJ_STATUS_IO_ERROR;

    objectd_request_t req;
    fill_request(&req, OBJ_REQ_CLOSE, sizeof(uint32_t));

    objectd_response_t resp;
    memset(&resp, 0, sizeof(resp));

    pthread_mutex_lock(&g_objectd_lock);
    int ret = objectd_send_recv(&req, &broker_handle, &resp, NULL, 0, NULL);
    pthread_mutex_unlock(&g_objectd_lock);

    if (ret < 0)
        return OBJ_STATUS_IO_ERROR;

    return resp.status;
}

/* ---- Registry operations ---- */

int objectd_reg_open(uint64_t parent, const char *subkey, uint64_t *handle_out)
{
    if (!objectd_available())
        return OBJ_STATUS_IO_ERROR;

    objectd_request_t req;
    reg_open_payload_t payload;

    memset(&payload, 0, sizeof(payload));
    payload.hkey = parent;
    if (subkey)
        strncpy(payload.subkey, subkey, sizeof(payload.subkey) - 1);

    fill_request(&req, OBJ_REQ_REG_OPEN, sizeof(payload));

    objectd_response_t resp;
    memset(&resp, 0, sizeof(resp));

    /* The broker returns the new handle in the response payload */
    uint64_t child = 0;

    pthread_mutex_lock(&g_objectd_lock);
    int ret = objectd_send_recv(&req, &payload, &resp, &child, sizeof(child), NULL);
    pthread_mutex_unlock(&g_objectd_lock);

    if (ret < 0)
        return OBJ_STATUS_IO_ERROR;

    if (resp.status == OBJ_STATUS_OK && handle_out) {
        /* Handle may come in response header or payload */
        if (child != 0)
            *handle_out = child;
        else
            *handle_out = (uint64_t)resp.handle;
    }

    return resp.status;
}

int objectd_reg_create(uint64_t parent, const char *subkey, uint64_t *handle_out)
{
    if (!objectd_available())
        return OBJ_STATUS_IO_ERROR;

    objectd_request_t req;
    reg_open_payload_t payload;

    memset(&payload, 0, sizeof(payload));
    payload.hkey = parent;
    if (subkey)
        strncpy(payload.subkey, subkey, sizeof(payload.subkey) - 1);

    fill_request(&req, OBJ_REQ_REG_CREATE, sizeof(payload));

    objectd_response_t resp;
    memset(&resp, 0, sizeof(resp));
    uint64_t child = 0;

    pthread_mutex_lock(&g_objectd_lock);
    int ret = objectd_send_recv(&req, &payload, &resp, &child, sizeof(child), NULL);
    pthread_mutex_unlock(&g_objectd_lock);

    if (ret < 0)
        return OBJ_STATUS_IO_ERROR;

    if ((resp.status == OBJ_STATUS_OK ||
         resp.status == OBJ_STATUS_ALREADY_EXISTS) && handle_out) {
        if (child != 0)
            *handle_out = child;
        else
            *handle_out = (uint64_t)resp.handle;
    }

    return resp.status;
}

int objectd_reg_close(uint64_t handle)
{
    if (!objectd_available())
        return OBJ_STATUS_IO_ERROR;

    objectd_request_t req;
    reg_close_payload_t payload;

    memset(&payload, 0, sizeof(payload));
    payload.hkey = handle;

    fill_request(&req, OBJ_REQ_REG_CLOSE, sizeof(payload));

    objectd_response_t resp;
    memset(&resp, 0, sizeof(resp));

    pthread_mutex_lock(&g_objectd_lock);
    int ret = objectd_send_recv(&req, &payload, &resp, NULL, 0, NULL);
    pthread_mutex_unlock(&g_objectd_lock);

    if (ret < 0)
        return OBJ_STATUS_IO_ERROR;

    return resp.status;
}

int objectd_reg_set_value(uint64_t handle, const char *name, uint32_t type,
                          const void *data, uint32_t len)
{
    if (!objectd_available())
        return OBJ_STATUS_IO_ERROR;

    /* Build payload: fixed header + variable data appended */
    uint32_t total_payload = sizeof(reg_set_value_payload_t) + len;

    /* payload_len in the wire header is uint16_t -- reject if too large */
    if (total_payload > UINT16_MAX)
        return OBJ_STATUS_INVALID;

    uint8_t *buf = malloc(total_payload);
    if (!buf)
        return OBJ_STATUS_NO_MEMORY;

    reg_set_value_payload_t *payload = (reg_set_value_payload_t *)buf;
    memset(payload, 0, sizeof(*payload));
    payload->hkey     = handle;
    if (name)
        strncpy(payload->name, name, sizeof(payload->name) - 1);
    payload->type     = type;
    payload->data_len = len;
    if (data && len > 0)
        memcpy(buf + sizeof(*payload), data, len);

    objectd_request_t req;
    fill_request(&req, OBJ_REQ_REG_SET_VALUE, (uint16_t)total_payload);

    objectd_response_t resp;
    memset(&resp, 0, sizeof(resp));

    pthread_mutex_lock(&g_objectd_lock);
    int ret = objectd_send_recv(&req, buf, &resp, NULL, 0, NULL);
    pthread_mutex_unlock(&g_objectd_lock);

    free(buf);

    if (ret < 0)
        return OBJ_STATUS_IO_ERROR;

    return resp.status;
}

int objectd_reg_get_value(uint64_t handle, const char *name, uint32_t *type_out,
                          void *data_out, uint32_t *len_inout)
{
    if (!objectd_available())
        return OBJ_STATUS_IO_ERROR;

    objectd_request_t req;
    reg_get_value_payload_t payload;

    memset(&payload, 0, sizeof(payload));
    payload.hkey = handle;
    if (name)
        strncpy(payload.name, name, sizeof(payload.name) - 1);
    payload.buf_size = len_inout ? *len_inout : 0;

    fill_request(&req, OBJ_REQ_REG_GET_VALUE, sizeof(payload));

    /* Response: reg_get_value_response header (type + data_len) + data */
    uint32_t resp_buf_size = 8 + (len_inout ? *len_inout : 0);
    uint8_t *resp_buf = malloc(resp_buf_size);
    if (!resp_buf)
        return OBJ_STATUS_NO_MEMORY;

    objectd_response_t resp;
    memset(&resp, 0, sizeof(resp));

    pthread_mutex_lock(&g_objectd_lock);
    int ret = objectd_send_recv(&req, &payload, &resp,
                                resp_buf, resp_buf_size, NULL);
    pthread_mutex_unlock(&g_objectd_lock);

    if (ret < 0) {
        free(resp_buf);
        return OBJ_STATUS_IO_ERROR;
    }

    if (resp.status == OBJ_STATUS_OK && resp.payload_len >= 8) {
        /* Response format: { uint32_t type, uint32_t data_len, data[] } */
        uint32_t r_type, r_data_len;
        memcpy(&r_type, resp_buf, 4);
        memcpy(&r_data_len, resp_buf + 4, 4);
        if (type_out)
            *type_out = r_type;
        if (len_inout) {
            uint32_t copy_len = r_data_len;
            if (copy_len > *len_inout)
                copy_len = *len_inout;
            /* Clamp against what we actually received */
            uint32_t avail = resp.payload_len > 8
                           ? resp.payload_len - 8 : 0;
            if (copy_len > avail)
                copy_len = avail;
            if (data_out && copy_len > 0)
                memcpy(data_out, resp_buf + 8, copy_len);
            *len_inout = r_data_len;
        }
    }

    free(resp_buf);
    return resp.status;
}

int objectd_reg_enum_key(uint64_t handle, uint32_t index,
                         char *name, uint32_t *len)
{
    if (!objectd_available())
        return OBJ_STATUS_IO_ERROR;

    objectd_request_t req;
    reg_enum_payload_t payload;

    memset(&payload, 0, sizeof(payload));
    payload.hkey    = handle;
    payload.index   = index;
    payload.buf_size = len ? *len : 0;

    fill_request(&req, OBJ_REQ_REG_ENUM_KEY, sizeof(payload));

    /* Response payload: key name string */
    uint32_t name_buf_size = len ? *len : 256;
    char *name_buf = malloc(name_buf_size);
    if (!name_buf)
        return OBJ_STATUS_NO_MEMORY;

    objectd_response_t resp;
    memset(&resp, 0, sizeof(resp));

    pthread_mutex_lock(&g_objectd_lock);
    int ret = objectd_send_recv(&req, &payload, &resp,
                                name_buf, name_buf_size, NULL);
    pthread_mutex_unlock(&g_objectd_lock);

    if (ret < 0) {
        free(name_buf);
        return OBJ_STATUS_IO_ERROR;
    }

    if (resp.status == OBJ_STATUS_OK && resp.payload_len >= 4) {
        /* Server sends reg_enum_key_response_t { uint32_t name_len } + name */
        uint32_t r_name_len;
        memcpy(&r_name_len, name_buf, 4);
        uint32_t avail = resp.payload_len > 4 ? resp.payload_len - 4 : 0;
        uint32_t copy_len = r_name_len < avail ? r_name_len : avail;
        if (len && copy_len > *len)
            copy_len = *len;
        if (name && copy_len > 0)
            memcpy(name, name_buf + 4, copy_len);
        if (name)
            name[copy_len] = '\0';
        if (len)
            *len = r_name_len;
    }

    free(name_buf);
    return resp.status;
}

int objectd_reg_enum_value(uint64_t handle, uint32_t index,
                           char *name, uint32_t *name_len,
                           uint32_t *type, void *data, uint32_t *data_len)
{
    if (!objectd_available())
        return OBJ_STATUS_IO_ERROR;

    objectd_request_t req;
    reg_enum_payload_t payload;

    memset(&payload, 0, sizeof(payload));
    payload.hkey     = handle;
    payload.index    = index;
    payload.buf_size = (name_len ? *name_len : 0) + (data_len ? *data_len : 0);

    fill_request(&req, OBJ_REQ_REG_ENUM_VALUE, sizeof(payload));

    /* Response: reg_enum_value_response_t { name_len(4), type(4), data_len(4) } + name + data */
    uint32_t resp_max = 12 + (name_len ? *name_len : 256) + (data_len ? *data_len : 4096);
    uint8_t *resp_buf = malloc(resp_max);
    if (!resp_buf)
        return OBJ_STATUS_NO_MEMORY;

    objectd_response_t resp;
    memset(&resp, 0, sizeof(resp));

    pthread_mutex_lock(&g_objectd_lock);
    int ret = objectd_send_recv(&req, &payload, &resp,
                                resp_buf, resp_max, NULL);
    pthread_mutex_unlock(&g_objectd_lock);

    if (ret < 0) {
        free(resp_buf);
        return OBJ_STATUS_IO_ERROR;
    }

    if (resp.status == OBJ_STATUS_OK && resp.payload_len >= 12) {
        /* Server sends reg_enum_value_response_t: {name_len, type, data_len} */
        uint32_t r_name_len, r_type, r_data_len;
        memcpy(&r_name_len, resp_buf + 0, 4);
        memcpy(&r_type,     resp_buf + 4, 4);
        memcpy(&r_data_len, resp_buf + 8, 4);

        if (type)
            *type = r_type;

        /* Server sends name with null terminator (+1 byte) */
        uint32_t off = 12;
        if (name && name_len) {
            uint32_t copy = r_name_len < *name_len ? r_name_len : *name_len;
            if (copy > 0 && off + copy <= resp.payload_len)
                memcpy(name, resp_buf + off, copy);
            if (copy < *name_len)
                name[copy] = '\0';
            *name_len = r_name_len;
        }
        off += r_name_len + 1;  /* +1 for null terminator sent by server */

        if (data && data_len) {
            uint32_t copy = r_data_len < *data_len ? r_data_len : *data_len;
            if (copy > 0 && off + copy <= resp.payload_len)
                memcpy(data, resp_buf + off, copy);
            *data_len = r_data_len;
        }
    }

    free(resp_buf);
    return resp.status;
}

/* ---- Registry delete operations ---- */

int objectd_reg_delete_key(uint64_t handle, const char *subkey)
{
    if (!objectd_available())
        return OBJ_STATUS_IO_ERROR;

    /* Reuse reg_delete_payload_t layout: { uint64_t hkey, char name[256] } */
    struct { uint64_t hkey; char name[256]; } payload;
    memset(&payload, 0, sizeof(payload));
    payload.hkey = handle;
    if (subkey)
        strncpy(payload.name, subkey, sizeof(payload.name) - 1);

    objectd_request_t req;
    fill_request(&req, OBJ_REQ_REG_DELETE_KEY, sizeof(payload));

    objectd_response_t resp;
    memset(&resp, 0, sizeof(resp));

    pthread_mutex_lock(&g_objectd_lock);
    int ret = objectd_send_recv(&req, &payload, &resp, NULL, 0, NULL);
    pthread_mutex_unlock(&g_objectd_lock);

    if (ret < 0)
        return OBJ_STATUS_IO_ERROR;
    return resp.status;
}

int objectd_reg_delete_value(uint64_t handle, const char *name)
{
    if (!objectd_available())
        return OBJ_STATUS_IO_ERROR;

    struct { uint64_t hkey; char name[256]; } payload;
    memset(&payload, 0, sizeof(payload));
    payload.hkey = handle;
    if (name)
        strncpy(payload.name, name, sizeof(payload.name) - 1);

    objectd_request_t req;
    fill_request(&req, OBJ_REQ_REG_DELETE_VALUE, sizeof(payload));

    objectd_response_t resp;
    memset(&resp, 0, sizeof(resp));

    pthread_mutex_lock(&g_objectd_lock);
    int ret = objectd_send_recv(&req, &payload, &resp, NULL, 0, NULL);
    pthread_mutex_unlock(&g_objectd_lock);

    if (ret < 0)
        return OBJ_STATUS_IO_ERROR;
    return resp.status;
}

/* ---- Namespace resolution ---- */

int objectd_ns_resolve(const char *path, char *linux_path_out, int linux_path_len)
{
    if (linux_path_len <= 0)
        return OBJ_STATUS_INVALID;

    if (!objectd_available())
        return OBJ_STATUS_IO_ERROR;

    objectd_request_t req;
    ns_resolve_payload_t payload;

    memset(&payload, 0, sizeof(payload));
    if (path)
        strncpy(payload.path, path, sizeof(payload.path) - 1);

    fill_request(&req, OBJ_REQ_NS_RESOLVE, sizeof(payload));

    objectd_response_t resp;
    memset(&resp, 0, sizeof(resp));

    uint32_t buf_max = (uint32_t)linux_path_len;
    char *buf = malloc(buf_max);
    if (!buf)
        return OBJ_STATUS_NO_MEMORY;

    pthread_mutex_lock(&g_objectd_lock);
    int ret = objectd_send_recv(&req, &payload, &resp, buf, buf_max, NULL);
    pthread_mutex_unlock(&g_objectd_lock);

    if (ret < 0) {
        free(buf);
        return OBJ_STATUS_IO_ERROR;
    }

    if (resp.status == OBJ_STATUS_OK && linux_path_out && resp.payload_len > 0) {
        uint32_t copy = resp.payload_len;
        if (copy >= (uint32_t)linux_path_len)
            copy = (uint32_t)linux_path_len - 1;
        memcpy(linux_path_out, buf, copy);
        linux_path_out[copy] = '\0';
    }

    free(buf);
    return resp.status;
}
