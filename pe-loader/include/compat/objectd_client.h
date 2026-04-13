/*
 * objectd_client.h - Client library for pe-objectd (Object Broker)
 *
 * Provides cross-process named objects, registry, and namespace resolution
 * by talking to the pe-objectd daemon over a Unix domain socket.
 *
 * All functions degrade gracefully: if the broker is not running, they
 * return error status and callers fall back to local implementations.
 */

#ifndef OBJECTD_CLIENT_H
#define OBJECTD_CLIENT_H

#include <stdint.h>

/* ---- Wire protocol constants (must match services/objectd/objectd_protocol.h) ---- */

#define OBJECTD_MAGIC    0x4F424A44  /* "OBJD" */
#define OBJECTD_VERSION  1
#define OBJECTD_SOCK     "/run/pe-compat/objects.sock"

/* Request types */
#define OBJ_REQ_CREATE_MUTEX     0x01
#define OBJ_REQ_CREATE_EVENT     0x02
#define OBJ_REQ_CREATE_SEMAPHORE 0x03
#define OBJ_REQ_CREATE_MAPPING   0x04
#define OBJ_REQ_OPEN             0x05
#define OBJ_REQ_CLOSE            0x06
#define OBJ_REQ_DUPLICATE        0x07

#define OBJ_REQ_REG_OPEN         0x10
#define OBJ_REQ_REG_CREATE       0x11
#define OBJ_REQ_REG_CLOSE        0x12
#define OBJ_REQ_REG_SET_VALUE    0x13
#define OBJ_REQ_REG_GET_VALUE    0x14
#define OBJ_REQ_REG_ENUM_KEY     0x15
#define OBJ_REQ_REG_ENUM_VALUE   0x16
#define OBJ_REQ_REG_DELETE_KEY   0x17
#define OBJ_REQ_REG_DELETE_VALUE 0x18

#define OBJ_REQ_NS_RESOLVE       0x20
#define OBJ_REQ_NS_CREATE_LINK   0x21
#define OBJ_REQ_NS_DELETE_LINK   0x22
#define OBJ_REQ_NS_ENUMERATE     0x23

/* Response status */
#define OBJ_STATUS_OK             0x00
#define OBJ_STATUS_NOT_FOUND      0x01
#define OBJ_STATUS_ALREADY_EXISTS 0x02
#define OBJ_STATUS_ACCESS_DENIED  0x03
#define OBJ_STATUS_NO_MEMORY      0x04
#define OBJ_STATUS_INVALID        0x05
#define OBJ_STATUS_FULL           0x06
#define OBJ_STATUS_IO_ERROR       0x07

/* ---- Wire protocol structures ---- */

/* Request header (32 bytes) */
typedef struct __attribute__((packed)) {
    uint32_t magic;        /* OBJECTD_MAGIC */
    uint16_t version;      /* OBJECTD_VERSION */
    uint8_t  request_type; /* OBJ_REQ_* */
    uint8_t  flags;
    uint32_t pid;          /* Caller PID */
    uint32_t subject_id;   /* Trust subject */
    uint16_t payload_len;  /* Bytes following this header */
    uint16_t _reserved;
    uint64_t sequence;     /* For matching response to request */
    uint8_t  _pad[4];      /* Pad to 32 bytes */
} objectd_request_t;

/* Response header (32 bytes) */
typedef struct __attribute__((packed)) {
    uint32_t magic;        /* OBJECTD_MAGIC */
    uint16_t version;
    uint8_t  status;       /* OBJ_STATUS_* */
    uint8_t  flags;
    uint64_t sequence;     /* Matches request */
    uint32_t handle;       /* Broker-side handle (if applicable) */
    int32_t  shm_fd;       /* Placeholder; actual fd via SCM_RIGHTS */
    uint16_t payload_len;
    uint16_t _reserved;
    uint8_t  _pad[4];      /* Pad to 32 bytes */
} objectd_response_t;

/* Callers MUST ensure strings fit within the buffer sizes below.
 * Use snprintf/strncpy with sizeof(field) - 1 to prevent overflow. */

/* Object creation payload */
typedef struct {
    char name[260];        /* Object name */
    int  initial_state;    /* Event: signaled; Mutex: owned; Semaphore: initial count */
    int  manual_reset;     /* Event only */
    int  max_count;        /* Semaphore only */
} obj_create_payload_t;

/* Callers MUST ensure strings fit within the buffer sizes below.
 * Use snprintf/strncpy with sizeof(field) - 1 to prevent overflow. */

/* Object open payload (must match services/objectd/objectd_protocol.h) */
typedef struct {
    char    name[260];     /* Object name */
    uint8_t type;          /* OBJ_REQ_CREATE_MUTEX/EVENT/SEMAPHORE */
    uint8_t _pad[3];
} obj_open_payload_t;

/* Callers MUST ensure strings fit within the buffer sizes below.
 * Use snprintf/strncpy with sizeof(field) - 1 to prevent overflow. */

/* Registry payloads */
typedef struct {
    uint64_t hkey;         /* Parent key handle */
    char     subkey[512];
} reg_open_payload_t;

/* Callers MUST ensure strings fit within the buffer sizes below.
 * Use snprintf/strncpy with sizeof(field) - 1 to prevent overflow. */
typedef struct {
    uint64_t hkey;
    char     name[256];
    uint32_t type;         /* REG_SZ, REG_DWORD, etc */
    uint32_t data_len;
    /* data follows immediately after this struct */
} reg_set_value_payload_t;

/* Callers MUST ensure strings fit within the buffer sizes below.
 * Use snprintf/strncpy with sizeof(field) - 1 to prevent overflow. */
typedef struct {
    uint64_t hkey;
    char     name[256];
    char     subkey[512];  /* Optional subkey for RegGetValue */
    uint32_t buf_size;     /* Caller's buffer size */
} reg_get_value_payload_t;

typedef struct {
    uint64_t hkey;
    uint32_t index;
    uint32_t buf_size;     /* Caller's name buffer size */
} reg_enum_payload_t;

typedef struct {
    uint64_t hkey;
} reg_close_payload_t;

/* Callers MUST ensure strings fit within the buffer sizes below.
 * Use snprintf/strncpy with sizeof(field) - 1 to prevent overflow. */

/* Namespace payload */
typedef struct {
    char path[512];        /* \Device\Foo or \DosDevices\C: */
} ns_resolve_payload_t;

/* ---- Shared memory layouts for futex-based sync objects ---- */

/* Shared memory layout for a named mutex */
typedef struct {
    _Atomic uint32_t  futex_word;   /* 0=unlocked, PID=locked */
    _Atomic uint32_t  owner_tid;
    _Atomic int32_t   recursion;
    uint32_t          _pad;
} shm_mutex_t;

/* Shared memory layout for a named event */
typedef struct {
    _Atomic uint32_t  futex_word;   /* 0=unsignaled, 1=signaled */
    uint32_t          manual_reset;
    uint32_t          _pad[2];
} shm_event_t;

/* Shared memory layout for a named semaphore */
typedef struct {
    _Atomic int32_t   futex_word;   /* Current count */
    int32_t           max_count;
    uint32_t          _pad[2];
} shm_semaphore_t;

/* ---- Client API ---- */

/* Connect to the object broker daemon.  Returns 0 on success, -1 if
 * the broker socket is not available (e.g. daemon not running). */
int objectd_connect(void);

/* Disconnect from the broker and release resources. */
void objectd_disconnect(void);

/* Returns non-zero if the broker is connected and available. */
int objectd_available(void);

/* ---- Named object operations ---- */

/* Create a named mutex.  On success *shm_fd_out receives the fd for
 * the shared memory page (caller should mmap then close).
 * Returns OBJ_STATUS_OK, OBJ_STATUS_ALREADY_EXISTS, or error. */
int objectd_create_mutex(const char *name, int initial_owner, int *shm_fd_out);

/* Create a named event. */
int objectd_create_event(const char *name, int manual_reset,
                         int initial_state, int *shm_fd_out);

/* Create a named semaphore. */
int objectd_create_semaphore(const char *name, int initial, int max,
                             int *shm_fd_out);

/* Open an existing named object by name.  type is OBJ_REQ_CREATE_MUTEX/EVENT/SEMAPHORE. */
int objectd_open_object(const char *name, int type, int *shm_fd_out);

/* Close a broker-side handle. */
int objectd_close_object(uint32_t broker_handle);

/* ---- Registry operations ---- */

int objectd_reg_open(uint64_t parent, const char *subkey, uint64_t *handle_out);
int objectd_reg_create(uint64_t parent, const char *subkey, uint64_t *handle_out);
int objectd_reg_close(uint64_t handle);
int objectd_reg_set_value(uint64_t handle, const char *name, uint32_t type,
                          const void *data, uint32_t len);
int objectd_reg_get_value(uint64_t handle, const char *name, uint32_t *type_out,
                          void *data_out, uint32_t *len_inout);
int objectd_reg_enum_key(uint64_t handle, uint32_t index,
                         char *name, uint32_t *len);
int objectd_reg_enum_value(uint64_t handle, uint32_t index,
                           char *name, uint32_t *name_len,
                           uint32_t *type, void *data, uint32_t *data_len);
int objectd_reg_delete_key(uint64_t handle, const char *subkey);
int objectd_reg_delete_value(uint64_t handle, const char *name);

/* ---- Namespace resolution ---- */

int objectd_ns_resolve(const char *path, char *linux_path_out, int linux_path_len);

#endif /* OBJECTD_CLIENT_H */
