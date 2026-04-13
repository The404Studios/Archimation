/*
 * objectd_protocol.h - Wire protocol for pe-objectd
 *
 * Request/response over Unix domain socket (stream mode).
 * 32-byte header + variable payload.
 */

#ifndef OBJECTD_PROTOCOL_H
#define OBJECTD_PROTOCOL_H

#include <stdint.h>

#define OBJECTD_MAGIC    0x4F424A44  /* "OBJD" */
#define OBJECTD_VERSION  1
#define OBJECTD_SOCK     "/run/pe-compat/objects.sock"
#define OBJECTD_RUNDIR   "/run/pe-compat"

/* Request types — named objects */
#define OBJ_REQ_CREATE_MUTEX     0x01
#define OBJ_REQ_CREATE_EVENT     0x02
#define OBJ_REQ_CREATE_SEMAPHORE 0x03
#define OBJ_REQ_CREATE_MAPPING   0x04
#define OBJ_REQ_OPEN             0x05
#define OBJ_REQ_CLOSE            0x06
#define OBJ_REQ_DUPLICATE        0x07

/* Request types — registry */
#define OBJ_REQ_REG_OPEN         0x10
#define OBJ_REQ_REG_CREATE       0x11
#define OBJ_REQ_REG_CLOSE        0x12
#define OBJ_REQ_REG_SET_VALUE    0x13
#define OBJ_REQ_REG_GET_VALUE    0x14
#define OBJ_REQ_REG_ENUM_KEY     0x15
#define OBJ_REQ_REG_ENUM_VALUE   0x16
#define OBJ_REQ_REG_DELETE_KEY   0x17
#define OBJ_REQ_REG_DELETE_VALUE 0x18

/* Request types — device namespace */
#define OBJ_REQ_NS_RESOLVE       0x20
#define OBJ_REQ_NS_CREATE_LINK   0x21
#define OBJ_REQ_NS_DELETE_LINK   0x22
#define OBJ_REQ_NS_ENUMERATE     0x23

/* Response status codes */
#define OBJ_STATUS_OK             0x00
#define OBJ_STATUS_NOT_FOUND      0x01
#define OBJ_STATUS_ALREADY_EXISTS 0x02
#define OBJ_STATUS_ACCESS_DENIED  0x03
#define OBJ_STATUS_NO_MEMORY      0x04
#define OBJ_STATUS_INVALID        0x05
#define OBJ_STATUS_FULL           0x06

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
    uint32_t _pad;         /* Pad to 32 bytes */
} objectd_request_t;

_Static_assert(sizeof(objectd_request_t) == 32, "Request header must be 32 bytes");

/* Response header (32 bytes) */
typedef struct __attribute__((packed)) {
    uint32_t magic;        /* OBJECTD_MAGIC */
    uint16_t version;
    uint8_t  status;       /* OBJ_STATUS_* */
    uint8_t  flags;
    uint64_t sequence;     /* Matches request */
    uint32_t handle;       /* Broker-side handle (if applicable) */
    int32_t  shm_fd;       /* File descriptor for shared memory (passed via SCM_RIGHTS) */
    uint16_t payload_len;
    uint16_t _reserved;
    uint32_t _pad;         /* Pad to 32 bytes */
} objectd_response_t;

_Static_assert(sizeof(objectd_response_t) == 32, "Response header must be 32 bytes");

/* --- Object creation payloads --- */

typedef struct {
    char name[260];        /* Object name (MAX_PATH) */
    int  initial_state;    /* Event: signaled; Mutex: owned; Semaphore: initial count */
    int  manual_reset;     /* Event only */
    int  max_count;        /* Semaphore only */
} obj_create_payload_t;

/* Object open payload (reuses name field) */
typedef struct {
    char    name[260];
    uint8_t type;          /* OBJ_REQ_CREATE_MUTEX/EVENT/SEMAPHORE */
    uint8_t _pad[3];
} obj_open_payload_t;

/* Object close payload */
typedef struct {
    uint32_t handle;       /* Broker-side handle to close */
} obj_close_payload_t;

/* --- Registry payloads --- */

typedef struct {
    uint64_t hkey;         /* Parent key handle (HKEY cast to uint64_t) */
    char     subkey[512];
} reg_open_payload_t;

typedef struct {
    uint64_t hkey;
    char     name[256];
    uint32_t type;         /* REG_SZ, REG_DWORD, etc */
    uint32_t data_len;
    /* data follows immediately after this struct */
} reg_set_value_payload_t;

typedef struct {
    uint64_t hkey;
    char     name[256];
    char     subkey[512];  /* Optional subkey for RegGetValue */
    uint32_t buf_size;     /* Caller's buffer size */
} reg_get_value_payload_t;

/* Response payload for REG_GET_VALUE */
typedef struct {
    uint32_t type;
    uint32_t data_len;
    /* data follows immediately after this struct */
} reg_get_value_response_t;

typedef struct {
    uint64_t hkey;
    uint32_t index;
    uint32_t buf_size;     /* Caller's name buffer size */
} reg_enum_payload_t;

/* Response payload for REG_ENUM_KEY */
typedef struct {
    uint32_t name_len;
    /* name follows immediately */
} reg_enum_key_response_t;

/* Response payload for REG_ENUM_VALUE */
typedef struct {
    uint32_t name_len;
    uint32_t type;
    uint32_t data_len;
    /* name + data follow immediately */
} reg_enum_value_response_t;

typedef struct {
    uint64_t hkey;
    char     name[256];    /* Value name (for delete_value) or subkey (for delete_key) */
} reg_delete_payload_t;

/* --- Namespace payloads --- */

typedef struct {
    char path[512];        /* \Device\Foo or \DosDevices\C: */
} ns_resolve_payload_t;

/* Response payload for NS_RESOLVE */
typedef struct {
    uint32_t path_len;
    /* path follows */
} ns_resolve_response_t;

typedef struct {
    char link_name[512];   /* Symbolic link path */
    char target[512];      /* Target path */
} ns_link_payload_t;

/* Response payload for NS_ENUMERATE */
typedef struct {
    uint32_t count;
    /* entries follow: each is (uint32_t name_len, char name[], uint32_t target_len, char target[]) */
} ns_enumerate_response_t;

#endif /* OBJECTD_PROTOCOL_H */
