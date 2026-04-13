# Phase 1: Event Bus + Object Broker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the foundation layer (Layer 1) and event communication protocol that all other layers depend on.

**Architecture:** A lightweight C daemon (pe-objectd) provides cross-process Windows shared state (named objects, registry, device namespace). A shared library (libpe-event) provides lock-free event emission from PE processes to the AI Cortex. Unix domain sockets for IPC, shared memory + futex for zero-overhead synchronization.

**Tech Stack:** C (POSIX), Unix domain sockets, shared memory (shm_open/mmap), futex, pthreads, lock-free ring buffers

---

## File Structure

### New files to create:

```
pe-loader/include/eventbus/
  pe_event.h              — Event frame format, type enums, emission API

pe-loader/loader/
  pe_event.c              — Lock-free ring buffer + socket drain thread

services/objectd/
  objectd_main.c          — Object broker daemon entry point
  objectd_objects.c       — Named object management (create/open/close/wait)
  objectd_registry.c      — Registry hive hosting (migrated from pe-loader/registry/)
  objectd_namespace.c     — Device namespace (\Device\*, \DosDevices\*)
  objectd_protocol.h      — Wire protocol definitions (request/response)
  objectd_shm.c           — Shared memory allocation for futex-based sync
  Makefile                — Build pe-objectd binary
```

### Files to modify:

```
pe-loader/Makefile                         — Add pe_event.c to LOADER_SRCS, add -lrt for shm
pe-loader/loader/main.c                    — Initialize event system, emit PE_LOAD events
pe-loader/dlls/kernel32/kernel32_sync.c    — Named objects delegate to broker
pe-loader/dlls/common/dll_common.h         — Add HANDLE_TYPE_BROKER_OBJECT
services/Makefile                          — Add objectd build target
```

---

### Task 1: Event Frame Protocol Header

**Files:**
- Create: `pe-loader/include/eventbus/pe_event.h`

- [ ] **Step 1:** Create the event protocol header with frame format, event types, and emission API

The event frame is 64 bytes fixed header + variable payload. All layers speak this protocol.

```c
/* pe_event.h — Universal event protocol for all layers */
#ifndef PE_EVENT_H
#define PE_EVENT_H

#include <stdint.h>
#include <time.h>

#define PE_EVENT_MAGIC 0x45564E54  /* "EVNT" */
#define PE_EVENT_VERSION 1

/* Source layers */
#define PE_EVENT_SRC_KERNEL   0
#define PE_EVENT_SRC_BROKER   1
#define PE_EVENT_SRC_RUNTIME  2
#define PE_EVENT_SRC_SCM      3
#define PE_EVENT_SRC_CORTEX   4

/* Event types — PE Runtime (source=2) */
#define PE_EVT_LOAD              0x01
#define PE_EVT_DLL_LOAD          0x02
#define PE_EVT_UNIMPLEMENTED_API 0x03
#define PE_EVT_EXCEPTION         0x04
#define PE_EVT_EXIT              0x05
#define PE_EVT_TRUST_DENY        0x06
#define PE_EVT_TRUST_ESCALATE    0x07
#define PE_EVT_DRIVER_LOAD       0x08
#define PE_EVT_DEVICE_CREATE     0x09

/* Event types — Object Broker (source=1) */
#define OBJ_EVT_CREATE           0x01
#define OBJ_EVT_DESTROY          0x02
#define OBJ_EVT_CONTENTION       0x03
#define OBJ_EVT_REGISTRY_WRITE   0x04
#define OBJ_EVT_REGISTRY_DELETE  0x05
#define OBJ_EVT_DEVICE_ARRIVE    0x06
#define OBJ_EVT_DEVICE_REMOVE    0x07

/* Event types — Service Fabric (source=3) */
#define SVC_EVT_INSTALL          0x01
#define SVC_EVT_START            0x02
#define SVC_EVT_STOP             0x03
#define SVC_EVT_CRASH            0x04
#define SVC_EVT_RESTART          0x05
#define SVC_EVT_DEPENDENCY_FAIL  0x06

/* Event types — Trust (source=0) */
#define TRUST_EVT_SCORE_CHANGE   0x01
#define TRUST_EVT_TOKEN_STARVE   0x02
#define TRUST_EVT_IMMUNE_ALERT   0x03
#define TRUST_EVT_QUARANTINE     0x04
#define TRUST_EVT_APOPTOSIS      0x05
#define TRUST_EVT_TRC_CHANGE     0x06

/* Event types — Cortex (source=4) */
#define CORTEX_EVT_DECISION      0x01
#define CORTEX_EVT_AUTONOMY      0x02
#define CORTEX_EVT_OVERRIDE      0x03
#define CORTEX_EVT_POLICY        0x04

/* Flags */
#define PE_EVENT_FLAG_URGENT          0x0001
#define PE_EVENT_FLAG_AUDIT           0x0002
#define PE_EVENT_FLAG_REPLY_REQUESTED 0x0004

/* Fixed 64-byte event header */
typedef struct __attribute__((packed)) {
    uint32_t magic;          /* PE_EVENT_MAGIC */
    uint16_t version;        /* PE_EVENT_VERSION */
    uint8_t  source_layer;   /* PE_EVENT_SRC_* */
    uint8_t  event_type;     /* Per-source event type enum */
    uint64_t timestamp_ns;   /* CLOCK_BOOTTIME nanoseconds */
    uint32_t pid;            /* Source process ID */
    uint32_t tid;            /* Source thread ID */
    uint32_t subject_id;     /* Trust subject ID */
    uint64_t sequence;       /* Monotonic per-source */
    uint16_t payload_len;    /* Bytes of payload following header */
    uint16_t flags;          /* PE_EVENT_FLAG_* */
    uint8_t  reserved[12];
} pe_event_header_t;

_Static_assert(sizeof(pe_event_header_t) == 64, "Event header must be 64 bytes");

/* Maximum event size (header + payload) */
#define PE_EVENT_MAX_SIZE 4096

/* Common payload structures */
typedef struct {
    char exe_path[256];
    uint32_t imports_resolved;
    uint32_t imports_unresolved;
    int32_t trust_score;
    uint32_t token_budget;
} pe_evt_load_t;

typedef struct {
    char dll_name[64];
    uint32_t resolved;
    uint32_t unresolved;
} pe_evt_dll_load_t;

typedef struct {
    char dll_name[64];
    char func_name[128];
} pe_evt_unimplemented_t;

typedef struct {
    uint32_t exit_code;
    uint32_t stubs_called;
    uint32_t runtime_ms;
} pe_evt_exit_t;

typedef struct {
    char api_name[128];
    uint8_t category;
    int32_t score;
    uint32_t tokens;
} pe_evt_trust_deny_t;

/* ---- Emission API ---- */

/* Initialize the event system (call once from main.c) */
int pe_event_init(void);

/* Shutdown (drain remaining events, close socket) */
void pe_event_shutdown(void);

/* Emit an event (non-blocking, lock-free, fire-and-forget) */
int pe_event_emit(uint8_t event_type, const void *payload, uint16_t payload_len);

/* Emit with custom flags */
int pe_event_emit_flags(uint8_t event_type, const void *payload,
                        uint16_t payload_len, uint16_t flags);

#endif /* PE_EVENT_H */
```

- [ ] **Step 2:** Verify header compiles: `gcc -fsyntax-only -I. pe_event.h`

---

### Task 2: Lock-Free Event Emitter

**Files:**
- Create: `pe-loader/loader/pe_event.c`
- Modify: `pe-loader/Makefile` (add to LOADER_SRCS)

- [ ] **Step 1:** Implement the lock-free ring buffer + drain thread

The ring buffer holds 4096 event frames. A background thread drains events to the cortex Unix domain socket. If the cortex isn't listening or the buffer is full, events are silently dropped. The PE process NEVER blocks.

Key design:
- Ring buffer: 4096 slots x 4096 bytes = 16MB (pre-allocated)
- Atomic head/tail for lock-free SPSC (single-producer-single-consumer per thread)
- Actually: use a global atomic counter for multi-producer, drain thread is single consumer
- Socket: `/run/pe-compat/events.sock` (datagram)
- Drain thread: wakes every 1ms or when buffer crosses 25% full

- [ ] **Step 2:** Add `loader/pe_event.c` to LOADER_SRCS in Makefile, add `-lrt` to LDFLAGS

- [ ] **Step 3:** Wire pe_event_init() and pe_event_shutdown() into main.c

- [ ] **Step 4:** Add PE_EVT_LOAD emission after successful PE load in main.c

- [ ] **Step 5:** Add PE_EVT_EXIT emission before cleanup in main.c

- [ ] **Step 6:** Build and verify: `make clean && make`

---

### Task 3: Object Broker Protocol

**Files:**
- Create: `services/objectd/objectd_protocol.h`

- [ ] **Step 1:** Define the wire protocol for broker IPC

Request/response over Unix domain socket (stream mode). 32-byte header + variable payload.

```c
/* objectd_protocol.h — Wire protocol for pe-objectd */
#ifndef OBJECTD_PROTOCOL_H
#define OBJECTD_PROTOCOL_H

#include <stdint.h>

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
#define OBJ_STATUS_OK            0x00
#define OBJ_STATUS_NOT_FOUND     0x01
#define OBJ_STATUS_ALREADY_EXISTS 0x02
#define OBJ_STATUS_ACCESS_DENIED 0x03
#define OBJ_STATUS_NO_MEMORY     0x04
#define OBJ_STATUS_INVALID       0x05

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
} objectd_response_t;

_Static_assert(sizeof(objectd_response_t) == 32, "Response header must be 32 bytes");

/* Object creation payloads */
typedef struct {
    char name[260];        /* Object name */
    int  initial_state;    /* Event: signaled; Mutex: owned; Semaphore: initial count */
    int  manual_reset;     /* Event only */
    int  max_count;        /* Semaphore only */
} obj_create_payload_t;

/* Registry payloads */
typedef struct {
    uint64_t hkey;         /* Parent key handle */
    char     subkey[512];
} reg_open_payload_t;

typedef struct {
    uint64_t hkey;
    char     name[256];
    uint32_t type;         /* REG_SZ, REG_DWORD, etc */
    uint32_t data_len;
    /* data follows */
} reg_set_value_payload_t;

typedef struct {
    uint64_t hkey;
    char     name[256];
    uint32_t type;         /* Out: type */
    uint32_t data_len;     /* In: buffer size; Out: actual size */
    /* data follows in response */
} reg_get_value_payload_t;

/* Namespace payloads */
typedef struct {
    char path[512];        /* \Device\Foo or \DosDevices\C: */
} ns_resolve_payload_t;

typedef struct {
    char link_name[512];   /* Symbolic link path */
    char target[512];      /* Target path */
} ns_link_payload_t;

#endif /* OBJECTD_PROTOCOL_H */
```

---

### Task 4: Object Broker Daemon — Core

**Files:**
- Create: `services/objectd/objectd_main.c`
- Create: `services/objectd/objectd_objects.c`
- Create: `services/objectd/objectd_shm.c`

- [ ] **Step 1:** Implement objectd_main.c — daemon entry point

Responsibilities:
- Create /run/pe-compat/ directory
- Bind Unix domain socket at /run/pe-compat/objects.sock
- Accept connections (one thread per client, or epoll reactor)
- Dispatch requests to handler functions
- Clean shutdown on SIGTERM

- [ ] **Step 2:** Implement objectd_objects.c — named object management

Core data structure:
```c
#define MAX_NAMED_OBJECTS 4096

typedef struct {
    char     name[260];
    uint8_t  type;            /* OBJ_REQ_CREATE_MUTEX/EVENT/SEMAPHORE */
    uint32_t owner_pid;       /* Creator */
    uint32_t ref_count;       /* Number of processes with handles */
    char     shm_name[64];   /* /dev/shm path for futex page */
    int      shm_fd;          /* File descriptor for shared memory */
    void    *shm_ptr;         /* Mapped pointer (broker side) */
    /* Initial state stored in shared memory page */
} named_object_t;
```

Operations:
- create: allocate shm page, initialize sync state, register in table
- open: find by name, increment ref_count, return shm_fd via SCM_RIGHTS
- close: decrement ref_count, destroy when zero
- Emit OBJ_EVT_CREATE/DESTROY events

- [ ] **Step 3:** Implement objectd_shm.c — shared memory management

For each named sync object, allocate a shared memory page:
```c
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
```

PE processes receive the shm_fd via SCM_RIGHTS, mmap it, and use futex() directly. Zero broker involvement on wait/signal paths.

---

### Task 5: Object Broker — Registry Hosting

**Files:**
- Create: `services/objectd/objectd_registry.c`
- Modify: `pe-loader/registry/registry.c` (remains as the backend, loaded by objectd)

- [ ] **Step 1:** Implement objectd_registry.c

The broker hosts the registry. It loads the existing registry.c code as its backend:
- REG_OPEN/REG_CREATE: call registry_open_key/registry_create_key
- REG_SET_VALUE/REG_GET_VALUE: call registry_set_value/registry_get_value
- REG_ENUM_KEY/REG_ENUM_VALUE: call registry_enum_key/registry_enum_value
- REG_DELETE: call registry_delete_key/registry_delete_value
- Emit OBJ_EVT_REGISTRY_WRITE events on writes

The registry.c functions already work with file-backed storage. The broker just wraps them with the socket protocol and trust checks.

- [ ] **Step 2:** Add trust checking on HKLM writes (require elevated trust score)

---

### Task 6: Object Broker — Device Namespace

**Files:**
- Create: `services/objectd/objectd_namespace.c`

- [ ] **Step 1:** Implement device namespace resolution

Maintains a table mapping Windows device paths to Linux paths or broker-managed devices:
```c
typedef struct {
    char win_path[512];    /* \Device\HarddiskVolume1 */
    char linux_path[512];  /* / */
    int  is_symlink;       /* 1 if this is a symlink to another win_path */
} ns_entry_t;
```

Default entries populated on init:
```
\Device\Null           → /dev/null
\Device\KsecDD         → /dev/urandom
\DosDevices\C:         → /
\DosDevices\Z:         → $HOME
\??\PIPE\              → /tmp/pe-compat/pipes/
```

Operations: resolve, create_symlink, delete_symlink, enumerate

---

### Task 7: Object Broker Makefile + Build Integration

**Files:**
- Create: `services/objectd/Makefile`
- Modify: `services/Makefile` (add objectd target)

- [ ] **Step 1:** Create objectd Makefile

```makefile
CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -I../../pe-loader/include -I../../pe-loader/registry
LDFLAGS = -lpthread -lrt

SRCS = objectd_main.c objectd_objects.c objectd_registry.c \
       objectd_namespace.c objectd_shm.c \
       ../../pe-loader/registry/registry.c
OBJS = $(SRCS:.c=.o)

pe-objectd: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJS) pe-objectd
```

- [ ] **Step 2:** Add to services/Makefile: `all: ... objectd`

- [ ] **Step 3:** Full build test: `make clean && make` from project root

---

### Task 8: Client Library for PE Processes

**Files:**
- Create: `pe-loader/loader/objectd_client.c`
- Create: `pe-loader/include/compat/objectd_client.h`

- [ ] **Step 1:** Implement the client library that PE processes use to talk to the broker

```c
/* objectd_client.h */
int objectd_connect(void);   /* Connect to broker, returns 0 on success */
void objectd_disconnect(void);

/* Named objects */
int objectd_create_mutex(const char *name, int initial_owner, int *shm_fd_out);
int objectd_create_event(const char *name, int manual_reset, int initial_state, int *shm_fd_out);
int objectd_create_semaphore(const char *name, int initial, int max, int *shm_fd_out);
int objectd_open_object(const char *name, int type, int *shm_fd_out);
int objectd_close_object(uint32_t broker_handle);

/* Registry */
int objectd_reg_open(uint64_t parent, const char *subkey, uint64_t *handle_out);
int objectd_reg_create(uint64_t parent, const char *subkey, uint64_t *handle_out);
int objectd_reg_close(uint64_t handle);
int objectd_reg_set_value(uint64_t handle, const char *name, uint32_t type,
                           const void *data, uint32_t len);
int objectd_reg_get_value(uint64_t handle, const char *name, uint32_t *type_out,
                           void *data_out, uint32_t *len_inout);
int objectd_reg_enum_key(uint64_t handle, uint32_t index, char *name, uint32_t *len);
int objectd_reg_enum_value(uint64_t handle, uint32_t index, char *name, uint32_t *name_len,
                            uint32_t *type, void *data, uint32_t *data_len);

/* Namespace */
int objectd_ns_resolve(const char *path, char *linux_path_out, int linux_path_len);
```

Connection is established lazily on first call. Socket fd cached in thread-local or global.

- [ ] **Step 2:** Add to LOADER_SRCS in pe-loader/Makefile

---

### Task 9: Wire Named Objects to Broker

**Files:**
- Modify: `pe-loader/dlls/kernel32/kernel32_sync.c`

- [ ] **Step 1:** Modify CreateMutexA/CreateEventA/CreateSemaphoreA

When a `name` parameter is non-NULL, delegate to the broker instead of the local hash table:

```c
HANDLE WINAPI_EXPORT CreateMutexA(void *sa, BOOL initial, LPCSTR name)
{
    if (name && name[0]) {
        /* Named mutex → broker */
        int shm_fd = -1;
        int ret = objectd_create_mutex(name, initial, &shm_fd);
        if (ret == OBJ_STATUS_ALREADY_EXISTS) {
            SetLastError(ERROR_ALREADY_EXISTS);
        }
        if (shm_fd >= 0) {
            /* mmap the shared page, create local handle wrapping it */
            void *shm = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, shm_fd, 0);
            close(shm_fd);
            /* Allocate handle with shm pointer as data */
            return handle_alloc(HANDLE_TYPE_MUTEX, -1, shm);
        }
        /* Fallback to local if broker not available */
    }
    /* Unnamed: existing local implementation */
    ...
}
```

- [ ] **Step 2:** Modify WaitForSingleObject for broker-backed objects

When the handle data points to a shared memory page, use futex() directly:
```c
/* For broker-backed mutex: */
shm_mutex_t *m = (shm_mutex_t *)handle_entry->data;
while (atomic_exchange(&m->futex_word, getpid()) != 0) {
    syscall(SYS_futex, &m->futex_word, FUTEX_WAIT, getpid(), timeout, NULL, 0);
}
```

- [ ] **Step 3:** Modify OpenMutexA/OpenEventA/OpenSemaphoreA to call objectd_open_object

---

### Task 10: Wire Registry to Broker

**Files:**
- Modify: `pe-loader/dlls/advapi32/advapi32_registry.c`

- [ ] **Step 1:** Modify RegOpenKeyExA/RegCreateKeyExA to call broker

When broker is available, delegate:
```c
LONG WINAPI_EXPORT RegOpenKeyExA(HKEY hKey, LPCSTR subkey, DWORD opts, REGSAM access, HKEY *result)
{
    if (objectd_available()) {
        uint64_t parent = (uint64_t)(uintptr_t)hKey;
        uint64_t child = 0;
        int ret = objectd_reg_open(parent, subkey, &child);
        if (ret == OBJ_STATUS_OK) {
            *result = (HKEY)(uintptr_t)child;
            return ERROR_SUCCESS;
        }
        return ERROR_FILE_NOT_FOUND;
    }
    /* Fallback: direct registry access */
    return registry_open_key(hKey, subkey, result);
}
```

- [ ] **Step 2:** Similarly modify RegSetValueExA, RegQueryValueExA, RegEnumKeyExA, RegEnumValueA, RegCloseKey

---

## Implementation Order

Tasks 1-2 (Event Bus) and Tasks 3-6 (Object Broker core) are independent and can be built in parallel.

Tasks 7 (build) depends on 3-6.
Task 8 (client lib) depends on 3.
Tasks 9-10 (wiring) depend on 8.

```
[Task 1: Event Header] ──→ [Task 2: Event Emitter] ──→ [Wire into main.c]
                                                              ↓
[Task 3: Protocol] ──→ [Task 4: Broker Core] ──→ [Task 7: Build]
                  ──→ [Task 5: Registry]     ──→      ↓
                  ──→ [Task 6: Namespace]    ──→ [Task 8: Client Lib]
                                                      ↓
                                               [Task 9: Named Objs]
                                               [Task 10: Registry Wire]
```
