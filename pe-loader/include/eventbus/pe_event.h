/*
 * pe_event.h - Universal event protocol for all layers
 *
 * Defines the event frame format used by every layer in the PE-compat
 * stack to communicate with the AI Cortex.  Events flow one-way from
 * producers (PE runtime, object broker, service fabric, trust kernel
 * module) to the cortex daemon via a Unix datagram socket.
 *
 * The event frame is a fixed 64-byte header followed by a variable-length
 * payload.  The header contains enough metadata for the cortex to route,
 * filter, and correlate events without parsing the payload.
 *
 * Emission API (pe_event_emit) is lock-free and non-blocking.  Events
 * are buffered in a ring buffer and drained to the cortex socket by a
 * background thread.  If the cortex is not listening or the buffer is
 * full, events are silently dropped.  The PE process NEVER blocks.
 *
 * Usage in PE loader:
 *   #include "eventbus/pe_event.h"
 *
 *   pe_event_init();
 *   pe_evt_load_t payload = { .exe_path = "foo.exe", ... };
 *   pe_event_emit(PE_EVT_LOAD, &payload, sizeof(payload));
 *   pe_event_shutdown();
 */

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

/* Event types -- PE Runtime (source=2) */
#define PE_EVT_LOAD              0x01
#define PE_EVT_DLL_LOAD          0x02
#define PE_EVT_UNIMPLEMENTED_API 0x03
#define PE_EVT_EXCEPTION         0x04
#define PE_EVT_EXIT              0x05
#define PE_EVT_TRUST_DENY        0x06
#define PE_EVT_TRUST_ESCALATE    0x07
#define PE_EVT_DRIVER_LOAD       0x08
#define PE_EVT_DEVICE_CREATE     0x09

/* Event types -- Object Broker (source=1) */
#define OBJ_EVT_CREATE           0x01
#define OBJ_EVT_DESTROY          0x02
#define OBJ_EVT_CONTENTION       0x03
#define OBJ_EVT_REGISTRY_WRITE   0x04
#define OBJ_EVT_REGISTRY_DELETE  0x05
#define OBJ_EVT_DEVICE_ARRIVE    0x06
#define OBJ_EVT_DEVICE_REMOVE    0x07

/* Event types -- Service Fabric (source=3) */
#define SVC_EVT_INSTALL          0x01
#define SVC_EVT_START            0x02
#define SVC_EVT_STOP             0x03
#define SVC_EVT_CRASH            0x04
#define SVC_EVT_RESTART          0x05
#define SVC_EVT_DEPENDENCY_FAIL  0x06

/* Event types -- Trust (source=0) */
#define TRUST_EVT_SCORE_CHANGE   0x01
#define TRUST_EVT_TOKEN_STARVE   0x02
#define TRUST_EVT_IMMUNE_ALERT   0x03
#define TRUST_EVT_QUARANTINE     0x04
#define TRUST_EVT_APOPTOSIS      0x05
#define TRUST_EVT_TRC_CHANGE     0x06

/* Event types -- Cortex (source=4) */
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
    uint8_t  reserved[24];
} pe_event_header_t;

_Static_assert(sizeof(pe_event_header_t) == 64, "Event header must be 64 bytes");

/* Maximum event size (header + payload) */
#define PE_EVENT_MAX_SIZE 4096

/* ========================================================================
 * Common payload structures
 * ======================================================================== */

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

/* ========================================================================
 * Emission API
 * ======================================================================== */

/* Initialize the event system (call once from main.c).
 * Opens datagram socket to /run/pe-compat/events.sock, starts drain thread.
 * Returns 0 on success, -1 if events are unavailable (graceful degradation). */
int pe_event_init(void);

/* Shutdown (drain remaining events, close socket).
 * Signals the drain thread to stop, joins it, closes the socket. */
void pe_event_shutdown(void);

/* Emit an event (non-blocking, lock-free, fire-and-forget).
 * Returns 0 on success, -1 if event system unavailable or buffer full. */
int pe_event_emit(uint8_t event_type, const void *payload, uint16_t payload_len);

/* Emit with custom flags.
 * Returns 0 on success, -1 if event system unavailable or buffer full. */
int pe_event_emit_flags(uint8_t event_type, const void *payload,
                        uint16_t payload_len, uint16_t flags);

#endif /* PE_EVENT_H */
