/*
 * cortex_cmd.h - PE Loader <-> AI Cortex Command Channel Protocol
 *
 * The event bus (pe_event.h) is fire-and-forget datagrams for telemetry.
 * The command channel is request/response over a Unix stream socket for
 * decisions that MUST be answered before the PE binary can proceed.
 *
 * Primary use case: PE load approval handshake.  Before a PE binary
 * loads, the loader asks the cortex for permission.  The cortex
 * responds with a verdict, token budget, capability mask, and priority.
 *
 * If the cortex is not running (socket missing or connection refused),
 * the loader falls back to permissive defaults -- never blocks.
 *
 * Socket path: /run/pe-compat/cortex-cmd.sock (Unix stream)
 */

#ifndef CORTEX_CMD_H
#define CORTEX_CMD_H

#include <stdint.h>

#define CORTEX_CMD_SOCK "/run/pe-compat/cortex-cmd.sock"
#define CORTEX_CMD_MAGIC 0x43545843  /* "CTXC" */

/* Command types */
#define CORTEX_CMD_PE_LOAD_REQUEST  0x01
#define CORTEX_CMD_PE_LOAD_RESPONSE 0x02
#define CORTEX_CMD_QUERY_STATUS     0x03
#define CORTEX_CMD_STATUS_RESPONSE  0x04

/* Response verdicts */
#define CORTEX_VERDICT_ALLOW     0
#define CORTEX_VERDICT_DENY      1
#define CORTEX_VERDICT_MODIFY    2  /* Allow with modified parameters */

/* Request: PE wants to load (peloader -> cortex) */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t  cmd_type;       /* CORTEX_CMD_PE_LOAD_REQUEST */
    uint8_t  _pad[3];
    uint32_t pid;
    uint32_t uid;
    char     exe_path[512];
    uint32_t subsystem;      /* PE subsystem (GUI=2, CONSOLE=3, NATIVE=1) */
    uint32_t import_count;   /* Number of DLL imports */
} cortex_pe_load_request_t;

/* Response: Cortex decision (cortex -> peloader) */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t  cmd_type;       /* CORTEX_CMD_PE_LOAD_RESPONSE */
    uint8_t  verdict;        /* CORTEX_VERDICT_* */
    uint8_t  _pad[2];
    uint32_t token_budget;   /* Assigned trust token budget */
    uint32_t capabilities;   /* Capability bitmask */
    int32_t  priority;       /* Nice value suggestion */
    char     deny_reason[256]; /* If denied, why */
} cortex_pe_load_response_t;

/* Connect to cortex command channel (blocking, with timeout).
 * Returns file descriptor on success, -1 if cortex is not reachable. */
int cortex_cmd_connect(int timeout_ms);

/* Close a command channel connection by fd (no global state). */
void cortex_cmd_disconnect_fd(int fd);

/* Request PE load approval (blocks until response or timeout).
 * On success, fills *response and returns 0.
 * On timeout, error, or cortex unavailable, fills response with
 * ALLOW + default budget (graceful degradation) and returns -1. */
int cortex_request_pe_load(const char *exe_path, uint32_t subsystem,
                            uint32_t import_count,
                            cortex_pe_load_response_t *response);

#endif /* CORTEX_CMD_H */
