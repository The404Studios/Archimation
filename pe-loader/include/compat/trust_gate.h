/*
 * trust_gate.h - Trust-Gated API Interception for PE Loader
 *
 * Every Windows API call from a PE binary passes through the trust gate.
 * The gate checks capabilities, consumes metabolic tokens, and generates
 * an audit trail via the Root of Authority kernel module (/dev/trust).
 *
 * This is the bridge between the trust kernel module (trust.ko) and
 * the PE execution layer (DLL stubs).
 *
 * Usage in DLL stubs:
 *   #include "compat/trust_gate.h"
 *
 *   WINAPI_EXPORT HANDLE CreateFileA(LPCSTR lpFileName, ...) {
 *       TRUST_CHECK_RET(TRUST_GATE_FILE_READ, "CreateFileA",
 *                        INVALID_HANDLE_VALUE);
 *       // ... actual implementation ...
 *   }
 */

#ifndef TRUST_GATE_H
#define TRUST_GATE_H

#include <stdint.h>

/* Trust gate categories - map to token costs and capability requirements.
 * Each category groups related Win32 APIs by their security impact. */
typedef enum {
    TRUST_GATE_FILE_READ       = 0,
    TRUST_GATE_FILE_WRITE      = 1,
    TRUST_GATE_NET_CONNECT     = 2,
    TRUST_GATE_NET_LISTEN      = 3,
    TRUST_GATE_PROCESS_CREATE  = 4,
    TRUST_GATE_PROCESS_INJECT  = 5,
    TRUST_GATE_THREAD_CREATE   = 6,
    TRUST_GATE_MEMORY_EXEC     = 7,
    TRUST_GATE_REGISTRY_READ   = 8,
    TRUST_GATE_REGISTRY_WRITE  = 9,
    TRUST_GATE_DRIVER_LOAD     = 10,
    TRUST_GATE_SERVICE_START   = 11,
    TRUST_GATE_DLL_LOAD        = 12,
    TRUST_GATE_DEVICE_IOCTL    = 13,
    TRUST_GATE_PRIVILEGE_ADJUST = 14,
    TRUST_GATE_CRYPTO_OP       = 15,
    TRUST_GATE_SYSTEM_INFO     = 16,
    TRUST_GATE_DEBUG_OP        = 17,
    TRUST_GATE_CLIPBOARD       = 18,
    TRUST_GATE_SCREEN_CAPTURE  = 19,
    TRUST_GATE_KEYBOARD_HOOK   = 20,
    TRUST_GATE_ANTI_TAMPER     = 21,
    TRUST_GATE_MAX             = 22
} trust_gate_category_t;

/* Gate check result */
typedef enum {
    TRUST_ALLOW    = 0,
    TRUST_DENY     = 1,
    TRUST_AUDIT    = 2,  /* Allow but audit */
    TRUST_ESCALATE = 3   /* Need higher authority - request sent to AI observer */
} trust_gate_result_t;

/* Per-API trust metadata.
 * Policies can be looked up by category or by specific API name. */
typedef struct {
    const char              *api_name;
    trust_gate_category_t    category;
    uint32_t                 token_cost;       /* Metabolic tokens consumed per call */
    uint32_t                 min_trust_score;  /* Minimum trust score required */
    uint32_t                 required_caps;    /* TRUST_CAP_* bitmask required */
    uint8_t                  audit_always;     /* Always generate audit entry */
} trust_api_policy_t;

/* Initialize trust gate system.
 * Opens /dev/trust, registers PE binary as trust subject.
 * Returns 0 on success, -1 if /dev/trust not available (dev mode). */
int trust_gate_init(void);

/* Close trust gate and release resources. */
void trust_gate_shutdown(void);

/* Check if an API call is allowed.
 * Performs capability check, score threshold check, token burn.
 * arg_summary is optional context for the audit log (e.g., filename). */
trust_gate_result_t trust_gate_check(trust_gate_category_t category,
                                      const char *api_name,
                                      const char *arg_summary);

/* Register the PE binary's trust subject.
 * Called during loader init with the exe path and a hash of the PE image.
 * The image_hash feeds into the B-segment (construction identity DNA). */
int trust_gate_register_pe(const char *exe_path, uint32_t image_hash);

/* Get current trust state for logging/diagnostics. */
int trust_gate_get_score(int32_t *score_out);
int trust_gate_get_tokens(uint32_t *balance_out);

/* Bulk check for batch operations (e.g., multi-file copy).
 * Submits multiple category checks, fills results array.
 * Returns 0 on success, -1 on error. */
int trust_gate_check_batch(const trust_gate_category_t *categories,
                           int count, trust_gate_result_t *results);

/*
 * Trust-aware wrapper macros for DLL stubs.
 *
 * TRUST_CHECK: Check and deny with SetLastError(ERROR_ACCESS_DENIED),
 *              return 0 (FALSE) on denial.
 *
 * TRUST_CHECK_RET: Same but returns a custom value on denial
 *                  (e.g., INVALID_HANDLE_VALUE, NULL, -1).
 *
 * These macros are designed to be used at the top of ms_abi DLL stub
 * functions. They call SetLastError which is exported by kernel32.
 */

/* Forward declaration - SetLastError is in kernel32_error.c */
extern void __attribute__((ms_abi)) SetLastError(uint32_t dwErrCode);

#ifndef ERROR_ACCESS_DENIED
#define ERROR_ACCESS_DENIED 5
#endif

#define TRUST_CHECK(cat, name) do { \
    trust_gate_result_t __tg_r = trust_gate_check((cat), (name), NULL); \
    if (__tg_r == TRUST_DENY) { \
        SetLastError(ERROR_ACCESS_DENIED); \
        return 0; \
    } \
} while (0)

#define TRUST_CHECK_RET(cat, name, retval) do { \
    trust_gate_result_t __tg_r = trust_gate_check((cat), (name), NULL); \
    if (__tg_r == TRUST_DENY) { \
        SetLastError(ERROR_ACCESS_DENIED); \
        return (retval); \
    } \
} while (0)

/* Variant with argument summary for audit trail */
#define TRUST_CHECK_ARG(cat, name, arg) do { \
    trust_gate_result_t __tg_r = trust_gate_check((cat), (name), (arg)); \
    if (__tg_r == TRUST_DENY) { \
        SetLastError(ERROR_ACCESS_DENIED); \
        return 0; \
    } \
} while (0)

#define TRUST_CHECK_ARG_RET(cat, name, arg, retval) do { \
    trust_gate_result_t __tg_r = trust_gate_check((cat), (name), (arg)); \
    if (__tg_r == TRUST_DENY) { \
        SetLastError(ERROR_ACCESS_DENIED); \
        return (retval); \
    } \
} while (0)

#endif /* TRUST_GATE_H */
