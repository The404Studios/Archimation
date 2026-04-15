/*
 * trust_gate.c - Trust-Gated API Interception for PE Loader
 *
 * Bridges the Root of Authority trust kernel module (/dev/trust) with the
 * PE loader's DLL stub layer.  Every Win32 API call that the PE binary
 * makes can be gated through trust_gate_check(), which:
 *
 *   1. Verifies the caller's capability bitmask
 *   2. Checks the trust score against a per-category threshold
 *   3. Burns metabolic tokens proportional to the operation's impact
 *   4. Generates an audit trail for denied/escalated/audited calls
 *
 * Performance strategy:
 *   - Thread-local cache of trust state avoids ioctl overhead
 *   - Cache refreshed every CACHE_TTL_MS milliseconds or CACHE_TTL_CALLS calls
 *   - When /dev/trust is absent, all checks return TRUST_ALLOW (dev mode)
 *   - The availability flag is checked once at init; fast-path skips all work
 *
 * The trust module is optional.  If /dev/trust does not exist (kernel module
 * not loaded), the gate operates in permissive dev mode with zero overhead.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <sys/ioctl.h>

#include "compat/trust_gate.h"
#include "../../trust/include/trust_types.h"
#include "../../trust/include/trust_ioctl.h"

/* ========================================================================
 * Configuration
 * ======================================================================== */

/* Thread-local cache refresh interval */
#define CACHE_TTL_MS     500      /* Refresh cached trust state every 500ms */
#define CACHE_TTL_CALLS  64       /* ... or every 64 API calls, whichever first */

/* Audit log ring buffer size */
#define AUDIT_RING_SIZE  256

/* ========================================================================
 * Capability aliases - map gate categories to TRUST_CAP_* bitmasks
 *
 * These bridge the PE-loader gate categories to the kernel module's
 * 14-bit capability system defined in trust_types.h.
 * ======================================================================== */

#define CAP_FILE_READ       TRUST_CAP_FILE_READ
#define CAP_FILE_WRITE      TRUST_CAP_FILE_WRITE
#define CAP_NET_OUT          TRUST_CAP_NET_CONNECT
#define CAP_NET_IN           TRUST_CAP_NET_LISTEN
#define CAP_EXEC             TRUST_CAP_PROCESS_CREATE
#define CAP_MEM_INJECT       (TRUST_CAP_PROCESS_CREATE | TRUST_CAP_PROCESS_SIGNAL)
#define CAP_THREAD           TRUST_CAP_PROCESS_CREATE
#define CAP_MEM_EXEC         TRUST_CAP_PROCESS_CREATE
#define CAP_REG_READ         TRUST_CAP_REGISTRY_READ
#define CAP_REG_WRITE        TRUST_CAP_REGISTRY_WRITE
#define CAP_DRIVER           TRUST_CAP_KERNEL_CALL
#define CAP_SERVICE          TRUST_CAP_SERVICE_CONTROL
#define CAP_DLL_LOAD         TRUST_CAP_FILE_READ
#define CAP_DEVICE           TRUST_CAP_DEVICE_ACCESS
#define CAP_PRIVILEGE        TRUST_CAP_TRUST_MODIFY
#define CAP_CRYPTO           TRUST_CAP_FILE_READ
#define CAP_SYSINFO          TRUST_CAP_FILE_READ
#define CAP_DEBUG            (TRUST_CAP_PROCESS_SIGNAL | TRUST_CAP_KERNEL_CALL)
#define CAP_CLIPBOARD        TRUST_CAP_FILE_READ
#define CAP_SCREEN           TRUST_CAP_DEVICE_ACCESS
#define CAP_KEYBOARD         TRUST_CAP_DEVICE_ACCESS
#define CAP_ANTITAMPER       TRUST_CAP_KERNEL_CALL

/* ========================================================================
 * Policy table - maps API categories to token costs, score thresholds,
 *                required capabilities, and audit flags.
 *
 * The token costs follow the metabolic cost model from trust_types.h:
 * higher-impact operations burn more tokens, bounding the damage from
 * any single compromised PE binary to C(E)/Cmin operations.
 * ======================================================================== */

static const trust_api_policy_t g_policy_table[TRUST_GATE_MAX] = {
    /* category                       cost  min_score  caps           audit */
    [TRUST_GATE_FILE_READ]       = {"FileRead",        TRUST_GATE_FILE_READ,        1,  10, CAP_FILE_READ,   0},
    [TRUST_GATE_FILE_WRITE]      = {"FileWrite",       TRUST_GATE_FILE_WRITE,       2,  20, CAP_FILE_WRITE,  0},
    [TRUST_GATE_NET_CONNECT]     = {"NetConnect",      TRUST_GATE_NET_CONNECT,      3,  30, CAP_NET_OUT,     0},
    [TRUST_GATE_NET_LISTEN]      = {"NetListen",       TRUST_GATE_NET_LISTEN,       5,  40, CAP_NET_IN,      1},
    [TRUST_GATE_PROCESS_CREATE]  = {"ProcessCreate",   TRUST_GATE_PROCESS_CREATE,   5,  50, CAP_EXEC,        1},
    [TRUST_GATE_PROCESS_INJECT]  = {"ProcessInject",   TRUST_GATE_PROCESS_INJECT,  10,  70, CAP_MEM_INJECT,  1},
    [TRUST_GATE_THREAD_CREATE]   = {"ThreadCreate",    TRUST_GATE_THREAD_CREATE,    2,  15, CAP_THREAD,      0},
    [TRUST_GATE_MEMORY_EXEC]     = {"MemoryExec",      TRUST_GATE_MEMORY_EXEC,      3,  40, CAP_MEM_EXEC,    0},
    [TRUST_GATE_REGISTRY_READ]   = {"RegistryRead",    TRUST_GATE_REGISTRY_READ,    1,   5, CAP_REG_READ,    0},
    [TRUST_GATE_REGISTRY_WRITE]  = {"RegistryWrite",   TRUST_GATE_REGISTRY_WRITE,   2,  25, CAP_REG_WRITE,   0},
    [TRUST_GATE_DRIVER_LOAD]     = {"DriverLoad",      TRUST_GATE_DRIVER_LOAD,     20,  90, CAP_DRIVER,      1},
    [TRUST_GATE_SERVICE_START]   = {"ServiceStart",    TRUST_GATE_SERVICE_START,    8,  60, CAP_SERVICE,     1},
    [TRUST_GATE_DLL_LOAD]        = {"DllLoad",         TRUST_GATE_DLL_LOAD,         1,  10, CAP_DLL_LOAD,    0},
    [TRUST_GATE_DEVICE_IOCTL]    = {"DeviceIoctl",     TRUST_GATE_DEVICE_IOCTL,     5,  50, CAP_DEVICE,      1},
    [TRUST_GATE_PRIVILEGE_ADJUST]= {"PrivilegeAdjust", TRUST_GATE_PRIVILEGE_ADJUST, 15,  80, CAP_PRIVILEGE,   1},
    [TRUST_GATE_CRYPTO_OP]       = {"CryptoOp",        TRUST_GATE_CRYPTO_OP,        1,  10, CAP_CRYPTO,      0},
    [TRUST_GATE_SYSTEM_INFO]     = {"SystemInfo",      TRUST_GATE_SYSTEM_INFO,      1,   5, CAP_SYSINFO,     0},
    [TRUST_GATE_DEBUG_OP]        = {"DebugOp",         TRUST_GATE_DEBUG_OP,         10,  80, CAP_DEBUG,       1},
    [TRUST_GATE_CLIPBOARD]       = {"Clipboard",       TRUST_GATE_CLIPBOARD,        1,  10, CAP_CLIPBOARD,   0},
    [TRUST_GATE_SCREEN_CAPTURE]  = {"ScreenCapture",   TRUST_GATE_SCREEN_CAPTURE,   5,  50, CAP_SCREEN,      1},
    [TRUST_GATE_KEYBOARD_HOOK]   = {"KeyboardHook",    TRUST_GATE_KEYBOARD_HOOK,    8,  70, CAP_KEYBOARD,    1},
    [TRUST_GATE_ANTI_TAMPER]     = {"AntiTamper",      TRUST_GATE_ANTI_TAMPER,      15,  85, CAP_ANTITAMPER,  1},
};

/* Mapping from gate category to TRUST_ACTION_* for kernel ioctl calls.
 * The kernel module uses TRUST_ACTION_* for threshold checks and token
 * burns; we translate our more granular gate categories to the kernel's
 * action types here. */
static const uint32_t g_category_to_action[TRUST_GATE_MAX] = {
    [TRUST_GATE_FILE_READ]        = TRUST_ACTION_FILE_OPEN,
    [TRUST_GATE_FILE_WRITE]       = TRUST_ACTION_FILE_WRITE,
    [TRUST_GATE_NET_CONNECT]      = TRUST_ACTION_NET_CONNECT,
    [TRUST_GATE_NET_LISTEN]       = TRUST_ACTION_NET_LISTEN,
    [TRUST_GATE_PROCESS_CREATE]   = TRUST_ACTION_PROCESS_CREATE,
    [TRUST_GATE_PROCESS_INJECT]   = TRUST_ACTION_PROCESS_SIGNAL,
    [TRUST_GATE_THREAD_CREATE]    = TRUST_ACTION_PROCESS_CREATE,
    [TRUST_GATE_MEMORY_EXEC]      = TRUST_ACTION_PROCESS_CREATE,
    [TRUST_GATE_REGISTRY_READ]    = TRUST_ACTION_REGISTRY_READ,
    [TRUST_GATE_REGISTRY_WRITE]   = TRUST_ACTION_REGISTRY_WRITE,
    [TRUST_GATE_DRIVER_LOAD]      = TRUST_ACTION_DEVICE_OPEN,
    [TRUST_GATE_SERVICE_START]    = TRUST_ACTION_SERVICE_START,
    [TRUST_GATE_DLL_LOAD]         = TRUST_ACTION_FILE_OPEN,
    [TRUST_GATE_DEVICE_IOCTL]     = TRUST_ACTION_DEVICE_OPEN,
    [TRUST_GATE_PRIVILEGE_ADJUST] = TRUST_ACTION_ESCALATE,
    [TRUST_GATE_CRYPTO_OP]        = TRUST_ACTION_FILE_OPEN,
    [TRUST_GATE_SYSTEM_INFO]      = TRUST_ACTION_FILE_OPEN,
    [TRUST_GATE_DEBUG_OP]         = TRUST_ACTION_PROCESS_SIGNAL,
    [TRUST_GATE_CLIPBOARD]        = TRUST_ACTION_FILE_OPEN,
    [TRUST_GATE_SCREEN_CAPTURE]   = TRUST_ACTION_DEVICE_OPEN,
    [TRUST_GATE_KEYBOARD_HOOK]    = TRUST_ACTION_DEVICE_OPEN,
    [TRUST_GATE_ANTI_TAMPER]      = TRUST_ACTION_TRUST_CHANGE,
};

/* ========================================================================
 * Global state
 * ======================================================================== */

static int      g_trust_fd    = -1;   /* fd for /dev/trust */
static int      g_available   = 0;    /* 1 = kernel module present */
static int      g_debug       = 0;    /* TRUST_GATE_DEBUG env var */
static uint32_t g_subject_id  = 0;    /* Our PID, registered with trust module */

static pthread_mutex_t g_init_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_initialized = 0;

/* ========================================================================
 * Thread-local trust state cache
 *
 * Each thread maintains a cached snapshot of the subject's trust score,
 * capability bitmask, and token balance.  The cache is refreshed when
 * either CACHE_TTL_MS milliseconds have elapsed or CACHE_TTL_CALLS
 * API checks have been performed, whichever comes first.
 *
 * This avoids an ioctl syscall on every Win32 API call.  In the common
 * case (trust score unchanged, plenty of tokens), the check is a
 * simple comparison against cached values.
 * ======================================================================== */

typedef struct {
    int32_t  trust_score;
    uint32_t capabilities;
    int32_t  token_balance;
    int32_t  token_max;
    uint64_t refresh_ts_ms;    /* Monotonic timestamp of last refresh */
    uint32_t calls_since;      /* API calls since last refresh */
    int      valid;            /* 0 = cache needs population */
} trust_cache_t;

static __thread trust_cache_t tl_cache = { .valid = 0 };

/* ========================================================================
 * Audit ring buffer
 *
 * Denied, escalated, and always-audit API calls are logged here.
 * The ring buffer is lock-free for the single-writer (trust_gate_check)
 * and can be read by the AI daemon via a future /proc or socket interface.
 * ======================================================================== */

typedef struct {
    uint64_t timestamp_ms;
    uint32_t category;
    uint32_t result;       /* trust_gate_result_t */
    int32_t  score_at_time;
    int32_t  tokens_at_time;
    char     api_name[48];
    char     arg_summary[80];
} audit_entry_t;

static audit_entry_t g_audit_ring[AUDIT_RING_SIZE];
static volatile uint32_t g_audit_head = 0;  /* Next write position */

/* ========================================================================
 * Internal helpers
 * ======================================================================== */

/* Get monotonic time in milliseconds */
static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* Refresh the thread-local cache from the kernel module */
static void cache_refresh(void)
{
    if (!g_available || g_trust_fd < 0) {
        tl_cache.trust_score   = TRUST_SCORE_DEFAULT;
        tl_cache.capabilities  = TRUST_CAPS_USER;
        tl_cache.token_balance = TRUST_TOKEN_MAX_DEFAULT;
        tl_cache.token_max     = TRUST_TOKEN_MAX_DEFAULT;
        tl_cache.refresh_ts_ms = now_ms();
        tl_cache.calls_since   = 0;
        tl_cache.valid         = 1;
        return;
    }

    /* Fetch full subject state in one ioctl */
    trust_ioc_get_subject_t req;
    memset(&req, 0, sizeof(req));
    req.subject_id = g_subject_id;

    if (ioctl(g_trust_fd, TRUST_IOC_GET_SUBJECT, &req) == 0) {
        tl_cache.trust_score   = req.subject.trust_score;
        tl_cache.capabilities  = req.subject.capabilities;
        tl_cache.token_balance = req.subject.tokens.balance;
        tl_cache.token_max     = req.subject.tokens.max_balance;
    } else {
        /* ioctl failed - use safe defaults, don't block the PE binary */
        tl_cache.trust_score   = TRUST_SCORE_DEFAULT;
        tl_cache.capabilities  = TRUST_CAPS_USER;
        tl_cache.token_balance = TRUST_TOKEN_MAX_DEFAULT;
        tl_cache.token_max     = TRUST_TOKEN_MAX_DEFAULT;
    }

    tl_cache.refresh_ts_ms = now_ms();
    tl_cache.calls_since   = 0;
    tl_cache.valid         = 1;
}

/* Check if cache needs refresh */
static inline void cache_ensure_fresh(void)
{
    if (!tl_cache.valid) {
        cache_refresh();
        return;
    }

    tl_cache.calls_since++;
    if (tl_cache.calls_since >= CACHE_TTL_CALLS) {
        cache_refresh();
        return;
    }

    uint64_t elapsed = now_ms() - tl_cache.refresh_ts_ms;
    if (elapsed >= CACHE_TTL_MS) {
        cache_refresh();
    }
}

/* Write an audit entry to the ring buffer */
static void audit_log(trust_gate_category_t category,
                       trust_gate_result_t result,
                       const char *api_name,
                       const char *arg_summary)
{
    uint32_t idx = __sync_fetch_and_add(&g_audit_head, 1) % AUDIT_RING_SIZE;
    audit_entry_t *e = &g_audit_ring[idx];

    e->timestamp_ms   = now_ms();
    e->category       = (uint32_t)category;
    e->result         = (uint32_t)result;
    e->score_at_time  = tl_cache.trust_score;
    e->tokens_at_time = tl_cache.token_balance;

    if (api_name) {
        strncpy(e->api_name, api_name, sizeof(e->api_name) - 1);
        e->api_name[sizeof(e->api_name) - 1] = '\0';
    } else {
        e->api_name[0] = '\0';
    }

    if (arg_summary) {
        strncpy(e->arg_summary, arg_summary, sizeof(e->arg_summary) - 1);
        e->arg_summary[sizeof(e->arg_summary) - 1] = '\0';
    } else {
        e->arg_summary[0] = '\0';
    }

    if (g_debug) {
        const char *result_str =
            result == TRUST_ALLOW  ? "ALLOW" :
            result == TRUST_DENY   ? "DENY" :
            result == TRUST_AUDIT  ? "AUDIT" :
            result == TRUST_ESCALATE ? "ESCALATE" : "?";

        fprintf(stderr, "[trust_gate] %s %s (score=%d tokens=%d cat=%u)%s%s\n",
                result_str,
                api_name ? api_name : g_policy_table[category].api_name,
                tl_cache.trust_score, tl_cache.token_balance,
                (unsigned)category,
                arg_summary ? " arg=" : "",
                arg_summary ? arg_summary : "");
    }
}

/* Burn tokens via kernel ioctl.
 * Returns 0 on success, -1 if starved (not enough tokens). */
static int burn_tokens(trust_gate_category_t category)
{
    if (!g_available || g_trust_fd < 0)
        return 0;  /* Dev mode - no token cost */

    uint32_t action = g_category_to_action[category];

    trust_ioc_token_burn_t req;
    memset(&req, 0, sizeof(req));
    req.subject_id  = g_subject_id;
    req.action_type = action;

    if (ioctl(g_trust_fd, TRUST_IOC_TOKEN_BURN, &req) < 0)
        return 0;  /* ioctl error - fail open */

    /* Update thread-local cache with new balance */
    tl_cache.token_balance = req.remaining;

    /* -ENOSPC from the kernel means token starvation */
    if (req.result != 0)
        return -1;

    return 0;
}

/* Perform the slow-path check via kernel ioctl.
 * Called when the fast-path cache indicates potential denial or
 * when the cache is unable to make a definitive decision. */
static trust_gate_result_t slow_path_check(trust_gate_category_t category,
                                            const trust_api_policy_t *policy)
{
    (void)policy;
    if (!g_available || g_trust_fd < 0)
        return TRUST_ALLOW;

    uint32_t action = g_category_to_action[category];

    /* Full policy evaluation through the kernel's FBC complex-path */
    trust_ioc_policy_eval_t peval;
    memset(&peval, 0, sizeof(peval));
    peval.subject_id  = g_subject_id;
    peval.action_type = action;
    peval.result      = TRUST_RESULT_DENY;

    if (ioctl(g_trust_fd, TRUST_IOC_POLICY_EVAL, &peval) < 0)
        return TRUST_ALLOW;  /* ioctl error - fail open */

    /* Refresh the cache after a kernel round-trip since the kernel
     * may have updated the subject's state */
    cache_refresh();

    switch (peval.result) {
    case TRUST_RESULT_ALLOW:
        return TRUST_ALLOW;
    case TRUST_RESULT_DENY:
        return TRUST_DENY;
    case TRUST_RESULT_ESCALATE:
        return TRUST_ESCALATE;
    default:
        return TRUST_DENY;
    }
}

/* ========================================================================
 * Public API
 * ======================================================================== */

int trust_gate_init(void)
{
    pthread_mutex_lock(&g_init_lock);

    if (g_initialized) {
        pthread_mutex_unlock(&g_init_lock);
        return g_available ? 0 : -1;
    }

    /* Check for debug mode */
    const char *dbg = getenv("TRUST_GATE_DEBUG");
    if (dbg && dbg[0] != '0')
        g_debug = 1;

    /* Try to open /dev/trust */
    g_trust_fd = open("/dev/trust", O_RDWR | O_CLOEXEC);
    if (g_trust_fd < 0) {
        /* Kernel module not loaded - operate in permissive dev mode.
         * All trust_gate_check() calls will return TRUST_ALLOW with
         * zero overhead (just a branch on g_available). */
        g_available = 0;
        g_initialized = 1;

        if (g_debug)
            fprintf(stderr, "[trust_gate] /dev/trust not available - "
                    "operating in permissive dev mode\n");

        pthread_mutex_unlock(&g_init_lock);
        return -1;
    }

    g_available = 1;
    g_subject_id = (uint32_t)getpid();

    if (g_debug)
        fprintf(stderr, "[trust_gate] Initialized: fd=%d subject=%u\n",
                g_trust_fd, g_subject_id);

    g_initialized = 1;
    pthread_mutex_unlock(&g_init_lock);
    return 0;
}

void trust_gate_shutdown(void)
{
    pthread_mutex_lock(&g_init_lock);

    if (g_available && g_trust_fd >= 0) {
        /* Unregister our subject before closing */
        trust_ioc_unregister_t unreg;
        unreg.subject_id = g_subject_id;
        ioctl(g_trust_fd, TRUST_IOC_UNREGISTER, &unreg);

        close(g_trust_fd);
        g_trust_fd = -1;
    }

    g_available = 0;
    g_initialized = 0;

    pthread_mutex_unlock(&g_init_lock);
}

int trust_gate_register_pe(const char *exe_path, uint32_t image_hash)
{
    if (!g_available || g_trust_fd < 0)
        return 0;  /* Dev mode - no-op success */

    g_subject_id = (uint32_t)getpid();

    /* Register as a Win32-domain user-level subject */
    trust_ioc_register_t reg;
    memset(&reg, 0, sizeof(reg));
    reg.subject_id    = g_subject_id;
    reg.domain        = TRUST_DOMAIN_WIN32;
    reg.authority     = TRUST_AUTH_USER;
    reg.initial_score = 0;  /* 0 = use kernel default (TRUST_SCORE_DEFAULT) */

    if (ioctl(g_trust_fd, TRUST_IOC_REGISTER, &reg) < 0) {
        if (g_debug)
            fprintf(stderr, "[trust_gate] Failed to register PE subject %u: %s\n",
                    g_subject_id, strerror(errno));
        return -1;
    }

    /* Mint an initial proof token for the proof chain.
     * The proof chain authenticates every subsequent trust operation. */
    trust_ioc_proof_mint_t mint;
    memset(&mint, 0, sizeof(mint));
    mint.subject_id = g_subject_id;

    if (ioctl(g_trust_fd, TRUST_IOC_PROOF_MINT, &mint) < 0) {
        if (g_debug)
            fprintf(stderr, "[trust_gate] Proof mint failed (non-fatal): %s\n",
                    strerror(errno));
        /* Non-fatal: subject is registered but proof chain is not active.
         * The kernel module will still do score/cap checks. */
    }

    /* Record the registration action */
    trust_ioc_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.subject_id  = g_subject_id;
    rec.action_type = TRUST_ACTION_FILE_OPEN;
    rec.result      = 0;
    ioctl(g_trust_fd, TRUST_IOC_RECORD_ACTION, &rec);

    /* Prime the thread-local cache */
    cache_refresh();

    if (g_debug)
        fprintf(stderr, "[trust_gate] Registered PE: pid=%u exe=%s hash=0x%08x "
                "score=%d caps=0x%08x tokens=%d\n",
                g_subject_id,
                exe_path ? exe_path : "(null)",
                image_hash,
                tl_cache.trust_score,
                tl_cache.capabilities,
                tl_cache.token_balance);

    return 0;
}

trust_gate_result_t trust_gate_check(trust_gate_category_t category,
                                      const char *api_name,
                                      const char *arg_summary)
{
    /* Fast exit: if trust module is not loaded, allow everything.
     * This is the zero-overhead path for dev mode. */
    if (!g_available)
        return TRUST_ALLOW;

    /* Bounds check the category */
    if ((unsigned)category >= TRUST_GATE_MAX)
        return TRUST_DENY;

    const trust_api_policy_t *policy = &g_policy_table[category];

    /* Ensure our thread-local cache is fresh */
    cache_ensure_fresh();

    /* ---- Fast-path check against cached state ---- */

    /* 1. Capability check: does the subject have the required caps? */
    uint32_t missing_caps = policy->required_caps & ~tl_cache.capabilities;
    if (missing_caps) {
        /* Missing capabilities - this is a hard deny.
         * No amount of trust score can override missing caps. */
        audit_log(category, TRUST_DENY, api_name, arg_summary);

        /* Record the denial with the kernel */
        if (g_trust_fd >= 0) {
            trust_ioc_record_t rec;
            memset(&rec, 0, sizeof(rec));
            rec.subject_id  = g_subject_id;
            rec.action_type = g_category_to_action[category];
            rec.result      = 1;  /* failure */
            ioctl(g_trust_fd, TRUST_IOC_RECORD_ACTION, &rec);
        }

        return TRUST_DENY;
    }

    /* 2. Score threshold check (fast-path: compare against cached score) */
    if (tl_cache.trust_score < (int32_t)policy->min_trust_score) {
        /* Score too low.  Before denying, do a slow-path check in case
         * the cache is stale and the kernel has updated our score. */
        trust_gate_result_t slow_result = slow_path_check(category, policy);

        if (slow_result != TRUST_ALLOW) {
            audit_log(category, slow_result, api_name, arg_summary);
            return slow_result;
        }
        /* Slow path allowed it - the cache was stale.  Fall through. */
    }

    /* 3. Token burn: consume metabolic tokens for this operation */
    if (burn_tokens(category) < 0) {
        /* Token starvation.  The subject has exhausted its metabolic
         * budget.  Deny the operation but don't permanently revoke caps;
         * tokens will regenerate over time. */
        audit_log(category, TRUST_DENY, api_name, arg_summary);
        return TRUST_DENY;
    }

    /* 4. Record successful action with the kernel (updates trust score) */
    if (g_trust_fd >= 0) {
        trust_ioc_record_t rec;
        memset(&rec, 0, sizeof(rec));
        rec.subject_id  = g_subject_id;
        rec.action_type = g_category_to_action[category];
        rec.result      = 0;  /* success */
        ioctl(g_trust_fd, TRUST_IOC_RECORD_ACTION, &rec);
    }

    /* 5. Always-audit APIs get logged even on success */
    if (policy->audit_always) {
        audit_log(category, TRUST_AUDIT, api_name, arg_summary);
        return TRUST_AUDIT;
    }

    return TRUST_ALLOW;
}

int trust_gate_get_score(int32_t *score_out)
{
    if (!score_out)
        return -1;

    if (!g_available) {
        *score_out = TRUST_SCORE_DEFAULT;
        return 0;
    }

    cache_ensure_fresh();
    *score_out = tl_cache.trust_score;
    return 0;
}

int trust_gate_get_tokens(uint32_t *balance_out)
{
    if (!balance_out)
        return -1;

    if (!g_available) {
        *balance_out = TRUST_TOKEN_MAX_DEFAULT;
        return 0;
    }

    cache_ensure_fresh();
    *balance_out = (uint32_t)tl_cache.token_balance;
    return 0;
}

int trust_gate_check_batch(const trust_gate_category_t *categories,
                           int count, trust_gate_result_t *results)
{
    if (!categories || !results || count <= 0)
        return -1;

    /* Fast exit for dev mode */
    if (!g_available) {
        for (int i = 0; i < count; i++)
            results[i] = TRUST_ALLOW;
        return 0;
    }

    /* Refresh cache once for the whole batch */
    cache_refresh();

    /* Check each category.  For batch operations we only do fast-path
     * checks and a single kernel round-trip for the token burn.
     * If any individual check needs a slow-path, we fall back to
     * individual trust_gate_check() for that entry. */
    for (int i = 0; i < count; i++) {
        trust_gate_category_t cat = categories[i];

        if ((unsigned)cat >= TRUST_GATE_MAX) {
            results[i] = TRUST_DENY;
            continue;
        }

        const trust_api_policy_t *policy = &g_policy_table[cat];

        /* Capability check */
        uint32_t missing = policy->required_caps & ~tl_cache.capabilities;
        if (missing) {
            results[i] = TRUST_DENY;
            continue;
        }

        /* Score threshold check */
        if (tl_cache.trust_score < (int32_t)policy->min_trust_score) {
            /* Use slow path for this specific entry */
            results[i] = slow_path_check(cat, policy);
            continue;
        }

        /* Token burn */
        if (burn_tokens(cat) < 0) {
            results[i] = TRUST_DENY;
            continue;
        }

        results[i] = policy->audit_always ? TRUST_AUDIT : TRUST_ALLOW;
    }

    return 0;
}
