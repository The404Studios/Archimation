/*
 * process_integrity.c - Process integrity faking for anti-cheat compatibility
 *
 * Anti-cheat systems perform various process integrity checks to detect
 * debuggers, injectors, and tampering. This module spoofs the results of
 * these checks to present the process as a clean, unmodified Windows
 * environment.
 *
 * Spoofed checks:
 *   - IsDebuggerPresent() -> FALSE
 *   - NtGlobalFlag -> 0 (no debug heap)
 *   - ProcessDebugPort -> 0 (no debugger attached)
 *   - ProcessDebugObjectHandle -> STATUS_PORT_NOT_SET
 *   - ProcessDebugFlags -> 1 (PROCESS_DEBUG_INHERIT = not being debugged)
 *   - Code signing / integrity level information
 *   - PsSetCreateProcessNotifyRoutine callback results
 *
 * This is a userspace implementation that provides the expected return
 * values for Windows NT API queries related to process integrity.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>

/*
 * Anti-cheats almost always have a background worker thread probing modules
 * while the main thread is registering freshly-loaded DLLs. Previously this
 * module had zero synchronization: two threads racing into
 * integrity_check_module() would both read num_modules==k, both write slot
 * k, and corrupt the hash. Worse, integrity_fake_signature() returns a
 * cert pointer into modules[idx]; if a racing check_module grows the table
 * and rewrites that slot the caller gets torn cert strings. A single
 * coarse mutex is adequate because these are cold paths compared to e.g.
 * the ACG access-check hot path. */
static pthread_mutex_t g_integrity_lock = PTHREAD_MUTEX_INITIALIZER;

#define INTEGRITY_LOG_PREFIX    "[anticheat/integrity] "
#define MAX_MODULES             256
#define MAX_PATH_LEN            4096

/* Windows integrity levels */
#define SECURITY_MANDATORY_UNTRUSTED_RID        0x0000
#define SECURITY_MANDATORY_LOW_RID              0x1000
#define SECURITY_MANDATORY_MEDIUM_RID           0x2000
#define SECURITY_MANDATORY_MEDIUM_PLUS_RID      0x2100
#define SECURITY_MANDATORY_HIGH_RID             0x3000
#define SECURITY_MANDATORY_SYSTEM_RID           0x4000
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID 0x5000

/* NtQueryInformationProcess information classes we spoof */
#define ProcessBasicInformation         0
#define ProcessDebugPort                7
#define ProcessWow64Information         26
#define ProcessImageFileName            27
#define ProcessDebugObjectHandle        30
#define ProcessDebugFlags               31
#define ProcessHandleTracing            32

/* NTSTATUS values */
#define STATUS_SUCCESS                  0x00000000
#define STATUS_INFO_LENGTH_MISMATCH     0xC0000004
#define STATUS_PORT_NOT_SET             0xC0000353
#define STATUS_INVALID_PARAMETER        0xC000000D
#define STATUS_BUFFER_TOO_SMALL        0xC0000023

/* Boolean values matching Windows conventions */
#define FALSE   0
#define TRUE    1

/* Fake code signing certificate info */
typedef struct {
    char    subject[256];
    char    issuer[256];
    char    serial[64];
    char    thumbprint[64];
    int     valid;
} fake_cert_info_t;

/* Module integrity entry */
typedef struct {
    char    name[MAX_PATH_LEN];
    char    path[MAX_PATH_LEN];
    int     signed_valid;       /* 1 if module appears validly signed */
    int     integrity_ok;       /* 1 if integrity check passes */
    fake_cert_info_t cert;
} module_entry_t;

/* Module-name -> modules[] index hash for O(1) dedup in integrity_check_module.
 * Anti-cheats often probe 30-100+ modules during startup; the original O(N)
 * scan was the dominant cost on 1GB/1-core HW. */
#define MOD_HASH_BUCKETS 512
#define MOD_HASH_EMPTY   -1

/* Process integrity state */
typedef struct {
    int             initialized;
    int             integrity_level;    /* SECURITY_MANDATORY_*_RID */
    int             is_debugger_present;
    int             nt_global_flag;
    int             process_debug_port;
    int             process_debug_flags;
    int             process_debug_object_handle_status;
    module_entry_t  modules[MAX_MODULES];
    int             num_modules;
    int             mod_hash[MOD_HASH_BUCKETS];   /* -1 or modules[] index */
    fake_cert_info_t process_cert;      /* Certificate for the main process */
} integrity_state_t;

static integrity_state_t g_integrity = {0};

static unsigned int mod_hash_name(const char *name)
{
    unsigned int h = 5381;
    while (*name) {
        unsigned char c = (unsigned char)*name++;
        if (c >= 'A' && c <= 'Z') c += 32;
        h = ((h << 5) + h) + c;
    }
    return h % MOD_HASH_BUCKETS;
}

static void mod_hash_reset(void)
{
    for (int i = 0; i < MOD_HASH_BUCKETS; i++)
        g_integrity.mod_hash[i] = MOD_HASH_EMPTY;
}

static int mod_hash_lookup(const char *name)
{
    unsigned int bucket = mod_hash_name(name);
    for (unsigned int step = 0; step < MOD_HASH_BUCKETS; step++) {
        unsigned int probe = (bucket + step) % MOD_HASH_BUCKETS;
        int idx = g_integrity.mod_hash[probe];
        if (idx == MOD_HASH_EMPTY)
            return -1;
        if (idx >= 0 && idx < g_integrity.num_modules &&
            strcasecmp(g_integrity.modules[idx].name, name) == 0) {
            return idx;
        }
    }
    return -1;
}

static void mod_hash_insert(const char *name, int idx)
{
    unsigned int bucket = mod_hash_name(name);
    for (unsigned int step = 0; step < MOD_HASH_BUCKETS; step++) {
        unsigned int probe = (bucket + step) % MOD_HASH_BUCKETS;
        if (g_integrity.mod_hash[probe] == MOD_HASH_EMPTY) {
            g_integrity.mod_hash[probe] = idx;
            return;
        }
    }
}

/* Forward declarations */
static void setup_default_certificate(fake_cert_info_t *cert, const char *subject);
static int  spoof_nt_query_information(int info_class, void *buffer, int buffer_size,
                                        int *return_length);

/* --- Internal helpers --- */

/*
 * Set up a fake but plausible code-signing certificate.
 * Anti-cheats check that the game process and its modules are signed
 * by expected publishers.
 *
 * The constant fields (issuer/serial/thumbprint) live in rodata as a
 * single template and are memcpy'd in.  Previously each of ~256 module
 * registrations re-ran strncpy three times for the same constants.
 */
static const char CERT_ISSUER_DIGICERT[] =
    "DigiCert SHA2 Assured ID Code Signing CA";
static const char CERT_SERIAL_DEFAULT[]  =
    "0A:1B:2C:3D:4E:5F:6A:7B:8C:9D";
static const char CERT_THUMBPRINT_DEFAULT[] =
    "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0";

static void setup_default_certificate(fake_cert_info_t *cert, const char *subject)
{
    memset(cert, 0, sizeof(*cert));
    strncpy(cert->subject, subject, sizeof(cert->subject) - 1);
    /* memcpy from rodata templates (sizeof includes NUL) */
    memcpy(cert->issuer, CERT_ISSUER_DIGICERT,
           sizeof(CERT_ISSUER_DIGICERT) < sizeof(cert->issuer)
               ? sizeof(CERT_ISSUER_DIGICERT) : sizeof(cert->issuer) - 1);
    memcpy(cert->serial, CERT_SERIAL_DEFAULT,
           sizeof(CERT_SERIAL_DEFAULT) < sizeof(cert->serial)
               ? sizeof(CERT_SERIAL_DEFAULT) : sizeof(cert->serial) - 1);
    memcpy(cert->thumbprint, CERT_THUMBPRINT_DEFAULT,
           sizeof(CERT_THUMBPRINT_DEFAULT) < sizeof(cert->thumbprint)
               ? sizeof(CERT_THUMBPRINT_DEFAULT) : sizeof(cert->thumbprint) - 1);
    cert->valid = 1;

    fprintf(stderr, INTEGRITY_LOG_PREFIX "Set up certificate: subject=\"%s\", "
            "issuer=\"%s\"\n", cert->subject, cert->issuer);
}

/*
 * Spoof NtQueryInformationProcess results.
 * This is called when the anti-cheat queries process debug information
 * through the NT native API.
 */
static int spoof_nt_query_information(int info_class, void *buffer, int buffer_size,
                                       int *return_length)
{
    switch (info_class) {

    case ProcessDebugPort:
        /*
         * ProcessDebugPort: returns a DWORD_PTR that is non-zero if a
         * debugger is attached. We always report 0 (no debugger).
         */
        if (buffer) {
            if (buffer_size < (int)sizeof(long))
                return STATUS_BUFFER_TOO_SMALL;
            *(long *)buffer = 0;
            fprintf(stderr, INTEGRITY_LOG_PREFIX "ProcessDebugPort -> 0 "
                    "(no debugger)\n");
        }
        if (return_length)
            *return_length = sizeof(long);
        return STATUS_SUCCESS;

    case ProcessDebugObjectHandle:
        /*
         * ProcessDebugObjectHandle: returns STATUS_PORT_NOT_SET if no
         * debug object is associated with the process (i.e., not being
         * debugged). A debugger would cause STATUS_SUCCESS with a handle.
         */
        fprintf(stderr, INTEGRITY_LOG_PREFIX "ProcessDebugObjectHandle -> "
                "STATUS_PORT_NOT_SET\n");
        return STATUS_PORT_NOT_SET;

    case ProcessDebugFlags:
        /*
         * ProcessDebugFlags: returns PROCESS_DEBUG_INHERIT flag.
         * If 0, the process is being debugged. We return 1 (not debugged).
         */
        if (buffer) {
            if (buffer_size < (int)sizeof(int))
                return STATUS_BUFFER_TOO_SMALL;
            *(int *)buffer = 1;
            fprintf(stderr, INTEGRITY_LOG_PREFIX "ProcessDebugFlags -> 1 "
                    "(not debugged)\n");
        }
        if (return_length)
            *return_length = sizeof(int);
        return STATUS_SUCCESS;

    case ProcessBasicInformation:
        /*
         * ProcessBasicInformation: we zero-fill, which is safe.
         * The PEB address and other fields are handled by the PE loader.
         */
        if (buffer) {
            if (buffer_size <= 0)
                return STATUS_BUFFER_TOO_SMALL;
            memset(buffer, 0, buffer_size);
        }
        if (return_length)
            *return_length = buffer_size;
        fprintf(stderr, INTEGRITY_LOG_PREFIX "ProcessBasicInformation -> "
                "zeroed (clean)\n");
        return STATUS_SUCCESS;

    case ProcessHandleTracing:
        /*
         * ProcessHandleTracing: anti-cheats use this to detect if handle
         * tracing is enabled (indicates debugging). We return not-set.
         */
        fprintf(stderr, INTEGRITY_LOG_PREFIX "ProcessHandleTracing -> "
                "STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;

    default:
        fprintf(stderr, INTEGRITY_LOG_PREFIX "Unknown info class %d, "
                "returning STATUS_INVALID_PARAMETER\n", info_class);
        return STATUS_INVALID_PARAMETER;
    }
}

/* --- Public API --- */

/*
 * integrity_init - Initialize process integrity spoofing
 *
 * Sets up the default state that anti-cheat systems expect to see:
 *   - Medium integrity level (standard user process)
 *   - No debugger present
 *   - Clean NtGlobalFlag
 *   - Valid process certificate
 *
 * Returns 0 on success.
 */
int integrity_init(void)
{
    if (g_integrity.initialized) {
        fprintf(stderr, INTEGRITY_LOG_PREFIX "Already initialized\n");
        return 0;
    }

    fprintf(stderr, INTEGRITY_LOG_PREFIX "Initializing process integrity spoofing\n");

    memset(&g_integrity, 0, sizeof(g_integrity));
    mod_hash_reset();

    /*
     * Set default values matching a clean Windows process:
     *   - Medium integrity level (normal user process)
     *   - IsDebuggerPresent = FALSE
     *   - NtGlobalFlag = 0 (no FLG_HEAP_ENABLE_TAIL_CHECK etc.)
     *   - ProcessDebugPort = 0
     *   - ProcessDebugFlags = 1 (not inherited debug)
     *   - ProcessDebugObjectHandle -> STATUS_PORT_NOT_SET
     */
    g_integrity.integrity_level = SECURITY_MANDATORY_MEDIUM_RID;
    g_integrity.is_debugger_present = FALSE;
    g_integrity.nt_global_flag = 0;
    g_integrity.process_debug_port = 0;
    g_integrity.process_debug_flags = 1;
    g_integrity.process_debug_object_handle_status = STATUS_PORT_NOT_SET;
    g_integrity.num_modules = 0;

    /* Set up a default process certificate */
    setup_default_certificate(&g_integrity.process_cert, "Game Application");

    g_integrity.initialized = 1;

    fprintf(stderr, INTEGRITY_LOG_PREFIX "Process integrity initialized:\n");
    fprintf(stderr, INTEGRITY_LOG_PREFIX "  Integrity level: 0x%04X (MEDIUM)\n",
            g_integrity.integrity_level);
    fprintf(stderr, INTEGRITY_LOG_PREFIX "  IsDebuggerPresent: FALSE\n");
    fprintf(stderr, INTEGRITY_LOG_PREFIX "  NtGlobalFlag: 0x%08X\n",
            g_integrity.nt_global_flag);
    fprintf(stderr, INTEGRITY_LOG_PREFIX "  ProcessDebugPort: %d\n",
            g_integrity.process_debug_port);
    fprintf(stderr, INTEGRITY_LOG_PREFIX "  ProcessDebugFlags: %d\n",
            g_integrity.process_debug_flags);

    return 0;
}

/*
 * integrity_get_level - Get the spoofed integrity level
 *
 * Returns the Windows integrity level RID that we report to anti-cheat.
 * Default is SECURITY_MANDATORY_MEDIUM_RID (0x2000).
 */
int integrity_get_level(void)
{
    if (!g_integrity.initialized) {
        fprintf(stderr, INTEGRITY_LOG_PREFIX "integrity_get_level: not initialized, "
                "returning MEDIUM\n");
        return SECURITY_MANDATORY_MEDIUM_RID;
    }

    fprintf(stderr, INTEGRITY_LOG_PREFIX "Integrity level query: 0x%04X\n",
            g_integrity.integrity_level);
    return g_integrity.integrity_level;
}

/*
 * integrity_check_module - Check/register a module for integrity verification
 *
 * @module_name: Short name of the module (e.g., "kernel32.dll")
 * @module_path: Full path to the module
 *
 * Anti-cheats verify that loaded modules are signed and unmodified.
 * This function registers a module and sets up fake integrity data
 * so that subsequent checks pass.
 *
 * Returns 1 if the module is "valid" (always returns valid for known modules),
 * 0 if not found or error.
 */
int integrity_check_module(const char *module_name, const char *module_path)
{
    if (!g_integrity.initialized) {
        fprintf(stderr, INTEGRITY_LOG_PREFIX "integrity_check_module: not initialized\n");
        return 0;
    }

    if (!module_name) {
        fprintf(stderr, INTEGRITY_LOG_PREFIX "integrity_check_module: null module name\n");
        return 0;
    }

    fprintf(stderr, INTEGRITY_LOG_PREFIX "Module integrity check: %s\n", module_name);

    pthread_mutex_lock(&g_integrity_lock);

    /* O(1) hash lookup instead of linear scan.  Modules are typically
     * re-checked many times during anti-cheat lifecycle. */
    int existing = mod_hash_lookup(module_name);
    if (existing >= 0) {
        int ok = g_integrity.modules[existing].integrity_ok;
        pthread_mutex_unlock(&g_integrity_lock);
        fprintf(stderr, INTEGRITY_LOG_PREFIX "  Module already registered, "
                "integrity=%s\n", ok ? "OK" : "FAIL");
        return ok;
    }

    /* Register new module */
    if (g_integrity.num_modules >= MAX_MODULES) {
        pthread_mutex_unlock(&g_integrity_lock);
        fprintf(stderr, INTEGRITY_LOG_PREFIX "  Module table full, "
                "reporting as valid anyway\n");
        return 1;
    }

    int new_idx = g_integrity.num_modules;
    module_entry_t *mod = &g_integrity.modules[new_idx];
    memset(mod, 0, sizeof(*mod));

    strncpy(mod->name, module_name, sizeof(mod->name) - 1);
    if (module_path)
        strncpy(mod->path, module_path, sizeof(mod->path) - 1);

    /* All modules pass integrity checks in our environment */
    mod->signed_valid = 1;
    mod->integrity_ok = 1;

    /* Set up a plausible certificate for the module */
    setup_default_certificate(&mod->cert, "Microsoft Windows");

    g_integrity.num_modules++;
    mod_hash_insert(mod->name, new_idx);

    int registered_count = g_integrity.num_modules;
    pthread_mutex_unlock(&g_integrity_lock);

    fprintf(stderr, INTEGRITY_LOG_PREFIX "  Registered module #%d: %s -> VALID\n",
            registered_count, module_name);

    return 1;
}

/*
 * integrity_fake_signature - Get fake code signing information
 *
 * @module_name: Module to get signature for (NULL for process itself)
 * @subject:     Output buffer for certificate subject (at least 256 bytes)
 * @issuer:      Output buffer for certificate issuer (at least 256 bytes)
 * @thumbprint:  Output buffer for certificate thumbprint (at least 64 bytes)
 *
 * Fills in fake but plausible code signing certificate information
 * that anti-cheat systems check via WinVerifyTrust or similar APIs.
 *
 * Returns 1 if signature information was provided, 0 on error.
 */
int integrity_fake_signature(const char *module_name, char *subject,
                              char *issuer, char *thumbprint)
{
    if (!g_integrity.initialized) {
        fprintf(stderr, INTEGRITY_LOG_PREFIX "integrity_fake_signature: "
                "not initialized\n");
        return 0;
    }

    /* Snapshot the cert under the lock; never hand a pointer back into the
     * shared table because a racing integrity_check_module() can rewrite
     * that slot under us (we would then strncpy from torn cert strings).
     * Copy into a local, release the lock, then do the output copies and
     * logging. Also guarantees NUL termination in the caller's buffers,
     * which strncpy() alone does not. */
    fake_cert_info_t snap;

    pthread_mutex_lock(&g_integrity_lock);
    if (!module_name) {
        snap = g_integrity.process_cert;
    } else {
        int idx = mod_hash_lookup(module_name);
        if (idx >= 0)
            snap = g_integrity.modules[idx].cert;
        else
            snap = g_integrity.process_cert;
    }
    pthread_mutex_unlock(&g_integrity_lock);

    if (subject) {
        strncpy(subject, snap.subject, 255);
        subject[255] = '\0';
    }
    if (issuer) {
        strncpy(issuer, snap.issuer, 255);
        issuer[255] = '\0';
    }
    if (thumbprint) {
        strncpy(thumbprint, snap.thumbprint, 63);
        thumbprint[63] = '\0';
    }

    fprintf(stderr, INTEGRITY_LOG_PREFIX "Signature query for %s\n",
            module_name ? module_name : "main process");
    fprintf(stderr, INTEGRITY_LOG_PREFIX "  Subject: %s\n", snap.subject);
    fprintf(stderr, INTEGRITY_LOG_PREFIX "  Issuer:  %s\n", snap.issuer);
    fprintf(stderr, INTEGRITY_LOG_PREFIX "  Valid:   %s\n",
            snap.valid ? "YES" : "NO");

    return snap.valid;
}

/*
 * integrity_query_process_info - Handle NtQueryInformationProcess calls
 *
 * @info_class:    ProcessInformationClass value
 * @buffer:        Output buffer
 * @buffer_size:   Size of output buffer
 * @return_length: Receives actual data size (can be NULL)
 *
 * This is called by our ntdll shim when a game (or anti-cheat) calls
 * NtQueryInformationProcess. We intercept debug-related queries and
 * return clean values.
 *
 * Returns NTSTATUS value.
 */
int integrity_query_process_info(int info_class, void *buffer, int buffer_size,
                                  int *return_length)
{
    if (!g_integrity.initialized) {
        fprintf(stderr, INTEGRITY_LOG_PREFIX "integrity_query_process_info: "
                "not initialized, initializing now\n");
        integrity_init();
    }

    fprintf(stderr, INTEGRITY_LOG_PREFIX "NtQueryInformationProcess "
            "class=%d, bufsize=%d\n", info_class, buffer_size);

    return spoof_nt_query_information(info_class, buffer, buffer_size, return_length);
}

/*
 * integrity_is_debugger_present - Spoofed IsDebuggerPresent check
 *
 * Always returns FALSE (0) to indicate no debugger is attached.
 * This matches what kernel32!IsDebuggerPresent reads from the PEB.
 */
int integrity_is_debugger_present(void)
{
    fprintf(stderr, INTEGRITY_LOG_PREFIX "IsDebuggerPresent -> FALSE\n");
    return FALSE;
}

/*
 * integrity_get_nt_global_flag - Spoofed NtGlobalFlag value
 *
 * Returns 0. When a debugger is attached, Windows sets flags like:
 *   FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
 *   FLG_HEAP_ENABLE_FREE_CHECK (0x20)
 *   FLG_HEAP_VALIDATE_PARAMETERS (0x40)
 * We return 0 to indicate no debugging flags are set.
 */
int integrity_get_nt_global_flag(void)
{
    fprintf(stderr, INTEGRITY_LOG_PREFIX "NtGlobalFlag -> 0x00000000\n");
    return 0;
}

/*
 * integrity_notify_process_create - Fake PsSetCreateProcessNotifyRoutine callback
 *
 * @pid:            Process ID of the new process
 * @parent_pid:     Parent process ID
 * @process_name:   Name of the new process
 * @is_create:      1 for creation, 0 for termination
 *
 * Anti-cheat kernel drivers register for process creation notifications.
 * This function simulates the callback, reporting the process as clean
 * (not a known cheat tool, debugger, or injector).
 *
 * Returns 1 if the process is "allowed", 0 if it would be blocked.
 * In our implementation, all processes are allowed.
 */
int integrity_notify_process_create(int pid, int parent_pid,
                                     const char *process_name, int is_create)
{
    fprintf(stderr, INTEGRITY_LOG_PREFIX "Process %s notification: "
            "PID=%d, ParentPID=%d, Name=%s\n",
            is_create ? "create" : "terminate",
            pid, parent_pid,
            process_name ? process_name : "(unknown)");

    /* Always report the process as clean/allowed */
    fprintf(stderr, INTEGRITY_LOG_PREFIX "  Result: ALLOWED (clean process)\n");
    return 1;
}
