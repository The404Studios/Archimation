/*
 * anticheat_guard.c - Cross-process protection for anti-cheat-protected games
 *
 * Provides the server-side enforcement component of the anti-cheat system.
 * Protected game processes are registered by PID, and all cross-process
 * access attempts (memory reads, handle creation, thread injection) are
 * validated against the protected set.
 *
 * This is a Linux userspace implementation that emulates the kernel-level
 * protections that Windows anti-cheat drivers (EAC, BattlEye, Vanguard)
 * provide via ObRegisterCallbacks and minifilter drivers.
 *
 * Features:
 *   - Protected PID set management (up to 256 concurrent protected processes)
 *   - Cross-process memory access control
 *   - Thread creation / DLL injection notification
 *   - Module integrity verification (SHA-256)
 *   - Thread-safe via pthread mutex
 *
 * Integration:
 *   - PE loader calls via anticheat_bridge (Unix domain socket)
 *   - kernel_callbacks.c registers ObRegisterCallbacks that call into here
 *   - process_integrity.c handles per-process anti-debug spoofing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>

#define ACG_LOG_PREFIX  "[anticheat/guard] "
#define MAX_PROTECTED   256
#define MAX_PATH_LEN    4096
#define SHA256_DIGEST_LEN 32

/*
 * Windows process access rights that anti-cheat systems care about.
 * These match the values from winnt.h.
 */
#define PROCESS_TERMINATE           0x0001
#define PROCESS_CREATE_THREAD       0x0002
#define PROCESS_SET_SESSIONID       0x0004
#define PROCESS_VM_OPERATION        0x0008
#define PROCESS_VM_READ             0x0010
#define PROCESS_VM_WRITE            0x0020
#define PROCESS_DUP_HANDLE          0x0040
#define PROCESS_CREATE_PROCESS      0x0080
#define PROCESS_SET_QUOTA           0x0100
#define PROCESS_SET_INFORMATION     0x0200
#define PROCESS_QUERY_INFORMATION   0x0400
#define PROCESS_SUSPEND_RESUME      0x0800
#define PROCESS_ALL_ACCESS          0x001FFFFF

/*
 * Access rights that are dangerous for protected processes.
 * Anti-cheat drivers strip these from handles opened by untrusted callers.
 */
#define DANGEROUS_ACCESS_MASK   (PROCESS_VM_READ | PROCESS_VM_WRITE | \
                                 PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | \
                                 PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | \
                                 PROCESS_DUP_HANDLE)

/* Notification callback types */
typedef void (*acg_thread_notify_fn)(pid_t pid, pid_t tid);
typedef void (*acg_image_notify_fn)(pid_t pid, const char *image_path);
typedef void (*acg_exit_notify_fn)(pid_t pid);

/* Protected process entry */
typedef struct {
    pid_t       pid;
    int         active;
    char        game_name[256];
    int         trusted_pids[64];       /* PIDs allowed to access this process */
    int         num_trusted;
    unsigned long access_denied_count;  /* Statistics */
    unsigned long image_load_count;
    unsigned long thread_create_count;
} acg_protected_entry_t;

/* Notification callback entry */
typedef struct {
    acg_thread_notify_fn    on_thread_create;
    acg_image_notify_fn     on_image_load;
    acg_exit_notify_fn      on_process_exit;
    void                   *context;
    int                     active;
} acg_callback_entry_t;

#define MAX_CALLBACKS   16

/* Guard state */
typedef struct {
    int                     initialized;
    acg_protected_entry_t   entries[MAX_PROTECTED];
    int                     num_entries;
    acg_callback_entry_t    callbacks[MAX_CALLBACKS];
    int                     num_callbacks;
    pthread_mutex_t         lock;

    /* Global statistics */
    unsigned long           total_access_checks;
    unsigned long           total_access_denied;
    unsigned long           total_memory_checks;
    unsigned long           total_memory_denied;
} acg_state_t;

static acg_state_t g_guard = {0};

/* --- Internal helpers --- */

/*
 * Find a protected entry by PID.
 * Caller must hold g_guard.lock.
 * Returns index or -1 if not found.
 */
static int find_protected_index(pid_t pid)
{
    for (int i = 0; i < g_guard.num_entries; i++) {
        if (g_guard.entries[i].active && g_guard.entries[i].pid == pid)
            return i;
    }
    return -1;
}

/*
 * Check if a caller PID is in the trusted list of a protected entry.
 * Caller must hold g_guard.lock.
 *
 * A process is trusted if:
 *   - It is the protected process itself (self-access)
 *   - It is in the explicit trusted PID list
 *   - It is PID 1 (init/systemd) or PID 0 (kernel)
 */
static int is_caller_trusted(acg_protected_entry_t *entry, pid_t caller)
{
    /* Self-access is always allowed */
    if (caller == entry->pid)
        return 1;

    /* System processes are trusted */
    if (caller == 0 || caller == 1)
        return 1;

    /* Check explicit trust list */
    for (int i = 0; i < entry->num_trusted; i++) {
        if (entry->trusted_pids[i] == (int)caller)
            return 1;
    }

    return 0;
}

/*
 * Simple file hash comparison.
 * Reads the file and computes a basic hash for verification.
 * Uses /proc/self/fd tricks or direct file I/O.
 *
 * For production use, this would use a proper SHA-256 implementation.
 * Currently uses a simple rolling hash that is sufficient for detecting
 * obvious tampering but not cryptographically secure.
 */
static int compute_file_hash(const char *path, unsigned char *out_hash, size_t hash_len)
{
    FILE *f;
    unsigned char buf[4096];
    size_t n;

    if (!path || !out_hash || hash_len < SHA256_DIGEST_LEN)
        return -1;

    f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, ACG_LOG_PREFIX "Cannot open file for hashing: %s\n", path);
        return -1;
    }

    /*
     * Simple rolling hash. This is NOT a real SHA-256 -- it is a placeholder
     * that produces a deterministic 32-byte digest for file content comparison.
     * A production build would link against libcrypto or use a bundled SHA-256.
     *
     * Algorithm: For each 4096-byte block, XOR-fold and rotate the accumulator.
     */
    unsigned char hash[SHA256_DIGEST_LEN];
    memset(hash, 0, sizeof(hash));

    unsigned long total_bytes = 0;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        for (size_t i = 0; i < n; i++) {
            size_t idx = i % SHA256_DIGEST_LEN;
            hash[idx] ^= buf[i];
            /* Rotate left by 1 bit within the byte */
            hash[idx] = (hash[idx] << 1) | (hash[idx] >> 7);
        }
        total_bytes += n;
    }

    fclose(f);

    /* Mix in total byte count for length-dependent differentiation */
    for (int i = 0; i < SHA256_DIGEST_LEN; i++) {
        hash[i] ^= (unsigned char)(total_bytes >> (i % 8));
    }

    memcpy(out_hash, hash, SHA256_DIGEST_LEN);

    fprintf(stderr, ACG_LOG_PREFIX "Hashed %s (%lu bytes)\n", path, total_bytes);
    return 0;
}

/* --- Public API: Guard lifecycle --- */

/*
 * anticheat_guard_init - Initialize the anti-cheat guard subsystem
 *
 * Sets up the protected PID table, mutex, and callback system.
 * Must be called before any other anticheat_guard functions.
 *
 * Returns 0 on success.
 */
int anticheat_guard_init(void)
{
    if (g_guard.initialized) {
        fprintf(stderr, ACG_LOG_PREFIX "Already initialized\n");
        return 0;
    }

    fprintf(stderr, ACG_LOG_PREFIX "Initializing anti-cheat guard\n");

    memset(&g_guard, 0, sizeof(g_guard));
    pthread_mutex_init(&g_guard.lock, NULL);
    g_guard.initialized = 1;

    fprintf(stderr, ACG_LOG_PREFIX "Guard ready (max %d protected processes)\n",
            MAX_PROTECTED);

    return 0;
}

/*
 * anticheat_guard_shutdown - Shut down the guard subsystem
 *
 * Unprotects all PIDs and releases resources.
 * Returns 0 on success.
 */
int anticheat_guard_shutdown(void)
{
    if (!g_guard.initialized) {
        fprintf(stderr, ACG_LOG_PREFIX "Not initialized\n");
        return 0;
    }

    fprintf(stderr, ACG_LOG_PREFIX "Shutting down anti-cheat guard\n");

    pthread_mutex_lock(&g_guard.lock);

    /* Report statistics */
    fprintf(stderr, ACG_LOG_PREFIX "Statistics:\n");
    fprintf(stderr, ACG_LOG_PREFIX "  Total access checks:  %lu\n",
            g_guard.total_access_checks);
    fprintf(stderr, ACG_LOG_PREFIX "  Total access denied:  %lu\n",
            g_guard.total_access_denied);
    fprintf(stderr, ACG_LOG_PREFIX "  Total memory checks:  %lu\n",
            g_guard.total_memory_checks);
    fprintf(stderr, ACG_LOG_PREFIX "  Total memory denied:  %lu\n",
            g_guard.total_memory_denied);

    /* Report per-process statistics */
    for (int i = 0; i < g_guard.num_entries; i++) {
        if (g_guard.entries[i].active) {
            fprintf(stderr, ACG_LOG_PREFIX "  PID %d (%s): denied=%lu, "
                    "images=%lu, threads=%lu\n",
                    g_guard.entries[i].pid,
                    g_guard.entries[i].game_name,
                    g_guard.entries[i].access_denied_count,
                    g_guard.entries[i].image_load_count,
                    g_guard.entries[i].thread_create_count);
        }
    }

    g_guard.initialized = 0;
    pthread_mutex_unlock(&g_guard.lock);
    pthread_mutex_destroy(&g_guard.lock);

    fprintf(stderr, ACG_LOG_PREFIX "Guard shut down\n");
    return 0;
}

/* --- Public API: Protected PID management --- */

/*
 * anticheat_protect_pid - Add a PID to the protected set
 *
 * @pid: Process ID to protect
 *
 * Once protected, cross-process access from untrusted callers will be denied.
 * Up to MAX_PROTECTED (256) processes can be protected simultaneously.
 *
 * Returns 0 on success, -1 on error (table full, already protected, etc.).
 */
int anticheat_protect_pid(pid_t pid)
{
    if (!g_guard.initialized) {
        fprintf(stderr, ACG_LOG_PREFIX "anticheat_protect_pid: not initialized\n");
        return -1;
    }

    if (pid <= 0) {
        fprintf(stderr, ACG_LOG_PREFIX "anticheat_protect_pid: invalid PID %d\n", pid);
        return -1;
    }

    pthread_mutex_lock(&g_guard.lock);

    /* Check if already protected */
    if (find_protected_index(pid) >= 0) {
        fprintf(stderr, ACG_LOG_PREFIX "PID %d is already protected\n", pid);
        pthread_mutex_unlock(&g_guard.lock);
        return 0;
    }

    /* Find a free slot (reuse inactive entries first) */
    int slot = -1;
    for (int i = 0; i < g_guard.num_entries; i++) {
        if (!g_guard.entries[i].active) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        if (g_guard.num_entries >= MAX_PROTECTED) {
            fprintf(stderr, ACG_LOG_PREFIX "Protected PID table full (%d entries)\n",
                    MAX_PROTECTED);
            pthread_mutex_unlock(&g_guard.lock);
            return -1;
        }
        slot = g_guard.num_entries++;
    }

    acg_protected_entry_t *entry = &g_guard.entries[slot];
    memset(entry, 0, sizeof(*entry));
    entry->pid = pid;
    entry->active = 1;
    snprintf(entry->game_name, sizeof(entry->game_name), "process_%d", pid);

    fprintf(stderr, ACG_LOG_PREFIX "Protected PID %d (slot %d, total %d)\n",
            pid, slot, g_guard.num_entries);

    pthread_mutex_unlock(&g_guard.lock);
    return 0;
}

/*
 * anticheat_unprotect_pid - Remove a PID from the protected set
 *
 * @pid: Process ID to unprotect
 *
 * After removal, cross-process access to this PID will no longer be blocked.
 *
 * Returns 0 on success, -1 if PID was not protected.
 */
int anticheat_unprotect_pid(pid_t pid)
{
    if (!g_guard.initialized) {
        fprintf(stderr, ACG_LOG_PREFIX "anticheat_unprotect_pid: not initialized\n");
        return -1;
    }

    pthread_mutex_lock(&g_guard.lock);

    int idx = find_protected_index(pid);
    if (idx < 0) {
        fprintf(stderr, ACG_LOG_PREFIX "PID %d is not protected\n", pid);
        pthread_mutex_unlock(&g_guard.lock);
        return -1;
    }

    g_guard.entries[idx].active = 0;

    fprintf(stderr, ACG_LOG_PREFIX "Unprotected PID %d (denied %lu accesses total)\n",
            pid, g_guard.entries[idx].access_denied_count);

    pthread_mutex_unlock(&g_guard.lock);
    return 0;
}

/*
 * anticheat_is_protected - Check if a PID is in the protected set
 *
 * @pid: Process ID to check
 *
 * Returns 1 if protected, 0 if not.
 */
int anticheat_is_protected(pid_t pid)
{
    if (!g_guard.initialized)
        return 0;

    pthread_mutex_lock(&g_guard.lock);
    int result = (find_protected_index(pid) >= 0) ? 1 : 0;
    pthread_mutex_unlock(&g_guard.lock);

    return result;
}

/* --- Public API: Access control --- */

/*
 * anticheat_check_process_access - Validate cross-process handle access
 *
 * @caller: PID of the process requesting access
 * @target: PID of the target process
 * @access: Requested access rights (PROCESS_* flags)
 *
 * This is called from the ObRegisterCallbacks emulation (kernel_callbacks.c)
 * when a process attempts to open a handle to another process.
 *
 * If the target is protected and the caller is not trusted, dangerous access
 * rights (VM read/write, thread creation, etc.) are denied.
 *
 * Returns 0 if access is allowed, -1 if denied.
 */
int anticheat_check_process_access(pid_t caller, pid_t target, unsigned long access)
{
    if (!g_guard.initialized)
        return 0;   /* Guard not active = allow all */

    pthread_mutex_lock(&g_guard.lock);

    g_guard.total_access_checks++;

    int idx = find_protected_index(target);
    if (idx < 0) {
        /* Target is not protected, allow all access */
        pthread_mutex_unlock(&g_guard.lock);
        return 0;
    }

    acg_protected_entry_t *entry = &g_guard.entries[idx];

    /* Trusted callers get full access */
    if (is_caller_trusted(entry, caller)) {
        pthread_mutex_unlock(&g_guard.lock);
        return 0;
    }

    /* Check if any dangerous access rights are requested */
    if (access & DANGEROUS_ACCESS_MASK) {
        entry->access_denied_count++;
        g_guard.total_access_denied++;

        fprintf(stderr, ACG_LOG_PREFIX "ACCESS DENIED: PID %d -> PID %d "
                "(access=0x%08lX, dangerous=0x%08lX)\n",
                caller, target, access, access & DANGEROUS_ACCESS_MASK);

        pthread_mutex_unlock(&g_guard.lock);
        return -1;
    }

    /* Non-dangerous access (QUERY_INFORMATION, etc.) is allowed */
    pthread_mutex_unlock(&g_guard.lock);
    return 0;
}

/*
 * anticheat_check_memory_access - Validate cross-process memory read/write
 *
 * @caller: PID of the process attempting memory access
 * @target: PID of the target process whose memory is being accessed
 *
 * This is a higher-level check than anticheat_check_process_access.
 * It specifically blocks ReadProcessMemory / WriteProcessMemory style
 * operations against protected processes.
 *
 * Returns 0 if allowed, -1 if denied.
 */
int anticheat_check_memory_access(pid_t caller, pid_t target)
{
    if (!g_guard.initialized)
        return 0;

    pthread_mutex_lock(&g_guard.lock);

    g_guard.total_memory_checks++;

    int idx = find_protected_index(target);
    if (idx < 0) {
        pthread_mutex_unlock(&g_guard.lock);
        return 0;
    }

    acg_protected_entry_t *entry = &g_guard.entries[idx];

    if (is_caller_trusted(entry, caller)) {
        pthread_mutex_unlock(&g_guard.lock);
        return 0;
    }

    /* Untrusted process attempting to read protected memory */
    entry->access_denied_count++;
    g_guard.total_memory_denied++;

    fprintf(stderr, ACG_LOG_PREFIX "MEMORY ACCESS DENIED: PID %d -> PID %d "
            "(%s)\n", caller, target, entry->game_name);

    pthread_mutex_unlock(&g_guard.lock);
    return -1;
}

/* --- Public API: Callback notifications --- */

/*
 * anticheat_notify_thread_create - Notify that a thread was created in a protected process
 *
 * @pid: Process ID of the protected process
 * @tid: Thread ID of the newly created thread
 *
 * This is called when CreateThread / CreateRemoteThread is invoked targeting
 * a protected process. The guard logs the event and invokes any registered
 * notification callbacks.
 *
 * Anti-cheat systems use this to detect DLL injection via CreateRemoteThread.
 */
void anticheat_notify_thread_create(pid_t pid, pid_t tid)
{
    if (!g_guard.initialized)
        return;

    pthread_mutex_lock(&g_guard.lock);

    int idx = find_protected_index(pid);
    if (idx >= 0) {
        g_guard.entries[idx].thread_create_count++;

        fprintf(stderr, ACG_LOG_PREFIX "Thread created in protected PID %d: TID=%d "
                "(count=%lu)\n", pid, tid,
                g_guard.entries[idx].thread_create_count);

        /* Invoke registered callbacks */
        for (int i = 0; i < g_guard.num_callbacks; i++) {
            if (g_guard.callbacks[i].active && g_guard.callbacks[i].on_thread_create) {
                g_guard.callbacks[i].on_thread_create(pid, tid);
            }
        }
    }

    pthread_mutex_unlock(&g_guard.lock);
}

/*
 * anticheat_notify_image_load - Notify that a DLL/image was loaded in a protected process
 *
 * @pid:        Process ID of the protected process
 * @image_path: Full path of the loaded image (DLL or EXE)
 *
 * Anti-cheat systems monitor DLL loads to detect injected modules.
 * Legitimate loads (system DLLs, game DLLs) are expected; unknown
 * modules trigger alerts.
 */
void anticheat_notify_image_load(pid_t pid, const char *image_path)
{
    if (!g_guard.initialized)
        return;

    pthread_mutex_lock(&g_guard.lock);

    int idx = find_protected_index(pid);
    if (idx >= 0) {
        g_guard.entries[idx].image_load_count++;

        fprintf(stderr, ACG_LOG_PREFIX "Image loaded in protected PID %d: %s "
                "(count=%lu)\n", pid,
                image_path ? image_path : "(null)",
                g_guard.entries[idx].image_load_count);

        /* Invoke registered callbacks */
        for (int i = 0; i < g_guard.num_callbacks; i++) {
            if (g_guard.callbacks[i].active && g_guard.callbacks[i].on_image_load) {
                g_guard.callbacks[i].on_image_load(pid, image_path);
            }
        }
    }

    pthread_mutex_unlock(&g_guard.lock);
}

/*
 * anticheat_notify_process_exit - Notify that a protected process has exited
 *
 * @pid: Process ID of the exiting process
 *
 * Performs cleanup: removes the PID from the protected set and invokes
 * any registered exit notification callbacks.
 */
void anticheat_notify_process_exit(pid_t pid)
{
    if (!g_guard.initialized)
        return;

    pthread_mutex_lock(&g_guard.lock);

    int idx = find_protected_index(pid);
    if (idx >= 0) {
        fprintf(stderr, ACG_LOG_PREFIX "Protected process exiting: PID %d (%s)\n",
                pid, g_guard.entries[idx].game_name);
        fprintf(stderr, ACG_LOG_PREFIX "  Final stats: denied=%lu, images=%lu, "
                "threads=%lu\n",
                g_guard.entries[idx].access_denied_count,
                g_guard.entries[idx].image_load_count,
                g_guard.entries[idx].thread_create_count);

        /* Invoke registered callbacks before cleanup */
        for (int i = 0; i < g_guard.num_callbacks; i++) {
            if (g_guard.callbacks[i].active && g_guard.callbacks[i].on_process_exit) {
                g_guard.callbacks[i].on_process_exit(pid);
            }
        }

        /* Remove from protected set */
        g_guard.entries[idx].active = 0;
    }

    pthread_mutex_unlock(&g_guard.lock);
}

/* --- Public API: Trusted PID management --- */

/*
 * anticheat_add_trusted_pid - Allow a PID to access a protected process
 *
 * @protected_pid: The protected process
 * @trusted_pid:   The PID to grant access to
 *
 * Anti-cheat launchers and service processes need to access the game process.
 * This function adds them to the trusted list so they bypass the access checks.
 *
 * Returns 0 on success, -1 on error.
 */
int anticheat_add_trusted_pid(pid_t protected_pid, pid_t trusted_pid)
{
    if (!g_guard.initialized)
        return -1;

    pthread_mutex_lock(&g_guard.lock);

    int idx = find_protected_index(protected_pid);
    if (idx < 0) {
        fprintf(stderr, ACG_LOG_PREFIX "Cannot add trusted PID: %d is not protected\n",
                protected_pid);
        pthread_mutex_unlock(&g_guard.lock);
        return -1;
    }

    acg_protected_entry_t *entry = &g_guard.entries[idx];

    /* Check if already trusted */
    for (int i = 0; i < entry->num_trusted; i++) {
        if (entry->trusted_pids[i] == (int)trusted_pid) {
            pthread_mutex_unlock(&g_guard.lock);
            return 0;   /* Already trusted */
        }
    }

    if (entry->num_trusted >= 64) {
        fprintf(stderr, ACG_LOG_PREFIX "Trusted PID list full for PID %d\n",
                protected_pid);
        pthread_mutex_unlock(&g_guard.lock);
        return -1;
    }

    entry->trusted_pids[entry->num_trusted++] = (int)trusted_pid;

    fprintf(stderr, ACG_LOG_PREFIX "PID %d is now trusted for protected PID %d\n",
            trusted_pid, protected_pid);

    pthread_mutex_unlock(&g_guard.lock);
    return 0;
}

/*
 * anticheat_set_game_name - Set the game name for a protected PID
 *
 * @pid:       The protected process
 * @game_name: Human-readable game name (for logging)
 *
 * Returns 0 on success, -1 if PID is not protected.
 */
int anticheat_set_game_name(pid_t pid, const char *game_name)
{
    if (!g_guard.initialized || !game_name)
        return -1;

    pthread_mutex_lock(&g_guard.lock);

    int idx = find_protected_index(pid);
    if (idx < 0) {
        pthread_mutex_unlock(&g_guard.lock);
        return -1;
    }

    strncpy(g_guard.entries[idx].game_name, game_name,
            sizeof(g_guard.entries[idx].game_name) - 1);

    fprintf(stderr, ACG_LOG_PREFIX "PID %d game name set to: %s\n", pid, game_name);

    pthread_mutex_unlock(&g_guard.lock);
    return 0;
}

/* --- Public API: Callback registration --- */

/*
 * anticheat_register_callback - Register notification callbacks
 *
 * @on_thread:  Called when a thread is created in a protected process (can be NULL)
 * @on_image:   Called when an image is loaded in a protected process (can be NULL)
 * @on_exit:    Called when a protected process exits (can be NULL)
 * @context:    Opaque pointer (unused, reserved for future use)
 *
 * Returns a callback ID (>= 0) on success, -1 on error.
 */
int anticheat_register_callback(acg_thread_notify_fn on_thread,
                                acg_image_notify_fn on_image,
                                acg_exit_notify_fn on_exit,
                                void *context)
{
    if (!g_guard.initialized)
        return -1;

    pthread_mutex_lock(&g_guard.lock);

    if (g_guard.num_callbacks >= MAX_CALLBACKS) {
        fprintf(stderr, ACG_LOG_PREFIX "Callback table full\n");
        pthread_mutex_unlock(&g_guard.lock);
        return -1;
    }

    int id = g_guard.num_callbacks;
    acg_callback_entry_t *cb = &g_guard.callbacks[id];
    cb->on_thread_create = on_thread;
    cb->on_image_load = on_image;
    cb->on_process_exit = on_exit;
    cb->context = context;
    cb->active = 1;
    g_guard.num_callbacks++;

    fprintf(stderr, ACG_LOG_PREFIX "Registered callback #%d\n", id);

    pthread_mutex_unlock(&g_guard.lock);
    return id;
}

/*
 * anticheat_unregister_callback - Unregister a previously registered callback
 *
 * @callback_id: ID returned from anticheat_register_callback
 *
 * Returns 0 on success, -1 if not found.
 */
int anticheat_unregister_callback(int callback_id)
{
    if (!g_guard.initialized)
        return -1;

    pthread_mutex_lock(&g_guard.lock);

    if (callback_id < 0 || callback_id >= g_guard.num_callbacks ||
        !g_guard.callbacks[callback_id].active) {
        pthread_mutex_unlock(&g_guard.lock);
        return -1;
    }

    g_guard.callbacks[callback_id].active = 0;
    fprintf(stderr, ACG_LOG_PREFIX "Unregistered callback #%d\n", callback_id);

    pthread_mutex_unlock(&g_guard.lock);
    return 0;
}

/* --- Public API: Integrity verification --- */

/*
 * anticheat_verify_module - Verify the integrity of a module file
 *
 * @path:          Path to the module file (DLL, EXE, .sys)
 * @expected_hash: Expected hash digest (SHA-256)
 * @hash_len:      Length of expected_hash (must be SHA256_DIGEST_LEN = 32)
 *
 * Computes the hash of the file at @path and compares it against @expected_hash.
 * This is used by anti-cheat systems to verify that game files have not been
 * modified (e.g., by aimbots or wallhacks that patch DLLs).
 *
 * Returns 1 if the hash matches (integrity OK), 0 if mismatch, -1 on error.
 */
int anticheat_verify_module(const char *path, const unsigned char *expected_hash,
                            size_t hash_len)
{
    if (!path || !expected_hash) {
        fprintf(stderr, ACG_LOG_PREFIX "anticheat_verify_module: invalid arguments\n");
        return -1;
    }

    if (hash_len != SHA256_DIGEST_LEN) {
        fprintf(stderr, ACG_LOG_PREFIX "anticheat_verify_module: unexpected hash length "
                "%zu (expected %d)\n", hash_len, SHA256_DIGEST_LEN);
        return -1;
    }

    fprintf(stderr, ACG_LOG_PREFIX "Verifying module integrity: %s\n", path);

    /* Check if file exists and is readable */
    if (access(path, R_OK) != 0) {
        fprintf(stderr, ACG_LOG_PREFIX "Module not readable: %s\n", path);
        return -1;
    }

    unsigned char computed_hash[SHA256_DIGEST_LEN];
    if (compute_file_hash(path, computed_hash, sizeof(computed_hash)) < 0) {
        fprintf(stderr, ACG_LOG_PREFIX "Failed to compute hash for: %s\n", path);
        return -1;
    }

    /* Constant-time comparison to avoid timing side-channels */
    int diff = 0;
    for (size_t i = 0; i < SHA256_DIGEST_LEN; i++) {
        diff |= computed_hash[i] ^ expected_hash[i];
    }

    if (diff == 0) {
        fprintf(stderr, ACG_LOG_PREFIX "Module integrity OK: %s\n", path);
        return 1;
    }

    fprintf(stderr, ACG_LOG_PREFIX "MODULE INTEGRITY MISMATCH: %s\n", path);
    fprintf(stderr, ACG_LOG_PREFIX "  Expected: ");
    for (int i = 0; i < SHA256_DIGEST_LEN; i++)
        fprintf(stderr, "%02x", expected_hash[i]);
    fprintf(stderr, "\n");

    fprintf(stderr, ACG_LOG_PREFIX "  Computed: ");
    for (int i = 0; i < SHA256_DIGEST_LEN; i++)
        fprintf(stderr, "%02x", computed_hash[i]);
    fprintf(stderr, "\n");

    return 0;
}

/*
 * anticheat_compute_module_hash - Compute the hash of a module file
 *
 * @path:     Path to the module file
 * @out_hash: Output buffer (must be at least SHA256_DIGEST_LEN bytes)
 * @hash_len: Size of output buffer
 *
 * Utility function to compute a module's hash for later verification.
 * The caller stores the hash and uses anticheat_verify_module to check it.
 *
 * Returns 0 on success, -1 on error.
 */
int anticheat_compute_module_hash(const char *path, unsigned char *out_hash,
                                  size_t hash_len)
{
    if (!path || !out_hash || hash_len < SHA256_DIGEST_LEN) {
        fprintf(stderr, ACG_LOG_PREFIX "anticheat_compute_module_hash: "
                "invalid arguments\n");
        return -1;
    }

    return compute_file_hash(path, out_hash, hash_len);
}
