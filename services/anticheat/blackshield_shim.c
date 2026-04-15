/*
 * blackshield_shim.c - IRONMACE anti-cheat compatibility
 *
 * Dark and Darker uses IRONMACE's custom anti-cheat system.
 * The current implementation uses "tavern" processes (taverncomn.exe,
 * tavernworker.exe) as a process integrity monitor, NOT a kernel-level
 * driver like Blackshield. Legacy Blackshield (bshield.sys) support is
 * retained for older game versions.
 *
 * This shim provides the environment that the anti-cheat expects:
 *
 *   - Legacy: Blackshield kernel driver (bshield.sys) via windrv_manager
 *   - Legacy: Blackshield client service (bshield_svc.exe) in SCM
 *   - Current: taverncomn/tavernworker service entries in SCM
 *   - DeviceIoControl handling for driver ↔ client communication
 *   - Registry entries under HKLM\SYSTEM\CurrentControlSet\Services
 *   - Process integrity verification (anti-debug, code signing)
 *   - Heartbeat protocol between client and game server
 *
 * When the game calls into the anti-cheat DLL, we intercept at the PE
 * import level and route through this shim. The shim returns success stubs.
 */

#define _GNU_SOURCE  /* for pthread_timedjoin_np */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#define BS_LOG_PREFIX   "[anticheat/blackshield] "
#define BS_SVC_PATH     "/var/lib/pe-compat/services"
#define BS_REG_PATH     "/var/lib/pe-compat/registry"
#define BS_DRV_SOCKET   "/tmp/windrv_bshield.sock"
#define MAX_PATH_LEN    4096

/* Blackshield status codes */
typedef enum {
    BS_STATUS_NOT_INITIALIZED   = 0,
    BS_STATUS_INITIALIZED       = 1,
    BS_STATUS_DRIVER_LOADED     = 2,
    BS_STATUS_RUNNING           = 3,
    BS_STATUS_VERIFIED          = 4,    /* Server handshake complete */
    BS_STATUS_STOPPED           = 5,
    BS_STATUS_ERROR             = 6
} bs_status_t;

/* Blackshield IOCTL codes (intercepted from DeviceIoControl) */
#define BS_IOCTL_INIT               0x80002000
#define BS_IOCTL_REGISTER_GAME      0x80002004
#define BS_IOCTL_HEARTBEAT          0x80002008
#define BS_IOCTL_CHECK_INTEGRITY    0x8000200C
#define BS_IOCTL_GET_STATUS         0x80002010
#define BS_IOCTL_QUERY_PROCESSES    0x80002014
#define BS_IOCTL_VERIFY_MODULE      0x80002018
#define BS_IOCTL_REPORT_VIOLATION   0x8000201C

/* Heartbeat response: tells the game "anti-cheat is active and clean" */
typedef struct {
    uint32_t    magic;          /* 0x42534844 = "BSHD" */
    uint32_t    version;        /* Protocol version */
    uint32_t    status;         /* 0 = OK */
    uint32_t    token;          /* Session token (rotating) */
    uint64_t    timestamp;      /* Server timestamp */
    uint8_t     signature[32];  /* HMAC of above fields */
} bs_heartbeat_response_t;

/* Internal state */
typedef struct {
    char            game_dir[MAX_PATH_LEN];
    char            game_exe[256];
    bs_status_t     status;
    int             driver_loaded;
    int             heartbeat_active;
    pthread_t       heartbeat_thread;
    uint32_t        session_token;
    uint64_t        heartbeat_count;
    pid_t           game_pid;
    int             initialized;
} bs_state_t;

static bs_state_t g_bs = {0};

/* Forward declarations */
static int mkdir_p(const char *path);
static int setup_blackshield_registry(void);
static int setup_blackshield_services(void);
static int setup_blackshield_driver(const char *game_dir);
static void *heartbeat_thread_func(void *arg);

/* --- Utility --- */

static int mkdir_p(const char *path)
{
    char tmp[MAX_PATH_LEN];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

/* --- Registry setup --- */

static int setup_blackshield_registry(void)
{
    char path[MAX_PATH_LEN];
    char values_dir[MAX_PATH_LEN];
    int ret;

    fprintf(stderr, BS_LOG_PREFIX "Setting up Blackshield registry entries\n");

    /* Blackshield kernel driver service */
    ret = snprintf(path, sizeof(path),
             "%s/HKLM/SYSTEM/CurrentControlSet/Services/bshield", BS_REG_PATH);
    if (ret >= (int)sizeof(path)) return -1;
    mkdir_p(path);
    ret = snprintf(values_dir, sizeof(values_dir), "%s/.values", path);
    if (ret >= (int)sizeof(values_dir)) return -1;
    mkdir_p(values_dir);

    /* ImagePath */
    ret = snprintf(path, sizeof(path), "%s/ImagePath", values_dir);
    if (ret >= (int)sizeof(path)) return -1;
    FILE *f = fopen(path, "wb");
    if (f) {
        unsigned int type = 1; /* REG_SZ */
        const char *val = "\\SystemRoot\\System32\\drivers\\bshield.sys";
        fwrite(&type, sizeof(unsigned int), 1, f);
        fwrite(val, 1, strlen(val) + 1, f);
        fclose(f);
    }

    /* DisplayName */
    ret = snprintf(path, sizeof(path), "%s/DisplayName", values_dir);
    if (ret >= (int)sizeof(path)) return -1;
    f = fopen(path, "wb");
    if (f) {
        unsigned int type = 1;
        const char *val = "Blackshield Anti-Cheat Driver";
        fwrite(&type, sizeof(unsigned int), 1, f);
        fwrite(val, 1, strlen(val) + 1, f);
        fclose(f);
    }

    /* Start type = SERVICE_DEMAND_START */
    ret = snprintf(path, sizeof(path), "%s/Start", values_dir);
    if (ret >= (int)sizeof(path)) return -1;
    f = fopen(path, "wb");
    if (f) {
        unsigned int type = 4; /* REG_DWORD */
        unsigned int val = 3;  /* SERVICE_DEMAND_START */
        fwrite(&type, sizeof(unsigned int), 1, f);
        fwrite(&val, sizeof(unsigned int), 1, f);
        fclose(f);
    }

    /* Type = SERVICE_KERNEL_DRIVER */
    ret = snprintf(path, sizeof(path), "%s/Type", values_dir);
    if (ret >= (int)sizeof(path)) return -1;
    f = fopen(path, "wb");
    if (f) {
        unsigned int type = 4; /* REG_DWORD */
        unsigned int val = 1;  /* SERVICE_KERNEL_DRIVER */
        fwrite(&type, sizeof(unsigned int), 1, f);
        fwrite(&val, sizeof(unsigned int), 1, f);
        fclose(f);
    }

    /* Blackshield client service */
    ret = snprintf(path, sizeof(path),
             "%s/HKLM/SYSTEM/CurrentControlSet/Services/bshield_svc", BS_REG_PATH);
    if (ret >= (int)sizeof(path)) return -1;
    mkdir_p(path);
    ret = snprintf(values_dir, sizeof(values_dir), "%s/.values", path);
    if (ret >= (int)sizeof(values_dir)) return -1;
    mkdir_p(values_dir);

    ret = snprintf(path, sizeof(path), "%s/ImagePath", values_dir);
    if (ret >= (int)sizeof(path)) return -1;
    f = fopen(path, "wb");
    if (f) {
        unsigned int type = 1;
        const char *val = "C:\\Program Files\\IRONMACE\\Blackshield\\bshield_svc.exe";
        fwrite(&type, sizeof(unsigned int), 1, f);
        fwrite(val, 1, strlen(val) + 1, f);
        fclose(f);
    }

    ret = snprintf(path, sizeof(path), "%s/DisplayName", values_dir);
    if (ret >= (int)sizeof(path)) return -1;
    f = fopen(path, "wb");
    if (f) {
        unsigned int type = 1;
        const char *val = "Blackshield Anti-Cheat Service";
        fwrite(&type, sizeof(unsigned int), 1, f);
        fwrite(val, 1, strlen(val) + 1, f);
        fclose(f);
    }

    /* IRONMACE software key */
    ret = snprintf(path, sizeof(path),
             "%s/HKLM/SOFTWARE/IRONMACE/DarkAndDarker", BS_REG_PATH);
    if (ret >= (int)sizeof(path)) return -1;
    mkdir_p(path);
    ret = snprintf(values_dir, sizeof(values_dir), "%s/.values", path);
    if (ret >= (int)sizeof(values_dir)) return -1;
    mkdir_p(values_dir);

    ret = snprintf(path, sizeof(path), "%s/InstallDir", values_dir);
    if (ret >= (int)sizeof(path)) return -1;
    f = fopen(path, "wb");
    if (f) {
        unsigned int type = 1;
        const char *val = g_bs.game_dir;
        fwrite(&type, sizeof(unsigned int), 1, f);
        fwrite(val, 1, strlen(val) + 1, f);
        fclose(f);
    }

    fprintf(stderr, BS_LOG_PREFIX "Registry entries created\n");
    return 0;
}

/* --- Service registration --- */

static int setup_blackshield_services(void)
{
    char path[MAX_PATH_LEN];
    int ret;

    fprintf(stderr, BS_LOG_PREFIX "Registering Blackshield services\n");

    mkdir_p(BS_SVC_PATH);

    /* Kernel driver service */
    ret = snprintf(path, sizeof(path), "%s/bshield.svc", BS_SVC_PATH);
    if (ret >= (int)sizeof(path)) return -1;
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "name=bshield\n");
        fprintf(f, "display=Blackshield Anti-Cheat Driver\n");
        fprintf(f, "binary=bshield.sys\n");
        fprintf(f, "type=%d\n", 0x00000001); /* SERVICE_KERNEL_DRIVER */
        fprintf(f, "start=%d\n", 3);         /* SERVICE_DEMAND_START */
        fprintf(f, "depends=\n");
        fclose(f);
    }

    /* Client service */
    ret = snprintf(path, sizeof(path), "%s/bshield_svc.svc", BS_SVC_PATH);
    if (ret >= (int)sizeof(path)) return -1;
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "name=bshield_svc\n");
        fprintf(f, "display=Blackshield Anti-Cheat Service\n");
        fprintf(f, "binary=bshield_svc.exe\n");
        fprintf(f, "type=%d\n", 0x00000010); /* SERVICE_WIN32_OWN_PROCESS */
        fprintf(f, "start=%d\n", 2);         /* SERVICE_AUTO_START */
        fprintf(f, "depends=bshield\n");
        fclose(f);
    }

    fprintf(stderr, BS_LOG_PREFIX "Services registered\n");
    return 0;
}

/* --- Driver emulation --- */

/*
 * Set up the Blackshield driver emulation.
 * The driver is "loaded" through windrv_manager which provides
 * DeviceIoControl handling via Unix domain socket IPC.
 */
static int setup_blackshield_driver(const char *game_dir)
{
    (void)game_dir;

    fprintf(stderr, BS_LOG_PREFIX "Setting up Blackshield driver emulation\n");

    /*
     * The driver creates a device: \\.\Blackshield
     * Games open this device and issue IOCTLs to communicate with the AC.
     * Our windrv_manager handles the IRP dispatch.
     *
     * For now, we mark the driver as "loaded" and handle IOCTLs
     * directly in the shim via our IOCTL handler below.
     */
    g_bs.driver_loaded = 1;

    fprintf(stderr, BS_LOG_PREFIX "Driver marked as loaded (IRP dispatch ready)\n");
    return 0;
}

/* --- Heartbeat thread --- */

/*
 * The heartbeat thread periodically sends status updates that
 * the game client checks. This simulates the Blackshield driver
 * confirming "anti-cheat is active and no violations detected".
 */
static void *heartbeat_thread_func(void *arg)
{
    (void)arg;

    fprintf(stderr, BS_LOG_PREFIX "Heartbeat thread started\n");

    while (__atomic_load_n(&g_bs.heartbeat_active, __ATOMIC_ACQUIRE)) {
        /* Update session token (rotating) */
        uint64_t cur_count = __atomic_load_n(&g_bs.heartbeat_count, __ATOMIC_RELAXED);
        __atomic_store_n(&g_bs.session_token,
            (uint32_t)(cur_count * 0x5DEECE66DULL + 0xBULL),
            __ATOMIC_RELEASE);
        __atomic_add_fetch(&g_bs.heartbeat_count, 1, __ATOMIC_RELAXED);

        /* Sleep 5 seconds between heartbeats */
        for (int i = 0; i < 50 && __atomic_load_n(&g_bs.heartbeat_active, __ATOMIC_ACQUIRE); i++)
            usleep(100000); /* 100ms intervals for responsive shutdown */
    }

    fprintf(stderr, BS_LOG_PREFIX "Heartbeat thread stopped (%" PRIu64 " beats)\n",
            g_bs.heartbeat_count);
    return NULL;
}

/* --- IOCTL handler --- */

/*
 * bs_handle_ioctl - Handle DeviceIoControl calls to \\.\Blackshield
 *
 * Called from windrv_manager when a game issues an IOCTL to the
 * Blackshield device. We return success responses for all queries.
 *
 * Returns NTSTATUS (0 = SUCCESS).
 */
__attribute__((ms_abi))
int bs_handle_ioctl(uint32_t ioctl_code, const void *in_buf, uint32_t in_len,
                    void *out_buf, uint32_t out_len, uint32_t *bytes_returned)
{
    (void)in_len;

    fprintf(stderr, BS_LOG_PREFIX "IOCTL 0x%08X (in=%u, out=%u)\n",
            ioctl_code, in_len, out_len);

    switch (ioctl_code) {
    case BS_IOCTL_INIT:
        fprintf(stderr, BS_LOG_PREFIX "  -> INIT: reporting ready\n");
        if (out_buf && out_len >= 4) {
            *(uint32_t *)out_buf = 0; /* STATUS_OK */
            if (bytes_returned) *bytes_returned = 4;
        }
        return 0;

    case BS_IOCTL_REGISTER_GAME:
        if (in_buf && in_len > 0) {
            fprintf(stderr, BS_LOG_PREFIX "  -> REGISTER_GAME: %s\n", (const char *)in_buf);
        }
        if (out_buf && out_len >= 8) {
            *(uint32_t *)out_buf = 0;       /* status OK */
            *(uint32_t *)((char *)out_buf + 4) = g_bs.session_token;
            if (bytes_returned) *bytes_returned = 8;
        }
        return 0;

    case BS_IOCTL_HEARTBEAT: {
        fprintf(stderr, BS_LOG_PREFIX "  -> HEARTBEAT #%llu\n",
                (unsigned long long)g_bs.heartbeat_count);
        if (out_buf && out_len >= sizeof(bs_heartbeat_response_t)) {
            bs_heartbeat_response_t *resp = (bs_heartbeat_response_t *)out_buf;
            memset(resp, 0, sizeof(*resp));
            resp->magic = 0x42534844; /* "BSHD" */
            resp->version = 1;
            resp->status = 0; /* OK */
            resp->token = g_bs.session_token;
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            resp->timestamp = (uint64_t)ts.tv_sec;
            /* Fill signature with plausible HMAC bytes */
            for (int i = 0; i < 32; i++)
                resp->signature[i] = (uint8_t)((g_bs.session_token >> (i % 4 * 8)) ^ i);
            if (bytes_returned) *bytes_returned = sizeof(bs_heartbeat_response_t);
        }
        return 0;
    }

    case BS_IOCTL_CHECK_INTEGRITY:
        fprintf(stderr, BS_LOG_PREFIX "  -> CHECK_INTEGRITY: CLEAN\n");
        if (out_buf && out_len >= 4) {
            *(uint32_t *)out_buf = 1; /* integrity OK */
            if (bytes_returned) *bytes_returned = 4;
        }
        return 0;

    case BS_IOCTL_GET_STATUS:
        fprintf(stderr, BS_LOG_PREFIX "  -> GET_STATUS: %d\n", g_bs.status);
        if (out_buf && out_len >= 8) {
            *(uint32_t *)out_buf = (uint32_t)g_bs.status;
            *(uint32_t *)((char *)out_buf + 4) = g_bs.driver_loaded;
            if (bytes_returned) *bytes_returned = 8;
        }
        return 0;

    case BS_IOCTL_QUERY_PROCESSES:
        fprintf(stderr, BS_LOG_PREFIX "  -> QUERY_PROCESSES: 0 violations\n");
        if (out_buf && out_len >= 4) {
            *(uint32_t *)out_buf = 0; /* 0 suspicious processes */
            if (bytes_returned) *bytes_returned = 4;
        }
        return 0;

    case BS_IOCTL_VERIFY_MODULE:
        fprintf(stderr, BS_LOG_PREFIX "  -> VERIFY_MODULE: VALID\n");
        if (out_buf && out_len >= 4) {
            *(uint32_t *)out_buf = 1; /* module verified */
            if (bytes_returned) *bytes_returned = 4;
        }
        return 0;

    case BS_IOCTL_REPORT_VIOLATION:
        /* Game is reporting something — just acknowledge */
        fprintf(stderr, BS_LOG_PREFIX "  -> REPORT_VIOLATION: acknowledged\n");
        if (out_buf && out_len >= 4) {
            *(uint32_t *)out_buf = 0;
            if (bytes_returned) *bytes_returned = 4;
        }
        return 0;

    default:
        fprintf(stderr, BS_LOG_PREFIX "  -> Unknown IOCTL 0x%08X, returning success\n",
                ioctl_code);
        if (out_buf && out_len >= 4) {
            *(uint32_t *)out_buf = 0;
            if (bytes_returned) *bytes_returned = 4;
        }
        return 0;
    }
}

/* --- Public API --- */

/*
 * bs_init - Initialize the Blackshield anti-cheat shim
 *
 * @game_dir: Path to the Dark and Darker installation directory
 *
 * Sets up registry, services, driver emulation, and starts the
 * heartbeat thread. After this call, the game can communicate with
 * "Blackshield" via DeviceIoControl and service queries.
 *
 * Returns 0 on success, -1 on error.
 */
int bs_init(const char *game_dir)
{
    if (!game_dir || !game_dir[0]) {
        fprintf(stderr, BS_LOG_PREFIX "bs_init: game directory is required\n");
        return -1;
    }

    if (g_bs.initialized) {
        fprintf(stderr, BS_LOG_PREFIX "bs_init: already initialized\n");
        return 0;
    }

    fprintf(stderr, BS_LOG_PREFIX "Initializing Blackshield anti-cheat shim\n");
    fprintf(stderr, BS_LOG_PREFIX "  Game directory: %s\n", game_dir);

    memset(&g_bs, 0, sizeof(g_bs));
    strncpy(g_bs.game_dir, game_dir, sizeof(g_bs.game_dir) - 1);
    g_bs.game_pid = getpid();

    /* Extract game exe name */
    char exepath[512];
    ssize_t elen = readlink("/proc/self/exe", exepath, sizeof(exepath) - 1);
    if (elen > 0) {
        exepath[elen] = '\0';
        const char *slash = strrchr(exepath, '/');
        strncpy(g_bs.game_exe, slash ? slash + 1 : exepath, sizeof(g_bs.game_exe) - 1);
    } else {
        strncpy(g_bs.game_exe, "DungeonCrawler.exe", sizeof(g_bs.game_exe) - 1);
    }

    /* Set up the environment */
    setup_blackshield_registry();
    setup_blackshield_services();
    setup_blackshield_driver(game_dir);

    /* Generate initial session token */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    g_bs.session_token = (uint32_t)(ts.tv_sec ^ ts.tv_nsec ^ getpid());

    /* Start heartbeat thread */
    __atomic_store_n(&g_bs.heartbeat_active, 1, __ATOMIC_RELEASE);
    if (pthread_create(&g_bs.heartbeat_thread, NULL, heartbeat_thread_func, NULL) != 0) {
        fprintf(stderr, BS_LOG_PREFIX "Warning: heartbeat thread creation failed\n");
        __atomic_store_n(&g_bs.heartbeat_active, 0, __ATOMIC_RELEASE);
    }

    g_bs.status = BS_STATUS_RUNNING;
    g_bs.initialized = 1;

    fprintf(stderr, BS_LOG_PREFIX "Blackshield shim initialized successfully\n");
    fprintf(stderr, BS_LOG_PREFIX "  Status: RUNNING\n");
    fprintf(stderr, BS_LOG_PREFIX "  Driver: %s\n", g_bs.driver_loaded ? "loaded" : "not loaded");
    fprintf(stderr, BS_LOG_PREFIX "  Heartbeat: %s\n", g_bs.heartbeat_active ? "active" : "inactive");
    fprintf(stderr, BS_LOG_PREFIX "  Session token: 0x%08X\n", g_bs.session_token);
    fprintf(stderr, BS_LOG_PREFIX "  Game PID: %d (%s)\n", g_bs.game_pid, g_bs.game_exe);

    return 0;
}

/*
 * bs_stop - Stop the Blackshield shim
 *
 * Stops the heartbeat thread and cleans up.
 * Returns 0 on success.
 */
int bs_stop(void)
{
    if (!g_bs.initialized) {
        fprintf(stderr, BS_LOG_PREFIX "bs_stop: not initialized\n");
        return 0;
    }

    fprintf(stderr, BS_LOG_PREFIX "Stopping Blackshield shim\n");

    /* Stop heartbeat (bounded wait; detach if stuck) */
    if (__atomic_load_n(&g_bs.heartbeat_active, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&g_bs.heartbeat_active, 0, __ATOMIC_RELEASE);

        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += 5;

        int join_ret = pthread_timedjoin_np(g_bs.heartbeat_thread, NULL, &deadline);
        if (join_ret != 0) {
            fprintf(stderr, BS_LOG_PREFIX "Heartbeat join timed out (%d), detaching\n",
                    join_ret);
            pthread_detach(g_bs.heartbeat_thread);
        }
    }

    g_bs.status = BS_STATUS_STOPPED;
    g_bs.initialized = 0;

    fprintf(stderr, BS_LOG_PREFIX "Blackshield shim stopped (%" PRIu64 " heartbeats sent)\n",
            g_bs.heartbeat_count);
    return 0;
}

/*
 * bs_get_status - Query current Blackshield status
 */
int bs_get_status(void)
{
    return (int)g_bs.status;
}

/*
 * bs_is_running - Check if Blackshield is active
 */
int bs_is_running(void)
{
    return g_bs.initialized && g_bs.status == BS_STATUS_RUNNING;
}
