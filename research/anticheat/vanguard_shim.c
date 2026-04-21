/*
 * vanguard_shim.c - Riot Vanguard anti-cheat compatibility
 *
 * Riot Vanguard consists of two components:
 *   - vgk.sys:  Kernel driver (loads at boot, monitors system)
 *   - vgc.exe:  Client service (communicates with Riot servers)
 *
 * This shim emulates both components:
 *   1. vgk.sys is "loaded" via windrv_manager with IRP dispatch
 *   2. vgc.exe is registered as a Windows service
 *   3. DeviceIoControl to \\.\Vanguard is handled by the IOCTL handler
 *   4. Registry entries match what Riot client expects
 *   5. Tray icon process is simulated
 *
 * Vanguard checks:
 *   - Kernel driver is loaded and responsive
 *   - No kernel debugger attached
 *   - Secure Boot is enabled
 *   - TPM 2.0 is available (Windows 11 requirement)
 *   - No known cheat tools in process list
 *   - Code integrity is enabled
 *   - Driver signing enforcement is active
 *
 * Our NtQuerySystemInformation already handles most of these checks.
 * This shim provides the Vanguard-specific IOCTL protocol.
 */

#define _GNU_SOURCE  /* for pthread_timedjoin_np */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#define VG_LOG_PREFIX   "[anticheat/vanguard] "
#define VG_SVC_PATH     "/var/lib/pe-compat/services"
#define VG_REG_PATH     "/var/lib/pe-compat/registry"
#define MAX_PATH_LEN    4096

/* Vanguard status */
typedef enum {
    VG_STATUS_NOT_INITIALIZED   = 0,
    VG_STATUS_DRIVER_LOADED     = 1,
    VG_STATUS_CLIENT_RUNNING    = 2,
    VG_STATUS_VERIFIED          = 3,
    VG_STATUS_STOPPED           = 4,
    VG_STATUS_ERROR             = 5
} vg_status_t;

/* Vanguard IOCTL codes */
#define VG_IOCTL_INIT               0x90002000
#define VG_IOCTL_HANDSHAKE          0x90002004
#define VG_IOCTL_HEARTBEAT          0x90002008
#define VG_IOCTL_CHECK_SYSTEM       0x9000200C
#define VG_IOCTL_QUERY_STATUS       0x90002010
#define VG_IOCTL_VERIFY_DRIVER      0x90002014
#define VG_IOCTL_GET_HARDWARE_ID    0x90002018
#define VG_IOCTL_CHECK_SECURE_BOOT  0x9000201C
#define VG_IOCTL_CHECK_TPM          0x90002020

/* Internal state */
typedef struct {
    vg_status_t     status;
    int             driver_loaded;
    int             client_running;
    int             heartbeat_active;
    pthread_t       heartbeat_thread;
    volatile int    shutdown_requested;  /* checked by heartbeat thread */
    uint32_t        session_id;
    uint64_t        heartbeat_count;
    int             initialized;
} vg_state_t;

static vg_state_t g_vg = {0};

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

static int setup_vanguard_registry(void)
{
    char path[MAX_PATH_LEN];
    char values_dir[MAX_PATH_LEN];
    int ret;

    fprintf(stderr, VG_LOG_PREFIX "Setting up Vanguard registry entries\n");

    /* vgk.sys kernel driver */
    ret = snprintf(path, sizeof(path),
             "%s/HKLM/SYSTEM/CurrentControlSet/Services/vgk", VG_REG_PATH);
    if (ret >= (int)sizeof(path)) return -1;
    mkdir_p(path);
    ret = snprintf(values_dir, sizeof(values_dir), "%s/.values", path);
    if (ret >= (int)sizeof(values_dir)) return -1;
    mkdir_p(values_dir);

    ret = snprintf(path, sizeof(path), "%s/ImagePath", values_dir);
    if (ret >= (int)sizeof(path)) return -1;
    FILE *f = fopen(path, "wb");
    if (f) {
        unsigned int type = 1;
        const char *val = "\\SystemRoot\\System32\\drivers\\vgk.sys";
        fwrite(&type, sizeof(unsigned int), 1, f);
        fwrite(val, 1, strlen(val) + 1, f);
        fclose(f);
    }

    ret = snprintf(path, sizeof(path), "%s/DisplayName", values_dir);
    if (ret >= (int)sizeof(path)) return -1;
    f = fopen(path, "wb");
    if (f) {
        unsigned int type = 1;
        const char *val = "Vanguard";
        fwrite(&type, sizeof(unsigned int), 1, f);
        fwrite(val, 1, strlen(val) + 1, f);
        fclose(f);
    }

    ret = snprintf(path, sizeof(path), "%s/Start", values_dir);
    if (ret >= (int)sizeof(path)) return -1;
    f = fopen(path, "wb");
    if (f) {
        unsigned int type = 4;
        unsigned int val = 0; /* SERVICE_BOOT_START */
        fwrite(&type, sizeof(unsigned int), 1, f);
        fwrite(&val, sizeof(unsigned int), 1, f);
        fclose(f);
    }

    /* vgc.exe client service */
    ret = snprintf(path, sizeof(path),
             "%s/HKLM/SYSTEM/CurrentControlSet/Services/vgc", VG_REG_PATH);
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
        const char *val = "C:\\Program Files\\Riot Vanguard\\vgc.exe";
        fwrite(&type, sizeof(unsigned int), 1, f);
        fwrite(val, 1, strlen(val) + 1, f);
        fclose(f);
    }

    /* Riot Vanguard installation key */
    ret = snprintf(path, sizeof(path),
             "%s/HKLM/SOFTWARE/Riot Vanguard", VG_REG_PATH);
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
        const char *val = "C:\\Program Files\\Riot Vanguard";
        fwrite(&type, sizeof(unsigned int), 1, f);
        fwrite(val, 1, strlen(val) + 1, f);
        fclose(f);
    }

    /* Riot Games installation key */
    ret = snprintf(path, sizeof(path),
             "%s/HKLM/SOFTWARE/Riot Games", VG_REG_PATH);
    if (ret >= (int)sizeof(path)) return -1;
    mkdir_p(path);

    fprintf(stderr, VG_LOG_PREFIX "Registry entries created\n");
    return 0;
}

/* --- Service registration --- */

static int setup_vanguard_services(void)
{
    char path[MAX_PATH_LEN];
    int ret;

    fprintf(stderr, VG_LOG_PREFIX "Registering Vanguard services\n");

    mkdir_p(VG_SVC_PATH);

    /* vgk - kernel driver */
    ret = snprintf(path, sizeof(path), "%s/vgk.svc", VG_SVC_PATH);
    if (ret >= (int)sizeof(path)) return -1;
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "name=vgk\n");
        fprintf(f, "display=Vanguard\n");
        fprintf(f, "binary=vgk.sys\n");
        fprintf(f, "type=%d\n", 0x00000001);
        fprintf(f, "start=%d\n", 0); /* BOOT_START */
        fprintf(f, "depends=\n");
        fclose(f);
    }

    /* vgc - client service */
    ret = snprintf(path, sizeof(path), "%s/vgc.svc", VG_SVC_PATH);
    if (ret >= (int)sizeof(path)) return -1;
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "name=vgc\n");
        fprintf(f, "display=Vanguard Client\n");
        fprintf(f, "binary=vgc.exe\n");
        fprintf(f, "type=%d\n", 0x00000010);
        fprintf(f, "start=%d\n", 2); /* AUTO_START */
        fprintf(f, "depends=vgk\n");
        fclose(f);
    }

    fprintf(stderr, VG_LOG_PREFIX "Services registered\n");
    return 0;
}

/* --- Heartbeat --- */

static void *vg_heartbeat_func(void *arg)
{
    (void)arg;
    fprintf(stderr, VG_LOG_PREFIX "Heartbeat thread started\n");

    while (__atomic_load_n(&g_vg.heartbeat_active, __ATOMIC_ACQUIRE) &&
           !g_vg.shutdown_requested) {
        __atomic_add_fetch(&g_vg.heartbeat_count, 1, __ATOMIC_RELAXED);
        for (int i = 0; i < 30 &&
             __atomic_load_n(&g_vg.heartbeat_active, __ATOMIC_ACQUIRE) &&
             !g_vg.shutdown_requested; i++)
            usleep(100000);
    }

    fprintf(stderr, VG_LOG_PREFIX "Heartbeat thread stopped\n");
    return NULL;
}

/* --- IOCTL handler --- */

__attribute__((ms_abi))
int vg_handle_ioctl(uint32_t ioctl_code, const void *in_buf, uint32_t in_len,
                    void *out_buf, uint32_t out_len, uint32_t *bytes_returned)
{
    (void)in_buf; (void)in_len;

    fprintf(stderr, VG_LOG_PREFIX "IOCTL 0x%08X\n", ioctl_code);

    switch (ioctl_code) {
    case VG_IOCTL_INIT:
        fprintf(stderr, VG_LOG_PREFIX "  -> INIT: driver ready\n");
        if (out_buf && out_len >= 4) {
            *(uint32_t *)out_buf = 0;
            if (bytes_returned) *bytes_returned = 4;
        }
        return 0;

    case VG_IOCTL_HANDSHAKE:
        fprintf(stderr, VG_LOG_PREFIX "  -> HANDSHAKE: session 0x%08X\n", g_vg.session_id);
        if (out_buf && out_len >= 8) {
            *(uint32_t *)out_buf = 0;
            *(uint32_t *)((char *)out_buf + 4) = g_vg.session_id;
            if (bytes_returned) *bytes_returned = 8;
        }
        return 0;

    case VG_IOCTL_HEARTBEAT:
        if (out_buf && out_len >= 4) {
            *(uint32_t *)out_buf = 0;
            if (bytes_returned) *bytes_returned = 4;
        }
        return 0;

    case VG_IOCTL_CHECK_SYSTEM:
        /* System checks: no debugger, no cheat tools, CI enabled */
        fprintf(stderr, VG_LOG_PREFIX "  -> CHECK_SYSTEM: CLEAN\n");
        if (out_buf && out_len >= 16) {
            memset(out_buf, 0, 16);
            *(uint32_t *)out_buf = 0;       /* status OK */
            *(uint32_t *)((char *)out_buf + 4) = 0;  /* 0 violations */
            *(uint32_t *)((char *)out_buf + 8) = 1;   /* secure boot */
            *(uint32_t *)((char *)out_buf + 12) = 1;  /* TPM present */
            if (bytes_returned) *bytes_returned = 16;
        }
        return 0;

    case VG_IOCTL_QUERY_STATUS:
        if (out_buf && out_len >= 8) {
            *(uint32_t *)out_buf = (uint32_t)g_vg.status;
            *(uint32_t *)((char *)out_buf + 4) = g_vg.driver_loaded;
            if (bytes_returned) *bytes_returned = 8;
        }
        return 0;

    case VG_IOCTL_VERIFY_DRIVER:
        fprintf(stderr, VG_LOG_PREFIX "  -> VERIFY_DRIVER: signature valid\n");
        if (out_buf && out_len >= 4) {
            *(uint32_t *)out_buf = 1; /* driver signature verified */
            if (bytes_returned) *bytes_returned = 4;
        }
        return 0;

    case VG_IOCTL_GET_HARDWARE_ID:
        fprintf(stderr, VG_LOG_PREFIX "  -> GET_HARDWARE_ID\n");
        if (out_buf && out_len >= 64) {
            /* Return a plausible hardware fingerprint */
            memset(out_buf, 0, 64);
            snprintf((char *)out_buf, 64,
                     "HWID-%08X-%08X-%08X-%08X",
                     0xA1B2C3D4, 0xE5F6A7B8, 0xC9D0E1F2, 0x13243546);
            if (bytes_returned) *bytes_returned = 64;
        }
        return 0;

    case VG_IOCTL_CHECK_SECURE_BOOT:
        fprintf(stderr, VG_LOG_PREFIX "  -> CHECK_SECURE_BOOT: enabled\n");
        if (out_buf && out_len >= 4) {
            *(uint32_t *)out_buf = 1; /* secure boot enabled */
            if (bytes_returned) *bytes_returned = 4;
        }
        return 0;

    case VG_IOCTL_CHECK_TPM:
        fprintf(stderr, VG_LOG_PREFIX "  -> CHECK_TPM: TPM 2.0 present\n");
        if (out_buf && out_len >= 8) {
            *(uint32_t *)out_buf = 1;       /* TPM present */
            *(uint32_t *)((char *)out_buf + 4) = 0x200; /* version 2.0 */
            if (bytes_returned) *bytes_returned = 8;
        }
        return 0;

    default:
        fprintf(stderr, VG_LOG_PREFIX "  -> Unknown IOCTL 0x%08X, returning success\n",
                ioctl_code);
        if (out_buf && out_len >= 4) {
            *(uint32_t *)out_buf = 0;
            if (bytes_returned) *bytes_returned = 4;
        }
        return 0;
    }
}

/* --- Public API --- */

int vg_init(void)
{
    if (g_vg.initialized) {
        fprintf(stderr, VG_LOG_PREFIX "Already initialized\n");
        return 0;
    }

    fprintf(stderr, VG_LOG_PREFIX "Initializing Riot Vanguard shim\n");

    memset(&g_vg, 0, sizeof(g_vg));

    setup_vanguard_registry();
    setup_vanguard_services();

    /* Generate session ID */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    g_vg.session_id = (uint32_t)(ts.tv_sec ^ ts.tv_nsec ^ getpid());

    g_vg.driver_loaded = 1;
    g_vg.client_running = 1;

    /* Start heartbeat */
    __atomic_store_n(&g_vg.heartbeat_active, 1, __ATOMIC_RELEASE);
    if (pthread_create(&g_vg.heartbeat_thread, NULL, vg_heartbeat_func, NULL) != 0) {
        fprintf(stderr, VG_LOG_PREFIX "Warning: heartbeat thread failed\n");
        __atomic_store_n(&g_vg.heartbeat_active, 0, __ATOMIC_RELEASE);
    }

    g_vg.status = VG_STATUS_VERIFIED;
    g_vg.initialized = 1;

    fprintf(stderr, VG_LOG_PREFIX "Vanguard shim initialized\n");
    fprintf(stderr, VG_LOG_PREFIX "  Driver: loaded\n");
    fprintf(stderr, VG_LOG_PREFIX "  Client: running\n");
    fprintf(stderr, VG_LOG_PREFIX "  Session: 0x%08X\n", g_vg.session_id);

    return 0;
}

int vg_stop(void)
{
    if (!g_vg.initialized)
        return 0;

    fprintf(stderr, VG_LOG_PREFIX "Stopping Vanguard shim\n");

    if (__atomic_load_n(&g_vg.heartbeat_active, __ATOMIC_ACQUIRE)) {
        /* Signal shutdown via both mechanisms so the thread exits promptly
         * even if the .so is about to be unloaded by the PE loader. */
        g_vg.shutdown_requested = 1;
        __atomic_store_n(&g_vg.heartbeat_active, 0, __ATOMIC_RELEASE);

        /* Timed join: wait up to 5 seconds, then detach to avoid hanging
         * if the thread is stuck or the stack is already being reclaimed. */
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += 5;

        int join_ret = pthread_timedjoin_np(g_vg.heartbeat_thread, NULL, &deadline);
        if (join_ret != 0) {
            fprintf(stderr, VG_LOG_PREFIX "Heartbeat thread join timed out (%d), "
                    "detaching thread\n", join_ret);
            pthread_detach(g_vg.heartbeat_thread);
        }
    }

    g_vg.status = VG_STATUS_STOPPED;
    g_vg.initialized = 0;
    return 0;
}

int vg_get_status(void)
{
    return (int)g_vg.status;
}

int vg_is_running(void)
{
    return g_vg.initialized && g_vg.status == VG_STATUS_VERIFIED;
}
