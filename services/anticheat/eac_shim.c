/*
 * eac_shim.c - EasyAntiCheat compatibility bridge
 *
 * EasyAntiCheat has official Linux support via Proton runtime. This shim:
 *   - Searches for the native EAC runtime (easyanticheat_x64.so / _x86.so)
 *   - If found, loads it via dlopen and forwards calls to the real runtime
 *   - If not found, provides stub implementations that report success
 *   - Sets up the required EasyAntiCheat/ directory structure
 *   - Registers EAC as a Windows service via the SCM database
 *
 * The native EAC runtime exports a C API that we forward to when available.
 * When stubbed, we return status values that let the game proceed without
 * actual anti-cheat enforcement (useful for single-player or offline mode).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#define EAC_LOG_PREFIX  "[anticheat/eac] "
#define EAC_SVC_PATH    "/var/lib/pe-compat/services"
#define EAC_REG_PATH    "/var/lib/pe-compat/registry"
#define MAX_PATH_LEN    4096

/* EAC status codes */
typedef enum {
    EAC_STATUS_NOT_INITIALIZED  = 0,
    EAC_STATUS_INITIALIZED      = 1,
    EAC_STATUS_RUNNING          = 2,
    EAC_STATUS_STOPPED          = 3,
    EAC_STATUS_ERROR            = 4
} eac_status_t;

/* Function pointer types for native EAC runtime */
typedef int  (*eac_native_init_fn)(void);
typedef int  (*eac_native_start_fn)(void);
typedef int  (*eac_native_stop_fn)(void);
typedef int  (*eac_native_status_fn)(void);

/* EAC shim internal state */
typedef struct {
    char            game_dir[MAX_PATH_LEN];
    char            runtime_path[MAX_PATH_LEN];
    void           *native_handle;      /* dlopen handle */
    int             using_native;       /* 1 if native runtime loaded */
    eac_status_t    status;

    /* Native function pointers (resolved via dlsym) */
    eac_native_init_fn      native_init;
    eac_native_start_fn     native_start;
    eac_native_stop_fn      native_stop;
    eac_native_status_fn    native_status;
} eac_state_t;

static eac_state_t g_eac = { {0}, {0}, NULL, 0, EAC_STATUS_NOT_INITIALIZED,
                              NULL, NULL, NULL, NULL };

/* Forward declarations */
static int  mkdir_p(const char *path);
static int  try_load_native_runtime(const char *game_dir);
static int  setup_eac_directory_structure(const char *game_dir);
static int  register_eac_service(void);

/* --- Utility --- */

static int mkdir_p(const char *path)
{
    char tmp[MAX_PATH_LEN];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755);
}

/*
 * Attempt to load the native EAC runtime shared library.
 * Searches for:
 *   1. <game_dir>/easyanticheat_x64.so (64-bit preferred)
 *   2. <game_dir>/easyanticheat_x86.so (32-bit fallback)
 *   3. <game_dir>/EasyAntiCheat/easyanticheat_x64.so
 *   4. <game_dir>/EasyAntiCheat/easyanticheat_x86.so
 */
static int try_load_native_runtime(const char *game_dir)
{
    const char *search_paths[] = {
        "%s/easyanticheat_x64.so",
        "%s/easyanticheat_x86.so",
        "%s/EasyAntiCheat/easyanticheat_x64.so",
        "%s/EasyAntiCheat/easyanticheat_x86.so",
        NULL
    };

    char path[MAX_PATH_LEN];

    for (int i = 0; search_paths[i] != NULL; i++) {
        snprintf(path, sizeof(path), search_paths[i], game_dir);

        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
            continue;

        fprintf(stderr, EAC_LOG_PREFIX "Found native runtime: %s\n", path);

        void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            fprintf(stderr, EAC_LOG_PREFIX "dlopen failed: %s\n", dlerror());
            continue;
        }

        fprintf(stderr, EAC_LOG_PREFIX "Successfully loaded native runtime\n");

        /* Resolve native function pointers */
        g_eac.native_init   = (eac_native_init_fn)dlsym(handle, "eac_init");
        g_eac.native_start  = (eac_native_start_fn)dlsym(handle, "eac_start");
        g_eac.native_stop   = (eac_native_stop_fn)dlsym(handle, "eac_stop");
        g_eac.native_status = (eac_native_status_fn)dlsym(handle, "eac_get_status");

        if (g_eac.native_init) {
            fprintf(stderr, EAC_LOG_PREFIX "Resolved eac_init from native runtime\n");
        } else {
            fprintf(stderr, EAC_LOG_PREFIX "Warning: eac_init not found in native runtime, "
                    "will use stub\n");
        }
        if (g_eac.native_start) {
            fprintf(stderr, EAC_LOG_PREFIX "Resolved eac_start from native runtime\n");
        }
        if (g_eac.native_stop) {
            fprintf(stderr, EAC_LOG_PREFIX "Resolved eac_stop from native runtime\n");
        }
        if (g_eac.native_status) {
            fprintf(stderr, EAC_LOG_PREFIX "Resolved eac_get_status from native runtime\n");
        }

        g_eac.native_handle = handle;
        strncpy(g_eac.runtime_path, path, sizeof(g_eac.runtime_path) - 1);
        return 1;
    }

    fprintf(stderr, EAC_LOG_PREFIX "No native EAC runtime found, using stub mode\n");
    return 0;
}

/*
 * Set up the EasyAntiCheat directory structure that games expect:
 *   <game_dir>/EasyAntiCheat/
 *   <game_dir>/EasyAntiCheat/Certificates/
 *   <game_dir>/EasyAntiCheat/Settings/
 */
static int setup_eac_directory_structure(const char *game_dir)
{
    char path[MAX_PATH_LEN];
    int ret = 0;

    fprintf(stderr, EAC_LOG_PREFIX "Setting up EAC directory structure in %s\n", game_dir);

    snprintf(path, sizeof(path), "%s/EasyAntiCheat", game_dir);
    if (mkdir_p(path) < 0 && errno != EEXIST) {
        fprintf(stderr, EAC_LOG_PREFIX "Failed to create %s: %s\n", path, strerror(errno));
        ret = -1;
    }

    snprintf(path, sizeof(path), "%s/EasyAntiCheat/Certificates", game_dir);
    if (mkdir_p(path) < 0 && errno != EEXIST) {
        fprintf(stderr, EAC_LOG_PREFIX "Failed to create %s: %s\n", path, strerror(errno));
        ret = -1;
    }

    snprintf(path, sizeof(path), "%s/EasyAntiCheat/Settings", game_dir);
    if (mkdir_p(path) < 0 && errno != EEXIST) {
        fprintf(stderr, EAC_LOG_PREFIX "Failed to create %s: %s\n", path, strerror(errno));
        ret = -1;
    }

    /* Create a stub settings file if it doesn't exist */
    snprintf(path, sizeof(path), "%s/EasyAntiCheat/Settings/settings.json", game_dir);
    struct stat st;
    if (stat(path, &st) != 0) {
        FILE *f = fopen(path, "w");
        if (f) {
            fprintf(f, "{\n  \"productid\": \"default\",\n  \"sandboxid\": \"\",\n"
                       "  \"deploymentid\": \"\"\n}\n");
            fclose(f);
            fprintf(stderr, EAC_LOG_PREFIX "Created default settings file\n");
        }
    }

    if (ret == 0)
        fprintf(stderr, EAC_LOG_PREFIX "Directory structure ready\n");

    return ret;
}

/*
 * Register EAC as a Windows service in the SCM database.
 * This creates the service config file that scm_daemon reads.
 */
static int register_eac_service(void)
{
    char path[MAX_PATH_LEN];

    fprintf(stderr, EAC_LOG_PREFIX "Registering EAC as Windows service via SCM\n");

    mkdir_p(EAC_SVC_PATH);

    snprintf(path, sizeof(path), "%s/EasyAntiCheat.svc", EAC_SVC_PATH);

    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, EAC_LOG_PREFIX "Failed to create service file: %s\n",
                strerror(errno));
        return -1;
    }

    fprintf(f, "name=EasyAntiCheat\n");
    fprintf(f, "display=EasyAntiCheat\n");
    fprintf(f, "binary=EasyAntiCheat.exe\n");
    fprintf(f, "type=%d\n", 0x00000010); /* SERVICE_WIN32_OWN_PROCESS */
    fprintf(f, "start=%d\n", 3);         /* SERVICE_DEMAND_START */
    fprintf(f, "depends=\n");
    fclose(f);

    fprintf(stderr, EAC_LOG_PREFIX "EAC service registered successfully\n");

    /* Also create the EAC registry service key */
    char reg_path[MAX_PATH_LEN];
    snprintf(reg_path, sizeof(reg_path),
             "%s/HKLM/SYSTEM/CurrentControlSet/Services/EasyAntiCheat",
             EAC_REG_PATH);
    mkdir_p(reg_path);

    /* Write ImagePath value */
    char values_dir[MAX_PATH_LEN];
    snprintf(values_dir, sizeof(values_dir), "%s/.values", reg_path);
    mkdir_p(values_dir);

    snprintf(path, sizeof(path), "%s/ImagePath", values_dir);
    f = fopen(path, "wb");
    if (f) {
        unsigned int type = 1; /* REG_SZ */
        const char *val = "C:\\Program Files (x86)\\EasyAntiCheat\\EasyAntiCheat.exe";
        fwrite(&type, sizeof(unsigned int), 1, f);
        fwrite(val, 1, strlen(val) + 1, f);
        fclose(f);
        fprintf(stderr, EAC_LOG_PREFIX "Created EAC registry service key\n");
    }

    return 0;
}

/* --- Public API --- */

/*
 * eac_init - Initialize the EasyAntiCheat shim
 *
 * @game_dir: Path to the game installation directory
 *
 * Searches for the native EAC runtime, sets up directory structure,
 * and registers the EAC service. If the native runtime is found, it
 * is loaded and future calls are forwarded to it.
 *
 * Returns 0 on success, -1 on error.
 */
int eac_init(const char *game_dir)
{
    if (!game_dir || !game_dir[0]) {
        fprintf(stderr, EAC_LOG_PREFIX "eac_init: game directory is required\n");
        return -1;
    }

    if (g_eac.status != EAC_STATUS_NOT_INITIALIZED) {
        fprintf(stderr, EAC_LOG_PREFIX "eac_init: already initialized\n");
        return -1;
    }

    fprintf(stderr, EAC_LOG_PREFIX "Initializing EasyAntiCheat shim for: %s\n", game_dir);

    strncpy(g_eac.game_dir, game_dir, sizeof(g_eac.game_dir) - 1);
    g_eac.game_dir[sizeof(g_eac.game_dir) - 1] = '\0';

    /* Set up directory structure */
    if (setup_eac_directory_structure(game_dir) < 0) {
        fprintf(stderr, EAC_LOG_PREFIX "Warning: directory structure setup had errors\n");
    }

    /* Register as Windows service */
    if (register_eac_service() < 0) {
        fprintf(stderr, EAC_LOG_PREFIX "Warning: service registration failed\n");
    }

    /* Try to load native runtime */
    g_eac.using_native = try_load_native_runtime(game_dir);

    /* If native runtime has its own init, call it */
    if (g_eac.using_native && g_eac.native_init) {
        fprintf(stderr, EAC_LOG_PREFIX "Forwarding init to native runtime\n");
        int ret = g_eac.native_init();
        if (ret != 0) {
            fprintf(stderr, EAC_LOG_PREFIX "Native init returned error %d, "
                    "falling back to stub mode\n", ret);
            dlclose(g_eac.native_handle);
            g_eac.native_handle = NULL;
            g_eac.using_native = 0;
            g_eac.native_init = NULL;
            g_eac.native_start = NULL;
            g_eac.native_stop = NULL;
            g_eac.native_status = NULL;
        }
    }

    g_eac.status = EAC_STATUS_INITIALIZED;
    fprintf(stderr, EAC_LOG_PREFIX "EAC shim initialized (mode: %s)\n",
            g_eac.using_native ? "native" : "stub");

    return 0;
}

/*
 * eac_start - Start EasyAntiCheat protection
 *
 * If using native runtime, forwards to the real implementation.
 * In stub mode, simply transitions to RUNNING state.
 *
 * Returns 0 on success, -1 on error.
 */
int eac_start(void)
{
    if (g_eac.status == EAC_STATUS_NOT_INITIALIZED) {
        fprintf(stderr, EAC_LOG_PREFIX "eac_start: not initialized\n");
        return -1;
    }

    if (g_eac.status == EAC_STATUS_RUNNING) {
        fprintf(stderr, EAC_LOG_PREFIX "eac_start: already running\n");
        return 0;
    }

    fprintf(stderr, EAC_LOG_PREFIX "Starting EasyAntiCheat protection\n");

    if (g_eac.using_native && g_eac.native_start) {
        fprintf(stderr, EAC_LOG_PREFIX "Forwarding start to native runtime\n");
        int ret = g_eac.native_start();
        if (ret != 0) {
            fprintf(stderr, EAC_LOG_PREFIX "Native start returned error %d\n", ret);
            g_eac.status = EAC_STATUS_ERROR;
            return -1;
        }
    } else {
        fprintf(stderr, EAC_LOG_PREFIX "Stub mode: reporting EAC as running\n");
    }

    g_eac.status = EAC_STATUS_RUNNING;
    fprintf(stderr, EAC_LOG_PREFIX "EasyAntiCheat is now running\n");
    return 0;
}

/*
 * eac_stop - Stop EasyAntiCheat protection
 *
 * If using native runtime, forwards to the real implementation.
 * In stub mode, transitions to STOPPED state.
 *
 * Returns 0 on success, -1 on error.
 */
int eac_stop(void)
{
    if (g_eac.status == EAC_STATUS_NOT_INITIALIZED) {
        fprintf(stderr, EAC_LOG_PREFIX "eac_stop: not initialized\n");
        return -1;
    }

    if (g_eac.status == EAC_STATUS_STOPPED) {
        fprintf(stderr, EAC_LOG_PREFIX "eac_stop: already stopped\n");
        return 0;
    }

    fprintf(stderr, EAC_LOG_PREFIX "Stopping EasyAntiCheat protection\n");

    if (g_eac.using_native && g_eac.native_stop) {
        fprintf(stderr, EAC_LOG_PREFIX "Forwarding stop to native runtime\n");
        int ret = g_eac.native_stop();
        if (ret != 0) {
            fprintf(stderr, EAC_LOG_PREFIX "Native stop returned error %d\n", ret);
        }
    }

    /* Unload native runtime if loaded */
    if (g_eac.native_handle) {
        fprintf(stderr, EAC_LOG_PREFIX "Unloading native runtime\n");
        dlclose(g_eac.native_handle);
        g_eac.native_handle = NULL;
        g_eac.native_init = NULL;
        g_eac.native_start = NULL;
        g_eac.native_stop = NULL;
        g_eac.native_status = NULL;
        g_eac.using_native = 0;
    }

    g_eac.status = EAC_STATUS_STOPPED;
    fprintf(stderr, EAC_LOG_PREFIX "EasyAntiCheat stopped\n");
    return 0;
}

/*
 * eac_get_status - Query current EAC status
 *
 * Returns the current eac_status_t value.
 * If native runtime has a status query function, forwards to it.
 */
eac_status_t eac_get_status(void)
{
    if (g_eac.using_native && g_eac.native_status) {
        int native_status = g_eac.native_status();
        fprintf(stderr, EAC_LOG_PREFIX "Native status query returned: %d\n", native_status);
        /* Map native status to our enum if needed */
        return (eac_status_t)native_status;
    }

    const char *status_names[] = {
        "NOT_INITIALIZED", "INITIALIZED", "RUNNING", "STOPPED", "ERROR"
    };
    fprintf(stderr, EAC_LOG_PREFIX "Status: %s (mode: %s)\n",
            status_names[g_eac.status],
            g_eac.using_native ? "native" : "stub");

    return g_eac.status;
}
