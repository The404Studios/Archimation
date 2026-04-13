/*
 * battleye_shim.c - BattlEye compatibility bridge
 *
 * BattlEye has official Linux support via Proton. This shim:
 *   - Searches for BEService_x64.exe or BEClient_x64.dll in the game's
 *     BattlEye/ directory, as well as native Linux runtime (.so) files
 *   - Provides BEService Windows service registration via the SCM database
 *   - If a native Linux runtime is available, loads it via dlopen
 *   - Otherwise provides stub implementations
 *   - Sets up the BattlEye directory structure and expected files
 *
 * BattlEye consists of two main components:
 *   - BEService: A Windows service that manages the anti-cheat backend
 *   - BEClient: A DLL loaded into the game process for client-side checks
 *   - BEDaisy: A kernel driver for deep system monitoring (stubbed here)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#define BE_LOG_PREFIX   "[anticheat/be] "
#define BE_SVC_PATH     "/var/lib/pe-compat/services"
#define BE_REG_PATH     "/var/lib/pe-compat/registry"
#define MAX_PATH_LEN    4096

/* BattlEye status codes */
typedef enum {
    BE_STATUS_NOT_INITIALIZED   = 0,
    BE_STATUS_INITIALIZED       = 1,
    BE_STATUS_SERVICE_RUNNING   = 2,
    BE_STATUS_SERVICE_STOPPED   = 3,
    BE_STATUS_ERROR             = 4
} be_status_t;

/* Function pointer types for native BattlEye runtime */
typedef int  (*be_native_init_fn)(void);
typedef int  (*be_native_start_fn)(void);
typedef int  (*be_native_stop_fn)(void);
typedef int  (*be_native_status_fn)(void);

/* BattlEye shim internal state */
typedef struct {
    char            game_dir[MAX_PATH_LEN];
    char            be_dir[MAX_PATH_LEN];       /* <game_dir>/BattlEye */
    char            runtime_path[MAX_PATH_LEN];
    void           *native_handle;              /* dlopen handle */
    int             using_native;
    be_status_t     status;
    int             has_beservice;              /* BEService_x64.exe found */
    int             has_beclient;               /* BEClient_x64.dll found */

    /* Native function pointers */
    be_native_init_fn       native_init;
    be_native_start_fn      native_start;
    be_native_stop_fn       native_stop;
    be_native_status_fn     native_status;
} be_state_t;

static be_state_t g_be = { {0}, {0}, {0}, NULL, 0, BE_STATUS_NOT_INITIALIZED,
                            0, 0, NULL, NULL, NULL, NULL };

/* Forward declarations */
static int  mkdir_p(const char *path);
static int  file_exists(const char *path);
static int  scan_battleye_directory(const char *game_dir);
static int  try_load_native_runtime(const char *game_dir);
static int  setup_be_directory_structure(const char *game_dir);
static int  register_be_service(void);
static int  register_be_driver(void);
static int  create_reg_value(const char *reg_path, const char *name, const char *value);

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

static int file_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
}

static int create_reg_value(const char *reg_path, const char *name, const char *value)
{
    char values_dir[MAX_PATH_LEN];
    snprintf(values_dir, sizeof(values_dir), "%s/.values", reg_path);
    mkdir_p(values_dir);

    char val_path[MAX_PATH_LEN];
    snprintf(val_path, sizeof(val_path), "%s/%s", values_dir, name);

    FILE *f = fopen(val_path, "wb");
    if (!f) return -1;

    unsigned int type = 1; /* REG_SZ */
    fwrite(&type, sizeof(unsigned int), 1, f);
    fwrite(value, 1, strlen(value) + 1, f);
    fclose(f);
    return 0;
}

/*
 * Scan the game's BattlEye directory for known files.
 * This helps determine what components are available.
 */
static int scan_battleye_directory(const char *game_dir)
{
    char path[MAX_PATH_LEN];

    fprintf(stderr, BE_LOG_PREFIX "Scanning BattlEye directory in %s\n", game_dir);

    /* Check for BEService executables */
    snprintf(path, sizeof(path), "%s/BattlEye/BEService_x64.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, BE_LOG_PREFIX "Found BEService_x64.exe\n");
        g_be.has_beservice = 1;
    }

    snprintf(path, sizeof(path), "%s/BEService_x64.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, BE_LOG_PREFIX "Found BEService_x64.exe (root)\n");
        g_be.has_beservice = 1;
    }

    snprintf(path, sizeof(path), "%s/BattlEye/BEService.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, BE_LOG_PREFIX "Found BEService.exe\n");
        g_be.has_beservice = 1;
    }

    /* Check for BEClient DLLs */
    snprintf(path, sizeof(path), "%s/BattlEye/BEClient_x64.dll", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, BE_LOG_PREFIX "Found BEClient_x64.dll\n");
        g_be.has_beclient = 1;
    }

    snprintf(path, sizeof(path), "%s/BEClient_x64.dll", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, BE_LOG_PREFIX "Found BEClient_x64.dll (root)\n");
        g_be.has_beclient = 1;
    }

    snprintf(path, sizeof(path), "%s/BattlEye/BEClient.dll", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, BE_LOG_PREFIX "Found BEClient.dll\n");
        g_be.has_beclient = 1;
    }

    fprintf(stderr, BE_LOG_PREFIX "Scan result: BEService=%s, BEClient=%s\n",
            g_be.has_beservice ? "found" : "not found",
            g_be.has_beclient ? "found" : "not found");

    return 0;
}

/*
 * Attempt to load the native BattlEye runtime.
 * BattlEye's Proton support provides a Linux shared library.
 * Search paths:
 *   1. <game_dir>/BattlEye/libBEClient_x64.so
 *   2. <game_dir>/BattlEye/libBEClient.so
 *   3. <game_dir>/libBEClient_x64.so
 *   4. <game_dir>/libBEClient.so
 */
static int try_load_native_runtime(const char *game_dir)
{
    const char *search_paths[] = {
        "%s/BattlEye/libBEClient_x64.so",
        "%s/BattlEye/libBEClient.so",
        "%s/libBEClient_x64.so",
        "%s/libBEClient.so",
        NULL
    };

    char path[MAX_PATH_LEN];

    for (int i = 0; search_paths[i] != NULL; i++) {
        snprintf(path, sizeof(path), search_paths[i], game_dir);

        if (!file_exists(path))
            continue;

        fprintf(stderr, BE_LOG_PREFIX "Found native runtime: %s\n", path);

        void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            fprintf(stderr, BE_LOG_PREFIX "dlopen failed: %s\n", dlerror());
            continue;
        }

        fprintf(stderr, BE_LOG_PREFIX "Successfully loaded native BattlEye runtime\n");

        /* Resolve function pointers */
        g_be.native_init   = (be_native_init_fn)dlsym(handle, "be_init");
        g_be.native_start  = (be_native_start_fn)dlsym(handle, "be_start_service");
        g_be.native_stop   = (be_native_stop_fn)dlsym(handle, "be_stop_service");
        g_be.native_status = (be_native_status_fn)dlsym(handle, "be_get_status");

        if (g_be.native_init)
            fprintf(stderr, BE_LOG_PREFIX "Resolved be_init from native runtime\n");
        if (g_be.native_start)
            fprintf(stderr, BE_LOG_PREFIX "Resolved be_start_service from native runtime\n");
        if (g_be.native_stop)
            fprintf(stderr, BE_LOG_PREFIX "Resolved be_stop_service from native runtime\n");
        if (g_be.native_status)
            fprintf(stderr, BE_LOG_PREFIX "Resolved be_get_status from native runtime\n");

        g_be.native_handle = handle;
        strncpy(g_be.runtime_path, path, sizeof(g_be.runtime_path) - 1);
        return 1;
    }

    fprintf(stderr, BE_LOG_PREFIX "No native BattlEye runtime found, using stub mode\n");
    return 0;
}

/*
 * Set up the BattlEye directory structure that games expect:
 *   <game_dir>/BattlEye/
 *   <game_dir>/BattlEye/BELauncher/
 *   <game_dir>/BattlEye/Logs/
 */
static int setup_be_directory_structure(const char *game_dir)
{
    char path[MAX_PATH_LEN];
    int ret = 0;

    fprintf(stderr, BE_LOG_PREFIX "Setting up BattlEye directory structure\n");

    snprintf(path, sizeof(path), "%s/BattlEye", game_dir);
    if (mkdir_p(path) < 0 && errno != EEXIST) {
        fprintf(stderr, BE_LOG_PREFIX "Failed to create %s: %s\n", path, strerror(errno));
        ret = -1;
    }

    /* Store the BattlEye directory path */
    strncpy(g_be.be_dir, path, sizeof(g_be.be_dir) - 1);

    snprintf(path, sizeof(path), "%s/BattlEye/BELauncher", game_dir);
    if (mkdir_p(path) < 0 && errno != EEXIST) {
        fprintf(stderr, BE_LOG_PREFIX "Failed to create %s: %s\n", path, strerror(errno));
        ret = -1;
    }

    snprintf(path, sizeof(path), "%s/BattlEye/Logs", game_dir);
    if (mkdir_p(path) < 0 && errno != EEXIST) {
        fprintf(stderr, BE_LOG_PREFIX "Failed to create %s: %s\n", path, strerror(errno));
        ret = -1;
    }

    /* Create a stub BattlEye launch config if not present */
    snprintf(path, sizeof(path), "%s/BattlEye/BELauncher.ini", game_dir);
    struct stat st;
    if (stat(path, &st) != 0) {
        FILE *f = fopen(path, "w");
        if (f) {
            fprintf(f, "[BELauncher]\n");
            fprintf(f, "BEArg=-be\n");
            fprintf(f, "BEPath=BattlEye\n");
            fclose(f);
            fprintf(stderr, BE_LOG_PREFIX "Created default BELauncher.ini\n");
        }
    }

    if (ret == 0)
        fprintf(stderr, BE_LOG_PREFIX "Directory structure ready\n");

    return ret;
}

/*
 * Register BEService as a Windows service in the SCM database.
 */
static int register_be_service(void)
{
    char path[MAX_PATH_LEN];

    fprintf(stderr, BE_LOG_PREFIX "Registering BEService as Windows service via SCM\n");

    mkdir_p(BE_SVC_PATH);

    snprintf(path, sizeof(path), "%s/BEService.svc", BE_SVC_PATH);

    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, BE_LOG_PREFIX "Failed to create service file: %s\n",
                strerror(errno));
        return -1;
    }

    fprintf(f, "name=BEService\n");
    fprintf(f, "display=BattlEye Service\n");
    fprintf(f, "binary=BEService_x64.exe\n");
    fprintf(f, "type=%d\n", 0x00000010); /* SERVICE_WIN32_OWN_PROCESS */
    fprintf(f, "start=%d\n", 3);         /* SERVICE_DEMAND_START */
    fprintf(f, "depends=\n");
    fclose(f);

    fprintf(stderr, BE_LOG_PREFIX "BEService registered successfully\n");

    /* Create registry entries for BEService */
    char reg_path[MAX_PATH_LEN];
    snprintf(reg_path, sizeof(reg_path),
             "%s/HKLM/SYSTEM/CurrentControlSet/Services/BEService", BE_REG_PATH);
    mkdir_p(reg_path);

    create_reg_value(reg_path, "DisplayName", "BattlEye Service");
    create_reg_value(reg_path, "ImagePath",
                     "C:\\Program Files (x86)\\Common Files\\BattlEye\\BEService.exe");

    fprintf(stderr, BE_LOG_PREFIX "BEService registry entries created\n");
    return 0;
}

/*
 * Register BEDaisy kernel driver in the SCM database.
 * This is a fake registration - we don't actually load a kernel driver.
 */
static int register_be_driver(void)
{
    char path[MAX_PATH_LEN];

    fprintf(stderr, BE_LOG_PREFIX "Registering BEDaisy kernel driver via SCM\n");

    mkdir_p(BE_SVC_PATH);

    snprintf(path, sizeof(path), "%s/BEDaisy.svc", BE_SVC_PATH);

    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, BE_LOG_PREFIX "Failed to create driver service file: %s\n",
                strerror(errno));
        return -1;
    }

    fprintf(f, "name=BEDaisy\n");
    fprintf(f, "display=BattlEye Protection Driver\n");
    fprintf(f, "binary=BEDaisy.sys\n");
    fprintf(f, "type=%d\n", 0x00000001); /* SERVICE_KERNEL_DRIVER */
    fprintf(f, "start=%d\n", 3);         /* SERVICE_DEMAND_START */
    fprintf(f, "depends=\n");
    fclose(f);

    /* Registry entries for BEDaisy */
    char reg_path[MAX_PATH_LEN];
    snprintf(reg_path, sizeof(reg_path),
             "%s/HKLM/SYSTEM/CurrentControlSet/Services/BEDaisy", BE_REG_PATH);
    mkdir_p(reg_path);

    create_reg_value(reg_path, "DisplayName", "BattlEye Protection Driver");
    create_reg_value(reg_path, "ImagePath",
                     "\\SystemRoot\\System32\\drivers\\BEDaisy.sys");

    fprintf(stderr, BE_LOG_PREFIX "BEDaisy driver registered\n");
    return 0;
}

/* --- Public API --- */

/*
 * be_init - Initialize the BattlEye shim
 *
 * @game_dir: Path to the game installation directory
 *
 * Scans for BattlEye components, sets up directory structure,
 * registers services, and loads native runtime if available.
 *
 * Returns 0 on success, -1 on error.
 */
int be_init(const char *game_dir)
{
    if (!game_dir || !game_dir[0]) {
        fprintf(stderr, BE_LOG_PREFIX "be_init: game directory is required\n");
        return -1;
    }

    if (g_be.status != BE_STATUS_NOT_INITIALIZED) {
        fprintf(stderr, BE_LOG_PREFIX "be_init: already initialized\n");
        return -1;
    }

    fprintf(stderr, BE_LOG_PREFIX "Initializing BattlEye shim for: %s\n", game_dir);

    strncpy(g_be.game_dir, game_dir, sizeof(g_be.game_dir) - 1);
    g_be.game_dir[sizeof(g_be.game_dir) - 1] = '\0';

    /* Set up directory structure */
    if (setup_be_directory_structure(game_dir) < 0) {
        fprintf(stderr, BE_LOG_PREFIX "Warning: directory structure setup had errors\n");
    }

    /* Scan for existing BattlEye files */
    scan_battleye_directory(game_dir);

    /* Register BEService and BEDaisy with SCM */
    if (register_be_service() < 0) {
        fprintf(stderr, BE_LOG_PREFIX "Warning: BEService registration failed\n");
    }
    if (register_be_driver() < 0) {
        fprintf(stderr, BE_LOG_PREFIX "Warning: BEDaisy registration failed\n");
    }

    /* Try to load native runtime */
    g_be.using_native = try_load_native_runtime(game_dir);

    /* Forward init to native runtime if available */
    if (g_be.using_native && g_be.native_init) {
        fprintf(stderr, BE_LOG_PREFIX "Forwarding init to native runtime\n");
        int ret = g_be.native_init();
        if (ret != 0) {
            fprintf(stderr, BE_LOG_PREFIX "Native init returned error %d, "
                    "falling back to stub mode\n", ret);
            dlclose(g_be.native_handle);
            g_be.native_handle = NULL;
            g_be.using_native = 0;
            g_be.native_init = NULL;
            g_be.native_start = NULL;
            g_be.native_stop = NULL;
            g_be.native_status = NULL;
        }
    }

    g_be.status = BE_STATUS_INITIALIZED;
    fprintf(stderr, BE_LOG_PREFIX "BattlEye shim initialized (mode: %s)\n",
            g_be.using_native ? "native" : "stub");

    return 0;
}

/*
 * be_start_service - Start the BattlEye service
 *
 * If using native runtime, forwards to the real implementation.
 * In stub mode, reports the service as running.
 *
 * Returns 0 on success, -1 on error.
 */
int be_start_service(void)
{
    if (g_be.status == BE_STATUS_NOT_INITIALIZED) {
        fprintf(stderr, BE_LOG_PREFIX "be_start_service: not initialized\n");
        return -1;
    }

    if (g_be.status == BE_STATUS_SERVICE_RUNNING) {
        fprintf(stderr, BE_LOG_PREFIX "be_start_service: already running\n");
        return 0;
    }

    fprintf(stderr, BE_LOG_PREFIX "Starting BattlEye service\n");

    if (g_be.using_native && g_be.native_start) {
        fprintf(stderr, BE_LOG_PREFIX "Forwarding start to native runtime\n");
        int ret = g_be.native_start();
        if (ret != 0) {
            fprintf(stderr, BE_LOG_PREFIX "Native start returned error %d\n", ret);
            g_be.status = BE_STATUS_ERROR;
            return -1;
        }
    } else {
        fprintf(stderr, BE_LOG_PREFIX "Stub mode: reporting BEService as running\n");

        /* Create a status file for other components to check */
        char status_path[MAX_PATH_LEN];
        snprintf(status_path, sizeof(status_path), "%s/BattlEye/.beservice_running",
                 g_be.game_dir);
        FILE *f = fopen(status_path, "w");
        if (f) {
            fprintf(f, "pid=%d\n", getpid());
            fclose(f);
        }
    }

    g_be.status = BE_STATUS_SERVICE_RUNNING;
    fprintf(stderr, BE_LOG_PREFIX "BattlEye service is now running\n");
    return 0;
}

/*
 * be_stop_service - Stop the BattlEye service
 *
 * Returns 0 on success, -1 on error.
 */
int be_stop_service(void)
{
    if (g_be.status == BE_STATUS_NOT_INITIALIZED) {
        fprintf(stderr, BE_LOG_PREFIX "be_stop_service: not initialized\n");
        return -1;
    }

    if (g_be.status == BE_STATUS_SERVICE_STOPPED) {
        fprintf(stderr, BE_LOG_PREFIX "be_stop_service: already stopped\n");
        return 0;
    }

    fprintf(stderr, BE_LOG_PREFIX "Stopping BattlEye service\n");

    if (g_be.using_native && g_be.native_stop) {
        fprintf(stderr, BE_LOG_PREFIX "Forwarding stop to native runtime\n");
        int ret = g_be.native_stop();
        if (ret != 0) {
            fprintf(stderr, BE_LOG_PREFIX "Native stop returned error %d\n", ret);
        }
    }

    /* Remove status file */
    char status_path[MAX_PATH_LEN];
    snprintf(status_path, sizeof(status_path), "%s/BattlEye/.beservice_running",
             g_be.game_dir);
    unlink(status_path);

    /* Unload native runtime */
    if (g_be.native_handle) {
        fprintf(stderr, BE_LOG_PREFIX "Unloading native runtime\n");
        dlclose(g_be.native_handle);
        g_be.native_handle = NULL;
        g_be.native_init = NULL;
        g_be.native_start = NULL;
        g_be.native_stop = NULL;
        g_be.native_status = NULL;
        g_be.using_native = 0;
    }

    g_be.status = BE_STATUS_SERVICE_STOPPED;
    fprintf(stderr, BE_LOG_PREFIX "BattlEye service stopped\n");
    return 0;
}

/*
 * be_get_status - Query current BattlEye status
 *
 * Returns the current be_status_t value.
 */
be_status_t be_get_status(void)
{
    if (g_be.using_native && g_be.native_status) {
        int native_status = g_be.native_status();
        fprintf(stderr, BE_LOG_PREFIX "Native status query returned: %d\n", native_status);
        return (be_status_t)native_status;
    }

    const char *status_names[] = {
        "NOT_INITIALIZED", "INITIALIZED",
        "SERVICE_RUNNING", "SERVICE_STOPPED", "ERROR"
    };
    fprintf(stderr, BE_LOG_PREFIX "Status: %s (mode: %s, BEService=%s, BEClient=%s)\n",
            status_names[g_be.status],
            g_be.using_native ? "native" : "stub",
            g_be.has_beservice ? "found" : "missing",
            g_be.has_beclient ? "found" : "missing");

    return g_be.status;
}
