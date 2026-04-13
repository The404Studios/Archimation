/*
 * driver_install.c - Windows driver installation manager
 *
 * Handles the complete driver installation workflow:
 *   1. Parse the .inf file to determine driver contents
 *   2. Copy .sys binary files to /var/lib/pe-compat/drivers/
 *   3. Register the driver as a kernel driver service with the SCM
 *   4. Set up device namespace entries for the driver's devices
 *   5. Apply registry entries defined in the .inf file
 *
 * Also supports uninstallation (reverse of the above) and listing
 * of installed drivers with their status information.
 *
 * Driver metadata is stored at /var/lib/pe-compat/drivers/<name>.drv
 * alongside the actual .sys binary.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>

#define DRV_LOG_PREFIX      "[drv_install] "
#define DRV_BASE_PATH       "/var/lib/pe-compat/drivers"
#define DRV_REGISTRY_PATH   "/var/lib/pe-compat/registry"
#define SCM_DB_PATH         "/var/lib/pe-compat/services"
#define DEVNS_RUN_PATH      "/run/pe-compat/devices"

#define MAX_PATH_LEN    1024
#define MAX_NAME_LEN    256

/* Service types (matching SCM daemon) */
#define SERVICE_KERNEL_DRIVER       0x00000001
#define SERVICE_FILE_SYSTEM_DRIVER  0x00000002

/* Start types */
#define SERVICE_BOOT_START      0
#define SERVICE_SYSTEM_START    1
#define SERVICE_AUTO_START      2
#define SERVICE_DEMAND_START    3

/* ---- INF parser types (duplicated minimally to avoid header dependency) ---- */

typedef struct {
    char    key[256];
    char    value[1024];
} inf_entry_t;

typedef struct {
    char            name[256];
    inf_entry_t     entries[512];
    int             num_entries;
} inf_section_t;

typedef struct {
    char    filename[256];
    char    source_dir[512];
    char    dest_dir[512];
    int     is_sys;
} inf_driver_file_t;

typedef struct {
    char    root_key[64];
    char    subkey[512];
    char    value_name[256];
    char    value_data[512];
    int     value_type;
} inf_reg_entry_t;

typedef struct {
    char                filepath[1024];
    inf_section_t       sections[128];
    int                 num_sections;
    inf_driver_file_t   driver_files[64];
    int                 num_driver_files;
    inf_reg_entry_t     reg_entries[128];
    int                 num_reg_entries;
} inf_file_t;

/* External INF parser functions (from inf_parser.c) */
extern inf_file_t      *inf_parse_file(const char *filepath);
extern inf_section_t   *inf_get_section(inf_file_t *inf, const char *name);
extern const char      *inf_get_value(inf_file_t *inf, const char *section,
                                      const char *key);
extern int              inf_get_driver_files(inf_file_t *inf,
                                             inf_driver_file_t **out_files,
                                             int *out_count);
extern int              inf_get_registry_entries(inf_file_t *inf,
                                                 inf_reg_entry_t **out_entries,
                                                 int *out_count);
extern void             inf_free(inf_file_t *inf);

/* External device namespace functions (from device_namespace.c) */
extern int device_namespace_init(void);
extern int device_register(const char *win_name, const char *linux_path,
                           const char *driver_name, int device_type,
                           void *driver_context);
extern int device_unregister(const char *win_name);

/* Forward declarations */
static int  ensure_directories(void);
static int  copy_file(const char *src, const char *dst);
static int  register_with_scm(const char *driver_name,
                               const char *display_name,
                               const char *sys_path,
                               int service_type, int start_type);
static int  unregister_from_scm(const char *driver_name);
static int  apply_registry_entries(const inf_reg_entry_t *entries, int count);
static int  remove_registry_entries(const char *driver_name);
static int  save_driver_metadata(const char *driver_name,
                                  const char *inf_path,
                                  const char *hardware_id,
                                  const inf_driver_file_t *files,
                                  int num_files);
static int  load_driver_metadata(const char *driver_name, char *inf_path,
                                  size_t inf_path_len, char *hardware_id,
                                  size_t hw_id_len);

/*
 * ensure_directories - Create all required directory paths.
 */
static int ensure_directories(void)
{
    const char *dirs[] = {
        "/var/lib/pe-compat",
        DRV_BASE_PATH,
        DRV_REGISTRY_PATH,
        SCM_DB_PATH,
        "/run/pe-compat",
        DEVNS_RUN_PATH,
        NULL
    };

    for (const char **d = dirs; *d; d++) {
        if (mkdir(*d, 0755) < 0 && errno != EEXIST) {
            fprintf(stderr, DRV_LOG_PREFIX
                    "Failed to create directory '%s': %s\n",
                    *d, strerror(errno));
            /* Non-fatal: directory may already exist from another component */
        }
    }

    return 0;
}

/*
 * copy_file - Copy a file from src to dst using buffered I/O.
 *
 * Returns 0 on success, -1 on failure.
 */
static int copy_file(const char *src, const char *dst)
{
    FILE *fin = fopen(src, "rb");
    if (!fin) {
        fprintf(stderr, DRV_LOG_PREFIX
                "Cannot open source file '%s': %s\n", src, strerror(errno));
        return -1;
    }

    FILE *fout = fopen(dst, "wb");
    if (!fout) {
        fprintf(stderr, DRV_LOG_PREFIX
                "Cannot create destination file '%s': %s\n",
                dst, strerror(errno));
        fclose(fin);
        return -1;
    }

    char buf[8192];
    size_t n;
    size_t total = 0;

    while ((n = fread(buf, 1, sizeof(buf), fin)) > 0) {
        if (fwrite(buf, 1, n, fout) != n) {
            fprintf(stderr, DRV_LOG_PREFIX
                    "Write error to '%s': %s\n", dst, strerror(errno));
            fclose(fin);
            fclose(fout);
            unlink(dst);
            return -1;
        }
        total += n;
    }

    fclose(fin);
    fclose(fout);

    /* Preserve reasonable permissions */
    chmod(dst, 0644);

    fprintf(stderr, DRV_LOG_PREFIX
            "Copied '%s' -> '%s' (%zu bytes)\n", src, dst, total);
    return 0;
}

/*
 * register_with_scm - Register the driver as a service in the SCM database.
 *
 * Creates a service configuration file at /var/lib/pe-compat/services/<name>.svc
 * in the format expected by scm_daemon.
 */
static int register_with_scm(const char *driver_name,
                               const char *display_name,
                               const char *sys_path,
                               int service_type, int start_type)
{
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s.svc", SCM_DB_PATH, driver_name);

    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, DRV_LOG_PREFIX
                "Failed to create SCM entry '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    fprintf(f, "name=%s\n", driver_name);
    fprintf(f, "display=%s\n", display_name ? display_name : driver_name);
    fprintf(f, "binary=%s\n", sys_path);
    fprintf(f, "type=%d\n", service_type);
    fprintf(f, "start=%d\n", start_type);
    fprintf(f, "depends=\n");
    fclose(f);

    fprintf(stderr, DRV_LOG_PREFIX
            "Registered with SCM: %s (type=%d, start=%d)\n",
            driver_name, service_type, start_type);
    return 0;
}

/*
 * unregister_from_scm - Remove a service entry from the SCM database.
 */
static int unregister_from_scm(const char *driver_name)
{
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s.svc", SCM_DB_PATH, driver_name);

    if (unlink(path) < 0 && errno != ENOENT) {
        fprintf(stderr, DRV_LOG_PREFIX
                "Failed to remove SCM entry '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    fprintf(stderr, DRV_LOG_PREFIX "Unregistered from SCM: %s\n", driver_name);
    return 0;
}

/*
 * apply_registry_entries - Write registry entries to the emulated registry.
 *
 * Each entry is stored as a file under /var/lib/pe-compat/registry/ with
 * the subkey path encoded in the filename.
 */
static int apply_registry_entries(const inf_reg_entry_t *entries, int count)
{
    int applied = 0;

    for (int i = 0; i < count; i++) {
        const inf_reg_entry_t *reg = &entries[i];

        if (!reg->subkey[0]) continue;

        /* Create a path-safe version of the subkey */
        char safe_subkey[512];
        size_t j = 0;
        for (size_t k = 0; reg->subkey[k] && j < sizeof(safe_subkey) - 1; k++) {
            char c = reg->subkey[k];
            if (c == '\\' || c == '/')
                safe_subkey[j++] = '_';
            else
                safe_subkey[j++] = c;
        }
        safe_subkey[j] = '\0';

        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s/%s_%s_%s",
                 DRV_REGISTRY_PATH,
                 reg->root_key, safe_subkey,
                 reg->value_name[0] ? reg->value_name : "_default_");

        FILE *f = fopen(path, "w");
        if (!f) {
            fprintf(stderr, DRV_LOG_PREFIX
                    "Failed to write registry entry '%s': %s\n",
                    path, strerror(errno));
            continue;
        }

        fprintf(f, "root=%s\n", reg->root_key);
        fprintf(f, "subkey=%s\n", reg->subkey);
        fprintf(f, "name=%s\n", reg->value_name);
        fprintf(f, "type=%d\n", reg->value_type);
        fprintf(f, "data=%s\n", reg->value_data);
        fclose(f);

        applied++;
    }

    fprintf(stderr, DRV_LOG_PREFIX
            "Applied %d/%d registry entries\n", applied, count);
    return 0;
}

/*
 * remove_registry_entries - Remove all registry entries associated with
 * a driver. Scans registry files for entries referencing the driver's
 * service subkey.
 */
static int remove_registry_entries(const char *driver_name)
{
    DIR *dir = opendir(DRV_REGISTRY_PATH);
    if (!dir) return 0;

    /* Build a pattern to match: entries containing the driver name in subkey */
    char pattern[MAX_NAME_LEN];
    snprintf(pattern, sizeof(pattern), "Services_%s", driver_name);

    struct dirent *entry;
    int removed = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        /* Check if this registry file is associated with our driver */
        if (strstr(entry->d_name, pattern)) {
            char path[MAX_PATH_LEN];
            snprintf(path, sizeof(path), "%s/%s",
                     DRV_REGISTRY_PATH, entry->d_name);
            if (unlink(path) == 0)
                removed++;
        }
    }

    closedir(dir);
    fprintf(stderr, DRV_LOG_PREFIX
            "Removed %d registry entries for driver '%s'\n",
            removed, driver_name);
    return 0;
}

/*
 * save_driver_metadata - Save driver installation metadata for later
 * reference (uninstall, status queries).
 */
static int save_driver_metadata(const char *driver_name,
                                  const char *inf_path,
                                  const char *hardware_id,
                                  const inf_driver_file_t *files,
                                  int num_files)
{
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s.drv", DRV_BASE_PATH, driver_name);

    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, DRV_LOG_PREFIX
                "Failed to save metadata '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    fprintf(f, "name=%s\n", driver_name);
    fprintf(f, "inf=%s\n", inf_path ? inf_path : "");
    fprintf(f, "hwid=%s\n", hardware_id ? hardware_id : "");
    fprintf(f, "num_files=%d\n", num_files);

    for (int i = 0; i < num_files; i++) {
        fprintf(f, "file.%d.name=%s\n", i, files[i].filename);
        fprintf(f, "file.%d.dest=%s\n", i, files[i].dest_dir);
        fprintf(f, "file.%d.sys=%d\n", i, files[i].is_sys);
    }

    fclose(f);
    return 0;
}

/*
 * load_driver_metadata - Load driver installation metadata from disk.
 */
static int load_driver_metadata(const char *driver_name, char *inf_path,
                                  size_t inf_path_len, char *hardware_id,
                                  size_t hw_id_len)
{
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s.drv", DRV_BASE_PATH, driver_name);

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *key = line;
        const char *val = eq + 1;

        if (strcmp(key, "inf") == 0 && inf_path)
            strncpy(inf_path, val, inf_path_len - 1);
        else if (strcmp(key, "hwid") == 0 && hardware_id)
            strncpy(hardware_id, val, hw_id_len - 1);
    }

    fclose(f);
    return 0;
}

/*
 * derive_driver_name - Extract a driver name from the .inf file contents.
 *
 * Tries the following in order:
 *   1. The first .sys file's basename (without extension)
 *   2. The .inf file's basename (without extension)
 */
static void derive_driver_name(const inf_file_t *inf, const char *inf_path,
                                char *name, size_t name_len)
{
    /* Try first .sys file */
    for (int i = 0; i < inf->num_driver_files; i++) {
        if (inf->driver_files[i].is_sys) {
            char tmp[256];
            strncpy(tmp, inf->driver_files[i].filename, sizeof(tmp) - 1);
            tmp[sizeof(tmp) - 1] = '\0';
            /* Remove .sys extension */
            char *dot = strrchr(tmp, '.');
            if (dot) *dot = '\0';
            strncpy(name, tmp, name_len - 1);
            name[name_len - 1] = '\0';
            return;
        }
    }

    /* Fall back to .inf filename */
    char tmp[MAX_PATH_LEN];
    strncpy(tmp, inf_path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    char *base = basename(tmp);
    char *dot = strrchr(base, '.');
    if (dot) *dot = '\0';
    strncpy(name, base, name_len - 1);
    name[name_len - 1] = '\0';
}

/*
 * driver_install - Install a Windows driver from an .inf file.
 *
 * inf_path:     Path to the .inf file
 * hardware_id:  Hardware ID string (e.g., "PCI\\VEN_8086&DEV_1234")
 *               Used for matching and display, may be NULL.
 *
 * The installation process:
 *   1. Parse the .inf file
 *   2. Determine driver name from .sys filename
 *   3. Copy all .sys files to /var/lib/pe-compat/drivers/
 *   4. Register as a kernel driver service with the SCM
 *   5. Set up device namespace entries
 *   6. Apply registry entries from the .inf
 *   7. Save installation metadata
 *
 * Returns 0 on success, -1 on failure.
 */
int driver_install(const char *inf_path, const char *hardware_id)
{
    if (!inf_path) {
        fprintf(stderr, DRV_LOG_PREFIX "driver_install: NULL inf_path\n");
        return -1;
    }

    fprintf(stderr, DRV_LOG_PREFIX
            "Installing driver from '%s' (hwid=%s)\n",
            inf_path, hardware_id ? hardware_id : "<none>");

    ensure_directories();

    /* Step 1: Parse the .inf file */
    inf_file_t *inf = inf_parse_file(inf_path);
    if (!inf) {
        fprintf(stderr, DRV_LOG_PREFIX "Failed to parse '%s'\n", inf_path);
        return -1;
    }

    /* Step 2: Determine driver name */
    char driver_name[MAX_NAME_LEN];
    memset(driver_name, 0, sizeof(driver_name));

    /* Try [Version] section for DriverVer or provider info */
    const char *class_name = inf_get_value(inf, "Version", "Class");
    const char *provider = inf_get_value(inf, "Version", "Provider");

    derive_driver_name(inf, inf_path, driver_name, sizeof(driver_name));

    if (!driver_name[0]) {
        fprintf(stderr, DRV_LOG_PREFIX
                "Could not determine driver name from '%s'\n", inf_path);
        inf_free(inf);
        return -1;
    }

    fprintf(stderr, DRV_LOG_PREFIX "Driver name: %s\n", driver_name);
    if (class_name)
        fprintf(stderr, DRV_LOG_PREFIX "Class: %s\n", class_name);
    if (provider)
        fprintf(stderr, DRV_LOG_PREFIX "Provider: %s\n", provider);

    /* Step 3: Copy .sys files */
    inf_driver_file_t *files = NULL;
    int num_files = 0;
    inf_get_driver_files(inf, &files, &num_files);

    /* Determine source directory (directory containing the .inf) */
    char src_dir[MAX_PATH_LEN];
    strncpy(src_dir, inf_path, sizeof(src_dir) - 1);
    src_dir[sizeof(src_dir) - 1] = '\0';
    char *last_slash = strrchr(src_dir, '/');
    if (!last_slash)
        last_slash = strrchr(src_dir, '\\');
    if (last_slash)
        *last_slash = '\0';
    else
        strcpy(src_dir, ".");

    char primary_sys_path[MAX_PATH_LEN] = "";
    int files_copied = 0;

    for (int i = 0; i < num_files; i++) {
        if (!files[i].is_sys) continue;

        char src_file[MAX_PATH_LEN];
        snprintf(src_file, sizeof(src_file), "%s/%s",
                 src_dir, files[i].filename);

        char dst_file[MAX_PATH_LEN];
        snprintf(dst_file, sizeof(dst_file), "%s/%s",
                 DRV_BASE_PATH, files[i].filename);

        if (copy_file(src_file, dst_file) == 0) {
            files_copied++;
            if (!primary_sys_path[0])
                strncpy(primary_sys_path, dst_file,
                        sizeof(primary_sys_path) - 1);
        } else {
            fprintf(stderr, DRV_LOG_PREFIX
                    "Warning: failed to copy '%s'\n", src_file);
        }
    }

    fprintf(stderr, DRV_LOG_PREFIX
            "Copied %d/%d driver files\n", files_copied, num_files);

    if (!primary_sys_path[0] && num_files > 0) {
        /* If copy failed, set a path anyway for the SCM registration */
        snprintf(primary_sys_path, sizeof(primary_sys_path),
                 "%s/%s", DRV_BASE_PATH, files[0].filename);
    }

    /* Step 4: Register with SCM */
    char display_name[MAX_NAME_LEN];
    if (class_name)
        snprintf(display_name, sizeof(display_name), "%s (%s)",
                 driver_name, class_name);
    else
        strncpy(display_name, driver_name, sizeof(display_name) - 1);

    /* Determine service type from .inf Class */
    int service_type = SERVICE_KERNEL_DRIVER;
    if (class_name && strcasecmp(class_name, "DiskDrive") == 0)
        service_type = SERVICE_FILE_SYSTEM_DRIVER;

    /* Determine start type from .inf StartType or default to demand */
    int start_type = SERVICE_DEMAND_START;
    const char *start_val = inf_get_value(inf, "DefaultInstall.Services",
                                           "StartType");
    if (!start_val)
        start_val = inf_get_value(inf, "DefaultInstall", "StartType");
    if (start_val)
        start_type = atoi(start_val);

    if (register_with_scm(driver_name, display_name, primary_sys_path,
                           service_type, start_type) < 0) {
        fprintf(stderr, DRV_LOG_PREFIX "SCM registration failed\n");
        /* Continue anyway - driver files are already copied */
    }

    /* Step 5: Set up device namespace entries */
    device_namespace_init();

    /* Create a virtual device entry for the driver */
    char win_dev_name[MAX_NAME_LEN];
    snprintf(win_dev_name, sizeof(win_dev_name), "\\\\.\\%s", driver_name);
    char linux_dev_path[MAX_PATH_LEN];
    snprintf(linux_dev_path, sizeof(linux_dev_path),
             "/run/pe-compat/devices/%s", driver_name);

    device_register(win_dev_name, linux_dev_path, driver_name,
                    0x04 /* DEVNS_TYPE_VIRTUAL */, NULL);

    /* Step 6: Apply registry entries */
    inf_reg_entry_t *reg_entries = NULL;
    int num_reg = 0;
    inf_get_registry_entries(inf, &reg_entries, &num_reg);

    if (num_reg > 0)
        apply_registry_entries(reg_entries, num_reg);

    /* Step 7: Save metadata */
    save_driver_metadata(driver_name, inf_path, hardware_id,
                          files, num_files);

    fprintf(stderr, DRV_LOG_PREFIX
            "Driver '%s' installed successfully "
            "(%d files, %d registry entries)\n",
            driver_name, files_copied, num_reg);

    inf_free(inf);
    return 0;
}

/*
 * driver_uninstall - Uninstall a previously installed driver.
 *
 * driver_name: Name of the driver to uninstall.
 *
 * Returns 0 on success, -1 on failure.
 */
int driver_uninstall(const char *driver_name)
{
    if (!driver_name) {
        fprintf(stderr, DRV_LOG_PREFIX "driver_uninstall: NULL driver_name\n");
        return -1;
    }

    fprintf(stderr, DRV_LOG_PREFIX "Uninstalling driver '%s'\n", driver_name);

    /* Load metadata to find files to remove */
    char inf_path[MAX_PATH_LEN] = "";
    char hardware_id[MAX_NAME_LEN] = "";
    load_driver_metadata(driver_name, inf_path, sizeof(inf_path),
                          hardware_id, sizeof(hardware_id));

    /* Unregister device namespace entries */
    char win_dev_name[MAX_NAME_LEN];
    snprintf(win_dev_name, sizeof(win_dev_name), "\\\\.\\%s", driver_name);
    device_namespace_init();
    device_unregister(win_dev_name);

    /* Remove from SCM */
    unregister_from_scm(driver_name);

    /* Remove registry entries */
    remove_registry_entries(driver_name);

    /* Remove driver files - scan for .sys files matching the driver name */
    DIR *dir = opendir(DRV_BASE_PATH);
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.') continue;

            /* Remove .sys files and the .drv metadata file */
            char *ext = strrchr(entry->d_name, '.');
            if (!ext) continue;

            char file_base[256];
            size_t base_len = (size_t)(ext - entry->d_name);
            if (base_len >= sizeof(file_base)) base_len = sizeof(file_base) - 1;
            memcpy(file_base, entry->d_name, base_len);
            file_base[base_len] = '\0';

            /* Remove files that match the driver name */
            if (strcasecmp(file_base, driver_name) == 0 ||
                (strcmp(ext, ".drv") == 0 &&
                 strcasecmp(file_base, driver_name) == 0)) {

                char path[MAX_PATH_LEN];
                snprintf(path, sizeof(path), "%s/%s",
                         DRV_BASE_PATH, entry->d_name);
                if (unlink(path) == 0) {
                    fprintf(stderr, DRV_LOG_PREFIX "Removed: %s\n", path);
                }
            }
        }
        closedir(dir);
    }

    /* Remove the metadata file explicitly */
    char meta_path[MAX_PATH_LEN];
    snprintf(meta_path, sizeof(meta_path), "%s/%s.drv",
             DRV_BASE_PATH, driver_name);
    unlink(meta_path);

    fprintf(stderr, DRV_LOG_PREFIX "Driver '%s' uninstalled\n", driver_name);
    return 0;
}

/*
 * driver_list - List all installed drivers.
 *
 * output: FILE stream to print the list to.
 *
 * Returns the number of installed drivers found.
 */
int driver_list(FILE *output)
{
    if (!output) output = stdout;

    DIR *dir = opendir(DRV_BASE_PATH);
    if (!dir) {
        fprintf(output, "No drivers installed (cannot open %s)\n",
                DRV_BASE_PATH);
        return 0;
    }

    fprintf(output, "%-20s %-30s %-15s %s\n",
            "DRIVER", "INF SOURCE", "HARDWARE ID", "SYS FILE");
    fprintf(output, "%-20s %-30s %-15s %s\n",
            "------", "----------", "-----------", "--------");

    int count = 0;
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        /* Only look at .drv metadata files */
        char *ext = strrchr(entry->d_name, '.');
        if (!ext || strcmp(ext, ".drv") != 0) continue;

        /* Extract driver name */
        char driver_name[MAX_NAME_LEN];
        size_t base_len = (size_t)(ext - entry->d_name);
        if (base_len >= sizeof(driver_name)) base_len = sizeof(driver_name) - 1;
        memcpy(driver_name, entry->d_name, base_len);
        driver_name[base_len] = '\0';

        /* Load metadata */
        char inf_path[MAX_PATH_LEN] = "";
        char hardware_id[MAX_NAME_LEN] = "";
        load_driver_metadata(driver_name, inf_path, sizeof(inf_path),
                              hardware_id, sizeof(hardware_id));

        /* Check if .sys file exists */
        char sys_path[MAX_PATH_LEN];
        snprintf(sys_path, sizeof(sys_path), "%s/%s.sys",
                 DRV_BASE_PATH, driver_name);
        struct stat st;
        const char *sys_status = (stat(sys_path, &st) == 0) ?
                                  "present" : "missing";

        /* Shorten inf_path for display */
        char *inf_display = inf_path;
        char *slash = strrchr(inf_path, '/');
        if (slash) inf_display = slash + 1;

        fprintf(output, "%-20s %-30s %-15s %s.sys (%s)\n",
                driver_name,
                inf_display[0] ? inf_display : "<unknown>",
                hardware_id[0] ? hardware_id : "<none>",
                driver_name, sys_status);
        count++;
    }

    closedir(dir);

    fprintf(output, "\nTotal: %d driver(s) installed\n", count);
    return count;
}
