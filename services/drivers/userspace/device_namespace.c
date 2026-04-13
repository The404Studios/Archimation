/*
 * device_namespace.c - Windows device namespace emulation
 *
 * Maps Windows-style device names to Linux equivalents:
 *   \\.\DeviceName       -> /dev/xxx or virtual file
 *   \\DosDevices\Name    -> /dev/xxx or virtual file
 *   \Device\Name         -> /dev/xxx or virtual file
 *
 * Maintains a registration table of device names, stored as filesystem
 * entries under /run/pe-compat/devices/ for persistence across lookups.
 * Each registered device has a symlink or config file describing its mapping.
 *
 * Thread-safe via pthread mutex for concurrent access from multiple
 * PE-loaded processes and the driver framework.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <dirent.h>
#include <ctype.h>

#define DEVNS_LOG_PREFIX    "[devns] "
#define DEVNS_RUN_PATH      "/run/pe-compat/devices"
#define MAX_DEVICES         256
#define MAX_NAME_LEN        256
#define MAX_PATH_LEN        1024

/* Device type flags */
#define DEVNS_TYPE_CHAR     0x01    /* Character device */
#define DEVNS_TYPE_BLOCK    0x02    /* Block device */
#define DEVNS_TYPE_VIRTUAL  0x04    /* Virtual device (no /dev/ backing) */
#define DEVNS_TYPE_SYMLINK  0x08    /* Symlink to real device node */

/* Device state */
#define DEVNS_STATE_INACTIVE    0
#define DEVNS_STATE_ACTIVE      1

typedef struct {
    char    win_name[MAX_NAME_LEN];     /* Windows device name (normalized) */
    char    linux_path[MAX_PATH_LEN];   /* Linux device path or virtual path */
    char    driver_name[MAX_NAME_LEN];  /* Owning driver name */
    int     device_type;                /* DEVNS_TYPE_* flags */
    int     state;                      /* DEVNS_STATE_* */
    void    *driver_context;            /* Opaque driver-specific context */
} device_entry_t;

static device_entry_t   g_devices[MAX_DEVICES];
static int              g_num_devices = 0;
static pthread_mutex_t  g_devns_lock = PTHREAD_MUTEX_INITIALIZER;
static int              g_initialized = 0;

/* Forward declarations */
static void normalize_win_name(char *dst, const char *src, size_t maxlen);
static int  persist_device(const device_entry_t *dev);
static int  unpersist_device(const char *normalized_name);
static int  load_persisted_devices(void);

/*
 * normalize_win_name - Normalize a Windows device name to a canonical form.
 *
 * Strips common prefixes (\\.\, \\DosDevices\, \Device\) and converts
 * backslashes to forward slashes for consistent internal use.
 */
static void normalize_win_name(char *dst, const char *src, size_t maxlen)
{
    const char *p = src;

    /* Strip known prefixes */
    if (strncmp(p, "\\\\.\\", 4) == 0)
        p += 4;
    else if (strncmp(p, "\\\\.\\", 4) == 0)
        p += 4;
    else if (strncasecmp(p, "\\DosDevices\\", 12) == 0)
        p += 12;
    else if (strncasecmp(p, "\\\\DosDevices\\", 13) == 0)
        p += 13;
    else if (strncasecmp(p, "\\Device\\", 8) == 0)
        p += 8;

    size_t i;
    for (i = 0; i < maxlen - 1 && p[i]; i++) {
        if (p[i] == '\\')
            dst[i] = '/';
        else
            dst[i] = p[i];
    }
    dst[i] = '\0';
}

/*
 * persist_device - Write device registration to the filesystem under
 * /run/pe-compat/devices/ so other processes can discover it.
 */
static int persist_device(const device_entry_t *dev)
{
    /* Create a safe filename from the normalized name */
    char safe_name[MAX_NAME_LEN];
    size_t j = 0;
    for (size_t i = 0; dev->win_name[i] && j < sizeof(safe_name) - 1; i++) {
        char c = dev->win_name[i];
        if (c == '/' || c == '\\')
            safe_name[j++] = '_';
        else if (isalnum((unsigned char)c) || c == '-' || c == '.')
            safe_name[j++] = c;
        else
            safe_name[j++] = '_';
    }
    safe_name[j] = '\0';

    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s", DEVNS_RUN_PATH, safe_name);

    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, DEVNS_LOG_PREFIX
                "Failed to persist device '%s': %s\n",
                dev->win_name, strerror(errno));
        return -1;
    }

    fprintf(f, "win_name=%s\n", dev->win_name);
    fprintf(f, "linux_path=%s\n", dev->linux_path);
    fprintf(f, "driver=%s\n", dev->driver_name);
    fprintf(f, "type=%d\n", dev->device_type);
    fprintf(f, "state=%d\n", dev->state);
    fclose(f);

    fprintf(stderr, DEVNS_LOG_PREFIX "Persisted device '%s' -> '%s'\n",
            dev->win_name, path);
    return 0;
}

/*
 * unpersist_device - Remove the device registration file from the filesystem.
 */
static int unpersist_device(const char *normalized_name)
{
    char safe_name[MAX_NAME_LEN];
    size_t j = 0;
    for (size_t i = 0; normalized_name[i] && j < sizeof(safe_name) - 1; i++) {
        char c = normalized_name[i];
        if (c == '/' || c == '\\')
            safe_name[j++] = '_';
        else if (isalnum((unsigned char)c) || c == '-' || c == '.')
            safe_name[j++] = c;
        else
            safe_name[j++] = '_';
    }
    safe_name[j] = '\0';

    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s", DEVNS_RUN_PATH, safe_name);

    if (unlink(path) < 0 && errno != ENOENT) {
        fprintf(stderr, DEVNS_LOG_PREFIX
                "Failed to remove device file '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    return 0;
}

/*
 * load_persisted_devices - Scan /run/pe-compat/devices/ and reload
 * any previously registered devices into the in-memory table.
 */
static int load_persisted_devices(void)
{
    DIR *dir = opendir(DEVNS_RUN_PATH);
    if (!dir) {
        /* Not an error if directory doesn't exist yet */
        return 0;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && g_num_devices < MAX_DEVICES) {
        if (entry->d_name[0] == '.')
            continue;

        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s/%s", DEVNS_RUN_PATH, entry->d_name);

        FILE *f = fopen(path, "r");
        if (!f) continue;

        device_entry_t *dev = &g_devices[g_num_devices];
        memset(dev, 0, sizeof(*dev));

        char line[1024];
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\r\n")] = '\0';
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = '\0';
            const char *key = line;
            const char *val = eq + 1;

            if (strcmp(key, "win_name") == 0)
                strncpy(dev->win_name, val, sizeof(dev->win_name) - 1);
            else if (strcmp(key, "linux_path") == 0)
                strncpy(dev->linux_path, val, sizeof(dev->linux_path) - 1);
            else if (strcmp(key, "driver") == 0)
                strncpy(dev->driver_name, val, sizeof(dev->driver_name) - 1);
            else if (strcmp(key, "type") == 0)
                dev->device_type = atoi(val);
            else if (strcmp(key, "state") == 0)
                dev->state = atoi(val);
        }
        fclose(f);

        if (dev->win_name[0]) {
            fprintf(stderr, DEVNS_LOG_PREFIX
                    "Loaded persisted device: '%s' -> '%s' (driver=%s)\n",
                    dev->win_name, dev->linux_path, dev->driver_name);
            g_num_devices++;
        }
    }

    closedir(dir);
    return 0;
}

/*
 * device_namespace_init - Initialize the device namespace subsystem.
 * Creates runtime directories and loads any persisted devices.
 *
 * Returns 0 on success, -1 on failure.
 */
int device_namespace_init(void)
{
    pthread_mutex_lock(&g_devns_lock);

    if (g_initialized) {
        pthread_mutex_unlock(&g_devns_lock);
        return 0;
    }

    /* Ensure runtime directories exist */
    mkdir("/run/pe-compat", 0755);
    mkdir(DEVNS_RUN_PATH, 0755);

    g_num_devices = 0;
    memset(g_devices, 0, sizeof(g_devices));

    load_persisted_devices();

    g_initialized = 1;
    fprintf(stderr, DEVNS_LOG_PREFIX
            "Device namespace initialized (%d persisted devices loaded)\n",
            g_num_devices);

    pthread_mutex_unlock(&g_devns_lock);
    return 0;
}

/*
 * device_register - Register a Windows device name mapping.
 *
 * win_name:       Windows device name (e.g., "\\\\.\\MyDevice")
 * linux_path:     Linux device path or virtual path (e.g., "/dev/mydevice")
 * driver_name:    Name of the owning driver
 * device_type:    DEVNS_TYPE_* flags
 * driver_context: Opaque pointer stored for the driver's use
 *
 * Returns 0 on success, -1 on failure (table full, duplicate, etc.).
 */
int device_register(const char *win_name, const char *linux_path,
                    const char *driver_name, int device_type,
                    void *driver_context)
{
    if (!win_name || !linux_path) {
        fprintf(stderr, DEVNS_LOG_PREFIX "device_register: NULL argument\n");
        return -1;
    }

    char normalized[MAX_NAME_LEN];
    normalize_win_name(normalized, win_name, sizeof(normalized));

    pthread_mutex_lock(&g_devns_lock);

    /* Check for duplicate */
    for (int i = 0; i < g_num_devices; i++) {
        if (strcasecmp(g_devices[i].win_name, normalized) == 0) {
            fprintf(stderr, DEVNS_LOG_PREFIX
                    "Device '%s' already registered\n", normalized);
            pthread_mutex_unlock(&g_devns_lock);
            return -1;
        }
    }

    if (g_num_devices >= MAX_DEVICES) {
        fprintf(stderr, DEVNS_LOG_PREFIX
                "Device table full (%d/%d)\n", g_num_devices, MAX_DEVICES);
        pthread_mutex_unlock(&g_devns_lock);
        return -1;
    }

    device_entry_t *dev = &g_devices[g_num_devices];
    memset(dev, 0, sizeof(*dev));
    strncpy(dev->win_name, normalized, sizeof(dev->win_name) - 1);
    strncpy(dev->linux_path, linux_path, sizeof(dev->linux_path) - 1);
    if (driver_name)
        strncpy(dev->driver_name, driver_name, sizeof(dev->driver_name) - 1);
    dev->device_type = device_type;
    dev->state = DEVNS_STATE_ACTIVE;
    dev->driver_context = driver_context;

    g_num_devices++;

    /* Persist to filesystem */
    persist_device(dev);

    /* If this is a symlink type, create the actual symlink */
    if (device_type & DEVNS_TYPE_SYMLINK) {
        struct stat st;
        if (stat(linux_path, &st) == 0) {
            /* Target exists; create a symlink for convenience */
            char link_path[MAX_PATH_LEN];
            snprintf(link_path, sizeof(link_path),
                     "%s/dev_%s", DEVNS_RUN_PATH, normalized);
            symlink(linux_path, link_path);
        }
    }

    fprintf(stderr, DEVNS_LOG_PREFIX
            "Registered: '%s' (%s) -> '%s' [type=0x%x, driver=%s]\n",
            win_name, normalized, linux_path, device_type,
            driver_name ? driver_name : "<none>");

    pthread_mutex_unlock(&g_devns_lock);
    return 0;
}

/*
 * device_unregister - Remove a device name registration.
 *
 * win_name: Windows device name to unregister.
 *
 * Returns 0 on success, -1 if device not found.
 */
int device_unregister(const char *win_name)
{
    if (!win_name) return -1;

    char normalized[MAX_NAME_LEN];
    normalize_win_name(normalized, win_name, sizeof(normalized));

    pthread_mutex_lock(&g_devns_lock);

    for (int i = 0; i < g_num_devices; i++) {
        if (strcasecmp(g_devices[i].win_name, normalized) == 0) {
            fprintf(stderr, DEVNS_LOG_PREFIX
                    "Unregistering device: '%s'\n", normalized);

            /* Remove from filesystem */
            unpersist_device(normalized);

            /* Remove symlink if created */
            char link_path[MAX_PATH_LEN];
            snprintf(link_path, sizeof(link_path),
                     "%s/dev_%s", DEVNS_RUN_PATH, normalized);
            unlink(link_path);

            /* Compact the array by shifting entries down */
            if (i < g_num_devices - 1) {
                memmove(&g_devices[i], &g_devices[i + 1],
                        (g_num_devices - i - 1) * sizeof(device_entry_t));
            }
            g_num_devices--;

            pthread_mutex_unlock(&g_devns_lock);
            return 0;
        }
    }

    fprintf(stderr, DEVNS_LOG_PREFIX
            "Device not found for unregister: '%s'\n", normalized);
    pthread_mutex_unlock(&g_devns_lock);
    return -1;
}

/*
 * device_resolve - Resolve a Windows device name to its Linux path.
 *
 * win_name:    Windows device name to resolve
 * out_path:    Buffer to receive the Linux path
 * path_len:    Size of the output buffer
 * out_context: Optional; receives the driver context pointer
 *
 * Returns 0 on success, -1 if device not found or inactive.
 */
int device_resolve(const char *win_name, char *out_path, size_t path_len,
                   void **out_context)
{
    if (!win_name || !out_path || path_len == 0) return -1;

    char normalized[MAX_NAME_LEN];
    normalize_win_name(normalized, win_name, sizeof(normalized));

    pthread_mutex_lock(&g_devns_lock);

    for (int i = 0; i < g_num_devices; i++) {
        if (strcasecmp(g_devices[i].win_name, normalized) == 0) {
            if (g_devices[i].state != DEVNS_STATE_ACTIVE) {
                fprintf(stderr, DEVNS_LOG_PREFIX
                        "Device '%s' is inactive\n", normalized);
                pthread_mutex_unlock(&g_devns_lock);
                return -1;
            }

            strncpy(out_path, g_devices[i].linux_path, path_len - 1);
            out_path[path_len - 1] = '\0';

            if (out_context)
                *out_context = g_devices[i].driver_context;

            pthread_mutex_unlock(&g_devns_lock);
            return 0;
        }
    }

    fprintf(stderr, DEVNS_LOG_PREFIX
            "Device not found: '%s' (normalized: '%s')\n",
            win_name, normalized);
    pthread_mutex_unlock(&g_devns_lock);
    return -1;
}

/*
 * device_set_state - Set a device's active/inactive state.
 *
 * Returns 0 on success, -1 if device not found.
 */
int device_set_state(const char *win_name, int state)
{
    if (!win_name) return -1;

    char normalized[MAX_NAME_LEN];
    normalize_win_name(normalized, win_name, sizeof(normalized));

    pthread_mutex_lock(&g_devns_lock);

    for (int i = 0; i < g_num_devices; i++) {
        if (strcasecmp(g_devices[i].win_name, normalized) == 0) {
            g_devices[i].state = state;
            persist_device(&g_devices[i]);

            fprintf(stderr, DEVNS_LOG_PREFIX
                    "Device '%s' state -> %s\n", normalized,
                    state == DEVNS_STATE_ACTIVE ? "ACTIVE" : "INACTIVE");

            pthread_mutex_unlock(&g_devns_lock);
            return 0;
        }
    }

    pthread_mutex_unlock(&g_devns_lock);
    return -1;
}

/*
 * device_list - Print all registered devices to the given file stream.
 *
 * output: FILE stream to print to (e.g., stdout).
 *
 * Returns the number of registered devices.
 */
int device_list(FILE *output)
{
    if (!output) output = stdout;

    pthread_mutex_lock(&g_devns_lock);

    fprintf(output, "%-30s %-30s %-15s %-8s %s\n",
            "WINDOWS NAME", "LINUX PATH", "DRIVER", "TYPE", "STATE");
    fprintf(output, "%-30s %-30s %-15s %-8s %s\n",
            "------------", "----------", "------", "----", "-----");

    for (int i = 0; i < g_num_devices; i++) {
        const device_entry_t *dev = &g_devices[i];
        const char *type_str;
        if (dev->device_type & DEVNS_TYPE_CHAR)
            type_str = "CHAR";
        else if (dev->device_type & DEVNS_TYPE_BLOCK)
            type_str = "BLOCK";
        else if (dev->device_type & DEVNS_TYPE_VIRTUAL)
            type_str = "VIRTUAL";
        else
            type_str = "OTHER";

        fprintf(output, "%-30s %-30s %-15s %-8s %s\n",
                dev->win_name,
                dev->linux_path,
                dev->driver_name[0] ? dev->driver_name : "<none>",
                type_str,
                dev->state == DEVNS_STATE_ACTIVE ? "ACTIVE" : "INACTIVE");
    }

    int count = g_num_devices;
    pthread_mutex_unlock(&g_devns_lock);

    fprintf(output, "\nTotal: %d device(s)\n", count);
    return count;
}

/*
 * device_find_by_driver - Find all devices owned by a specific driver.
 *
 * driver_name:  Name of the driver to search for
 * out_names:    Array of string buffers to receive device names
 * max_results:  Maximum number of results to return
 *
 * Returns the number of matching devices found.
 */
int device_find_by_driver(const char *driver_name, char out_names[][MAX_NAME_LEN],
                          int max_results)
{
    if (!driver_name || !out_names || max_results <= 0) return 0;

    int found = 0;

    pthread_mutex_lock(&g_devns_lock);

    for (int i = 0; i < g_num_devices && found < max_results; i++) {
        if (strcasecmp(g_devices[i].driver_name, driver_name) == 0) {
            strncpy(out_names[found], g_devices[i].win_name, MAX_NAME_LEN - 1);
            out_names[found][MAX_NAME_LEN - 1] = '\0';
            found++;
        }
    }

    pthread_mutex_unlock(&g_devns_lock);
    return found;
}

/*
 * device_namespace_cleanup - Shut down the device namespace subsystem.
 * Removes all in-memory registrations. Persisted files are left intact
 * for reload on next init.
 */
void device_namespace_cleanup(void)
{
    pthread_mutex_lock(&g_devns_lock);

    fprintf(stderr, DEVNS_LOG_PREFIX
            "Cleaning up device namespace (%d devices)\n", g_num_devices);

    g_num_devices = 0;
    memset(g_devices, 0, sizeof(g_devices));
    g_initialized = 0;

    pthread_mutex_unlock(&g_devns_lock);
}
