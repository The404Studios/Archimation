/*
 * devcon.c - devcon.exe equivalent CLI tool
 *
 * Provides a command-line interface for Windows driver management on the
 * PE compatibility layer, mirroring the functionality of Microsoft's
 * devcon.exe (Device Console) utility.
 *
 * Supported commands:
 *   install <inf_file> <hardware_id>  - Install a driver from .inf file
 *   remove <driver_name>              - Uninstall a driver
 *   list                              - List all installed drivers
 *   status <device_name>              - Show device/driver status
 *   enable <device_name>              - Enable a device
 *   disable <device_name>             - Disable a device
 *
 * This tool acts as a frontend to the driver_install and device_namespace
 * subsystems, and communicates with the SCM daemon for service management.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>

#define DEVCON_VERSION      "1.0.0"
#define DEVCON_LOG_PREFIX   "[devcon] "

#define DRV_BASE_PATH       "/var/lib/pe-compat/drivers"
#define SCM_DB_PATH         "/var/lib/pe-compat/services"
#define DEVNS_RUN_PATH      "/run/pe-compat/devices"

#define MAX_PATH_LEN    1024
#define MAX_NAME_LEN    256

/* Service states (matching SCM daemon definitions) */
#define SERVICE_STOPPED         1
#define SERVICE_START_PENDING   2
#define SERVICE_STOP_PENDING    3
#define SERVICE_RUNNING         4

/* Device namespace states */
#define DEVNS_STATE_INACTIVE    0
#define DEVNS_STATE_ACTIVE      1

/* External functions from driver_install.c */
extern int  driver_install(const char *inf_path, const char *hardware_id);
extern int  driver_uninstall(const char *driver_name);
extern int  driver_list(FILE *output);

/* External functions from device_namespace.c */
extern int  device_namespace_init(void);
extern int  device_resolve(const char *win_name, char *out_path,
                           size_t path_len, void **out_context);
extern int  device_set_state(const char *win_name, int state);
extern int  device_list(FILE *output);
extern void device_namespace_cleanup(void);

/* Forward declarations */
static void usage(const char *progname);
static int  cmd_install(int argc, char **argv);
static int  cmd_remove(int argc, char **argv);
static int  cmd_list(int argc, char **argv);
static int  cmd_status(int argc, char **argv);
static int  cmd_enable(int argc, char **argv);
static int  cmd_disable(int argc, char **argv);
static int  read_scm_service(const char *name, char *display, size_t dlen,
                              char *binary, size_t blen, int *svc_type,
                              int *start_type);
static const char *start_type_str(int start_type);
static const char *service_type_str(int svc_type);

/*
 * usage - Print usage information.
 */
static void usage(const char *progname)
{
    fprintf(stderr,
        "devcon %s - Windows Device Console for PE compatibility layer\n"
        "\n"
        "Usage: %s <command> [arguments...]\n"
        "\n"
        "Commands:\n"
        "  install <inf_file> <hardware_id>  Install a driver package\n"
        "  remove <driver_name>              Uninstall a driver\n"
        "  list                              List installed drivers\n"
        "  status <device_name>              Show device/driver status\n"
        "  enable <device_name>              Enable a device\n"
        "  disable <device_name>             Disable a device\n"
        "\n"
        "Examples:\n"
        "  %s install mydriver.inf \"PCI\\VEN_8086&DEV_1234\"\n"
        "  %s list\n"
        "  %s status mydriver\n"
        "  %s remove mydriver\n"
        "\n"
        "Paths:\n"
        "  Driver files:    %s\n"
        "  Service configs: %s\n"
        "  Device entries:  %s\n",
        DEVCON_VERSION, progname,
        progname, progname, progname, progname,
        DRV_BASE_PATH, SCM_DB_PATH, DEVNS_RUN_PATH);
}

/*
 * read_scm_service - Read a service configuration file from the SCM database.
 *
 * Returns 0 on success, -1 if the service file doesn't exist or can't be read.
 */
static int read_scm_service(const char *name, char *display, size_t dlen,
                              char *binary, size_t blen, int *svc_type,
                              int *start_type)
{
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s.svc", SCM_DB_PATH, name);

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

        if (strcmp(key, "display") == 0 && display)
            strncpy(display, val, dlen - 1);
        else if (strcmp(key, "binary") == 0 && binary)
            strncpy(binary, val, blen - 1);
        else if (strcmp(key, "type") == 0 && svc_type)
            *svc_type = atoi(val);
        else if (strcmp(key, "start") == 0 && start_type)
            *start_type = atoi(val);
    }

    fclose(f);
    return 0;
}

/*
 * start_type_str - Convert numeric start type to display string.
 */
static const char *start_type_str(int start_type)
{
    switch (start_type) {
    case 0: return "Boot";
    case 1: return "System";
    case 2: return "Automatic";
    case 3: return "Manual";
    case 4: return "Disabled";
    default: return "Unknown";
    }
}

/*
 * service_type_str - Convert numeric service type to display string.
 */
static const char *service_type_str(int svc_type)
{
    switch (svc_type) {
    case 0x01: return "Kernel Driver";
    case 0x02: return "File System Driver";
    case 0x10: return "Win32 Own Process";
    case 0x20: return "Win32 Shared Process";
    default:   return "Unknown";
    }
}

/*
 * cmd_install - Handle the "install" command.
 *
 * Usage: devcon install <inf_file> <hardware_id>
 */
static int cmd_install(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: devcon install <inf_file> <hardware_id>\n");
        return 1;
    }

    const char *inf_path = argv[0];
    const char *hardware_id = argv[1];

    /* Verify the .inf file exists */
    struct stat st;
    if (stat(inf_path, &st) < 0) {
        fprintf(stderr, "Error: Cannot access '%s': %s\n",
                inf_path, strerror(errno));
        return 1;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Error: '%s' is not a regular file\n", inf_path);
        return 1;
    }

    printf("Installing driver:\n");
    printf("  INF file:    %s\n", inf_path);
    printf("  Hardware ID: %s\n", hardware_id);
    printf("\n");

    int ret = driver_install(inf_path, hardware_id);

    if (ret == 0) {
        printf("\nDriver installed successfully.\n");
        printf("Note: Use 'devcon status <device>' to verify the installation.\n");
    } else {
        fprintf(stderr, "\nDriver installation failed.\n");
    }

    return ret == 0 ? 0 : 1;
}

/*
 * cmd_remove - Handle the "remove" command.
 *
 * Usage: devcon remove <driver_name>
 */
static int cmd_remove(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "Usage: devcon remove <driver_name>\n");
        return 1;
    }

    const char *driver_name = argv[0];

    /* Check if driver exists */
    char meta_path[MAX_PATH_LEN];
    snprintf(meta_path, sizeof(meta_path), "%s/%s.drv",
             DRV_BASE_PATH, driver_name);

    struct stat st;
    if (stat(meta_path, &st) < 0) {
        /* Also check SCM */
        char svc_path[MAX_PATH_LEN];
        snprintf(svc_path, sizeof(svc_path), "%s/%s.svc",
                 SCM_DB_PATH, driver_name);
        if (stat(svc_path, &st) < 0) {
            fprintf(stderr, "Error: Driver '%s' is not installed.\n",
                    driver_name);
            return 1;
        }
    }

    printf("Removing driver: %s\n", driver_name);

    int ret = driver_uninstall(driver_name);

    if (ret == 0) {
        printf("Driver '%s' removed successfully.\n", driver_name);
    } else {
        fprintf(stderr, "Failed to remove driver '%s'.\n", driver_name);
    }

    return ret == 0 ? 0 : 1;
}

/*
 * cmd_list - Handle the "list" command.
 *
 * Usage: devcon list
 */
static int cmd_list(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("Installed Drivers:\n");
    printf("==================\n\n");

    int count = driver_list(stdout);

    if (count == 0) {
        printf("No drivers currently installed.\n");
    }

    /* Also show registered device namespace entries */
    printf("\nRegistered Devices:\n");
    printf("===================\n\n");

    device_namespace_init();
    device_list(stdout);

    return 0;
}

/*
 * cmd_status - Handle the "status" command.
 *
 * Usage: devcon status <device_name>
 *
 * Shows detailed information about a device/driver including:
 *   - SCM service configuration
 *   - Device namespace registration
 *   - Driver binary file status
 */
static int cmd_status(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "Usage: devcon status <device_name>\n");
        return 1;
    }

    const char *name = argv[0];
    int found = 0;

    printf("Device/Driver Status: %s\n", name);
    printf("========================");
    for (size_t i = 0; i < strlen(name); i++) printf("=");
    printf("\n\n");

    /* Check SCM service status */
    char display[MAX_NAME_LEN] = "";
    char binary[MAX_PATH_LEN] = "";
    int svc_type = 0, start_type = 0;

    if (read_scm_service(name, display, sizeof(display),
                          binary, sizeof(binary),
                          &svc_type, &start_type) == 0) {
        found = 1;
        printf("Service Configuration:\n");
        printf("  Display name: %s\n", display[0] ? display : name);
        printf("  Service type: %s (0x%x)\n",
               service_type_str(svc_type), svc_type);
        printf("  Start type:   %s (%d)\n",
               start_type_str(start_type), start_type);
        printf("  Binary path:  %s\n", binary[0] ? binary : "<not set>");

        /* Check if binary exists */
        if (binary[0]) {
            struct stat st;
            if (stat(binary, &st) == 0) {
                printf("  Binary size:  %ld bytes\n", (long)st.st_size);
                printf("  Binary state: Present\n");
            } else {
                printf("  Binary state: MISSING (%s)\n", strerror(errno));
            }
        }
        printf("\n");
    }

    /* Check device namespace */
    device_namespace_init();
    char resolved_path[MAX_PATH_LEN];

    /* Try multiple Windows name formats */
    const char *prefixes[] = { "\\\\.\\", "\\Device\\", "" };
    for (int i = 0; i < 3; i++) {
        char win_name[MAX_NAME_LEN];
        snprintf(win_name, sizeof(win_name), "%s%s", prefixes[i], name);

        if (device_resolve(win_name, resolved_path, sizeof(resolved_path),
                           NULL) == 0) {
            found = 1;
            printf("Device Namespace:\n");
            printf("  Windows name: %s\n", win_name);
            printf("  Linux path:   %s\n", resolved_path);

            /* Check if the linux path exists */
            struct stat st;
            if (stat(resolved_path, &st) == 0) {
                printf("  Path state:   Exists\n");
                if (S_ISCHR(st.st_mode))
                    printf("  Device type:  Character device\n");
                else if (S_ISBLK(st.st_mode))
                    printf("  Device type:  Block device\n");
                else if (S_ISREG(st.st_mode))
                    printf("  Device type:  Virtual (regular file)\n");
                else if (S_ISDIR(st.st_mode))
                    printf("  Device type:  Virtual (directory)\n");
            } else {
                printf("  Path state:   Not materialized\n");
            }
            printf("\n");
            break;
        }
    }

    /* Check driver metadata file */
    char meta_path[MAX_PATH_LEN];
    snprintf(meta_path, sizeof(meta_path), "%s/%s.drv", DRV_BASE_PATH, name);

    FILE *f = fopen(meta_path, "r");
    if (f) {
        found = 1;
        printf("Installation Metadata:\n");

        char line[1024];
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\r\n")] = '\0';
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = '\0';
            const char *key = line;
            const char *val = eq + 1;

            if (strcmp(key, "inf") == 0)
                printf("  Source INF:   %s\n", val[0] ? val : "<unknown>");
            else if (strcmp(key, "hwid") == 0)
                printf("  Hardware ID:  %s\n", val[0] ? val : "<none>");
            else if (strcmp(key, "num_files") == 0)
                printf("  File count:   %s\n", val);
        }
        fclose(f);
        printf("\n");
    }

    if (!found) {
        printf("Device/driver '%s' not found.\n", name);
        printf("\nTry 'devcon list' to see all installed drivers.\n");
        return 1;
    }

    return 0;
}

/*
 * cmd_enable - Handle the "enable" command.
 *
 * Usage: devcon enable <device_name>
 */
static int cmd_enable(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "Usage: devcon enable <device_name>\n");
        return 1;
    }

    const char *name = argv[0];

    printf("Enabling device: %s\n", name);

    device_namespace_init();

    /* Try to enable via device namespace */
    char win_name[MAX_NAME_LEN];
    snprintf(win_name, sizeof(win_name), "\\\\.\\%s", name);

    if (device_set_state(win_name, DEVNS_STATE_ACTIVE) == 0) {
        printf("Device '%s' enabled.\n", name);
    } else {
        /* Try without prefix */
        if (device_set_state(name, DEVNS_STATE_ACTIVE) == 0) {
            printf("Device '%s' enabled.\n", name);
        } else {
            fprintf(stderr, "Failed to enable device '%s'.\n", name);
            fprintf(stderr, "Device may not be registered. "
                    "Use 'devcon list' to see registered devices.\n");
            return 1;
        }
    }

    /* Also update the SCM service start type to manual (from disabled) */
    char svc_path[MAX_PATH_LEN];
    snprintf(svc_path, sizeof(svc_path), "%s/%s.svc", SCM_DB_PATH, name);

    struct stat st;
    if (stat(svc_path, &st) == 0) {
        /* Read, modify start type, rewrite */
        char display[MAX_NAME_LEN] = "";
        char binary[MAX_PATH_LEN] = "";
        int svc_type = 0, start_type = 0;
        read_scm_service(name, display, sizeof(display),
                          binary, sizeof(binary), &svc_type, &start_type);

        if (start_type == 4) {  /* SERVICE_DISABLED */
            /* Rewrite with DEMAND_START */
            FILE *f = fopen(svc_path, "w");
            if (f) {
                fprintf(f, "name=%s\n", name);
                fprintf(f, "display=%s\n", display);
                fprintf(f, "binary=%s\n", binary);
                fprintf(f, "type=%d\n", svc_type);
                fprintf(f, "start=%d\n", 3); /* SERVICE_DEMAND_START */
                fprintf(f, "depends=\n");
                fclose(f);
                printf("Service start type changed from Disabled to Manual.\n");
            }
        }
    }

    return 0;
}

/*
 * cmd_disable - Handle the "disable" command.
 *
 * Usage: devcon disable <device_name>
 */
static int cmd_disable(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "Usage: devcon disable <device_name>\n");
        return 1;
    }

    const char *name = argv[0];

    printf("Disabling device: %s\n", name);

    device_namespace_init();

    /* Disable via device namespace */
    char win_name[MAX_NAME_LEN];
    snprintf(win_name, sizeof(win_name), "\\\\.\\%s", name);

    if (device_set_state(win_name, DEVNS_STATE_INACTIVE) == 0) {
        printf("Device '%s' disabled.\n", name);
    } else {
        if (device_set_state(name, DEVNS_STATE_INACTIVE) == 0) {
            printf("Device '%s' disabled.\n", name);
        } else {
            fprintf(stderr, "Failed to disable device '%s'.\n", name);
            fprintf(stderr, "Device may not be registered. "
                    "Use 'devcon list' to see registered devices.\n");
            return 1;
        }
    }

    /* Also update the SCM service start type to disabled */
    char svc_path[MAX_PATH_LEN];
    snprintf(svc_path, sizeof(svc_path), "%s/%s.svc", SCM_DB_PATH, name);

    struct stat st_buf;
    if (stat(svc_path, &st_buf) == 0) {
        char display[MAX_NAME_LEN] = "";
        char binary[MAX_PATH_LEN] = "";
        int svc_type = 0, start_type = 0;
        read_scm_service(name, display, sizeof(display),
                          binary, sizeof(binary), &svc_type, &start_type);

        FILE *f = fopen(svc_path, "w");
        if (f) {
            fprintf(f, "name=%s\n", name);
            fprintf(f, "display=%s\n", display);
            fprintf(f, "binary=%s\n", binary);
            fprintf(f, "type=%d\n", svc_type);
            fprintf(f, "start=%d\n", 4); /* SERVICE_DISABLED */
            fprintf(f, "depends=\n");
            fclose(f);
            printf("Service start type changed to Disabled.\n");
        }
    }

    return 0;
}

/*
 * main - Entry point for the devcon CLI tool.
 */
int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *command = argv[1];

    /* Skip past "devcon <command>" to get sub-command arguments */
    int sub_argc = argc - 2;
    char **sub_argv = argv + 2;

    if (strcmp(command, "install") == 0) {
        return cmd_install(sub_argc, sub_argv);
    }
    else if (strcmp(command, "remove") == 0 ||
             strcmp(command, "uninstall") == 0) {
        return cmd_remove(sub_argc, sub_argv);
    }
    else if (strcmp(command, "list") == 0 ||
             strcmp(command, "ls") == 0) {
        return cmd_list(sub_argc, sub_argv);
    }
    else if (strcmp(command, "status") == 0 ||
             strcmp(command, "info") == 0) {
        return cmd_status(sub_argc, sub_argv);
    }
    else if (strcmp(command, "enable") == 0) {
        return cmd_enable(sub_argc, sub_argv);
    }
    else if (strcmp(command, "disable") == 0) {
        return cmd_disable(sub_argc, sub_argv);
    }
    else if (strcmp(command, "help") == 0 ||
             strcmp(command, "--help") == 0 ||
             strcmp(command, "-h") == 0) {
        usage(argv[0]);
        return 0;
    }
    else if (strcmp(command, "--version") == 0 ||
             strcmp(command, "-v") == 0) {
        printf("devcon %s (PE compatibility layer)\n", DEVCON_VERSION);
        return 0;
    }
    else {
        fprintf(stderr, "Unknown command: '%s'\n\n", command);
        usage(argv[0]);
        return 1;
    }
}
