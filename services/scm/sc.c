/*
 * sc.c - Service control CLI tool (equivalent to Windows sc.exe)
 *
 * Commands:
 *   sc start <service>
 *   sc stop <service>
 *   sc query <service>
 *   sc list
 *   sc install <name> <binary_path> [type] [start_type]
 *   sc delete <service>
 *   sc config <service> [start=<type>]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "scm.h"

/*
 * Send a command to the SCM daemon via Unix socket and print the response.
 * Returns 0 on success, 1 on error.
 */
static int scm_send_command(const char *action, const char *name)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "[SC] Cannot create socket: %s\n", strerror(errno));
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SCM_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[SC] Cannot connect to SCM daemon at %s: %s\n",
                SCM_SOCKET_PATH, strerror(errno));
        fprintf(stderr, "     Is the scm_daemon service running?\n");
        close(fd);
        return 1;
    }

    /* Send command */
    char cmd_buf[4096];
    int cmd_len;
    if (name)
        cmd_len = snprintf(cmd_buf, sizeof(cmd_buf), "%s %s\n", action, name);
    else
        cmd_len = snprintf(cmd_buf, sizeof(cmd_buf), "%s\n", action);

    /* Clamp: snprintf returns "would have" on truncation; never write past buffer. */
    if (cmd_len < 0) {
        close(fd);
        return 1;
    }
    if ((size_t)cmd_len >= sizeof(cmd_buf))
        cmd_len = (int)sizeof(cmd_buf) - 1;

    /* Loop the write: AF_UNIX SOCK_STREAM can return short writes under
     * SO_SNDBUF pressure.  Report error only on hard failure (EPIPE/EINTR
     * after retry).  A prior single-call write() dropped bytes silently
     * for cmd_len > MSS on some kernels. */
    {
        ssize_t sent = 0;
        while (sent < cmd_len) {
            ssize_t wn = write(fd, cmd_buf + sent, cmd_len - sent);
            if (wn < 0) {
                if (errno == EINTR) continue;
                fprintf(stderr, "[SC] Failed to send command: %s\n", strerror(errno));
                close(fd);
                return 1;
            }
            if (wn == 0) {
                fprintf(stderr, "[SC] Short write: peer closed mid-send\n");
                close(fd);
                return 1;
            }
            sent += wn;
        }
    }

    /* Read response: loop until EOF or buffer full.  A single read() can
     * return a short fragment (e.g., header arrives before body for large
     * list payloads); previously we truncated and printed partial JSON. */
    char resp[8192];
    size_t total = 0;
    while (total < sizeof(resp) - 1) {
        ssize_t n = read(fd, resp + total, sizeof(resp) - 1 - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;  /* EOF -- daemon closed after sending full response */
        total += (size_t)n;
    }
    close(fd);

    if (total == 0) {
        fprintf(stderr, "[SC] No response from SCM daemon\n");
        return 1;
    }
    resp[total] = '\0';

    /* Print the response */
    printf("%s", resp);

    /* Check if response contains "error" */
    if (strstr(resp, "\"error\""))
        return 1;

    return 0;
}

static void usage(void)
{
    printf("Usage: sc <command> [options]\n\n");
    printf("Commands:\n");
    printf("  start <service>                          Start a service\n");
    printf("  stop <service>                           Stop a service\n");
    printf("  query <service>                          Query service status\n");
    printf("  list                                     List all services\n");
    printf("  install <name> <binary> [type] [start]   Install a service\n");
    printf("  delete <service>                         Delete a service\n");
    printf("  config <service> start=<type>            Configure a service\n");
    printf("\nService types: kernel=1, fs=2, user=16\n");
    printf("Start types: boot=0, system=1, auto=2, demand=3, disabled=4\n");
}

/* Read a service config file */
static int read_service_config(const char *name, char *display, char *binary,
                               int *type, int *start_type)
{
    char filepath[4096];
    snprintf(filepath, sizeof(filepath), "%s/%s.svc", SCM_DB_PATH, name);

    FILE *f = fopen(filepath, "r");
    if (!f) return -1;

    if (display) display[0] = '\0';
    if (binary) binary[0] = '\0';
    if (type) *type = 16;
    if (start_type) *start_type = 3;

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';

        if (strcmp(line, "display_name") == 0 && display) {
            strncpy(display, eq + 1, 255);
            display[255] = '\0';
        } else if (strcmp(line, "binary_path") == 0 && binary) {
            strncpy(binary, eq + 1, 4095);
            binary[4095] = '\0';
        } else if (strcmp(line, "type") == 0 && type)
            *type = atoi(eq + 1);
        else if (strcmp(line, "start_type") == 0 && start_type)
            *start_type = atoi(eq + 1);
    }

    fclose(f);
    return 0;
}

/* Read the current state from the status file (returns SERVICE_STOPPED if
 * no status file exists or cannot be parsed). */
static int read_service_state(const char *name)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s.status", SCM_RUN_PATH, name);
    FILE *f = fopen(path, "r");
    if (!f) return SERVICE_STOPPED;

    int state = SERVICE_STOPPED;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "state=", 6) == 0)
            state = atoi(line + 6);
    }
    fclose(f);
    return state;
}

/* Check if a service is running */
static int is_service_running(const char *name)
{
    return read_service_state(name) == SERVICE_RUNNING;
}

static int cmd_query(const char *name)
{
    char display[256], binary[4096];
    int type, start_type;

    if (read_service_config(name, display, binary, &type, &start_type) < 0) {
        fprintf(stderr, "Service '%s' not found.\n", name);
        return 1;
    }

    int state = read_service_state(name);

    printf("SERVICE_NAME: %s\n", name);
    if (display[0])
        printf("DISPLAY_NAME: %s\n", display);

    const char *type_str = "WIN32_OWN_PROCESS";
    if (type == 1) type_str = "KERNEL_DRIVER";
    else if (type == 2) type_str = "FILE_SYSTEM_DRIVER";

    const char *state_str;
    switch (state) {
    case SERVICE_RUNNING:       state_str = "RUNNING"; break;
    case SERVICE_START_PENDING: state_str = "START_PENDING"; break;
    case SERVICE_STOP_PENDING:  state_str = "STOP_PENDING"; break;
    case SERVICE_PAUSED:        state_str = "PAUSED"; break;
    case SERVICE_STOPPED:
    default:                    state_str = "STOPPED"; state = SERVICE_STOPPED; break;
    }

    printf("        TYPE               : %-3d  %s\n", type, type_str);
    printf("        STATE              : %-3d  %s\n", state, state_str);
    printf("        BINARY_PATH_NAME   : %s\n", binary);

    const char *start_str = "DEMAND_START";
    switch (start_type) {
    case 0: start_str = "BOOT_START"; break;
    case 1: start_str = "SYSTEM_START"; break;
    case 2: start_str = "AUTO_START"; break;
    case 3: start_str = "DEMAND_START"; break;
    case 4: start_str = "DISABLED"; break;
    }
    printf("        START_TYPE         : %-3d  %s\n", start_type, start_str);

    return 0;
}

static int cmd_list(void)
{
    DIR *d = opendir(SCM_DB_PATH);
    if (!d) {
        fprintf(stderr, "Cannot open service database at %s\n", SCM_DB_PATH);
        return 1;
    }

    printf("%-30s %-8s %-8s %s\n", "SERVICE NAME", "TYPE", "STATE", "START TYPE");
    printf("%-30s %-8s %-8s %s\n", "---", "---", "---", "---");

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        const char *ext = strrchr(ent->d_name, '.');
        if (!ext || strcmp(ext, ".svc") != 0)
            continue;

        /* Extract service name */
        char name[256];
        strncpy(name, ent->d_name, sizeof(name) - 1);
        char *dot = strrchr(name, '.');
        if (dot) *dot = '\0';

        int type, start_type;
        read_service_config(name, NULL, NULL, &type, &start_type);
        int running = is_service_running(name);

        const char *type_str = "USER";
        if (type == 1) type_str = "KERNEL";
        else if (type == 2) type_str = "FS_DRV";

        const char *start_str = "DEMAND";
        switch (start_type) {
        case 0: start_str = "BOOT"; break;
        case 1: start_str = "SYSTEM"; break;
        case 2: start_str = "AUTO"; break;
        case 4: start_str = "DISABLED"; break;
        }

        printf("%-30s %-8s %-8s %s\n", name, type_str,
               running ? "RUNNING" : "STOPPED", start_str);
    }

    closedir(d);
    return 0;
}

static int cmd_install(const char *name, const char *binary, int type, int start_type)
{
    char filepath[4096];
    snprintf(filepath, sizeof(filepath), "%s/%s.svc", SCM_DB_PATH, name);

    /* Check if already exists */
    FILE *f = fopen(filepath, "r");
    if (f) {
        fclose(f);
        fprintf(stderr, "Service '%s' already exists.\n", name);
        return 1;
    }

    /* Create */
    mkdir("/var/lib/pe-compat", 0755);
    mkdir(SCM_DB_PATH, 0755);

    f = fopen(filepath, "w");
    if (!f) {
        fprintf(stderr, "Cannot create service config: %s\n", strerror(errno));
        return 1;
    }

    fprintf(f, "name=%s\n", name);
    fprintf(f, "display_name=%s\n", name);
    fprintf(f, "type=%d\n", type);
    fprintf(f, "start_type=%d\n", start_type);
    fprintf(f, "binary_path=%s\n", binary);
    fclose(f);

    printf("[SC] CreateService SUCCESS\n");
    return 0;
}

static int cmd_delete(const char *name)
{
    char filepath[4096];
    snprintf(filepath, sizeof(filepath), "%s/%s.svc", SCM_DB_PATH, name);

    if (unlink(filepath) < 0) {
        fprintf(stderr, "Service '%s' not found.\n", name);
        return 1;
    }

    /* Also remove status file */
    char status_path[4096];
    snprintf(status_path, sizeof(status_path), "%s/%s.status", SCM_RUN_PATH, name);
    unlink(status_path);

    printf("[SC] DeleteService SUCCESS\n");
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage();
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        usage();
        return 0;
    }

    if (strcmp(cmd, "query") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: sc query <service>\n");
            return 1;
        }
        return cmd_query(argv[2]);
    }

    if (strcmp(cmd, "list") == 0) {
        return cmd_list();
    }

    if (strcmp(cmd, "install") == 0 || strcmp(cmd, "create") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: sc install <name> <binary_path> [type] [start_type]\n");
            return 1;
        }
        /* Build "install <name> <binary> [type] [start_type]" command */
        {
            char install_args[4096];
            int ia_len = snprintf(install_args, sizeof(install_args), "%s %s", argv[2], argv[3]);
            if (ia_len < 0 || (size_t)ia_len >= sizeof(install_args))
                ia_len = (int)sizeof(install_args) - 1;
            if (argc > 4 && (size_t)ia_len < sizeof(install_args) - 1) {
                int w = snprintf(install_args + ia_len, sizeof(install_args) - ia_len, " %s", argv[4]);
                if (w > 0) {
                    if ((size_t)w >= sizeof(install_args) - ia_len)
                        ia_len = (int)sizeof(install_args) - 1;
                    else
                        ia_len += w;
                }
            }
            if (argc > 5 && (size_t)ia_len < sizeof(install_args) - 1) {
                int w = snprintf(install_args + ia_len, sizeof(install_args) - ia_len, " %s", argv[5]);
                if (w > 0) {
                    if ((size_t)w >= sizeof(install_args) - ia_len)
                        ia_len = (int)sizeof(install_args) - 1;
                    else
                        ia_len += w;
                }
            }

            int rc = scm_send_command("install", install_args);
            if (rc != 0) {
                int type = (argc > 4) ? atoi(argv[4]) : 16;
                int start_type = (argc > 5) ? atoi(argv[5]) : 3;
                return cmd_install(argv[2], argv[3], type, start_type);
            }
            return rc;
        }
    }

    if (strcmp(cmd, "delete") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: sc delete <service>\n");
            return 1;
        }
        /* Try routing through daemon first; fall back to local */
        int rc = scm_send_command("delete", argv[2]);
        if (rc != 0)
            return cmd_delete(argv[2]);
        return rc;
    }

    if (strcmp(cmd, "start") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: sc start <service>\n");
            return 1;
        }
        return scm_send_command("start", argv[2]);
    }

    if (strcmp(cmd, "stop") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: sc stop <service>\n");
            return 1;
        }
        return scm_send_command("stop", argv[2]);
    }

    if (strcmp(cmd, "status") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: sc status <service>\n");
            return 1;
        }
        return scm_send_command("status", argv[2]);
    }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    usage();
    return 1;
}
