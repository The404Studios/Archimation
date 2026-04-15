/*
 * advapi32_service.c - Windows Service API stubs
 *
 * OpenSCManagerA, CreateServiceA, OpenServiceA, StartServiceA,
 * ControlService, QueryServiceStatus, CloseServiceHandle, etc.
 *
 * These forward to the SCM daemon via IPC (or direct calls for now).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>

#include "common/dll_common.h"

/* ---- Registry sync helpers -----------------------------------------
 * CreateService/ChangeServiceConfig/DeleteService keep the SCM flat
 * file (/var/lib/pe-compat/services/<name>.svc) and the registry hive
 * at HKLM\SYSTEM\CurrentControlSet\Services\<name> in sync so that PE
 * code that reads its own config via QueryServiceConfig and PE code
 * that enumerates the registry see the same view.
 *
 * We call our own exported Reg* functions by prototype rather than
 * pulling in advapi32_registry.c's private forward decls. Those go
 * through objectd when the broker is up (authoritative cross-process
 * hive) and fall back to the local file-backed registry otherwise.
 * Same-process -> no lock conflict with objectd_client's per-call
 * request/response model.
 */

#define ADVAPI32_HKEY_LOCAL_MACHINE    ((HANDLE)(uintptr_t)0x80000002)
#define ADVAPI32_REG_SZ                1
#define ADVAPI32_REG_EXPAND_SZ         2
#define ADVAPI32_REG_DWORD             4
#define ADVAPI32_KEY_ALL_ACCESS        0xF003F

WINAPI_EXPORT LONG RegCreateKeyExA(HANDLE, LPCSTR, DWORD, LPSTR, DWORD, DWORD,
                                   LPSECURITY_ATTRIBUTES, HANDLE *, LPDWORD);
WINAPI_EXPORT LONG RegSetValueExA(HANDLE, LPCSTR, DWORD, DWORD,
                                  const BYTE *, DWORD);
WINAPI_EXPORT LONG RegCloseKey(HANDLE);
WINAPI_EXPORT LONG RegDeleteKeyA(HANDLE, LPCSTR);
WINAPI_EXPORT LONG RegOpenKeyExA(HANDLE, LPCSTR, DWORD, DWORD, HANDLE *);
WINAPI_EXPORT LONG RegDeleteValueA(HANDLE, LPCSTR);

/*
 * Format the services subkey path: SYSTEM\CurrentControlSet\Services\<name>.
 * Returns 0 on success, -1 if the name would overflow the buffer.
 */
static int svc_reg_subkey(const char *svc_name, char *out, size_t out_sz)
{
    int n = snprintf(out, out_sz,
                     "SYSTEM\\CurrentControlSet\\Services\\%s", svc_name);
    if (n < 0 || (size_t)n >= out_sz)
        return -1;
    return 0;
}

/*
 * Write the full set of service registry values under
 * HKLM\SYSTEM\CurrentControlSet\Services\<name>.
 * lpDisplayName / lpBinaryPathName / lpDescription may be NULL.
 * Silent on failure (registry sync is best-effort).
 */
static void svc_reg_write_config(const char *svc_name,
                                 DWORD dwServiceType,
                                 DWORD dwStartType,
                                 DWORD dwErrorControl,
                                 LPCSTR lpBinaryPathName,
                                 LPCSTR lpDisplayName,
                                 LPCSTR lpDescription)
{
    char subkey[600];
    if (svc_reg_subkey(svc_name, subkey, sizeof(subkey)) < 0)
        return;

    HANDLE hk = NULL;
    LONG rc = RegCreateKeyExA(ADVAPI32_HKEY_LOCAL_MACHINE, subkey, 0, NULL, 0,
                              ADVAPI32_KEY_ALL_ACCESS, NULL, &hk, NULL);
    if (rc != ERROR_SUCCESS || !hk)
        return;

    if (lpBinaryPathName) {
        RegSetValueExA(hk, "ImagePath", 0, ADVAPI32_REG_EXPAND_SZ,
                       (const BYTE *)lpBinaryPathName,
                       (DWORD)(strlen(lpBinaryPathName) + 1));
    }
    if (lpDisplayName) {
        RegSetValueExA(hk, "DisplayName", 0, ADVAPI32_REG_SZ,
                       (const BYTE *)lpDisplayName,
                       (DWORD)(strlen(lpDisplayName) + 1));
    }
    {
        DWORD v = dwServiceType;
        RegSetValueExA(hk, "Type", 0, ADVAPI32_REG_DWORD,
                       (const BYTE *)&v, sizeof(v));
    }
    {
        DWORD v = dwStartType;
        RegSetValueExA(hk, "Start", 0, ADVAPI32_REG_DWORD,
                       (const BYTE *)&v, sizeof(v));
    }
    {
        DWORD v = dwErrorControl;
        RegSetValueExA(hk, "ErrorControl", 0, ADVAPI32_REG_DWORD,
                       (const BYTE *)&v, sizeof(v));
    }
    if (lpDescription) {
        RegSetValueExA(hk, "Description", 0, ADVAPI32_REG_SZ,
                       (const BYTE *)lpDescription,
                       (DWORD)(strlen(lpDescription) + 1));
    }

    RegCloseKey(hk);
}

/*
 * Remove the service's registry subkey. Tries to delete all known
 * values first (some registry backends don't support recursive
 * RegDeleteKey and require the key be empty).
 */
static void svc_reg_delete_config(const char *svc_name)
{
    char subkey[600];
    if (svc_reg_subkey(svc_name, subkey, sizeof(subkey)) < 0)
        return;

    HANDLE hk = NULL;
    if (RegOpenKeyExA(ADVAPI32_HKEY_LOCAL_MACHINE, subkey, 0,
                      ADVAPI32_KEY_ALL_ACCESS, &hk) == ERROR_SUCCESS && hk) {
        RegDeleteValueA(hk, "ImagePath");
        RegDeleteValueA(hk, "DisplayName");
        RegDeleteValueA(hk, "Type");
        RegDeleteValueA(hk, "Start");
        RegDeleteValueA(hk, "ErrorControl");
        RegDeleteValueA(hk, "Description");
        RegCloseKey(hk);
    }

    RegDeleteKeyA(ADVAPI32_HKEY_LOCAL_MACHINE, subkey);
}

/* Service types */
#define SERVICE_KERNEL_DRIVER       0x00000001
#define SERVICE_FILE_SYSTEM_DRIVER  0x00000002
#define SERVICE_WIN32_OWN_PROCESS   0x00000010
#define SERVICE_WIN32_SHARE_PROCESS 0x00000020
#define SERVICE_INTERACTIVE_PROCESS 0x00000100

/* Service start types */
#define SERVICE_BOOT_START      0
#define SERVICE_SYSTEM_START    1
#define SERVICE_AUTO_START      2
#define SERVICE_DEMAND_START    3
#define SERVICE_DISABLED        4

/* Service states */
#define SERVICE_STOPPED         1
#define SERVICE_START_PENDING   2
#define SERVICE_STOP_PENDING    3
#define SERVICE_RUNNING         4

/* Service control codes */
#define SERVICE_CONTROL_STOP            0x00000001
#define SERVICE_CONTROL_PAUSE           0x00000002
#define SERVICE_CONTROL_CONTINUE        0x00000003
#define SERVICE_CONTROL_INTERROGATE     0x00000004
#define SERVICE_CONTROL_SHUTDOWN        0x00000005

/* Controls accepted (SERVICE_STATUS.dwControlsAccepted bits) */
#define SERVICE_ACCEPT_STOP             0x00000001
#define SERVICE_ACCEPT_PAUSE_CONTINUE   0x00000002
#define SERVICE_ACCEPT_SHUTDOWN         0x00000004

/* Extra errors the SCM raises */
#ifndef ERROR_SERVICE_EXISTS
#define ERROR_SERVICE_EXISTS            1073
#endif
#ifndef ERROR_SERVICE_DOES_NOT_EXIST
#define ERROR_SERVICE_DOES_NOT_EXIST    1060
#endif

/* Service access rights */
#define SC_MANAGER_ALL_ACCESS           0x000F003F
#define SC_MANAGER_CONNECT              0x00000001
#define SC_MANAGER_ENUMERATE_SERVICE    0x00000004
#define SERVICE_ALL_ACCESS              0x000F01FF
#define SERVICE_QUERY_STATUS            0x00000004
#define SERVICE_START                   0x00000010
#define SERVICE_STOP                    0x00000020

/* SERVICE_STATUS structure */
typedef struct {
    DWORD dwServiceType;
    DWORD dwCurrentState;
    DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode;
    DWORD dwServiceSpecificExitCode;
    DWORD dwCheckPoint;
    DWORD dwWaitHint;
} SERVICE_STATUS, *LPSERVICE_STATUS;

/* SC_HANDLE is just a HANDLE alias */
typedef HANDLE SC_HANDLE;

/* Service handle data */
typedef struct {
    char name[256];
    int  is_scm;    /* 1 = SCManager handle, 0 = service handle */
} sc_handle_data_t;

WINAPI_EXPORT SC_HANDLE OpenSCManagerA(
    LPCSTR lpMachineName,
    LPCSTR lpDatabaseName,
    DWORD dwDesiredAccess)
{
    (void)lpMachineName;
    (void)lpDatabaseName;
    (void)dwDesiredAccess;

    sc_handle_data_t *data = calloc(1, sizeof(sc_handle_data_t));
    if (!data) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    strcpy(data->name, "SCManager");
    data->is_scm = 1;

    fprintf(stderr, "[advapi32] OpenSCManagerA() -> handle allocated\n");
    return handle_alloc(HANDLE_TYPE_SERVICE, -1, data); /* Custom type */
}

WINAPI_EXPORT SC_HANDLE OpenSCManagerW(
    LPCWSTR lpMachineName,
    LPCWSTR lpDatabaseName,
    DWORD dwDesiredAccess)
{
    (void)lpMachineName;
    (void)lpDatabaseName;
    return OpenSCManagerA(NULL, NULL, dwDesiredAccess);
}

WINAPI_EXPORT SC_HANDLE CreateServiceA(
    SC_HANDLE hSCManager,
    LPCSTR lpServiceName,
    LPCSTR lpDisplayName,
    DWORD dwDesiredAccess,
    DWORD dwServiceType,
    DWORD dwStartType,
    DWORD dwErrorControl,
    LPCSTR lpBinaryPathName,
    LPCSTR lpLoadOrderGroup,
    LPDWORD lpdwTagId,
    LPCSTR lpDependencies,
    LPCSTR lpServiceStartName,
    LPCSTR lpPassword)
{
    (void)hSCManager;
    (void)dwDesiredAccess;
    (void)dwErrorControl;
    (void)lpLoadOrderGroup;
    (void)lpdwTagId;
    (void)lpDependencies;
    (void)lpServiceStartName;
    (void)lpPassword;

    if (!lpServiceName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    /* Reject service names that could escape the services directory.
     * Windows SCM rejects '/', '\\', '..' in service names; enforce the
     * same so attacker-controlled input cannot overwrite arbitrary files. */
    if (strchr(lpServiceName, '/') || strchr(lpServiceName, '\\') ||
        strstr(lpServiceName, "..")) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    fprintf(stderr, "[advapi32] CreateServiceA('%s', type=%u, start=%u, path='%s')\n",
            lpServiceName, dwServiceType, dwStartType,
            lpBinaryPathName ? lpBinaryPathName : "(null)");

    /* Ensure SCM database directory exists. Running without it caused
     * CreateService to silently skip persisting the service config. */
    mkdir("/var/lib/pe-compat", 0755);
    mkdir("/var/lib/pe-compat/services", 0755);

    /* Create service config file in SCM database */
    char svc_path[4096];
    snprintf(svc_path, sizeof(svc_path), "/var/lib/pe-compat/services/%s.svc", lpServiceName);

    /* MSDN: if the service already exists, CreateService returns NULL and
     * sets ERROR_SERVICE_EXISTS. Silent overwrite would corrupt registered
     * services that share a name. */
    struct stat st;
    if (stat(svc_path, &st) == 0) {
        set_last_error(ERROR_SERVICE_EXISTS);
        return NULL;
    }

    FILE *f = fopen(svc_path, "w");
    if (f) {
        fprintf(f, "name=%s\n", lpServiceName);
        if (lpDisplayName) fprintf(f, "display_name=%s\n", lpDisplayName);
        fprintf(f, "type=%u\n", dwServiceType);
        fprintf(f, "start_type=%u\n", dwStartType);
        fprintf(f, "error_control=%u\n", dwErrorControl);
        if (lpBinaryPathName) fprintf(f, "binary_path=%s\n", lpBinaryPathName);
        fclose(f);
    }

    /* Mirror the config into the registry so PE code that reads
     * HKLM\SYSTEM\CurrentControlSet\Services\<name> sees the same view
     * as QueryServiceConfig via the .svc file. Description is set by
     * ChangeServiceConfig2, not CreateService, so we pass NULL here. */
    svc_reg_write_config(lpServiceName, dwServiceType, dwStartType,
                         dwErrorControl, lpBinaryPathName, lpDisplayName,
                         NULL);

    sc_handle_data_t *data = calloc(1, sizeof(sc_handle_data_t));
    if (!data) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    strncpy(data->name, lpServiceName, sizeof(data->name) - 1);
    data->is_scm = 0;

    return handle_alloc(HANDLE_TYPE_SERVICE, -1, data);
}

WINAPI_EXPORT SC_HANDLE OpenServiceA(
    SC_HANDLE hSCManager,
    LPCSTR lpServiceName,
    DWORD dwDesiredAccess)
{
    (void)hSCManager;
    (void)dwDesiredAccess;

    if (!lpServiceName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    /* Reject service names that could escape the services directory. */
    if (strchr(lpServiceName, '/') || strchr(lpServiceName, '\\') ||
        strstr(lpServiceName, "..")) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    /* Check if service exists */
    char svc_path[4096];
    snprintf(svc_path, sizeof(svc_path), "/var/lib/pe-compat/services/%s.svc", lpServiceName);

    FILE *f = fopen(svc_path, "r");
    if (!f) {
        /* MSDN-documented error for OpenService on a missing service. */
        set_last_error(ERROR_SERVICE_DOES_NOT_EXIST);
        return NULL;
    }
    fclose(f);

    sc_handle_data_t *data = calloc(1, sizeof(sc_handle_data_t));
    if (!data) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    strncpy(data->name, lpServiceName, sizeof(data->name) - 1);
    data->is_scm = 0;

    fprintf(stderr, "[advapi32] OpenServiceA('%s')\n", lpServiceName);
    return handle_alloc(HANDLE_TYPE_SERVICE, -1, data);
}

WINAPI_EXPORT SC_HANDLE OpenServiceW(
    SC_HANDLE hSCManager,
    LPCWSTR lpServiceName,
    DWORD dwDesiredAccess)
{
    char narrow[256];
    if (lpServiceName) {
        int i;
        for (i = 0; lpServiceName[i] && i < 255; i++)
            narrow[i] = (char)(lpServiceName[i] & 0xFF);
        narrow[i] = '\0';
    } else {
        narrow[0] = '\0';
    }
    return OpenServiceA(hSCManager, narrow, dwDesiredAccess);
}

WINAPI_EXPORT BOOL StartServiceA(
    SC_HANDLE hService,
    DWORD dwNumServiceArgs,
    LPCSTR *lpServiceArgVectors)
{
    (void)dwNumServiceArgs;
    (void)lpServiceArgVectors;

    handle_entry_t *entry = handle_lookup(hService);
    if (!entry || !entry->data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    sc_handle_data_t *svc = (sc_handle_data_t *)entry->data;
    if (svc->is_scm) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    fprintf(stderr, "[advapi32] StartServiceA('%s')\n", svc->name);

    /* Write a status file to indicate the service is running */
    char status_path[4096];
    snprintf(status_path, sizeof(status_path), "/run/pe-compat/services/%s.status", svc->name);

    /* Ensure directory exists */
    mkdir("/run/pe-compat", 0755);
    mkdir("/run/pe-compat/services", 0755);

    FILE *f = fopen(status_path, "w");
    if (f) {
        fprintf(f, "state=%d\n", SERVICE_RUNNING);
        fprintf(f, "type=%u\n", (unsigned)SERVICE_WIN32_OWN_PROCESS);
        fprintf(f, "controls_accepted=%u\n",
                (unsigned)(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN));
        fprintf(f, "pid=%d\n", getpid());
        fclose(f);
    }

    return TRUE;
}

WINAPI_EXPORT BOOL ControlService(
    SC_HANDLE hService,
    DWORD dwControl,
    LPSERVICE_STATUS lpServiceStatus)
{
    handle_entry_t *entry = handle_lookup(hService);
    if (!entry || !entry->data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    sc_handle_data_t *svc = (sc_handle_data_t *)entry->data;
    if (svc->is_scm) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    fprintf(stderr, "[advapi32] ControlService('%s', control=%u)\n",
            svc->name, dwControl);

    /* Apply the control by updating the persistent status file so that a
     * subsequent QueryServiceStatus reflects the new state (previously the
     * file stayed at RUNNING forever and STOP was a no-op). */
    char status_path[4096];
    snprintf(status_path, sizeof(status_path),
             "/run/pe-compat/services/%s.status", svc->name);

    DWORD new_state = SERVICE_RUNNING;
    switch (dwControl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        new_state = SERVICE_STOPPED;
        unlink(status_path);
        break;
    case SERVICE_CONTROL_PAUSE:
        new_state = 7; /* SERVICE_PAUSED */
        break;
    case SERVICE_CONTROL_CONTINUE:
    case SERVICE_CONTROL_INTERROGATE:
    default:
        new_state = SERVICE_RUNNING;
        break;
    }

    if (lpServiceStatus) {
        memset(lpServiceStatus, 0, sizeof(*lpServiceStatus));
        lpServiceStatus->dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        lpServiceStatus->dwCurrentState = new_state;
        lpServiceStatus->dwControlsAccepted =
            (new_state == SERVICE_RUNNING)
            ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN)
            : 0;
    }

    return TRUE;
}

WINAPI_EXPORT BOOL QueryServiceStatus(
    SC_HANDLE hService,
    LPSERVICE_STATUS lpServiceStatus)
{
    handle_entry_t *entry = handle_lookup(hService);
    if (!entry || !entry->data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    sc_handle_data_t *svc = (sc_handle_data_t *)entry->data;

    /* SCManager handle is not a service handle -- ControlService et al
     * require a service handle (ERROR_INVALID_HANDLE on Windows). */
    if (svc->is_scm) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (!lpServiceStatus) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    memset(lpServiceStatus, 0, sizeof(*lpServiceStatus));
    lpServiceStatus->dwServiceType = SERVICE_WIN32_OWN_PROCESS;

    /* Read the status file. If the service process wrote dwCurrentState
     * via SetServiceStatus, parse it back; otherwise assume RUNNING if the
     * file exists at all, STOPPED if not. */
    char status_path[4096];
    snprintf(status_path, sizeof(status_path),
             "/run/pe-compat/services/%s.status", svc->name);

    FILE *f = fopen(status_path, "r");
    if (!f) {
        lpServiceStatus->dwCurrentState = SERVICE_STOPPED;
        return TRUE;
    }

    DWORD state = SERVICE_RUNNING;
    DWORD accepted = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        unsigned v;
        if (sscanf(line, "state=%u", &v) == 1) state = v;
        else if (sscanf(line, "controls_accepted=%u", &v) == 1) accepted = v;
    }
    fclose(f);

    lpServiceStatus->dwCurrentState = state;
    /* If the running service never advertised what it accepts, default to
     * the common baseline so callers can ControlService(STOP) on it. */
    if (state == SERVICE_RUNNING && accepted == 0)
        accepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    lpServiceStatus->dwControlsAccepted = accepted;

    return TRUE;
}

WINAPI_EXPORT BOOL CloseServiceHandle(SC_HANDLE hSCObject)
{
    handle_entry_t *entry = handle_lookup(hSCObject);
    if (entry && entry->data) {
        free(entry->data);
        entry->data = NULL;
    }
    handle_close(hSCObject);
    return TRUE;
}

WINAPI_EXPORT BOOL DeleteService(SC_HANDLE hService)
{
    handle_entry_t *entry = handle_lookup(hService);
    if (!entry || !entry->data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    sc_handle_data_t *svc = (sc_handle_data_t *)entry->data;
    if (svc->is_scm) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    char svc_path[4096];
    snprintf(svc_path, sizeof(svc_path), "/var/lib/pe-compat/services/%s.svc", svc->name);
    if (unlink(svc_path) != 0) {
        /* Already gone -- Windows reports ERROR_SERVICE_DOES_NOT_EXIST. */
        set_last_error(ERROR_SERVICE_DOES_NOT_EXIST);
        return FALSE;
    }

    /* Also drop any live status so QueryServiceStatus reflects deletion. */
    char status_path[4096];
    snprintf(status_path, sizeof(status_path), "/run/pe-compat/services/%s.status", svc->name);
    unlink(status_path);

    /* Scrub the registry mirror so an ensuing OpenService in another
     * process that looks at the registry sees the service is gone. */
    svc_reg_delete_config(svc->name);

    fprintf(stderr, "[advapi32] DeleteService('%s')\n", svc->name);
    return TRUE;
}

/*
 * SERVICE_NO_CHANGE: Windows sentinel that tells ChangeServiceConfig to
 * leave a particular field untouched. Callers frequently pass it for
 * fields they don't want to modify. We honor it for the DWORDs and the
 * string fields (NULL means "no change" for strings).
 */
#define SERVICE_NO_CHANGE 0xFFFFFFFF

/*
 * Best-effort re-read of .svc file so we can preserve fields the
 * caller didn't want to change. Returns 0 on success, -1 on failure.
 */
static int svc_read_existing(const char *svc_name, char *display, size_t disp_sz,
                             char *binpath, size_t bp_sz,
                             DWORD *type_out, DWORD *start_out, DWORD *err_out)
{
    char svc_path[4096];
    snprintf(svc_path, sizeof(svc_path),
             "/var/lib/pe-compat/services/%s.svc", svc_name);
    FILE *f = fopen(svc_path, "r");
    if (!f)
        return -1;

    if (display && disp_sz) display[0] = '\0';
    if (binpath && bp_sz)   binpath[0] = '\0';
    if (type_out)  *type_out  = SERVICE_WIN32_OWN_PROCESS;
    if (start_out) *start_out = SERVICE_DEMAND_START;
    if (err_out)   *err_out   = 1; /* SERVICE_ERROR_NORMAL */

    char line[4200];
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (strncmp(line, "display_name=", 13) == 0 && display && disp_sz) {
            strncpy(display, line + 13, disp_sz - 1);
            display[disp_sz - 1] = '\0';
        } else if (strncmp(line, "binary_path=", 12) == 0 && binpath && bp_sz) {
            strncpy(binpath, line + 12, bp_sz - 1);
            binpath[bp_sz - 1] = '\0';
        } else if (strncmp(line, "type=", 5) == 0 && type_out) {
            *type_out = (DWORD)strtoul(line + 5, NULL, 10);
        } else if (strncmp(line, "start_type=", 11) == 0 && start_out) {
            *start_out = (DWORD)strtoul(line + 11, NULL, 10);
        } else if (strncmp(line, "error_control=", 14) == 0 && err_out) {
            *err_out = (DWORD)strtoul(line + 14, NULL, 10);
        }
    }
    fclose(f);
    return 0;
}

WINAPI_EXPORT BOOL ChangeServiceConfigA(
    SC_HANDLE hService,
    DWORD dwServiceType,
    DWORD dwStartType,
    DWORD dwErrorControl,
    LPCSTR lpBinaryPathName,
    LPCSTR lpLoadOrderGroup,
    LPDWORD lpdwTagId,
    LPCSTR lpDependencies,
    LPCSTR lpServiceStartName,
    LPCSTR lpPassword,
    LPCSTR lpDisplayName)
{
    (void)lpLoadOrderGroup;
    (void)lpdwTagId;
    (void)lpDependencies;
    (void)lpServiceStartName;
    (void)lpPassword;

    handle_entry_t *entry = handle_lookup(hService);
    if (!entry || !entry->data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    sc_handle_data_t *svc = (sc_handle_data_t *)entry->data;
    if (svc->is_scm) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /* Load existing config so we can preserve fields with SERVICE_NO_CHANGE */
    char cur_display[256] = {0};
    char cur_binpath[4096] = {0};
    DWORD cur_type = SERVICE_WIN32_OWN_PROCESS;
    DWORD cur_start = SERVICE_DEMAND_START;
    DWORD cur_err = 1;
    if (svc_read_existing(svc->name, cur_display, sizeof(cur_display),
                          cur_binpath, sizeof(cur_binpath),
                          &cur_type, &cur_start, &cur_err) != 0) {
        set_last_error(ERROR_SERVICE_DOES_NOT_EXIST);
        return FALSE;
    }

    DWORD new_type  = (dwServiceType  == SERVICE_NO_CHANGE) ? cur_type  : dwServiceType;
    DWORD new_start = (dwStartType    == SERVICE_NO_CHANGE) ? cur_start : dwStartType;
    DWORD new_err   = (dwErrorControl == SERVICE_NO_CHANGE) ? cur_err   : dwErrorControl;
    const char *new_bin  = lpBinaryPathName ? lpBinaryPathName : cur_binpath;
    const char *new_disp = lpDisplayName    ? lpDisplayName    : cur_display;

    fprintf(stderr, "[advapi32] ChangeServiceConfigA('%s', type=%u, start=%u, path='%s')\n",
            svc->name, new_type, new_start,
            new_bin[0] ? new_bin : "(unchanged)");

    /* Rewrite the .svc file atomically via rename-on-write */
    char svc_path[4096];
    snprintf(svc_path, sizeof(svc_path),
             "/var/lib/pe-compat/services/%s.svc", svc->name);

    FILE *f = fopen(svc_path, "w");
    if (f) {
        fprintf(f, "name=%s\n", svc->name);
        if (new_disp[0]) fprintf(f, "display_name=%s\n", new_disp);
        fprintf(f, "type=%u\n", new_type);
        fprintf(f, "start_type=%u\n", new_start);
        fprintf(f, "error_control=%u\n", new_err);
        if (new_bin[0]) fprintf(f, "binary_path=%s\n", new_bin);
        fclose(f);
    }

    /* Mirror to registry. Pass NULL for description; ChangeServiceConfig2
     * is the documented path for description updates. */
    svc_reg_write_config(svc->name, new_type, new_start, new_err,
                         new_bin[0] ? new_bin : NULL,
                         new_disp[0] ? new_disp : NULL,
                         NULL);

    return TRUE;
}

/* ========================================================================
 * Service-side APIs (called by the service process itself)
 * ======================================================================== */

/* SERVICE_STATUS_HANDLE is an opaque handle.
 * We store the control handler callback so we can dispatch to it. */
typedef void (__attribute__((ms_abi)) *SERVICE_CTRL_HANDLER_FUNC)(DWORD);

typedef struct {
    char service_name[256];
    SERVICE_CTRL_HANDLER_FUNC handler;
    SERVICE_STATUS status;
} svc_ctrl_entry_t;

#define MAX_SVC_CTRL 16
static svc_ctrl_entry_t g_svc_ctrl[MAX_SVC_CTRL];
static int g_svc_ctrl_count = 0;
static pthread_mutex_t g_svc_ctrl_lock = PTHREAD_MUTEX_INITIALIZER;

WINAPI_EXPORT HANDLE RegisterServiceCtrlHandlerA(
    LPCSTR lpServiceName,
    void *lpHandlerProc)
{
    if (!lpServiceName || !lpHandlerProc) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    /* Reject service names that would escape the /run/pe-compat/services
     * directory when SetServiceStatus later builds a status path. */
    if (strchr(lpServiceName, '/') || strchr(lpServiceName, '\\') ||
        strstr(lpServiceName, "..")) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    pthread_mutex_lock(&g_svc_ctrl_lock);
    if (g_svc_ctrl_count >= MAX_SVC_CTRL) {
        pthread_mutex_unlock(&g_svc_ctrl_lock);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    int slot = g_svc_ctrl_count++;
    svc_ctrl_entry_t *entry = &g_svc_ctrl[slot];
    strncpy(entry->service_name, lpServiceName, sizeof(entry->service_name) - 1);
    entry->service_name[sizeof(entry->service_name) - 1] = '\0';
    entry->handler = (SERVICE_CTRL_HANDLER_FUNC)lpHandlerProc;
    memset(&entry->status, 0, sizeof(entry->status));
    pthread_mutex_unlock(&g_svc_ctrl_lock);

    /* Return a 1-based index as the SERVICE_STATUS_HANDLE */
    HANDLE h = (HANDLE)(uintptr_t)(slot + 1);

    fprintf(stderr, "[advapi32] RegisterServiceCtrlHandlerA('%s') -> %p\n",
            lpServiceName, h);
    return h;
}

WINAPI_EXPORT HANDLE RegisterServiceCtrlHandlerW(
    LPCWSTR lpServiceName,
    void *lpHandlerProc)
{
    char narrow[256];
    if (lpServiceName) {
        int i;
        for (i = 0; lpServiceName[i] && i < 255; i++)
            narrow[i] = (char)(lpServiceName[i] & 0xFF);
        narrow[i] = '\0';
    } else {
        narrow[0] = '\0';
    }
    return RegisterServiceCtrlHandlerA(narrow, lpHandlerProc);
}

WINAPI_EXPORT BOOL SetServiceStatus(
    HANDLE hServiceStatus,
    LPSERVICE_STATUS lpServiceStatus)
{
    int idx = (int)(uintptr_t)hServiceStatus - 1;

    if (!lpServiceStatus) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    pthread_mutex_lock(&g_svc_ctrl_lock);
    if (idx < 0 || idx >= g_svc_ctrl_count) {
        pthread_mutex_unlock(&g_svc_ctrl_lock);
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    memcpy(&g_svc_ctrl[idx].status, lpServiceStatus, sizeof(SERVICE_STATUS));

    /* Snapshot the service name under the lock; release before doing I/O
     * so we don't hold the lock across fopen/fprintf. */
    char svc_name[256];
    strncpy(svc_name, g_svc_ctrl[idx].service_name, sizeof(svc_name) - 1);
    svc_name[sizeof(svc_name) - 1] = '\0';
    pthread_mutex_unlock(&g_svc_ctrl_lock);

    fprintf(stderr, "[advapi32] SetServiceStatus('%s', state=%u)\n",
            svc_name, lpServiceStatus->dwCurrentState);

    /* Write status to /run for SCM daemon to read */
    char status_path[4096];
    snprintf(status_path, sizeof(status_path),
             "/run/pe-compat/services/%s.status", svc_name);

    mkdir("/run/pe-compat", 0755);
    mkdir("/run/pe-compat/services", 0755);

    FILE *f = fopen(status_path, "w");
    if (f) {
        fprintf(f, "state=%u\n", lpServiceStatus->dwCurrentState);
        fprintf(f, "type=%u\n", lpServiceStatus->dwServiceType);
        fprintf(f, "controls_accepted=%u\n", lpServiceStatus->dwControlsAccepted);
        fprintf(f, "exit_code=%u\n", lpServiceStatus->dwWin32ExitCode);
        fprintf(f, "checkpoint=%u\n", lpServiceStatus->dwCheckPoint);
        fprintf(f, "wait_hint=%u\n", lpServiceStatus->dwWaitHint);
        fprintf(f, "pid=%d\n", getpid());
        fclose(f);
    }

    return TRUE;
}

/* StartServiceCtrlDispatcherA - normally connects to SCM and dispatches.
 * In our loader, we just call ServiceMain directly since the PE loader
 * acts as the host process. */
typedef struct {
    LPCSTR lpServiceName;
    void  *lpServiceProc;
} SERVICE_TABLE_ENTRYA;

typedef void (__attribute__((ms_abi)) *SERVICE_MAIN_FUNC)(DWORD, LPSTR *);

WINAPI_EXPORT BOOL StartServiceCtrlDispatcherA(
    const SERVICE_TABLE_ENTRYA *lpServiceTable)
{
    if (!lpServiceTable) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Iterate the service table and call each ServiceMain */
    for (int i = 0; lpServiceTable[i].lpServiceProc != NULL; i++) {
        fprintf(stderr, "[advapi32] StartServiceCtrlDispatcherA: dispatching '%s'\n",
                lpServiceTable[i].lpServiceName ? lpServiceTable[i].lpServiceName : "(null)");

        SERVICE_MAIN_FUNC svc_main = (SERVICE_MAIN_FUNC)lpServiceTable[i].lpServiceProc;
        svc_main(0, NULL);
    }

    return TRUE;
}

/* Security API stubs moved to advapi32_security.c */
