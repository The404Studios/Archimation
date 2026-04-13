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
#include <unistd.h>
#include <sys/stat.h>

#include "common/dll_common.h"

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

    fprintf(stderr, "[advapi32] CreateServiceA('%s', type=%u, start=%u, path='%s')\n",
            lpServiceName, dwServiceType, dwStartType,
            lpBinaryPathName ? lpBinaryPathName : "(null)");

    /* Create service config file in SCM database */
    char svc_path[4096];
    snprintf(svc_path, sizeof(svc_path), "/var/lib/pe-compat/services/%s.svc", lpServiceName);

    FILE *f = fopen(svc_path, "w");
    if (f) {
        fprintf(f, "name=%s\n", lpServiceName);
        if (lpDisplayName) fprintf(f, "display_name=%s\n", lpDisplayName);
        fprintf(f, "type=%u\n", dwServiceType);
        fprintf(f, "start_type=%u\n", dwStartType);
        if (lpBinaryPathName) fprintf(f, "binary_path=%s\n", lpBinaryPathName);
        fclose(f);
    }

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

    /* Check if service exists */
    char svc_path[4096];
    snprintf(svc_path, sizeof(svc_path), "/var/lib/pe-compat/services/%s.svc", lpServiceName);

    FILE *f = fopen(svc_path, "r");
    if (!f) {
        set_last_error(ERROR_FILE_NOT_FOUND);
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

    fprintf(stderr, "[advapi32] ControlService('%s', control=%u)\n",
            svc->name, dwControl);

    if (lpServiceStatus) {
        memset(lpServiceStatus, 0, sizeof(*lpServiceStatus));
        lpServiceStatus->dwServiceType = SERVICE_WIN32_OWN_PROCESS;

        switch (dwControl) {
        case SERVICE_CONTROL_STOP:
            lpServiceStatus->dwCurrentState = SERVICE_STOPPED;
            break;
        case SERVICE_CONTROL_INTERROGATE:
            lpServiceStatus->dwCurrentState = SERVICE_RUNNING;
            break;
        default:
            lpServiceStatus->dwCurrentState = SERVICE_RUNNING;
            break;
        }
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

    if (lpServiceStatus) {
        memset(lpServiceStatus, 0, sizeof(*lpServiceStatus));
        lpServiceStatus->dwServiceType = SERVICE_WIN32_OWN_PROCESS;

        /* Check if status file exists (service is running) */
        char status_path[4096];
        snprintf(status_path, sizeof(status_path),
                 "/run/pe-compat/services/%s.status", svc->name);

        FILE *f = fopen(status_path, "r");
        if (f) {
            lpServiceStatus->dwCurrentState = SERVICE_RUNNING;
            fclose(f);
        } else {
            lpServiceStatus->dwCurrentState = SERVICE_STOPPED;
        }
    }

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

    char svc_path[4096];
    snprintf(svc_path, sizeof(svc_path), "/var/lib/pe-compat/services/%s.svc", svc->name);
    unlink(svc_path);

    fprintf(stderr, "[advapi32] DeleteService('%s')\n", svc->name);
    return TRUE;
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
    (void)hService;
    (void)dwServiceType;
    (void)dwStartType;
    (void)dwErrorControl;
    (void)lpBinaryPathName;
    (void)lpLoadOrderGroup;
    (void)lpdwTagId;
    (void)lpDependencies;
    (void)lpServiceStartName;
    (void)lpPassword;
    (void)lpDisplayName;

    fprintf(stderr, "[advapi32] ChangeServiceConfigA() - stub\n");
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

WINAPI_EXPORT HANDLE RegisterServiceCtrlHandlerA(
    LPCSTR lpServiceName,
    void *lpHandlerProc)
{
    if (!lpServiceName || !lpHandlerProc) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    if (g_svc_ctrl_count >= MAX_SVC_CTRL) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    svc_ctrl_entry_t *entry = &g_svc_ctrl[g_svc_ctrl_count];
    strncpy(entry->service_name, lpServiceName, sizeof(entry->service_name) - 1);
    entry->handler = (SERVICE_CTRL_HANDLER_FUNC)lpHandlerProc;
    memset(&entry->status, 0, sizeof(entry->status));

    /* Return a 1-based index as the SERVICE_STATUS_HANDLE */
    HANDLE h = (HANDLE)(uintptr_t)(++g_svc_ctrl_count);

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

    if (idx < 0 || idx >= g_svc_ctrl_count || !lpServiceStatus) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    memcpy(&g_svc_ctrl[idx].status, lpServiceStatus, sizeof(SERVICE_STATUS));

    fprintf(stderr, "[advapi32] SetServiceStatus('%s', state=%u)\n",
            g_svc_ctrl[idx].service_name,
            lpServiceStatus->dwCurrentState);

    /* Write status to /run for SCM daemon to read */
    char status_path[4096];
    snprintf(status_path, sizeof(status_path),
             "/run/pe-compat/services/%s.status", g_svc_ctrl[idx].service_name);

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
