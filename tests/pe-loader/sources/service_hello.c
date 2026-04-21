/*
 * service_hello.c -- Win32 service skeleton.
 *
 * Surface tested:
 *   advapi32!StartServiceCtrlDispatcherA, advapi32!RegisterServiceCtrlHandlerA,
 *   advapi32!SetServiceStatus
 *
 * Rationale:
 *   Validates Agent A4's Service Control Manager.  When invoked under
 *   our PE loader directly (NOT via scm-daemon), StartServiceCtrlDispatcher
 *   should return ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (1063).  That's
 *   actually the SUCCESS path here -- it proves:
 *     - StartServiceCtrlDispatcherA is wired
 *     - The SERVICE_TABLE_ENTRY layout is correct
 *     - The error code propagates correctly
 *
 *   When run under scm-daemon, dispatcher returns TRUE and ServiceMain
 *   gets called -- we set status to SERVICE_RUNNING then immediately
 *   STOPPED and exit cleanly.
 *
 * Harness expectation: outputs:SERVICE_HELLO_OK
 *                  OR  outputs:SERVICE_HELLO_NOSCM   (expected outside SCM)
 */

#include <windows.h>
#include <stdio.h>

static SERVICE_STATUS_HANDLE g_status_handle = NULL;
static SERVICE_STATUS g_status = {0};

static DWORD WINAPI svc_ctrl_handler(DWORD ctrl, DWORD evt_type,
                                     LPVOID evt_data, LPVOID ctx) {
    (void)evt_type; (void)evt_data; (void)ctx;
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        g_status.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_status_handle, &g_status);
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

static VOID WINAPI svc_main(DWORD argc, LPSTR *argv) {
    (void)argc; (void)argv;

    g_status_handle = RegisterServiceCtrlHandlerExA(
        "PELoaderCorpus", svc_ctrl_handler, NULL);
    if (!g_status_handle) {
        return;
    }

    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = SERVICE_RUNNING;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP |
                                  SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_status_handle, &g_status);

    /* Brief sleep to let SCM record the running state. */
    Sleep(100);

    g_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_status_handle, &g_status);
}

int main(void) {
    SERVICE_TABLE_ENTRYA table[] = {
        { (LPSTR)"PELoaderCorpus", svc_main },
        { NULL, NULL }
    };

    BOOL ok = StartServiceCtrlDispatcherA(table);
    if (ok) {
        printf("SERVICE_HELLO_OK\n");
        fflush(stdout);
        return 0;
    }

    DWORD err = GetLastError();
    /* 1063 = ERROR_FAILED_SERVICE_CONTROLLER_CONNECT.  Expected when
     * not running under an SCM (i.e. invoked as a normal binary). */
    if (err == 1063) {
        printf("dispatcher returned ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (expected)\n");
        printf("SERVICE_HELLO_NOSCM\n");
        fflush(stdout);
        return 0;
    }

    fprintf(stderr, "StartServiceCtrlDispatcherA failed: GLE=%lu\n",
            (unsigned long)err);
    return 70;
}
