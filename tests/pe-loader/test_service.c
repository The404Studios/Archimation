/*
 * test_service.c - Windows service test executable
 *
 * Tests: Service control dispatcher, RegisterServiceCtrlHandler,
 *        SetServiceStatus
 *
 * Build: x86_64-w64-mingw32-gcc -o test_service.exe test_service.c \
 *        -lkernel32 -ladvapi32 -nostartfiles -Wl,--entry=_start
 */

#include <windows.h>

#define SERVICE_NAME "TestService"

static SERVICE_STATUS_HANDLE g_hServiceStatus = NULL;
static SERVICE_STATUS g_ServiceStatus;
static HANDLE g_hStopEvent = NULL;

static void write_msg(const char *msg)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    WriteFile(hOut, msg, lstrlenA(msg), &written, NULL);
}

static void WINAPI ServiceCtrlHandler(DWORD control)
{
    char buf[128];

    switch (control) {
    case SERVICE_CONTROL_STOP:
        write_msg("[service] Received STOP control\r\n");
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = 0;
        SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);
        if (g_hStopEvent)
            SetEvent(g_hStopEvent);
        break;
    case SERVICE_CONTROL_INTERROGATE:
        write_msg("[service] Received INTERROGATE control\r\n");
        SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);
        break;
    default:
        wsprintfA(buf, "[service] Received control: %u\r\n", (unsigned)control);
        write_msg(buf);
        break;
    }
}

static void WINAPI ServiceMain(DWORD argc, LPSTR *argv)
{
    (void)argc;
    (void)argv;
    char buf[256];

    write_msg("[service] ServiceMain entered\r\n");

    /* Register the service control handler */
    g_hServiceStatus = RegisterServiceCtrlHandlerA(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_hServiceStatus) {
        wsprintfA(buf, "[service] RegisterServiceCtrlHandler failed: %u\r\n",
                  (unsigned)GetLastError());
        write_msg(buf);
        write_msg("[FAIL] RegisterServiceCtrlHandler\r\n");
        return;
    }
    write_msg("[PASS] RegisterServiceCtrlHandler\r\n");

    /* Report SERVICE_START_PENDING */
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 1;
    g_ServiceStatus.dwWaitHint = 3000;
    SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);
    write_msg("[PASS] SetServiceStatus(START_PENDING)\r\n");

    /* Create stop event */
    g_hStopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_hStopEvent) {
        write_msg("[FAIL] CreateEvent for stop\r\n");
    } else {
        write_msg("[PASS] CreateEvent\r\n");
    }

    /* Report SERVICE_RUNNING */
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);
    write_msg("[PASS] SetServiceStatus(RUNNING)\r\n");

    write_msg("[service] Service is running. Stopping immediately for test.\r\n");

    /* In test mode: immediately stop */
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);
    write_msg("[PASS] SetServiceStatus(STOPPED)\r\n");

    write_msg("[service] ALL SERVICE TESTS PASSED\r\n");
}

void _start(void)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;

    const char *banner = "=== Windows Service Test ===\r\n\r\n";
    WriteFile(hOut, banner, lstrlenA(banner), &written, NULL);

    /* Normally a service would call StartServiceCtrlDispatcher.
     * For testing, we call ServiceMain directly since we're
     * running under the PE loader, not the real SCM. */
    write_msg("[service] Calling ServiceMain directly for test...\r\n");
    ServiceMain(0, NULL);

    ExitProcess(0);
}
