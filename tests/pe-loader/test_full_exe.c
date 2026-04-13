/*
 * test_full_exe.c - Comprehensive PE executable test
 *
 * Tests: kernel32, msvcrt, advapi32 API coverage
 * Build: x86_64-w64-mingw32-gcc -o test_full_exe.exe test_full_exe.c \
 *        -lkernel32 -ladvapi32 -lmsvcrt -nostartfiles -Wl,--entry=_start
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

static int g_tests_passed = 0;
static int g_tests_failed = 0;

static void check(const char *name, int condition)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    char buf[256];
    int len;

    if (condition) {
        len = wsprintfA(buf, "  [PASS] %s\r\n", name);
        g_tests_passed++;
    } else {
        len = wsprintfA(buf, "  [FAIL] %s\r\n", name);
        g_tests_failed++;
    }
    WriteFile(hOut, buf, len, &written, NULL);
}

void _start(void)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    char buf[512];
    int len;

    const char *banner = "=== Full EXE Test Suite ===\r\n\r\n";
    WriteFile(hOut, banner, lstrlenA(banner), &written, NULL);

    /* --- Kernel32 Tests --- */
    const char *k32 = "-- kernel32 tests --\r\n";
    WriteFile(hOut, k32, lstrlenA(k32), &written, NULL);

    /* Test 1: GetVersion */
    DWORD ver = GetVersion();
    check("GetVersion returns non-zero", ver != 0);

    /* Test 2: GetLastError/SetLastError */
    SetLastError(0);
    check("GetLastError after SetLastError(0) == 0", GetLastError() == 0);
    SetLastError(1234);
    check("GetLastError after SetLastError(1234) == 1234", GetLastError() == 1234);

    /* Test 3: GetCurrentProcessId */
    DWORD pid = GetCurrentProcessId();
    check("GetCurrentProcessId > 0", pid > 0);

    /* Test 4: GetCurrentThreadId */
    DWORD tid = GetCurrentThreadId();
    check("GetCurrentThreadId > 0", tid > 0);

    /* Test 5: VirtualAlloc/VirtualFree */
    void *mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    check("VirtualAlloc returned non-NULL", mem != NULL);
    if (mem) {
        /* Write and read back */
        memset(mem, 0xAB, 4096);
        check("VirtualAlloc memory is writable", ((unsigned char *)mem)[0] == 0xAB);
        VirtualFree(mem, 0, MEM_RELEASE);
    }

    /* Test 6: GetModuleHandle */
    HMODULE hMod = GetModuleHandleA(NULL);
    check("GetModuleHandleA(NULL) non-NULL", hMod != NULL);

    /* Test 7: GetCommandLineA */
    LPCSTR cmd = GetCommandLineA();
    check("GetCommandLineA non-NULL", cmd != NULL);

    /* Test 8: GetTickCount */
    DWORD tick = GetTickCount();
    check("GetTickCount > 0", tick > 0);

    /* Test 9: QueryPerformanceCounter */
    LARGE_INTEGER pc;
    BOOL qpc_ok = QueryPerformanceCounter(&pc);
    check("QueryPerformanceCounter succeeds", qpc_ok);

    /* Test 10: GetSystemInfo */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    check("GetSystemInfo.dwPageSize > 0", si.dwPageSize > 0);
    check("GetSystemInfo.dwNumberOfProcessors > 0", si.dwNumberOfProcessors > 0);

    /* Test 11: GetEnvironmentVariableA */
    char envbuf[256];
    DWORD envlen = GetEnvironmentVariableA("PATH", envbuf, sizeof(envbuf));
    check("GetEnvironmentVariableA(PATH) returns > 0", envlen > 0);

    /* Test 12: CreateFileA for stdout equivalent */
    /* (We already have stdout, so just check that the function doesn't crash) */
    HANDLE hNull = CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    check("CreateFileA(NUL) returns handle", hNull != INVALID_HANDLE_VALUE);
    if (hNull != INVALID_HANDLE_VALUE)
        CloseHandle(hNull);

    /* Test 13: GetComputerNameA */
    char compname[256];
    DWORD complen = sizeof(compname);
    BOOL compok = GetComputerNameA(compname, &complen);
    check("GetComputerNameA succeeds", compok);

    /* --- MSVCRT Tests --- */
    const char *crt = "\r\n-- msvcrt tests --\r\n";
    WriteFile(hOut, crt, lstrlenA(crt), &written, NULL);

    /* Test 14: strlen */
    check("strlen(\"hello\") == 5", strlen("hello") == 5);

    /* Test 15: memcpy */
    char src[] = "test123";
    char dst[16] = {0};
    memcpy(dst, src, 8);
    check("memcpy copies correctly", strcmp(dst, "test123") == 0);

    /* --- Results --- */
    len = wsprintfA(buf, "\r\n=== Results: %d passed, %d failed ===\r\n",
                    g_tests_passed, g_tests_failed);
    WriteFile(hOut, buf, len, &written, NULL);

    if (g_tests_failed == 0) {
        const char *ok = "ALL TESTS PASSED\r\n";
        WriteFile(hOut, ok, lstrlenA(ok), &written, NULL);
    }

    ExitProcess(g_tests_failed);
}
