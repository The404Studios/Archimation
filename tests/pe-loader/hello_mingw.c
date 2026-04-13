/*
 * hello_mingw.c - Test PE binary for cross-compilation with MinGW
 *
 * Build (inside Arch Linux with mingw-w64-gcc installed):
 *   x86_64-w64-mingw32-gcc -o hello_mingw.exe hello_mingw.c -nostdlib \
 *       -Wl,--entry=_start -lkernel32
 *
 * Tests: basic console I/O, GetVersion, GetLastError
 */

#include <windows.h>

void _start(void)
{
    HANDLE hStdOut;
    DWORD written;
    DWORD version;
    char buf[128];
    int len;

    /* Get stdout handle */
    hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

    /* Print greeting */
    const char *msg = "Hello from MinGW PE!\r\n";
    WriteFile(hStdOut, msg, lstrlenA(msg), &written, NULL);

    /* Print Windows version */
    version = GetVersion();
    len = wsprintfA(buf, "GetVersion() = 0x%08X (major=%d, minor=%d, build=%d)\r\n",
                    version,
                    version & 0xFF,
                    (version >> 8) & 0xFF,
                    (version >> 16) & 0x7FFF);
    WriteFile(hStdOut, buf, len, &written, NULL);

    /* Test GetLastError (should be 0 initially) */
    SetLastError(42);
    DWORD err = GetLastError();
    len = wsprintfA(buf, "GetLastError() = %u (expected 42)\r\n", err);
    WriteFile(hStdOut, buf, len, &written, NULL);

    /* Print result */
    if (err == 42) {
        const char *ok = "ALL TESTS PASSED\r\n";
        WriteFile(hStdOut, ok, lstrlenA(ok), &written, NULL);
        ExitProcess(0);
    } else {
        const char *fail = "TEST FAILED\r\n";
        WriteFile(hStdOut, fail, lstrlenA(fail), &written, NULL);
        ExitProcess(1);
    }
}
