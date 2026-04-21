/*
 * tiny_console.c -- Minimal PE32+ console fixture.
 *
 * WHY: Exercises the core console-subsystem import graph end-to-end:
 *   kernel32!GetStdHandle, kernel32!WriteFile, kernel32!ExitProcess
 *   msvcrt!printf, msvcrt!exit
 *
 * Both kernel32 stdout (WriteFile->fd(1)) AND msvcrt stdio (FILE*
 * stdout -> printf) need to be live. Hitting both in one fixture
 * catches the common "CRT stdout wasn't wired to Linux stdout" bug.
 *
 * Printed exact marker "Hello from PE!" is asserted by the test harness
 * (test_fixtures.sh). If the marker appears on stdout AND exit == 0,
 * the entire console I/O plumbing is working.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -s -nostartfiles -Wl,--entry=_start \
 *       -o tiny_console.exe tiny_console.c -lkernel32 -lmsvcrt
 *
 * Expected:
 *   stdout: "Hello from PE!\n" (possibly twice: WriteFile + printf)
 *   exit:   0
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/* Explicit literal length so the WriteFile byte count is obvious.
 * sizeof(HELLO) picks up the NUL terminator, hence the -1 below. */
static const char HELLO[] = "Hello from PE!\n";

void _start(void)
{
    /* Path A: kernel32 stdout. Independent of any CRT state. */
    HANDLE h = GetStdHandle((DWORD)-11);  /* STD_OUTPUT_HANDLE == -11 */
    DWORD written = 0;
    if (h == NULL || h == INVALID_HANDLE_VALUE) {
        ExitProcess(2);
    }
    if (!WriteFile(h, HELLO, sizeof(HELLO) - 1, &written, NULL) ||
        written != sizeof(HELLO) - 1) {
        ExitProcess(3);
    }

    /* Path B: msvcrt printf. Triggers FILE* stdout init + vfprintf. */
    int n = printf("Hello from PE!\n");
    if (n <= 0) {
        /* printf returned <=0 but we already proved stdout works above;
         * report as a CRT-specific failure so the harness can discriminate. */
        ExitProcess(4);
    }

    /* exit() flushes CRT buffers + calls atexit handlers; ExitProcess
     * would skip flush. Use exit(0) for a clean CRT teardown. */
    exit(0);
}
