/*
 * test_minimal.c - Absolute minimum PE test
 *
 * Build: x86_64-w64-mingw32-gcc -o test_minimal.exe test_minimal.c
 *        -lkernel32 -nostartfiles -Wl,--entry=_start
 */

#include <windows.h>

void _start(void)
{
    HANDLE hOut = GetStdHandle((DWORD)-11); /* STD_OUTPUT_HANDLE */
    const char msg[] = "HELLO FROM PE\n";
    DWORD written;
    WriteFile(hOut, msg, 14, &written, NULL);
    ExitProcess(written > 0 ? 0 : 99);
}
