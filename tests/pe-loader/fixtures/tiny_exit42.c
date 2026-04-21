/*
 * tiny_exit42.c -- Simplest possible PE32+ fixture.
 *
 * WHY: This is the minimum viable PE test: if peloader can parse
 * headers, map sections, resolve kernel32!ExitProcess, and dispatch
 * control, then ExitProcess(42) returns exit code 42 to Linux.
 *
 * A non-zero exit code (42) proves the kernel32 stub's ExitProcess
 * correctly forwards to Linux exit(2) without clobbering the status
 * — a wrong exit code would mean the loader is swallowing the value.
 *
 * No imports beyond kernel32.dll::ExitProcess. No CRT. No stdout. The
 * only thing that can fail here is PE parse, section mapping, or the
 * ABI transition into ExitProcess. Keeps the failure surface tiny so
 * regressions here point at the loader, not the fixture.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -s -nostartfiles -Wl,--entry=_start \
 *       -o tiny_exit42.exe tiny_exit42.c -lkernel32
 *
 * Expected: peloader tiny_exit42.exe; echo $?  ==> 42
 */

#include <windows.h>

void _start(void)
{
    ExitProcess(42);
}
