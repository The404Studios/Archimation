/*
 * tiny_messagebox.c -- PE32+ GUI-subsystem fixture.
 *
 * WHY: Verifies the GUI import path: user32!MessageBoxA. Even with no
 * DISPLAY available the loader must:
 *   - parse the PE as subsystem=2 (Windows GUI)
 *   - resolve user32.dll::MessageBoxA from the .so stub
 *   - dispatch into the stub without crashing
 *
 * Why MessageBoxA specifically:
 *   It's the canonical GUI smoke test in Win32 land and our user32
 *   stub has a documented path that either pops a GTK dialog (DISPLAY
 *   set) or logs + returns IDOK (headless). Either outcome is a pass;
 *   failure is "unresolved import" or loader crash.
 *
 * MB_OK | MB_ICONINFORMATION = 0x40. Any user32 implementation that
 * recognises these flags (even just to log them) will accept the call.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -s -nostartfiles -Wl,--entry=_start \
 *       -mwindows -o tiny_messagebox.exe tiny_messagebox.c \
 *       -lkernel32 -luser32
 *
 * Expected:
 *   - DISPLAY set:    dialog shown OR immediate IDOK, exit 0
 *   - headless:       stub logs "MessageBoxA: <title>: <text>", exit 0
 *   - import broken:  loader prints "unresolved import: user32.MessageBoxA",
 *                     non-zero exit -- THIS IS the known-failing case the
 *                     test harness expects when user32 stub is incomplete.
 */

#include <windows.h>

void _start(void)
{
    /* hWnd=NULL so no parent-window lookup is needed. */
    int rc = MessageBoxA(NULL,
                         "peloader GUI smoke test",
                         "tiny_messagebox",
                         0x40 /* MB_OK | MB_ICONINFORMATION */);

    /* rc is IDOK(1) on success. Headless stub may return 0 if it can't
     * show anything; that's still acceptable for the smoke test. */
    ExitProcess(rc > 0 ? 0 : 1);
}
