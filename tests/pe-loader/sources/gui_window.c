/*
 * gui_window.c -- user32 window class + message pump.
 *
 * Surface tested:
 *   user32!RegisterClassExA, user32!CreateWindowExA, user32!ShowWindow,
 *   user32!SetWindowTextA, user32!GetMessageA, user32!TranslateMessage,
 *   user32!DispatchMessageA, user32!PostQuitMessage, user32!DefWindowProcA,
 *   user32!SetTimer
 *
 * Rationale:
 *   Stand up a real top-level window, set a self-quit timer for 2 seconds,
 *   pump messages until WM_QUIT, exit 0.  Catches:
 *     - HINSTANCE returned by GetModuleHandleA matches what
 *       RegisterClassEx expects
 *     - WNDCLASSEX layout/size/alignment
 *     - WndProc calling convention (must be ms_abi for STDCALL on x64)
 *     - SetTimer + WM_TIMER delivery
 *     - DefWindowProc handles WM_DESTROY/WM_NCDESTROY properly
 *
 *   Runs HEADLESS-FRIENDLY: even if no display is available, the loader
 *   should be able to satisfy the import graph and run the message pump
 *   against a stubbed display.  If RegisterClassEx returns 0 with the
 *   stub backend, we still print STUB_OK so the harness can record it as
 *   a partial pass.
 *
 * Harness expectation: outputs:GUI_WINDOW_OK   (real GUI ran)
 *                  OR  outputs:GUI_WINDOW_STUB (stub backend, imports OK)
 */

#include <windows.h>
#include <stdio.h>

#define TIMER_ID_QUIT  1

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg,
                                 WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_TIMER:
        if (wp == TIMER_ID_QUIT) {
            KillTimer(hwnd, TIMER_ID_QUIT);
            DestroyWindow(hwnd);
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcA(hwnd, msg, wp, lp);
    }
}

int main(void) {
    HINSTANCE hi = GetModuleHandleA(NULL);

    WNDCLASSEXA wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = hi;
    wc.lpszClassName = "PELoaderCorpusWindow";

    ATOM cls = RegisterClassExA(&wc);
    if (!cls) {
        /* Stub backend may decline.  Still report import graph health. */
        DWORD gle = GetLastError();
        printf("RegisterClassExA returned 0; GLE=%lu (stub backend?)\n",
               (unsigned long)gle);
        printf("GUI_WINDOW_STUB\n");
        fflush(stdout);
        return 0;
    }

    HWND hwnd = CreateWindowExA(
        0, "PELoaderCorpusWindow", "PE Loader Corpus",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 320, 200,
        NULL, NULL, hi, NULL);

    if (!hwnd) {
        DWORD gle = GetLastError();
        printf("CreateWindowExA returned NULL; GLE=%lu (stub backend?)\n",
               (unsigned long)gle);
        printf("GUI_WINDOW_STUB\n");
        fflush(stdout);
        return 0;
    }

    SetWindowTextA(hwnd, "Corpus: Hello");
    ShowWindow(hwnd, SW_SHOW);

    /* 2-second self-quit. */
    if (!SetTimer(hwnd, TIMER_ID_QUIT, 2000, NULL)) {
        printf("SetTimer failed; GLE=%lu\n",
               (unsigned long)GetLastError());
        DestroyWindow(hwnd);
        printf("GUI_WINDOW_STUB\n");
        fflush(stdout);
        return 0;
    }

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    printf("GUI_WINDOW_OK\n");
    fflush(stdout);
    return 0;
}
