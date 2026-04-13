/*
 * kernel32_console.c - Windows Console API stubs
 *
 * Maps WriteConsole/ReadConsole to Linux terminal I/O.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "common/dll_common.h"

WINAPI_EXPORT HANDLE GetStdHandle(DWORD nStdHandle)
{
    return get_std_handle(nStdHandle);
}

WINAPI_EXPORT BOOL WriteConsoleA(
    HANDLE  hConsoleOutput,
    LPCVOID lpBuffer,
    DWORD   nNumberOfCharsToWrite,
    LPDWORD lpNumberOfCharsWritten,
    LPVOID  lpReserved)
{
    (void)lpReserved;

    int fd = handle_get_fd(hConsoleOutput);
    if (fd < 0) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    ssize_t written = write(fd, lpBuffer, nNumberOfCharsToWrite);
    if (written < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    if (lpNumberOfCharsWritten)
        *lpNumberOfCharsWritten = (DWORD)written;

    return TRUE;
}

WINAPI_EXPORT BOOL WriteConsoleW(
    HANDLE  hConsoleOutput,
    LPCVOID lpBuffer,
    DWORD   nNumberOfCharsToWrite,
    LPDWORD lpNumberOfCharsWritten,
    LPVOID  lpReserved)
{
    /* Simple UTF-16 to UTF-8 conversion for basic ASCII */
    const uint16_t *src = (const uint16_t *)lpBuffer;
    char buf[8192];
    DWORD out_len = 0;

    for (DWORD i = 0; i < nNumberOfCharsToWrite && out_len < sizeof(buf) - 4; i++) {
        uint16_t ch = src[i];
        if (ch < 0x80) {
            buf[out_len++] = (char)ch;
        } else if (ch < 0x800) {
            buf[out_len++] = 0xC0 | (ch >> 6);
            buf[out_len++] = 0x80 | (ch & 0x3F);
        } else {
            buf[out_len++] = 0xE0 | (ch >> 12);
            buf[out_len++] = 0x80 | ((ch >> 6) & 0x3F);
            buf[out_len++] = 0x80 | (ch & 0x3F);
        }
    }

    return WriteConsoleA(hConsoleOutput, buf, out_len, lpNumberOfCharsWritten, lpReserved);
}

WINAPI_EXPORT BOOL ReadConsoleA(
    HANDLE  hConsoleInput,
    LPVOID  lpBuffer,
    DWORD   nNumberOfCharsToRead,
    LPDWORD lpNumberOfCharsRead,
    LPVOID  pInputControl)
{
    (void)pInputControl;

    int fd = handle_get_fd(hConsoleInput);
    if (fd < 0) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    ssize_t n = read(fd, lpBuffer, nNumberOfCharsToRead);
    if (n < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    if (lpNumberOfCharsRead)
        *lpNumberOfCharsRead = (DWORD)n;

    return TRUE;
}

WINAPI_EXPORT BOOL AllocConsole(void)
{
    /* On Linux we always have a console via the terminal */
    return TRUE;
}

WINAPI_EXPORT BOOL FreeConsole(void)
{
    return TRUE;
}

WINAPI_EXPORT BOOL SetConsoleMode(HANDLE hConsoleHandle, DWORD dwMode)
{
    (void)hConsoleHandle;
    (void)dwMode;
    /* Stub - terminal mode settings would go here */
    return TRUE;
}

WINAPI_EXPORT BOOL GetConsoleMode(HANDLE hConsoleHandle, LPDWORD lpMode)
{
    (void)hConsoleHandle;
    if (lpMode)
        *lpMode = ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT;
    return TRUE;
}

WINAPI_EXPORT UINT GetConsoleOutputCP(void)
{
    return 65001; /* UTF-8 */
}

WINAPI_EXPORT BOOL SetConsoleOutputCP(UINT wCodePageID)
{
    (void)wCodePageID;
    return TRUE;
}

WINAPI_EXPORT UINT GetConsoleCP(void)
{
    return 65001;
}

WINAPI_EXPORT BOOL SetConsoleCP(UINT wCodePageID)
{
    (void)wCodePageID;
    return TRUE;
}

WINAPI_EXPORT BOOL SetConsoleTitleA(LPCSTR lpConsoleTitle)
{
    /* Set terminal title using ANSI escape sequence */
    if (lpConsoleTitle)
        fprintf(stderr, "\033]0;%s\007", lpConsoleTitle);
    return TRUE;
}

WINAPI_EXPORT BOOL SetConsoleTitleW(const uint16_t *lpConsoleTitle)
{
    if (!lpConsoleTitle) return FALSE;
    char buf[512] = {0};
    for (int i = 0; lpConsoleTitle[i] && i < 511; i++)
        buf[i] = (char)lpConsoleTitle[i];
    return SetConsoleTitleA(buf);
}

WINAPI_EXPORT HWND GetConsoleWindow(void)
{
    /* No real console window in PE loader — return NULL */
    return NULL;
}

WINAPI_EXPORT BOOL AttachConsole(DWORD dwProcessId)
{
    (void)dwProcessId;
    /* We always have stdin/stdout/stderr — pretend success */
    return TRUE;
}

WINAPI_EXPORT BOOL SetStdHandle(DWORD nStdHandle, HANDLE hHandle)
{
    (void)nStdHandle; (void)hHandle;
    return TRUE;
}

WINAPI_EXPORT BOOL GetConsoleScreenBufferInfo(HANDLE hConsoleOutput,
    void *lpConsoleScreenBufferInfo)
{
    (void)hConsoleOutput;
    /* CONSOLE_SCREEN_BUFFER_INFO: size(COORD), cursorPos(COORD), attr(WORD),
     * window(SMALL_RECT), maxWinSize(COORD). All 20 bytes. */
    if (lpConsoleScreenBufferInfo) {
        uint8_t *b = (uint8_t*)lpConsoleScreenBufferInfo;
        memset(b, 0, 22);
        *(uint16_t*)(b+0) = 80;  /* dwSize.X */
        *(uint16_t*)(b+2) = 25;  /* dwSize.Y */
        *(uint16_t*)(b+8) = 7;   /* wAttributes: grey on black */
        *(uint16_t*)(b+18)= 80;  /* dwMaximumWindowSize.X */
        *(uint16_t*)(b+20)= 25;  /* dwMaximumWindowSize.Y */
    }
    return TRUE;
}

WINAPI_EXPORT BOOL SetConsoleTextAttribute(HANDLE hConsoleOutput, uint16_t wAttributes)
{
    (void)hConsoleOutput;
    /* Map Windows console colors to ANSI escape codes */
    int fg = wAttributes & 0xF;
    static const int ansi_fg[] = {30,34,32,36,31,35,33,37,90,94,92,96,91,95,93,97};
    fprintf(stderr, "\033[%dm", ansi_fg[fg & 0xF]);
    return TRUE;
}

WINAPI_EXPORT BOOL SetConsoleCursorPosition(HANDLE hConsoleOutput, uint32_t dwCursorPosition)
{
    (void)hConsoleOutput;
    int x = (int)(dwCursorPosition & 0xFFFF);
    int y = (int)((dwCursorPosition >> 16) & 0xFFFF);
    fprintf(stderr, "\033[%d;%dH", y+1, x+1);
    return TRUE;
}

WINAPI_EXPORT BOOL FlushConsoleInputBuffer(HANDLE hConsoleInput)
{
    (void)hConsoleInput;
    return TRUE;
}

WINAPI_EXPORT BOOL GetNumberOfConsoleInputEvents(HANDLE hConsoleInput, LPDWORD lpcNumberOfEvents)
{
    (void)hConsoleInput;
    if (lpcNumberOfEvents) *lpcNumberOfEvents = 0;
    return TRUE;
}

WINAPI_EXPORT BOOL ReadConsoleInputA(HANDLE hConsoleInput, void *lpBuffer,
    DWORD nLength, LPDWORD lpNumberOfEventsRead)
{
    (void)hConsoleInput; (void)lpBuffer; (void)nLength;
    if (lpNumberOfEventsRead) *lpNumberOfEventsRead = 0;
    return TRUE;
}

WINAPI_EXPORT BOOL PeekConsoleInputA(HANDLE hConsoleInput, void *lpBuffer,
    DWORD nLength, LPDWORD lpNumberOfEventsRead)
{
    (void)hConsoleInput; (void)lpBuffer; (void)nLength;
    if (lpNumberOfEventsRead) *lpNumberOfEventsRead = 0;
    return TRUE;
}

WINAPI_EXPORT HANDLE CreateConsoleScreenBuffer(DWORD dwDesiredAccess, DWORD dwShareMode,
    const void *lpSecurityAttributes, DWORD dwFlags, LPVOID lpScreenBufferData)
{
    (void)dwDesiredAccess; (void)dwShareMode; (void)lpSecurityAttributes;
    (void)dwFlags; (void)lpScreenBufferData;
    return (HANDLE)(uintptr_t)2; /* stdout */
}

WINAPI_EXPORT BOOL SetConsoleActiveScreenBuffer(HANDLE hConsoleOutput)
{
    (void)hConsoleOutput;
    return TRUE;
}

WINAPI_EXPORT BOOL FillConsoleOutputCharacterA(HANDLE hConsoleOutput, char cCharacter,
    DWORD nLength, uint32_t dwWriteCoord, LPDWORD lpNumberOfCharsWritten)
{
    (void)hConsoleOutput; (void)cCharacter; (void)nLength; (void)dwWriteCoord;
    if (lpNumberOfCharsWritten) *lpNumberOfCharsWritten = nLength;
    return TRUE;
}

WINAPI_EXPORT BOOL FillConsoleOutputAttribute(HANDLE hConsoleOutput, uint16_t wAttribute,
    DWORD nLength, uint32_t dwWriteCoord, LPDWORD lpNumberOfAttrsWritten)
{
    (void)hConsoleOutput; (void)wAttribute; (void)nLength; (void)dwWriteCoord;
    if (lpNumberOfAttrsWritten) *lpNumberOfAttrsWritten = nLength;
    return TRUE;
}
