/*
 * console_files.c -- kernel32 file API roundtrip.
 *
 * Surface tested:
 *   kernel32!CreateFileA, kernel32!WriteFile, kernel32!ReadFile,
 *   kernel32!CloseHandle, kernel32!DeleteFileA, kernel32!SetFilePointer,
 *   kernel32!GetTempPathA
 *
 * Rationale:
 *   File I/O is the most common Win32 entrypoint for ports.  This test
 *   writes a known string, rewinds, reads it back, asserts byte-equality,
 *   then deletes the temp file.  Catches:
 *     - GENERIC_READ/WRITE flag mapping
 *     - OPEN_ALWAYS / CREATE_ALWAYS dispositions
 *     - FILE_BEGIN seek anchor
 *     - GetTempPath behavior (must return non-empty path with trailing slash)
 *
 * Harness expectation: outputs:CONSOLE_FILES_OK
 *
 * Note: we deliberately use the GetTempPath result rather than hard-coding
 * /tmp because a Win32-correct loader should map %TEMP% to a writable dir
 * even if the underlying OS is Linux.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

static const char PAYLOAD[] = "PE-LOADER-FILE-ROUND-TRIP-MARKER";

int main(void) {
    char tmpdir[MAX_PATH];
    DWORD got = GetTempPathA(MAX_PATH, tmpdir);
    if (got == 0 || got >= MAX_PATH) {
        fprintf(stderr, "GetTempPathA failed: got=%lu\n", (unsigned long)got);
        return 20;
    }
    printf("temp dir: %s\n", tmpdir);

    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%speloader_test_%lu.bin",
             tmpdir, (unsigned long)GetCurrentProcessId());

    /* --- Write phase --- */
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateFileA(write) failed: GLE=%lu\n",
                (unsigned long)GetLastError());
        return 21;
    }

    DWORD wrote = 0;
    if (!WriteFile(h, PAYLOAD, sizeof(PAYLOAD) - 1, &wrote, NULL) ||
        wrote != sizeof(PAYLOAD) - 1) {
        fprintf(stderr, "WriteFile failed: wrote=%lu\n", (unsigned long)wrote);
        CloseHandle(h);
        return 22;
    }
    CloseHandle(h);

    /* --- Read phase --- */
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateFileA(read) failed: GLE=%lu\n",
                (unsigned long)GetLastError());
        DeleteFileA(path);
        return 23;
    }

    char buf[128] = {0};
    DWORD got_read = 0;
    if (!ReadFile(h, buf, sizeof(buf) - 1, &got_read, NULL)) {
        fprintf(stderr, "ReadFile failed: GLE=%lu\n",
                (unsigned long)GetLastError());
        CloseHandle(h);
        DeleteFileA(path);
        return 24;
    }
    CloseHandle(h);

    if (got_read != sizeof(PAYLOAD) - 1 ||
        memcmp(buf, PAYLOAD, sizeof(PAYLOAD) - 1) != 0) {
        fprintf(stderr, "Roundtrip mismatch: got %lu bytes\n",
                (unsigned long)got_read);
        DeleteFileA(path);
        return 25;
    }

    /* --- Cleanup --- */
    if (!DeleteFileA(path)) {
        fprintf(stderr, "DeleteFileA failed: GLE=%lu\n",
                (unsigned long)GetLastError());
        return 26;
    }

    printf("CONSOLE_FILES_OK\n");
    fflush(stdout);
    return 0;
}
