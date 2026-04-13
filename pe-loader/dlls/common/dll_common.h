#ifndef DLL_COMMON_H
#define DLL_COMMON_H

#include "win32/windef.h"
#include "win32/winnt.h"

/*
 * WINAPI_EXPORT: Mark functions exported by our stub DLLs.
 *
 * We use __attribute__((ms_abi)) so GCC/Clang generate Windows x64
 * calling convention code. This way PE code can call our stubs
 * directly without runtime thunking.
 *
 * We also use __attribute__((visibility("default"))) so the symbols
 * are visible to dlsym.
 */
#define WINAPI_EXPORT __attribute__((ms_abi, visibility("default")))

/*
 * Handle table - maps Windows HANDLE values to Linux objects
 */
typedef enum {
    HANDLE_TYPE_INVALID = 0,
    HANDLE_TYPE_FILE,
    HANDLE_TYPE_THREAD,
    HANDLE_TYPE_PROCESS,
    HANDLE_TYPE_EVENT,
    HANDLE_TYPE_MUTEX,
    HANDLE_TYPE_SEMAPHORE,
    HANDLE_TYPE_PIPE,
    HANDLE_TYPE_SOCKET,
    HANDLE_TYPE_REGISTRY_KEY,
    HANDLE_TYPE_TIMER,
    HANDLE_TYPE_HEAP,
    HANDLE_TYPE_CONSOLE,
    HANDLE_TYPE_SERVICE,
    HANDLE_TYPE_FIND,
    HANDLE_TYPE_FILE_MAPPING,
} handle_type_t;

/* Per-handle flags (stored in handle_entry_t.flags) */
#define HANDLE_FLAG_OVERLAPPED  0x01  /* Opened with FILE_FLAG_OVERLAPPED */

typedef struct {
    handle_type_t type;
    int           fd;           /* File descriptor (for files, pipes, sockets) */
    void         *data;         /* Type-specific data */
    int           ref_count;
    unsigned int  flags;        /* HANDLE_FLAG_* bitmask */
} handle_entry_t;

#define MAX_HANDLES 16384

/* Initialize the handle table */
void handle_table_init(void);

/* Allocate a new HANDLE wrapping a file descriptor */
HANDLE handle_alloc(handle_type_t type, int fd, void *data);

/* Allocate a new HANDLE with flags */
HANDLE handle_alloc_flags(handle_type_t type, int fd, void *data, unsigned int flags);

/* Look up the entry for a HANDLE.
 * WARNING: returns a pointer into the global handle table -- the entry
 * may be invalidated by a concurrent handle_close().  Prefer
 * handle_get_data() when only the data pointer is needed. */
handle_entry_t *handle_lookup(HANDLE h);

/* Safely extract the data pointer for a HANDLE under the read lock.
 * Returns NULL if the handle is invalid. */
void *handle_get_data(HANDLE h);

/* Close a HANDLE and free its entry */
int handle_close(HANDLE h);

/* Get the fd associated with a HANDLE */
int handle_get_fd(HANDLE h);

/* Check if a HANDLE was opened with FILE_FLAG_OVERLAPPED */
int handle_is_overlapped(HANDLE h);

/*
 * Per-thread error code (Windows GetLastError/SetLastError)
 */
void set_last_error(DWORD error);
DWORD get_last_error(void);

/*
 * Error code translation
 */
DWORD errno_to_win32_error(int err);
int   win32_error_to_errno(DWORD err);

/*
 * Path translation: Windows paths to Linux paths
 */
int win_path_to_linux(const char *win_path, char *linux_path, size_t size);

/* Get the PE compat home directory (~/.pe-compat/) */
const char *get_pe_compat_prefix(void);

/* Case-insensitive path resolution (casefold.c) */
int casefold_resolve(const char *path, char *resolved, size_t size);
void casefold_cache_flush(void);

/* UTF-16LE <-> UTF-8 conversion (wchar_util.c) */
int utf16_to_utf8(const WCHAR *src, int src_len, char *dst, int dst_size);
int utf8_to_utf16(const char *src, int src_len, WCHAR *dst, int dst_size);

/* Handle types for new subsystems */
#define HANDLE_TYPE_WINHTTP_SESSION  20
#define HANDLE_TYPE_WINHTTP_CONNECTION 21
#define HANDLE_TYPE_WINHTTP_REQUEST  22
#define HANDLE_TYPE_INOTIFY          23
#define HANDLE_TYPE_ASYNC_IO         24
#define HANDLE_TYPE_IOCP             25

/*
 * Standard handle management
 */
HANDLE get_std_handle(DWORD std_handle_id);

/*
 * Wide-to-narrow string conversion with narrow-string detection.
 *
 * Many Win32 W-suffix functions receive narrow (ASCII) strings cast to
 * LPCWSTR when apps mix A/W calls or use GetProcAddress. This helper
 * detects that case and copies the narrow string directly.
 *
 * Properly converts UTF-16LE to UTF-8, handling BMP and surrogate pairs.
 *
 * Returns the length of the resulting narrow string (excluding null).
 */
static inline int wide_to_narrow_safe(const uint16_t *wide, char *narrow, int max_len)
{
    if (!wide) { narrow[0] = '\0'; return 0; }

    /* Detect narrow string passed as wide: if second byte is non-zero,
     * the input is really an ASCII string (valid UTF-16LE ASCII has 0x00
     * as the high byte of each code unit) */
    const unsigned char *raw = (const unsigned char *)wide;
    if (raw[0] && raw[1] != 0x00) {
        /* It's a narrow string -- copy directly */
        int i = 0;
        while (raw[i] && i < max_len - 1) {
            narrow[i] = (char)raw[i];
            i++;
        }
        narrow[i] = '\0';
        return i;
    }

    /* Real UTF-16LE -> UTF-8 conversion */
    int len = utf16_to_utf8((const WCHAR *)wide, -1, narrow, max_len);
    /* utf16_to_utf8 returns bytes written including null terminator;
     * we return the length excluding null */
    if (len > 0) len--;
    /* Ensure null-termination even if buffer was too small */
    if (max_len > 0) narrow[max_len - 1] = '\0';
    return len > 0 ? len : 0;
}

#endif /* DLL_COMMON_H */
