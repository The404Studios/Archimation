/*
 * kernel32_find.c - FindFirstFileA/FindNextFileA/FindClose
 *
 * Backed by opendir/readdir/closedir + fnmatch for wildcard matching.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fnmatch.h>
#include <limits.h>
#include <wchar.h>
#include <time.h>

#include "common/dll_common.h"

/* WIN32_FIND_DATAA structure */
typedef struct {
    DWORD    dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD    nFileSizeHigh;
    DWORD    nFileSizeLow;
    DWORD    dwReserved0;
    DWORD    dwReserved1;
    CHAR     cFileName[MAX_PATH];
    CHAR     cAlternateFileName[14];
} WIN32_FIND_DATAA;

/* Find handle data */
typedef struct {
    DIR  *dir;
    char  dir_path[4096];
    char  pattern[256];
} find_data_t;

/* Convert Unix timespec to Windows FILETIME (100-ns intervals since 1601-01-01) */
static FILETIME unix_to_filetime(time_t t)
{
    FILETIME ft;
    /* Windows epoch is 11644473600 seconds before Unix epoch */
    uint64_t ticks = ((uint64_t)t + 11644473600ULL) * 10000000ULL;
    ft.dwLowDateTime = (DWORD)(ticks & 0xFFFFFFFF);
    ft.dwHighDateTime = (DWORD)(ticks >> 32);
    return ft;
}

/* Split a path like "C:\foo\*.txt" into directory ("C:\foo") and pattern ("*.txt") */
static void split_path_pattern(const char *path, char *dir_out, size_t dir_sz,
                               char *pattern_out, size_t pat_sz)
{
    char linux_path[4096];
    win_path_to_linux(path, linux_path, sizeof(linux_path));

    /* Find last separator */
    const char *last_sep = strrchr(linux_path, '/');
    if (last_sep) {
        size_t dir_len = (size_t)(last_sep - linux_path);
        if (dir_len >= dir_sz) dir_len = dir_sz - 1;
        memcpy(dir_out, linux_path, dir_len);
        dir_out[dir_len] = '\0';
        strncpy(pattern_out, last_sep + 1, pat_sz - 1);
        pattern_out[pat_sz - 1] = '\0';
    } else {
        strncpy(dir_out, ".", dir_sz - 1);
        dir_out[dir_sz - 1] = '\0';
        strncpy(pattern_out, linux_path, pat_sz - 1);
        pattern_out[pat_sz - 1] = '\0';
    }

    /* If pattern is empty, match everything */
    if (pattern_out[0] == '\0')
        strncpy(pattern_out, "*", pat_sz - 1);
}

static void fill_find_data(WIN32_FIND_DATAA *fd, const char *dir_path,
                           const char *filename)
{
    memset(fd, 0, sizeof(*fd));
    strncpy(fd->cFileName, filename, MAX_PATH - 1);

    char full_path[4096];
    snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, filename);

    struct stat st;
    if (stat(full_path, &st) == 0) {
        fd->nFileSizeLow = (DWORD)(st.st_size & 0xFFFFFFFF);
        fd->nFileSizeHigh = (DWORD)(st.st_size >> 32);
        fd->ftCreationTime = unix_to_filetime(st.st_ctime);
        fd->ftLastAccessTime = unix_to_filetime(st.st_atime);
        fd->ftLastWriteTime = unix_to_filetime(st.st_mtime);

        DWORD attrs = 0;
        if (S_ISDIR(st.st_mode))
            attrs |= FILE_ATTRIBUTE_DIRECTORY;
        if (!(st.st_mode & S_IWUSR))
            attrs |= FILE_ATTRIBUTE_READONLY;
        /* Linux dotfiles map to Windows hidden files */
        if (filename[0] == '.')
            attrs |= FILE_ATTRIBUTE_HIDDEN;
        /* Regular files get ARCHIVE (most Windows files have it) */
        if (S_ISREG(st.st_mode))
            attrs |= FILE_ATTRIBUTE_ARCHIVE;
        /* NORMAL is only valid when no other attributes are set */
        if (attrs == 0)
            attrs = FILE_ATTRIBUTE_NORMAL;
        fd->dwFileAttributes = attrs;
    } else {
        fd->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
    }
}

WINAPI_EXPORT HANDLE FindFirstFileA(LPCSTR lpFileName, WIN32_FIND_DATAA *lpFindFileData)
{
    if (!lpFileName || !lpFindFileData) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    find_data_t *fdata = calloc(1, sizeof(find_data_t));
    if (!fdata) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return INVALID_HANDLE_VALUE;
    }

    split_path_pattern(lpFileName, fdata->dir_path, sizeof(fdata->dir_path),
                       fdata->pattern, sizeof(fdata->pattern));

    fdata->dir = opendir(fdata->dir_path);
    if (!fdata->dir) {
        free(fdata);
        set_last_error(ERROR_PATH_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }

    /* Find the first matching entry */
    struct dirent *ent;
    while ((ent = readdir(fdata->dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        if (fnmatch(fdata->pattern, ent->d_name, FNM_CASEFOLD) == 0) {
            fill_find_data(lpFindFileData, fdata->dir_path, ent->d_name);
            return handle_alloc(HANDLE_TYPE_FIND, -1, fdata);
        }
    }

    /* No match found */
    closedir(fdata->dir);
    free(fdata);
    set_last_error(ERROR_FILE_NOT_FOUND);
    return INVALID_HANDLE_VALUE;
}

WINAPI_EXPORT BOOL FindNextFileA(HANDLE hFindFile, WIN32_FIND_DATAA *lpFindFileData)
{
    handle_entry_t *entry = handle_lookup(hFindFile);
    if (!entry || entry->type != HANDLE_TYPE_FIND || !lpFindFileData) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    find_data_t *fdata = (find_data_t *)entry->data;
    if (!fdata || !fdata->dir) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    struct dirent *ent;
    while ((ent = readdir(fdata->dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        if (fnmatch(fdata->pattern, ent->d_name, FNM_CASEFOLD) == 0) {
            fill_find_data(lpFindFileData, fdata->dir_path, ent->d_name);
            return TRUE;
        }
    }

    set_last_error(ERROR_NO_MORE_FILES);
    return FALSE;
}

WINAPI_EXPORT BOOL FindClose(HANDLE hFindFile)
{
    handle_entry_t *entry = handle_lookup(hFindFile);
    if (!entry || entry->type != HANDLE_TYPE_FIND) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    find_data_t *fdata = (find_data_t *)entry->data;
    if (fdata && fdata->dir) {
        closedir(fdata->dir);
        fdata->dir = NULL;
    }

    /* handle_close will free fdata */
    handle_close(hFindFile);
    return TRUE;
}

/* ---------- Wide-char wrappers ---------- */

/*
 * WIN32_FIND_DATAW layout (592 bytes total):
 *   0..43:  Non-string fields (same as A: attributes, times, sizes, reserved)
 *   44..563: WCHAR cFileName[MAX_PATH]       = 260 * 2 = 520 bytes
 *   564..591: WCHAR cAlternateFileName[14]   = 14  * 2 =  28 bytes
 *
 * The A struct has cFileName at offset 44 too, but only 260 bytes (char),
 * followed by 14 bytes for cAlternateFileName.  We must NOT use A-struct
 * offsets when writing into the W struct's string fields.
 */
#define FIND_DATA_STRINGS_OFFSET 44              /* shared: first string field */
#define FIND_DATAW_FILENAME_SIZE (MAX_PATH * 2)  /* 520 bytes */
#define FIND_DATAW_ALTNAME_OFFSET (FIND_DATA_STRINGS_OFFSET + FIND_DATAW_FILENAME_SIZE)
#define FIND_DATAW_ALTNAME_SIZE  (14 * 2)        /* 28 bytes */
#define FIND_DATAW_TOTAL_SIZE    (FIND_DATAW_ALTNAME_OFFSET + FIND_DATAW_ALTNAME_SIZE) /* 592 */

/* Helper: convert wide string (UTF-16LE) to narrow (UTF-8) */
static void wide_to_narrow(LPCWSTR src, char *dst, size_t dst_size)
{
    if (!src || !dst || dst_size == 0) return;
    int written = utf16_to_utf8(src, -1, dst, (int)dst_size);
    if (written <= 0) dst[0] = '\0';
    dst[dst_size - 1] = '\0'; /* Ensure null-termination */
}

/* Helper: fill the W struct from a narrow WIN32_FIND_DATAA result */
static void find_data_a_to_w(const WIN32_FIND_DATAA *narrow, void *wide_out)
{
    /* Zero the entire W struct first (592 bytes) */
    memset(wide_out, 0, FIND_DATAW_TOTAL_SIZE);

    /* Copy the non-string prefix (44 bytes: attributes, times, sizes, reserved) */
    memcpy(wide_out, narrow, FIND_DATA_STRINGS_OFFSET);

    /* Convert cFileName (narrow) to wide at proper W offset */
    uint16_t *wide_name = (uint16_t *)((char *)wide_out + FIND_DATA_STRINGS_OFFSET);
    int i;
    for (i = 0; narrow->cFileName[i] && i < MAX_PATH - 1; i++)
        wide_name[i] = (uint16_t)(unsigned char)narrow->cFileName[i];
    wide_name[i] = 0;

    /* Convert cAlternateFileName (narrow) to wide at proper W offset */
    uint16_t *wide_alt = (uint16_t *)((char *)wide_out + FIND_DATAW_ALTNAME_OFFSET);
    for (i = 0; narrow->cAlternateFileName[i] && i < 13; i++)
        wide_alt[i] = (uint16_t)(unsigned char)narrow->cAlternateFileName[i];
    wide_alt[i] = 0;
}

WINAPI_EXPORT BOOL FindNextFileW(HANDLE hFindFile, void *lpFindFileData)
{
    WIN32_FIND_DATAA narrow_data;
    BOOL result = FindNextFileA(hFindFile, &narrow_data);
    if (!result) return FALSE;

    find_data_a_to_w(&narrow_data, lpFindFileData);
    return TRUE;
}

WINAPI_EXPORT HANDLE FindFirstFileW(LPCWSTR lpFileName, void *lpFindFileData)
{
    if (!lpFileName || !lpFindFileData) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    char narrow_path[4096];
    wide_to_narrow(lpFileName, narrow_path, sizeof(narrow_path));

    WIN32_FIND_DATAA narrow_data;
    HANDLE h = FindFirstFileA(narrow_path, &narrow_data);
    if (h == INVALID_HANDLE_VALUE) return h;

    find_data_a_to_w(&narrow_data, lpFindFileData);
    return h;
}

WINAPI_EXPORT HANDLE FindFirstFileExW(
    LPCWSTR lpFileName, int fInfoLevelId, void *lpFindFileData,
    int fSearchOp, void *lpSearchFilter, DWORD dwAdditionalFlags)
{
    (void)fInfoLevelId; (void)fSearchOp; (void)lpSearchFilter; (void)dwAdditionalFlags;
    return FindFirstFileW(lpFileName, lpFindFileData);
}

/* ---------- GetFullPathNameW ---------- */

WINAPI_EXPORT DWORD GetFullPathNameW(
    LPCWSTR lpFileName,
    DWORD nBufferLength,
    LPWSTR lpBuffer,
    LPWSTR *lpFilePart)
{
    if (!lpFileName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    /* Convert wide path to narrow */
    char narrow_path[4096];
    wide_to_narrow(lpFileName, narrow_path, sizeof(narrow_path));

    /* Translate Windows path to Linux */
    char linux_path[4096];
    win_path_to_linux(narrow_path, linux_path, sizeof(linux_path));

    /* Resolve to absolute path */
    char resolved[PATH_MAX];
    if (!realpath(linux_path, resolved)) {
        /* realpath failed - just use the input path as-is */
        strncpy(resolved, linux_path, sizeof(resolved) - 1);
        resolved[sizeof(resolved) - 1] = '\0';
    }

    /* Convert result back to wide */
    int len = (int)strlen(resolved);
    if (nBufferLength == 0)
        return (DWORD)(len + 1); /* Return required size */

    int copy = len < (int)(nBufferLength - 1) ? len : (int)(nBufferLength - 1);
    for (int i = 0; i < copy; i++)
        lpBuffer[i] = (WCHAR)(unsigned char)resolved[i];
    lpBuffer[copy] = 0;

    /* Set file part to last component */
    if (lpFilePart) {
        *lpFilePart = NULL;
        for (int i = copy - 1; i >= 0; i--) {
            if (lpBuffer[i] == '/' || lpBuffer[i] == '\\') {
                *lpFilePart = &lpBuffer[i + 1];
                break;
            }
        }
    }

    return (DWORD)copy;
}

/* ---------- GetDiskFreeSpaceExW ---------- */

WINAPI_EXPORT BOOL GetDiskFreeSpaceExW(
    LPCWSTR lpDirectoryName,
    ULARGE_INTEGER *lpFreeBytesAvailableToCaller,
    ULARGE_INTEGER *lpTotalNumberOfBytes,
    ULARGE_INTEGER *lpTotalNumberOfFreeBytes)
{
    char narrow_dir[4096];
    char linux_dir[4096];
    const char *dir_path = "/";

    if (lpDirectoryName) {
        wide_to_narrow(lpDirectoryName, narrow_dir, sizeof(narrow_dir));
        win_path_to_linux(narrow_dir, linux_dir, sizeof(linux_dir));
        dir_path = linux_dir;
    }

    struct statvfs svfs;
    if (statvfs(dir_path, &svfs) != 0) {
        set_last_error(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }

    uint64_t block_size = svfs.f_frsize ? svfs.f_frsize : svfs.f_bsize;
    uint64_t total_bytes = block_size * svfs.f_blocks;
    uint64_t free_bytes  = block_size * svfs.f_bfree;
    uint64_t avail_bytes = block_size * svfs.f_bavail;

    if (lpFreeBytesAvailableToCaller) lpFreeBytesAvailableToCaller->QuadPart = avail_bytes;
    if (lpTotalNumberOfBytes)         lpTotalNumberOfBytes->QuadPart = total_bytes;
    if (lpTotalNumberOfFreeBytes)     lpTotalNumberOfFreeBytes->QuadPart = free_bytes;

    return TRUE;
}
