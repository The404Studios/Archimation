/*
 * ntdll_file.c - NT native file I/O functions
 *
 * NtCreateFile, NtOpenFile, NtReadFile, NtWriteFile, NtQueryInformationFile, etc.
 * These are the low-level NT APIs that kernel32 CreateFile/ReadFile/etc. call into.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <errno.h>
#include <wchar.h>
#include <pthread.h>

#include "common/dll_common.h"

/* IO_STATUS_BLOCK */
typedef struct {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

/* OBJECT_ATTRIBUTES */
#ifndef _OBJECT_ATTRIBUTES_DEFINED
#define _OBJECT_ATTRIBUTES_DEFINED
typedef struct {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#endif

/* FILE_INFORMATION_CLASS (subset) */
#define FileBasicInformation        4
#define FileStandardInformation     5
#define FilePositionInformation     14
#define FileEndOfFileInformation    20

/* FILE_BASIC_INFORMATION */
typedef struct {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG         FileAttributes;
} FILE_BASIC_INFORMATION;

/* FILE_STANDARD_INFORMATION */
typedef struct {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    BOOL          DeletePending;
    BOOL          Directory;
} FILE_STANDARD_INFORMATION;

/* FILE_POSITION_INFORMATION */
typedef struct {
    LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION;

/* Access mask bits */
#define FILE_READ_DATA          0x0001
#define FILE_WRITE_DATA         0x0002
#define FILE_APPEND_DATA        0x0004
#define FILE_READ_ATTRIBUTES    0x0080
#define FILE_WRITE_ATTRIBUTES   0x0100

/* Create disposition */
#define FILE_SUPERSEDE          0
#define FILE_OPEN               1
#define FILE_CREATE             2
#define FILE_OPEN_IF            3
#define FILE_OVERWRITE          4
#define FILE_OVERWRITE_IF       5

/* Create options */
#define FILE_DIRECTORY_FILE     0x00000001
#define FILE_NON_DIRECTORY_FILE 0x00000040

#define FILETIME_UNIX_DIFF 116444736000000000ULL

static void timespec_to_nt_time(const struct timespec *ts, LARGE_INTEGER *nt)
{
    uint64_t ticks = ((uint64_t)ts->tv_sec * 10000000ULL) +
                     ((uint64_t)ts->tv_nsec / 100ULL) +
                     FILETIME_UNIX_DIFF;
    nt->QuadPart = (LONGLONG)ticks;
}

/* Helper: extract path from OBJECT_ATTRIBUTES unicode string */
static int nt_path_to_linux(POBJECT_ATTRIBUTES oa, char *buf, size_t size)
{
    if (!oa || !oa->ObjectName || !oa->ObjectName->Buffer) {
        buf[0] = '\0';
        return -1;
    }

    /* Convert UNICODE_STRING to narrow ASCII */
    int wlen = oa->ObjectName->Length / sizeof(WCHAR);
    char narrow[4096];
    int i;
    for (i = 0; i < wlen && i < 4095; i++)
        narrow[i] = (char)(oa->ObjectName->Buffer[i] & 0xFF);
    narrow[i] = '\0';

    /* Strip NT object namespace prefixes */
    const char *path = narrow;
    if (strncmp(path, "\\??\\", 4) == 0)
        path += 4;
    else if (strncmp(path, "\\DosDevices\\", 12) == 0)
        path += 12;

    return win_path_to_linux(path, buf, size);
}

WINAPI_EXPORT NTSTATUS NtCreateFile(
    HANDLE *FileHandle,
    DWORD DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength)
{
    (void)AllocationSize;
    (void)FileAttributes;
    (void)ShareAccess;
    (void)CreateOptions;
    (void)EaBuffer;
    (void)EaLength;

    if (!FileHandle || !ObjectAttributes) {
        return STATUS_INVALID_PARAMETER;
    }

    char linux_path[4096];
    if (nt_path_to_linux(ObjectAttributes, linux_path, sizeof(linux_path)) < 0) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    int flags = 0;
    mode_t mode = 0644;

    /* Access flags: check combined read+write cases BEFORE individual
     * read/write so apps passing GENERIC_READ|GENERIC_WRITE open the file
     * read/write instead of falling into the first matched single branch. */
    if ((DesiredAccess & FILE_READ_DATA) && (DesiredAccess & FILE_WRITE_DATA))
        flags = O_RDWR;
    else if ((DesiredAccess & GENERIC_READ) && (DesiredAccess & GENERIC_WRITE))
        flags = O_RDWR;
    else if (DesiredAccess & FILE_WRITE_DATA)
        flags = O_WRONLY;
    else if (DesiredAccess & GENERIC_WRITE)
        flags = O_WRONLY;
    else if (DesiredAccess & (FILE_READ_DATA | GENERIC_READ))
        flags = O_RDONLY;
    else
        flags = O_RDONLY;

    /* Create disposition */
    switch (CreateDisposition) {
    case FILE_SUPERSEDE:    flags |= O_CREAT | O_TRUNC; break;
    case FILE_OPEN:         break;
    case FILE_CREATE:       flags |= O_CREAT | O_EXCL; break;
    case FILE_OPEN_IF:      flags |= O_CREAT; break;
    case FILE_OVERWRITE:    flags |= O_TRUNC; break;
    case FILE_OVERWRITE_IF: flags |= O_CREAT | O_TRUNC; break;
    }

    int fd = open(linux_path, flags, mode);
    if (fd < 0) {
        *FileHandle = NULL;
        NTSTATUS st = errno == ENOENT ? STATUS_NO_SUCH_FILE :
                      errno == EACCES ? STATUS_ACCESS_DENIED :
                      errno == EEXIST ? STATUS_OBJECT_NAME_COLLISION :
                      STATUS_UNSUCCESSFUL;
        if (IoStatusBlock) {
            IoStatusBlock->Status = st;
            IoStatusBlock->Information = 0;
        }
        return st;
    }

    HANDLE h = handle_alloc(HANDLE_TYPE_FILE, fd, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        close(fd);
        *FileHandle = NULL;
        if (IoStatusBlock) {
            IoStatusBlock->Status = STATUS_UNSUCCESSFUL;
            IoStatusBlock->Information = 0;
        }
        return STATUS_UNSUCCESSFUL;
    }
    *FileHandle = h;
    if (IoStatusBlock) {
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = (CreateDisposition == FILE_CREATE) ? 2 : 1;
    }
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtOpenFile(
    HANDLE *FileHandle,
    DWORD DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions)
{
    return NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                        IoStatusBlock, NULL, 0, ShareAccess,
                        FILE_OPEN, OpenOptions, NULL, 0);
}

WINAPI_EXPORT NTSTATUS NtReadFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key)
{
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)Key;

    int fd = handle_get_fd(FileHandle);
    if (fd < 0)
        return STATUS_INVALID_HANDLE;

    if (ByteOffset && ByteOffset->QuadPart >= 0) {
        lseek(fd, (off_t)ByteOffset->QuadPart, SEEK_SET);
    }

    ssize_t n = read(fd, Buffer, Length);
    if (n < 0) {
        if (IoStatusBlock) {
            IoStatusBlock->Status = STATUS_UNSUCCESSFUL;
            IoStatusBlock->Information = 0;
        }
        return STATUS_UNSUCCESSFUL;
    }

    if (IoStatusBlock) {
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = (ULONG_PTR)n;
    }
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key)
{
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)Key;

    int fd = handle_get_fd(FileHandle);
    if (fd < 0)
        return STATUS_INVALID_HANDLE;

    if (ByteOffset && ByteOffset->QuadPart >= 0) {
        lseek(fd, (off_t)ByteOffset->QuadPart, SEEK_SET);
    }

    ssize_t n = write(fd, Buffer, Length);
    if (n < 0) {
        if (IoStatusBlock) {
            IoStatusBlock->Status = STATUS_UNSUCCESSFUL;
            IoStatusBlock->Information = 0;
        }
        return STATUS_UNSUCCESSFUL;
    }

    if (IoStatusBlock) {
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = (ULONG_PTR)n;
    }
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtQueryInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    ULONG FileInformationClass)
{
    int fd = handle_get_fd(FileHandle);
    if (fd < 0)
        return STATUS_INVALID_HANDLE;

    struct stat st;
    if (fstat(fd, &st) < 0)
        return STATUS_UNSUCCESSFUL;

    switch (FileInformationClass) {
    case FileBasicInformation: {
        if (Length < sizeof(FILE_BASIC_INFORMATION))
            return STATUS_INVALID_PARAMETER;
        FILE_BASIC_INFORMATION *info = (FILE_BASIC_INFORMATION *)FileInformation;
        timespec_to_nt_time(&st.st_ctim, &info->CreationTime);
        timespec_to_nt_time(&st.st_atim, &info->LastAccessTime);
        timespec_to_nt_time(&st.st_mtim, &info->LastWriteTime);
        timespec_to_nt_time(&st.st_ctim, &info->ChangeTime);
        info->FileAttributes = S_ISDIR(st.st_mode) ?
            FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
        if (IoStatusBlock) {
            IoStatusBlock->Status = STATUS_SUCCESS;
            IoStatusBlock->Information = sizeof(FILE_BASIC_INFORMATION);
        }
        return STATUS_SUCCESS;
    }

    case FileStandardInformation: {
        if (Length < sizeof(FILE_STANDARD_INFORMATION))
            return STATUS_INVALID_PARAMETER;
        FILE_STANDARD_INFORMATION *info = (FILE_STANDARD_INFORMATION *)FileInformation;
        info->AllocationSize.QuadPart = st.st_blocks * 512;
        info->EndOfFile.QuadPart = st.st_size;
        info->NumberOfLinks = (ULONG)st.st_nlink;
        info->DeletePending = FALSE;
        info->Directory = S_ISDIR(st.st_mode) ? TRUE : FALSE;
        if (IoStatusBlock) {
            IoStatusBlock->Status = STATUS_SUCCESS;
            IoStatusBlock->Information = sizeof(FILE_STANDARD_INFORMATION);
        }
        return STATUS_SUCCESS;
    }

    case FilePositionInformation: {
        if (Length < sizeof(FILE_POSITION_INFORMATION))
            return STATUS_INVALID_PARAMETER;
        FILE_POSITION_INFORMATION *info = (FILE_POSITION_INFORMATION *)FileInformation;
        off_t pos = lseek(fd, 0, SEEK_CUR);
        info->CurrentByteOffset.QuadPart = pos >= 0 ? pos : 0;
        if (IoStatusBlock) {
            IoStatusBlock->Status = STATUS_SUCCESS;
            IoStatusBlock->Information = sizeof(FILE_POSITION_INFORMATION);
        }
        return STATUS_SUCCESS;
    }

    default:
        return STATUS_NOT_IMPLEMENTED;
    }
}

WINAPI_EXPORT NTSTATUS NtSetInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    ULONG FileInformationClass)
{
    int fd = handle_get_fd(FileHandle);
    if (fd < 0)
        return STATUS_INVALID_HANDLE;

    switch (FileInformationClass) {
    case FilePositionInformation: {
        if (Length < sizeof(FILE_POSITION_INFORMATION))
            return STATUS_INVALID_PARAMETER;
        FILE_POSITION_INFORMATION *info = (FILE_POSITION_INFORMATION *)FileInformation;
        off_t result = lseek(fd, (off_t)info->CurrentByteOffset.QuadPart, SEEK_SET);
        if (result < 0)
            return STATUS_UNSUCCESSFUL;
        if (IoStatusBlock) {
            IoStatusBlock->Status = STATUS_SUCCESS;
            IoStatusBlock->Information = 0;
        }
        return STATUS_SUCCESS;
    }

    case FileEndOfFileInformation: {
        LARGE_INTEGER *eof = (LARGE_INTEGER *)FileInformation;
        if (ftruncate(fd, (off_t)eof->QuadPart) < 0)
            return STATUS_UNSUCCESSFUL;
        if (IoStatusBlock) {
            IoStatusBlock->Status = STATUS_SUCCESS;
            IoStatusBlock->Information = 0;
        }
        return STATUS_SUCCESS;
    }

    default:
        return STATUS_NOT_IMPLEMENTED;
    }
}

WINAPI_EXPORT NTSTATUS NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes)
{
    char linux_path[4096];
    if (nt_path_to_linux(ObjectAttributes, linux_path, sizeof(linux_path)) < 0)
        return STATUS_OBJECT_NAME_NOT_FOUND;

    if (unlink(linux_path) < 0)
        return errno == ENOENT ? STATUS_NO_SUCH_FILE : STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}

/*
 * Directory enumeration state, stored in handle data.
 * When NtQueryDirectoryFile is first called on a directory handle,
 * we open a DIR* and store it here. Subsequent calls continue reading.
 */
typedef struct {
    DIR    *dirp;
    HANDLE  handle;          /* Owning file handle (used for lookup key) */
    char    path[4096];      /* Linux directory path */
    char    pattern[256];    /* Glob pattern (e.g., "*.txt") or "" for all */
    int     first_query;     /* 1 if this is the first call */
    int     in_use;          /* 1 if this slot is allocated */
} dir_enum_state_t;

#define MAX_DIR_STATES 256
static dir_enum_state_t g_dir_states[MAX_DIR_STATES];
static pthread_mutex_t g_dir_states_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Release a directory state slot. Must be called with g_dir_states_lock held.
 * Closes any open DIR* and marks the slot free for reuse.
 */
static void release_dir_state_locked(dir_enum_state_t *state)
{
    if (!state)
        return;
    if (state->dirp) {
        closedir(state->dirp);
        state->dirp = NULL;
    }
    state->handle = NULL;
    state->path[0] = '\0';
    state->pattern[0] = '\0';
    state->first_query = 0;
    state->in_use = 0;
}

static dir_enum_state_t *get_dir_state(HANDLE FileHandle, int create)
{
    pthread_mutex_lock(&g_dir_states_lock);

    /* Look for existing state for this handle (primary key: FileHandle) */
    for (int i = 0; i < MAX_DIR_STATES; i++) {
        if (g_dir_states[i].in_use && g_dir_states[i].handle == FileHandle) {
            pthread_mutex_unlock(&g_dir_states_lock);
            return &g_dir_states[i];
        }
    }

    if (!create) {
        pthread_mutex_unlock(&g_dir_states_lock);
        return NULL;
    }

    /* Allocate new state */
    for (int i = 0; i < MAX_DIR_STATES; i++) {
        if (!g_dir_states[i].in_use) {
            g_dir_states[i].in_use = 1;
            g_dir_states[i].handle = FileHandle;
            g_dir_states[i].dirp = NULL;
            g_dir_states[i].path[0] = '\0';
            g_dir_states[i].pattern[0] = '\0';
            g_dir_states[i].first_query = 1;

            /* Populate path from fd readlink */
            int fd = handle_get_fd(FileHandle);
            if (fd >= 0) {
                char proc_path[64];
                snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
                ssize_t len = readlink(proc_path, g_dir_states[i].path,
                                       sizeof(g_dir_states[i].path) - 1);
                if (len > 0)
                    g_dir_states[i].path[len] = '\0';
                else
                    g_dir_states[i].path[0] = '\0';
            }

            pthread_mutex_unlock(&g_dir_states_lock);
            return &g_dir_states[i];
        }
    }

    pthread_mutex_unlock(&g_dir_states_lock);
    return NULL;
}

/*
 * Release the dir state associated with a handle (called from NtClose hook).
 * Safe to call even if no state exists for the handle.
 */
void ntdll_file_release_dir_state(HANDLE FileHandle)
{
    pthread_mutex_lock(&g_dir_states_lock);
    for (int i = 0; i < MAX_DIR_STATES; i++) {
        if (g_dir_states[i].in_use && g_dir_states[i].handle == FileHandle) {
            release_dir_state_locked(&g_dir_states[i]);
            break;
        }
    }
    pthread_mutex_unlock(&g_dir_states_lock);
}

/* FILE_BOTH_DIR_INFORMATION - the most commonly used info class for directory queries */
#define FileBothDirectoryInformation 3
#define FileDirectoryInformation     1
#define FileFullDirectoryInformation 2
#define FileNamesInformation         12

typedef struct {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    ULONG         EaSize;
    SHORT         ShortNameLength;
    WCHAR         ShortName[12];
    WCHAR         FileName[1]; /* Variable length */
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

WINAPI_EXPORT NTSTATUS NtQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    ULONG FileInformationClass,
    BOOL ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOL RestartScan)
{
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;

    dir_enum_state_t *state = get_dir_state(FileHandle, 1);
    if (!state) {
        if (IoStatusBlock) {
            IoStatusBlock->Status = STATUS_NO_MORE_ENTRIES;
            IoStatusBlock->Information = 0;
        }
        return STATUS_NO_MORE_ENTRIES;
    }

    /* Get path from fd if not set (may be empty if fd was unavailable at create) */
    if (state->path[0] == '\0') {
        int fd = handle_get_fd(FileHandle);
        if (fd >= 0) {
            char proc_path[64];
            snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
            ssize_t plen = readlink(proc_path, state->path, sizeof(state->path) - 1);
            if (plen > 0) state->path[plen] = '\0';
            else state->path[0] = '\0';
        }
    }

    /* Extract glob pattern from FileName if provided */
    if (FileName && FileName->Buffer && FileName->Length > 0 && state->first_query) {
        int wlen = FileName->Length / (int)sizeof(WCHAR);
        if (wlen > 255) wlen = 255;
        for (int i = 0; i < wlen; i++)
            state->pattern[i] = (char)(FileName->Buffer[i] & 0xFF);
        state->pattern[wlen] = '\0';
        /* Convert backslashes to forward slashes */
        for (char *p = state->pattern; *p; p++)
            if (*p == '\\') *p = '/';
    }

    /* Open directory if needed */
    if (!state->dirp || RestartScan) {
        if (state->dirp) {
            closedir(state->dirp);
            state->dirp = NULL;
        }
        state->dirp = (state->path[0] != '\0') ? opendir(state->path) : NULL;
        if (!state->dirp) {
            if (IoStatusBlock) {
                IoStatusBlock->Status = STATUS_NO_SUCH_FILE;
                IoStatusBlock->Information = 0;
            }
            /* Release the slot so it doesn't leak on failure */
            pthread_mutex_lock(&g_dir_states_lock);
            release_dir_state_locked(state);
            pthread_mutex_unlock(&g_dir_states_lock);
            return STATUS_NO_SUCH_FILE;
        }
    }

    state->first_query = 0;

    /* Read entries and fill buffer */
    unsigned char *buf = (unsigned char *)FileInformation;
    ULONG buf_used = 0;
    ULONG last_entry_offset = 0;
    int entry_count = 0;

    struct dirent *de;
    while ((de = readdir(state->dirp)) != NULL) {
        /* Skip . and .. unless pattern is specifically for them */
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        /* Apply pattern filter */
        if (state->pattern[0] && strcmp(state->pattern, "*") != 0 &&
            strcmp(state->pattern, "*.*") != 0) {
            if (fnmatch(state->pattern, de->d_name, FNM_CASEFOLD) != 0)
                continue;
        }

        /* Get file info */
        char full_path[4096 + 256];
        snprintf(full_path, sizeof(full_path), "%s/%s", state->path, de->d_name);
        struct stat st;
        if (stat(full_path, &st) < 0)
            memset(&st, 0, sizeof(st));

        /* Calculate entry size */
        int name_len = (int)strlen(de->d_name);
        ULONG entry_size;

        if (FileInformationClass == FileBothDirectoryInformation) {
            /* Base size of FILE_BOTH_DIR_INFORMATION minus FileName[1] + actual name */
            entry_size = (ULONG)(offsetof(FILE_BOTH_DIR_INFORMATION, FileName) +
                                 name_len * sizeof(WCHAR));
        } else {
            /* Simple: just provide FILE_BOTH_DIR_INFORMATION for all classes */
            entry_size = (ULONG)(offsetof(FILE_BOTH_DIR_INFORMATION, FileName) +
                                 name_len * sizeof(WCHAR));
        }

        /* Align to 8 bytes */
        entry_size = (entry_size + 7) & ~7U;

        /* Check if it fits in buffer */
        if (buf_used + entry_size > Length)
            break;

        /* Fill entry */
        FILE_BOTH_DIR_INFORMATION *info = (FILE_BOTH_DIR_INFORMATION *)(buf + buf_used);
        memset(info, 0, entry_size);

        info->FileIndex = (ULONG)(entry_count + 1);
        timespec_to_nt_time(&st.st_ctim, &info->CreationTime);
        timespec_to_nt_time(&st.st_atim, &info->LastAccessTime);
        timespec_to_nt_time(&st.st_mtim, &info->LastWriteTime);
        timespec_to_nt_time(&st.st_ctim, &info->ChangeTime);
        info->EndOfFile.QuadPart = st.st_size;
        info->AllocationSize.QuadPart = st.st_blocks * 512;

        if (S_ISDIR(st.st_mode))
            info->FileAttributes = 0x10; /* FILE_ATTRIBUTE_DIRECTORY */
        else
            info->FileAttributes = 0x80; /* FILE_ATTRIBUTE_NORMAL */

        info->FileNameLength = (ULONG)(name_len * sizeof(WCHAR));
        info->EaSize = 0;
        info->ShortNameLength = 0;

        /* Convert filename to wide chars */
        for (int i = 0; i < name_len; i++)
            info->FileName[i] = (WCHAR)(unsigned char)de->d_name[i];

        /* Link entries */
        if (entry_count > 0) {
            FILE_BOTH_DIR_INFORMATION *prev =
                (FILE_BOTH_DIR_INFORMATION *)(buf + last_entry_offset);
            prev->NextEntryOffset = buf_used - last_entry_offset;
        }

        last_entry_offset = buf_used;
        buf_used += entry_size;
        entry_count++;

        if (ReturnSingleEntry)
            break;
    }

    if (entry_count == 0) {
        if (IoStatusBlock) {
            IoStatusBlock->Status = STATUS_NO_MORE_ENTRIES;
            IoStatusBlock->Information = 0;
        }
        /* Enumeration complete: release the slot so the handle can re-enumerate
         * if caller RestartScans later, and so a handle close doesn't leak. */
        pthread_mutex_lock(&g_dir_states_lock);
        release_dir_state_locked(state);
        pthread_mutex_unlock(&g_dir_states_lock);
        return STATUS_NO_MORE_ENTRIES;
    }

    /* Last entry has NextEntryOffset = 0 */
    FILE_BOTH_DIR_INFORMATION *last =
        (FILE_BOTH_DIR_INFORMATION *)(buf + last_entry_offset);
    last->NextEntryOffset = 0;

    if (IoStatusBlock) {
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = buf_used;
    }
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtFlushBuffersFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock)
{
    int fd = handle_get_fd(FileHandle);
    if (fd < 0)
        return STATUS_INVALID_HANDLE;

    fsync(fd);
    if (IoStatusBlock) {
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = 0;
    }
    return STATUS_SUCCESS;
}
