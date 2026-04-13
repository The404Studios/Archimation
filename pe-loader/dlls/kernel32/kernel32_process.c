/*
 * kernel32_process.c - Process management functions
 *
 * Functions that belong here: ExitProcess, TerminateProcess, GetCurrentProcess/Id,
 * GetCurrentThread/Id, IsDebuggerPresent, OutputDebugString, GetVersion, GetACP.
 *
 * NOTE: GetCommandLineA/W, GetEnvironmentVariable*, GetStartupInfo* live in
 *       kernel32_environ.c.  GetModuleHandle* lives in kernel32_module.c.
 *       GetModuleFileName* lives in kernel32_path.c.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <spawn.h>
#include <errno.h>
#define gettid() syscall(SYS_gettid)

#include "common/dll_common.h"
#include "kernel32_internal.h"
#include "compat/trust_gate.h"

WINAPI_EXPORT void ExitProcess(UINT uExitCode)
{
    _exit((int)uExitCode);
}

WINAPI_EXPORT BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode)
{
    TRUST_CHECK(TRUST_GATE_PROCESS_CREATE, "TerminateProcess");

    (void)hProcess;
    _exit((int)uExitCode);
    return TRUE; /* unreachable */
}

WINAPI_EXPORT HANDLE GetCurrentProcess(void)
{
    /* Windows returns a pseudo-handle (-1) for the current process */
    return (HANDLE)(intptr_t)-1;
}

WINAPI_EXPORT DWORD GetCurrentProcessId(void)
{
    return (DWORD)getpid();
}

WINAPI_EXPORT HANDLE GetCurrentThread(void)
{
    return (HANDLE)(intptr_t)-2;
}

WINAPI_EXPORT DWORD GetCurrentThreadId(void)
{
    return (DWORD)gettid();
}

WINAPI_EXPORT BOOL IsDebuggerPresent(void)
{
    return FALSE;
}

WINAPI_EXPORT void OutputDebugStringA(LPCSTR lpOutputString)
{
    if (lpOutputString)
        fprintf(stderr, "[OutputDebugString] %s\n", lpOutputString);
}

WINAPI_EXPORT void OutputDebugStringW(LPCWSTR lpOutputString)
{
    if (!lpOutputString) return;
    /* Convert UTF-16LE to UTF-8 and print to stderr */
    const uint16_t *src = (const uint16_t *)lpOutputString;
    size_t len = 0;
    while (src[len]) len++;
    /* Worst case: 3 bytes per BMP codepoint + prefix + newline + null */
    char buf[4096];
    const char *prefix = "[OutputDebugString] ";
    size_t plen = strlen(prefix);
    memcpy(buf, prefix, plen);
    size_t out = plen;
    for (size_t i = 0; i < len && out < sizeof(buf) - 4; i++) {
        uint16_t c = src[i];
        if (c < 0x80) {
            buf[out++] = (char)c;
        } else if (c < 0x800) {
            buf[out++] = (char)(0xC0 | (c >> 6));
            buf[out++] = (char)(0x80 | (c & 0x3F));
        } else {
            buf[out++] = (char)(0xE0 | (c >> 12));
            buf[out++] = (char)(0x80 | ((c >> 6) & 0x3F));
            buf[out++] = (char)(0x80 | (c & 0x3F));
        }
    }
    buf[out++] = '\n';
    buf[out] = '\0';
    fputs(buf, stderr);
}

WINAPI_EXPORT DWORD GetVersion(void)
{
    /* Return Windows 10.0 build 19044
     * Low byte = major (10), next byte = minor (0), high word = build.
     * Bit 31 must be clear (indicates NT-based OS). Build number is
     * masked to 15 bits to avoid setting bit 31 (which would indicate
     * Win9x/ME). */
    return 10 | (0 << 8) | ((19044 & 0x7FFF) << 16);
}

WINAPI_EXPORT BOOL GetVersionExA(void *lpVersionInformation)
{
    /* OSVERSIONINFOA structure */
    typedef struct {
        DWORD dwOSVersionInfoSize;
        DWORD dwMajorVersion;
        DWORD dwMinorVersion;
        DWORD dwBuildNumber;
        DWORD dwPlatformId;
        CHAR  szCSDVersion[128];
    } OSVERSIONINFOA;

    OSVERSIONINFOA *info = (OSVERSIONINFOA *)lpVersionInformation;
    info->dwMajorVersion = 10;
    info->dwMinorVersion = 0;
    info->dwBuildNumber = 19044; /* Windows 10 21H2 */
    info->dwPlatformId = 2;     /* VER_PLATFORM_WIN32_NT */
    memset(info->szCSDVersion, 0, sizeof(info->szCSDVersion));
    return TRUE;
}

WINAPI_EXPORT UINT GetACP(void)
{
    return 65001; /* UTF-8 */
}

WINAPI_EXPORT BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)
{
    (void)ProcessorFeature;
    return TRUE; /* Assume all features present on modern x86-64 */
}

/* ---------- GetSystemInfo / GetNativeSystemInfo ---------- */

typedef struct {
    union {
        DWORD dwOemId;
        struct {
            WORD wProcessorArchitecture;
            WORD wReserved;
        };
    };
    DWORD  dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask;
    DWORD  dwNumberOfProcessors;
    DWORD  dwProcessorType;
    DWORD  dwAllocationGranularity;
    WORD   wProcessorLevel;
    WORD   wProcessorRevision;
} SYSTEM_INFO;

static void fill_system_info(SYSTEM_INFO *si)
{
    memset(si, 0, sizeof(*si));
    si->wProcessorArchitecture = 9; /* PROCESSOR_ARCHITECTURE_AMD64 */
    si->dwPageSize = (DWORD)sysconf(_SC_PAGESIZE);
    si->lpMinimumApplicationAddress = (LPVOID)(uintptr_t)0x00010000;
    si->lpMaximumApplicationAddress = (LPVOID)(uintptr_t)0x7FFFFFFEFFFF;

    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    si->dwNumberOfProcessors = (DWORD)(nproc > 0 ? nproc : 1);
    if (si->dwNumberOfProcessors >= 64)
        si->dwActiveProcessorMask = (DWORD_PTR)~0ULL;
    else
        si->dwActiveProcessorMask = ((DWORD_PTR)1ULL << si->dwNumberOfProcessors) - 1;
    si->dwProcessorType = 8664; /* PROCESSOR_AMD_X8664 */
    si->dwAllocationGranularity = 0x10000; /* 64KB */
    si->wProcessorLevel = 6;
    si->wProcessorRevision = 0;
}

WINAPI_EXPORT void GetSystemInfo(SYSTEM_INFO *lpSystemInfo)
{
    if (lpSystemInfo)
        fill_system_info(lpSystemInfo);
}

WINAPI_EXPORT void GetNativeSystemInfo(SYSTEM_INFO *lpSystemInfo)
{
    if (lpSystemInfo)
        fill_system_info(lpSystemInfo);
}

/* ---------- CreateProcessA/W ---------- */

/*
 * PROCESS_INFORMATION and STARTUPINFOA structures.
 * Defined locally since we only need partial fields.
 */
typedef struct {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
} PROCESS_INFORMATION;

typedef struct {
    DWORD  cb;
    LPSTR  lpReserved;
    LPSTR  lpDesktop;
    LPSTR  lpTitle;
    DWORD  dwX, dwY, dwXSize, dwYSize;
    DWORD  dwXCountChars, dwYCountChars;
    DWORD  dwFillAttribute;
    DWORD  dwFlags;
    WORD   wShowWindow;
    WORD   cbReserved2;
    BYTE  *lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOA;

#define PE_LOADER_PATH "/usr/bin/peloader"

WINAPI_EXPORT BOOL CreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR  lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    STARTUPINFOA *lpStartupInfo,
    PROCESS_INFORMATION *lpProcessInformation)
{
    TRUST_CHECK_ARG(TRUST_GATE_PROCESS_CREATE, "CreateProcessA",
                    lpApplicationName ? lpApplicationName : lpCommandLine);

    (void)lpProcessAttributes;
    (void)lpThreadAttributes;
    (void)bInheritHandles;
    (void)dwCreationFlags;
    (void)lpEnvironment;
    (void)lpStartupInfo;

    if (!lpApplicationName && !lpCommandLine) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Determine the executable path */
    char exe_path[4096] = {0};
    char args_buf[4096] = {0};

    if (lpApplicationName) {
        win_path_to_linux(lpApplicationName, exe_path, sizeof(exe_path));
    } else if (lpCommandLine) {
        /* Extract exe from command line (first token, possibly quoted) */
        const char *p = lpCommandLine;
        while (*p == ' ') p++;
        if (*p == '"') {
            p++;
            const char *end = strchr(p, '"');
            if (end) {
                size_t len = (size_t)(end - p);
                if (len >= sizeof(exe_path)) len = sizeof(exe_path) - 1;
                memcpy(exe_path, p, len);
                exe_path[len] = '\0';
                /* Rest is arguments */
                p = end + 1;
                while (*p == ' ') p++;
                strncpy(args_buf, p, sizeof(args_buf) - 1);
            }
        } else {
            const char *end = strchr(p, ' ');
            if (end) {
                size_t len = (size_t)(end - p);
                if (len >= sizeof(exe_path)) len = sizeof(exe_path) - 1;
                memcpy(exe_path, p, len);
                exe_path[len] = '\0';
                strncpy(args_buf, end + 1, sizeof(args_buf) - 1);
            } else {
                strncpy(exe_path, p, sizeof(exe_path) - 1);
            }
        }

        /* Translate Windows path */
        char linux_path[4096];
        win_path_to_linux(exe_path, linux_path, sizeof(linux_path));
        strncpy(exe_path, linux_path, sizeof(exe_path) - 1);
    }

    /* Check if it's a PE file — if so, run through peloader */
    int is_pe = 0;
    FILE *f = fopen(exe_path, "rb");
    if (f) {
        unsigned char magic[2] = {0};
        if (fread(magic, 1, 2, f) == 2 && magic[0] == 'M' && magic[1] == 'Z')
            is_pe = 1;
        fclose(f);
    }

    /* lpCurrentDirectory conversion is done in the child; no need in parent */

    pid_t pid = fork();
    if (pid < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    if (pid == 0) {
        /* Child process */
        if (lpCurrentDirectory) {
            char linux_dir[4096];
            win_path_to_linux(lpCurrentDirectory, linux_dir, sizeof(linux_dir));
            if (chdir(linux_dir) < 0)
                _exit(127);
        }

        /* Build argv array by splitting args_buf on spaces */
        char *argv_arr[256];
        int argc_arr = 0;

        if (is_pe) {
            argv_arr[argc_arr++] = PE_LOADER_PATH;
            argv_arr[argc_arr++] = exe_path;
        } else {
            argv_arr[argc_arr++] = exe_path;
        }

        /* Split remaining args (non-static: safe in fork child) */
        char args_copy[4096];
        strncpy(args_copy, args_buf, sizeof(args_copy) - 1);
        args_copy[sizeof(args_copy) - 1] = '\0';
        char *saveptr = NULL;
        char *tok = strtok_r(args_copy, " \t", &saveptr);
        while (tok && argc_arr < 254) {
            argv_arr[argc_arr++] = tok;
            tok = strtok_r(NULL, " \t", &saveptr);
        }
        argv_arr[argc_arr] = NULL;

        execvp(argv_arr[0], argv_arr);
        _exit(127); /* exec failed */
    }

    /* Parent: allocate a proper process handle */
    process_data_t *proc = calloc(1, sizeof(process_data_t));
    HANDLE hProcess = NULL;
    if (proc) {
        proc->pid = pid;
        proc->finished = 0;
        proc->exit_code = -1;
        hProcess = handle_alloc(HANDLE_TYPE_PROCESS, -1, proc);
        if (!hProcess) {
            free(proc);
            hProcess = (HANDLE)(uintptr_t)pid; /* fallback */
        }
    } else {
        hProcess = (HANDLE)(uintptr_t)pid;
    }

    if (lpProcessInformation) {
        memset(lpProcessInformation, 0, sizeof(*lpProcessInformation));
        lpProcessInformation->dwProcessId = (DWORD)pid;
        lpProcessInformation->dwThreadId  = (DWORD)pid;
        lpProcessInformation->hProcess    = hProcess;
        lpProcessInformation->hThread     = hProcess; /* no separate thread handle */
    }

    return TRUE;
}

/* ---------- Additional Process Functions ---------- */

WINAPI_EXPORT BOOL CheckRemoteDebuggerPresent(HANDLE hProcess, BOOL *pbDebuggerPresent)
{
    (void)hProcess;
    if (pbDebuggerPresent) *pbDebuggerPresent = FALSE;
    return TRUE;
}

WINAPI_EXPORT DWORD GetProcessId(HANDLE Process)
{
    if (Process == (HANDLE)(intptr_t)-1 || Process == NULL)
        return (DWORD)getpid();
    return (DWORD)(uintptr_t)Process;
}

WINAPI_EXPORT BOOL GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode)
{
    if (!lpExitCode) return FALSE;

    /* Check handle table first */
    handle_entry_t *entry = handle_lookup(hProcess);
    if (entry && entry->type == HANDLE_TYPE_PROCESS) {
        process_data_t *proc = (process_data_t *)entry->data;
        if (!proc->finished) {
            int status;
            pid_t ret = waitpid(proc->pid, &status, WNOHANG);
            if (ret == proc->pid) {
                proc->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
                proc->finished = 1;
            }
        }
        *lpExitCode = proc->finished ? (DWORD)proc->exit_code : 259; /* STILL_ACTIVE */
        return TRUE;
    }

    /* Fallback: raw PID handle */
    pid_t pid = (pid_t)(uintptr_t)hProcess;
    if (pid <= 0) {
        *lpExitCode = 0;
        return TRUE;
    }
    int status;
    pid_t ret = waitpid(pid, &status, WNOHANG);
    if (ret == 0) {
        *lpExitCode = 259; /* STILL_ACTIVE */
    } else if (ret > 0 && WIFEXITED(status)) {
        *lpExitCode = (DWORD)WEXITSTATUS(status);
    } else {
        *lpExitCode = 1;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL GetProcessTimes(HANDLE hProcess, LPFILETIME lpCreationTime,
                                    LPFILETIME lpExitTime, LPFILETIME lpKernelTime,
                                    LPFILETIME lpUserTime)
{
    (void)hProcess;
    if (lpCreationTime) memset(lpCreationTime, 0, sizeof(FILETIME));
    if (lpExitTime) memset(lpExitTime, 0, sizeof(FILETIME));
    if (lpKernelTime) memset(lpKernelTime, 0, sizeof(FILETIME));
    if (lpUserTime) memset(lpUserTime, 0, sizeof(FILETIME));
    return TRUE;
}

WINAPI_EXPORT DWORD GetPriorityClass(HANDLE hProcess)
{
    (void)hProcess;
    return 0x20; /* NORMAL_PRIORITY_CLASS */
}

WINAPI_EXPORT BOOL SetPriorityClass(HANDLE hProcess, DWORD dwPriorityClass)
{
    (void)hProcess; (void)dwPriorityClass;
    return TRUE;
}

WINAPI_EXPORT BOOL GetProcessAffinityMask(HANDLE hProcess, DWORD_PTR *lpProcessAffinityMask,
                                            DWORD_PTR *lpSystemAffinityMask)
{
    (void)hProcess;
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    DWORD_PTR mask = (nproc >= 64) ? ~(DWORD_PTR)0 : ((DWORD_PTR)1 << nproc) - 1;
    if (lpProcessAffinityMask) *lpProcessAffinityMask = mask;
    if (lpSystemAffinityMask) *lpSystemAffinityMask = mask;
    return TRUE;
}

WINAPI_EXPORT BOOL SetProcessAffinityMask(HANDLE hProcess, DWORD_PTR dwProcessAffinityMask)
{
    (void)hProcess; (void)dwProcessAffinityMask;
    return TRUE;
}

WINAPI_EXPORT SIZE_T GetLargePageMinimum(void)
{
    return 2 * 1024 * 1024; /* 2MB */
}

WINAPI_EXPORT BOOL IsWow64Process(HANDLE hProcess, BOOL *Wow64Process)
{
    (void)hProcess;
    if (Wow64Process) *Wow64Process = FALSE;
    return TRUE;
}

WINAPI_EXPORT BOOL GetProcessWorkingSetSize(HANDLE hProcess, SIZE_T *lpMinimumWorkingSetSize,
                                             SIZE_T *lpMaximumWorkingSetSize)
{
    (void)hProcess;
    if (lpMinimumWorkingSetSize) *lpMinimumWorkingSetSize = 204800;
    if (lpMaximumWorkingSetSize) *lpMaximumWorkingSetSize = 1413120;
    return TRUE;
}

WINAPI_EXPORT BOOL SetProcessWorkingSetSize(HANDLE hProcess, SIZE_T dwMinimumWorkingSetSize,
                                             SIZE_T dwMaximumWorkingSetSize)
{
    (void)hProcess; (void)dwMinimumWorkingSetSize; (void)dwMaximumWorkingSetSize;
    return TRUE;
}

WINAPI_EXPORT BOOL GetProcessHandleCount(HANDLE hProcess, PDWORD pdwHandleCount)
{
    (void)hProcess;
    if (pdwHandleCount) *pdwHandleCount = 42;
    return TRUE;
}

WINAPI_EXPORT UINT GetOEMCP(void)
{
    return 437; /* US English OEM */
}

WINAPI_EXPORT BOOL GetVersionExW(void *lpVersionInformation)
{
    typedef struct {
        DWORD dwOSVersionInfoSize;
        DWORD dwMajorVersion;
        DWORD dwMinorVersion;
        DWORD dwBuildNumber;
        DWORD dwPlatformId;
        WCHAR szCSDVersion[128];
    } OSVERSIONINFOW;

    OSVERSIONINFOW *info = (OSVERSIONINFOW *)lpVersionInformation;
    info->dwMajorVersion = 10;
    info->dwMinorVersion = 0;
    info->dwBuildNumber = 19041;
    info->dwPlatformId = 2;
    memset(info->szCSDVersion, 0, sizeof(info->szCSDVersion));
    return TRUE;
}

WINAPI_EXPORT BOOL CreateProcessW(
    LPCWSTR lpApplicationName,
    LPWSTR  lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    void *lpStartupInfo,
    PROCESS_INFORMATION *lpProcessInformation)
{
    /* Convert wide strings to narrow and delegate */
    char app_name_a[4096] = {0};
    char cmd_line_a[4096] = {0};
    char cur_dir_a[4096] = {0};

    if (lpApplicationName) {
        for (int i = 0; i < 4095 && lpApplicationName[i]; i++)
            app_name_a[i] = (char)(lpApplicationName[i] & 0xFF);
    }
    if (lpCommandLine) {
        for (int i = 0; i < 4095 && lpCommandLine[i]; i++)
            cmd_line_a[i] = (char)(lpCommandLine[i] & 0xFF);
    }
    if (lpCurrentDirectory) {
        for (int i = 0; i < 4095 && lpCurrentDirectory[i]; i++)
            cur_dir_a[i] = (char)(lpCurrentDirectory[i] & 0xFF);
    }

    return CreateProcessA(
        lpApplicationName ? app_name_a : NULL,
        lpCommandLine ? cmd_line_a : NULL,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory ? cur_dir_a : NULL,
        (STARTUPINFOA *)lpStartupInfo,
        lpProcessInformation
    );
}

/* ---------- DuplicateHandle ---------- */

#define DUPLICATE_CLOSE_SOURCE 0x00000001
#define DUPLICATE_SAME_ACCESS  0x00000002

WINAPI_EXPORT BOOL DuplicateHandle(
    HANDLE hSourceProcessHandle,
    HANDLE hSourceHandle,
    HANDLE hTargetProcessHandle,
    HANDLE *lpTargetHandle,
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwOptions)
{
    (void)hSourceProcessHandle;
    (void)hTargetProcessHandle;
    (void)dwDesiredAccess;
    (void)bInheritHandle;

    if (!lpTargetHandle) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Try to get the fd from the source handle and dup() it */
    int src_fd = handle_get_fd(hSourceHandle);
    if (src_fd >= 0) {
        int new_fd = dup(src_fd);
        if (new_fd >= 0) {
            handle_entry_t *entry = handle_lookup(hSourceHandle);
            handle_type_t type = entry ? entry->type : HANDLE_TYPE_FILE;
            *lpTargetHandle = handle_alloc(type, new_fd, NULL);
        } else {
            /* dup failed, just copy the handle value */
            *lpTargetHandle = hSourceHandle;
        }
    } else {
        /* Non-fd handle (event, mutex, etc) - copy the handle and increment ref_count */
        handle_entry_t *entry = handle_lookup(hSourceHandle);
        if (entry)
            entry->ref_count++;
        *lpTargetHandle = hSourceHandle;
    }

    if (dwOptions & DUPLICATE_CLOSE_SOURCE) {
        handle_close(hSourceHandle);
    }

    return TRUE;
}

/* ---------- OpenProcess ---------- */

#define PROCESS_ALL_ACCESS       0x1F0FFF
#define PROCESS_QUERY_INFORMATION 0x0400
#define PROCESS_VM_READ           0x0010

WINAPI_EXPORT HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    TRUST_CHECK_RET(TRUST_GATE_PROCESS_CREATE, "OpenProcess", NULL);

    (void)dwDesiredAccess;
    (void)bInheritHandle;

    /* Current process pseudo-handle */
    if (dwProcessId == (DWORD)getpid())
        return (HANDLE)(intptr_t)-1;

    /* Check if we already have a handle for this PID */
    /* For simplicity, allocate a new process handle entry */
    process_data_t *proc = calloc(1, sizeof(process_data_t));
    if (!proc) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    proc->pid = (pid_t)dwProcessId;
    proc->finished = 0;
    proc->exit_code = -1;

    /* Check if process is still alive */
    if (kill(proc->pid, 0) != 0 && errno == ESRCH) {
        free(proc);
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    HANDLE h = handle_alloc(HANDLE_TYPE_PROCESS, -1, proc);
    if (!h) {
        free(proc);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    return h;
}

/* ---------- TerminateProcess (real PID-based) ---------- */

/* ---------- GetProcessMitigationPolicy ---------- */

WINAPI_EXPORT BOOL GetProcessMitigationPolicy(
    HANDLE hProcess,
    int MitigationPolicy,
    void *lpBuffer,
    SIZE_T dwLength)
{
    (void)hProcess;
    (void)MitigationPolicy;
    (void)lpBuffer;
    (void)dwLength;
    set_last_error(ERROR_INVALID_PARAMETER);
    return FALSE;
}

/* ---------- Admin spoofing (Blacksmith launcher checks for admin rights) ---------- */

WINAPI_EXPORT BOOL IsUserAnAdmin(void)
{
    return TRUE; /* Always report admin — Blacksmith launcher requires it */
}

/* ----------------------------------------------------------------
 * OpenProcessToken / GetTokenInformation - forwarded to canonical advapi32
 *
 * Many Windows executables import these from kernel32.dll (they are
 * actually advapi32 exports, but kernel32 re-exports them on modern
 * Windows).  We forward at runtime via dlsym.
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL WINAPI OpenProcessToken(HANDLE ProcessHandle,
                                            DWORD DesiredAccess,
                                            HANDLE *TokenHandle)
{
    typedef BOOL (WINAPI *fn_t)(HANDLE, DWORD, HANDLE*);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        void *h = dlopen("libpe_advapi32.so", RTLD_LAZY);
        if (h) real_fn = (fn_t)dlsym(h, "OpenProcessToken");
    }
    if (real_fn) return real_fn(ProcessHandle, DesiredAccess, TokenHandle);
    if (TokenHandle) *TokenHandle = (HANDLE)(uintptr_t)0xFEED0001;
    return TRUE;
}

WINAPI_EXPORT BOOL WINAPI GetTokenInformation(HANDLE TokenHandle,
                                               int TokenInformationClass,
                                               LPVOID TokenInformation,
                                               DWORD TokenInformationLength,
                                               DWORD *ReturnLength)
{
    typedef BOOL (WINAPI *fn_t)(HANDLE, int, LPVOID, DWORD, DWORD*);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        void *h = dlopen("libpe_advapi32.so", RTLD_LAZY);
        if (h) real_fn = (fn_t)dlsym(h, "GetTokenInformation");
    }
    if (real_fn) return real_fn(TokenHandle, TokenInformationClass,
                                TokenInformation, TokenInformationLength,
                                ReturnLength);
    if (ReturnLength) *ReturnLength = 0;
    return FALSE;
}
