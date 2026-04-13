/*
 * kernel32_debug.c - Process memory, debug, and cross-process APIs
 *
 * ReadProcessMemory, WriteProcessMemory, VirtualAllocEx, VirtualProtectEx,
 * VirtualQueryEx, DebugActiveProcess, OutputDebugString, etc.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/uio.h>

#include "common/dll_common.h"

/* Forward declarations for types from kernel32_memory.c */
typedef struct {
    PVOID  BaseAddress;
    PVOID  AllocationBase;
    DWORD  AllocationProtect;
    SIZE_T RegionSize;
    DWORD  State;
    DWORD  Protect;
    DWORD  Type;
} MEMORY_BASIC_INFORMATION;

extern WINAPI_EXPORT SIZE_T VirtualQuery(LPCVOID lpAddress,
    MEMORY_BASIC_INFORMATION *lpBuffer, SIZE_T dwLength);

/* ---------- ReadProcessMemory / WriteProcessMemory ---------- */

WINAPI_EXPORT BOOL ReadProcessMemory(
    HANDLE  hProcess,
    LPCVOID lpBaseAddress,
    LPVOID  lpBuffer,
    SIZE_T  nSize,
    SIZE_T *lpNumberOfBytesRead)
{
    /* Self-process: direct memcpy */
    if (hProcess == (HANDLE)(intptr_t)-1 || hProcess == NULL) {
        memcpy(lpBuffer, lpBaseAddress, nSize);
        if (lpNumberOfBytesRead) *lpNumberOfBytesRead = nSize;
        return TRUE;
    }

    /* Cross-process via process_vm_readv */
    struct iovec local = { lpBuffer, nSize };
    struct iovec remote = { (void *)lpBaseAddress, nSize };

    pid_t pid = (pid_t)(uintptr_t)hProcess;
    ssize_t result = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (result < 0) {
        /* Fallback: try /proc/pid/mem */
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/mem", pid);
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            set_last_error(errno_to_win32_error(errno));
            return FALSE;
        }
        ssize_t rd = pread(fd, lpBuffer, nSize, (off_t)(uintptr_t)lpBaseAddress);
        close(fd);
        if (rd < 0) {
            set_last_error(errno_to_win32_error(errno));
            return FALSE;
        }
        if (lpNumberOfBytesRead) *lpNumberOfBytesRead = (SIZE_T)rd;
        return TRUE;
    }

    if (lpNumberOfBytesRead) *lpNumberOfBytesRead = (SIZE_T)result;
    return TRUE;
}

WINAPI_EXPORT BOOL WriteProcessMemory(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T *lpNumberOfBytesWritten)
{
    /* Self-process: direct memcpy */
    if (hProcess == (HANDLE)(intptr_t)-1 || hProcess == NULL) {
        memcpy(lpBaseAddress, lpBuffer, nSize);
        if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;
        return TRUE;
    }

    /* Cross-process via process_vm_writev */
    struct iovec local = { (void *)lpBuffer, nSize };
    struct iovec remote = { lpBaseAddress, nSize };

    pid_t pid = (pid_t)(uintptr_t)hProcess;
    ssize_t result = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (result < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = (SIZE_T)result;
    return TRUE;
}

/* ---------- VirtualAllocEx / VirtualFreeEx / VirtualProtectEx ---------- */

/* These operate on the current process (remote process not yet supported) */
extern WINAPI_EXPORT LPVOID VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
extern WINAPI_EXPORT BOOL VirtualFree(LPVOID, SIZE_T, DWORD);
extern WINAPI_EXPORT BOOL VirtualProtect(LPVOID, SIZE_T, DWORD, DWORD *);

WINAPI_EXPORT LPVOID VirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect)
{
    (void)hProcess; /* Only support current process */
    return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

WINAPI_EXPORT BOOL VirtualFreeEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  dwFreeType)
{
    (void)hProcess;
    return VirtualFree(lpAddress, dwSize, dwFreeType);
}

WINAPI_EXPORT BOOL VirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    DWORD *lpflOldProtect)
{
    (void)hProcess;
    return VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

WINAPI_EXPORT SIZE_T VirtualQueryEx(
    HANDLE hProcess,
    LPCVOID lpAddress,
    MEMORY_BASIC_INFORMATION *lpBuffer,
    SIZE_T dwLength)
{
    (void)hProcess;
    return VirtualQuery(lpAddress, lpBuffer, dwLength);
}

/* ---------- Debug Functions ---------- */
/* OutputDebugStringA/W, IsDebuggerPresent, CheckRemoteDebuggerPresent → kernel32_process.c */
/* RaiseException, SetUnhandledExceptionFilter, UnhandledExceptionFilter → kernel32_error.c */

WINAPI_EXPORT void DebugBreak(void)
{
    /* Raise SIGTRAP (like INT 3) */
    raise(SIGTRAP);
}

WINAPI_EXPORT BOOL DebugActiveProcess(DWORD dwProcessId)
{
    (void)dwProcessId;
    set_last_error(ERROR_ACCESS_DENIED);
    return FALSE;
}

WINAPI_EXPORT BOOL DebugActiveProcessStop(DWORD dwProcessId)
{
    (void)dwProcessId;
    return TRUE;
}

WINAPI_EXPORT BOOL ContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId,
                                       DWORD dwContinueStatus)
{
    (void)dwProcessId; (void)dwThreadId; (void)dwContinueStatus;
    return TRUE;
}

WINAPI_EXPORT BOOL WaitForDebugEvent(void *lpDebugEvent, DWORD dwMilliseconds)
{
    (void)lpDebugEvent; (void)dwMilliseconds;
    set_last_error(ERROR_SEM_TIMEOUT);
    return FALSE;
}

WINAPI_EXPORT BOOL SetThreadContext(HANDLE hThread, const void *lpContext)
{
    (void)hThread; (void)lpContext;
    return TRUE;
}

WINAPI_EXPORT BOOL GetThreadContext(HANDLE hThread, void *lpContext)
{
    (void)hThread;
    if (lpContext) memset(lpContext, 0, 1232); /* sizeof(CONTEXT) on x64 */
    return TRUE;
}

/* ---------- FlushInstructionCache ---------- */

WINAPI_EXPORT BOOL FlushInstructionCache(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize)
{
    (void)hProcess; (void)lpBaseAddress; (void)dwSize;
    /* x86/x64: not needed (coherent I/D caches) */
    return TRUE;
}
