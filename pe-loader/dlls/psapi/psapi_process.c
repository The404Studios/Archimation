/*
 * psapi_process.c - Process Status API (psapi.dll) stubs
 *
 * Provides EnumProcesses, EnumProcessModules, GetModuleFileNameEx, etc.
 * Backed by /proc filesystem on Linux.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>

#include "common/dll_common.h"

/* ========== Process Enumeration ========== */

WINAPI_EXPORT BOOL EnumProcesses(uint32_t *lpidProcess, uint32_t cb, uint32_t *lpcbNeeded)
{
    if (!lpidProcess || !lpcbNeeded) return FALSE;

    uint32_t max_pids = cb / sizeof(uint32_t);
    uint32_t count = 0;

    DIR *dir = opendir("/proc");
    if (!dir) {
        /* Fallback: just return current PID */
        if (max_pids > 0) {
            lpidProcess[0] = (uint32_t)getpid();
            count = 1;
        }
        *lpcbNeeded = count * sizeof(uint32_t);
        return TRUE;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && count < max_pids) {
        /* Only numeric entries are PIDs */
        int is_pid = 1;
        for (const char *p = entry->d_name; *p; p++) {
            if (!isdigit(*p)) { is_pid = 0; break; }
        }
        if (is_pid) {
            lpidProcess[count++] = (uint32_t)atoi(entry->d_name);
        }
    }
    closedir(dir);

    *lpcbNeeded = count * sizeof(uint32_t);
    return TRUE;
}

WINAPI_EXPORT BOOL EnumProcessModules(void *hProcess, void **lphModule,
                                       uint32_t cb, uint32_t *lpcbNeeded)
{
    (void)hProcess;
    if (!lphModule || !lpcbNeeded) return FALSE;

    /* Return at least the main module */
    uint32_t max_modules = cb / sizeof(void *);
    if (max_modules > 0) {
        lphModule[0] = NULL; /* Main module handle */
    }
    *lpcbNeeded = sizeof(void *);
    return TRUE;
}

WINAPI_EXPORT BOOL EnumProcessModulesEx(void *hProcess, void **lphModule,
                                          uint32_t cb, uint32_t *lpcbNeeded,
                                          uint32_t dwFilterFlag)
{
    (void)dwFilterFlag;
    return EnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);
}

/* ========== Module Information ========== */

WINAPI_EXPORT uint32_t GetModuleFileNameExA(void *hProcess, void *hModule,
                                              char *lpFilename, uint32_t nSize)
{
    (void)hProcess; (void)hModule;
    if (!lpFilename || nSize == 0) return 0;

    ssize_t len = readlink("/proc/self/exe", lpFilename, nSize - 1);
    if (len < 0) {
        strncpy(lpFilename, "unknown.exe", nSize - 1);
        lpFilename[nSize - 1] = '\0';
        return (uint32_t)strlen(lpFilename);
    }
    lpFilename[len] = '\0';
    return (uint32_t)len;
}

WINAPI_EXPORT uint32_t GetModuleFileNameExW(void *hProcess, void *hModule,
                                              uint16_t *lpFilename, uint32_t nSize)
{
    char buf[1024];
    uint32_t len = GetModuleFileNameExA(hProcess, hModule, buf, sizeof(buf));
    if (len == 0 || !lpFilename || nSize == 0) return 0;

    uint32_t i;
    for (i = 0; i < len && i < nSize - 1; i++)
        lpFilename[i] = (uint16_t)(uint8_t)buf[i];
    lpFilename[i] = 0;
    return i;
}

WINAPI_EXPORT uint32_t GetModuleBaseNameA(void *hProcess, void *hModule,
                                            char *lpBaseName, uint32_t nSize)
{
    if (!lpBaseName || nSize == 0) return 0;

    char fullpath[1024];
    uint32_t len = GetModuleFileNameExA(hProcess, hModule, fullpath, sizeof(fullpath));
    if (len == 0) return 0;

    const char *base = strrchr(fullpath, '/');
    if (!base) base = strrchr(fullpath, '\\');
    base = base ? base + 1 : fullpath;

    strncpy(lpBaseName, base, nSize - 1);
    lpBaseName[nSize - 1] = '\0';
    return (uint32_t)strlen(lpBaseName);
}

WINAPI_EXPORT uint32_t GetModuleBaseNameW(void *hProcess, void *hModule,
                                            uint16_t *lpBaseName, uint32_t nSize)
{
    char buf[256];
    uint32_t len = GetModuleBaseNameA(hProcess, hModule, buf, sizeof(buf));
    if (len == 0 || !lpBaseName || nSize == 0) return 0;

    uint32_t i;
    for (i = 0; i < len && i < nSize - 1; i++)
        lpBaseName[i] = (uint16_t)(uint8_t)buf[i];
    lpBaseName[i] = 0;
    return i;
}

/* ========== Module Info Structure ========== */

typedef struct {
    void *lpBaseOfDll;
    uint32_t SizeOfImage;
    void *EntryPoint;
} MODULEINFO;

WINAPI_EXPORT BOOL GetModuleInformation(void *hProcess, void *hModule,
                                          MODULEINFO *lpmodinfo, uint32_t cb)
{
    (void)hProcess; (void)hModule;
    if (!lpmodinfo || cb < sizeof(MODULEINFO)) return FALSE;
    lpmodinfo->lpBaseOfDll = NULL;
    lpmodinfo->SizeOfImage = 0;
    lpmodinfo->EntryPoint = NULL;
    return TRUE;
}

/* ========== Process Memory Info ========== */

typedef struct {
    uint32_t cb;
    uint32_t PageFaultCount;
    size_t PeakWorkingSetSize;
    size_t WorkingSetSize;
    size_t QuotaPeakPagedPoolUsage;
    size_t QuotaPagedPoolUsage;
    size_t QuotaPeakNonPagedPoolUsage;
    size_t QuotaNonPagedPoolUsage;
    size_t PagefileUsage;
    size_t PeakPagefileUsage;
} PROCESS_MEMORY_COUNTERS;

WINAPI_EXPORT BOOL GetProcessMemoryInfo(void *Process,
                                          PROCESS_MEMORY_COUNTERS *ppsmemCounters,
                                          uint32_t cb)
{
    (void)Process;
    if (!ppsmemCounters || cb < sizeof(PROCESS_MEMORY_COUNTERS)) return FALSE;

    memset(ppsmemCounters, 0, cb);
    ppsmemCounters->cb = cb;

    /* Read from /proc/self/statm */
    FILE *f = fopen("/proc/self/statm", "r");
    if (f) {
        unsigned long size, resident;
        if (fscanf(f, "%lu %lu", &size, &resident) == 2) {
            long page_size = sysconf(_SC_PAGESIZE);
            ppsmemCounters->WorkingSetSize = resident * page_size;
            ppsmemCounters->PeakWorkingSetSize = resident * page_size;
            ppsmemCounters->PagefileUsage = size * page_size;
        }
        fclose(f);
    }
    return TRUE;
}

/* ========== Mapped File Names ========== */

WINAPI_EXPORT uint32_t GetMappedFileNameA(void *hProcess, void *lpv,
                                            char *lpFilename, uint32_t nSize)
{
    (void)hProcess; (void)lpv;
    if (!lpFilename || nSize == 0) return 0;
    lpFilename[0] = '\0';
    return 0;
}

WINAPI_EXPORT uint32_t GetMappedFileNameW(void *hProcess, void *lpv,
                                            uint16_t *lpFilename, uint32_t nSize)
{
    (void)hProcess; (void)lpv;
    if (!lpFilename || nSize == 0) return 0;
    lpFilename[0] = 0;
    return 0;
}

WINAPI_EXPORT uint32_t GetProcessImageFileNameA(void *hProcess, char *lpImageFileName,
                                                  uint32_t nSize)
{
    return GetModuleFileNameExA(hProcess, NULL, lpImageFileName, nSize);
}

WINAPI_EXPORT uint32_t GetProcessImageFileNameW(void *hProcess, uint16_t *lpImageFileName,
                                                  uint32_t nSize)
{
    return GetModuleFileNameExW(hProcess, NULL, lpImageFileName, nSize);
}

WINAPI_EXPORT BOOL EmptyWorkingSet(void *hProcess)
{
    (void)hProcess;
    return TRUE; /* No-op on Linux */
}

/* K32 prefixed versions (Windows 7+ kernel32 re-exports) */
WINAPI_EXPORT BOOL K32EnumProcesses(uint32_t *pids, uint32_t cb, uint32_t *needed)
{
    return EnumProcesses(pids, cb, needed);
}

WINAPI_EXPORT BOOL K32EnumProcessModules(void *proc, void **mods, uint32_t cb, uint32_t *needed)
{
    return EnumProcessModules(proc, mods, cb, needed);
}

WINAPI_EXPORT uint32_t K32GetModuleFileNameExA(void *proc, void *mod, char *name, uint32_t sz)
{
    return GetModuleFileNameExA(proc, mod, name, sz);
}

WINAPI_EXPORT uint32_t K32GetModuleFileNameExW(void *proc, void *mod, uint16_t *name, uint32_t sz)
{
    return GetModuleFileNameExW(proc, mod, name, sz);
}

WINAPI_EXPORT uint32_t K32GetModuleBaseNameA(void *proc, void *mod, char *name, uint32_t sz)
{
    return GetModuleBaseNameA(proc, mod, name, sz);
}

WINAPI_EXPORT uint32_t K32GetModuleBaseNameW(void *proc, void *mod, uint16_t *name, uint32_t sz)
{
    return GetModuleBaseNameW(proc, mod, name, sz);
}

WINAPI_EXPORT BOOL K32GetProcessMemoryInfo(void *proc, PROCESS_MEMORY_COUNTERS *info, uint32_t cb)
{
    return GetProcessMemoryInfo(proc, info, cb);
}
