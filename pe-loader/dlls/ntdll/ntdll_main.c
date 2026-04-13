/*
 * ntdll_main.c - Minimal NTDLL stubs
 *
 * NTDLL is the lowest-level Windows DLL, providing the NT native API.
 * Most Win32 functions in kernel32 eventually call down to ntdll.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>

#include "common/dll_common.h"
#include "compat/env_setup.h"
#include "compat/ms_abi_format.h"
#include "compat/trust_gate.h"

#ifndef BOOLEAN
typedef unsigned char BOOLEAN;
#endif

/* RtlInitUnicodeString */
WINAPI_EXPORT void RtlInitUnicodeString(PUNICODE_STRING dest, PCWSTR src)
{
    if (src) {
        size_t len = 0;
        while (src[len])
            len++;
        dest->Length = (USHORT)(len * sizeof(WCHAR));
        dest->MaximumLength = dest->Length + sizeof(WCHAR);
        dest->Buffer = (PWSTR)src;
    } else {
        dest->Length = 0;
        dest->MaximumLength = 0;
        dest->Buffer = NULL;
    }
}

/* RtlInitAnsiString */
WINAPI_EXPORT void RtlInitAnsiString(PANSI_STRING dest, PCSTR src)
{
    if (src) {
        size_t len = strlen(src);
        dest->Length = (USHORT)len;
        dest->MaximumLength = (USHORT)(len + 1);
        dest->Buffer = (PSTR)src;
    } else {
        dest->Length = 0;
        dest->MaximumLength = 0;
        dest->Buffer = NULL;
    }
}

/* NtTerminateProcess */
WINAPI_EXPORT NTSTATUS NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
    TRUST_CHECK_RET(TRUST_GATE_PROCESS_CREATE, "NtTerminateProcess", STATUS_ACCESS_DENIED);
    (void)ProcessHandle;
    _exit((int)ExitStatus);
    return STATUS_SUCCESS;
}

/* NtClose */
WINAPI_EXPORT NTSTATUS NtClose(HANDLE Handle)
{
    if (handle_close(Handle) < 0)
        return STATUS_INVALID_HANDLE;
    return STATUS_SUCCESS;
}

/* RtlNtStatusToDosError */
WINAPI_EXPORT ULONG RtlNtStatusToDosError(NTSTATUS Status)
{
    switch (Status) {
    case STATUS_SUCCESS:                return ERROR_SUCCESS;
    case STATUS_INVALID_HANDLE:         return ERROR_INVALID_HANDLE;
    case STATUS_INVALID_PARAMETER:      return ERROR_INVALID_PARAMETER;
    case STATUS_NO_SUCH_FILE:           return ERROR_FILE_NOT_FOUND;
    case STATUS_ACCESS_DENIED:          return ERROR_ACCESS_DENIED;
    case STATUS_OBJECT_NAME_NOT_FOUND:  return ERROR_FILE_NOT_FOUND;
    case STATUS_OBJECT_NAME_COLLISION:  return ERROR_ALREADY_EXISTS;
    case STATUS_NOT_IMPLEMENTED:        return ERROR_INVALID_FUNCTION;
    default:                            return ERROR_INVALID_FUNCTION;
    }
}

/* RtlGetVersion - returns Windows version info */
WINAPI_EXPORT NTSTATUS RtlGetVersion(void *lpVersionInformation)
{
    typedef struct {
        ULONG dwOSVersionInfoSize;
        ULONG dwMajorVersion;
        ULONG dwMinorVersion;
        ULONG dwBuildNumber;
        ULONG dwPlatformId;
        WCHAR szCSDVersion[128];
    } RTL_OSVERSIONINFOW;

    RTL_OSVERSIONINFOW *info = (RTL_OSVERSIONINFOW *)lpVersionInformation;
    info->dwMajorVersion = 10;
    info->dwMinorVersion = 0;
    info->dwBuildNumber = 19044;
    info->dwPlatformId = 2;
    memset(info->szCSDVersion, 0, sizeof(info->szCSDVersion));
    return STATUS_SUCCESS;
}

/* NtQueryInformationProcess - commonly used by anti-cheat and CRT init */
WINAPI_EXPORT NTSTATUS NtQueryInformationProcess(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength)
{
    (void)ProcessHandle;
    (void)ProcessInformationLength;

    switch (ProcessInformationClass) {
    case 0: /* ProcessBasicInformation */
        if (ProcessInformation) {
            memset(ProcessInformation, 0, 48);
            /* PEB address - use the real PEB from env_setup */
            void *peb = env_get_peb();
            *(uint64_t *)((char *)ProcessInformation + 8) =
                peb ? (uint64_t)(uintptr_t)peb : 0;
        }
        if (ReturnLength)
            *ReturnLength = 48;
        return STATUS_SUCCESS;

    case 7: /* ProcessDebugPort */
        if (ProcessInformation)
            *(ULONG_PTR *)ProcessInformation = 0; /* Not being debugged */
        if (ReturnLength)
            *ReturnLength = sizeof(ULONG_PTR);
        return STATUS_SUCCESS;

    case 29: /* ProcessImageFileName */
    {
        const ULONG required = sizeof(UNICODE_STRING) + 256 * sizeof(WCHAR);
        if (ProcessInformation && ProcessInformationLength >= required) {
            /* Return UNICODE_STRING with image path */
            char path[256];
            ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
            if (len > 0) {
                path[len] = '\0';
                UNICODE_STRING *us = (UNICODE_STRING *)ProcessInformation;
                us->Buffer = (PWSTR)((char *)ProcessInformation + sizeof(UNICODE_STRING));
                int i;
                for (i = 0; i < len && i < 255; i++)
                    us->Buffer[i] = (WCHAR)path[i];
                us->Buffer[i] = 0;
                us->Length = (USHORT)(i * 2);
                us->MaximumLength = us->Length + 2;
            } else {
                memset(ProcessInformation, 0, required);
            }
        } else if (ProcessInformation && ProcessInformationLength < required) {
            return (NTSTATUS)0xC0000004; /* STATUS_INFO_LENGTH_MISMATCH */
        }
        if (ReturnLength) *ReturnLength = required;
        return STATUS_SUCCESS;
    }

    case 30: /* ProcessDebugObjectHandle */
        /* Anti-debug: return STATUS_PORT_NOT_SET -> no debug object */
        return (NTSTATUS)0xC0000353; /* STATUS_PORT_NOT_SET */

    case 31: /* ProcessDebugFlags */
        if (ProcessInformation)
            *(ULONG *)ProcessInformation = 1; /* NoDebugInherit = 1 (not being debugged) */
        if (ReturnLength)
            *ReturnLength = sizeof(ULONG);
        return STATUS_SUCCESS;

    case 34: /* ProcessHandleCount */
        if (ProcessInformation)
            *(ULONG *)ProcessInformation = 42; /* Reasonable handle count */
        if (ReturnLength)
            *ReturnLength = sizeof(ULONG);
        return STATUS_SUCCESS;

    case 26: /* ProcessWow64Information */
        /* Return 0 = not WoW64 (we're native 64-bit) */
        if (ProcessInformation)
            *(ULONG_PTR *)ProcessInformation = 0;
        if (ReturnLength)
            *ReturnLength = sizeof(ULONG_PTR);
        return STATUS_SUCCESS;

    case 36: /* ProcessImageInformation */
        if (ProcessInformation && ProcessInformationLength >= 64)
            memset(ProcessInformation, 0, 64);
        if (ReturnLength) *ReturnLength = 64;
        return STATUS_SUCCESS;

    default:
        return STATUS_NOT_IMPLEMENTED;
    }
}

/* -----------------------------------------------------------------------
 * NtQuerySystemInformation - Full implementation for anti-cheat compat
 *
 * Anti-cheats query many information classes to verify they're running
 * on real Windows. We return convincing data for all commonly-checked
 * classes: process lists, kernel modules, handles, firmware, etc.
 * ----------------------------------------------------------------------- */

/* SYSTEM_PROCESS_INFORMATION entry (per-process, variable-length) */
#define SPI_ENTRY_SIZE  256  /* Fixed part per process entry */

/* Fake process table: what a clean Windows 10 system looks like */
typedef struct {
    const char *name;
    ULONG       pid;
    ULONG       ppid;
    ULONG       threads;
    ULONG       session_id;
} fake_process_t;

static const fake_process_t g_fake_processes[] = {
    { "System",                 4,      0,   120, 0 },
    { "Registry",              92,      4,     4, 0 },
    { "smss.exe",             348,      4,     2, 0 },
    { "csrss.exe",            468,    460,    12, 0 },
    { "wininit.exe",          544,    460,     1, 0 },
    { "csrss.exe",            552,    536,    14, 1 },
    { "winlogon.exe",         620,    536,     3, 1 },
    { "services.exe",         668,    544,     8, 0 },
    { "lsass.exe",            688,    544,    10, 0 },
    { "svchost.exe",          816,    668,    22, 0 },
    { "svchost.exe",          868,    668,    12, 0 },
    { "svchost.exe",          972,    668,    65, 0 },
    { "svchost.exe",         1076,    668,    18, 0 },
    { "svchost.exe",         1196,    668,     8, 0 },
    { "svchost.exe",         1296,    668,    14, 0 },
    { "svchost.exe",         1436,    668,    10, 0 },
    { "svchost.exe",         1516,    668,     6, 0 },
    { "dwm.exe",             1600,    816,    16, 1 },
    { "svchost.exe",         1700,    668,     4, 0 },
    { "svchost.exe",         1872,    668,     7, 0 },
    { "spoolsv.exe",         2120,    668,    12, 0 },
    { "svchost.exe",         2456,    668,     3, 0 },
    { "MsMpEng.exe",         2700,    668,    28, 0 },
    { "sihost.exe",          3148,    972,    11, 1 },
    { "taskhostw.exe",       3204,    972,     8, 1 },
    { "explorer.exe",        3376,   3340,    72, 1 },
    { "SearchHost.exe",      3632,    816,    30, 1 },
    { "RuntimeBroker.exe",   3840,    816,     6, 1 },
    { "SecurityHealthSystray.exe", 4020, 668,  2, 1 },
    { "conhost.exe",         4200,    552,     4, 1 },
    { "NisSrv.exe",          4360,    668,     6, 0 },
    { "WmiPrvSE.exe",        4500,    816,     9, 0 },
    { "dllhost.exe",         4680,    816,     5, 1 },
    { "audiodg.exe",         4820,    816,     6, 0 },
    { NULL, 0, 0, 0, 0 }
};

/* Write a UNICODE_STRING (name) into a process entry at given offset */
static void spi_write_name(char *entry, ULONG name_offset, const char *name)
{
    /* ImageName UNICODE_STRING at offset 56 (Length, MaxLen, Buffer) */
    USHORT wlen = 0;
    uint16_t *wbuf = (uint16_t *)(entry + name_offset);
    while (*name && wlen < 127) {
        wbuf[wlen++] = (uint16_t)(unsigned char)*name++;
    }
    /* Defensive cap (loop already bounds at 127, but guard for MaximumLength calc) */
    if (wlen > 127) wlen = 127;
    wbuf[wlen] = 0;

    /* UNICODE_STRING header at offset 56
     * Length and MaximumLength are byte counts (sizeof(WCHAR) == 2) */
    *(USHORT *)(entry + 56) = (USHORT)(wlen * 2);          /* Length in bytes */
    *(USHORT *)(entry + 58) = (USHORT)((wlen + 1) * 2);    /* MaximumLength in bytes (includes null) */
    *(uint64_t *)(entry + 60) = (uint64_t)(uintptr_t)(entry + name_offset); /* Buffer */
}

static NTSTATUS fill_system_process_info(PVOID buf, ULONG buflen, PULONG ret)
{
    /* Count how many processes we need */
    int nproc = 0;
    for (int i = 0; g_fake_processes[i].name; i++)
        nproc++;
    /* +1 for the actual game process */
    nproc++;

    ULONG entry_size = SPI_ENTRY_SIZE;
    ULONG total = (ULONG)nproc * entry_size;

    if (ret) *ret = total;
    if (!buf || buflen < total)
        return (NTSTATUS)0xC0000004; /* STATUS_INFO_LENGTH_MISMATCH */

    memset(buf, 0, total);
    char *ptr = (char *)buf;
    ULONG name_data_offset = 184; /* name data starts after fixed fields */

    for (int i = 0; g_fake_processes[i].name; i++) {
        const fake_process_t *fp = &g_fake_processes[i];
        int is_last = (g_fake_processes[i + 1].name == NULL && 1 /* game entry follows */);

        /* NextEntryOffset at offset 0 */
        *(ULONG *)ptr = is_last ? 0 : entry_size;

        /* NumberOfThreads at offset 4 */
        *(ULONG *)(ptr + 4) = fp->threads;

        /* CreateTime at offset 8 (LARGE_INTEGER) - plausible boot time */
        *(int64_t *)(ptr + 8) = 132800000000000000LL + (int64_t)fp->pid * 100000LL;

        /* UserTime at offset 24 */
        *(int64_t *)(ptr + 24) = (int64_t)fp->threads * 15600100LL;

        /* KernelTime at offset 32 */
        *(int64_t *)(ptr + 32) = (int64_t)fp->threads * 7800050LL;

        /* UniqueProcessId at offset 80 */
        *(ULONG_PTR *)(ptr + 80) = (ULONG_PTR)fp->pid;

        /* InheritedFromUniqueProcessId at offset 88 */
        *(ULONG_PTR *)(ptr + 88) = (ULONG_PTR)fp->ppid;

        /* HandleCount at offset 96 */
        *(ULONG *)(ptr + 96) = fp->threads * 15 + 40;

        /* SessionId at offset 100 */
        *(ULONG *)(ptr + 100) = fp->session_id;

        /* WorkingSetSize at offset 112 */
        *(ULONG_PTR *)(ptr + 112) = (ULONG_PTR)(fp->threads * 2048 * 1024);

        /* VirtualSize at offset 120 */
        *(ULONG_PTR *)(ptr + 120) = (ULONG_PTR)(fp->threads * 32ULL * 1024 * 1024);

        /* ImageName UNICODE_STRING */
        spi_write_name(ptr, name_data_offset, fp->name);

        /* NextEntryOffset: if this is NOT the last fake proc, chain */
        if (g_fake_processes[i + 1].name != NULL) {
            *(ULONG *)ptr = entry_size;
        } else {
            /* Last fake entry chains to game entry */
            *(ULONG *)ptr = entry_size;
        }

        ptr += entry_size;
    }

    /* Final entry: the actual game process */
    *(ULONG *)ptr = 0; /* Last entry */
    *(ULONG *)(ptr + 4) = 4; /* threads */
    *(ULONG_PTR *)(ptr + 80) = (ULONG_PTR)getpid();
    *(ULONG_PTR *)(ptr + 88) = 3376; /* parent = explorer.exe */
    *(ULONG *)(ptr + 96) = 120; /* handles */
    *(ULONG *)(ptr + 100) = 1; /* session 1 */
    *(ULONG_PTR *)(ptr + 112) = 256 * 1024 * 1024; /* 256MB working set */

    /* Read our own executable name */
    char exename[256] = "game.exe";
    char exepath[512];
    ssize_t elen = readlink("/proc/self/exe", exepath, sizeof(exepath) - 1);
    if (elen > 0) {
        exepath[elen] = '\0';
        const char *slash = strrchr(exepath, '/');
        if (slash) strncpy(exename, slash + 1, sizeof(exename) - 1);
    }
    spi_write_name(ptr, name_data_offset, exename);

    return STATUS_SUCCESS;
}

/* Kernel module information: what ntoskrnl reports for lm/modules */
typedef struct {
    const char *name;
    uint64_t    base;
    uint32_t    size;
} fake_kmod_t;

static const fake_kmod_t g_fake_kmods[] = {
    { "\\SystemRoot\\system32\\ntoskrnl.exe",       0xFFFFF80000000000ULL, 0x00A00000 },
    { "\\SystemRoot\\system32\\hal.dll",            0xFFFFF80000A00000ULL, 0x00080000 },
    { "\\SystemRoot\\system32\\kd.dll",             0xFFFFF80000A80000ULL, 0x00020000 },
    { "\\SystemRoot\\system32\\mcupdate_GenuineIntel.dll", 0xFFFFF80000B00000ULL, 0x00300000 },
    { "\\SystemRoot\\system32\\PSHED.dll",          0xFFFFF80001000000ULL, 0x00020000 },
    { "\\SystemRoot\\system32\\CLFS.SYS",           0xFFFFF80001020000ULL, 0x00080000 },
    { "\\SystemRoot\\system32\\CI.dll",             0xFFFFF80001100000ULL, 0x000C0000 },
    { "\\SystemRoot\\system32\\drivers\\Wdf01000.sys",  0xFFFFF80001200000ULL, 0x000A0000 },
    { "\\SystemRoot\\system32\\drivers\\WDFLDR.SYS",    0xFFFFF800012A0000ULL, 0x00020000 },
    { "\\SystemRoot\\system32\\drivers\\acpi.sys",      0xFFFFF80001300000ULL, 0x00080000 },
    { "\\SystemRoot\\system32\\drivers\\WMILIB.SYS",    0xFFFFF80001380000ULL, 0x00010000 },
    { "\\SystemRoot\\system32\\drivers\\pci.sys",       0xFFFFF80001400000ULL, 0x00060000 },
    { "\\SystemRoot\\system32\\drivers\\ndis.sys",      0xFFFFF80001500000ULL, 0x00180000 },
    { "\\SystemRoot\\system32\\drivers\\NETIO.SYS",     0xFFFFF80001700000ULL, 0x000A0000 },
    { "\\SystemRoot\\system32\\drivers\\tcpip.sys",     0xFFFFF80001800000ULL, 0x00400000 },
    { "\\SystemRoot\\system32\\drivers\\fwpkclnt.sys",  0xFFFFF80001C00000ULL, 0x00080000 },
    { "\\SystemRoot\\System32\\drivers\\dxgkrnl.sys",   0xFFFFF80002000000ULL, 0x00300000 },
    { "\\SystemRoot\\System32\\win32kfull.sys",         0xFFFFF80002400000ULL, 0x00400000 },
    { "\\SystemRoot\\System32\\win32kbase.sys",         0xFFFFF80002800000ULL, 0x00200000 },
    { "\\SystemRoot\\system32\\drivers\\volmgr.sys",    0xFFFFF80002A00000ULL, 0x00020000 },
    { "\\SystemRoot\\system32\\drivers\\mountmgr.sys",  0xFFFFF80002A20000ULL, 0x00030000 },
    { "\\SystemRoot\\system32\\drivers\\intelppm.sys",  0xFFFFF80002B00000ULL, 0x00020000 },
    { NULL, 0, 0 }
};

/*
 * RTL_PROCESS_MODULE_INFORMATION is 284 bytes on x64:
 *   HANDLE Section;           // 0    (8 bytes)
 *   PVOID MappedBase;         // 8    (8 bytes)
 *   PVOID ImageBase;          // 16   (8 bytes)
 *   ULONG ImageSize;          // 24   (4 bytes)
 *   ULONG Flags;              // 28   (4 bytes)
 *   USHORT LoadOrderIndex;    // 32   (2 bytes)
 *   USHORT InitOrderIndex;    // 34   (2 bytes)
 *   USHORT LoadCount;         // 36   (2 bytes)
 *   USHORT OffsetToFileName;  // 38   (2 bytes)
 *   CHAR FullPathName[256];   // 40   (256 bytes)
 *   Total: 296 bytes
 */
#define KMOD_ENTRY_SIZE 296

static NTSTATUS fill_system_module_info(PVOID buf, ULONG buflen, PULONG ret)
{
    int nmod = 0;
    for (int i = 0; g_fake_kmods[i].name; i++)
        nmod++;

    /* 4 bytes for NumberOfModules + entries */
    ULONG total = 4 + (ULONG)(nmod * KMOD_ENTRY_SIZE);
    if (ret) *ret = total;
    if (!buf || buflen < total)
        return (NTSTATUS)0xC0000004;

    memset(buf, 0, total);
    *(ULONG *)buf = (ULONG)nmod;

    char *ptr = (char *)buf + 4;
    for (int i = 0; i < nmod; i++) {
        const fake_kmod_t *km = &g_fake_kmods[i];

        /* ImageBase at offset 16 */
        *(uint64_t *)(ptr + 16) = km->base;
        /* ImageSize at offset 24 */
        *(ULONG *)(ptr + 24) = km->size;
        /* Flags at offset 28 */
        *(ULONG *)(ptr + 28) = 0x08004000; /* LDRP_IMAGE_DLL | LDRP_ENTRY_PROCESSED */
        /* LoadOrderIndex at offset 32 */
        *(USHORT *)(ptr + 32) = (USHORT)i;
        /* LoadCount at offset 36 */
        *(USHORT *)(ptr + 36) = 1;

        /* FullPathName at offset 40, max 256 chars (null-terminated) */
        strncpy(ptr + 40, km->name, 255);
        ptr[40 + 255] = '\0';

        /* OffsetToFileName at offset 38 - find last backslash */
        const char *fname = strrchr(km->name, '\\');
        if (fname)
            *(USHORT *)(ptr + 38) = (USHORT)(fname - km->name + 1);
        else
            *(USHORT *)(ptr + 38) = 0;

        ptr += KMOD_ENTRY_SIZE;
    }

    return STATUS_SUCCESS;
}

/* Fake handle table: typical Windows system handle set */
static NTSTATUS fill_system_handle_info(PVOID buf, ULONG buflen, PULONG ret)
{
    /*
     * SYSTEM_HANDLE_INFORMATION:
     *   ULONG NumberOfHandles;
     *   SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[];
     *
     * Each entry is 24 bytes on x64:
     *   USHORT UniqueProcessId;    // 0
     *   USHORT CreatorBackTraceIndex; // 2
     *   UCHAR ObjectTypeIndex;     // 4
     *   UCHAR HandleAttributes;    // 5
     *   USHORT HandleValue;        // 6
     *   PVOID Object;              // 8  (8 bytes)
     *   ULONG GrantedAccess;       // 16 (4 bytes)
     *   // pad to 24
     */
    #define HANDLE_ENTRY_SIZE 24

    /* Generate a reasonable number of handles for system processes */
    struct { USHORT pid; UCHAR type; USHORT handle; ULONG access; } fake_handles[] = {
        {   4, 0x05, 0x0004, 0x001F0003 }, /* System - Event */
        {   4, 0x24, 0x0008, 0x001F0003 }, /* System - File */
        {   4, 0x02, 0x000C, 0x001F0001 }, /* System - Thread */
        { 668, 0x05, 0x0004, 0x001F0003 }, /* services.exe - Event */
        { 668, 0x28, 0x0008, 0x000F003F }, /* services.exe - Key */
        { 688, 0x05, 0x0004, 0x001F0003 }, /* lsass.exe - Event */
        { 688, 0x24, 0x0010, 0x00120089 }, /* lsass.exe - File */
        { 816, 0x05, 0x0004, 0x001F0003 }, /* svchost.exe - Event */
        { 816, 0x02, 0x0028, 0x001F0FFF }, /* svchost.exe - Thread */
        {1600, 0x05, 0x0004, 0x001F0003 }, /* dwm.exe - Event */
        {3376, 0x05, 0x0004, 0x001F0003 }, /* explorer.exe - Event */
        {3376, 0x24, 0x0014, 0x00120089 }, /* explorer.exe - File */
        {3376, 0x28, 0x0018, 0x000F003F }, /* explorer.exe - Key */
        {3376, 0x02, 0x0030, 0x001F0FFF }, /* explorer.exe - Thread */
    };
    int nhandles = sizeof(fake_handles) / sizeof(fake_handles[0]);

    ULONG total = 4 + (ULONG)(nhandles * HANDLE_ENTRY_SIZE);
    if (ret) *ret = total;
    if (!buf || buflen < total)
        return (NTSTATUS)0xC0000004;

    memset(buf, 0, total);
    *(ULONG *)buf = (ULONG)nhandles;

    char *ptr = (char *)buf + 4;
    for (int i = 0; i < nhandles; i++) {
        *(USHORT *)(ptr + 0) = fake_handles[i].pid;
        *(UCHAR *)(ptr + 4)  = fake_handles[i].type;
        *(USHORT *)(ptr + 6) = fake_handles[i].handle;
        *(uint64_t *)(ptr + 8) = 0xFFFFFA8000000000ULL + (uint64_t)i * 0x1000;
        *(ULONG *)(ptr + 16) = fake_handles[i].access;
        ptr += HANDLE_ENTRY_SIZE;
    }

    return STATUS_SUCCESS;
}

/* SystemFirmwareTableInformation - SMBIOS data that anti-cheats read */
static NTSTATUS fill_firmware_table_info(PVOID buf, ULONG buflen, PULONG ret)
{
    /*
     * Anti-cheats read SMBIOS tables to get hardware serial numbers,
     * manufacturer info, etc. for hardware banning. We provide plausible
     * data that looks like a real gaming PC.
     */
    /* Minimal SMBIOS header + BIOS info */
    unsigned char smbios[] = {
        /* Header */
        0x00, 0x00, 0x00, 0x00,  /* Action (query) */
        'R', 'S', 'M', 'B',     /* ProviderSignature = RSMB */
        0x00, 0x00, 0x00, 0x00,  /* TableID */
        0x00, 0x01, 0x00, 0x00,  /* TableBufferLength */
        /* SMBIOS entry point */
        0x03, 0x01,              /* Major/Minor version (3.1) */
        /* Type 0: BIOS Information */
        0x00, 0x1A, 0x00, 0x00,  /* Type=0, Length=26, Handle=0 */
        0x01, 0x02, 0x00, 0xF0,  /* Vendor(1), Version(2), StartSegment */
        0x03, 0x08, 0x00, 0x00,  /* ReleaseDate(3), RomSize, Characteristics */
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x0F,
        0x03, 0x0C, 0xFF, 0xFF,
        0x01, 0x01,
        /* Strings */
        'A', 'M', 'I', 0x00,                              /* String 1: Vendor */
        'F', '2', '0', 0x00,                               /* String 2: Version */
        '0', '1', '/', '1', '5', '/', '2', '0', '2', '4', 0x00, /* String 3: Date */
        0x00,  /* End of strings */
        /* Type 1: System Information */
        0x01, 0x1B, 0x01, 0x00,  /* Type=1, Length=27, Handle=1 */
        0x01, 0x02, 0x03, 0x04,
        /* UUID - random but fixed */
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x17, 0x28,
        0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F, 0xA0,
        0x06, 0x05, 0x04,
        /* Strings */
        'A', 'S', 'U', 'S', 0x00,                         /* Manufacturer */
        'R', 'O', 'G', ' ', 'S', 'T', 'R', 'I', 'X', 0x00, /* Product */
        'R', 'e', 'v', ' ', '1', '.', '0', 0x00,          /* Version */
        'S', 'N', '1', '2', '3', '4', '5', '6', 0x00,    /* Serial */
        0x00,  /* End of strings */
    };

    ULONG total = sizeof(smbios);
    if (ret) *ret = total;
    if (!buf || buflen < total)
        return (NTSTATUS)0xC0000004;

    memcpy(buf, smbios, total);
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    switch (SystemInformationClass) {
    case 0: /* SystemBasicInformation */ {
        if (SystemInformation && SystemInformationLength >= 64) {
            memset(SystemInformation, 0, 64);
            /* PageSize at offset 4 */
            *(ULONG *)((char *)SystemInformation + 4) = 4096;
            /* MinimumUserModeAddress at offset 16 */
            *(ULONG_PTR *)((char *)SystemInformation + 16) = 0x10000;
            /* MaximumUserModeAddress at offset 24 */
            *(ULONG_PTR *)((char *)SystemInformation + 24) = 0x00007FFFFFFEFFFFULL;
            /* ActiveProcessorsAffinityMask at offset 32 */
            long nproc = sysconf(_SC_NPROCESSORS_ONLN);
            if (nproc < 1) nproc = 1;
            if (nproc > 64) nproc = 64;
            *(ULONG_PTR *)((char *)SystemInformation + 32) = ((ULONG_PTR)1 << nproc) - 1;
            /* NumberOfProcessors at offset 40 */
            *(ULONG *)((char *)SystemInformation + 40) = (ULONG)nproc;
        }
        if (ReturnLength) *ReturnLength = 64;
        return STATUS_SUCCESS;
    }

    case 1: { /* SystemProcessorInformation */
        if (SystemInformation && SystemInformationLength >= 12) {
            memset(SystemInformation, 0, 12);
            *(USHORT *)SystemInformation = 9;       /* ProcessorArchitecture = AMD64 */
            *(USHORT *)((char *)SystemInformation + 2) = 0; /* ProcessorLevel */
            *(USHORT *)((char *)SystemInformation + 4) = 0; /* ProcessorRevision */
            *(USHORT *)((char *)SystemInformation + 6) = 0; /* MaximumProcessors */
            *(ULONG *)((char *)SystemInformation + 8) = 0x00040651; /* ProcessorFeatureBits */
        }
        if (ReturnLength) *ReturnLength = 12;
        return STATUS_SUCCESS;
    }

    case 2: { /* SystemPerformanceInformation */
        if (SystemInformation && SystemInformationLength >= 312) {
            memset(SystemInformation, 0, 312);
            /* AvailablePages at offset 8 */
            *(ULONG_PTR *)((char *)SystemInformation + 8) = 2 * 1024 * 1024; /* ~8GB free */
            /* CommittedPages at offset 16 */
            *(ULONG_PTR *)((char *)SystemInformation + 16) = 1 * 1024 * 1024; /* ~4GB committed */
            /* CommitLimit at offset 24 */
            *(ULONG_PTR *)((char *)SystemInformation + 24) = 4 * 1024 * 1024; /* ~16GB limit */
        }
        if (ReturnLength) *ReturnLength = 312;
        return STATUS_SUCCESS;
    }

    case 3: { /* SystemTimeOfDayInformation */
        if (SystemInformation && SystemInformationLength >= 48) {
            memset(SystemInformation, 0, 48);
            /* BootTime at offset 0 - about 2 hours ago in Windows FILETIME */
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            int64_t now_ft = (int64_t)ts.tv_sec * 10000000LL + 116444736000000000LL;
            *(int64_t *)SystemInformation = now_ft - 72000000000LL; /* boot 2h ago */
            /* CurrentTime at offset 8 */
            *(int64_t *)((char *)SystemInformation + 8) = now_ft;
            /* TimeZoneBias at offset 16 */
            *(int64_t *)((char *)SystemInformation + 16) = 0;
            /* CurrentTimeZoneId at offset 24 */
            *(ULONG *)((char *)SystemInformation + 24) = 2; /* TIME_ZONE_ID_DAYLIGHT */
        }
        if (ReturnLength) *ReturnLength = 48;
        return STATUS_SUCCESS;
    }

    case 5: /* SystemProcessInformation */
        return fill_system_process_info(SystemInformation, SystemInformationLength, ReturnLength);

    case 8: { /* SystemProcessorPerformanceInformation */
        long nproc = sysconf(_SC_NPROCESSORS_ONLN);
        if (nproc < 1) nproc = 1;
        ULONG size = (ULONG)(nproc * 48);
        if (SystemInformation && SystemInformationLength >= size)
            memset(SystemInformation, 0, size);
        if (ReturnLength) *ReturnLength = size;
        return STATUS_SUCCESS;
    }

    case 11: /* SystemModuleInformation */
        return fill_system_module_info(SystemInformation, SystemInformationLength, ReturnLength);

    case 16: /* SystemHandleInformation */
        return fill_system_handle_info(SystemInformation, SystemInformationLength, ReturnLength);

    case 23: { /* SystemInterruptInformation */
        long nproc = sysconf(_SC_NPROCESSORS_ONLN);
        if (nproc < 1) nproc = 1;
        ULONG size = (ULONG)(nproc * 24);
        if (SystemInformation && SystemInformationLength >= size)
            memset(SystemInformation, 0, size);
        if (ReturnLength) *ReturnLength = size;
        return STATUS_SUCCESS;
    }

    case 35: /* SystemKernelDebuggerInformation */
        if (SystemInformation && SystemInformationLength >= 2) {
            ((unsigned char *)SystemInformation)[0] = 0; /* Enabled = FALSE */
            ((unsigned char *)SystemInformation)[1] = 1; /* NotPresent = TRUE */
        }
        if (ReturnLength) *ReturnLength = 2;
        return STATUS_SUCCESS;

    case 44: /* SystemKernelDebuggerInformationEx */
        if (SystemInformation && SystemInformationLength >= 4) {
            memset(SystemInformation, 0, 4);
            ((unsigned char *)SystemInformation)[1] = 1; /* NotPresent = TRUE */
        }
        if (ReturnLength) *ReturnLength = 4;
        return STATUS_SUCCESS;

    case 51: /* SystemCodeIntegrityInformation */
        if (SystemInformation && SystemInformationLength >= 8) {
            memset(SystemInformation, 0, 8);
            *(ULONG *)SystemInformation = 8; /* Length */
            /* CI enabled | TESTSIGN off | FLIGHTSIGN off */
            *(ULONG *)((char *)SystemInformation + 4) = 0x01;
        }
        if (ReturnLength) *ReturnLength = 8;
        return STATUS_SUCCESS;

    case 64: { /* SystemHandleInformationEx (extended, 40-byte entries) */
        /* Same as class 16 but with 40-byte entries instead of 24 */
        ULONG total = 8; /* NumberOfHandles (ULONG_PTR) */
        if (ReturnLength) *ReturnLength = total;
        if (SystemInformation && SystemInformationLength >= total) {
            memset(SystemInformation, 0, total);
            /* 0 handles in extended query */
        }
        return STATUS_SUCCESS;
    }

    case 76: /* SystemFirmwareTableInformation */
        return fill_firmware_table_info(SystemInformation, SystemInformationLength, ReturnLength);

    case 103: { /* SystemSecureBootInformation */
        if (SystemInformation && SystemInformationLength >= 2) {
            ((unsigned char *)SystemInformation)[0] = 1; /* SecureBootEnabled = TRUE */
            ((unsigned char *)SystemInformation)[1] = 1; /* SecureBootCapable = TRUE */
        }
        if (ReturnLength) *ReturnLength = 2;
        return STATUS_SUCCESS;
    }

    case 196: { /* SystemCodeIntegrityUnlockInformation */
        if (SystemInformation && SystemInformationLength >= 4) {
            memset(SystemInformation, 0, 4);
            /* UnlockId = 0 (locked, CI enforced) */
        }
        if (ReturnLength) *ReturnLength = 4;
        return STATUS_SUCCESS;
    }

    default:
        /* For unknown classes, return success with zeroed data if buffer provided.
         * This prevents anti-cheats from detecting unsupported classes. */
        if (SystemInformation && SystemInformationLength > 0) {
            ULONG fill = SystemInformationLength < 4096 ? SystemInformationLength : 4096;
            memset(SystemInformation, 0, fill);
        }
        if (ReturnLength) *ReturnLength = 0;
        return STATUS_SUCCESS;
    }
}

/* Forward-declare heap functions from ntdll_memory.c for consistency */
extern PVOID RtlAllocateHeap(HANDLE, ULONG, SIZE_T) __attribute__((ms_abi));
extern BOOL  RtlFreeHeap(HANDLE, ULONG, PVOID)      __attribute__((ms_abi));
extern HANDLE GetProcessHeap(void)                    __attribute__((ms_abi));

/* RtlFreeUnicodeString - frees Buffer allocated by conversion functions */
WINAPI_EXPORT void RtlFreeUnicodeString(PUNICODE_STRING UnicodeString)
{
    if (UnicodeString && UnicodeString->Buffer) {
        RtlFreeHeap(GetProcessHeap(), 0, UnicodeString->Buffer);
        UnicodeString->Buffer = NULL;
        UnicodeString->Length = 0;
        UnicodeString->MaximumLength = 0;
    }
}

/* RtlFreeAnsiString - frees Buffer allocated by conversion functions */
WINAPI_EXPORT void RtlFreeAnsiString(PANSI_STRING AnsiString)
{
    if (AnsiString && AnsiString->Buffer) {
        RtlFreeHeap(GetProcessHeap(), 0, AnsiString->Buffer);
        AnsiString->Buffer = NULL;
        AnsiString->Length = 0;
        AnsiString->MaximumLength = 0;
    }
}

/* RtlUnicodeStringToAnsiString - convert uint16_t UTF-16LE to narrow char */
WINAPI_EXPORT NTSTATUS RtlUnicodeStringToAnsiString(
    PANSI_STRING DestinationString,
    PUNICODE_STRING SourceString,
    BOOLEAN AllocateDestinationString)
{
    if (!DestinationString || !SourceString)
        return STATUS_INVALID_PARAMETER;

    USHORT wchar_count = SourceString->Length / sizeof(WCHAR);
    USHORT ansi_len = wchar_count;              /* 1 byte per char (truncating conversion) */
    USHORT buf_size = ansi_len + 1;             /* room for null terminator */

    if (AllocateDestinationString) {
        PSTR buf = (PSTR)RtlAllocateHeap(GetProcessHeap(), 0, buf_size);
        if (!buf)
            return STATUS_NO_MEMORY;
        DestinationString->Buffer = buf;
        DestinationString->MaximumLength = buf_size;
    } else {
        if (buf_size > DestinationString->MaximumLength)
            return STATUS_BUFFER_OVERFLOW;
    }

    /* Truncating conversion: take low byte of each uint16_t */
    const uint16_t *src = (const uint16_t *)SourceString->Buffer;
    USHORT i;
    for (i = 0; i < wchar_count; i++)
        DestinationString->Buffer[i] = (char)(src[i] & 0xFF);
    DestinationString->Buffer[wchar_count] = '\0';
    DestinationString->Length = ansi_len;

    return STATUS_SUCCESS;
}

/* RtlAnsiStringToUnicodeString - convert narrow char to uint16_t UTF-16LE */
WINAPI_EXPORT NTSTATUS RtlAnsiStringToUnicodeString(
    PUNICODE_STRING DestinationString,
    PANSI_STRING SourceString,
    BOOLEAN AllocateDestinationString)
{
    if (!DestinationString || !SourceString)
        return STATUS_INVALID_PARAMETER;

    USHORT ansi_len = SourceString->Length;
    USHORT byte_len = ansi_len * sizeof(WCHAR);            /* Length in bytes */
    USHORT buf_bytes = byte_len + sizeof(WCHAR);            /* + null terminator (2 bytes) */

    if (AllocateDestinationString) {
        PWSTR buf = (PWSTR)RtlAllocateHeap(GetProcessHeap(), 0, buf_bytes);
        if (!buf)
            return STATUS_NO_MEMORY;
        DestinationString->Buffer = buf;
        DestinationString->MaximumLength = buf_bytes;
    } else {
        if (buf_bytes > DestinationString->MaximumLength)
            return STATUS_BUFFER_OVERFLOW;
    }

    /* Widening conversion: zero-extend each byte to uint16_t */
    const unsigned char *src = (const unsigned char *)SourceString->Buffer;
    USHORT i;
    for (i = 0; i < ansi_len; i++)
        DestinationString->Buffer[i] = (uint16_t)src[i];
    DestinationString->Buffer[ansi_len] = 0;
    DestinationString->Length = byte_len;

    return STATUS_SUCCESS;
}

/* RtlCompareUnicodeString - case-sensitive or case-insensitive compare */
WINAPI_EXPORT LONG RtlCompareUnicodeString(
    PUNICODE_STRING String1,
    PUNICODE_STRING String2,
    BOOLEAN CaseInSensitive)
{
    if (!String1 || !String2)
        return String1 ? 1 : (String2 ? -1 : 0);

    USHORT len1 = String1->Length / sizeof(WCHAR);
    USHORT len2 = String2->Length / sizeof(WCHAR);
    USHORT min_len = len1 < len2 ? len1 : len2;
    const uint16_t *s1 = (const uint16_t *)String1->Buffer;
    const uint16_t *s2 = (const uint16_t *)String2->Buffer;

    USHORT i;
    for (i = 0; i < min_len; i++) {
        uint16_t c1 = s1[i];
        uint16_t c2 = s2[i];
        if (CaseInSensitive) {
            if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
            if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
        }
        if (c1 != c2)
            return (LONG)c1 - (LONG)c2;
    }

    return (LONG)len1 - (LONG)len2;
}

/* RtlEqualUnicodeString - boolean equality check */
WINAPI_EXPORT BOOLEAN RtlEqualUnicodeString(
    PUNICODE_STRING String1,
    PUNICODE_STRING String2,
    BOOLEAN CaseInSensitive)
{
    if (!String1 || !String2)
        return (!String1 && !String2);
    if (String1->Length != String2->Length)
        return FALSE;
    return RtlCompareUnicodeString(String1, String2, CaseInSensitive) == 0;
}

/* RtlCopyUnicodeString */
WINAPI_EXPORT void RtlCopyUnicodeString(
    PUNICODE_STRING DestinationString,
    PUNICODE_STRING SourceString)
{
    if (!DestinationString)
        return;
    if (!SourceString || !SourceString->Buffer || SourceString->Length == 0) {
        DestinationString->Length = 0;
        return;
    }

    USHORT copy_len = SourceString->Length;
    if (copy_len > DestinationString->MaximumLength)
        copy_len = DestinationString->MaximumLength;
    memcpy(DestinationString->Buffer, SourceString->Buffer, copy_len);
    DestinationString->Length = copy_len;

    /* Null-terminate if space allows */
    if (copy_len + sizeof(WCHAR) <= DestinationString->MaximumLength)
        DestinationString->Buffer[copy_len / sizeof(WCHAR)] = 0;
}

/* ---------- LdrLoadDll ----------
 * NT native DLL loading. MSVC CRT startup calls this to load api-ms-win-* DLLs.
 * Without this, the CRT falls back to LoadLibraryA with wide strings → garbled names.
 */

/* Forward declaration of kernel32 LoadLibraryW (in same process) */
extern HMODULE LoadLibraryW(LPCWSTR lpLibFileName) __attribute__((ms_abi));
extern HMODULE LoadLibraryA(LPCSTR lpLibFileName) __attribute__((ms_abi));
extern FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName) __attribute__((ms_abi));

WINAPI_EXPORT NTSTATUS LdrLoadDll(
    PWSTR PathToFile,
    ULONG *Flags,
    PUNICODE_STRING ModuleFileName,
    HANDLE *ModuleHandle)
{
    (void)PathToFile;
    (void)Flags;

    if (!ModuleFileName || !ModuleFileName->Buffer || !ModuleHandle) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Convert UNICODE_STRING to narrow for LoadLibraryA */
    int wlen = ModuleFileName->Length / sizeof(WCHAR);
    char narrow[512];
    int i;
    for (i = 0; i < wlen && i < 511; i++)
        narrow[i] = (char)(ModuleFileName->Buffer[i] & 0xFF);
    narrow[i] = '\0';

    HMODULE h = LoadLibraryA(narrow);
    if (h) {
        *ModuleHandle = (HANDLE)h;
        return STATUS_SUCCESS;
    }

    *ModuleHandle = NULL;
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

/* LdrGetDllHandle - look up already-loaded DLL */
WINAPI_EXPORT NTSTATUS LdrGetDllHandle(
    PWSTR DllPath,
    PULONG DllCharacteristics,
    PUNICODE_STRING DllName,
    HANDLE *DllHandle)
{
    (void)DllPath;
    (void)DllCharacteristics;

    if (!DllName || !DllName->Buffer || !DllHandle)
        return STATUS_INVALID_PARAMETER;

    /* Convert UNICODE_STRING to narrow */
    int wlen = DllName->Length / sizeof(WCHAR);
    char narrow[512];
    int i;
    for (i = 0; i < wlen && i < 511; i++)
        narrow[i] = (char)(DllName->Buffer[i] & 0xFF);
    narrow[i] = '\0';

    /* Use GetModuleHandleA-style lookup via LoadLibraryA (returns existing if cached) */
    HMODULE h = LoadLibraryA(narrow);
    if (h) {
        *DllHandle = (HANDLE)h;
        return STATUS_SUCCESS;
    }

    *DllHandle = NULL;
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

/* LdrGetProcedureAddress - look up function in loaded DLL */
WINAPI_EXPORT NTSTATUS LdrGetProcedureAddress(
    HANDLE ModuleHandle,
    PANSI_STRING FunctionName,
    WORD Ordinal,
    PVOID *FunctionAddress)
{
    if (!FunctionAddress)
        return STATUS_INVALID_PARAMETER;

    LPCSTR name = NULL;
    if (FunctionName && FunctionName->Buffer && FunctionName->Length > 0) {
        name = FunctionName->Buffer;
    } else {
        /* Ordinal lookup */
        name = (LPCSTR)(uintptr_t)Ordinal;
    }

    FARPROC proc = GetProcAddress((HMODULE)ModuleHandle, name);
    if (proc) {
        *FunctionAddress = (PVOID)proc;
        return STATUS_SUCCESS;
    }

    *FunctionAddress = NULL;
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

/* DbgPrint - kernel debug print (used by some CRT init code)
 * Must use __builtin_ms_va_list since this is ms_abi but vfprintf expects sysv_abi va_list. */
WINAPI_EXPORT ULONG DbgPrint(const char *Format, ...)
{
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, Format);
    int ret = ms_abi_vformat(stderr, NULL, 0, Format, args);
    __builtin_ms_va_end(args);
    return (ULONG)ret;
}

/* NtCurrentTeb - get Thread Environment Block */
WINAPI_EXPORT PTEB NtCurrentTeb(void)
{
    /* Use the thread-local TEB from env_setup.c */
    void *teb = env_get_teb();
    if (teb)
        return (PTEB)teb;

    /* Fallback: shouldn't happen after env_setup_init */
    static __thread TEB fallback_teb;
    static PEB fallback_peb;
    fallback_teb.ProcessEnvironmentBlock = &fallback_peb;
    return &fallback_teb;
}

/* NtQueryInformationThread - return TEB address for ThreadBasicInformation */
WINAPI_EXPORT NTSTATUS NtQueryInformationThread(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength)
{
    (void)ThreadHandle;
    (void)ThreadInformationLength;

    switch (ThreadInformationClass) {
    case 0: { /* ThreadBasicInformation */
        /* THREAD_BASIC_INFORMATION:
         *   NTSTATUS ExitStatus;       // offset 0
         *   PVOID    TebBaseAddress;   // offset 8
         *   CLIENT_ID ClientId;        // offset 16 (UniqueProcess + UniqueThread = 16 bytes)
         *   KAFFINITY AffinityMask;    // offset 32
         *   KPRIORITY Priority;        // offset 40
         *   KPRIORITY BasePriority;    // offset 44
         *   Total: 48 bytes
         */
        if (ThreadInformation) {
            memset(ThreadInformation, 0, 48);
            void *teb = env_get_teb();
            /* TebBaseAddress at offset 8 */
            *(uint64_t *)((char *)ThreadInformation + 8) =
                teb ? (uint64_t)(uintptr_t)teb : 0;
            /* ClientId at offset 16 */
            *(uint64_t *)((char *)ThreadInformation + 16) =
                (uint64_t)(uintptr_t)getpid();
            *(uint64_t *)((char *)ThreadInformation + 24) =
                (uint64_t)(uintptr_t)pthread_self();
        }
        if (ReturnLength)
            *ReturnLength = 48;
        return STATUS_SUCCESS;
    }
    default:
        return STATUS_NOT_IMPLEMENTED;
    }
}
