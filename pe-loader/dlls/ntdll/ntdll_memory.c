/*
 * ntdll_memory.c - NT native memory management
 *
 * NtAllocateVirtualMemory, NtFreeVirtualMemory, NtProtectVirtualMemory, etc.
 * These are the low-level NT APIs that kernel32 VirtualAlloc/Free call into.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <malloc.h>

#include "common/dll_common.h"

/* Memory information structures */
typedef struct {
    PVOID  BaseAddress;
    PVOID  AllocationBase;
    DWORD  AllocationProtect;
    SIZE_T RegionSize;
    DWORD  State;
    DWORD  Protect;
    DWORD  Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

/* Memory information class */
#define MemoryBasicInformation 0

/* Section constants */
#define SEC_COMMIT      0x08000000
#define SEC_IMAGE       0x01000000
#define SEC_RESERVE     0x04000000

/* Win32 protection to Linux mmap prot */
static int win32_prot_to_mmap(DWORD protect)
{
    switch (protect & 0xFF) {
    case PAGE_NOACCESS:          return PROT_NONE;
    case PAGE_READONLY:          return PROT_READ;
    case PAGE_READWRITE:         return PROT_READ | PROT_WRITE;
    case PAGE_WRITECOPY:         return PROT_READ | PROT_WRITE;
    case PAGE_EXECUTE:           return PROT_EXEC;
    case PAGE_EXECUTE_READ:      return PROT_READ | PROT_EXEC;
    case PAGE_EXECUTE_READWRITE: return PROT_READ | PROT_WRITE | PROT_EXEC;
    case PAGE_EXECUTE_WRITECOPY: return PROT_READ | PROT_WRITE | PROT_EXEC;
    default:                     return PROT_READ | PROT_WRITE;
    }
}

WINAPI_EXPORT NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    (void)ProcessHandle;
    (void)ZeroBits;

    if (!BaseAddress || !RegionSize)
        return STATUS_INVALID_PARAMETER;

    size_t size = *RegionSize;
    long page_size = sysconf(_SC_PAGESIZE);
    size = (size + page_size - 1) & ~(page_size - 1);

    int prot = win32_prot_to_mmap(Protect);
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;

    if (*BaseAddress) {
        flags |= MAP_FIXED_NOREPLACE;
    }

    void *addr = *BaseAddress;

    if (AllocationType & MEM_RESERVE) {
        /* Reserve: map with PROT_NONE */
        addr = mmap(addr, size, PROT_NONE, flags, -1, 0);
        if (addr == MAP_FAILED)
            return STATUS_UNSUCCESSFUL;

        if (AllocationType & MEM_COMMIT) {
            /* Reserve + Commit: apply requested protection */
            mprotect(addr, size, prot);
        }
    } else if (AllocationType & MEM_COMMIT) {
        /* Commit only: apply protection to already-reserved region */
        if (addr) {
            mprotect(addr, size, prot);
        } else {
            addr = mmap(NULL, size, prot, flags, -1, 0);
            if (addr == MAP_FAILED)
                return STATUS_UNSUCCESSFUL;
        }
    }

    *BaseAddress = addr;
    *RegionSize = size;
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType)
{
    (void)ProcessHandle;

    if (!BaseAddress || !*BaseAddress)
        return STATUS_INVALID_PARAMETER;

    if (FreeType & MEM_RELEASE) {
        size_t size = *RegionSize;
        if (size == 0) {
            /* Query /proc/self/maps to find the actual mapping size */
            FILE *maps = fopen("/proc/self/maps", "r");
            if (maps) {
                char line[256];
                uintptr_t target = (uintptr_t)*BaseAddress;
                while (fgets(line, sizeof(line), maps)) {
                    uintptr_t start, end;
                    if (sscanf(line, "%lx-%lx", &start, &end) == 2 && start == target) {
                        size = end - start;
                        break;
                    }
                }
                fclose(maps);
            }
            if (size == 0)
                size = 4096; /* Last resort: one page */
        }
        munmap(*BaseAddress, size);
        *BaseAddress = NULL;
        *RegionSize = 0;
    } else if (FreeType & MEM_DECOMMIT) {
        /* Decommit: set PROT_NONE but keep mapping */
        size_t size = *RegionSize;
        if (size > 0)
            mprotect(*BaseAddress, size, PROT_NONE);
    }

    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection)
{
    (void)ProcessHandle;

    if (!BaseAddress || !*BaseAddress || !NumberOfBytesToProtect)
        return STATUS_INVALID_PARAMETER;

    if (OldAccessProtection)
        *OldAccessProtection = PAGE_READWRITE; /* Approximate */

    int prot = win32_prot_to_mmap(NewAccessProtection);
    if (mprotect(*BaseAddress, *NumberOfBytesToProtect, prot) < 0)
        return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength)
{
    (void)ProcessHandle;

    if (MemoryInformationClass != MemoryBasicInformation)
        return STATUS_NOT_IMPLEMENTED;

    if (MemoryInformationLength < sizeof(MEMORY_BASIC_INFORMATION))
        return STATUS_INVALID_PARAMETER;

    MEMORY_BASIC_INFORMATION *mbi = (MEMORY_BASIC_INFORMATION *)MemoryInformation;
    memset(mbi, 0, sizeof(*mbi));

    /*
     * Read /proc/self/maps to find the region containing BaseAddress.
     * This is the most reliable way to query memory state on Linux.
     */
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) {
        /* If /proc is unavailable, return a generic free region */
        mbi->BaseAddress = BaseAddress;
        mbi->RegionSize = 4096;
        mbi->State = 0x10000; /* MEM_FREE */
        mbi->Protect = PAGE_NOACCESS;
        mbi->Type = 0;
        if (ReturnLength)
            *ReturnLength = sizeof(*mbi);
        return STATUS_SUCCESS;
    }

    uintptr_t target = (uintptr_t)BaseAddress;
    char line[512];
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
            continue;

        if (target >= start && target < end) {
            mbi->BaseAddress = (PVOID)start;
            mbi->AllocationBase = (PVOID)start;
            mbi->RegionSize = end - start;
            mbi->State = MEM_COMMIT;
            mbi->Type = 0x20000; /* MEM_PRIVATE */

            /* Convert Linux permissions to Windows protection */
            int r = (perms[0] == 'r');
            int w = (perms[1] == 'w');
            int x = (perms[2] == 'x');

            if (x && w)      mbi->Protect = PAGE_EXECUTE_READWRITE;
            else if (x && r)  mbi->Protect = PAGE_EXECUTE_READ;
            else if (x)       mbi->Protect = PAGE_EXECUTE;
            else if (w)       mbi->Protect = PAGE_READWRITE;
            else if (r)       mbi->Protect = PAGE_READONLY;
            else              mbi->Protect = PAGE_NOACCESS;

            mbi->AllocationProtect = mbi->Protect;
            found = 1;
            break;
        }
    }

    fclose(f);

    if (!found) {
        mbi->BaseAddress = BaseAddress;
        mbi->RegionSize = 4096;
        mbi->State = 0x10000; /* MEM_FREE */
        mbi->Protect = PAGE_NOACCESS;
        mbi->Type = 0;
    }

    if (ReturnLength)
        *ReturnLength = sizeof(*mbi);

    return STATUS_SUCCESS;
}

/* RtlAllocateHeap / RtlFreeHeap - used by MSVCRT and some apps directly */
WINAPI_EXPORT PVOID RtlAllocateHeap(HANDLE HeapHandle, ULONG Flags, SIZE_T Size)
{
    (void)HeapHandle;
    void *ptr;
    SIZE_T alloc_size = Size ? Size : 1; /* Zero-size returns valid pointer */

    if (Flags & HEAP_ZERO_MEMORY)
        ptr = calloc(1, alloc_size);
    else
        ptr = malloc(alloc_size);

    return ptr;
}

WINAPI_EXPORT BOOL RtlFreeHeap(HANDLE HeapHandle, ULONG Flags, PVOID BaseAddress)
{
    (void)HeapHandle;
    (void)Flags;

    if (BaseAddress)
        free(BaseAddress);
    return TRUE;
}

WINAPI_EXPORT PVOID RtlReAllocateHeap(HANDLE HeapHandle, ULONG Flags, PVOID Ptr, SIZE_T Size)
{
    (void)HeapHandle;
    SIZE_T alloc_size = Size ? Size : 1;

    if (!Ptr)
        return RtlAllocateHeap(HeapHandle, Flags, alloc_size);

    SIZE_T old_size = malloc_usable_size(Ptr);
    void *result = realloc(Ptr, alloc_size);
    if (result && (Flags & HEAP_ZERO_MEMORY) && alloc_size > old_size)
        memset((char *)result + old_size, 0, alloc_size - old_size);

    return result;
}

WINAPI_EXPORT SIZE_T RtlSizeHeap(HANDLE HeapHandle, ULONG Flags, PVOID BaseAddress)
{
    (void)HeapHandle;
    (void)Flags;
    if (!BaseAddress) return (SIZE_T)-1;
    return malloc_usable_size(BaseAddress);
}

WINAPI_EXPORT PVOID RtlCreateHeap(ULONG Flags, PVOID HeapBase, SIZE_T ReserveSize,
                                    SIZE_T CommitSize, PVOID Lock, PVOID Parameters)
{
    (void)Flags;
    (void)HeapBase;
    (void)ReserveSize;
    (void)CommitSize;
    (void)Lock;
    (void)Parameters;
    /* Return a non-NULL sentinel; we use libc malloc for all heap ops */
    return (PVOID)(uintptr_t)0xDEADBEEF;
}

WINAPI_EXPORT NTSTATUS RtlDestroyHeap(PVOID HeapHandle)
{
    (void)HeapHandle;
    return STATUS_SUCCESS;
}
