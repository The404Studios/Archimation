/*
 * ntoskrnl_mm.c - Memory Manager stubs for ntoskrnl.exe
 *
 * Pool allocation (ExAllocatePoolWithTag, etc.) and MDL management.
 * In userspace, all pool types map to malloc/free.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/dll_common.h"
#include "win32/wdm.h"

#define LOG_PREFIX "[ntoskrnl/mm] "

/* ===== Pool Allocation ===== */

WINAPI_EXPORT PVOID ExAllocatePoolWithTag(
    POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag)
{
    (void)PoolType;
    (void)Tag;
    return calloc(1, NumberOfBytes);
}

WINAPI_EXPORT PVOID ExAllocatePool(POOL_TYPE PoolType, SIZE_T NumberOfBytes)
{
    return ExAllocatePoolWithTag(PoolType, NumberOfBytes, 0);
}

WINAPI_EXPORT PVOID ExAllocatePool2(
    ULONGLONG Flags, SIZE_T NumberOfBytes, ULONG Tag)
{
    (void)Flags;
    (void)Tag;
    return calloc(1, NumberOfBytes);
}

WINAPI_EXPORT void ExFreePoolWithTag(PVOID P, ULONG Tag)
{
    (void)Tag;
    free(P);
}

WINAPI_EXPORT void ExFreePool(PVOID P)
{
    free(P);
}

/* ===== MDL Management ===== */

WINAPI_EXPORT PMDL IoAllocateMdl(
    PVOID VirtualAddress, ULONG Length,
    BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp)
{
    (void)SecondaryBuffer;
    (void)ChargeQuota;

    PMDL mdl = (PMDL)calloc(1, sizeof(MDL));
    if (!mdl)
        return NULL;

    mdl->StartVa = VirtualAddress;
    mdl->ByteCount = Length;
    mdl->ByteOffset = 0;
    mdl->MappedSystemVa = VirtualAddress;
    mdl->MdlFlags = MDL_SOURCE_IS_NONPAGED_POOL;

    /* Link to IRP if provided */
    if (Irp)
        Irp->MdlAddress = mdl;

    return mdl;
}

WINAPI_EXPORT void IoFreeMdl(PMDL Mdl)
{
    free(Mdl);
}

WINAPI_EXPORT void MmBuildMdlForNonPagedPool(PMDL MemoryDescriptorList)
{
    /* In userspace, all memory is effectively "non-paged" */
    if (MemoryDescriptorList) {
        MemoryDescriptorList->MdlFlags |= MDL_SOURCE_IS_NONPAGED_POOL;
        MemoryDescriptorList->MappedSystemVa = MemoryDescriptorList->StartVa;
    }
}

WINAPI_EXPORT PVOID MmGetSystemAddressForMdlSafe(PMDL Mdl, ULONG Priority)
{
    (void)Priority;
    if (!Mdl)
        return NULL;
    return Mdl->MappedSystemVa ? Mdl->MappedSystemVa : Mdl->StartVa;
}

/* ===== Memory copy/zero helpers ===== */

WINAPI_EXPORT void RtlCopyMemory(void *Destination, const void *Source, SIZE_T Length)
{
    memcpy(Destination, Source, Length);
}

WINAPI_EXPORT void RtlZeroMemory(void *Destination, SIZE_T Length)
{
    memset(Destination, 0, Length);
}

WINAPI_EXPORT void RtlMoveMemory(void *Destination, const void *Source, SIZE_T Length)
{
    memmove(Destination, Source, Length);
}

WINAPI_EXPORT void RtlFillMemory(void *Destination, SIZE_T Length, UCHAR Fill)
{
    memset(Destination, Fill, Length);
}

WINAPI_EXPORT SIZE_T RtlCompareMemory(const void *Source1, const void *Source2, SIZE_T Length)
{
    const UCHAR *s1 = (const UCHAR *)Source1;
    const UCHAR *s2 = (const UCHAR *)Source2;
    SIZE_T i;
    for (i = 0; i < Length; i++) {
        if (s1[i] != s2[i])
            break;
    }
    return i;
}

/* ===== MmMapIoSpace / MmUnmapIoSpace (stubs) ===== */

WINAPI_EXPORT PVOID MmMapIoSpace(
    LARGE_INTEGER PhysicalAddress, SIZE_T NumberOfBytes, ULONG CacheType)
{
    (void)CacheType;
    printf(LOG_PREFIX "MmMapIoSpace: phys=0x%llx size=0x%lx (STUB - returning NULL)\n",
           (unsigned long long)PhysicalAddress.QuadPart, (unsigned long)NumberOfBytes);
    return NULL;
}

WINAPI_EXPORT void MmUnmapIoSpace(PVOID BaseAddress, SIZE_T NumberOfBytes)
{
    (void)BaseAddress;
    (void)NumberOfBytes;
}

/* ===== MmAllocateContiguousMemory (stub) ===== */

WINAPI_EXPORT PVOID MmAllocateContiguousMemory(
    SIZE_T NumberOfBytes, LARGE_INTEGER HighestAcceptableAddress)
{
    (void)HighestAcceptableAddress;
    return calloc(1, NumberOfBytes);
}

WINAPI_EXPORT void MmFreeContiguousMemory(PVOID BaseAddress)
{
    free(BaseAddress);
}
