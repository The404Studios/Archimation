/*
 * ndis_stubs.c - NDIS (Network Driver Interface Specification) stubs
 *
 * Minimal NDIS miniport driver support.
 * Enough to let a network driver's DriverEntry succeed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "common/dll_common.h"
#include "win32/wdm.h"

#define LOG_PREFIX "[ndis] "

/* NDIS version */
#define NDIS_MINIPORT_MAJOR_VERSION 6
#define NDIS_MINIPORT_MINOR_VERSION 0

/* NDIS status codes */
#define NDIS_STATUS_SUCCESS             0x00000000
#define NDIS_STATUS_PENDING             0x00000103
#define NDIS_STATUS_FAILURE             0xC0000001
#define NDIS_STATUS_RESOURCES           0xC000009A
#define NDIS_STATUS_NOT_SUPPORTED       0xC00000BB

/* ===== NdisInitializeWrapper ===== */
WINAPI_EXPORT void NdisInitializeWrapper(
    PVOID *NdisWrapperHandle,
    PVOID SystemSpecific1,
    PVOID SystemSpecific2,
    PVOID SystemSpecific3)
{
    (void)SystemSpecific1;
    (void)SystemSpecific2;
    (void)SystemSpecific3;

    /* Return a dummy wrapper handle */
    static int wrapper_handle = 1;
    if (NdisWrapperHandle)
        *NdisWrapperHandle = &wrapper_handle;

    printf(LOG_PREFIX "NdisInitializeWrapper\n");
}

/* ===== NdisTerminateWrapper ===== */
WINAPI_EXPORT void NdisTerminateWrapper(PVOID NdisWrapperHandle, PVOID SystemSpecific)
{
    (void)NdisWrapperHandle;
    (void)SystemSpecific;
    printf(LOG_PREFIX "NdisTerminateWrapper\n");
}

/* ===== NdisMRegisterMiniportDriver ===== */
WINAPI_EXPORT NTSTATUS NdisMRegisterMiniportDriver(
    PVOID DriverObject,
    PVOID RegistryPath,
    PVOID MiniportDriverContext,
    PVOID MiniportDriverCharacteristics,
    PVOID *NdisMiniportDriverHandle)
{
    (void)DriverObject;
    (void)RegistryPath;
    (void)MiniportDriverContext;
    (void)MiniportDriverCharacteristics;

    static int miniport_handle = 2;
    if (NdisMiniportDriverHandle)
        *NdisMiniportDriverHandle = &miniport_handle;

    printf(LOG_PREFIX "NdisMRegisterMiniportDriver\n");
    return NDIS_STATUS_SUCCESS;
}

/* ===== NdisMDeregisterMiniportDriver ===== */
WINAPI_EXPORT void NdisMDeregisterMiniportDriver(PVOID NdisMiniportDriverHandle)
{
    (void)NdisMiniportDriverHandle;
    printf(LOG_PREFIX "NdisMDeregisterMiniportDriver\n");
}

/* ===== Memory allocation ===== */

WINAPI_EXPORT NTSTATUS NdisAllocateMemoryWithTag(
    PVOID *VirtualAddress, ULONG Length, ULONG Tag)
{
    (void)Tag;
    if (!VirtualAddress) return NDIS_STATUS_RESOURCES;
    *VirtualAddress = calloc(1, Length);
    return *VirtualAddress ? NDIS_STATUS_SUCCESS : NDIS_STATUS_RESOURCES;
}

WINAPI_EXPORT void NdisFreeMemory(PVOID VirtualAddress, ULONG Length, ULONG MemoryFlags)
{
    (void)Length;
    (void)MemoryFlags;
    free(VirtualAddress);
}

WINAPI_EXPORT NTSTATUS NdisAllocateMemory(
    PVOID *VirtualAddress, ULONG Length, ULONG MemoryFlags, LARGE_INTEGER HighAddr)
{
    (void)MemoryFlags;
    (void)HighAddr;
    if (!VirtualAddress) return NDIS_STATUS_RESOURCES;
    *VirtualAddress = calloc(1, Length);
    return *VirtualAddress ? NDIS_STATUS_SUCCESS : NDIS_STATUS_RESOURCES;
}

/* ===== NdisMSetAttributesEx ===== */
WINAPI_EXPORT void NdisMSetAttributesEx(
    PVOID MiniportAdapterHandle,
    PVOID MiniportAdapterContext,
    ULONG CheckForHangTimeInSeconds,
    ULONG AttributeFlags,
    ULONG AdapterType)
{
    (void)MiniportAdapterHandle;
    (void)MiniportAdapterContext;
    (void)CheckForHangTimeInSeconds;
    (void)AttributeFlags;
    (void)AdapterType;
    printf(LOG_PREFIX "NdisMSetAttributesEx: flags=0x%x type=%u\n",
           AttributeFlags, AdapterType);
}

/* ===== Packet management (stubs) ===== */

WINAPI_EXPORT void NdisAllocatePacketPool(
    NTSTATUS *Status, PVOID *PoolHandle,
    ULONG NumberOfDescriptors, ULONG ProtocolReservedLength)
{
    (void)NumberOfDescriptors;
    (void)ProtocolReservedLength;
    static int pool = 3;
    *PoolHandle = &pool;
    *Status = NDIS_STATUS_SUCCESS;
}

WINAPI_EXPORT void NdisFreePacketPool(PVOID PoolHandle)
{
    (void)PoolHandle;
}

WINAPI_EXPORT void NdisAllocatePacket(
    NTSTATUS *Status, PVOID *Packet, PVOID PoolHandle)
{
    (void)PoolHandle;
    if (!Status) return;
    if (!Packet) { *Status = NDIS_STATUS_RESOURCES; return; }
    *Packet = calloc(1, 256); /* Dummy packet */
    *Status = *Packet ? NDIS_STATUS_SUCCESS : NDIS_STATUS_RESOURCES;
}

WINAPI_EXPORT void NdisFreePacket(PVOID Packet)
{
    free(Packet);
}

/* ===== Buffer management ===== */

WINAPI_EXPORT void NdisAllocateBufferPool(
    NTSTATUS *Status, PVOID *PoolHandle, ULONG NumberOfBuffers)
{
    (void)NumberOfBuffers;
    static int buf_pool = 4;
    *PoolHandle = &buf_pool;
    *Status = NDIS_STATUS_SUCCESS;
}

WINAPI_EXPORT void NdisFreeBufferPool(PVOID PoolHandle)
{
    (void)PoolHandle;
}

/* ===== Status indication ===== */

WINAPI_EXPORT void NdisMIndicateStatus(
    PVOID MiniportAdapterHandle, NTSTATUS GeneralStatus,
    PVOID StatusBuffer, ULONG StatusBufferSize)
{
    (void)MiniportAdapterHandle;
    (void)StatusBuffer;
    (void)StatusBufferSize;
    printf(LOG_PREFIX "NdisMIndicateStatus: 0x%08x\n", (unsigned)GeneralStatus);
}

WINAPI_EXPORT void NdisMIndicateStatusComplete(PVOID MiniportAdapterHandle)
{
    (void)MiniportAdapterHandle;
}

/* ===== Spinlock ===== */

WINAPI_EXPORT void NdisAllocateSpinLock(PVOID SpinLock)
{
    /* Treat as KSPIN_LOCK */
    PKSPIN_LOCK lock = (PKSPIN_LOCK)SpinLock;
    pthread_mutex_t *mtx = (pthread_mutex_t *)calloc(1, sizeof(pthread_mutex_t));
    if (mtx) {
        pthread_mutex_init(mtx, NULL);
        *lock = (KSPIN_LOCK)(uintptr_t)mtx;
    }
}

WINAPI_EXPORT void NdisFreeSpinLock(PVOID SpinLock)
{
    PKSPIN_LOCK lock = (PKSPIN_LOCK)SpinLock;
    pthread_mutex_t *mtx = (pthread_mutex_t *)(uintptr_t)*lock;
    if (mtx) {
        pthread_mutex_destroy(mtx);
        free(mtx);
    }
}

WINAPI_EXPORT void NdisAcquireSpinLock(PVOID SpinLock)
{
    PKSPIN_LOCK lock = (PKSPIN_LOCK)SpinLock;
    pthread_mutex_t *mtx = (pthread_mutex_t *)(uintptr_t)*lock;
    if (mtx)
        pthread_mutex_lock(mtx);
}

WINAPI_EXPORT void NdisReleaseSpinLock(PVOID SpinLock)
{
    PKSPIN_LOCK lock = (PKSPIN_LOCK)SpinLock;
    pthread_mutex_t *mtx = (pthread_mutex_t *)(uintptr_t)*lock;
    if (mtx)
        pthread_mutex_unlock(mtx);
}
