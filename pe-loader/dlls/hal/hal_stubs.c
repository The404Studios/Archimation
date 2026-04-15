/*
 * hal_stubs.c - Hardware Abstraction Layer stubs for HAL.dll
 *
 * Performance counters, stall execution, bus data access,
 * spinlock fast-path (Kf* variants), and port I/O.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "common/dll_common.h"
#include "win32/wdm.h"

#define LOG_PREFIX "[hal] "

/* ===== Performance counter ===== */

WINAPI_EXPORT LARGE_INTEGER KeQueryPerformanceCounter(
    LARGE_INTEGER *PerformanceFrequency)
{
    LARGE_INTEGER result;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    result.QuadPart = (LONGLONG)ts.tv_sec * 1000000000LL + ts.tv_nsec;

    if (PerformanceFrequency)
        PerformanceFrequency->QuadPart = 1000000000LL; /* 1 GHz */

    return result;
}

/* ===== Stall execution ===== */

WINAPI_EXPORT void KeStallExecutionProcessor(ULONG MicroSeconds)
{
    /* usleep rejects values >= 1000000; chunk the sleep */
    ULONG remaining = MicroSeconds;
    while (remaining > 0) {
        ULONG chunk = remaining > 999999U ? 999999U : remaining;
        usleep(chunk);
        remaining -= chunk;
    }
}

/* ===== Fast spinlock (Kf* variants) ===== */

WINAPI_EXPORT KIRQL KfAcquireSpinLock(PKSPIN_LOCK SpinLock)
{
    pthread_mutex_t *mtx = (pthread_mutex_t *)(uintptr_t)*SpinLock;
    if (mtx)
        pthread_mutex_lock(mtx);
    return PASSIVE_LEVEL;
}

WINAPI_EXPORT void KfReleaseSpinLock(PKSPIN_LOCK SpinLock, KIRQL NewIrql)
{
    (void)NewIrql;
    pthread_mutex_t *mtx = (pthread_mutex_t *)(uintptr_t)*SpinLock;
    if (mtx)
        pthread_mutex_unlock(mtx);
}

WINAPI_EXPORT KIRQL KfRaiseIrql(KIRQL NewIrql)
{
    (void)NewIrql;
    return PASSIVE_LEVEL;
}

WINAPI_EXPORT void KfLowerIrql(KIRQL NewIrql)
{
    (void)NewIrql;
}

/* ===== Bus data access (stubs) ===== */

WINAPI_EXPORT ULONG HalGetBusDataByOffset(
    ULONG BusDataType, ULONG BusNumber, ULONG SlotNumber,
    PVOID Buffer, ULONG Offset, ULONG Length)
{
    (void)BusDataType;
    (void)BusNumber;
    (void)SlotNumber;
    (void)Buffer;
    (void)Offset;
    (void)Length;
    printf(LOG_PREFIX "HalGetBusDataByOffset: bus=%u slot=%u (STUB)\n",
           BusNumber, SlotNumber);
    return 0;
}

WINAPI_EXPORT ULONG HalSetBusDataByOffset(
    ULONG BusDataType, ULONG BusNumber, ULONG SlotNumber,
    PVOID Buffer, ULONG Offset, ULONG Length)
{
    (void)BusDataType;
    (void)BusNumber;
    (void)SlotNumber;
    (void)Buffer;
    (void)Offset;
    (void)Length;
    return 0;
}

WINAPI_EXPORT BOOLEAN HalTranslateBusAddress(
    ULONG InterfaceType, ULONG BusNumber,
    LARGE_INTEGER BusAddress, PULONG AddressSpace,
    LARGE_INTEGER *TranslatedAddress)
{
    (void)InterfaceType;
    (void)BusNumber;
    if (TranslatedAddress)
        TranslatedAddress->QuadPart = BusAddress.QuadPart;
    if (AddressSpace)
        *AddressSpace = 0; /* Memory space */
    return TRUE;
}

/* ===== Port I/O (no-op stubs) ===== */

WINAPI_EXPORT UCHAR READ_PORT_UCHAR(PVOID Port)
{
    (void)Port;
    return 0xFF;
}

WINAPI_EXPORT USHORT READ_PORT_USHORT(PVOID Port)
{
    (void)Port;
    return 0xFFFF;
}

WINAPI_EXPORT ULONG READ_PORT_ULONG(PVOID Port)
{
    (void)Port;
    return 0xFFFFFFFF;
}

WINAPI_EXPORT void WRITE_PORT_UCHAR(PVOID Port, UCHAR Value)
{
    (void)Port;
    (void)Value;
}

WINAPI_EXPORT void WRITE_PORT_USHORT(PVOID Port, USHORT Value)
{
    (void)Port;
    (void)Value;
}

WINAPI_EXPORT void WRITE_PORT_ULONG(PVOID Port, ULONG Value)
{
    (void)Port;
    (void)Value;
}

/* ===== Interrupt management (stubs) ===== */

WINAPI_EXPORT BOOLEAN HalDisableSystemInterrupt(ULONG Vector, KIRQL Irql)
{
    (void)Vector;
    (void)Irql;
    return TRUE;
}

WINAPI_EXPORT BOOLEAN HalEnableSystemInterrupt(
    ULONG Vector, KIRQL Irql, ULONG InterruptMode)
{
    (void)Vector;
    (void)Irql;
    (void)InterruptMode;
    return TRUE;
}
