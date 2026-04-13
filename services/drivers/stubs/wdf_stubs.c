/*
 * wdf_stubs.c - Windows Driver Framework (WDF/KMDF) Stub Implementations
 *
 * Userspace stubs emulating WDF framework APIs on Linux. WDF is a higher-level
 * abstraction over WDM used by many modern Windows drivers. These stubs allow
 * WDF-based drivers (including some anti-cheat components) to initialize and
 * run in the emulation environment.
 *
 * Compile with: gcc -c wdf_stubs.c -o wdf_stubs.o -Wall -Wextra
 */

#include "wdm_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Logging
 * ============================================================================ */

#define WDF_LOG(fmt, ...) \
    fprintf(stderr, "[WDF_STUB] %s: " fmt "\n", __func__, ##__VA_ARGS__)

/* ============================================================================
 * WDF Opaque Handle Types
 *
 * In real WDF, these are opaque handles backed by framework objects.
 * Here we use simple structs or sentinel values.
 * ============================================================================ */

typedef PVOID WDFDRIVER;
typedef PVOID WDFDEVICE;
typedef PVOID WDFQUEUE;
typedef PVOID WDFREQUEST;
typedef PVOID WDFSPINLOCK;
typedef PVOID WDFTIMER;
typedef PVOID WDFDEVICE_INIT;

typedef WDFDRIVER   *PWDFDRIVER;
typedef WDFDEVICE   *PWDFDEVICE;
typedef WDFQUEUE    *PWDFQUEUE;
typedef WDFREQUEST  *PWDFREQUEST;
typedef WDFSPINLOCK *PWDFSPINLOCK;
typedef WDFTIMER    *PWDFTIMER;

/* ============================================================================
 * WDF Configuration Structures (simplified)
 * ============================================================================ */

typedef enum _WDF_IO_QUEUE_DISPATCH_TYPE {
    WdfIoQueueDispatchSequential    = 1,
    WdfIoQueueDispatchParallel      = 2,
    WdfIoQueueDispatchManual        = 3
} WDF_IO_QUEUE_DISPATCH_TYPE;

typedef enum _WDF_DEVICE_IO_TYPE {
    WdfDeviceIoUndefined    = 0,
    WdfDeviceIoNeither      = 1,
    WdfDeviceIoBuffered     = 2,
    WdfDeviceIoDirect       = 3
} WDF_DEVICE_IO_TYPE;

/* WDF_DRIVER_CONFIG */
typedef struct _WDF_DRIVER_CONFIG {
    ULONG                   Size;
    PVOID                   EvtDriverDeviceAdd;     /* PFN_WDF_DRIVER_DEVICE_ADD */
    PVOID                   EvtDriverUnload;        /* PFN_WDF_DRIVER_UNLOAD */
    ULONG                   DriverInitFlags;
    ULONG                   DriverPoolTag;
} WDF_DRIVER_CONFIG, *PWDF_DRIVER_CONFIG;

/* WDF_OBJECT_ATTRIBUTES */
typedef struct _WDF_OBJECT_ATTRIBUTES {
    ULONG   Size;
    PVOID   EvtCleanupCallback;
    PVOID   EvtDestroyCallback;
    PVOID   ExecutionLevel;
    PVOID   SynchronizationScope;
    PVOID   ParentObject;
    SIZE_T  ContextSizeOverride;
    PVOID   ContextTypeInfo;
} WDF_OBJECT_ATTRIBUTES, *PWDF_OBJECT_ATTRIBUTES;

/* WDF_IO_QUEUE_CONFIG */
typedef struct _WDF_IO_QUEUE_CONFIG {
    ULONG                           Size;
    WDF_IO_QUEUE_DISPATCH_TYPE      DispatchType;
    BOOLEAN                         PowerManaged;
    BOOLEAN                         AllowZeroLengthRequests;
    BOOLEAN                         DefaultQueue;
    PVOID                           EvtIoDefault;
    PVOID                           EvtIoRead;
    PVOID                           EvtIoWrite;
    PVOID                           EvtIoDeviceControl;
    PVOID                           EvtIoInternalDeviceControl;
    PVOID                           EvtIoStop;
    PVOID                           EvtIoResume;
    PVOID                           EvtIoCanceledOnQueue;
} WDF_IO_QUEUE_CONFIG, *PWDF_IO_QUEUE_CONFIG;

/* WDF_TIMER_CONFIG */
typedef struct _WDF_TIMER_CONFIG {
    ULONG       Size;
    PVOID       EvtTimerFunc;           /* PFN_WDF_TIMER */
    ULONG       Period;
    BOOLEAN     AutomaticSerialization;
    ULONG       TolerableDelay;
} WDF_TIMER_CONFIG, *PWDF_TIMER_CONFIG;

/* ============================================================================
 * Internal tracking - unique handle generation
 * ============================================================================ */

static uintptr_t g_wdf_next_handle = 0x10000;

static PVOID wdf_alloc_handle(const char *type)
{
    PVOID handle = (PVOID)g_wdf_next_handle;
    g_wdf_next_handle += 0x100;
    WDF_LOG("Allocated %s handle: %p", type, handle);
    return handle;
}

/* ============================================================================
 * WDF Driver Functions
 * ============================================================================ */

/*
 * WdfDriverCreate - Creates a WDF driver object.
 * Called from DriverEntry of WDF-based drivers.
 */
NTSTATUS WdfDriverCreate(PDRIVER_OBJECT_FULL DriverObject,
                          PCUNICODE_STRING RegistryPath,
                          PWDF_OBJECT_ATTRIBUTES DriverAttributes,
                          PWDF_DRIVER_CONFIG DriverConfig,
                          PWDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverAttributes);

    WDF_LOG("Creating WDF driver");

    if (DriverConfig) {
        WDF_LOG("  DriverConfig.Size=%u", (unsigned)DriverConfig->Size);
        WDF_LOG("  DeviceAdd callback=%p", DriverConfig->EvtDriverDeviceAdd);
        WDF_LOG("  Unload callback=%p", DriverConfig->EvtDriverUnload);
    }

    if (Driver) {
        *Driver = wdf_alloc_handle("WDFDRIVER");
    }

    return STATUS_SUCCESS;
}

/* ============================================================================
 * WDF Device Functions
 * ============================================================================ */

/*
 * WdfDeviceCreate - Creates a WDF device object.
 */
NTSTATUS WdfDeviceCreate(WDFDEVICE_INIT **DeviceInit,
                          PWDF_OBJECT_ATTRIBUTES DeviceAttributes,
                          PWDFDEVICE Device)
{
    UNREFERENCED_PARAMETER(DeviceInit);
    UNREFERENCED_PARAMETER(DeviceAttributes);

    WDF_LOG("Creating WDF device");

    if (Device) {
        *Device = wdf_alloc_handle("WDFDEVICE");
    }

    /* Consume the DeviceInit (as the real API does) */
    if (DeviceInit && *DeviceInit) {
        WDF_LOG("  DeviceInit consumed (was %p)", *DeviceInit);
        *DeviceInit = NULL;
    }

    return STATUS_SUCCESS;
}

/*
 * WdfDeviceInitSetIoType - Sets the I/O type for a device.
 * Must be called before WdfDeviceCreate.
 */
void WdfDeviceInitSetIoType(WDFDEVICE_INIT *DeviceInit,
                             WDF_DEVICE_IO_TYPE IoType)
{
    UNREFERENCED_PARAMETER(DeviceInit);

    const char *type_str;
    switch (IoType) {
    case WdfDeviceIoBuffered:   type_str = "Buffered"; break;
    case WdfDeviceIoDirect:     type_str = "Direct"; break;
    case WdfDeviceIoNeither:    type_str = "Neither"; break;
    default:                    type_str = "Undefined"; break;
    }

    WDF_LOG("DeviceInit=%p IoType=%s(%d)", (void *)DeviceInit, type_str, (int)IoType);
}

/* ============================================================================
 * WDF Request Functions
 * ============================================================================ */

/*
 * WdfRequestComplete - Completes a WDF I/O request with a given status.
 */
void WdfRequestComplete(WDFREQUEST Request, NTSTATUS Status)
{
    WDF_LOG("Request=%p Status=0x%08x", Request, (unsigned)Status);
    /* In real WDF, this signals the framework to complete the underlying IRP */
}

/*
 * WdfRequestRetrieveInputBuffer - Retrieves the input buffer for a request.
 */
NTSTATUS WdfRequestRetrieveInputBuffer(WDFREQUEST Request,
                                        SIZE_T MinimumRequiredSize,
                                        PVOID *Buffer,
                                        SIZE_T *Length)
{
    WDF_LOG("Request=%p MinSize=%zu", Request, (size_t)MinimumRequiredSize);

    if (!Buffer) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * Stub: allocate a zeroed buffer of the minimum size.
     * Real WDF retrieves this from the IRP's system buffer.
     */
    if (MinimumRequiredSize > 0) {
        *Buffer = calloc(1, MinimumRequiredSize);
        if (!*Buffer) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    } else {
        *Buffer = NULL;
    }

    if (Length) {
        *Length = MinimumRequiredSize;
    }

    WDF_LOG("  Buffer=%p Length=%zu", *Buffer, (size_t)MinimumRequiredSize);
    return STATUS_SUCCESS;
}

/*
 * WdfRequestRetrieveOutputBuffer - Retrieves the output buffer for a request.
 */
NTSTATUS WdfRequestRetrieveOutputBuffer(WDFREQUEST Request,
                                         SIZE_T MinimumRequiredSize,
                                         PVOID *Buffer,
                                         SIZE_T *Length)
{
    WDF_LOG("Request=%p MinSize=%zu", Request, (size_t)MinimumRequiredSize);

    if (!Buffer) {
        return STATUS_INVALID_PARAMETER;
    }

    if (MinimumRequiredSize > 0) {
        *Buffer = calloc(1, MinimumRequiredSize);
        if (!*Buffer) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    } else {
        *Buffer = NULL;
    }

    if (Length) {
        *Length = MinimumRequiredSize;
    }

    WDF_LOG("  Buffer=%p Length=%zu", *Buffer, (size_t)MinimumRequiredSize);
    return STATUS_SUCCESS;
}

/* ============================================================================
 * WDF I/O Queue Functions
 * ============================================================================ */

/*
 * WdfIoQueueCreate - Creates an I/O queue for a device.
 */
NTSTATUS WdfIoQueueCreate(WDFDEVICE Device,
                           PWDF_IO_QUEUE_CONFIG Config,
                           PWDF_OBJECT_ATTRIBUTES QueueAttributes,
                           PWDFQUEUE Queue)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(QueueAttributes);

    WDF_LOG("Device=%p", Device);

    if (Config) {
        const char *dispatch_str;
        switch (Config->DispatchType) {
        case WdfIoQueueDispatchSequential:  dispatch_str = "Sequential"; break;
        case WdfIoQueueDispatchParallel:    dispatch_str = "Parallel"; break;
        case WdfIoQueueDispatchManual:      dispatch_str = "Manual"; break;
        default:                            dispatch_str = "Unknown"; break;
        }

        WDF_LOG("  DispatchType=%s Default=%d PowerManaged=%d",
                dispatch_str, (int)Config->DefaultQueue, (int)Config->PowerManaged);
        WDF_LOG("  EvtIoRead=%p EvtIoWrite=%p EvtIoDeviceControl=%p",
                Config->EvtIoRead, Config->EvtIoWrite, Config->EvtIoDeviceControl);
    }

    if (Queue) {
        *Queue = wdf_alloc_handle("WDFQUEUE");
    }

    return STATUS_SUCCESS;
}

/* ============================================================================
 * WDF Spin Lock Functions
 * ============================================================================ */

/*
 * WdfSpinLockCreate - Creates a WDF spin lock object.
 */
NTSTATUS WdfSpinLockCreate(PWDF_OBJECT_ATTRIBUTES SpinLockAttributes,
                            PWDFSPINLOCK SpinLock)
{
    UNREFERENCED_PARAMETER(SpinLockAttributes);

    WDF_LOG("Creating WDF spin lock");

    if (SpinLock) {
        *SpinLock = wdf_alloc_handle("WDFSPINLOCK");
    }

    return STATUS_SUCCESS;
}

/* ============================================================================
 * WDF Timer Functions
 * ============================================================================ */

/*
 * WdfTimerCreate - Creates a WDF timer object.
 */
NTSTATUS WdfTimerCreate(PWDF_TIMER_CONFIG Config,
                         PWDF_OBJECT_ATTRIBUTES Attributes,
                         PWDFTIMER Timer)
{
    UNREFERENCED_PARAMETER(Attributes);

    WDF_LOG("Creating WDF timer");

    if (Config) {
        WDF_LOG("  Period=%u ms EvtTimerFunc=%p AutoSerial=%d",
                (unsigned)Config->Period,
                Config->EvtTimerFunc,
                (int)Config->AutomaticSerialization);
    }

    if (Timer) {
        *Timer = wdf_alloc_handle("WDFTIMER");
    }

    return STATUS_SUCCESS;
}
