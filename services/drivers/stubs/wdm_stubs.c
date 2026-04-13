/*
 * wdm_stubs.c - Windows Driver Model Kernel API Stub Implementations
 *
 * Userspace stubs that emulate WDM kernel APIs on Linux. Each function
 * provides a basic implementation or logs the call and returns STATUS_SUCCESS.
 * These stubs allow Windows kernel drivers (especially anti-cheat drivers)
 * to be loaded and executed in a controlled Linux userspace environment.
 *
 * Compile with: gcc -c wdm_stubs.c -o wdm_stubs.o -Wall -Wextra
 */

#include "wdm_types.h"

#include <stdio.h>

/* NTSTATUS codes used below but not in wdm_types.h */
#ifndef STATUS_PORT_NOT_SET
#define STATUS_PORT_NOT_SET ((NTSTATUS)0xC0000353)
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>

/* ============================================================================
 * Internal helpers
 * ============================================================================ */

#define WDM_LOG(fmt, ...) \
    fprintf(stderr, "[WDM_STUB] %s: " fmt "\n", __func__, ##__VA_ARGS__)

/* Maximum number of registered notification callbacks */
#define MAX_PROCESS_NOTIFY_ROUTINES     8
#define MAX_THREAD_NOTIFY_ROUTINES      8
#define MAX_IMAGE_NOTIFY_ROUTINES       8
#define MAX_OB_CALLBACKS                8

/* Stored callback registrations */
static PCREATE_PROCESS_NOTIFY_ROUTINE g_process_notify[MAX_PROCESS_NOTIFY_ROUTINES] = {0};
static PCREATE_THREAD_NOTIFY_ROUTINE  g_thread_notify[MAX_THREAD_NOTIFY_ROUTINES]   = {0};
static PLOAD_IMAGE_NOTIFY_ROUTINE     g_image_notify[MAX_IMAGE_NOTIFY_ROUTINES]     = {0};

static PVOID g_ob_callbacks[MAX_OB_CALLBACKS] = {0};
static int   g_ob_callback_count = 0;

/* ============================================================================
 * I/O Manager Functions
 * ============================================================================ */

/*
 * IoCreateDevice - Creates a device object for use by a driver.
 * Allocates a DEVICE_OBJECT_FULL and links it to the driver object.
 */
NTSTATUS IoCreateDevice(struct _DRIVER_OBJECT *DriverObject,
                        ULONG DeviceExtensionSize,
                        PUNICODE_STRING DeviceName,
                        DEVICE_TYPE DeviceType,
                        ULONG DeviceCharacteristics,
                        BOOLEAN Exclusive,
                        PDEVICE_OBJECT_FULL *DeviceObject)
{
    PDEVICE_OBJECT_FULL dev;
    UNREFERENCED_PARAMETER(DeviceCharacteristics);
    UNREFERENCED_PARAMETER(Exclusive);

    WDM_LOG("DeviceType=0x%x ExtSize=%u", (unsigned)DeviceType, (unsigned)DeviceExtensionSize);

    dev = (PDEVICE_OBJECT_FULL)calloc(1, sizeof(DEVICE_OBJECT_FULL) + DeviceExtensionSize);
    if (!dev) {
        WDM_LOG("Failed to allocate device object");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    dev->Type = 3;  /* IO_TYPE_DEVICE */
    dev->Size = (USHORT)(sizeof(DEVICE_OBJECT_FULL) + DeviceExtensionSize);
    dev->ReferenceCount = 1;
    dev->DriverObject = DriverObject;
    dev->DeviceType = DeviceType;
    dev->StackSize = 1;
    dev->Flags = 0;
    dev->DeviceExtensionSize = DeviceExtensionSize;

    if (DeviceExtensionSize > 0) {
        dev->DeviceExtension = (PVOID)((uint8_t *)dev + sizeof(DEVICE_OBJECT_FULL));
    }

    /* Copy device name if provided */
    if (DeviceName && DeviceName->Buffer && DeviceName->Length > 0) {
        dev->DeviceName.Length = DeviceName->Length;
        dev->DeviceName.MaximumLength = DeviceName->MaximumLength;
        dev->DeviceName.Buffer = (PWCHAR)malloc(DeviceName->MaximumLength);
        if (dev->DeviceName.Buffer) {
            memcpy(dev->DeviceName.Buffer, DeviceName->Buffer, DeviceName->Length);
        }
    }

    /* Link into driver's device list */
    if (DriverObject) {
        dev->NextDevice = (PDEVICE_OBJECT_FULL)DriverObject->DeviceObject;
        DriverObject->DeviceObject = dev;
    }

    *DeviceObject = dev;
    WDM_LOG("Created device object at %p", (void *)dev);
    return STATUS_SUCCESS;
}

/*
 * IoDeleteDevice - Deletes a device object from the system.
 */
void IoDeleteDevice(PDEVICE_OBJECT_FULL DeviceObject)
{
    WDM_LOG("DeviceObject=%p", (void *)DeviceObject);

    if (!DeviceObject) {
        return;
    }

    /* Unlink from driver's device list */
    if (DeviceObject->DriverObject) {
        struct _DRIVER_OBJECT *drv = DeviceObject->DriverObject;
        if (drv->DeviceObject == DeviceObject) {
            drv->DeviceObject = DeviceObject->NextDevice;
        } else {
            PDEVICE_OBJECT_FULL prev = (PDEVICE_OBJECT_FULL)drv->DeviceObject;
            while (prev && prev->NextDevice != DeviceObject) {
                prev = prev->NextDevice;
            }
            if (prev) {
                prev->NextDevice = DeviceObject->NextDevice;
            }
        }
    }

    if (DeviceObject->DeviceName.Buffer) {
        free(DeviceObject->DeviceName.Buffer);
    }
    free(DeviceObject);
}

/*
 * IoCreateSymbolicLink - Creates a symbolic link name in the object manager.
 */
NTSTATUS IoCreateSymbolicLink(PUNICODE_STRING SymbolicLinkName,
                               PUNICODE_STRING DeviceName)
{
    UNREFERENCED_PARAMETER(SymbolicLinkName);
    UNREFERENCED_PARAMETER(DeviceName);
    WDM_LOG("Creating symbolic link (stub)");
    return STATUS_SUCCESS;
}

/*
 * IoDeleteSymbolicLink - Deletes a symbolic link name.
 */
NTSTATUS IoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName)
{
    UNREFERENCED_PARAMETER(SymbolicLinkName);
    WDM_LOG("Deleting symbolic link (stub)");
    return STATUS_SUCCESS;
}

/*
 * IoCompleteRequest - Signals that a driver has finished processing an IRP.
 */
void IoCompleteRequest(PIRP Irp, UCHAR PriorityBoost)
{
    UNREFERENCED_PARAMETER(PriorityBoost);

    if (!Irp) {
        WDM_LOG("WARNING: NULL IRP");
        return;
    }

    WDM_LOG("Irp=%p Status=0x%08x Info=%lu",
            (void *)Irp,
            (unsigned)Irp->IoStatus.Status,
            (unsigned long)Irp->IoStatus.Information);

    /* Mark as completed - in real implementation this would signal waiters */
    Irp->PendingReturned = 0;
}

/* ============================================================================
 * Synchronization Functions
 * ============================================================================ */

/*
 * KeInitializeEvent - Initializes a kernel event object.
 */
void KeInitializeEvent(PKEVENT Event, EVENT_TYPE Type, BOOLEAN State)
{
    WDM_LOG("Event=%p Type=%d State=%d", (void *)Event, (int)Type, (int)State);

    if (Event) {
        Event->State = State ? 1 : 0;
        Event->Type = (ULONG)Type;
    }
}

/*
 * KeSetEvent - Sets an event to the signaled state.
 */
LONG KeSetEvent(PKEVENT Event, LONG Increment, BOOLEAN Wait)
{
    LONG prev;
    UNREFERENCED_PARAMETER(Increment);
    UNREFERENCED_PARAMETER(Wait);

    if (!Event) return 0;

    prev = Event->State;
    Event->State = 1;
    WDM_LOG("Event=%p PreviousState=%d", (void *)Event, (int)prev);
    return prev;
}

/*
 * KeResetEvent - Resets an event to the not-signaled state.
 */
LONG KeResetEvent(PKEVENT Event)
{
    LONG prev;

    if (!Event) return 0;

    prev = Event->State;
    Event->State = 0;
    WDM_LOG("Event=%p PreviousState=%d", (void *)Event, (int)prev);
    return prev;
}

/*
 * KeWaitForSingleObject - Waits for a dispatcher object.
 * Stub: returns immediately as if the object was signaled.
 */
NTSTATUS KeWaitForSingleObject(PVOID Object, KWAIT_REASON WaitReason,
                                KPROCESSOR_MODE WaitMode, BOOLEAN Alertable,
                                PLARGE_INTEGER Timeout)
{
    UNREFERENCED_PARAMETER(WaitReason);
    UNREFERENCED_PARAMETER(WaitMode);
    UNREFERENCED_PARAMETER(Alertable);
    UNREFERENCED_PARAMETER(Timeout);

    WDM_LOG("Object=%p (returning immediately)", (void *)Object);
    return STATUS_SUCCESS;
}

/*
 * KeInitializeMutex - Initializes a kernel mutex.
 */
void KeInitializeMutex(PKMUTEX Mutex, ULONG Level)
{
    UNREFERENCED_PARAMETER(Level);

    WDM_LOG("Mutex=%p Level=%u", (void *)Mutex, (unsigned)Level);

    if (Mutex) {
        Mutex->State = 0;
        Mutex->OwnerThread = NULL;
    }
}

/*
 * KeReleaseMutex - Releases a kernel mutex.
 */
LONG KeReleaseMutex(PKMUTEX Mutex, BOOLEAN Wait)
{
    UNREFERENCED_PARAMETER(Wait);

    if (!Mutex) return 0;

    WDM_LOG("Mutex=%p", (void *)Mutex);
    Mutex->State = 0;
    Mutex->OwnerThread = NULL;
    return 0;
}

/*
 * KeInitializeSpinLock - Initializes a spin lock.
 */
void KeInitializeSpinLock(PKSPIN_LOCK SpinLock)
{
    WDM_LOG("SpinLock=%p", (void *)SpinLock);

    if (SpinLock) {
        SpinLock->Lock = 0;
    }
}

/*
 * KeAcquireSpinLock - Acquires a spin lock and raises IRQL.
 */
void KeAcquireSpinLock(PKSPIN_LOCK SpinLock, PKIRQL OldIrql)
{
    WDM_LOG("SpinLock=%p", (void *)SpinLock);

    if (OldIrql) {
        *OldIrql = PASSIVE_LEVEL;
    }

    if (SpinLock) {
        /* Simple atomic-like set for stub purposes */
        SpinLock->Lock = 1;
    }
}

/*
 * KeReleaseSpinLock - Releases a spin lock and restores IRQL.
 */
void KeReleaseSpinLock(PKSPIN_LOCK SpinLock, KIRQL NewIrql)
{
    UNREFERENCED_PARAMETER(NewIrql);

    WDM_LOG("SpinLock=%p", (void *)SpinLock);

    if (SpinLock) {
        SpinLock->Lock = 0;
    }
}

/* ============================================================================
 * Memory Pool Functions
 * ============================================================================ */

/*
 * ExAllocatePool - Allocates pool memory (deprecated but widely used).
 */
PVOID ExAllocatePool(POOL_TYPE PoolType, SIZE_T NumberOfBytes)
{
    PVOID ptr;
    UNREFERENCED_PARAMETER(PoolType);

    ptr = calloc(1, NumberOfBytes);
    WDM_LOG("PoolType=%d Size=%zu -> %p", (int)PoolType, (size_t)NumberOfBytes, ptr);
    return ptr;
}

/*
 * ExAllocatePoolWithTag - Allocates pool memory with a tag for tracking.
 */
PVOID ExAllocatePoolWithTag(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag)
{
    PVOID ptr;
    UNREFERENCED_PARAMETER(PoolType);

    ptr = calloc(1, NumberOfBytes);
    WDM_LOG("PoolType=%d Size=%zu Tag=0x%08x -> %p",
            (int)PoolType, (size_t)NumberOfBytes, (unsigned)Tag, ptr);
    return ptr;
}

/*
 * ExFreePool - Frees previously allocated pool memory.
 */
void ExFreePool(PVOID P)
{
    WDM_LOG("Ptr=%p", P);
    free(P);
}

/*
 * ExFreePoolWithTag - Frees pool memory allocated with a specific tag.
 */
void ExFreePoolWithTag(PVOID P, ULONG Tag)
{
    WDM_LOG("Ptr=%p Tag=0x%08x", P, (unsigned)Tag);
    free(P);
}

/* ============================================================================
 * Unicode String Functions
 * ============================================================================ */

/*
 * RtlInitUnicodeString - Initializes a UNICODE_STRING from a wide-char source.
 */
void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
    if (!DestinationString) return;

    if (SourceString) {
        /* Calculate length of wide string (each WCHAR is 2 bytes) */
        size_t len = 0;
        const WCHAR *p = SourceString;
        while (*p++) len++;

        DestinationString->Length = (USHORT)(len * sizeof(WCHAR));
        DestinationString->MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
        DestinationString->Buffer = (PWCHAR)SourceString;
    } else {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = NULL;
    }

    WDM_LOG("Length=%u MaxLength=%u",
            (unsigned)DestinationString->Length,
            (unsigned)DestinationString->MaximumLength);
}

/*
 * RtlCopyUnicodeString - Copies a source UNICODE_STRING to a destination.
 */
void RtlCopyUnicodeString(PUNICODE_STRING DestinationString, PCUNICODE_STRING SourceString)
{
    USHORT copyLen;

    if (!DestinationString) return;

    if (!SourceString || !SourceString->Buffer) {
        DestinationString->Length = 0;
        return;
    }

    copyLen = SourceString->Length;
    if (copyLen > DestinationString->MaximumLength) {
        copyLen = DestinationString->MaximumLength;
    }

    if (DestinationString->Buffer && copyLen > 0) {
        memcpy(DestinationString->Buffer, SourceString->Buffer, copyLen);
    }

    DestinationString->Length = copyLen;

    WDM_LOG("Copied %u bytes", (unsigned)copyLen);
}

/*
 * RtlCompareUnicodeString - Compares two UNICODE_STRINGs.
 */
LONG RtlCompareUnicodeString(PCUNICODE_STRING String1, PCUNICODE_STRING String2,
                              BOOLEAN CaseInSensitive)
{
    USHORT len;
    USHORT i;

    WDM_LOG("CaseInsensitive=%d", (int)CaseInSensitive);

    if (!String1 || !String2) return 0;
    if (!String1->Buffer || !String2->Buffer) return 0;

    len = String1->Length < String2->Length ? String1->Length : String2->Length;
    len /= sizeof(WCHAR);

    for (i = 0; i < len; i++) {
        WCHAR c1 = String1->Buffer[i];
        WCHAR c2 = String2->Buffer[i];

        if (CaseInSensitive) {
            /* Simple ASCII case folding */
            if (c1 >= 'A' && c1 <= 'Z') c1 += ('a' - 'A');
            if (c2 >= 'A' && c2 <= 'Z') c2 += ('a' - 'A');
        }

        if (c1 != c2) {
            return (LONG)c1 - (LONG)c2;
        }
    }

    return (LONG)String1->Length - (LONG)String2->Length;
}

/* ============================================================================
 * Miscellaneous Kernel Functions
 * ============================================================================ */

/*
 * MmGetSystemRoutineAddress - Returns the address of a kernel routine by name.
 * Stub: always returns NULL (function not found).
 */
PVOID MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName)
{
    UNREFERENCED_PARAMETER(SystemRoutineName);
    WDM_LOG("Looking up system routine (returning NULL - not found)");
    return NULL;
}

/* ============================================================================
 * Object Manager Functions
 * ============================================================================ */

/*
 * ObReferenceObjectByHandle - Gets a pointer to an object given a handle.
 * Stub: returns a dummy object pointer.
 */
NTSTATUS ObReferenceObjectByHandle(HANDLE Handle, ACCESS_MASK DesiredAccess,
                                    PVOID ObjectType, KPROCESSOR_MODE AccessMode,
                                    PVOID *Object, PVOID HandleInformation)
{
    UNREFERENCED_PARAMETER(Handle);
    UNREFERENCED_PARAMETER(DesiredAccess);
    UNREFERENCED_PARAMETER(ObjectType);
    UNREFERENCED_PARAMETER(AccessMode);
    UNREFERENCED_PARAMETER(HandleInformation);

    WDM_LOG("Handle=%p DesiredAccess=0x%x", Handle, (unsigned)DesiredAccess);

    if (Object) {
        /* Return a non-NULL sentinel value */
        static char dummy_object = 0;
        *Object = &dummy_object;
    }

    return STATUS_SUCCESS;
}

/*
 * ObDereferenceObject - Decrements the reference count on an object.
 */
void ObDereferenceObject(PVOID Object)
{
    WDM_LOG("Object=%p", Object);
    /* No-op in stub - object lifetime is not tracked */
}

/*
 * ObRegisterCallbacks - Registers callback routines for thread/process/desktop
 * handle operations. Critical for anti-cheat drivers that monitor process access.
 */
NTSTATUS ObRegisterCallbacks(POB_CALLBACK_REGISTRATION CallbackRegistration,
                              PVOID *RegistrationHandle)
{
    WDM_LOG("Registering OB callbacks (anti-cheat hook point)");

    if (!CallbackRegistration || !RegistrationHandle) {
        return STATUS_INVALID_PARAMETER;
    }

    WDM_LOG("  Version=%u OperationCount=%u",
            (unsigned)CallbackRegistration->Version,
            (unsigned)CallbackRegistration->OperationRegistrationCount);

    if (g_ob_callback_count < MAX_OB_CALLBACKS) {
        /* Store a reference to the registration for later cleanup */
        g_ob_callbacks[g_ob_callback_count] = CallbackRegistration;
        *RegistrationHandle = (PVOID)(uintptr_t)(g_ob_callback_count + 1);
        g_ob_callback_count++;
        WDM_LOG("  Registered as handle %p", *RegistrationHandle);
    } else {
        WDM_LOG("  WARNING: Maximum OB callbacks reached");
        *RegistrationHandle = (PVOID)(uintptr_t)0xDEAD;
    }

    return STATUS_SUCCESS;
}

/*
 * ObUnRegisterCallbacks - Unregisters previously registered OB callbacks.
 */
void ObUnRegisterCallbacks(PVOID RegistrationHandle)
{
    WDM_LOG("Unregistering OB callbacks handle=%p", RegistrationHandle);

    uintptr_t index = (uintptr_t)RegistrationHandle;
    if (index > 0 && index <= MAX_OB_CALLBACKS) {
        g_ob_callbacks[index - 1] = NULL;
    }
}

/* ============================================================================
 * Process and Thread Functions
 * ============================================================================ */

/*
 * PsGetCurrentProcessId - Returns the process ID of the current process.
 */
HANDLE PsGetCurrentProcessId(void)
{
    pid_t pid = getpid();
    WDM_LOG("pid=%d", (int)pid);
    return (HANDLE)(uintptr_t)pid;
}

/*
 * PsGetCurrentThreadId - Returns the thread ID of the current thread.
 */
HANDLE PsGetCurrentThreadId(void)
{
    /* Use pthread_self() for a unique thread identifier */
    pthread_t tid = pthread_self();
    WDM_LOG("tid=%lu", (unsigned long)tid);
    return (HANDLE)(uintptr_t)tid;
}

/*
 * PsSetCreateProcessNotifyRoutine - Registers/unregisters a process creation
 * notification callback. Used by anti-cheat to monitor new processes.
 */
NTSTATUS PsSetCreateProcessNotifyRoutine(PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
                                          BOOLEAN Remove)
{
    int i;

    WDM_LOG("NotifyRoutine=%p Remove=%d (anti-cheat hook point)",
            (void *)(uintptr_t)NotifyRoutine, (int)Remove);

    if (Remove) {
        for (i = 0; i < MAX_PROCESS_NOTIFY_ROUTINES; i++) {
            if (g_process_notify[i] == NotifyRoutine) {
                g_process_notify[i] = NULL;
                WDM_LOG("  Removed process notify routine at slot %d", i);
                return STATUS_SUCCESS;
            }
        }
        WDM_LOG("  WARNING: Routine not found for removal");
        return STATUS_UNSUCCESSFUL;
    } else {
        for (i = 0; i < MAX_PROCESS_NOTIFY_ROUTINES; i++) {
            if (g_process_notify[i] == NULL) {
                g_process_notify[i] = NotifyRoutine;
                WDM_LOG("  Registered process notify routine at slot %d", i);
                return STATUS_SUCCESS;
            }
        }
        WDM_LOG("  WARNING: No free slots for process notify routine");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
}

/*
 * PsSetCreateThreadNotifyRoutine - Registers a thread creation notification callback.
 * Used by anti-cheat to monitor thread injection.
 */
NTSTATUS PsSetCreateThreadNotifyRoutine(PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine)
{
    int i;

    WDM_LOG("NotifyRoutine=%p (anti-cheat hook point)", (void *)(uintptr_t)NotifyRoutine);

    for (i = 0; i < MAX_THREAD_NOTIFY_ROUTINES; i++) {
        if (g_thread_notify[i] == NULL) {
            g_thread_notify[i] = NotifyRoutine;
            WDM_LOG("  Registered thread notify routine at slot %d", i);
            return STATUS_SUCCESS;
        }
    }

    WDM_LOG("  WARNING: No free slots for thread notify routine");
    return STATUS_INSUFFICIENT_RESOURCES;
}

/*
 * PsSetLoadImageNotifyRoutine - Registers an image load notification callback.
 * Used by anti-cheat to detect DLL injection and module loading.
 */
NTSTATUS PsSetLoadImageNotifyRoutine(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine)
{
    int i;

    WDM_LOG("NotifyRoutine=%p (anti-cheat hook point)", (void *)(uintptr_t)NotifyRoutine);

    for (i = 0; i < MAX_IMAGE_NOTIFY_ROUTINES; i++) {
        if (g_image_notify[i] == NULL) {
            g_image_notify[i] = NotifyRoutine;
            WDM_LOG("  Registered image notify routine at slot %d", i);
            return STATUS_SUCCESS;
        }
    }

    WDM_LOG("  WARNING: No free slots for image notify routine");
    return STATUS_INSUFFICIENT_RESOURCES;
}

/* ============================================================================
 * Zw (Native API) Functions
 * ============================================================================ */

/*
 * ZwQueryInformationProcess - Retrieves process information.
 * Anti-cheat drivers use this to inspect process attributes (e.g., debug port).
 */
NTSTATUS ZwQueryInformationProcess(HANDLE ProcessHandle,
                                    PROCESSINFOCLASS ProcessInformationClass,
                                    PVOID ProcessInformation,
                                    ULONG ProcessInformationLength,
                                    PULONG ReturnLength)
{
    UNREFERENCED_PARAMETER(ProcessHandle);

    WDM_LOG("Handle=%p InfoClass=%d BufLen=%u",
            ProcessHandle, (int)ProcessInformationClass,
            (unsigned)ProcessInformationLength);

    /* Zero out the output buffer to provide safe defaults */
    if (ProcessInformation && ProcessInformationLength > 0) {
        memset(ProcessInformation, 0, ProcessInformationLength);
    }

    if (ReturnLength) {
        *ReturnLength = 0;
    }

    switch (ProcessInformationClass) {
    case ProcessBasicInformation:
        WDM_LOG("  ProcessBasicInformation (returning zeroed data)");
        if (ReturnLength) *ReturnLength = ProcessInformationLength;
        return STATUS_SUCCESS;

    case ProcessDebugPort:
        WDM_LOG("  ProcessDebugPort (returning 0 = no debugger)");
        if (ReturnLength) *ReturnLength = sizeof(ULONG_PTR);
        return STATUS_SUCCESS;

    case ProcessDebugObjectHandle:
        WDM_LOG("  ProcessDebugObjectHandle (returning not found)");
        return STATUS_PORT_NOT_SET;

    case ProcessDebugFlags:
        WDM_LOG("  ProcessDebugFlags (returning 1 = no debugger)");
        if (ProcessInformation && ProcessInformationLength >= sizeof(ULONG)) {
            *(ULONG *)ProcessInformation = 1;  /* 1 = no debugger attached */
        }
        if (ReturnLength) *ReturnLength = sizeof(ULONG);
        return STATUS_SUCCESS;

    case ProcessImageFileName:
        WDM_LOG("  ProcessImageFileName (returning empty)");
        return STATUS_SUCCESS;

    default:
        WDM_LOG("  Unknown info class %d", (int)ProcessInformationClass);
        return STATUS_NOT_SUPPORTED;
    }
}

/*
 * ZwQuerySystemInformation - Retrieves system information.
 * Anti-cheat uses this to enumerate loaded modules, handles, etc.
 */
NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                   PVOID SystemInformation,
                                   ULONG SystemInformationLength,
                                   PULONG ReturnLength)
{
    WDM_LOG("InfoClass=%d BufLen=%u",
            (int)SystemInformationClass, (unsigned)SystemInformationLength);

    /* Zero out output buffer */
    if (SystemInformation && SystemInformationLength > 0) {
        memset(SystemInformation, 0, SystemInformationLength);
    }

    if (ReturnLength) {
        *ReturnLength = 0;
    }

    switch (SystemInformationClass) {
    case SystemBasicInformation:
        WDM_LOG("  SystemBasicInformation");
        return STATUS_SUCCESS;

    case SystemProcessInformation:
        WDM_LOG("  SystemProcessInformation (returning empty list)");
        return STATUS_SUCCESS;

    case SystemModuleInformation:
        WDM_LOG("  SystemModuleInformation (returning empty list)");
        return STATUS_SUCCESS;

    case SystemHandleInformation:
        WDM_LOG("  SystemHandleInformation (returning empty list)");
        return STATUS_SUCCESS;

    case SystemKernelDebuggerInformation:
        WDM_LOG("  SystemKernelDebuggerInformation (no debugger)");
        /* Return: debugger not present */
        if (SystemInformation && SystemInformationLength >= 2) {
            ((uint8_t *)SystemInformation)[0] = 0; /* KernelDebuggerEnabled = FALSE */
            ((uint8_t *)SystemInformation)[1] = 0; /* KernelDebuggerNotPresent = FALSE */
        }
        if (ReturnLength) *ReturnLength = 2;
        return STATUS_SUCCESS;

    case SystemCodeIntegrityInformation:
        WDM_LOG("  SystemCodeIntegrityInformation");
        return STATUS_SUCCESS;

    default:
        WDM_LOG("  Unknown system info class %d", (int)SystemInformationClass);
        return STATUS_NOT_SUPPORTED;
    }
}
