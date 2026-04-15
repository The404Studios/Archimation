/*
 * ntoskrnl_io.c - I/O Manager stubs for ntoskrnl.exe
 *
 * Provides IoCreateDevice, IoDeleteDevice, IoCompleteRequest,
 * symbolic link management, IRP allocation, and device stack operations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "common/dll_common.h"
#include "win32/wdm.h"
#include "compat/abi_bridge.h"

extern int wcscmp16(const uint16_t *a, const uint16_t *b);
extern size_t wcslen16(const uint16_t *s);

#define LOG_PREFIX "[ntoskrnl/io] "

/* ===== Device name registry ===== */
#define MAX_DEVICES  64

static struct {
    WCHAR           name[260];
    PDEVICE_OBJECT  device;
    int             in_use;
} g_device_table[MAX_DEVICES];
static int g_device_count = 0;
static pthread_mutex_t g_device_lock = PTHREAD_MUTEX_INITIALIZER;

/* ===== Symbolic link table ===== */
#define MAX_SYMLINKS 64

static struct {
    WCHAR link_name[260];
    WCHAR target_name[260];
    int   in_use;
} g_symlink_table[MAX_SYMLINKS];
static int g_symlink_count = 0;
static pthread_mutex_t g_symlink_lock = PTHREAD_MUTEX_INITIALIZER;

/* ===== Helper: copy UNICODE_STRING to wchar buffer ===== */
static void copy_ustr(WCHAR *dst, size_t dst_chars, PUNICODE_STRING src)
{
    if (!src || !src->Buffer || src->Length == 0) {
        dst[0] = 0;
        return;
    }
    size_t chars = src->Length / sizeof(WCHAR);
    if (chars >= dst_chars)
        chars = dst_chars - 1;
    memcpy(dst, src->Buffer, chars * sizeof(WCHAR));
    dst[chars] = 0;
}

/* ===== IoCreateDevice ===== */
WINAPI_EXPORT NTSTATUS IoCreateDevice(
    PDRIVER_OBJECT  DriverObject,
    ULONG           DeviceExtensionSize,
    PUNICODE_STRING DeviceName,
    ULONG           DeviceType,
    ULONG           DeviceCharacteristics,
    BOOLEAN         Exclusive,
    PDEVICE_OBJECT *DeviceObject)
{
    (void)DeviceCharacteristics;
    (void)Exclusive;

    size_t alloc_size = sizeof(DEVICE_OBJECT) + DeviceExtensionSize;
    PDEVICE_OBJECT dev = (PDEVICE_OBJECT)calloc(1, alloc_size);
    if (!dev)
        return STATUS_INSUFFICIENT_RESOURCES;

    dev->Type = IO_TYPE_DEVICE;
    dev->Size = (USHORT)sizeof(DEVICE_OBJECT);
    dev->ReferenceCount = 1;
    dev->DriverObject = DriverObject;
    dev->DeviceType = DeviceType;
    dev->StackSize = 1;
    dev->DeviceExtension = DeviceExtensionSize > 0
        ? (void *)((char *)dev + sizeof(DEVICE_OBJECT)) : NULL;

    /* Link into driver's device list */
    dev->NextDevice = DriverObject->DeviceObject;
    DriverObject->DeviceObject = dev;

    /* Register device name */
    if (DeviceName && DeviceName->Buffer) {
        /* Allocate name buffer on the device.  Use ULONG math to avoid USHORT
         * wrap when DeviceName->Length is near 0xFFFF (yields 0x10001 which
         * would truncate to 1 and cause a heap overflow on memcpy). */
        ULONG name_max32 = (ULONG)DeviceName->Length + sizeof(WCHAR);
        USHORT copy_len = DeviceName->Length;
        USHORT name_max;
        if (name_max32 > 0xFFFF) {
            name_max = 0xFFFE;
            if (copy_len > (USHORT)(name_max - sizeof(WCHAR)))
                copy_len = (USHORT)(name_max - sizeof(WCHAR));
        } else {
            name_max = (USHORT)name_max32;
        }
        dev->DeviceName.Buffer = (PWSTR)malloc(name_max);
        if (dev->DeviceName.Buffer) {
            dev->DeviceName.Length = copy_len;
            dev->DeviceName.MaximumLength = name_max;
            memcpy(dev->DeviceName.Buffer, DeviceName->Buffer, copy_len);
            dev->DeviceName.Buffer[copy_len / sizeof(WCHAR)] = 0;
        } else {
            dev->DeviceName.Length = 0;
            dev->DeviceName.MaximumLength = 0;
        }

        pthread_mutex_lock(&g_device_lock);
        /* Scan for a free slot (supports slot reuse after IoDeleteDevice) */
        int slot = -1;
        for (int i = 0; i < g_device_count; i++) {
            if (!g_device_table[i].in_use) { slot = i; break; }
        }
        if (slot < 0 && g_device_count < MAX_DEVICES)
            slot = g_device_count++;
        if (slot >= 0) {
            copy_ustr(g_device_table[slot].name, 260, DeviceName);
            g_device_table[slot].device = dev;
            g_device_table[slot].in_use = 1;
        }
        pthread_mutex_unlock(&g_device_lock);

        {
            char dnb[512];
            size_t di = 0;
            if (dev->DeviceName.Buffer) {
                for (; dev->DeviceName.Buffer[di] && di < 511; di++)
                    dnb[di] = (char)(dev->DeviceName.Buffer[di] & 0xFF);
            }
            dnb[di] = '\0';
            printf(LOG_PREFIX "IoCreateDevice: '%s' type=0x%x ext=%u\n",
                   dnb, DeviceType, DeviceExtensionSize);
        }
    } else {
        printf(LOG_PREFIX "IoCreateDevice: (unnamed) type=0x%x ext=%u\n",
               DeviceType, DeviceExtensionSize);
    }

    *DeviceObject = dev;
    return STATUS_SUCCESS;
}

/* ===== IoDeleteDevice ===== */
WINAPI_EXPORT void IoDeleteDevice(PDEVICE_OBJECT DeviceObject)
{
    if (!DeviceObject)
        return;

    printf(LOG_PREFIX "IoDeleteDevice: %p\n", (void *)DeviceObject);

    /* Unlink from driver's device list */
    PDRIVER_OBJECT drv = DeviceObject->DriverObject;
    if (drv) {
        if (drv->DeviceObject == DeviceObject) {
            drv->DeviceObject = DeviceObject->NextDevice;
        } else {
            PDEVICE_OBJECT prev = drv->DeviceObject;
            while (prev && prev->NextDevice != DeviceObject)
                prev = prev->NextDevice;
            if (prev)
                prev->NextDevice = DeviceObject->NextDevice;
        }
    }

    /* Remove from device table */
    pthread_mutex_lock(&g_device_lock);
    for (int i = 0; i < g_device_count; i++) {
        if (g_device_table[i].device == DeviceObject) {
            g_device_table[i].in_use = 0;
            g_device_table[i].device = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&g_device_lock);

    if (DeviceObject->DeviceName.Buffer)
        free(DeviceObject->DeviceName.Buffer);
    free(DeviceObject);
}

/* ===== IoCreateSymbolicLink ===== */
WINAPI_EXPORT NTSTATUS IoCreateSymbolicLink(
    PUNICODE_STRING SymbolicLinkName,
    PUNICODE_STRING DeviceName)
{
    pthread_mutex_lock(&g_symlink_lock);
    /* Scan for a free slot (supports slot reuse after IoDeleteSymbolicLink) */
    int idx = -1;
    for (int i = 0; i < g_symlink_count; i++) {
        if (!g_symlink_table[i].in_use) { idx = i; break; }
    }
    if (idx < 0) {
        if (g_symlink_count >= MAX_SYMLINKS) {
            pthread_mutex_unlock(&g_symlink_lock);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        idx = g_symlink_count++;
    }
    copy_ustr(g_symlink_table[idx].link_name, 260, SymbolicLinkName);
    copy_ustr(g_symlink_table[idx].target_name, 260, DeviceName);
    g_symlink_table[idx].in_use = 1;
    pthread_mutex_unlock(&g_symlink_lock);

    {
        char ln[512], tn[512];
        size_t li, ti;
        for (li = 0; g_symlink_table[idx].link_name[li] && li < 511; li++)
            ln[li] = (char)(g_symlink_table[idx].link_name[li] & 0xFF);
        ln[li] = '\0';
        for (ti = 0; g_symlink_table[idx].target_name[ti] && ti < 511; ti++)
            tn[ti] = (char)(g_symlink_table[idx].target_name[ti] & 0xFF);
        tn[ti] = '\0';
        printf(LOG_PREFIX "IoCreateSymbolicLink: '%s' -> '%s'\n", ln, tn);
    }

    return STATUS_SUCCESS;
}

/* ===== IoDeleteSymbolicLink ===== */
WINAPI_EXPORT NTSTATUS IoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName)
{
    WCHAR name[260];
    copy_ustr(name, 260, SymbolicLinkName);

    pthread_mutex_lock(&g_symlink_lock);
    for (int i = 0; i < g_symlink_count; i++) {
        if (g_symlink_table[i].in_use &&
            wcscmp16(g_symlink_table[i].link_name, name) == 0) {
            g_symlink_table[i].in_use = 0;
            pthread_mutex_unlock(&g_symlink_lock);
            {
                char nb[512];
                size_t ni;
                for (ni = 0; name[ni] && ni < 511; ni++)
                    nb[ni] = (char)(name[ni] & 0xFF);
                nb[ni] = '\0';
                printf(LOG_PREFIX "IoDeleteSymbolicLink: '%s'\n", nb);
            }
            return STATUS_SUCCESS;
        }
    }
    pthread_mutex_unlock(&g_symlink_lock);
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

/* ===== IoCompleteRequest / IofCompleteRequest ===== */
WINAPI_EXPORT void IoCompleteRequest(PIRP Irp, CHAR PriorityBoost)
{
    (void)PriorityBoost;
    if (!Irp)
        return;
    Irp->PendingReturned = TRUE;
}

WINAPI_EXPORT void IofCompleteRequest(PIRP Irp, CHAR PriorityBoost)
{
    IoCompleteRequest(Irp, PriorityBoost);
}

/* ===== IoAllocateIrp ===== */
WINAPI_EXPORT PIRP IoAllocateIrp(CHAR StackSize, BOOLEAN ChargeQuota)
{
    (void)ChargeQuota;

    PIRP irp = (PIRP)calloc(1, sizeof(IRP));
    if (!irp)
        return NULL;

    /* Clamp StackSize to the fixed-size stack array to avoid OOB access */
    CHAR clamped = StackSize;
    if (clamped < 1) clamped = 1;
    if (clamped > IRP_MAX_STACK) clamped = IRP_MAX_STACK;

    irp->Type = IO_TYPE_IRP;
    irp->Size = sizeof(IRP);
    irp->StackCount = clamped;
    irp->CurrentLocation = 0;

    return irp;
}

/* ===== IoFreeIrp ===== */
WINAPI_EXPORT void IoFreeIrp(PIRP Irp)
{
    free(Irp);
}

/* ===== IoCallDriver / IofCallDriver ===== */
WINAPI_EXPORT NTSTATUS IoCallDriver(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (!DeviceObject || !DeviceObject->DriverObject || !Irp)
        return STATUS_INVALID_PARAMETER;

    if (Irp->CurrentLocation < 0 || Irp->CurrentLocation >= IRP_MAX_STACK)
        return STATUS_INVALID_PARAMETER;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    stack->DeviceObject = DeviceObject;

    UCHAR major = stack->MajorFunction;
    if (major > IRP_MJ_MAXIMUM_FUNCTION)
        return STATUS_INVALID_PARAMETER;

    PDRIVER_DISPATCH dispatch = DeviceObject->DriverObject->MajorFunction[major];
    if (!dispatch)
        return STATUS_NOT_IMPLEMENTED;

    return (NTSTATUS)abi_call_win64_2((void *)dispatch,
        (uint64_t)(uintptr_t)DeviceObject,
        (uint64_t)(uintptr_t)Irp);
}

WINAPI_EXPORT NTSTATUS IofCallDriver(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    return IoCallDriver(DeviceObject, Irp);
}

/* ===== IoAttachDeviceToDeviceStack ===== */
WINAPI_EXPORT PDEVICE_OBJECT IoAttachDeviceToDeviceStack(
    PDEVICE_OBJECT SourceDevice,
    PDEVICE_OBJECT TargetDevice)
{
    if (!SourceDevice || !TargetDevice)
        return NULL;

    /* Walk to the top of the target's stack */
    PDEVICE_OBJECT top = TargetDevice;
    while (top->AttachedDevice)
        top = top->AttachedDevice;

    /* Attach source on top */
    top->AttachedDevice = SourceDevice;
    SourceDevice->StackSize = top->StackSize + 1;

    printf(LOG_PREFIX "IoAttachDeviceToDeviceStack: %p -> %p\n",
           (void *)SourceDevice, (void *)top);

    return top;
}

/* ===== IoDetachDevice ===== */
WINAPI_EXPORT void IoDetachDevice(PDEVICE_OBJECT TargetDevice)
{
    if (!TargetDevice)
        return;
    TargetDevice->AttachedDevice = NULL;
}

/* ===== Device lookup (used by windrv_manager) ===== */
WINAPI_EXPORT PDEVICE_OBJECT IoGetDeviceByName(const WCHAR *name)
{
    PDEVICE_OBJECT result = NULL;
    pthread_mutex_lock(&g_device_lock);
    for (int i = 0; i < g_device_count; i++) {
        if (g_device_table[i].in_use &&
            wcscmp16(g_device_table[i].name, name) == 0) {
            result = g_device_table[i].device;
            break;
        }
    }
    pthread_mutex_unlock(&g_device_lock);
    return result;
}
