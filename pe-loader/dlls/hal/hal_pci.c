/*
 * hal_pci.c - HAL PCI configuration space access.
 *
 * Replaces the previous "(STUB)" HalGetBusDataByOffset with a real
 * implementation backed by /sys/bus/pci/devices/<segment>:<bus>:<dev>.<fn>/config
 * which the Linux PCI driver subsystem exposes for every probed device.
 *
 * Read access is gated through trust_gate_check(HAL_TRUST_PCI_READ).
 * Write access is gated through HAL_TRUST_PCI_WRITE which maps to
 * TRUST_GATE_DEVICE_IOCTL -- only callers at TRUST_OPERATOR (400) or
 * higher pass.  On denial we return 0 (Length=0) and SetLastError
 * matches the trust gate convention.
 *
 * Limitations:
 *  - Reading config space requires the user to own the file or
 *    CAP_SYS_ADMIN; on most distros standard users get vendor/device
 *    info free but BARs+irq require root.
 *  - Writing config space requires CAP_SYS_ADMIN.
 *  - The /sys path requires the device to be enumerated by Linux PCI
 *    (i.e. not detached via vfio-pci with no_iommu).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include "hal_internal.h"

#define LOG_PREFIX "[hal/pci] "

/* ===== Path / helper utilities ====================================== */

void hal_pci_sysfs_path(const hal_pci_bdf_t *bdf, const char *attr,
                        char *buf, size_t buf_size)
{
    snprintf(buf, buf_size,
             "/sys/bus/pci/devices/%04x:%02x:%02x.%x/%s",
             (unsigned)bdf->segment,
             (unsigned)bdf->bus,
             (unsigned)bdf->device,
             (unsigned)bdf->function,
             attr);
}

long hal_pci_read_int_attr(const hal_pci_bdf_t *bdf, const char *attr)
{
    char path[128], buf[64];
    hal_pci_sysfs_path(bdf, attr, path, sizeof(path));

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    char *end = NULL;
    /* sysfs ints are decimal except where they aren't (vendor/device
     * are 0x-prefixed hex).  strtol with base 0 handles both. */
    errno = 0;
    long v = strtol(buf, &end, 0);
    if (errno != 0 || end == buf)
        return -1;
    return v;
}

/* ===== HalGetBusDataByOffset ======================================== */

WINAPI_EXPORT ULONG HalGetBusDataByOffset(
    ULONG BusDataType, ULONG BusNumber, ULONG SlotNumber,
    PVOID Buffer, ULONG Offset, ULONG Length)
{
    if (BusDataType != PCIConfiguration)
        return 0;
    if (Buffer == NULL || Length == 0)
        return 0;

    hal_pci_bdf_t bdf;
    hal_decode_slot(SlotNumber, &bdf, BusNumber);

    char arg[64];
    snprintf(arg, sizeof(arg), "%04x:%02x:%02x.%x off=%u len=%u",
             bdf.segment, bdf.bus, bdf.device, bdf.function,
             Offset, Length);

    if (!hal_trust_check(HAL_TRUST_PCI_READ, "HalGetBusDataByOffset", arg))
        return 0;

    char path[128];
    hal_pci_sysfs_path(&bdf, "config", path, sizeof(path));

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (getenv("HAL_DEBUG"))
            fprintf(stderr, LOG_PREFIX "open(%s): %s\n", path, strerror(errno));
        return 0;
    }

    ssize_t n = pread(fd, Buffer, Length, (off_t)Offset);
    close(fd);
    if (n < 0)
        return 0;
    return (ULONG)n;
}

/* HalGetBusData calls HalGetBusDataByOffset with offset=0 -- exactly
 * what real HAL.dll does. */
WINAPI_EXPORT ULONG HalGetBusData(
    ULONG BusDataType, ULONG BusNumber, ULONG SlotNumber,
    PVOID Buffer, ULONG Length)
{
    return HalGetBusDataByOffset(BusDataType, BusNumber, SlotNumber,
                                  Buffer, 0, Length);
}

/* ===== HalSetBusDataByOffset ======================================== */

WINAPI_EXPORT ULONG HalSetBusDataByOffset(
    ULONG BusDataType, ULONG BusNumber, ULONG SlotNumber,
    PVOID Buffer, ULONG Offset, ULONG Length)
{
    if (BusDataType != PCIConfiguration)
        return 0;
    if (Buffer == NULL || Length == 0)
        return 0;

    hal_pci_bdf_t bdf;
    hal_decode_slot(SlotNumber, &bdf, BusNumber);

    char arg[64];
    snprintf(arg, sizeof(arg), "%04x:%02x:%02x.%x off=%u len=%u",
             bdf.segment, bdf.bus, bdf.device, bdf.function,
             Offset, Length);

    /* Writes need OPERATOR-band trust. */
    if (!hal_trust_check(HAL_TRUST_PCI_WRITE, "HalSetBusDataByOffset", arg))
        return 0;

    char path[128];
    hal_pci_sysfs_path(&bdf, "config", path, sizeof(path));

    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        if (getenv("HAL_DEBUG"))
            fprintf(stderr, LOG_PREFIX "open(%s, O_WRONLY): %s\n",
                    path, strerror(errno));
        return 0;
    }

    ssize_t n = pwrite(fd, Buffer, Length, (off_t)Offset);
    close(fd);
    if (n < 0)
        return 0;
    return (ULONG)n;
}

WINAPI_EXPORT ULONG HalSetBusData(
    ULONG BusDataType, ULONG BusNumber, ULONG SlotNumber,
    PVOID Buffer, ULONG Length)
{
    return HalSetBusDataByOffset(BusDataType, BusNumber, SlotNumber,
                                  Buffer, 0, Length);
}

/* ===== HalAssignSlotResources ======================================= *
 *
 * Real Windows builds a CM_RESOURCE_LIST describing the BARs and IRQ
 * the device claims.  We approximate by reading /sys/bus/pci/<bdf>/resource
 * (one decimal "start end flags" line per BAR) and the irq attribute.
 * Most modern drivers ignore the resource list and call MmMapIoSpace
 * directly using BAR addresses they read from config space themselves;
 * the function is here so legacy drivers don't crash on a missing import.
 */

WINAPI_EXPORT NTSTATUS HalAssignSlotResources(
    PUNICODE_STRING RegistryPath,
    PUNICODE_STRING DriverClassName,
    PDRIVER_OBJECT  DriverObject,
    PDEVICE_OBJECT  DeviceObject,
    INTERFACE_TYPE  BusType,
    ULONG           BusNumber,
    ULONG           SlotNumber,
    PVOID          *AllocatedResources)   /* PCM_RESOURCE_LIST* */
{
    (void)RegistryPath;
    (void)DriverClassName;
    (void)DriverObject;
    (void)DeviceObject;

    if (BusType != PCIBus || AllocatedResources == NULL)
        return STATUS_DEVICE_DOES_NOT_EXIST;

    *AllocatedResources = NULL;

    hal_pci_bdf_t bdf;
    hal_decode_slot(SlotNumber, &bdf, BusNumber);

    char arg[64];
    snprintf(arg, sizeof(arg), "%04x:%02x:%02x.%x",
             bdf.segment, bdf.bus, bdf.device, bdf.function);
    if (!hal_trust_check(HAL_TRUST_PCI_READ, "HalAssignSlotResources", arg))
        return STATUS_INSUFFICIENT_RESOURCES;

    /* Probe the device exists: vendor read of 4 bytes. */
    char path[128];
    hal_pci_sysfs_path(&bdf, "config", path, sizeof(path));
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return STATUS_DEVICE_DOES_NOT_EXIST;
    uint32_t vendor_dev = 0;
    ssize_t n = pread(fd, &vendor_dev, 4, 0);
    close(fd);
    if (n != 4 || vendor_dev == 0xFFFFFFFFu)
        return STATUS_DEVICE_DOES_NOT_EXIST;

    /* We don't currently materialize a CM_RESOURCE_LIST; drivers that
     * need it should switch to MmMapIoSpace + HalGetInterruptVector.
     * Returning success with NULL list signals "no resources assigned"
     * and prompts callers to fall back to direct config-space probing. */
    return STATUS_SUCCESS;
}

/* ===== HalTranslateBusAddress (PCI variant override) ================ *
 *
 * The stub in hal_stubs.c just identity-mapped.  For PCI we need to
 * preserve that (since /sys exposes the real CPU-physical BAR) and
 * tag AddressSpace=0 (memory) for memory BARs, AddressSpace=1 (port)
 * for I/O BARs.  We don't have the BAR type here without a config
 * read, so we keep the identity behaviour from the stub but expose
 * a stronger variant for callers that supply explicit BAR info.
 *
 * (We do NOT redefine HalTranslateBusAddress here -- the stub already
 * provides it.  This file adds the helpers a real driver would chain.)
 */

WINAPI_EXPORT ULONG HalGetBusInterfaceVersion(void)
{
    /* HAL bus interface version 1, matches NT 5.0+ */
    return 1;
}

/* Quick PCI presence check used by some legacy drivers. */
WINAPI_EXPORT BOOLEAN HalIsPciDevicePresent(
    ULONG BusNumber, ULONG SlotNumber)
{
    hal_pci_bdf_t bdf;
    hal_decode_slot(SlotNumber, &bdf, BusNumber);
    if (!hal_trust_check(HAL_TRUST_PCI_READ, "HalIsPciDevicePresent", NULL))
        return FALSE;

    char path[128];
    hal_pci_sysfs_path(&bdf, "vendor", path, sizeof(path));
    struct stat st;
    return stat(path, &st) == 0 ? TRUE : FALSE;
}

/* Enumerate PCI devices: invokes callback for each /sys/bus/pci/devices
 * entry, parses BDF, looks up vendor/device via sysfs.  Public so that
 * drivers using a generic "find device" pattern don't need to walk
 * /sys themselves. */
typedef BOOLEAN (__attribute__((ms_abi)) *PHAL_PCI_ENUM_CALLBACK)(
    ULONG bus, ULONG slot, ULONG vendor_device, PVOID context);

WINAPI_EXPORT ULONG HalEnumeratePciDevices(
    PHAL_PCI_ENUM_CALLBACK Callback, PVOID Context)
{
    if (!Callback)
        return 0;
    if (!hal_trust_check(HAL_TRUST_PCI_READ, "HalEnumeratePciDevices", NULL))
        return 0;

    DIR *d = opendir("/sys/bus/pci/devices");
    if (!d)
        return 0;

    ULONG count = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        unsigned seg, bus, dev, fn;
        if (sscanf(de->d_name, "%4x:%2x:%2x.%1x",
                   &seg, &bus, &dev, &fn) != 4)
            continue;

        hal_pci_bdf_t bdf = {
            .segment  = (uint16_t)seg,
            .bus      = (uint8_t)bus,
            .device   = (uint8_t)dev,
            .function = (uint8_t)fn,
        };

        long vendor = hal_pci_read_int_attr(&bdf, "vendor");
        long devid  = hal_pci_read_int_attr(&bdf, "device");
        if (vendor < 0 || devid < 0)
            continue;

        ULONG vd = ((ULONG)devid << 16) | (ULONG)(vendor & 0xFFFF);
        ULONG slot = ((ULONG)dev << 3) | (ULONG)fn;

        count++;
        if (!Callback((ULONG)bus, slot, vd, Context))
            break;  /* Callback requested early stop */
    }
    closedir(d);
    return count;
}
