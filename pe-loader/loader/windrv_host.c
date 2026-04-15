/*
 * windrv_host.c - Windows Driver Model (WDM) host in userspace
 *
 * Provides a comprehensive driver hosting environment that lets Windows
 * kernel drivers (.sys) run in userspace on Linux.  WDM/WDF calls are
 * intercepted and mapped to Linux kernel interfaces (POSIX I/O, pthreads,
 * ioctl, etc.).
 *
 * The driver host owns:
 *   - Device namespace (\Device\Foo, \DosDevices\C:, symlinks)
 *   - IRP allocation, dispatch, and completion
 *   - Pool memory with tag tracking
 *   - Synchronization primitives (events, spinlocks, mutexes)
 *   - Device stack management (attach/detach)
 *   - IOCTL translation (Windows CTL_CODE -> Linux ioctl)
 *   - SCM integration (SERVICE_KERNEL_DRIVER loading)
 *
 * All exported functions that Windows drivers call use
 * __attribute__((ms_abi)) so PE driver binaries can call them directly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasecmp */
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Linux block-device ioctls (used by IOCTL translation table).
 * These are only available on Linux with kernel headers installed. */
#ifdef __linux__
#include <linux/fs.h>
#else
/* Fallback definitions for non-Linux build environments */
#ifndef BLKGETSIZE64
#define BLKGETSIZE64 0x80081272
#endif
#ifndef BLKSSZGET
#define BLKSSZGET    0x1268
#endif
#endif

#include "windrv_manager.h"
#include "common/dll_common.h"
#include "win32/wdm.h"
#include "compat/abi_bridge.h"

/* ===================================================================
 * Logging
 * =================================================================== */

#define LOG_PREFIX      "[windrv_host] "
#define LOG_INFO(...)   do { printf(LOG_PREFIX __VA_ARGS__); } while (0)
#define LOG_WARN(...)   do { fprintf(stderr, LOG_PREFIX "WARN: " __VA_ARGS__); } while (0)
#define LOG_ERR(...)    do { fprintf(stderr, LOG_PREFIX "ERROR: " __VA_ARGS__); } while (0)

/* ===================================================================
 * Forward declarations / helpers
 * =================================================================== */

extern size_t wcslen16(const uint16_t *s);
extern int wcscmp16(const uint16_t *a, const uint16_t *b);

static void ustr_to_narrow(const UNICODE_STRING *ustr, char *out, size_t out_sz);
static void narrow_to_ustr16(const char *src, uint16_t *buf, size_t buf_chars);

/* ===================================================================
 * Device types (additional, beyond wdm.h)
 * =================================================================== */

#ifndef FILE_DEVICE_KEYBOARD
#define FILE_DEVICE_KEYBOARD    0x0000000B
#endif
#ifndef FILE_DEVICE_MOUSE
#define FILE_DEVICE_MOUSE       0x0000000F
#endif
#ifndef FILE_DEVICE_DISK
#define FILE_DEVICE_DISK        0x00000007
#endif

/* ===================================================================
 * 1. Device Namespace
 *
 *   Maps Windows device paths to DEVICE_OBJECTs or Linux paths.
 *     \Device\Foo           -> device_object
 *     \DosDevices\C:        -> symlink to \Device\HarddiskVolume1
 *     \Device\Null          -> /dev/null
 * =================================================================== */

#define MAX_NS_ENTRIES      128
#define MAX_NS_NAME         260

typedef struct {
    uint16_t        wname[MAX_NS_NAME]; /* UTF-16LE device name */
    PDEVICE_OBJECT  device;             /* NULL if it is a symlink */
    uint16_t        target[MAX_NS_NAME];/* symlink target (UTF-16LE) */
    char            linux_path[512];    /* mapped Linux path, or empty */
    int             in_use;
} ns_entry_t;

static ns_entry_t  g_namespace[MAX_NS_ENTRIES];
static int          g_ns_count = 0;
static pthread_mutex_t g_ns_lock = PTHREAD_MUTEX_INITIALIZER;

/* Pre-populated well-known device -> Linux path mappings */
typedef struct {
    const char *win_name;   /* narrow, e.g. "\\Device\\Null" */
    const char *linux_path; /* e.g. "/dev/null" */
} wellknown_map_t;

static const wellknown_map_t g_wellknown[] = {
    { "\\Device\\Null",             "/dev/null"     },
    { "\\Device\\Zero",             "/dev/zero"     },
    { "\\Device\\Urandom",          "/dev/urandom"  },
    { "\\Device\\KsecDD",          "/dev/urandom"  },  /* crypto RNG */
    { "\\Device\\ConDrv",          "/dev/tty"      },
    { NULL, NULL }
};

/* Volume label -> Linux mount point */
static const struct {
    const char *dos_name;
    const char *linux_path;
} g_volume_map[] = {
    { "\\DosDevices\\C:",           "/"             },
    { "\\DosDevices\\D:",           "/mnt/d"        },
    { "\\DosDevices\\Z:",           "/tmp"          },
    { "\\??\\C:",                   "/"             },
    { NULL, NULL }
};

/* Internal: copy UNICODE_STRING into a uint16_t buffer */
static void copy_ustr_buf(uint16_t *dst, size_t dst_chars,
                           const UNICODE_STRING *src)
{
    if (!src || !src->Buffer || src->Length == 0) {
        dst[0] = 0;
        return;
    }
    size_t chars = src->Length / sizeof(uint16_t);
    if (chars >= dst_chars)
        chars = dst_chars - 1;
    memcpy(dst, src->Buffer, chars * sizeof(uint16_t));
    dst[chars] = 0;
}

/* Convert UNICODE_STRING to narrow C string */
static void ustr_to_narrow(const UNICODE_STRING *ustr, char *out, size_t out_sz)
{
    if (!ustr || !ustr->Buffer || ustr->Length == 0) {
        out[0] = '\0';
        return;
    }
    size_t chars = ustr->Length / sizeof(uint16_t);
    if (chars >= out_sz)
        chars = out_sz - 1;
    for (size_t i = 0; i < chars; i++)
        out[i] = (char)(ustr->Buffer[i] & 0xFF);
    out[chars] = '\0';
}

/* Convert narrow string to uint16_t buffer */
static void narrow_to_ustr16(const char *src, uint16_t *buf, size_t buf_chars)
{
    size_t i;
    for (i = 0; src[i] && i < buf_chars - 1; i++)
        buf[i] = (uint16_t)(unsigned char)src[i];
    buf[i] = 0;
}

/* Lookup a namespace entry by wide name */
static ns_entry_t *ns_find_w(const uint16_t *wname)
{
    for (int i = 0; i < g_ns_count; i++) {
        if (g_namespace[i].in_use &&
            wcscmp16(g_namespace[i].wname, wname) == 0)
            return &g_namespace[i];
    }
    return NULL;
}

/* Lookup a namespace entry by narrow name */
static __attribute__((unused)) ns_entry_t *ns_find(const char *name)
{
    uint16_t wbuf[MAX_NS_NAME];
    narrow_to_ustr16(name, wbuf, MAX_NS_NAME);
    return ns_find_w(wbuf);
}

/* Register a device in the namespace */
static int ns_register_device(const uint16_t *wname, PDEVICE_OBJECT dev,
                               const char *linux_path)
{
    pthread_mutex_lock(&g_ns_lock);
    if (g_ns_count >= MAX_NS_ENTRIES) {
        pthread_mutex_unlock(&g_ns_lock);
        return -1;
    }

    ns_entry_t *ent = &g_namespace[g_ns_count++];
    memset(ent, 0, sizeof(*ent));

    size_t len = wcslen16(wname);
    if (len >= MAX_NS_NAME) len = MAX_NS_NAME - 1;
    memcpy(ent->wname, wname, len * sizeof(uint16_t));
    ent->wname[len] = 0;

    ent->device = dev;
    if (linux_path)
        snprintf(ent->linux_path, sizeof(ent->linux_path), "%s", linux_path);
    ent->in_use = 1;

    pthread_mutex_unlock(&g_ns_lock);
    return 0;
}

/* Register a symlink in the namespace */
static int ns_register_symlink(const uint16_t *link_name,
                                const uint16_t *target_name)
{
    pthread_mutex_lock(&g_ns_lock);
    if (g_ns_count >= MAX_NS_ENTRIES) {
        pthread_mutex_unlock(&g_ns_lock);
        return -1;
    }

    ns_entry_t *ent = &g_namespace[g_ns_count++];
    memset(ent, 0, sizeof(*ent));

    size_t llen = wcslen16(link_name);
    if (llen >= MAX_NS_NAME) llen = MAX_NS_NAME - 1;
    memcpy(ent->wname, link_name, llen * sizeof(uint16_t));
    ent->wname[llen] = 0;

    size_t tlen = wcslen16(target_name);
    if (tlen >= MAX_NS_NAME) tlen = MAX_NS_NAME - 1;
    memcpy(ent->target, target_name, tlen * sizeof(uint16_t));
    ent->target[tlen] = 0;

    ent->device = NULL; /* symlinks have no direct device */
    ent->in_use = 1;

    pthread_mutex_unlock(&g_ns_lock);
    return 0;
}

/* Remove entry from namespace */
static void ns_remove(const uint16_t *wname)
{
    pthread_mutex_lock(&g_ns_lock);
    for (int i = 0; i < g_ns_count; i++) {
        if (g_namespace[i].in_use &&
            wcscmp16(g_namespace[i].wname, wname) == 0) {
            g_namespace[i].in_use = 0;
            g_namespace[i].device = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&g_ns_lock);
}

/* Resolve a device name through symlinks to find the DEVICE_OBJECT */
static PDEVICE_OBJECT ns_resolve_device(const uint16_t *wname, int max_depth)
{
    if (max_depth <= 0)
        return NULL;

    pthread_mutex_lock(&g_ns_lock);
    ns_entry_t *ent = ns_find_w(wname);
    if (!ent) {
        pthread_mutex_unlock(&g_ns_lock);
        return NULL;
    }

    if (ent->device) {
        PDEVICE_OBJECT dev = ent->device;
        pthread_mutex_unlock(&g_ns_lock);
        return dev;
    }

    /* Follow symlink */
    if (ent->target[0]) {
        uint16_t target_copy[MAX_NS_NAME];
        memcpy(target_copy, ent->target, sizeof(target_copy));
        pthread_mutex_unlock(&g_ns_lock);
        return ns_resolve_device(target_copy, max_depth - 1);
    }

    pthread_mutex_unlock(&g_ns_lock);
    return NULL;
}

/* Get the Linux path for a device name (for mapping to real files) */
static __attribute__((unused)) const char *ns_get_linux_path(const uint16_t *wname)
{
    pthread_mutex_lock(&g_ns_lock);
    ns_entry_t *ent = ns_find_w(wname);
    const char *path = NULL;
    if (ent && ent->linux_path[0])
        path = ent->linux_path;
    pthread_mutex_unlock(&g_ns_lock);
    return path;
}

/* Populate well-known device names */
static void ns_init_wellknown(void)
{
    for (int i = 0; g_wellknown[i].win_name; i++) {
        uint16_t wname[MAX_NS_NAME];
        narrow_to_ustr16(g_wellknown[i].win_name, wname, MAX_NS_NAME);
        ns_register_device(wname, NULL, g_wellknown[i].linux_path);
    }

    for (int i = 0; g_volume_map[i].dos_name; i++) {
        uint16_t link[MAX_NS_NAME];
        narrow_to_ustr16(g_volume_map[i].dos_name, link, MAX_NS_NAME);
        /* DosDevices point to \Device\HarddiskVolumeN as a convention,
         * but we store the Linux path directly for quick resolution. */
        ns_register_device(link, NULL, g_volume_map[i].linux_path);
    }
}

/* ===================================================================
 * 2. Pool Memory with Tag Tracking
 *
 *   ExAllocatePoolWithTag -> malloc with metadata header
 *   ExFreePoolWithTag     -> free with tag verification
 *   Pool statistics for leak detection.
 * =================================================================== */

#define POOL_TAG_MAGIC  0x504F4F4CU  /* "POOL" */
#define MAX_POOL_TAGS   256

typedef struct pool_header {
    uint32_t        magic;
    uint32_t        tag;
    size_t          size;
    POOL_TYPE       pool_type;
    struct pool_header *next;
    struct pool_header *prev;
} pool_header_t;

typedef struct {
    uint32_t tag;
    size_t   total_bytes;
    uint32_t alloc_count;
    uint32_t free_count;
} pool_tag_stat_t;

static pool_header_t   *g_pool_list = NULL;
static pthread_mutex_t  g_pool_lock = PTHREAD_MUTEX_INITIALIZER;
static pool_tag_stat_t  g_pool_stats[MAX_POOL_TAGS];
static int              g_pool_stat_count = 0;
static size_t           g_pool_total_bytes = 0;
static uint32_t         g_pool_total_allocs = 0;

static pool_tag_stat_t *pool_find_stat(uint32_t tag)
{
    for (int i = 0; i < g_pool_stat_count; i++) {
        if (g_pool_stats[i].tag == tag)
            return &g_pool_stats[i];
    }
    if (g_pool_stat_count < MAX_POOL_TAGS) {
        pool_tag_stat_t *st = &g_pool_stats[g_pool_stat_count++];
        st->tag = tag;
        st->total_bytes = 0;
        st->alloc_count = 0;
        st->free_count = 0;
        return st;
    }
    return NULL;
}

static char *tag_to_str(uint32_t tag, char buf[5])
{
    buf[0] = (char)((tag >>  0) & 0xFF);
    buf[1] = (char)((tag >>  8) & 0xFF);
    buf[2] = (char)((tag >> 16) & 0xFF);
    buf[3] = (char)((tag >> 24) & 0xFF);
    buf[4] = '\0';
    /* Replace non-printable characters with '.' */
    for (int i = 0; i < 4; i++) {
        if (buf[i] < 32 || buf[i] > 126)
            buf[i] = '.';
    }
    return buf;
}

__attribute__((ms_abi, visibility("default")))
PVOID windrv_pool_alloc(POOL_TYPE pool_type, SIZE_T size, ULONG tag)
{
    pool_header_t *hdr = (pool_header_t *)calloc(1, sizeof(pool_header_t) + size);
    if (!hdr)
        return NULL;

    hdr->magic = POOL_TAG_MAGIC;
    hdr->tag = tag;
    hdr->size = size;
    hdr->pool_type = pool_type;

    pthread_mutex_lock(&g_pool_lock);

    /* Insert at head of list */
    hdr->next = g_pool_list;
    hdr->prev = NULL;
    if (g_pool_list)
        g_pool_list->prev = hdr;
    g_pool_list = hdr;

    /* Update stats */
    g_pool_total_bytes += size;
    g_pool_total_allocs++;
    pool_tag_stat_t *st = pool_find_stat(tag);
    if (st) {
        st->total_bytes += size;
        st->alloc_count++;
    }

    pthread_mutex_unlock(&g_pool_lock);

    return (void *)(hdr + 1); /* Return pointer past header */
}

__attribute__((ms_abi, visibility("default")))
void windrv_pool_free(PVOID ptr, ULONG tag)
{
    if (!ptr)
        return;

    pool_header_t *hdr = ((pool_header_t *)ptr) - 1;

    if (hdr->magic != POOL_TAG_MAGIC) {
        LOG_WARN("pool_free: bad magic at %p (double free or corruption)\n", ptr);
        /* Don't free -- memory is in unknown state; freeing could corrupt the heap */
        return;
    }

    if (tag != 0 && hdr->tag != tag) {
        char expected[5], actual[5];
        LOG_WARN("pool_free: tag mismatch at %p: expected '%s' got '%s'\n",
                 ptr, tag_to_str(tag, expected), tag_to_str(hdr->tag, actual));
    }

    pthread_mutex_lock(&g_pool_lock);

    /* Unlink from list */
    if (hdr->prev)
        hdr->prev->next = hdr->next;
    else
        g_pool_list = hdr->next;
    if (hdr->next)
        hdr->next->prev = hdr->prev;

    g_pool_total_bytes -= hdr->size;

    pool_tag_stat_t *st = pool_find_stat(hdr->tag);
    if (st)
        st->free_count++;

    pthread_mutex_unlock(&g_pool_lock);

    hdr->magic = 0; /* Poison to catch double-free */
    free(hdr);
}

/* Dump pool statistics (for debugging / leak detection) */
void windrv_pool_dump_stats(void)
{
    pthread_mutex_lock(&g_pool_lock);
    LOG_INFO("=== Pool Memory Statistics ===\n");
    LOG_INFO("  Total allocated: %zu bytes in %u allocations\n",
             g_pool_total_bytes, g_pool_total_allocs);

    for (int i = 0; i < g_pool_stat_count; i++) {
        pool_tag_stat_t *st = &g_pool_stats[i];
        char tagbuf[5];
        int32_t outstanding = (int32_t)st->alloc_count - (int32_t)st->free_count;
        LOG_INFO("  Tag '%s': allocs=%u frees=%u outstanding=%d bytes=%zu\n",
                 tag_to_str(st->tag, tagbuf),
                 st->alloc_count, st->free_count, outstanding,
                 st->total_bytes);
    }
    LOG_INFO("==============================\n");
    pthread_mutex_unlock(&g_pool_lock);
}

/* ===================================================================
 * 3. IRP Allocation, Dispatch, and Completion
 * =================================================================== */

__attribute__((ms_abi, visibility("default")))
PIRP windrv_alloc_irp(UCHAR stack_size)
{
    PIRP irp = (PIRP)calloc(1, sizeof(IRP));
    if (!irp)
        return NULL;

    irp->Type = IO_TYPE_IRP;
    irp->Size = sizeof(IRP);
    irp->StackCount = (stack_size > 0 && stack_size <= IRP_MAX_STACK)
                          ? stack_size : 1;
    /* CurrentLocation indexes into Stack[] via IoGetCurrentIrpStackLocation.
     * For a new IRP, start at the top stack location (StackCount - 1). */
    irp->CurrentLocation = irp->StackCount - 1;
    irp->RequestorMode = KernelMode;
    irp->PendingReturned = FALSE;
    irp->Cancel = FALSE;

    return irp;
}

__attribute__((ms_abi, visibility("default")))
void windrv_free_irp(PIRP irp)
{
    if (!irp)
        return;

    /* Free system buffer if it was allocated for buffered I/O */
    if (irp->AssociatedIrp_SystemBuffer) {
        free(irp->AssociatedIrp_SystemBuffer);
        irp->AssociatedIrp_SystemBuffer = NULL;
    }

    /* Free MDL chain */
    PMDL mdl = irp->MdlAddress;
    while (mdl) {
        PMDL next = mdl->Next;
        free(mdl);
        mdl = next;
    }

    free(irp);
}

/* Build an IRP with populated stack location for a specific operation */
static PIRP build_irp_for_operation(UCHAR major_function,
                                     PDEVICE_OBJECT device,
                                     void *buffer, uint32_t buffer_len,
                                     uint32_t ioctl_code,
                                     uint32_t input_len,
                                     uint32_t output_len)
{
    PIRP irp = windrv_alloc_irp(device ? device->StackSize : 1);
    if (!irp)
        return NULL;

    /* Allocate system buffer for METHOD_BUFFERED */
    size_t sys_buf_size = 0;
    if (major_function == IRP_MJ_DEVICE_CONTROL) {
        sys_buf_size = (input_len > output_len) ? input_len : output_len;
    } else if (major_function == IRP_MJ_READ) {
        sys_buf_size = buffer_len;
    } else if (major_function == IRP_MJ_WRITE) {
        sys_buf_size = buffer_len;
    }

    if (sys_buf_size > 0) {
        irp->AssociatedIrp_SystemBuffer = calloc(1, sys_buf_size);
        if (!irp->AssociatedIrp_SystemBuffer) {
            windrv_free_irp(irp);
            return NULL;
        }
        if (buffer && (major_function == IRP_MJ_WRITE ||
                       major_function == IRP_MJ_DEVICE_CONTROL)) {
            memcpy(irp->AssociatedIrp_SystemBuffer, buffer,
                   (major_function == IRP_MJ_DEVICE_CONTROL)
                       ? input_len : buffer_len);
        }
    }

    irp->UserBuffer = buffer;

    /* Populate the IO_STACK_LOCATION */
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    stack->MajorFunction = major_function;
    stack->MinorFunction = 0;
    stack->DeviceObject = device;

    switch (major_function) {
    case IRP_MJ_READ:
        stack->Parameters.Read.Length = buffer_len;
        stack->Parameters.Read.ByteOffset.QuadPart = 0;
        break;
    case IRP_MJ_WRITE:
        stack->Parameters.Write.Length = buffer_len;
        stack->Parameters.Write.ByteOffset.QuadPart = 0;
        break;
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
        stack->Parameters.DeviceIoControl.IoControlCode = ioctl_code;
        stack->Parameters.DeviceIoControl.InputBufferLength = input_len;
        stack->Parameters.DeviceIoControl.OutputBufferLength = output_len;
        break;
    default:
        break;
    }

    return irp;
}

/* Dispatch an IRP to a device's driver */
__attribute__((ms_abi, visibility("default")))
NTSTATUS windrv_call_driver(PDEVICE_OBJECT device, PIRP irp)
{
    if (!device || !irp)
        return STATUS_INVALID_PARAMETER;

    PDRIVER_OBJECT driver = device->DriverObject;
    if (!driver)
        return STATUS_INVALID_PARAMETER;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    stack->DeviceObject = device;

    UCHAR major = stack->MajorFunction;
    if (major > IRP_MJ_MAXIMUM_FUNCTION)
        return STATUS_INVALID_PARAMETER;

    PDRIVER_DISPATCH dispatch = driver->MajorFunction[major];
    if (!dispatch) {
        irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        irp->IoStatus.Information = 0;
        return STATUS_NOT_IMPLEMENTED;
    }

    /* Call the driver's dispatch function via ABI bridge */
    NTSTATUS status = (NTSTATUS)abi_call_win64_2(
        (void *)dispatch,
        (uint64_t)(uintptr_t)device,
        (uint64_t)(uintptr_t)irp);

    return status;
}

/* IoCompleteRequest equivalent */
__attribute__((ms_abi, visibility("default")))
void windrv_complete_request(PIRP irp, CHAR priority_boost)
{
    (void)priority_boost;
    if (!irp)
        return;

    irp->PendingReturned = TRUE;

    /* Walk the stack backwards calling completion routines */
    for (int loc = (int)irp->StackCount - 1; loc >= 0; loc--) {
        IO_STACK_LOCATION *sl = &irp->Stack[loc];
        if (sl->CompletionRoutine) {
            NTSTATUS cr_status = (NTSTATUS)abi_call_win64_3(
                (void *)sl->CompletionRoutine,
                (uint64_t)(uintptr_t)sl->DeviceObject,
                (uint64_t)(uintptr_t)irp,
                (uint64_t)(uintptr_t)sl->Context);

            if (cr_status == STATUS_MORE_PROCESSING_REQUIRED)
                return; /* Driver wants to keep the IRP */
        }
    }

    /* If IRP had a user event, signal it */
    if (irp->UserEvent) {
        PKEVENT ev = (PKEVENT)irp->UserEvent;
        /* Use ntoskrnl's KeSetEvent indirectly */
        ev->Header.SignalState = 1;
    }
}

/* ===================================================================
 * 4. Device Object Management
 *
 *   - Create/delete device objects
 *   - Device stack (attach/detach)
 *   - Linux fd mapping
 * =================================================================== */

#define MAX_HOSTED_DEVICES  128

typedef struct {
    PDEVICE_OBJECT  device;
    PDRIVER_OBJECT  driver;
    int             linux_fd;       /* Mapped Linux fd, or -1 */
    char            linux_path[512];
    int             in_use;
} hosted_device_t;

static hosted_device_t  g_hosted_devices[MAX_HOSTED_DEVICES];
static int              g_hosted_count = 0;
static pthread_mutex_t  g_device_host_lock = PTHREAD_MUTEX_INITIALIZER;

/* Create a device object and register it */
__attribute__((ms_abi, visibility("default")))
NTSTATUS windrv_create_device(
    PDRIVER_OBJECT  driver,
    ULONG           device_extension_size,
    PUNICODE_STRING device_name,
    ULONG           device_type,
    ULONG           device_characteristics,
    BOOLEAN         exclusive,
    PDEVICE_OBJECT *device_out)
{
    if (!driver || !device_out)
        return STATUS_INVALID_PARAMETER;

    (void)device_characteristics;
    (void)exclusive;

    /* Allocate device + extension in one block */
    size_t alloc_size = sizeof(DEVICE_OBJECT) + device_extension_size;
    PDEVICE_OBJECT dev = (PDEVICE_OBJECT)calloc(1, alloc_size);
    if (!dev)
        return STATUS_INSUFFICIENT_RESOURCES;

    dev->Type = IO_TYPE_DEVICE;
    dev->Size = (USHORT)sizeof(DEVICE_OBJECT);
    dev->ReferenceCount = 1;
    dev->DriverObject = driver;
    dev->DeviceType = device_type;
    dev->StackSize = 1;
    dev->Flags = DO_BUFFERED_IO; /* Default to buffered I/O */
    dev->DeviceExtension = (device_extension_size > 0)
        ? (void *)((char *)dev + sizeof(DEVICE_OBJECT)) : NULL;

    /* Link into driver's device list */
    dev->NextDevice = driver->DeviceObject;
    driver->DeviceObject = dev;

    /* Set up device name */
    char narrow_name[512] = {0};
    if (device_name && device_name->Buffer) {
        dev->DeviceName.Length = device_name->Length;
        dev->DeviceName.MaximumLength = device_name->Length + sizeof(WCHAR);
        dev->DeviceName.Buffer = (PWSTR)malloc(dev->DeviceName.MaximumLength);
        if (dev->DeviceName.Buffer) {
            memcpy(dev->DeviceName.Buffer, device_name->Buffer,
                   device_name->Length);
            dev->DeviceName.Buffer[device_name->Length / sizeof(WCHAR)] = 0;
        }
        ustr_to_narrow(device_name, narrow_name, sizeof(narrow_name));
    }

    /* Register in the namespace */
    if (device_name && device_name->Buffer) {
        uint16_t wname[MAX_NS_NAME];
        copy_ustr_buf(wname, MAX_NS_NAME, device_name);

        /* Check for well-known Linux path mapping */
        const char *lpath = NULL;
        for (int i = 0; g_wellknown[i].win_name; i++) {
            if (strcmp(narrow_name, g_wellknown[i].win_name) == 0) {
                lpath = g_wellknown[i].linux_path;
                break;
            }
        }

        ns_register_device(wname, dev, lpath);
    }

    /* Register in hosted device table */
    pthread_mutex_lock(&g_device_host_lock);
    if (g_hosted_count < MAX_HOSTED_DEVICES) {
        hosted_device_t *hd = &g_hosted_devices[g_hosted_count++];
        hd->device = dev;
        hd->driver = driver;
        hd->linux_fd = -1;
        hd->in_use = 1;
        if (narrow_name[0]) {
            /* Try to find Linux path mapping */
            for (int i = 0; g_wellknown[i].win_name; i++) {
                if (strcmp(narrow_name, g_wellknown[i].win_name) == 0) {
                    snprintf(hd->linux_path, sizeof(hd->linux_path),
                             "%s", g_wellknown[i].linux_path);
                    break;
                }
            }
        }
    }
    pthread_mutex_unlock(&g_device_host_lock);

    LOG_INFO("windrv_create_device: '%s' type=0x%x ext=%u\n",
             narrow_name[0] ? narrow_name : "(unnamed)",
             device_type, device_extension_size);

    *device_out = dev;
    return STATUS_SUCCESS;
}

/* Delete a device object */
__attribute__((ms_abi, visibility("default")))
void windrv_delete_device(PDEVICE_OBJECT device)
{
    if (!device)
        return;

    /* Unlink from driver's device list */
    PDRIVER_OBJECT drv = device->DriverObject;
    if (drv) {
        if (drv->DeviceObject == device) {
            drv->DeviceObject = device->NextDevice;
        } else {
            PDEVICE_OBJECT prev = drv->DeviceObject;
            while (prev && prev->NextDevice != device)
                prev = prev->NextDevice;
            if (prev)
                prev->NextDevice = device->NextDevice;
        }
    }

    /* Remove from namespace */
    if (device->DeviceName.Buffer) {
        ns_remove(device->DeviceName.Buffer);
    }

    /* Remove from hosted table and close Linux fd */
    pthread_mutex_lock(&g_device_host_lock);
    for (int i = 0; i < g_hosted_count; i++) {
        if (g_hosted_devices[i].in_use &&
            g_hosted_devices[i].device == device) {
            if (g_hosted_devices[i].linux_fd >= 0)
                close(g_hosted_devices[i].linux_fd);
            g_hosted_devices[i].in_use = 0;
            g_hosted_devices[i].device = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&g_device_host_lock);

    LOG_INFO("windrv_delete_device: %p\n", (void *)device);

    if (device->DeviceName.Buffer)
        free(device->DeviceName.Buffer);
    free(device);
}

/* Attach a device to the top of another device's stack */
__attribute__((ms_abi, visibility("default")))
PDEVICE_OBJECT windrv_attach_device(PDEVICE_OBJECT source,
                                     PDEVICE_OBJECT target)
{
    if (!source || !target)
        return NULL;

    /* Walk to the top of target's stack */
    PDEVICE_OBJECT top = target;
    while (top->AttachedDevice)
        top = top->AttachedDevice;

    top->AttachedDevice = source;
    source->StackSize = top->StackSize + 1;

    LOG_INFO("windrv_attach_device: %p on top of %p (stack_size=%d)\n",
             (void *)source, (void *)top, source->StackSize);

    return top; /* Return the previously-top device */
}

/* Detach a device from a stack */
__attribute__((ms_abi, visibility("default")))
void windrv_detach_device(PDEVICE_OBJECT target)
{
    if (target)
        target->AttachedDevice = NULL;
}

/* Get the hosted device table entry for a device object */
static hosted_device_t *find_hosted_device(PDEVICE_OBJECT dev)
{
    for (int i = 0; i < g_hosted_count; i++) {
        if (g_hosted_devices[i].in_use &&
            g_hosted_devices[i].device == dev)
            return &g_hosted_devices[i];
    }
    return NULL;
}

/* Open the Linux fd for a hosted device (lazy open on first IRP_MJ_CREATE) */
static int hosted_device_open_fd(hosted_device_t *hd)
{
    if (hd->linux_fd >= 0)
        return hd->linux_fd;

    if (hd->linux_path[0]) {
        hd->linux_fd = open(hd->linux_path, O_RDWR | O_NONBLOCK);
        if (hd->linux_fd < 0) {
            /* Try read-only */
            hd->linux_fd = open(hd->linux_path, O_RDONLY | O_NONBLOCK);
        }
        if (hd->linux_fd >= 0) {
            LOG_INFO("Opened Linux device '%s' as fd %d\n",
                     hd->linux_path, hd->linux_fd);
        }
    }
    return hd->linux_fd;
}

/* ===================================================================
 * 5. IOCTL Translation
 *
 *   Map Windows CTL_CODE-encoded IOCTLs to Linux ioctl numbers
 *   where a reasonable mapping exists. Returns 0 if no mapping.
 * =================================================================== */

/* Windows IOCTL structure: DeviceType(16) | Access(2) | Function(12) | Method(2)
 * Linux ioctl: direction(2) | size(14) | type(8) | nr(8) */

/* Common Windows device IOCTL device types */
#define WIN_FILE_DEVICE_DISK        0x00000007
#define WIN_FILE_DEVICE_KEYBOARD    0x0000000B
#define WIN_FILE_DEVICE_NETWORK     0x00000012
#define WIN_FILE_DEVICE_SERIAL_PORT 0x0000001B

/* Translation table for known IOCTLs */
typedef struct {
    uint32_t        win_ioctl;
    unsigned long   linux_ioctl;
    const char      *description;
} ioctl_map_entry_t;

static const ioctl_map_entry_t g_ioctl_map[] = {
    /* Disk IOCTLs */
    { CTL_CODE(WIN_FILE_DEVICE_DISK, 0x0000, METHOD_BUFFERED, FILE_ANY_ACCESS),
      BLKGETSIZE64, "IOCTL_DISK_GET_LENGTH_INFO" },
    { CTL_CODE(WIN_FILE_DEVICE_DISK, 0x0024, METHOD_BUFFERED, FILE_READ_ACCESS),
      BLKSSZGET,    "IOCTL_DISK_GET_DRIVE_GEOMETRY" },

    /* Sentinel */
    { 0, 0, NULL }
};

__attribute__((ms_abi, visibility("default")))
int windrv_translate_ioctl(uint32_t win_ioctl, unsigned long *linux_ioctl)
{
    if (!linux_ioctl)
        return 0;

    for (int i = 0; g_ioctl_map[i].description; i++) {
        if (g_ioctl_map[i].win_ioctl == win_ioctl) {
            *linux_ioctl = g_ioctl_map[i].linux_ioctl;
            LOG_INFO("IOCTL translated: 0x%08x -> 0x%lx (%s)\n",
                     win_ioctl, *linux_ioctl, g_ioctl_map[i].description);
            return 1;
        }
    }

    /* No mapping found */
    return 0;
}

/* ===================================================================
 * 6. Linux I/O Integration
 *
 *   When a driver's dispatch routine returns STATUS_NOT_IMPLEMENTED
 *   or the device has a Linux fd, we can fall through to Linux I/O.
 * =================================================================== */

/* Handle IRP_MJ_CREATE by opening the Linux device */
static NTSTATUS linux_handle_create(PDEVICE_OBJECT device, PIRP irp)
{
    hosted_device_t *hd = find_hosted_device(device);
    if (!hd)
        return STATUS_DEVICE_DOES_NOT_EXIST;

    int fd = hosted_device_open_fd(hd);
    if (fd < 0) {
        /* No Linux backing -- driver will handle it */
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        return STATUS_SUCCESS;
    }

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

/* Handle IRP_MJ_READ via Linux read() */
static NTSTATUS linux_handle_read(PDEVICE_OBJECT device, PIRP irp)
{
    hosted_device_t *hd = find_hosted_device(device);
    if (!hd || hd->linux_fd < 0)
        return STATUS_DEVICE_DOES_NOT_EXIST;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    uint32_t length = stack->Parameters.Read.Length;

    void *buffer = irp->AssociatedIrp_SystemBuffer;
    if (!buffer)
        buffer = irp->UserBuffer;
    if (!buffer || length == 0) {
        irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    ssize_t n = read(hd->linux_fd, buffer, length);
    if (n < 0) {
        irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        irp->IoStatus.Information = 0;
        return STATUS_UNSUCCESSFUL;
    }

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = (ULONG_PTR)n;
    return STATUS_SUCCESS;
}

/* Handle IRP_MJ_WRITE via Linux write() */
static NTSTATUS linux_handle_write(PDEVICE_OBJECT device, PIRP irp)
{
    hosted_device_t *hd = find_hosted_device(device);
    if (!hd || hd->linux_fd < 0)
        return STATUS_DEVICE_DOES_NOT_EXIST;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    uint32_t length = stack->Parameters.Write.Length;

    void *buffer = irp->AssociatedIrp_SystemBuffer;
    if (!buffer)
        buffer = irp->UserBuffer;
    if (!buffer || length == 0) {
        irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    ssize_t n = write(hd->linux_fd, buffer, length);
    if (n < 0) {
        irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        irp->IoStatus.Information = 0;
        return STATUS_UNSUCCESSFUL;
    }

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = (ULONG_PTR)n;
    return STATUS_SUCCESS;
}

/* Handle IRP_MJ_DEVICE_CONTROL via Linux ioctl() */
static NTSTATUS linux_handle_ioctl(PDEVICE_OBJECT device, PIRP irp)
{
    hosted_device_t *hd = find_hosted_device(device);
    if (!hd || hd->linux_fd < 0)
        return STATUS_DEVICE_DOES_NOT_EXIST;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    uint32_t win_ioctl = stack->Parameters.DeviceIoControl.IoControlCode;

    unsigned long linux_ioctl_code = 0;
    if (!windrv_translate_ioctl(win_ioctl, &linux_ioctl_code)) {
        /* No translation available -- pass raw to Linux (may fail) */
        LOG_WARN("No IOCTL translation for 0x%08x\n", win_ioctl);
        irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        irp->IoStatus.Information = 0;
        return STATUS_NOT_IMPLEMENTED;
    }

    void *buffer = irp->AssociatedIrp_SystemBuffer;
    int rc = ioctl(hd->linux_fd, linux_ioctl_code, buffer);
    if (rc < 0) {
        irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        irp->IoStatus.Information = 0;
        return STATUS_UNSUCCESSFUL;
    }

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information =
        stack->Parameters.DeviceIoControl.OutputBufferLength;
    return STATUS_SUCCESS;
}

/* Handle IRP_MJ_CLOSE by (optionally) closing the Linux fd */
static NTSTATUS linux_handle_close(PDEVICE_OBJECT device, PIRP irp)
{
    (void)device;
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

/* ===================================================================
 * 7. Synchronization Primitives (for driver use)
 *
 *   These complement the ntoskrnl_sync.c stubs but are available
 *   directly from the host for drivers that link at load time.
 * =================================================================== */

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    int             signaled;
    int             auto_reset; /* SynchronizationEvent */
} host_event_t;

__attribute__((ms_abi, visibility("default")))
void windrv_init_event(PKEVENT event, EVENT_TYPE type, BOOLEAN initial_state)
{
    host_event_t *he = (host_event_t *)calloc(1, sizeof(host_event_t));
    if (!he) {
        memset(event, 0, sizeof(KEVENT));
        return;
    }

    pthread_mutex_init(&he->mutex, NULL);
    pthread_cond_init(&he->cond, NULL);
    he->signaled = initial_state ? 1 : 0;
    he->auto_reset = (type == SynchronizationEvent) ? 1 : 0;

    event->_internal[0] = &he->mutex;
    event->_internal[1] = &he->cond;
    event->_internal[2] = (PVOID)(uintptr_t)type;
    event->_internal[3] = he; /* Store full struct for cleanup */
    event->Header.SignalState = he->signaled;
}

__attribute__((ms_abi, visibility("default")))
NTSTATUS windrv_wait_event(PKEVENT event, LARGE_INTEGER *timeout)
{
    host_event_t *he = (host_event_t *)event->_internal[3];
    if (!he) {
        /* Fall back to polling the SignalState */
        return event->Header.SignalState ? STATUS_SUCCESS : STATUS_TIMEOUT;
    }

    pthread_mutex_lock(&he->mutex);

    /* Non-blocking check */
    if (timeout && timeout->QuadPart == 0) {
        NTSTATUS result = he->signaled ? STATUS_SUCCESS : STATUS_TIMEOUT;
        if (result == STATUS_SUCCESS && he->auto_reset)
            he->signaled = 0;
        event->Header.SignalState = he->signaled;
        pthread_mutex_unlock(&he->mutex);
        return result;
    }

    /* Wait with optional timeout */
    while (!he->signaled) {
        if (timeout) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            long long ns = (-timeout->QuadPart) * 100; /* 100ns -> ns */
            ts.tv_sec += ns / 1000000000LL;
            ts.tv_nsec += ns % 1000000000LL;
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000L;
            }
            int rc = pthread_cond_timedwait(&he->cond, &he->mutex, &ts);
            if (rc != 0) {
                pthread_mutex_unlock(&he->mutex);
                return STATUS_TIMEOUT;
            }
        } else {
            pthread_cond_wait(&he->cond, &he->mutex);
        }
    }

    if (he->auto_reset)
        he->signaled = 0;
    event->Header.SignalState = he->signaled;
    pthread_mutex_unlock(&he->mutex);
    return STATUS_SUCCESS;
}

__attribute__((ms_abi, visibility("default")))
LONG windrv_set_event(PKEVENT event)
{
    host_event_t *he = (host_event_t *)event->_internal[3];
    LONG prev = event->Header.SignalState;

    if (he) {
        pthread_mutex_lock(&he->mutex);
        he->signaled = 1;
        event->Header.SignalState = 1;
        pthread_cond_broadcast(&he->cond);
        pthread_mutex_unlock(&he->mutex);
    } else {
        event->Header.SignalState = 1;
    }

    return prev;
}

__attribute__((ms_abi, visibility("default")))
void windrv_reset_event(PKEVENT event)
{
    host_event_t *he = (host_event_t *)event->_internal[3];
    if (he) {
        pthread_mutex_lock(&he->mutex);
        he->signaled = 0;
        event->Header.SignalState = 0;
        pthread_mutex_unlock(&he->mutex);
    } else {
        event->Header.SignalState = 0;
    }
}

/* Spinlock wrapper using pthread_spinlock_t */
__attribute__((ms_abi, visibility("default")))
void windrv_init_spinlock(PKSPIN_LOCK lock)
{
    pthread_spinlock_t *sl = (pthread_spinlock_t *)calloc(
        1, sizeof(pthread_spinlock_t));
    if (sl) {
        pthread_spin_init(sl, PTHREAD_PROCESS_PRIVATE);
        *lock = (KSPIN_LOCK)(uintptr_t)sl;
    } else {
        *lock = 0;
    }
}

__attribute__((ms_abi, visibility("default")))
KIRQL windrv_acquire_spinlock(PKSPIN_LOCK lock)
{
    pthread_spinlock_t *sl = (pthread_spinlock_t *)(uintptr_t)*lock;
    if (sl)
        pthread_spin_lock(sl);
    return PASSIVE_LEVEL;
}

__attribute__((ms_abi, visibility("default")))
void windrv_release_spinlock(PKSPIN_LOCK lock, KIRQL old_irql)
{
    (void)old_irql;
    pthread_spinlock_t *sl = (pthread_spinlock_t *)(uintptr_t)*lock;
    if (sl)
        pthread_spin_unlock(sl);
}

__attribute__((ms_abi, visibility("default")))
void windrv_destroy_spinlock(PKSPIN_LOCK lock)
{
    pthread_spinlock_t *sl = (pthread_spinlock_t *)(uintptr_t)*lock;
    if (sl) {
        pthread_spin_destroy(sl);
        free((void *)sl);
        *lock = 0;
    }
}

/* ===================================================================
 * 8. Loaded Driver Registry
 *
 *   Track all drivers loaded through the host.
 * =================================================================== */

#define MAX_LOADED_DRIVERS  32

typedef struct {
    PDRIVER_OBJECT  driver;
    char            name[256];
    char            sys_path[4096];
    void            *image_base;
    uint32_t        image_size;
    int             is_kernel_driver;   /* SERVICE_KERNEL_DRIVER */
    int             is_fs_driver;       /* SERVICE_FILE_SYSTEM_DRIVER */
    int             in_use;
} loaded_driver_t;

static loaded_driver_t  g_loaded_drivers[MAX_LOADED_DRIVERS];
static int              g_loaded_count = 0;
static pthread_mutex_t  g_driver_lock = PTHREAD_MUTEX_INITIALIZER;

/* ===================================================================
 * 9. Driver Loading
 * =================================================================== */

/* Default dispatch for unhandled IRP major functions */
static NTSTATUS __attribute__((ms_abi, unused)) host_default_dispatch(
    PDEVICE_OBJECT device, PIRP irp)
{
    (void)device;
    irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
    irp->IoStatus.Information = 0;
    irp->PendingReturned = TRUE;
    return STATUS_NOT_IMPLEMENTED;
}

/* Fallback dispatch: if the driver does not handle an IRP, try Linux I/O */
static NTSTATUS __attribute__((ms_abi)) host_fallback_dispatch(
    PDEVICE_OBJECT device, PIRP irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

    switch (stack->MajorFunction) {
    case IRP_MJ_CREATE:
        return linux_handle_create(device, irp);
    case IRP_MJ_CLOSE:
        return linux_handle_close(device, irp);
    case IRP_MJ_READ:
        return linux_handle_read(device, irp);
    case IRP_MJ_WRITE:
        return linux_handle_write(device, irp);
    case IRP_MJ_DEVICE_CONTROL:
        return linux_handle_ioctl(device, irp);
    default:
        irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        irp->IoStatus.Information = 0;
        return STATUS_NOT_IMPLEMENTED;
    }
}

__attribute__((ms_abi, visibility("default")))
int windrv_host_load_driver(const char *sys_path, const char *registry_path)
{
    LOG_INFO("Loading driver: %s\n", sys_path);

    if (!sys_path) {
        LOG_ERR("NULL sys_path\n");
        return -1;
    }

    /* Check driver limit -- keep lock held through the check to prevent
     * TOCTOU race where another thread registers between our check and
     * registration. We release after reserving the slot below. */
    pthread_mutex_lock(&g_driver_lock);
    if (g_loaded_count >= MAX_LOADED_DRIVERS) {
        pthread_mutex_unlock(&g_driver_lock);
        LOG_ERR("Maximum drivers (%d) exceeded\n", MAX_LOADED_DRIVERS);
        return -1;
    }
    /* Reserve the slot now while holding the lock */
    int reserved_slot = g_loaded_count;
    g_loaded_count++;
    pthread_mutex_unlock(&g_driver_lock);

    /* Extract driver name from path:
     * "C:\Windows\System32\drivers\foo.sys" -> "foo"
     * "/path/to/foo.sys" -> "foo" */
    const char *base = sys_path;
    const char *p;
    for (p = sys_path; *p; p++) {
        if (*p == '/' || *p == '\\')
            base = p + 1;
    }
    char driver_name[256];
    snprintf(driver_name, sizeof(driver_name), "%s", base);
    /* Strip .sys extension */
    char *dot = strrchr(driver_name, '.');
    if (dot && (strcasecmp(dot, ".sys") == 0))
        *dot = '\0';

    /* Load the .sys PE image via dlopen (our PE loader handles this) */
    void *handle = dlopen(sys_path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        LOG_ERR("Failed to load %s: %s\n", sys_path, dlerror());
        pthread_mutex_lock(&g_driver_lock);
        if (reserved_slot == g_loaded_count - 1) g_loaded_count--;
        else g_loaded_drivers[reserved_slot].in_use = 0;
        pthread_mutex_unlock(&g_driver_lock);
        return -1;
    }

    /* Find DriverEntry */
    void *entry = dlsym(handle, "DriverEntry");
    if (!entry) {
        /* Some drivers export GsDriverEntry (for stack cookie init) */
        entry = dlsym(handle, "GsDriverEntry");
    }
    if (!entry) {
        LOG_ERR("No DriverEntry found in %s\n", sys_path);
        dlclose(handle);
        pthread_mutex_lock(&g_driver_lock);
        if (reserved_slot == g_loaded_count - 1) g_loaded_count--;
        else g_loaded_drivers[reserved_slot].in_use = 0;
        pthread_mutex_unlock(&g_driver_lock);
        return -1;
    }

    /* Allocate DRIVER_OBJECT */
    PDRIVER_OBJECT drv = (PDRIVER_OBJECT)calloc(1, sizeof(DRIVER_OBJECT));
    PDRIVER_EXTENSION ext = (PDRIVER_EXTENSION)calloc(1, sizeof(DRIVER_EXTENSION));
    if (!drv || !ext) {
        free(drv);
        free(ext);
        dlclose(handle);
        pthread_mutex_lock(&g_driver_lock);
        if (reserved_slot == g_loaded_count - 1) g_loaded_count--;
        else g_loaded_drivers[reserved_slot].in_use = 0;
        pthread_mutex_unlock(&g_driver_lock);
        return -1;
    }

    drv->Type = IO_TYPE_DRIVER;
    drv->Size = sizeof(DRIVER_OBJECT);
    drv->DriverStart = handle; /* Use dlopen handle as base */
    drv->DriverSize = 0;
    drv->DriverInit = entry;
    drv->DriverExtension = ext;
    ext->DriverObject = drv;

    /* Build driver name: \Driver\<name> (UTF-16LE) */
    uint16_t *name_buf = (uint16_t *)calloc(256, sizeof(uint16_t));
    if (name_buf) {
        char narrow[256];
        snprintf(narrow, sizeof(narrow), "\\Driver\\%s", driver_name);
        narrow_to_ustr16(narrow, name_buf, 256);
        drv->DriverName.Length = (USHORT)(wcslen16(name_buf) * sizeof(WCHAR));
        drv->DriverName.MaximumLength = drv->DriverName.Length + sizeof(WCHAR);
        drv->DriverName.Buffer = name_buf;
    }

    /* Build registry path UNICODE_STRING */
    uint16_t *reg_buf = (uint16_t *)calloc(512, sizeof(uint16_t));
    UNICODE_STRING *reg_ustr = (UNICODE_STRING *)calloc(1, sizeof(UNICODE_STRING));
    if (reg_buf && reg_ustr) {
        const char *rpath = registry_path ? registry_path : "";
        char narrow_rp[512];
        if (rpath[0]) {
            snprintf(narrow_rp, sizeof(narrow_rp), "%s", rpath);
        } else {
            snprintf(narrow_rp, sizeof(narrow_rp),
                     "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s",
                     driver_name);
        }
        narrow_to_ustr16(narrow_rp, reg_buf, 512);
        reg_ustr->Length = (USHORT)(wcslen16(reg_buf) * sizeof(WCHAR));
        reg_ustr->MaximumLength = reg_ustr->Length + sizeof(WCHAR);
        reg_ustr->Buffer = reg_buf;
    } else {
        free(reg_buf);
        free(reg_ustr);
        reg_buf = NULL;
        reg_ustr = NULL;
    }

    /* Initialize all MajorFunction entries to the fallback dispatcher.
     * The fallback tries Linux I/O for CREATE/READ/WRITE/CLOSE/IOCTL
     * and returns STATUS_NOT_IMPLEMENTED for the rest. */
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        drv->MajorFunction[i] = host_fallback_dispatch;

    LOG_INFO("Calling DriverEntry for '%s'...\n", driver_name);

    /* Call DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING) */
    NTSTATUS status = (NTSTATUS)abi_call_win64_2(
        entry,
        (uint64_t)(uintptr_t)drv,
        (uint64_t)(uintptr_t)reg_ustr);

    if (!NT_SUCCESS(status)) {
        LOG_ERR("DriverEntry for '%s' FAILED: NTSTATUS 0x%08X\n",
                driver_name, (unsigned)status);
        pthread_mutex_lock(&g_driver_lock);
        if (reserved_slot == g_loaded_count - 1) g_loaded_count--;
        else g_loaded_drivers[reserved_slot].in_use = 0;
        pthread_mutex_unlock(&g_driver_lock);
        free(drv);
        free(ext);
        free(name_buf);
        free(reg_buf);
        free(reg_ustr);
        dlclose(handle);
        return (int)status;
    }

    LOG_INFO("DriverEntry for '%s' returned STATUS_SUCCESS\n", driver_name);

    /* Report devices */
    PDEVICE_OBJECT dev = drv->DeviceObject;
    int dev_count = 0;
    while (dev) {
        dev_count++;
        char dname[512] = "(unnamed)";
        if (dev->DeviceName.Buffer)
            ustr_to_narrow(&dev->DeviceName, dname, sizeof(dname));
        LOG_INFO("  Device %d: %p '%s' type=0x%x\n",
                 dev_count, (void *)dev, dname, dev->DeviceType);
        dev = dev->NextDevice;
    }

    if (drv->DriverUnload)
        LOG_INFO("  DriverUnload: %p\n", (void *)drv->DriverUnload);

    /* Fill the pre-reserved slot in the loaded driver table */
    pthread_mutex_lock(&g_driver_lock);
    loaded_driver_t *ld = &g_loaded_drivers[reserved_slot];
    memset(ld, 0, sizeof(*ld));
    ld->driver = drv;
    snprintf(ld->name, sizeof(ld->name), "%s", driver_name);
    snprintf(ld->sys_path, sizeof(ld->sys_path), "%s", sys_path);
    ld->image_base = handle;
    ld->is_kernel_driver = 1;
    ld->in_use = 1;
    pthread_mutex_unlock(&g_driver_lock);

    /* RegistryPath is a transient parameter to DriverEntry; drivers that
     * need it must copy the buffer. Free after DriverEntry returns to
     * avoid per-load leak. */
    free(reg_buf);
    free(reg_ustr);

    return 0;
}

/* ===================================================================
 * 10. Driver Unloading
 * =================================================================== */

__attribute__((ms_abi, visibility("default")))
void windrv_host_unload_driver(PDRIVER_OBJECT driver)
{
    if (!driver)
        return;

    char dname[512] = "(unknown)";
    if (driver->DriverName.Buffer)
        ustr_to_narrow(&driver->DriverName, dname, sizeof(dname));

    LOG_INFO("Unloading driver '%s'\n", dname);

    /* Call DriverUnload if registered */
    if (driver->DriverUnload) {
        LOG_INFO("Calling DriverUnload for '%s'\n", dname);
        abi_call_win64_1((void *)driver->DriverUnload,
                         (uint64_t)(uintptr_t)driver);
    }

    /* Delete all devices */
    while (driver->DeviceObject) {
        PDEVICE_OBJECT dev = driver->DeviceObject;
        windrv_delete_device(dev);
    }

    /* Remove from loaded driver table */
    pthread_mutex_lock(&g_driver_lock);
    for (int i = 0; i < g_loaded_count; i++) {
        if (g_loaded_drivers[i].in_use &&
            g_loaded_drivers[i].driver == driver) {
            /* Close the dlopen handle */
            if (g_loaded_drivers[i].image_base)
                dlclose(g_loaded_drivers[i].image_base);
            g_loaded_drivers[i].in_use = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_driver_lock);

    /* Free driver object and associated allocations */
    if (driver->DriverName.Buffer)
        free(driver->DriverName.Buffer);
    if (driver->DriverExtension)
        free(driver->DriverExtension);
    free(driver);
}

/* ===================================================================
 * 11. SCM (Service Control Manager) Integration
 *
 *   SERVICE_KERNEL_DRIVER and SERVICE_FILE_SYSTEM_DRIVER service types
 *   are routed through the driver host instead of being launched as
 *   regular processes.
 * =================================================================== */

/* Service type constants matching scm.h */
#ifndef SERVICE_KERNEL_DRIVER
#define SERVICE_KERNEL_DRIVER       0x00000001
#endif
#ifndef SERVICE_FILE_SYSTEM_DRIVER
#define SERVICE_FILE_SYSTEM_DRIVER  0x00000002
#endif

/* Called by SCM when a kernel driver service is started */
__attribute__((visibility("default")))
int windrv_scm_start_driver(const char *name, const char *binary_path,
                             int service_type)
{
    LOG_INFO("SCM start request: name='%s' path='%s' type=0x%x\n",
             name, binary_path, service_type);

    if (service_type != SERVICE_KERNEL_DRIVER &&
        service_type != SERVICE_FILE_SYSTEM_DRIVER) {
        LOG_ERR("Service '%s' is not a driver type (type=0x%x)\n",
                name, service_type);
        return -1;
    }

    /* Build registry path */
    char reg_path[512];
    snprintf(reg_path, sizeof(reg_path),
             "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s",
             name);

    return windrv_host_load_driver(binary_path, reg_path);
}

/* Called by SCM when a kernel driver service is stopped */
__attribute__((visibility("default")))
int windrv_scm_stop_driver(const char *name)
{
    LOG_INFO("SCM stop request: name='%s'\n", name);

    pthread_mutex_lock(&g_driver_lock);
    for (int i = 0; i < g_loaded_count; i++) {
        if (g_loaded_drivers[i].in_use &&
            strcasecmp(g_loaded_drivers[i].name, name) == 0) {
            PDRIVER_OBJECT drv = g_loaded_drivers[i].driver;
            pthread_mutex_unlock(&g_driver_lock);
            windrv_host_unload_driver(drv);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_driver_lock);

    LOG_WARN("Driver '%s' not found in loaded driver table\n", name);
    return -1;
}

/* Query driver status for SCM */
__attribute__((visibility("default")))
int windrv_scm_query_driver(const char *name, int *state_out, int *device_count_out)
{
    pthread_mutex_lock(&g_driver_lock);
    for (int i = 0; i < g_loaded_count; i++) {
        if (g_loaded_drivers[i].in_use &&
            strcasecmp(g_loaded_drivers[i].name, name) == 0) {
            if (state_out)
                *state_out = 4; /* SERVICE_RUNNING */

            if (device_count_out) {
                int count = 0;
                PDEVICE_OBJECT dev = g_loaded_drivers[i].driver->DeviceObject;
                while (dev) { count++; dev = dev->NextDevice; }
                *device_count_out = count;
            }

            pthread_mutex_unlock(&g_driver_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_driver_lock);

    if (state_out)
        *state_out = 1; /* SERVICE_STOPPED */
    if (device_count_out)
        *device_count_out = 0;
    return -1;
}

/* ===================================================================
 * 12. IRP Timeout and Watchdog
 *
 *   Send an IRP and wait for completion with a timeout.
 *   If the driver takes too long, cancel the IRP.
 * =================================================================== */

typedef struct {
    PDEVICE_OBJECT  device;
    PIRP            irp;
    NTSTATUS        result;
    int             completed;
    int             cancelled;  /* Set by caller on timeout; thread checks before freeing */
    pthread_mutex_t lock;
    pthread_cond_t  cond;
} irp_async_ctx_t;

static void *irp_dispatch_thread(void *arg)
{
    irp_async_ctx_t *ctx = (irp_async_ctx_t *)arg;

    ctx->result = windrv_call_driver(ctx->device, ctx->irp);

    pthread_mutex_lock(&ctx->lock);
    ctx->completed = 1;
    int was_cancelled = ctx->cancelled;
    pthread_cond_signal(&ctx->cond);
    pthread_mutex_unlock(&ctx->lock);

    /* If the caller timed out and abandoned us, we own the ctx -- free it */
    if (was_cancelled) {
        pthread_mutex_destroy(&ctx->lock);
        pthread_cond_destroy(&ctx->cond);
        free(ctx);
    }

    return NULL;
}

/* Send IRP to device with a timeout (in milliseconds).
 * timeout_ms == 0 means no timeout (infinite wait).
 * Returns the IRP's completion status. */
__attribute__((ms_abi, visibility("default")))
NTSTATUS windrv_call_driver_timeout(PDEVICE_OBJECT device, PIRP irp,
                                     uint32_t timeout_ms)
{
    if (timeout_ms == 0) {
        /* No timeout -- synchronous dispatch */
        return windrv_call_driver(device, irp);
    }

    /* Heap-allocate ctx so the dispatch thread can outlive us on timeout
     * without causing a use-after-free on a stack-allocated struct. */
    irp_async_ctx_t *ctx = (irp_async_ctx_t *)calloc(1, sizeof(irp_async_ctx_t));
    if (!ctx)
        return STATUS_INSUFFICIENT_RESOURCES;

    ctx->device = device;
    ctx->irp = irp;
    ctx->result = STATUS_PENDING;
    ctx->completed = 0;
    ctx->cancelled = 0;
    pthread_mutex_init(&ctx->lock, NULL);
    pthread_cond_init(&ctx->cond, NULL);

    pthread_t tid;
    if (pthread_create(&tid, NULL, irp_dispatch_thread, ctx) != 0) {
        pthread_mutex_destroy(&ctx->lock);
        pthread_cond_destroy(&ctx->cond);
        free(ctx);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    pthread_detach(tid);

    /* Wait with timeout */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&ctx->lock);
    while (!ctx->completed) {
        int rc = pthread_cond_timedwait(&ctx->cond, &ctx->lock, &ts);
        if (rc != 0) {
            /* Timeout -- mark cancelled so the thread will free ctx when done */
            ctx->cancelled = 1;
            irp->Cancel = TRUE;
            LOG_WARN("IRP timed out after %u ms, cancelling\n", timeout_ms);
            pthread_mutex_unlock(&ctx->lock);
            /* Don't destroy mutex/cond or free ctx -- the thread will do it */
            return STATUS_TIMEOUT;
        }
    }
    pthread_mutex_unlock(&ctx->lock);

    NTSTATUS result = ctx->result;
    pthread_mutex_destroy(&ctx->lock);
    pthread_cond_destroy(&ctx->cond);
    free(ctx);
    return result;
}

/* ===================================================================
 * 13. Host Initialization and Shutdown
 * =================================================================== */

static int g_host_initialized = 0;

__attribute__((visibility("default")))
void windrv_host_init(void)
{
    if (g_host_initialized)
        return;

    LOG_INFO("Initializing driver host subsystem\n");

    /* Initialize namespace */
    memset(g_namespace, 0, sizeof(g_namespace));
    g_ns_count = 0;
    ns_init_wellknown();

    /* Initialize pool tracking */
    memset(g_pool_stats, 0, sizeof(g_pool_stats));
    g_pool_stat_count = 0;
    g_pool_total_bytes = 0;
    g_pool_total_allocs = 0;
    g_pool_list = NULL;

    /* Initialize device and driver tables */
    memset(g_hosted_devices, 0, sizeof(g_hosted_devices));
    g_hosted_count = 0;
    memset(g_loaded_drivers, 0, sizeof(g_loaded_drivers));
    g_loaded_count = 0;

    g_host_initialized = 1;

    LOG_INFO("Driver host initialized (%d well-known devices registered)\n",
             g_ns_count);
}

/* Shut down the driver host: unload all drivers and dump pool stats */
__attribute__((visibility("default")))
void windrv_host_shutdown(void)
{
    if (!g_host_initialized)
        return;

    LOG_INFO("Shutting down driver host\n");

    /* Snapshot the driver list while holding the lock, then iterate
     * the snapshot without holding the lock. This avoids stale index
     * issues when windrv_host_unload_driver modifies the table. */
    typedef struct { PDRIVER_OBJECT drv; char name[256]; } shutdown_entry_t;
    int shutdown_count = 0;
    shutdown_entry_t *snapshot = NULL;

    pthread_mutex_lock(&g_driver_lock);
    if (g_loaded_count > 0) {
        snapshot = (shutdown_entry_t *)calloc(g_loaded_count, sizeof(shutdown_entry_t));
        if (snapshot) {
            for (int i = g_loaded_count - 1; i >= 0; i--) {
                if (g_loaded_drivers[i].in_use) {
                    snapshot[shutdown_count].drv = g_loaded_drivers[i].driver;
                    snprintf(snapshot[shutdown_count].name,
                             sizeof(snapshot[shutdown_count].name),
                             "%s", g_loaded_drivers[i].name);
                    shutdown_count++;
                }
            }
        }
    }
    pthread_mutex_unlock(&g_driver_lock);

    /* Unload from the snapshot -- no lock held, no stale indices */
    for (int i = 0; i < shutdown_count; i++) {
        LOG_INFO("Unloading driver '%s' during shutdown\n", snapshot[i].name);
        windrv_host_unload_driver(snapshot[i].drv);
    }
    free(snapshot);

    /* Dump pool stats if any leaks */
    if (g_pool_total_bytes > 0) {
        LOG_WARN("Pool memory leak detected: %zu bytes outstanding\n",
                 g_pool_total_bytes);
        windrv_pool_dump_stats();
    }

    /* Clean up remaining namespace entries */
    pthread_mutex_lock(&g_ns_lock);
    g_ns_count = 0;
    memset(g_namespace, 0, sizeof(g_namespace));
    pthread_mutex_unlock(&g_ns_lock);

    g_host_initialized = 0;
    LOG_INFO("Driver host shut down\n");
}

/* ===================================================================
 * 14. Debug / Inspection APIs
 * =================================================================== */

/* List all registered devices in the namespace */
__attribute__((visibility("default")))
void windrv_host_dump_namespace(void)
{
    pthread_mutex_lock(&g_ns_lock);
    LOG_INFO("=== Device Namespace (%d entries) ===\n", g_ns_count);
    for (int i = 0; i < g_ns_count; i++) {
        if (!g_namespace[i].in_use)
            continue;

        char name[MAX_NS_NAME];
        for (size_t j = 0; j < MAX_NS_NAME - 1 && g_namespace[i].wname[j]; j++)
            name[j] = (char)(g_namespace[i].wname[j] & 0xFF);
        name[MAX_NS_NAME - 1] = '\0';
        /* Find the actual end */
        for (size_t j = 0; j < MAX_NS_NAME; j++) {
            if (!g_namespace[i].wname[j]) {
                name[j] = '\0';
                break;
            }
        }

        if (g_namespace[i].device) {
            LOG_INFO("  [DEV]  %-40s -> %p (type=0x%x)\n",
                     name, (void *)g_namespace[i].device,
                     g_namespace[i].device->DeviceType);
        } else if (g_namespace[i].target[0]) {
            char target[MAX_NS_NAME];
            for (size_t j = 0; j < MAX_NS_NAME; j++) {
                target[j] = (char)(g_namespace[i].target[j] & 0xFF);
                if (!g_namespace[i].target[j]) break;
            }
            target[MAX_NS_NAME - 1] = '\0';
            LOG_INFO("  [LINK] %-40s -> %s\n", name, target);
        } else if (g_namespace[i].linux_path[0]) {
            LOG_INFO("  [PATH] %-40s -> %s\n",
                     name, g_namespace[i].linux_path);
        }
    }
    LOG_INFO("====================================\n");
    pthread_mutex_unlock(&g_ns_lock);
}

/* List all loaded drivers */
__attribute__((visibility("default")))
void windrv_host_dump_drivers(void)
{
    pthread_mutex_lock(&g_driver_lock);
    LOG_INFO("=== Loaded Drivers (%d) ===\n", g_loaded_count);
    for (int i = 0; i < g_loaded_count; i++) {
        if (!g_loaded_drivers[i].in_use)
            continue;

        loaded_driver_t *ld = &g_loaded_drivers[i];
        int dev_count = 0;
        PDEVICE_OBJECT dev = ld->driver->DeviceObject;
        while (dev) { dev_count++; dev = dev->NextDevice; }

        LOG_INFO("  [%d] %-20s path=%s devices=%d type=%s\n",
                 i, ld->name, ld->sys_path, dev_count,
                 ld->is_fs_driver ? "FS" : "KERNEL");
    }
    LOG_INFO("==========================\n");
    pthread_mutex_unlock(&g_driver_lock);
}

/* ===================================================================
 * 15. High-Level IRP send helpers
 *
 *   Convenience functions for sending specific IRP types to a device.
 * =================================================================== */

/* Send an IRP_MJ_CREATE to a device (open) */
__attribute__((ms_abi, visibility("default")))
NTSTATUS windrv_device_open(PDEVICE_OBJECT device)
{
    PIRP irp = build_irp_for_operation(IRP_MJ_CREATE, device,
                                        NULL, 0, 0, 0, 0);
    if (!irp)
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = windrv_call_driver(device, irp);
    windrv_free_irp(irp);
    return status;
}

/* Send an IRP_MJ_CLOSE to a device (close) */
__attribute__((ms_abi, visibility("default")))
NTSTATUS windrv_device_close(PDEVICE_OBJECT device)
{
    PIRP irp = build_irp_for_operation(IRP_MJ_CLOSE, device,
                                        NULL, 0, 0, 0, 0);
    if (!irp)
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = windrv_call_driver(device, irp);
    windrv_free_irp(irp);
    return status;
}

/* Send an IRP_MJ_READ to a device */
__attribute__((ms_abi, visibility("default")))
NTSTATUS windrv_device_read(PDEVICE_OBJECT device, void *buffer,
                             uint32_t length, uint32_t *bytes_read)
{
    PIRP irp = build_irp_for_operation(IRP_MJ_READ, device,
                                        buffer, length, 0, 0, 0);
    if (!irp)
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = windrv_call_driver(device, irp);

    if (bytes_read)
        *bytes_read = (uint32_t)irp->IoStatus.Information;

    /* Copy from system buffer back to user buffer if buffered I/O */
    if (NT_SUCCESS(status) && irp->AssociatedIrp_SystemBuffer &&
        irp->AssociatedIrp_SystemBuffer != buffer) {
        uint32_t to_copy = (uint32_t)irp->IoStatus.Information;
        if (to_copy > length)
            to_copy = length;
        memcpy(buffer, irp->AssociatedIrp_SystemBuffer, to_copy);
    }

    windrv_free_irp(irp);
    return status;
}

/* Send an IRP_MJ_WRITE to a device */
__attribute__((ms_abi, visibility("default")))
NTSTATUS windrv_device_write(PDEVICE_OBJECT device, const void *buffer,
                              uint32_t length, uint32_t *bytes_written)
{
    PIRP irp = build_irp_for_operation(IRP_MJ_WRITE, device,
                                        (void *)buffer, length, 0, 0, 0);
    if (!irp)
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = windrv_call_driver(device, irp);

    if (bytes_written)
        *bytes_written = (uint32_t)irp->IoStatus.Information;

    windrv_free_irp(irp);
    return status;
}

/* Send an IRP_MJ_DEVICE_CONTROL to a device (ioctl) */
__attribute__((ms_abi, visibility("default")))
NTSTATUS windrv_device_ioctl(PDEVICE_OBJECT device,
                              uint32_t ioctl_code,
                              void *input_buf, uint32_t input_len,
                              void *output_buf, uint32_t output_len,
                              uint32_t *bytes_returned)
{
    PIRP irp = build_irp_for_operation(IRP_MJ_DEVICE_CONTROL, device,
                                        input_buf, 0,
                                        ioctl_code, input_len, output_len);
    if (!irp)
        return STATUS_INSUFFICIENT_RESOURCES;

    irp->UserBuffer = output_buf;

    NTSTATUS status = windrv_call_driver(device, irp);

    if (bytes_returned)
        *bytes_returned = (uint32_t)irp->IoStatus.Information;

    /* Copy system buffer to output */
    if (NT_SUCCESS(status) && output_buf && irp->AssociatedIrp_SystemBuffer) {
        uint32_t to_copy = (uint32_t)irp->IoStatus.Information;
        if (to_copy > output_len)
            to_copy = output_len;
        memcpy(output_buf, irp->AssociatedIrp_SystemBuffer, to_copy);
    }

    windrv_free_irp(irp);
    return status;
}

/* ===================================================================
 * 16. PnP / Power IRP helpers
 *
 *   Drivers that implement PnP or power management need these IRPs.
 * =================================================================== */

/* Send a PnP IRP with a specific minor function */
__attribute__((ms_abi, visibility("default")))
NTSTATUS windrv_send_pnp_irp(PDEVICE_OBJECT device, UCHAR minor_function)
{
    PIRP irp = windrv_alloc_irp(device ? device->StackSize : 1);
    if (!irp)
        return STATUS_INSUFFICIENT_RESOURCES;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    stack->MajorFunction = IRP_MJ_PNP;
    stack->MinorFunction = minor_function;
    stack->DeviceObject = device;

    /* Default IoStatus for PnP (some drivers check this) */
    irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
    irp->IoStatus.Information = 0;

    NTSTATUS status = windrv_call_driver(device, irp);
    windrv_free_irp(irp);
    return status;
}

/* Send IRP_MN_START_DEVICE to the device */
__attribute__((ms_abi, visibility("default")))
NTSTATUS windrv_start_device(PDEVICE_OBJECT device)
{
    LOG_INFO("Sending IRP_MN_START_DEVICE to %p\n", (void *)device);
    return windrv_send_pnp_irp(device, IRP_MN_START_DEVICE);
}

/* Send IRP_MN_REMOVE_DEVICE to the device */
__attribute__((ms_abi, visibility("default")))
NTSTATUS windrv_remove_device(PDEVICE_OBJECT device)
{
    LOG_INFO("Sending IRP_MN_REMOVE_DEVICE to %p\n", (void *)device);
    return windrv_send_pnp_irp(device, IRP_MN_REMOVE_DEVICE);
}

/* Send a Power IRP */
__attribute__((ms_abi, visibility("default")))
NTSTATUS windrv_send_power_irp(PDEVICE_OBJECT device, UCHAR minor_function)
{
    PIRP irp = windrv_alloc_irp(device ? device->StackSize : 1);
    if (!irp)
        return STATUS_INSUFFICIENT_RESOURCES;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    stack->MajorFunction = IRP_MJ_POWER;
    stack->MinorFunction = minor_function;
    stack->DeviceObject = device;

    irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;

    NTSTATUS status = windrv_call_driver(device, irp);
    windrv_free_irp(irp);
    return status;
}

/* ===================================================================
 * 17. Device Lookup by Name
 *
 *   Resolves a Windows device path to a DEVICE_OBJECT through the
 *   namespace, following symlinks.
 * =================================================================== */

__attribute__((ms_abi, visibility("default")))
PDEVICE_OBJECT windrv_find_device(const char *device_path)
{
    uint16_t wpath[MAX_NS_NAME];
    narrow_to_ustr16(device_path, wpath, MAX_NS_NAME);
    return ns_resolve_device(wpath, 8); /* max 8 symlink hops */
}

__attribute__((ms_abi, visibility("default")))
PDEVICE_OBJECT windrv_find_device_w(const uint16_t *device_path)
{
    return ns_resolve_device(device_path, 8);
}

/* ===================================================================
 * 18. Namespace Symlink Management (public API)
 *
 *   Used by IoCreateSymbolicLink / IoDeleteSymbolicLink implementations
 *   that want to register in the host namespace.
 * =================================================================== */

__attribute__((ms_abi, visibility("default")))
NTSTATUS windrv_create_symlink(PUNICODE_STRING link_name,
                                PUNICODE_STRING target_name)
{
    if (!link_name || !link_name->Buffer ||
        !target_name || !target_name->Buffer)
        return STATUS_INVALID_PARAMETER;

    uint16_t lbuf[MAX_NS_NAME], tbuf[MAX_NS_NAME];
    copy_ustr_buf(lbuf, MAX_NS_NAME, link_name);
    copy_ustr_buf(tbuf, MAX_NS_NAME, target_name);

    if (ns_register_symlink(lbuf, tbuf) < 0)
        return STATUS_INSUFFICIENT_RESOURCES;

    char ln[512], tn[512];
    ustr_to_narrow(link_name, ln, sizeof(ln));
    ustr_to_narrow(target_name, tn, sizeof(tn));
    LOG_INFO("Symlink: '%s' -> '%s'\n", ln, tn);

    return STATUS_SUCCESS;
}

__attribute__((ms_abi, visibility("default")))
NTSTATUS windrv_delete_symlink(PUNICODE_STRING link_name)
{
    if (!link_name || !link_name->Buffer)
        return STATUS_INVALID_PARAMETER;

    uint16_t lbuf[MAX_NS_NAME];
    copy_ustr_buf(lbuf, MAX_NS_NAME, link_name);
    ns_remove(lbuf);
    return STATUS_SUCCESS;
}
