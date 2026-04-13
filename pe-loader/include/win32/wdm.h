/*
 * wdm.h - Windows Driver Model type definitions
 *
 * Provides the core structures that Windows kernel drivers (.sys) expect:
 * DRIVER_OBJECT, DEVICE_OBJECT, IRP, IO_STACK_LOCATION, etc.
 *
 * These are userspace-compatible definitions that mirror the Windows
 * kernel structures at the ABI level.
 */

#ifndef WDM_H
#define WDM_H

#include "windef.h"
#include "winnt.h"

/* BOOLEAN type (Windows uses UCHAR) */
#ifndef BOOLEAN
typedef UCHAR BOOLEAN;
#endif

/* ===== Forward declarations ===== */
typedef struct _DEVICE_OBJECT   DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef struct _DRIVER_OBJECT   DRIVER_OBJECT, *PDRIVER_OBJECT;
typedef struct _IRP             IRP, *PIRP;
typedef struct _IO_STACK_LOCATION IO_STACK_LOCATION, *PIO_STACK_LOCATION;
typedef struct _FILE_OBJECT     FILE_OBJECT, *PFILE_OBJECT;
typedef struct _MDL             MDL, *PMDL;
typedef struct _KDPC            KDPC, *PKDPC;

/* ===== NTSTATUS helpers ===== */
#define NT_SUCCESS(Status)          ((NTSTATUS)(Status) >= 0)
#define NT_INFORMATION(Status)      (((ULONG)(Status) >> 30) == 1)
#define NT_WARNING(Status)          (((ULONG)(Status) >> 30) == 2)
#define NT_ERROR(Status)            (((ULONG)(Status) >> 30) == 3)

/* Additional NTSTATUS codes for drivers */
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009A)
#define STATUS_DEVICE_NOT_READY         ((NTSTATUS)0xC00000A3)
#define STATUS_CANCELLED                ((NTSTATUS)0xC0000120)
#define STATUS_DELETE_PENDING           ((NTSTATUS)0xC0000056)
#define STATUS_OBJECT_NAME_INVALID      ((NTSTATUS)0xC0000033)
#define STATUS_DEVICE_DOES_NOT_EXIST    ((NTSTATUS)0xC00000C0)
#define STATUS_MORE_PROCESSING_REQUIRED ((NTSTATUS)0x00000016)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023)

/* ===== IRQL (Interrupt Request Level) ===== */
typedef UCHAR KIRQL, *PKIRQL;

#define PASSIVE_LEVEL   0
#define APC_LEVEL       1
#define DISPATCH_LEVEL  2
#define DIRQL           3   /* Device IRQL (not precisely emulated) */

/* ===== Pool types ===== */
typedef enum _POOL_TYPE {
    NonPagedPool                = 0,
    PagedPool                   = 1,
    NonPagedPoolMustSucceed     = 2,
    NonPagedPoolCacheAligned    = 4,
    PagedPoolCacheAligned       = 5,
    NonPagedPoolNx              = 512
} POOL_TYPE;

/* Pool allocation tags */
#define POOL_TAG(a,b,c,d) ((ULONG)(a) | ((ULONG)(b)<<8) | ((ULONG)(c)<<16) | ((ULONG)(d)<<24))

/* ===== IRP Major Function Codes ===== */
#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_QUERY_INFORMATION        0x05
#define IRP_MJ_SET_INFORMATION          0x06
#define IRP_MJ_FLUSH_BUFFERS            0x09
#define IRP_MJ_QUERY_VOLUME_INFORMATION 0x0A
#define IRP_MJ_DIRECTORY_CONTROL        0x0C
#define IRP_MJ_FILE_SYSTEM_CONTROL      0x0D
#define IRP_MJ_DEVICE_CONTROL           0x0E
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0F
#define IRP_MJ_SHUTDOWN                 0x10
#define IRP_MJ_LOCK_CONTROL             0x11
#define IRP_MJ_CLEANUP                  0x12
#define IRP_MJ_POWER                    0x16
#define IRP_MJ_SYSTEM_CONTROL           0x17
#define IRP_MJ_PNP                      0x1B
#define IRP_MJ_MAXIMUM_FUNCTION         0x1B

/* IRP Minor PnP codes */
#define IRP_MN_START_DEVICE             0x00
#define IRP_MN_QUERY_REMOVE_DEVICE      0x01
#define IRP_MN_REMOVE_DEVICE            0x02
#define IRP_MN_CANCEL_REMOVE_DEVICE     0x03
#define IRP_MN_STOP_DEVICE              0x04
#define IRP_MN_QUERY_STOP_DEVICE        0x05
#define IRP_MN_CANCEL_STOP_DEVICE       0x06
#define IRP_MN_QUERY_DEVICE_RELATIONS   0x07
#define IRP_MN_QUERY_CAPABILITIES       0x09

/* ===== I/O Control codes ===== */
#define METHOD_BUFFERED         0
#define METHOD_IN_DIRECT        1
#define METHOD_OUT_DIRECT       2
#define METHOD_NEITHER          3

#define FILE_ANY_ACCESS         0
#define FILE_READ_ACCESS        1
#define FILE_WRITE_ACCESS       2

#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))

#define IOCTL_METHOD(code)      ((code) & 0x3)
#define IOCTL_FUNCTION(code)    (((code) >> 2) & 0xFFF)
#define IOCTL_DEVICE(code)      (((code) >> 16) & 0xFFFF)

/* Common device types */
#define FILE_DEVICE_UNKNOWN         0x00000022
#define FILE_DEVICE_BEEP            0x00000001
#define FILE_DEVICE_NETWORK         0x00000012
#define FILE_DEVICE_TRANSPORT       0x00000021
#define FILE_DEVICE_KS              0x0000002F
#define FILE_DEVICE_KSEC            0x00000039

/* Device characteristics */
#define FILE_REMOVABLE_MEDIA        0x00000001
#define FILE_READ_ONLY_DEVICE       0x00000002
#define FILE_DEVICE_SECURE_OPEN     0x00000100

/* Device object flags */
#define DO_BUFFERED_IO              0x00000004
#define DO_DIRECT_IO                0x00000010
#define DO_EXCLUSIVE                0x00000008
#define DO_POWER_PAGABLE            0x00002000

/* I/O priority boost */
#define IO_NO_INCREMENT             0
#define IO_DISK_INCREMENT           1
#define IO_NETWORK_INCREMENT        2

/* ===== IO_STATUS_BLOCK ===== */
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

/* ===== KEVENT ===== */
typedef enum _EVENT_TYPE {
    NotificationEvent = 0,
    SynchronizationEvent = 1
} EVENT_TYPE;

typedef struct _KEVENT {
    struct {
        UCHAR  Type;
        UCHAR  Size;
        USHORT SignalState;
    } Header;
    /* Internal: we use a pthread_cond + mutex pair */
    PVOID _internal[4];
} KEVENT, *PKEVENT;

/* ===== KSPIN_LOCK ===== */
typedef ULONG_PTR KSPIN_LOCK, *PKSPIN_LOCK;

/* ===== KDPC (Deferred Procedure Call) ===== */
typedef void (__attribute__((ms_abi)) *PKDEFERRED_ROUTINE)(
    PKDPC Dpc, PVOID DeferredContext,
    PVOID SystemArgument1, PVOID SystemArgument2);

struct _KDPC {
    UCHAR  Type;
    UCHAR  Number;
    USHORT Importance;
    PVOID  DeferredRoutine;
    PVOID  DeferredContext;
    PVOID  SystemArgument1;
    PVOID  SystemArgument2;
};

/* ===== KTIMER ===== */
typedef struct _KTIMER {
    struct {
        UCHAR  Type;
        UCHAR  Size;
    } Header;
    LARGE_INTEGER DueTime;
    PVOID         _internal[4]; /* timer_t + state */
} KTIMER, *PKTIMER;

/* ===== KDEVICE_QUEUE ===== */
typedef struct _KDEVICE_QUEUE {
    SHORT  Type;
    SHORT  Size;
    BOOL   Busy;
} KDEVICE_QUEUE, *PKDEVICE_QUEUE;

/* ===== MDL (Memory Descriptor List) ===== */
#define MDL_MAPPED_TO_SYSTEM_VA     0x0001
#define MDL_PAGES_LOCKED            0x0002
#define MDL_SOURCE_IS_NONPAGED_POOL 0x0004

typedef struct _MDL {
    PMDL    Next;
    SHORT   MdlFlags;
    SHORT   Size;
    PVOID   Process;
    PVOID   MappedSystemVa;
    PVOID   StartVa;
    ULONG   ByteCount;
    ULONG   ByteOffset;
} MDL;

/* ===== DRIVER_EXTENSION ===== */
typedef struct _DRIVER_EXTENSION {
    PDRIVER_OBJECT DriverObject;
    PVOID          AddDevice;
    ULONG          Count;
    UNICODE_STRING ServiceKeyName;
} DRIVER_EXTENSION, *PDRIVER_EXTENSION;

/* ===== Function pointer typedefs ===== */

/* Driver dispatch function: NTSTATUS Dispatch(PDEVICE_OBJECT, PIRP) */
typedef NTSTATUS (__attribute__((ms_abi)) *PDRIVER_DISPATCH)(
    PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* Driver unload function: void DriverUnload(PDRIVER_OBJECT) */
typedef void (__attribute__((ms_abi)) *PDRIVER_UNLOAD)(
    PDRIVER_OBJECT DriverObject);

/* Driver StartIo function */
typedef void (__attribute__((ms_abi)) *PDRIVER_STARTIO)(
    PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* I/O completion routine */
typedef NTSTATUS (__attribute__((ms_abi)) *PIO_COMPLETION_ROUTINE)(
    PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context);

/* ===== DRIVER_OBJECT ===== */
#define IO_TYPE_DRIVER  4

typedef struct _DRIVER_OBJECT {
    SHORT              Type;                    /* IO_TYPE_DRIVER */
    SHORT              Size;
    PDEVICE_OBJECT     DeviceObject;            /* Head of device list */
    ULONG              Flags;
    PVOID              DriverStart;             /* Image base */
    ULONG              DriverSize;
    PVOID              DriverSection;           /* Opaque LDR entry */
    PDRIVER_EXTENSION  DriverExtension;
    UNICODE_STRING     DriverName;
    PUNICODE_STRING    HardwareDatabase;
    PVOID              FastIoDispatch;
    PVOID              DriverInit;              /* DriverEntry address */
    PDRIVER_STARTIO    DriverStartIo;
    PDRIVER_UNLOAD     DriverUnload;
    PDRIVER_DISPATCH   MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT;

/* ===== DEVICE_OBJECT ===== */
#define IO_TYPE_DEVICE  3

typedef struct _DEVICE_OBJECT {
    SHORT              Type;                    /* IO_TYPE_DEVICE */
    USHORT             Size;
    LONG               ReferenceCount;
    PDRIVER_OBJECT     DriverObject;
    PDEVICE_OBJECT     NextDevice;              /* Next in driver's list */
    PDEVICE_OBJECT     AttachedDevice;          /* Device attached on top */
    PIRP               CurrentIrp;
    ULONG              Flags;
    ULONG              Characteristics;
    PVOID              DeviceExtension;
    ULONG              DeviceType;
    CHAR               StackSize;
    UCHAR              _padding[3];
    KDEVICE_QUEUE      DeviceQueue;
    ULONG              AlignmentRequirement;
    KEVENT             DeviceLock;
    USHORT             SectorSize;
    USHORT             _reserved;
    /* Extra: track device name for symlink resolution */
    UNICODE_STRING     DeviceName;
} DEVICE_OBJECT;

/* ===== FILE_OBJECT ===== */
typedef struct _FILE_OBJECT {
    SHORT              Type;
    SHORT              Size;
    PDEVICE_OBJECT     DeviceObject;
    PVOID              FsContext;
    PVOID              FsContext2;
    UNICODE_STRING     FileName;
    LARGE_INTEGER      CurrentByteOffset;
    ULONG              Flags;
} FILE_OBJECT;

/* ===== IO_STACK_LOCATION ===== */
typedef struct _IO_STACK_LOCATION {
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    UCHAR Flags;
    UCHAR Control;

    union {
        /* IRP_MJ_CREATE */
        struct {
            PVOID   SecurityContext;
            ULONG   Options;
            USHORT  FileAttributes;
            USHORT  ShareAccess;
            ULONG   EaLength;
        } Create;

        /* IRP_MJ_READ */
        struct {
            ULONG           Length;
            ULONG           Key;
            LARGE_INTEGER   ByteOffset;
        } Read;

        /* IRP_MJ_WRITE */
        struct {
            ULONG           Length;
            ULONG           Key;
            LARGE_INTEGER   ByteOffset;
        } Write;

        /* IRP_MJ_DEVICE_CONTROL / IRP_MJ_INTERNAL_DEVICE_CONTROL */
        struct {
            ULONG   OutputBufferLength;
            ULONG   InputBufferLength;
            ULONG   IoControlCode;
            PVOID   Type3InputBuffer;
        } DeviceIoControl;

        /* IRP_MJ_PNP */
        struct {
            ULONG   Type;
        } QueryDeviceRelations;

        /* Generic parameters */
        struct {
            PVOID   Argument1;
            PVOID   Argument2;
            PVOID   Argument3;
            PVOID   Argument4;
        } Others;
    } Parameters;

    PDEVICE_OBJECT          DeviceObject;
    PFILE_OBJECT            FileObject;
    PIO_COMPLETION_ROUTINE  CompletionRoutine;
    PVOID                   Context;
} IO_STACK_LOCATION;

/* ===== IRP (I/O Request Packet) ===== */
#define IO_TYPE_IRP     6
#define IRP_MAX_STACK   8

typedef struct _IRP {
    SHORT              Type;                    /* IO_TYPE_IRP */
    USHORT             Size;
    PMDL               MdlAddress;
    ULONG              Flags;

    /* IoStatus */
    IO_STATUS_BLOCK    IoStatus;

    CHAR               RequestorMode;           /* KernelMode=0, UserMode=1 */
    BOOLEAN            PendingReturned;
    CHAR               StackCount;
    CHAR               CurrentLocation;
    BOOLEAN            Cancel;
    KIRQL              CancelIrql;
    CHAR               _padding[2];

    PVOID              UserBuffer;
    PVOID              AssociatedIrp_SystemBuffer; /* METHOD_BUFFERED */

    IO_STACK_LOCATION  Stack[IRP_MAX_STACK];

    PVOID              UserEvent;
    PVOID              Tail_Overlay_Thread;
} IRP;

/* ===== IRP accessor macros ===== */
#define IoGetCurrentIrpStackLocation(Irp) \
    (&(Irp)->Stack[(int)(Irp)->CurrentLocation])

#define IoGetNextIrpStackLocation(Irp) \
    (&(Irp)->Stack[(int)(Irp)->CurrentLocation + 1])

#define IoSkipCurrentIrpStackLocation(Irp) \
    do { (Irp)->CurrentLocation++; } while(0)

#define IoCopyCurrentIrpStackLocationToNext(Irp) \
    do { \
        PIO_STACK_LOCATION _src = IoGetCurrentIrpStackLocation(Irp); \
        PIO_STACK_LOCATION _dst = IoGetNextIrpStackLocation(Irp); \
        *_dst = *_src; \
        _dst->CompletionRoutine = NULL; \
        _dst->Context = NULL; \
    } while(0)

/* ===== Object Manager ===== */
#define OBJ_CASE_INSENSITIVE   0x00000040
#define OBJ_KERNEL_HANDLE      0x00000200

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) do { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);            \
    (p)->RootDirectory = (r);                           \
    (p)->Attributes = (a);                              \
    (p)->ObjectName = (n);                              \
    (p)->SecurityDescriptor = (s);                      \
    (p)->SecurityQualityOfService = NULL;               \
} while(0)

/* ===== Processor modes ===== */
#define KernelMode  0
#define UserMode    1

/* ===== DriverEntry prototype ===== */
typedef NTSTATUS (__attribute__((ms_abi)) *PDRIVER_INITIALIZE)(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath);

#endif /* WDM_H */
