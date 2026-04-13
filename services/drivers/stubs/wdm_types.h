/*
 * wdm_types.h - Windows Driver Model Type Definitions (Linux Userspace Emulation)
 *
 * Provides WDM kernel type definitions, constants, and structures needed to
 * compile and run Windows kernel driver code as Linux userspace stubs.
 * This is part of the driver compatibility layer for anti-cheat and device
 * driver emulation.
 *
 * All types use standard C (stdint.h) equivalents suitable for GCC on Linux.
 */

#ifndef WDM_TYPES_H
#define WDM_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Fundamental Windows Kernel Types
 * ============================================================================ */

typedef int32_t     NTSTATUS;
typedef uint32_t    ULONG;
typedef int32_t     LONG;
typedef uint16_t    USHORT;
typedef int16_t     SHORT;
typedef uint8_t     UCHAR;
typedef int8_t      CHAR;
typedef uint8_t     BOOLEAN;
typedef uint8_t     BYTE;
typedef uint16_t    WORD;
typedef uint32_t    DWORD;
typedef uint64_t    ULONGLONG;
typedef int64_t     LONGLONG;
typedef void        VOID;
typedef void       *PVOID;
typedef void       *HANDLE;
typedef uintptr_t   ULONG_PTR;
typedef intptr_t    LONG_PTR;
typedef uintptr_t   SIZE_T;
typedef uint16_t    WCHAR;
typedef WCHAR      *PWCHAR;
typedef const WCHAR *PCWSTR;
typedef ULONG      *PULONG;
typedef PVOID       PMDL;

/* Pointer-sized types */
typedef void       *PDEVICE_OBJECT;
typedef void       *PDRIVER_OBJECT;

/* ============================================================================
 * NTSTATUS Constants
 * ============================================================================ */

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001)
#define STATUS_NOT_IMPLEMENTED          ((NTSTATUS)0xC0000002)
#define STATUS_NOT_SUPPORTED            ((NTSTATUS)0xC00000BB)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000D)
#define STATUS_INVALID_DEVICE_REQUEST   ((NTSTATUS)0xC0000010)
#define STATUS_NO_MEMORY                ((NTSTATUS)0xC0000017)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034)
#define STATUS_OBJECT_NAME_COLLISION    ((NTSTATUS)0xC0000035)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009A)
#define STATUS_PENDING                  ((NTSTATUS)0x00000103)
#define STATUS_CANCELLED                ((NTSTATUS)0xC0000120)
#define STATUS_TIMEOUT                  ((NTSTATUS)0x00000102)
#define STATUS_MORE_PROCESSING_REQUIRED ((NTSTATUS)0xC0000016)
#define STATUS_BUFFER_OVERFLOW          ((NTSTATUS)0x80000005)

/* NTSTATUS helper macros */
#define NT_SUCCESS(Status)      ((NTSTATUS)(Status) >= 0)
#define NT_INFORMATION(Status)  ((((NTSTATUS)(Status)) >> 30) == 1)
#define NT_WARNING(Status)      ((((NTSTATUS)(Status)) >> 30) == 2)
#define NT_ERROR(Status)        ((((NTSTATUS)(Status)) >> 30) == 3)

/* ============================================================================
 * IRQL (Interrupt Request Level)
 * ============================================================================ */

typedef uint8_t KIRQL;
typedef KIRQL  *PKIRQL;

#define PASSIVE_LEVEL   0
#define LOW_LEVEL       0
#define APC_LEVEL       1
#define DISPATCH_LEVEL  2
#define DEVICE_LEVEL    3
#define HIGH_LEVEL      31

/* ============================================================================
 * Processor Mode
 * ============================================================================ */

typedef enum _KPROCESSOR_MODE {
    KernelMode = 0,
    UserMode   = 1,
    MaximumMode
} KPROCESSOR_MODE;

/* ============================================================================
 * Device Types
 * ============================================================================ */

typedef uint32_t DEVICE_TYPE;

#define FILE_DEVICE_UNKNOWN         0x00000022
#define FILE_DEVICE_BEEP            0x00000001
#define FILE_DEVICE_KEYBOARD        0x0000000B
#define FILE_DEVICE_MOUSE           0x0000000F
#define FILE_DEVICE_NETWORK         0x00000012
#define FILE_DEVICE_DISK            0x00000007
#define FILE_DEVICE_CONTROLLER      0x00000004
#define FILE_DEVICE_KS              0x0000002F
#define FILE_DEVICE_TRANSPORT       0x00000021

/* ============================================================================
 * UNICODE_STRING
 * ============================================================================ */

typedef struct _UNICODE_STRING {
    USHORT  Length;          /* Length in bytes (not including terminating null) */
    USHORT  MaximumLength;  /* Maximum length in bytes */
    PWCHAR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef const UNICODE_STRING *PCUNICODE_STRING;

/* ============================================================================
 * OBJECT_ATTRIBUTES
 * ============================================================================ */

#define OBJ_INHERIT             0x00000002
#define OBJ_PERMANENT           0x00000010
#define OBJ_EXCLUSIVE           0x00000020
#define OBJ_CASE_INSENSITIVE    0x00000040
#define OBJ_OPENIF              0x00000080
#define OBJ_OPENLINK            0x00000100
#define OBJ_KERNEL_HANDLE       0x00000200

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);          \
    (p)->RootDirectory = (r);                         \
    (p)->Attributes = (a);                            \
    (p)->ObjectName = (n);                            \
    (p)->SecurityDescriptor = (s);                    \
    (p)->SecurityQualityOfService = NULL;             \
}

/* ============================================================================
 * IO_STATUS_BLOCK
 * ============================================================================ */

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS    Status;
        PVOID       Pointer;
    };
    ULONG_PTR       Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

/* ============================================================================
 * MDL - Memory Descriptor List
 * ============================================================================ */

typedef struct _MDL {
    struct _MDL    *Next;
    SHORT           Size;
    SHORT           MdlFlags;
    PVOID           Process;
    PVOID           MappedSystemVa;
    PVOID           StartVa;
    ULONG           ByteCount;
    ULONG           ByteOffset;
} MDL;

#define MDL_MAPPED_TO_SYSTEM_VA     0x0001
#define MDL_PAGES_LOCKED            0x0002
#define MDL_SOURCE_IS_NONPAGED_POOL 0x0004
#define MDL_ALLOCATED_FIXED_SIZE    0x0008

/* Helper to get the virtual address from an MDL */
#define MmGetMdlVirtualAddress(Mdl) \
    ((PVOID)((uintptr_t)(Mdl)->StartVa + (Mdl)->ByteOffset))

#define MmGetMdlByteCount(Mdl) ((Mdl)->ByteCount)

/* ============================================================================
 * IRP Major Function Codes
 * ============================================================================ */

#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_QUERY_INFORMATION        0x05
#define IRP_MJ_SET_INFORMATION          0x06
#define IRP_MJ_FLUSH_BUFFERS            0x09
#define IRP_MJ_DEVICE_CONTROL           0x0E
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0F
#define IRP_MJ_SHUTDOWN                 0x10
#define IRP_MJ_CLEANUP                  0x12
#define IRP_MJ_POWER                    0x16
#define IRP_MJ_SYSTEM_CONTROL           0x17
#define IRP_MJ_PNP                      0x1B
#define IRP_MJ_MAXIMUM_FUNCTION         0x1B

/* ============================================================================
 * IRP Minor Function Codes (PnP)
 * ============================================================================ */

#define IRP_MN_START_DEVICE             0x00
#define IRP_MN_QUERY_REMOVE_DEVICE      0x01
#define IRP_MN_REMOVE_DEVICE            0x02
#define IRP_MN_CANCEL_REMOVE_DEVICE     0x03
#define IRP_MN_STOP_DEVICE              0x04
#define IRP_MN_QUERY_STOP_DEVICE        0x05
#define IRP_MN_CANCEL_STOP_DEVICE       0x06
#define IRP_MN_QUERY_DEVICE_RELATIONS   0x07
#define IRP_MN_QUERY_CAPABILITIES       0x09
#define IRP_MN_SURPRISE_REMOVAL         0x17

/* ============================================================================
 * IO_STACK_LOCATION
 * ============================================================================ */

typedef struct _IO_STACK_LOCATION {
    UCHAR   MajorFunction;
    UCHAR   MinorFunction;
    UCHAR   Flags;
    UCHAR   Control;

    /* Parameters union - simplified for stub usage */
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
            ULONG   Length;
            ULONG   Key;
            LONGLONG ByteOffset;
        } Read;

        /* IRP_MJ_WRITE */
        struct {
            ULONG   Length;
            ULONG   Key;
            LONGLONG ByteOffset;
        } Write;

        /* IRP_MJ_DEVICE_CONTROL / IRP_MJ_INTERNAL_DEVICE_CONTROL */
        struct {
            ULONG   OutputBufferLength;
            ULONG   InputBufferLength;
            ULONG   IoControlCode;
            PVOID   Type3InputBuffer;
        } DeviceIoControl;

        /* IRP_MJ_POWER */
        struct {
            ULONG   SystemContext;
            ULONG   Type;
            ULONG   State;
        } Power;

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

    PVOID   DeviceObject;       /* Target device for this request */
    PVOID   FileObject;
    PVOID   CompletionRoutine;
    PVOID   Context;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

/* ============================================================================
 * IRP - I/O Request Packet
 * ============================================================================ */

#define IRP_MAX_STACK_SIZE  8

typedef struct _IRP {
    SHORT                   Type;
    USHORT                  Size;
    PMDL                    MdlAddress;
    ULONG                   Flags;
    union {
        struct _IRP        *MasterIrp;
        PVOID               SystemBuffer;
    } AssociatedIrp;
    IO_STATUS_BLOCK         IoStatus;
    KPROCESSOR_MODE         RequestorMode;
    BOOLEAN                 PendingReturned;
    BOOLEAN                 Cancel;
    KIRQL                   CancelIrql;
    PVOID                   UserBuffer;
    PVOID                   UserEvent;

    /* Stack location tracking */
    int8_t                  CurrentLocation;
    int8_t                  StackCount;
    IO_STACK_LOCATION       Stack[IRP_MAX_STACK_SIZE];

    /* Tail overlay - completion info */
    PVOID                   Tail_CompletionKey;
} IRP, *PIRP;

/* ============================================================================
 * DRIVER_OBJECT
 * ============================================================================ */

/* Forward declare the full struct types */
struct _DRIVER_OBJECT;
struct _DEVICE_OBJECT_FULL;

/* Driver dispatch function type */
typedef NTSTATUS (*PDRIVER_DISPATCH)(struct _DRIVER_OBJECT *DriverObject, PIRP Irp);

/* Driver initialization function type (DriverEntry) */
typedef NTSTATUS (*PDRIVER_INITIALIZE)(struct _DRIVER_OBJECT *DriverObject,
                                       PUNICODE_STRING RegistryPath);

/* Driver unload function type */
typedef void (*PDRIVER_UNLOAD)(struct _DRIVER_OBJECT *DriverObject);

/* Driver add device function type */
typedef NTSTATUS (*PDRIVER_ADD_DEVICE)(struct _DRIVER_OBJECT *DriverObject,
                                       PVOID PhysicalDeviceObject);

typedef struct _DRIVER_OBJECT {
    SHORT                   Type;
    SHORT                   Size;
    PVOID                   DeviceObject;           /* Head of device list */
    ULONG                   Flags;
    PVOID                   DriverStart;
    ULONG                   DriverSize;
    PVOID                   DriverSection;
    PVOID                   DriverExtension;
    UNICODE_STRING          DriverName;
    PUNICODE_STRING         HardwareDatabase;
    PVOID                   FastIoDispatch;
    PDRIVER_INITIALIZE      DriverInit;
    PVOID                   DriverStartIo;
    PDRIVER_UNLOAD          DriverUnload;

    /* Major function dispatch table */
    PDRIVER_DISPATCH        MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT;

/* Redefine pointer types now that full struct is available */
#undef PDRIVER_OBJECT
#undef PDEVICE_OBJECT
typedef struct _DRIVER_OBJECT *PDRIVER_OBJECT_FULL;

/* ============================================================================
 * DEVICE_OBJECT (full definition)
 * ============================================================================ */

#define DO_BUFFERED_IO      0x00000004
#define DO_EXCLUSIVE        0x00000008
#define DO_DIRECT_IO        0x00000010
#define DO_POWER_PAGABLE    0x00002000

typedef struct _DEVICE_OBJECT_FULL {
    SHORT                   Type;
    USHORT                  Size;
    LONG                    ReferenceCount;
    struct _DRIVER_OBJECT  *DriverObject;
    struct _DEVICE_OBJECT_FULL *NextDevice;
    struct _DEVICE_OBJECT_FULL *AttachedDevice;
    PIRP                    CurrentIrp;
    ULONG                   Flags;
    ULONG                   Characteristics;
    DEVICE_TYPE             DeviceType;
    UCHAR                   StackSize;
    PVOID                   DeviceExtension;
    ULONG                   DeviceExtensionSize;
    ULONG                   AlignmentRequirement;
    UNICODE_STRING          DeviceName;
} DEVICE_OBJECT_FULL, *PDEVICE_OBJECT_FULL;

/* ============================================================================
 * Pool Types (for ExAllocatePool)
 * ============================================================================ */

typedef enum _POOL_TYPE {
    NonPagedPool            = 0,
    PagedPool               = 1,
    NonPagedPoolMustSucceed = 2,
    DontUseThisType         = 3,
    NonPagedPoolCacheAligned = 4,
    PagedPoolCacheAligned   = 5,
    NonPagedPoolNx          = 512,
    NonPagedPoolNxCacheAligned = 516
} POOL_TYPE;

/* ============================================================================
 * IOCTL Macros
 * ============================================================================ */

/* Method codes for IOCTL */
#define METHOD_BUFFERED     0
#define METHOD_IN_DIRECT    1
#define METHOD_OUT_DIRECT   2
#define METHOD_NEITHER      3

/* File access types */
#define FILE_ANY_ACCESS     0
#define FILE_READ_ACCESS    1
#define FILE_WRITE_ACCESS   2

/* CTL_CODE macro - builds a device I/O control code */
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))

/* Extract fields from IOCTL code */
#define DEVICE_TYPE_FROM_CTL_CODE(code)     (((ULONG)(code)) >> 16)
#define METHOD_FROM_CTL_CODE(code)          ((code) & 0x3)
#define FUNCTION_FROM_CTL_CODE(code)        (((code) >> 2) & 0xFFF)
#define ACCESS_FROM_CTL_CODE(code)          (((code) >> 14) & 0x3)

/* ============================================================================
 * Synchronization Primitives (opaque types for stubs)
 * ============================================================================ */

typedef struct _KEVENT {
    LONG    State;      /* 0 = not signaled, 1 = signaled */
    ULONG   Type;       /* 0 = Notification, 1 = Synchronization */
} KEVENT, *PKEVENT;

typedef enum _EVENT_TYPE {
    NotificationEvent   = 0,
    SynchronizationEvent = 1
} EVENT_TYPE;

typedef struct _KMUTEX {
    LONG    State;      /* 0 = not held, 1 = held */
    HANDLE  OwnerThread;
} KMUTEX, *PKMUTEX;

typedef struct _KSPIN_LOCK {
    volatile LONG Lock;
} KSPIN_LOCK, *PKSPIN_LOCK;

typedef struct _FAST_MUTEX {
    LONG    Count;
    HANDLE  Owner;
    ULONG   Contention;
    KEVENT  Event;
} FAST_MUTEX, *PFAST_MUTEX;

/* ============================================================================
 * LARGE_INTEGER
 * ============================================================================ */

typedef union _LARGE_INTEGER {
    struct {
        ULONG   LowPart;
        LONG    HighPart;
    };
    struct {
        ULONG   LowPart;
        LONG    HighPart;
    } u;
    LONGLONG    QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

/* ============================================================================
 * Wait block and timeout types
 * ============================================================================ */

typedef enum _KWAIT_REASON {
    Executive       = 0,
    UserRequest     = 6,
    MaximumWaitReason
} KWAIT_REASON;

/* ============================================================================
 * Process/Thread notification callback types (anti-cheat relevant)
 * ============================================================================ */

typedef void (*PCREATE_PROCESS_NOTIFY_ROUTINE)(HANDLE ParentId,
                                                HANDLE ProcessId,
                                                BOOLEAN Create);

typedef void (*PCREATE_THREAD_NOTIFY_ROUTINE)(HANDLE ProcessId,
                                               HANDLE ThreadId,
                                               BOOLEAN Create);

typedef struct _IMAGE_INFO {
    ULONG   ImageAddressingMode;
    USHORT  SystemModeImage;
    USHORT  ImageMappedToAllPids;
    PVOID   ImageBase;
    ULONG   ImageSelector;
    SIZE_T  ImageSize;
    ULONG   ImageSectionNumber;
} IMAGE_INFO, *PIMAGE_INFO;

typedef void (*PLOAD_IMAGE_NOTIFY_ROUTINE)(PUNICODE_STRING FullImageName,
                                            HANDLE ProcessId,
                                            PIMAGE_INFO ImageInfo);

/* ============================================================================
 * Object Callbacks (anti-cheat relevant - ObRegisterCallbacks)
 * ============================================================================ */

typedef enum _OB_OPERATION {
    OB_OPERATION_HANDLE_CREATE  = 1,
    OB_OPERATION_HANDLE_DUPLICATE = 2
} OB_OPERATION;

typedef struct _OB_PRE_OPERATION_INFORMATION {
    OB_OPERATION    Operation;
    ULONG           Flags;
    PVOID           Object;
    PVOID           ObjectType;
    PVOID           CallContext;
    ULONG           DesiredAccess;
    ULONG           OriginalDesiredAccess;
} OB_PRE_OPERATION_INFORMATION, *POB_PRE_OPERATION_INFORMATION;

typedef struct _OB_POST_OPERATION_INFORMATION {
    OB_OPERATION    Operation;
    ULONG           Flags;
    PVOID           Object;
    PVOID           ObjectType;
    PVOID           CallContext;
    NTSTATUS        ReturnStatus;
    ULONG           GrantedAccess;
} OB_POST_OPERATION_INFORMATION, *POB_POST_OPERATION_INFORMATION;

typedef NTSTATUS (*POB_PRE_OPERATION_CALLBACK)(PVOID RegistrationContext,
                                                POB_PRE_OPERATION_INFORMATION OperationInformation);

typedef void (*POB_POST_OPERATION_CALLBACK)(PVOID RegistrationContext,
                                             POB_POST_OPERATION_INFORMATION OperationInformation);

typedef struct _OB_OPERATION_REGISTRATION {
    PVOID                       ObjectType;
    OB_OPERATION                Operations;
    POB_PRE_OPERATION_CALLBACK  PreOperation;
    POB_POST_OPERATION_CALLBACK PostOperation;
} OB_OPERATION_REGISTRATION, *POB_OPERATION_REGISTRATION;

typedef struct _OB_CALLBACK_REGISTRATION {
    USHORT                      Version;
    USHORT                      OperationRegistrationCount;
    UNICODE_STRING              Altitude;
    PVOID                       RegistrationContext;
    OB_OPERATION_REGISTRATION  *OperationRegistration;
} OB_CALLBACK_REGISTRATION, *POB_CALLBACK_REGISTRATION;

/* ============================================================================
 * ACCESS_MASK and related
 * ============================================================================ */

typedef ULONG ACCESS_MASK;

#define PROCESS_ALL_ACCESS          0x001FFFFF
#define PROCESS_TERMINATE           0x00000001
#define PROCESS_VM_READ             0x00000010
#define PROCESS_VM_WRITE            0x00000020
#define PROCESS_VM_OPERATION        0x00000008
#define PROCESS_QUERY_INFORMATION   0x00000400

#define THREAD_ALL_ACCESS           0x001FFFFF
#define THREAD_TERMINATE            0x00000001

/* ============================================================================
 * System Information Classes (for ZwQuerySystemInformation)
 * ============================================================================ */

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation          = 0,
    SystemProcessorInformation      = 1,
    SystemPerformanceInformation    = 2,
    SystemTimeOfDayInformation      = 3,
    SystemProcessInformation        = 5,
    SystemModuleInformation         = 11,
    SystemHandleInformation         = 16,
    SystemKernelDebuggerInformation = 35,
    SystemCodeIntegrityInformation  = 103
} SYSTEM_INFORMATION_CLASS;

/* ============================================================================
 * Process Information Classes (for ZwQueryInformationProcess)
 * ============================================================================ */

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation     = 0,
    ProcessDebugPort            = 7,
    ProcessWow64Information     = 26,
    ProcessImageFileName        = 27,
    ProcessDebugObjectHandle    = 30,
    ProcessDebugFlags           = 31,
    ProcessHandleInformation    = 51
} PROCESSINFOCLASS;

/* ============================================================================
 * IO Completion constants
 * ============================================================================ */

#define IO_NO_INCREMENT     0
#define IO_DISK_INCREMENT   1
#define IO_NETWORK_INCREMENT 2

/* ============================================================================
 * Misc macros
 * ============================================================================ */

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) ((void)(P))
#endif

#ifndef PAGED_CODE
#define PAGED_CODE()    /* no-op in userspace */
#endif

#ifndef ASSERT
#define ASSERT(x)       /* no-op in userspace */
#endif

/* Tag for pool allocations (4-char code packed into ULONG) */
#define POOL_TAG(a, b, c, d) \
    ((ULONG)(a) | ((ULONG)(b) << 8) | ((ULONG)(c) << 16) | ((ULONG)(d) << 24))

/* ============================================================================
 * Helper: IoGetCurrentIrpStackLocation (inline)
 * ============================================================================ */

static inline PIO_STACK_LOCATION IoGetCurrentIrpStackLocation_inline(PIRP Irp) {
    if (Irp && Irp->CurrentLocation >= 0 && Irp->CurrentLocation < IRP_MAX_STACK_SIZE) {
        return &Irp->Stack[Irp->CurrentLocation];
    }
    return NULL;
}

#define IoGetCurrentIrpStackLocation(Irp) IoGetCurrentIrpStackLocation_inline(Irp)

/* ============================================================================
 * Function declarations - implemented in wdm_stubs.c
 * ============================================================================ */

/* I/O Manager */
NTSTATUS IoCreateDevice(struct _DRIVER_OBJECT *DriverObject,
                        ULONG DeviceExtensionSize,
                        PUNICODE_STRING DeviceName,
                        DEVICE_TYPE DeviceType,
                        ULONG DeviceCharacteristics,
                        BOOLEAN Exclusive,
                        PDEVICE_OBJECT_FULL *DeviceObject);

void IoDeleteDevice(PDEVICE_OBJECT_FULL DeviceObject);

NTSTATUS IoCreateSymbolicLink(PUNICODE_STRING SymbolicLinkName,
                               PUNICODE_STRING DeviceName);

NTSTATUS IoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName);

void IoCompleteRequest(PIRP Irp, UCHAR PriorityBoost);

/* Synchronization */
void KeInitializeEvent(PKEVENT Event, EVENT_TYPE Type, BOOLEAN State);
LONG KeSetEvent(PKEVENT Event, LONG Increment, BOOLEAN Wait);
LONG KeResetEvent(PKEVENT Event);
NTSTATUS KeWaitForSingleObject(PVOID Object, KWAIT_REASON WaitReason,
                                KPROCESSOR_MODE WaitMode, BOOLEAN Alertable,
                                PLARGE_INTEGER Timeout);

void KeInitializeMutex(PKMUTEX Mutex, ULONG Level);
LONG KeReleaseMutex(PKMUTEX Mutex, BOOLEAN Wait);

void KeInitializeSpinLock(PKSPIN_LOCK SpinLock);
void KeAcquireSpinLock(PKSPIN_LOCK SpinLock, PKIRQL OldIrql);
void KeReleaseSpinLock(PKSPIN_LOCK SpinLock, KIRQL NewIrql);

/* Memory pool */
PVOID ExAllocatePool(POOL_TYPE PoolType, SIZE_T NumberOfBytes);
PVOID ExAllocatePoolWithTag(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag);
void ExFreePool(PVOID P);
void ExFreePoolWithTag(PVOID P, ULONG Tag);

/* Unicode string */
void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
void RtlCopyUnicodeString(PUNICODE_STRING DestinationString, PCUNICODE_STRING SourceString);
LONG RtlCompareUnicodeString(PCUNICODE_STRING String1, PCUNICODE_STRING String2,
                              BOOLEAN CaseInSensitive);

/* Misc kernel routines */
PVOID MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName);

/* Object manager */
NTSTATUS ObReferenceObjectByHandle(HANDLE Handle, ACCESS_MASK DesiredAccess,
                                    PVOID ObjectType, KPROCESSOR_MODE AccessMode,
                                    PVOID *Object, PVOID HandleInformation);
void ObDereferenceObject(PVOID Object);
NTSTATUS ObRegisterCallbacks(POB_CALLBACK_REGISTRATION CallbackRegistration,
                              PVOID *RegistrationHandle);
void ObUnRegisterCallbacks(PVOID RegistrationHandle);

/* Process/Thread */
HANDLE PsGetCurrentProcessId(void);
HANDLE PsGetCurrentThreadId(void);
NTSTATUS PsSetCreateProcessNotifyRoutine(PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
                                          BOOLEAN Remove);
NTSTATUS PsSetCreateThreadNotifyRoutine(PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine);
NTSTATUS PsSetLoadImageNotifyRoutine(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);

/* Zw (native API) */
NTSTATUS ZwQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                    PVOID ProcessInformation, ULONG ProcessInformationLength,
                                    PULONG ReturnLength);
NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                   PVOID SystemInformation, ULONG SystemInformationLength,
                                   PULONG ReturnLength);

#ifdef __cplusplus
}
#endif

#endif /* WDM_TYPES_H */
