/*
 * hal_internal.h - HAL.dll internal types, helpers, trust band mapping.
 *
 * Defines the few WDM types not present in include/win32/wdm.h that the
 * real HAL surface requires (PHYSICAL_ADDRESS, MEMORY_CACHING_TYPE,
 * INTERFACE_TYPE, BUS_DATA_TYPE, KSERVICE_ROUTINE, IO_CONNECT_INTERRUPT_*,
 * KINTERRUPT) plus the PCI BDF / IRQ helpers shared between hal_pci.c,
 * hal_mmio.c, hal_irq.c.
 *
 * Real Windows HAL exposes ~120 entry points; we cover the subset that
 * any actual driver needs for PCI config / MMIO / IRQ work, and we
 * trust-gate every privileged path through the existing trust_gate_check
 * surface declared in compat/trust_gate.h.
 */

#ifndef HAL_INTERNAL_H
#define HAL_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#include "common/dll_common.h"
#include "win32/wdm.h"
#include "compat/trust_gate.h"

/* ---- Types missing from win32/wdm.h --------------------------------- */

/* CPU affinity bitmask -- Windows uses ULONG_PTR. */
#ifndef KAFFINITY_DEFINED
#define KAFFINITY_DEFINED
typedef ULONG_PTR KAFFINITY;
#endif

/* PHYSICAL_ADDRESS is a LARGE_INTEGER on x64 in the Windows DDK. */
typedef LARGE_INTEGER PHYSICAL_ADDRESS;

/* MmMapIoSpace caching hint */
typedef enum _MEMORY_CACHING_TYPE {
    MmNonCached            = 0,
    MmCached               = 1,
    MmWriteCombined        = 2,
    MmHardwareCoherentCached = 3,
    MmNonCachedUnordered   = 4,
    MmUSWCCached           = 5,
    MmMaximumCacheType     = 6
} MEMORY_CACHING_TYPE;

/* HalGetBusData / HalSetBusData bus-type selector */
typedef enum _BUS_DATA_TYPE {
    ConfigurationSpaceUndefined = -1,
    Cmos                        = 0,
    EisaConfiguration           = 1,
    Pos                         = 2,
    CbusConfiguration           = 3,
    PCIConfiguration            = 4,
    VMEConfiguration            = 5,
    NuBusConfiguration          = 6,
    PCMCIAConfiguration         = 7,
    MPIConfiguration            = 8,
    MPSAConfiguration           = 9,
    PNPISAConfiguration         = 10,
    SgiInternalConfiguration    = 11,
    MaximumBusDataType
} BUS_DATA_TYPE;

/* IO bus interface type (for IoConnectInterrupt etc.) */
typedef enum _INTERFACE_TYPE {
    InterfaceTypeUndefined = -1,
    Internal               = 0,
    Isa                    = 1,
    Eisa                   = 2,
    MicroChannel           = 3,
    TurboChannel           = 4,
    PCIBus                 = 5,
    VMEBus                 = 6,
    NuBus                  = 7,
    PCMCIABus              = 8,
    CBus                   = 9,
    MPIBus                 = 10,
    MPSABus                = 11,
    ProcessorInternal      = 12,
    InternalPowerBus       = 13,
    PNPISABus              = 14,
    PNPBus                 = 15,
    MaximumInterfaceType
} INTERFACE_TYPE;

/* IRQ delivery mode */
typedef enum _KINTERRUPT_MODE {
    LevelSensitive = 0,
    Latched        = 1
} KINTERRUPT_MODE;

/* Forward decl so PKSERVICE_ROUTINE doesn't introduce a parameter-scope type. */
struct _KINTERRUPT;

/* ISR return value (TRUE = handled, FALSE = chain) */
typedef BOOLEAN (__attribute__((ms_abi)) *PKSERVICE_ROUTINE)(
    struct _KINTERRUPT *Interrupt, PVOID ServiceContext);

/* Synchronize routine (passed to KeSynchronizeExecution) */
typedef BOOLEAN (__attribute__((ms_abi)) *PKSYNCHRONIZE_ROUTINE)(
    PVOID SynchronizeContext);

/* PCI Bus-Device-Function key.  We use this internally and as the
 * "SlotNumber" parameter encoding for HalGetBusData* (Windows packs
 * device:function into the low 8 bits of SlotNumber). */
typedef struct _hal_pci_bdf {
    uint16_t segment;   /* PCI domain (0 on most systems) */
    uint8_t  bus;
    uint8_t  device;    /* 0..31 */
    uint8_t  function;  /* 0..7 */
} hal_pci_bdf_t;

/* ---- KINTERRUPT ----------------------------------------------------- */
/* In real Windows this is opaque; here we expose enough state to drive
 * a userspace ISR loop.  Drivers must NOT touch the internals. */
struct _KINTERRUPT {
    /* Public-ish fields (Windows compat) */
    KSPIN_LOCK         SpinLock;       /* For KeSynchronizeExecution */
    PKSERVICE_ROUTINE  ServiceRoutine;
    PVOID              ServiceContext;
    ULONG              Vector;
    KIRQL              Irql;
    KIRQL              SynchronizeIrql;
    KINTERRUPT_MODE    Mode;
    BOOLEAN            ShareVector;

    /* Linux backing */
    int                uio_fd;         /* /dev/uioN, -1 if not bound */
    int                stop_fd;        /* eventfd to wake the ISR thread */
    pthread_t          isr_thread;
    pthread_mutex_t    sync_mtx;       /* Real lock under SpinLock */
    volatile int       running;
    uint64_t           irq_count;      /* Diagnostics */
};
typedef struct _KINTERRUPT KINTERRUPT, *PKINTERRUPT;

/* IO_CONNECT_INTERRUPT_PARAMETERS (simplified union; we accept the
 * "FullySpecified" or "LineBased" variant). */
typedef enum _IO_CONNECT_INTERRUPT_TYPE {
    CONNECT_FULLY_SPECIFIED         = 1,
    CONNECT_LINE_BASED              = 2,
    CONNECT_MESSAGE_BASED           = 3,
    CONNECT_FULLY_SPECIFIED_GROUP   = 4
} IO_CONNECT_INTERRUPT_TYPE;

typedef struct _IO_CONNECT_INTERRUPT_PARAMETERS {
    ULONG                       Version;     /* CONNECT_* */
    union {
        struct {
            PDEVICE_OBJECT        PhysicalDeviceObject;
            PKINTERRUPT          *InterruptObject;
            PKSERVICE_ROUTINE     ServiceRoutine;
            PVOID                 ServiceContext;
            PKSPIN_LOCK           SpinLock;
            KIRQL                 SynchronizeIrql;
            BOOLEAN               FloatingSave;
            BOOLEAN               ShareVector;
            ULONG                 Vector;
            KIRQL                 Irql;
            KINTERRUPT_MODE       InterruptMode;
            ULONG                 ProcessorEnableMask;
            USHORT                Group;
        } FullySpecified;
        struct {
            PDEVICE_OBJECT        PhysicalDeviceObject;
            PKINTERRUPT          *InterruptObject;
            PKSERVICE_ROUTINE     ServiceRoutine;
            PVOID                 ServiceContext;
            PKSPIN_LOCK           SpinLock;
            KIRQL                 SynchronizeIrql;
            BOOLEAN               FloatingSave;
        } LineBased;
    };
} IO_CONNECT_INTERRUPT_PARAMETERS, *PIO_CONNECT_INTERRUPT_PARAMETERS;

typedef struct _IO_DISCONNECT_INTERRUPT_PARAMETERS {
    ULONG        Version;
    PKINTERRUPT  ConnectionContext;
} IO_DISCONNECT_INTERRUPT_PARAMETERS, *PIO_DISCONNECT_INTERRUPT_PARAMETERS;

/* ---- Trust band → category mapping ---------------------------------- *
 *
 * The kernel module exposes "trust bands" (PUBLIC=0, USER=100,
 * INTERACT=200, OPERATOR=400, KERNEL=800).  The DLL-side trust gate
 * surface (compat/trust_gate.h) operates on categories instead.  We
 * map HAL operations to the closest existing category and rely on
 * the kernel policy table to enforce the score threshold for that
 * category.
 *
 * READ access to PCI config space (BARs, vendor ID, capability list)
 *      → TRUST_GATE_SYSTEM_INFO   (read-only, non-destructive)
 * WRITE access to PCI config space (enable mastering, change BARs,
 * disable interrupts, MSI vectors) → TRUST_GATE_DEVICE_IOCTL
 * MMIO mapping (/dev/mem)          → TRUST_GATE_DRIVER_LOAD
 * IRQ wiring (uio FD + ISR thread) → TRUST_GATE_DRIVER_LOAD
 */
#define HAL_TRUST_PCI_READ      TRUST_GATE_SYSTEM_INFO
#define HAL_TRUST_PCI_WRITE     TRUST_GATE_DEVICE_IOCTL
#define HAL_TRUST_MMIO          TRUST_GATE_DRIVER_LOAD
#define HAL_TRUST_IRQ           TRUST_GATE_DRIVER_LOAD

/* Returns 1 = allowed, 0 = denied.  Wraps trust_gate_check() so the
 * /dev/trust unavailability case is centrally handled (permissive in
 * dev mode -- matches the rest of the loader). */
int hal_trust_check(trust_gate_category_t cat,
                    const char *op,
                    const char *arg_summary);

/* ---- PCI helpers (hal_pci.c) ---------------------------------------- */

/* Decode SlotNumber per Windows convention: low 3 bits = function,
 * next 5 bits = device. */
static inline void hal_decode_slot(ULONG SlotNumber, hal_pci_bdf_t *out,
                                   ULONG BusNumber)
{
    out->segment  = 0;
    out->bus      = (uint8_t)(BusNumber & 0xFF);
    out->device   = (uint8_t)((SlotNumber >> 3) & 0x1F);
    out->function = (uint8_t)(SlotNumber & 0x07);
}

/* Build the sysfs path for a BDF.  buf must be >= 64 bytes. */
void hal_pci_sysfs_path(const hal_pci_bdf_t *bdf,
                        const char *attr,   /* "config", "irq", "resource", ... */
                        char *buf, size_t buf_size);

/* Read an integer attribute (e.g. /sys/.../irq).  Returns -1 on
 * failure, otherwise the parsed value. */
long hal_pci_read_int_attr(const hal_pci_bdf_t *bdf, const char *attr);

/* ---- IRQ helpers (hal_irq.c) ---------------------------------------- */

/* Resolve an IRQ vector to a /dev/uio fd by walking
 * /sys/class/uio/uio*\/device and matching the parent symlink to
 * the requested PCI device.  Returns -1 if no uio device is bound.
 * If `bdf` is NULL, attempts a direct match on Linux IRQ number. */
int hal_irq_open_uio(const hal_pci_bdf_t *bdf, ULONG vector);

#endif /* HAL_INTERNAL_H */
