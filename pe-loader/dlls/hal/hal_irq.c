/*
 * hal_irq.c - HAL interrupt routing.
 *
 * IoConnectInterruptEx / IoConnectInterrupt / IoDisconnectInterrupt /
 * KeInitializeInterrupt / KeSynchronizeExecution.
 *
 * Linux equivalence: a userspace ISR thread blocks on read() of a
 * /dev/uioN file descriptor.  Each completed read returns the IRQ
 * count; we then re-arm the IRQ by writing a 4-byte 1 back to the fd
 * (the uio standard "unmask" protocol) and invoke the ISR with the
 * caller's ServiceContext.
 *
 * To stop the ISR thread cleanly (IoDisconnectInterrupt), we add a
 * second "stop" eventfd to the poll set; signalling it forces the
 * read loop to wake and check the running flag.
 *
 * Trust gating: every IoConnectInterrupt* path checks
 * HAL_TRUST_IRQ (TRUST_GATE_DRIVER_LOAD).  uio devices are only
 * accessible to root by default, so the gate is a defence-in-depth
 * layer in addition to filesystem permissions.
 *
 * HalGetInterruptVector resolves a (Bus, Slot) pair to a Linux IRQ
 * number by reading /sys/bus/pci/devices/<bdf>/irq.
 *
 * Limitations:
 *  - We use level-triggered semantics for everything; LevelSensitive
 *    is the standard for PCI legacy IRQs.  MSI/MSI-X requires VFIO.
 *  - SynchronizeIrql is honoured as a process-wide pthread mutex;
 *    KeSynchronizeExecution acquires this lock around the caller's
 *    SynchronizeRoutine to prevent reentrancy with the ISR.
 *  - Vector→/dev/uioN mapping: we walk /sys/class/uio and match the
 *    device's parent symlink to a known PCI BDF.  For non-PCI uio
 *    devices (e.g. uio_dmem_genirq), drivers can pass vector==N to
 *    open /dev/uioN directly.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include "hal_internal.h"

#define LOG_PREFIX "[hal/irq] "

/* ===== Vector → /dev/uio resolution ================================= */

/* Walk /sys/class/uio/uio*\/device looking for a matching PCI BDF.
 * Returns -1 if not found.  Outputs uio index in *out_uio_index. */
static int hal_irq_find_uio_for_pci(const hal_pci_bdf_t *bdf,
                                     int *out_uio_index)
{
    DIR *d = opendir("/sys/class/uio");
    if (!d)
        return -1;

    char wanted_bdf[32];
    snprintf(wanted_bdf, sizeof(wanted_bdf),
             "%04x:%02x:%02x.%x",
             (unsigned)bdf->segment, (unsigned)bdf->bus,
             (unsigned)bdf->device, (unsigned)bdf->function);

    int found_idx = -1;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        int idx;
        if (sscanf(de->d_name, "uio%d", &idx) != 1)
            continue;

        char devlink[256], target[256];
        snprintf(devlink, sizeof(devlink), "/sys/class/uio/%s/device",
                 de->d_name);
        ssize_t n = readlink(devlink, target, sizeof(target) - 1);
        if (n <= 0)
            continue;
        target[n] = '\0';

        /* target ends with the BDF, e.g. "../../0000:01:00.0" */
        size_t tlen = (size_t)n;
        size_t blen = strlen(wanted_bdf);
        if (tlen >= blen &&
            strcmp(target + tlen - blen, wanted_bdf) == 0) {
            found_idx = idx;
            break;
        }
    }
    closedir(d);
    if (found_idx < 0)
        return -1;
    if (out_uio_index)
        *out_uio_index = found_idx;
    return 0;
}

int hal_irq_open_uio(const hal_pci_bdf_t *bdf, ULONG vector)
{
    int uio_idx = -1;
    if (bdf) {
        if (hal_irq_find_uio_for_pci(bdf, &uio_idx) != 0)
            uio_idx = -1;
    }
    if (uio_idx < 0) {
        /* Fall back: caller passed vector as the uio device index
         * directly (e.g. for non-PCI uio drivers). */
        uio_idx = (int)vector;
    }

    char path[64];
    snprintf(path, sizeof(path), "/dev/uio%d", uio_idx);
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0 && getenv("HAL_DEBUG"))
        fprintf(stderr, LOG_PREFIX "open(%s): %s\n", path, strerror(errno));
    return fd;
}

/* ===== ISR thread ==================================================== */

static void *hal_isr_thread(void *arg)
{
    PKINTERRUPT intr = (PKINTERRUPT)arg;
    struct pollfd pfds[2];
    pfds[0].fd     = intr->uio_fd;
    pfds[0].events = POLLIN;
    pfds[1].fd     = intr->stop_fd;
    pfds[1].events = POLLIN;

    while (intr->running) {
        int r = poll(pfds, 2, -1);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pfds[1].revents & POLLIN)
            break;          /* stop signalled */
        if (!(pfds[0].revents & POLLIN))
            continue;

        /* Drain the IRQ count (4 bytes BE counter). */
        uint32_t count_be;
        ssize_t n = read(intr->uio_fd, &count_be, sizeof(count_be));
        if (n != sizeof(count_be))
            continue;

        intr->irq_count++;

        /* Synchronize with KeSynchronizeExecution callers. */
        pthread_mutex_lock(&intr->sync_mtx);
        BOOLEAN handled = FALSE;
        if (intr->ServiceRoutine)
            handled = intr->ServiceRoutine(intr, intr->ServiceContext);
        pthread_mutex_unlock(&intr->sync_mtx);

        /* Re-arm the IRQ (uio standard: write a 4-byte 1). */
        uint32_t arm = 1;
        ssize_t wn = write(intr->uio_fd, &arm, sizeof(arm));
        (void)wn;
        (void)handled;
    }
    return NULL;
}

/* ===== KeInitializeInterrupt ======================================== */

WINAPI_EXPORT NTSTATUS KeInitializeInterrupt(
    PKINTERRUPT       Interrupt,
    PKSERVICE_ROUTINE ServiceRoutine,
    PVOID             ServiceContext,
    PKSPIN_LOCK       SpinLock,
    ULONG             Vector,
    KIRQL             Irql,
    KIRQL             SynchronizeIrql,
    KINTERRUPT_MODE   InterruptMode,
    BOOLEAN           ShareVector,
    CHAR              ProcessorNumber,
    BOOLEAN           FloatingSave)
{
    (void)SpinLock;
    (void)ProcessorNumber;
    (void)FloatingSave;
    if (Interrupt == NULL || ServiceRoutine == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    memset(Interrupt, 0, sizeof(*Interrupt));
    Interrupt->ServiceRoutine    = ServiceRoutine;
    Interrupt->ServiceContext    = ServiceContext;
    Interrupt->Vector            = Vector;
    Interrupt->Irql              = Irql;
    Interrupt->SynchronizeIrql   = SynchronizeIrql;
    Interrupt->Mode              = InterruptMode;
    Interrupt->ShareVector       = ShareVector;
    Interrupt->uio_fd            = -1;
    Interrupt->stop_fd           = -1;
    Interrupt->running           = 0;
    pthread_mutex_init(&Interrupt->sync_mtx, NULL);
    return STATUS_SUCCESS;
}

/* ===== IoConnectInterrupt =========================================== *
 *
 * The legacy form -- single function, returns InterruptObject via OUT
 * parameter.  We allocate the KINTERRUPT for the caller. */

WINAPI_EXPORT NTSTATUS IoConnectInterrupt(
    PKINTERRUPT      *InterruptObject,
    PKSERVICE_ROUTINE ServiceRoutine,
    PVOID             ServiceContext,
    PKSPIN_LOCK       SpinLock,
    ULONG             Vector,
    KIRQL             Irql,
    KIRQL             SynchronizeIrql,
    KINTERRUPT_MODE   InterruptMode,
    BOOLEAN           ShareVector,
    KAFFINITY         ProcessorEnableMask,
    BOOLEAN           FloatingSave)
{
    (void)ProcessorEnableMask;
    if (InterruptObject == NULL || ServiceRoutine == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    char arg[40];
    snprintf(arg, sizeof(arg), "vec=%u irql=%u%s",
             (unsigned)Vector, (unsigned)Irql,
             ShareVector ? " shared" : "");
    if (!hal_trust_check(HAL_TRUST_IRQ, "IoConnectInterrupt", arg))
        return STATUS_INSUFFICIENT_RESOURCES;

    PKINTERRUPT intr = calloc(1, sizeof(*intr));
    if (!intr)
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS s = KeInitializeInterrupt(intr, ServiceRoutine, ServiceContext,
                                        SpinLock, Vector, Irql,
                                        SynchronizeIrql, InterruptMode,
                                        ShareVector, 0, FloatingSave);
    if (!NT_SUCCESS(s)) {
        free(intr);
        return s;
    }

    intr->uio_fd  = hal_irq_open_uio(NULL, Vector);
    intr->stop_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (intr->uio_fd < 0 || intr->stop_fd < 0) {
        if (intr->uio_fd >= 0)  close(intr->uio_fd);
        if (intr->stop_fd >= 0) close(intr->stop_fd);
        pthread_mutex_destroy(&intr->sync_mtx);
        free(intr);
        return STATUS_DEVICE_DOES_NOT_EXIST;
    }

    intr->running = 1;
    if (pthread_create(&intr->isr_thread, NULL, hal_isr_thread, intr) != 0) {
        intr->running = 0;
        close(intr->uio_fd);
        close(intr->stop_fd);
        pthread_mutex_destroy(&intr->sync_mtx);
        free(intr);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *InterruptObject = intr;
    return STATUS_SUCCESS;
}

/* ===== IoConnectInterruptEx ========================================= */

WINAPI_EXPORT NTSTATUS IoConnectInterruptEx(
    PIO_CONNECT_INTERRUPT_PARAMETERS Parameters)
{
    if (Parameters == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    KAFFINITY mask = (KAFFINITY)0;
    PKINTERRUPT *out = NULL;
    PKSERVICE_ROUTINE  isr = NULL;
    PVOID              ctx = NULL;
    PKSPIN_LOCK        spin = NULL;
    KIRQL              irql = 0, sirql = 0;
    KINTERRUPT_MODE    mode = LevelSensitive;
    BOOLEAN            shared = FALSE, fsave = FALSE;
    ULONG              vector = 0;

    switch (Parameters->Version) {
    case CONNECT_FULLY_SPECIFIED:
    case CONNECT_FULLY_SPECIFIED_GROUP:
        out    = Parameters->FullySpecified.InterruptObject;
        isr    = Parameters->FullySpecified.ServiceRoutine;
        ctx    = Parameters->FullySpecified.ServiceContext;
        spin   = Parameters->FullySpecified.SpinLock;
        vector = Parameters->FullySpecified.Vector;
        irql   = Parameters->FullySpecified.Irql;
        sirql  = Parameters->FullySpecified.SynchronizeIrql;
        mode   = Parameters->FullySpecified.InterruptMode;
        shared = Parameters->FullySpecified.ShareVector;
        fsave  = Parameters->FullySpecified.FloatingSave;
        mask   = (KAFFINITY)Parameters->FullySpecified.ProcessorEnableMask;
        break;
    case CONNECT_LINE_BASED:
        out    = Parameters->LineBased.InterruptObject;
        isr    = Parameters->LineBased.ServiceRoutine;
        ctx    = Parameters->LineBased.ServiceContext;
        spin   = Parameters->LineBased.SpinLock;
        sirql  = Parameters->LineBased.SynchronizeIrql;
        fsave  = Parameters->LineBased.FloatingSave;
        /* Line-based: no explicit vector; driver expects HAL to pick.
         * We use 0 and let hal_irq_open_uio fall back. */
        break;
    case CONNECT_MESSAGE_BASED:
        /* MSI/MSI-X requires VFIO; not yet supported. */
        return STATUS_INSUFFICIENT_RESOURCES;
    default:
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!out || !isr)
        return STATUS_INSUFFICIENT_RESOURCES;

    return IoConnectInterrupt(out, isr, ctx, spin, vector, irql, sirql,
                               mode, shared, mask, fsave);
}

/* ===== IoDisconnectInterrupt ======================================== */

WINAPI_EXPORT void IoDisconnectInterrupt(PKINTERRUPT InterruptObject)
{
    if (!InterruptObject)
        return;

    InterruptObject->running = 0;
    if (InterruptObject->stop_fd >= 0) {
        uint64_t one = 1;
        ssize_t wn = write(InterruptObject->stop_fd, &one, sizeof(one));
        (void)wn;
    }
    pthread_join(InterruptObject->isr_thread, NULL);

    if (InterruptObject->uio_fd >= 0)
        close(InterruptObject->uio_fd);
    if (InterruptObject->stop_fd >= 0)
        close(InterruptObject->stop_fd);
    pthread_mutex_destroy(&InterruptObject->sync_mtx);
    free(InterruptObject);
}

WINAPI_EXPORT void IoDisconnectInterruptEx(
    PIO_DISCONNECT_INTERRUPT_PARAMETERS Parameters)
{
    if (Parameters && Parameters->ConnectionContext)
        IoDisconnectInterrupt(Parameters->ConnectionContext);
}

/* ===== KeSynchronizeExecution ======================================= */

WINAPI_EXPORT BOOLEAN KeSynchronizeExecution(
    PKINTERRUPT          Interrupt,
    PKSYNCHRONIZE_ROUTINE SynchronizeRoutine,
    PVOID                SynchronizeContext)
{
    if (!Interrupt || !SynchronizeRoutine)
        return FALSE;
    pthread_mutex_lock(&Interrupt->sync_mtx);
    BOOLEAN r = SynchronizeRoutine(SynchronizeContext);
    pthread_mutex_unlock(&Interrupt->sync_mtx);
    return r;
}

/* ===== HalGetInterruptVector ======================================== *
 *
 * Maps (BusType, BusNumber, Slot, IRQL, Affinity) -> Linux IRQ number.
 * For PCI we read /sys/bus/pci/devices/<bdf>/irq directly.
 * Returns the vector via the function return + populates *Irql / *Affinity. */

WINAPI_EXPORT ULONG HalGetInterruptVector(
    INTERFACE_TYPE  InterfaceType,
    ULONG           BusNumber,
    ULONG           BusInterruptLevel,
    ULONG           BusInterruptVector,
    PKIRQL          Irql,
    KAFFINITY      *Affinity)
{
    (void)BusInterruptLevel;

    if (Irql)     *Irql = DISPATCH_LEVEL;
    if (Affinity) *Affinity = (KAFFINITY)1; /* CPU 0 only -- userspace */

    if (InterfaceType != PCIBus) {
        /* Non-PCI: just echo the level back. */
        return BusInterruptVector;
    }

    /* The caller's BusInterruptVector encodes our SlotNumber. */
    hal_pci_bdf_t bdf;
    hal_decode_slot(BusInterruptVector, &bdf, BusNumber);

    if (!hal_trust_check(HAL_TRUST_PCI_READ, "HalGetInterruptVector", NULL))
        return 0;

    long irq = hal_pci_read_int_attr(&bdf, "irq");
    if (irq < 0)
        return 0;
    return (ULONG)irq;
}
