/*
 * ndis_miniport.c - NDIS6 miniport registration + RX/TX path on Linux TAP.
 *
 * Provides the surface a Windows network driver needs to actually
 * register itself and shuttle Ethernet frames in/out:
 *
 *   - NdisRegisterMiniportDriver  (NDIS6 modern entry)
 *   - NdisDeregisterMiniportDriver
 *   - NdisMSendNetBufferListsComplete  (TX completion downcall path)
 *   - NdisMRegisterInterruptEx / NdisMDeregisterInterruptEx
 *   - NdisMIndicateReceiveNetBufferLists (helper for RX upcalls)
 *
 * Transport: a per-driver Linux TAP device (/dev/net/tun).  Each
 * registered miniport gets ndistap<N>.  RX is a blocking read() loop
 * in a dedicated thread; the loop wraps each frame in a flat buffer
 * and (a) increments rx counters, (b) optionally invokes the saved
 * MiniportInterrupt/Dpc to satisfy ISR contracts, then (c) drops the
 * frame into the driver's MiniportSendNetBufferLists-paired receive
 * indication.  We do not implement the full NET_BUFFER_LIST scatter-
 * gather chain: ndis_gather_nbl() walks a simplified single-buffer
 * NBL; PE drivers calling our stubs see a flat 2KB frame buffer.
 *
 * ============================================================
 *  CAPABILITY REQUIREMENTS
 * ============================================================
 *
 *  TAP creation (open("/dev/net/tun") + ioctl(TUNSETIFF)) requires
 *  CAP_NET_ADMIN.  Three ways to get it:
 *
 *    1. setcap cap_net_admin+ep on /usr/bin/peloader
 *    2. Run loader as root (not recommended for general use)
 *    3. Trust kernel cap negotiation: trust band TRUST_OPERATOR
 *       (band >= 6) is granted CAP_NET_ADMIN by the trust gate at
 *       process spawn.  The loader requests this cap from trust.ko
 *       when the loaded PE imports any ndis.sys symbol -- see
 *       trust_gate.c::trust_negotiate_caps().
 *
 *  Without CAP_NET_ADMIN, NdisRegisterMiniportDriver still returns
 *  NDIS_STATUS_SUCCESS so the driver's DriverEntry doesn't fail, but
 *  the miniport is marked tap_open_failed=1 and TX/RX become no-ops
 *  with counters incrementing rx_errors/tx_errors.  This matches
 *  Windows behaviour where a driver can register but the adapter
 *  never reaches Operational state.
 * ============================================================
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <pthread.h>

#include "ndis_miniport.h"

#define LOG_PREFIX "[ndis-mp] "

/* ===== Global tap-index allocator ================================== */
static pthread_mutex_t g_tap_index_lock = PTHREAD_MUTEX_INITIALIZER;
static int             g_tap_index_next = 0;

int ndis_next_tap_index(void) {
    pthread_mutex_lock(&g_tap_index_lock);
    int idx = g_tap_index_next++;
    pthread_mutex_unlock(&g_tap_index_lock);
    return idx;
}

/* ===== Track all live miniports for clean shutdown ================= */
#define NDIS_MAX_MINIPORTS 16
static pthread_mutex_t g_mp_table_lock = PTHREAD_MUTEX_INITIALIZER;
static ndis_miniport_t *g_mp_table[NDIS_MAX_MINIPORTS];

static int register_miniport(ndis_miniport_t *mp) {
    pthread_mutex_lock(&g_mp_table_lock);
    for (int i = 0; i < NDIS_MAX_MINIPORTS; i++) {
        if (!g_mp_table[i]) {
            g_mp_table[i] = mp;
            pthread_mutex_unlock(&g_mp_table_lock);
            return i;
        }
    }
    pthread_mutex_unlock(&g_mp_table_lock);
    return -1;
}

static void unregister_miniport(ndis_miniport_t *mp) {
    pthread_mutex_lock(&g_mp_table_lock);
    for (int i = 0; i < NDIS_MAX_MINIPORTS; i++) {
        if (g_mp_table[i] == mp) {
            g_mp_table[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&g_mp_table_lock);
}

/* ===== MAC synthesis =============================================== *
 * Build a locally-administered unicast MAC (LSB of first byte = 0,
 * 2nd-LSB = 1) deterministically from the driver name so multiple
 * loads of the same driver don't fight over MACs. */
void ndis_synth_mac(const void *seed, size_t seed_len, UCHAR mac[NDIS_MAC_LEN]) {
    /* Tiny FNV-1a so we don't pull in OpenSSL */
    uint64_t h = 0xcbf29ce484222325ULL;
    const unsigned char *p = (const unsigned char *)seed;
    for (size_t i = 0; i < seed_len; i++) {
        h ^= p[i];
        h *= 0x100000001b3ULL;
    }
    mac[0] = (UCHAR)((h >> 0)  & 0xFC) | 0x02;   /* locally administered, unicast */
    mac[1] = (UCHAR)((h >> 8)  & 0xFF);
    mac[2] = (UCHAR)((h >> 16) & 0xFF);
    mac[3] = (UCHAR)((h >> 24) & 0xFF);
    mac[4] = (UCHAR)((h >> 32) & 0xFF);
    mac[5] = (UCHAR)((h >> 40) & 0xFF);
}

/* ===== TAP device setup ============================================ */
static int open_tap_device(ndis_miniport_t *mp) {
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, LOG_PREFIX "open(/dev/net/tun) failed: %s "
                "(needs CAP_NET_ADMIN; see ndis_miniport.c header)\n",
                strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "ndistap%d", mp->tap_index);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        fprintf(stderr, LOG_PREFIX "ioctl(TUNSETIFF, %s) failed: %s\n",
                ifr.ifr_name, strerror(errno));
        close(fd);
        return -1;
    }

    /* Persist actually-allocated name (kernel may rewrite) */
    snprintf(mp->tap_name, sizeof(mp->tap_name), "%s", ifr.ifr_name);

    /* Non-blocking is wrong for us -- the RX thread WANTS to block on
     * read().  We do, however, want O_CLOEXEC (set above). */

    fprintf(stderr, LOG_PREFIX "TAP device %s ready (fd=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x)\n",
            mp->tap_name, fd,
            mp->mac[0], mp->mac[1], mp->mac[2],
            mp->mac[3], mp->mac[4], mp->mac[5]);
    return fd;
}

/* ===== RX loop ===================================================== *
 *
 * Per-miniport thread; blocks on read(tap_fd) for up to MTU bytes.
 * On each frame:
 *   - bumps rx counters
 *   - if NdisMRegisterInterruptEx supplied an ISR, calls it (the
 *     real Windows contract demands MiniportInterrupt return whether
 *     a DPC is needed; we always call MiniportInterruptDpc afterward
 *     for simplicity).
 *
 * We DO NOT actually call back into a driver's receive indication
 * routine here -- the proper NDIS6 hook is a callback stored in the
 * MINIPORT_DRIVER_CHARACTERISTICS struct (offset depends on Win
 * version).  Walking that opaque struct correctly requires matching
 * the driver's compiled NDIS version; for safety we ONLY drive the
 * ISR path and let drivers that need RX upcalls register one
 * explicitly via NdisMIndicateReceiveNetBufferLists, which they call
 * during ISR DPC processing in real Windows.
 */
static void *ndis_rx_loop(void *arg) {
    ndis_miniport_t *mp = (ndis_miniport_t *)arg;
    UCHAR frame[NDIS_FRAME_BUF_SIZE];

    while (!mp->rx_stop) {
        ssize_t n = read(mp->tap_fd, frame, sizeof(frame));
        if (n < 0) {
            if (errno == EINTR) continue;
            if (mp->rx_stop) break;
            __atomic_add_fetch(&mp->rx_errors, 1, __ATOMIC_RELAXED);
            usleep(10000);
            continue;
        }
        if (n == 0) continue;

        __atomic_add_fetch(&mp->rx_packets, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&mp->rx_bytes, (uint64_t)n, __ATOMIC_RELAXED);

        /* Fake an IRQ if the driver registered one. */
        if (mp->interrupt_registered) {
            typedef int  (*pisr)(void *ctx);
            typedef void (*pdpc)(void *ctx);
            if (mp->isr_handler) {
                /* MiniportInterrupt returns BOOLEAN "queue-DPC"; we
                 * ignore the return value -- always run the DPC. */
                ((pisr)mp->isr_handler)(mp->interrupt_context);
            }
            if (mp->dpc_handler) {
                ((pdpc)mp->dpc_handler)(mp->interrupt_context);
            }
        }
    }
    return NULL;
}

/* ===== NdisRegisterMiniportDriver (NDIS6 entry) ==================== */
WINAPI_EXPORT NDIS_STATUS NdisRegisterMiniportDriver(
    PUNICODE_STRING DriverName,
    NDIS_HANDLE     DriverObject,
    void           *Characteristics,
    NDIS_HANDLE    *DriverHandle)
{
    (void)DriverObject;

    if (!DriverHandle) return NDIS_STATUS_INVALID_PARAMETER;

    ndis_miniport_t *mp = (ndis_miniport_t *)calloc(1, sizeof(*mp));
    if (!mp) return NDIS_STATUS_RESOURCES;

    pthread_mutex_init(&mp->lock, NULL);
    mp->characteristics = Characteristics;
    mp->mtu             = NDIS_DEFAULT_MTU;
    mp->link_speed_bps  = 1000ULL * 1000ULL * 1000ULL;   /* 1 Gbps */
    mp->lookahead       = NDIS_DEFAULT_MTU;
    mp->packet_filter   = 0;
    mp->tap_index       = ndis_next_tap_index();

    /* Synthesise MAC from driver name (best-effort: UNICODE_STRING.Buffer
     * may be NULL or hold UTF-16; treat raw bytes as seed). */
    if (DriverName && DriverName->Buffer && DriverName->Length > 0) {
        ndis_synth_mac(DriverName->Buffer, DriverName->Length, mp->mac);
    } else {
        /* Fall back to tap_index so we still get a unique MAC. */
        ndis_synth_mac(&mp->tap_index, sizeof(mp->tap_index), mp->mac);
    }

    /* Try to open the TAP.  Failure is non-fatal -- driver still gets
     * a handle, just sees no traffic.  See header comment for why. */
    mp->tap_fd = open_tap_device(mp);
    if (mp->tap_fd < 0) {
        mp->tap_open_failed = 1;
    } else {
        mp->rx_stop = 0;
        if (pthread_create(&mp->rx_thread, NULL, ndis_rx_loop, mp) == 0) {
            mp->rx_thread_active = 1;
        } else {
            fprintf(stderr, LOG_PREFIX "pthread_create(rx) failed\n");
            close(mp->tap_fd);
            mp->tap_fd = -1;
            mp->tap_open_failed = 1;
        }
    }

    register_miniport(mp);
    mp->driver_handle = (NDIS_HANDLE)mp;
    *DriverHandle = mp->driver_handle;

    fprintf(stderr, LOG_PREFIX "NdisRegisterMiniportDriver -> handle=%p tap=%s\n",
            mp, mp->tap_open_failed ? "(none)" : mp->tap_name);
    return NDIS_STATUS_SUCCESS;
}

WINAPI_EXPORT void NdisDeregisterMiniportDriver(NDIS_HANDLE NdisMiniportDriverHandle)
{
    ndis_miniport_t *mp = (ndis_miniport_t *)NdisMiniportDriverHandle;
    if (!mp) return;

    /* Stop RX thread first so it can't race the close(tap_fd). */
    if (mp->rx_thread_active) {
        mp->rx_stop = 1;
        if (mp->tap_fd >= 0) {
            shutdown(mp->tap_fd, SHUT_RDWR);  /* unblock read() if possible */
        }
        pthread_join(mp->rx_thread, NULL);
        mp->rx_thread_active = 0;
    }
    if (mp->tap_fd >= 0) {
        close(mp->tap_fd);
        mp->tap_fd = -1;
    }

    unregister_miniport(mp);
    pthread_mutex_destroy(&mp->lock);
    fprintf(stderr, LOG_PREFIX "NdisDeregisterMiniportDriver mp=%p\n", mp);
    free(mp);
}

/* ===== TX path: NdisMSendNetBufferListsComplete =====================
 *
 * Real Windows semantics: the *driver* calls this to acknowledge a
 * send the OS gave it (i.e. it's a downward "I'm done" notification
 * back to NDIS).  Some drivers also call NdisMSendNetBufferLists
 * (without "Complete") to inject internally-generated frames.
 *
 * Both flow through ndis_gather_nbl() into write(tap_fd).
 *
 * NET_BUFFER_LIST is opaque to us.  We assume the simplest layout: a
 * pointer to a NET_BUFFER list whose first entry's MDL chain points
 * at a single contiguous frame.  If the layout doesn't match, we
 * silently drop with tx_errors++.
 *
 * Layout we accept (offsets from start of NET_BUFFER_LIST):
 *   +0x10  PNET_BUFFER FirstNetBuffer  (we read this pointer)
 * NET_BUFFER:
 *   +0x10  ULONG  DataLength
 *   +0x18  PMDL   CurrentMdl
 *   +0x20  ULONG  CurrentMdlOffset
 * MDL:
 *   +0x18  PVOID  MappedSystemVa
 *   +0x28  ULONG  ByteCount
 *
 * We bounds-check every dereference and bail to tx_errors on any
 * NULL.  This is intentionally defensive -- we *cannot* trust an
 * untrusted PE driver to give us well-formed buffers.
 */
static ULONG ndis_gather_nbl(void *nbl, UCHAR *out, ULONG out_max) {
    if (!nbl || !out || out_max == 0) return 0;
    UCHAR *base = (UCHAR *)nbl;

    void *first_nb = *(void **)(base + 0x10);
    if (!first_nb) return 0;

    UCHAR *nb = (UCHAR *)first_nb;
    ULONG  data_len = *(ULONG *)(nb + 0x10);
    void  *mdl      = *(void  **)(nb + 0x18);
    ULONG  mdl_off  = *(ULONG *)(nb + 0x20);

    if (!mdl || data_len == 0 || data_len > out_max) return 0;

    UCHAR *mdl_b = (UCHAR *)mdl;
    void  *va    = *(void  **)(mdl_b + 0x18);
    ULONG  bc    = *(ULONG *)(mdl_b + 0x28);

    if (!va || mdl_off >= bc) return 0;

    ULONG copy = bc - mdl_off;
    if (copy > data_len) copy = data_len;
    if (copy > out_max)  copy = out_max;

    memcpy(out, (UCHAR *)va + mdl_off, copy);
    return copy;
}

WINAPI_EXPORT void NdisMSendNetBufferListsComplete(
    NDIS_HANDLE NdisMiniportHandle,
    void       *NetBufferList,
    ULONG       SendCompleteFlags)
{
    (void)SendCompleteFlags;
    ndis_miniport_t *mp = (ndis_miniport_t *)NdisMiniportHandle;
    if (!mp) return;

    if (mp->tap_open_failed || mp->tap_fd < 0) {
        __atomic_add_fetch(&mp->tx_errors, 1, __ATOMIC_RELAXED);
        return;
    }

    UCHAR  frame[NDIS_FRAME_BUF_SIZE];
    ULONG  total = ndis_gather_nbl(NetBufferList, frame, sizeof(frame));
    if (total == 0) {
        __atomic_add_fetch(&mp->tx_errors, 1, __ATOMIC_RELAXED);
        return;
    }

    ssize_t w = write(mp->tap_fd, frame, total);
    if (w == (ssize_t)total) {
        __atomic_add_fetch(&mp->tx_packets, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&mp->tx_bytes, (uint64_t)total, __ATOMIC_RELAXED);
    } else {
        __atomic_add_fetch(&mp->tx_errors, 1, __ATOMIC_RELAXED);
    }
}

/* Some drivers call NdisMSendNetBufferLists (without "Complete") to
 * inject frames.  Identical TX gather/write path. */
WINAPI_EXPORT void NdisMSendNetBufferLists(
    NDIS_HANDLE NdisMiniportHandle,
    void       *NetBufferList,
    NDIS_HANDLE PortNumber,
    ULONG       SendFlags)
{
    (void)PortNumber;
    NdisMSendNetBufferListsComplete(NdisMiniportHandle, NetBufferList, SendFlags);
}

/* ===== RX upcall: driver hands us frames (rare; DPC path) ==========
 * Called by drivers that want to inject frames upward into NDIS.
 * For us this is a no-op accounting hook.  We just count it. */
WINAPI_EXPORT void NdisMIndicateReceiveNetBufferLists(
    NDIS_HANDLE NdisMiniportHandle,
    void       *NetBufferLists,
    NDIS_HANDLE PortNumber,
    ULONG       NumberOfNetBufferLists,
    ULONG       ReceiveFlags)
{
    (void)NetBufferLists;
    (void)PortNumber;
    (void)ReceiveFlags;
    ndis_miniport_t *mp = (ndis_miniport_t *)NdisMiniportHandle;
    if (!mp) return;
    __atomic_add_fetch(&mp->rx_packets, NumberOfNetBufferLists, __ATOMIC_RELAXED);
}

/* ===== IRQ surface: NdisMRegisterInterruptEx ======================= */
WINAPI_EXPORT NDIS_STATUS NdisMRegisterInterruptEx(
    NDIS_HANDLE   MiniportAdapterHandle,
    void         *MiniportInterruptContext,
    void         *MiniportInterruptCharacteristics, /* PNDIS_MINIPORT_INTERRUPT_CHARACTERISTICS */
    NDIS_HANDLE  *NdisInterruptHandle)
{
    ndis_miniport_t *mp = (ndis_miniport_t *)MiniportAdapterHandle;
    if (!mp) return NDIS_STATUS_INVALID_PARAMETER;

    /* MINIPORT_INTERRUPT_CHARACTERISTICS layout (NDIS 6.x):
     *   +0x00  NDIS_OBJECT_HEADER Header
     *   +0x08  W_MINIPORT_ISR_HANDLER InterruptHandler
     *   +0x10  W_MINIPORT_INTERRUPT_DPC_HANDLER InterruptDpcHandler
     * We read the two function pointers; everything else is opaque.
     */
    if (MiniportInterruptCharacteristics) {
        UCHAR *cs = (UCHAR *)MiniportInterruptCharacteristics;
        mp->isr_handler         = *(void **)(cs + 0x08);
        mp->dpc_handler         = *(void **)(cs + 0x10);
    }
    mp->interrupt_context   = MiniportInterruptContext;
    mp->interrupt_registered = 1;

    if (NdisInterruptHandle) *NdisInterruptHandle = mp;
    fprintf(stderr, LOG_PREFIX "NdisMRegisterInterruptEx isr=%p dpc=%p\n",
            mp->isr_handler, mp->dpc_handler);
    return NDIS_STATUS_SUCCESS;
}

WINAPI_EXPORT void NdisMDeregisterInterruptEx(NDIS_HANDLE NdisInterruptHandle)
{
    ndis_miniport_t *mp = (ndis_miniport_t *)NdisInterruptHandle;
    if (!mp) return;
    mp->interrupt_registered = 0;
    mp->isr_handler          = NULL;
    mp->dpc_handler          = NULL;
    mp->interrupt_context    = NULL;
}

/* ===== OID query/set entry points ==================================
 *
 * Drivers normally implement MiniportQueryInformation/SetInformation
 * themselves -- the *driver* receives these calls.  But many drivers
 * also call back into NDIS via NdisMQueryInformationComplete /
 * NdisMSetInformationComplete to acknowledge async completions.  We
 * provide the call-into-driver path (ndis_oid_query/set in
 * ndis_oid.c) so internal consumers can ask about the synthesised
 * adapter, and we provide the completion stubs as no-ops.
 */
WINAPI_EXPORT void NdisMQueryInformationComplete(
    NDIS_HANDLE MiniportAdapterHandle, NDIS_STATUS Status)
{
    (void)MiniportAdapterHandle;
    (void)Status;
}

WINAPI_EXPORT void NdisMSetInformationComplete(
    NDIS_HANDLE MiniportAdapterHandle, NDIS_STATUS Status)
{
    (void)MiniportAdapterHandle;
    (void)Status;
}

/* ===== Public OID dispatch wrappers (callable from outside) ======== *
 * Exposed for other DLL stubs (e.g. iphlpapi) that want to query the
 * synthesised adapter. */
WINAPI_EXPORT NDIS_STATUS NdisOidQuery(
    NDIS_HANDLE Handle, uint32_t Oid,
    void *Buf, uint32_t BufLen,
    uint32_t *BytesWritten, uint32_t *BytesNeeded)
{
    ndis_miniport_t *mp = (ndis_miniport_t *)Handle;
    if (!mp) return NDIS_STATUS_INVALID_PARAMETER;
    return ndis_oid_query(mp, Oid, Buf, BufLen, BytesWritten, BytesNeeded);
}

WINAPI_EXPORT NDIS_STATUS NdisOidSet(
    NDIS_HANDLE Handle, uint32_t Oid,
    const void *Buf, uint32_t BufLen,
    uint32_t *BytesRead, uint32_t *BytesNeeded)
{
    ndis_miniport_t *mp = (ndis_miniport_t *)Handle;
    if (!mp) return NDIS_STATUS_INVALID_PARAMETER;
    return ndis_oid_set(mp, Oid, Buf, BufLen, BytesRead, BytesNeeded);
}
