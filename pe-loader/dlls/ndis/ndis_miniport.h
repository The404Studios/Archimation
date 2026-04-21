/*
 * ndis_miniport.h - Internal NDIS miniport state shared between
 *                   ndis_miniport.c (registration + RX loop) and
 *                   ndis_oid.c (OID query/set handlers).
 *
 * NOT a public Win32 header.  Real Windows DDK ndis.h types are
 * forward-declared as opaque.
 */
#ifndef NDIS_MINIPORT_H
#define NDIS_MINIPORT_H

#include <stdint.h>
#include <pthread.h>

#include "common/dll_common.h"
#include "win32/wdm.h"

/* ---- NDIS forward typedefs (opaque to PE driver) -------------------- */
typedef PVOID  NDIS_HANDLE;
typedef NTSTATUS NDIS_STATUS;

/* NDIS status codes (mirror ndis_stubs.c so users link cleanly) */
#ifndef NDIS_STATUS_SUCCESS
#define NDIS_STATUS_SUCCESS              ((NDIS_STATUS)0x00000000)
#define NDIS_STATUS_PENDING              ((NDIS_STATUS)0x00000103)
#define NDIS_STATUS_FAILURE              ((NDIS_STATUS)0xC0000001)
#define NDIS_STATUS_INVALID_PARAMETER    ((NDIS_STATUS)0xC000000D)
#define NDIS_STATUS_INVALID_LENGTH       ((NDIS_STATUS)0xC0000004)
#define NDIS_STATUS_BUFFER_TOO_SHORT     ((NDIS_STATUS)0xC0000023)
#define NDIS_STATUS_RESOURCES            ((NDIS_STATUS)0xC000009A)
#define NDIS_STATUS_NOT_SUPPORTED        ((NDIS_STATUS)0xC00000BB)
#endif

/* ---- Generic OID values (subset that matters) ---------------------- */
#define OID_GEN_SUPPORTED_LIST           0x00010101
#define OID_GEN_HARDWARE_STATUS          0x00010102
#define OID_GEN_MEDIA_SUPPORTED          0x00010103
#define OID_GEN_MEDIA_IN_USE             0x00010104
#define OID_GEN_MAXIMUM_LOOKAHEAD        0x00010105
#define OID_GEN_MAXIMUM_FRAME_SIZE       0x00010106
#define OID_GEN_LINK_SPEED               0x00010107
#define OID_GEN_TRANSMIT_BUFFER_SPACE    0x00010108
#define OID_GEN_RECEIVE_BUFFER_SPACE     0x00010109
#define OID_GEN_TRANSMIT_BLOCK_SIZE      0x0001010A
#define OID_GEN_RECEIVE_BLOCK_SIZE       0x0001010B
#define OID_GEN_VENDOR_ID                0x0001010C
#define OID_GEN_VENDOR_DESCRIPTION       0x0001010D
#define OID_GEN_CURRENT_PACKET_FILTER    0x0001010E
#define OID_GEN_CURRENT_LOOKAHEAD        0x0001010F
#define OID_GEN_DRIVER_VERSION           0x00010110
#define OID_GEN_MAXIMUM_TOTAL_SIZE       0x00010111
#define OID_GEN_MAC_OPTIONS              0x00010113
#define OID_GEN_MEDIA_CONNECT_STATUS     0x00010114
#define OID_GEN_VENDOR_DRIVER_VERSION    0x00010116
#define OID_GEN_PHYSICAL_MEDIUM          0x00010202
#define OID_802_3_PERMANENT_ADDRESS      0x01010101
#define OID_802_3_CURRENT_ADDRESS        0x01010102
#define OID_802_3_MAXIMUM_LIST_SIZE      0x01010104

#define NdisMedium802_3                  0
#define NdisHardwareStatusReady          0
#define NdisMediaStateConnected          0

#define NDIS_DEFAULT_MTU                 1500
#define NDIS_FRAME_BUF_SIZE              2048
#define NDIS_MAC_LEN                     6

/* ---- Miniport state -------------------------------------------------- */
typedef struct ndis_miniport {
    NDIS_HANDLE  driver_handle;        /* Cookie returned to PE driver */
    void        *characteristics;      /* Saved PNDIS_M_DRIVER_CHARACTERISTICS
                                          (opaque -- we read function ptrs by
                                          documented offset only when present) */

    /* Linux TAP transport */
    int          tap_fd;
    int          tap_index;            /* /dev/net/tun ndistap<N> */
    char         tap_name[32];
    int          tap_open_failed;      /* Non-zero if /dev/net/tun unusable */

    /* Synthesised link parameters */
    UCHAR        mac[NDIS_MAC_LEN];
    uint64_t     link_speed_bps;       /* Reported via OID_GEN_LINK_SPEED */
    uint32_t     mtu;
    uint32_t     packet_filter;        /* Set by NDIS_PACKET_TYPE_* writes */
    uint32_t     lookahead;

    /* RX path */
    pthread_t    rx_thread;
    int          rx_thread_active;
    volatile int rx_stop;

    /* "IRQ" fakery: NdisMRegisterInterruptEx */
    void        *isr_handler;          /* MiniportInterrupt */
    void        *dpc_handler;          /* MiniportInterruptDpc */
    void        *interrupt_context;
    int          interrupt_registered;

    /* Counters (exposed via OIDs and for diagnostics) */
    uint64_t     rx_packets;
    uint64_t     rx_bytes;
    uint64_t     tx_packets;
    uint64_t     tx_bytes;
    uint64_t     rx_errors;
    uint64_t     tx_errors;

    pthread_mutex_t lock;
} ndis_miniport_t;

/* ---- Internal helpers (defined in ndis_miniport.c) ----------------- */
int  ndis_next_tap_index(void);
void ndis_synth_mac(const void *seed, size_t seed_len, UCHAR mac[NDIS_MAC_LEN]);

/* ---- OID dispatcher (defined in ndis_oid.c) ------------------------ */
NDIS_STATUS ndis_oid_query(ndis_miniport_t *mp,
                           uint32_t oid,
                           void *buf,
                           uint32_t buf_len,
                           uint32_t *bytes_written,
                           uint32_t *bytes_needed);

NDIS_STATUS ndis_oid_set(ndis_miniport_t *mp,
                         uint32_t oid,
                         const void *buf,
                         uint32_t buf_len,
                         uint32_t *bytes_read,
                         uint32_t *bytes_needed);

#endif /* NDIS_MINIPORT_H */
