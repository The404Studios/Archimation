/*
 * ndis_oid.c - OID query/set handlers for synthesised NDIS adapter.
 *
 * A real NDIS driver responds to OIDs from the OS.  We're providing the
 * MIRROR side: when something inside the loader (or another stub) wants
 * to ask the synthesised adapter what its MAC is, what speed it links at,
 * etc., it calls into here.  Returns sane Ethernet 1Gbps values.
 *
 * Layout discipline: every responder writes the result + sets
 * *bytes_written.  On undersized buffers we set *bytes_needed and return
 * NDIS_STATUS_BUFFER_TOO_SHORT.  Unsupported OIDs return
 * NDIS_STATUS_NOT_SUPPORTED with both counters zeroed.
 */

#include <stdint.h>
#include <string.h>

#include "ndis_miniport.h"

/* Supported-OID list -- order matters for OID_GEN_SUPPORTED_LIST. */
static const uint32_t SUPPORTED_OIDS[] = {
    OID_GEN_SUPPORTED_LIST,
    OID_GEN_HARDWARE_STATUS,
    OID_GEN_MEDIA_SUPPORTED,
    OID_GEN_MEDIA_IN_USE,
    OID_GEN_MAXIMUM_LOOKAHEAD,
    OID_GEN_MAXIMUM_FRAME_SIZE,
    OID_GEN_LINK_SPEED,
    OID_GEN_TRANSMIT_BUFFER_SPACE,
    OID_GEN_RECEIVE_BUFFER_SPACE,
    OID_GEN_TRANSMIT_BLOCK_SIZE,
    OID_GEN_RECEIVE_BLOCK_SIZE,
    OID_GEN_VENDOR_ID,
    OID_GEN_VENDOR_DESCRIPTION,
    OID_GEN_CURRENT_PACKET_FILTER,
    OID_GEN_CURRENT_LOOKAHEAD,
    OID_GEN_DRIVER_VERSION,
    OID_GEN_MAXIMUM_TOTAL_SIZE,
    OID_GEN_MAC_OPTIONS,
    OID_GEN_MEDIA_CONNECT_STATUS,
    OID_GEN_VENDOR_DRIVER_VERSION,
    OID_GEN_PHYSICAL_MEDIUM,
    OID_802_3_PERMANENT_ADDRESS,
    OID_802_3_CURRENT_ADDRESS,
    OID_802_3_MAXIMUM_LIST_SIZE,
};

/* Helper: write a uint32 result, set bytes_written, bail if undersized. */
#define WRITE_U32(val) do {                                              \
    if (buf_len < sizeof(uint32_t)) {                                    \
        if (bytes_needed) *bytes_needed = sizeof(uint32_t);              \
        return NDIS_STATUS_BUFFER_TOO_SHORT;                             \
    }                                                                    \
    *(uint32_t *)buf = (uint32_t)(val);                                  \
    if (bytes_written) *bytes_written = sizeof(uint32_t);                \
    return NDIS_STATUS_SUCCESS;                                          \
} while (0)

#define WRITE_U64(val) do {                                              \
    if (buf_len < sizeof(uint64_t)) {                                    \
        if (bytes_needed) *bytes_needed = sizeof(uint64_t);              \
        return NDIS_STATUS_BUFFER_TOO_SHORT;                             \
    }                                                                    \
    *(uint64_t *)buf = (uint64_t)(val);                                  \
    if (bytes_written) *bytes_written = sizeof(uint64_t);                \
    return NDIS_STATUS_SUCCESS;                                          \
} while (0)

#define WRITE_BYTES(src, len) do {                                       \
    if (buf_len < (uint32_t)(len)) {                                     \
        if (bytes_needed) *bytes_needed = (len);                         \
        return NDIS_STATUS_BUFFER_TOO_SHORT;                             \
    }                                                                    \
    memcpy(buf, (src), (len));                                           \
    if (bytes_written) *bytes_written = (len);                           \
    return NDIS_STATUS_SUCCESS;                                          \
} while (0)

NDIS_STATUS ndis_oid_query(ndis_miniport_t *mp,
                           uint32_t oid,
                           void *buf,
                           uint32_t buf_len,
                           uint32_t *bytes_written,
                           uint32_t *bytes_needed)
{
    if (!mp || !buf) {
        if (bytes_written) *bytes_written = 0;
        if (bytes_needed)  *bytes_needed  = 0;
        return NDIS_STATUS_INVALID_PARAMETER;
    }
    if (bytes_written) *bytes_written = 0;
    if (bytes_needed)  *bytes_needed  = 0;

    switch (oid) {
    case OID_GEN_SUPPORTED_LIST:
        WRITE_BYTES(SUPPORTED_OIDS, sizeof(SUPPORTED_OIDS));

    case OID_GEN_HARDWARE_STATUS:
        WRITE_U32(NdisHardwareStatusReady);

    case OID_GEN_MEDIA_SUPPORTED:
    case OID_GEN_MEDIA_IN_USE:
        WRITE_U32(NdisMedium802_3);

    case OID_GEN_MAXIMUM_LOOKAHEAD:
    case OID_GEN_CURRENT_LOOKAHEAD:
        WRITE_U32(mp->lookahead);

    case OID_GEN_MAXIMUM_FRAME_SIZE:
        WRITE_U32(mp->mtu);                /* 1500 */

    case OID_GEN_MAXIMUM_TOTAL_SIZE:
        WRITE_U32(mp->mtu + 14);           /* + Ethernet header */

    case OID_GEN_LINK_SPEED: {
        /* Reported in 100 bps units per NDIS spec */
        uint32_t v = (uint32_t)(mp->link_speed_bps / 100ULL);
        WRITE_U32(v);
    }

    case OID_GEN_TRANSMIT_BUFFER_SPACE:
    case OID_GEN_RECEIVE_BUFFER_SPACE:
        WRITE_U32(NDIS_FRAME_BUF_SIZE * 64);   /* 128 KB worth of buffers */

    case OID_GEN_TRANSMIT_BLOCK_SIZE:
    case OID_GEN_RECEIVE_BLOCK_SIZE:
        WRITE_U32(NDIS_FRAME_BUF_SIZE);

    case OID_GEN_VENDOR_ID:
        /* Locally administered "vendor" ID -- 0xffffff is the NDIS
         * "no vendor" sentinel which keeps Windows quiet. */
        WRITE_U32(0x00FFFFFF);

    case OID_GEN_VENDOR_DESCRIPTION: {
        static const char desc[] = "PE-Loader virtual NDIS miniport";
        WRITE_BYTES(desc, sizeof(desc));   /* includes trailing NUL */
    }

    case OID_GEN_CURRENT_PACKET_FILTER:
        WRITE_U32(mp->packet_filter);

    case OID_GEN_DRIVER_VERSION:
    case OID_GEN_VENDOR_DRIVER_VERSION:
        /* High byte = major (6), low byte = minor (0) */
        WRITE_U32(0x00000600);

    case OID_GEN_MAC_OPTIONS:
        /* NDIS_MAC_OPTION_NO_LOOPBACK | NDIS_MAC_OPTION_TRANSFERS_NOT_PEND */
        WRITE_U32(0x00000008 | 0x00000001);

    case OID_GEN_MEDIA_CONNECT_STATUS:
        WRITE_U32(mp->tap_open_failed ? 1 : NdisMediaStateConnected);

    case OID_GEN_PHYSICAL_MEDIUM:
        WRITE_U32(0);   /* NdisPhysicalMediumUnspecified */

    case OID_802_3_PERMANENT_ADDRESS:
    case OID_802_3_CURRENT_ADDRESS:
        WRITE_BYTES(mp->mac, NDIS_MAC_LEN);

    case OID_802_3_MAXIMUM_LIST_SIZE:
        WRITE_U32(32);  /* multicast list capacity */

    default:
        return NDIS_STATUS_NOT_SUPPORTED;
    }
}

NDIS_STATUS ndis_oid_set(ndis_miniport_t *mp,
                         uint32_t oid,
                         const void *buf,
                         uint32_t buf_len,
                         uint32_t *bytes_read,
                         uint32_t *bytes_needed)
{
    if (!mp || !buf) {
        if (bytes_read)   *bytes_read   = 0;
        if (bytes_needed) *bytes_needed = 0;
        return NDIS_STATUS_INVALID_PARAMETER;
    }
    if (bytes_read)   *bytes_read   = 0;
    if (bytes_needed) *bytes_needed = 0;

    switch (oid) {
    case OID_GEN_CURRENT_PACKET_FILTER:
        if (buf_len < sizeof(uint32_t)) {
            *bytes_needed = sizeof(uint32_t);
            return NDIS_STATUS_BUFFER_TOO_SHORT;
        }
        mp->packet_filter = *(const uint32_t *)buf;
        *bytes_read = sizeof(uint32_t);
        return NDIS_STATUS_SUCCESS;

    case OID_GEN_CURRENT_LOOKAHEAD:
        if (buf_len < sizeof(uint32_t)) {
            *bytes_needed = sizeof(uint32_t);
            return NDIS_STATUS_BUFFER_TOO_SHORT;
        }
        mp->lookahead = *(const uint32_t *)buf;
        *bytes_read = sizeof(uint32_t);
        return NDIS_STATUS_SUCCESS;

    case OID_802_3_CURRENT_ADDRESS:
        if (buf_len < NDIS_MAC_LEN) {
            *bytes_needed = NDIS_MAC_LEN;
            return NDIS_STATUS_BUFFER_TOO_SHORT;
        }
        memcpy(mp->mac, buf, NDIS_MAC_LEN);
        *bytes_read = NDIS_MAC_LEN;
        return NDIS_STATUS_SUCCESS;

    default:
        return NDIS_STATUS_NOT_SUPPORTED;
    }
}
