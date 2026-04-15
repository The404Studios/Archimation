/*
 * trust_uapi.h - Root of Authority Userspace API
 *
 * Convenience header: includes all user-facing types, constants,
 * and ioctl definitions needed to interact with /dev/trust.
 *
 * Implements the Dynamic Hyperlation architecture:
 *   Self-Consuming Proof Chains, Chromosomal Authority Model,
 *   Token Economy, Mitotic/Meiotic Lifecycle, Immune Response
 *
 * Userspace callers should include this single header.
 */

#ifndef TRUST_UAPI_H
#define TRUST_UAPI_H

#include "trust_types.h"
#include "trust_ioctl.h"

/* /dev/trust device path */
#define TRUST_DEVICE_PATH   "/dev/trust"

/* Module/version info for userspace tools */
#define TRUST_MODULE_NAME   "trust"
#define TRUST_VERSION_MAJOR 1
#define TRUST_VERSION_MINOR 0

/* Architecture identifier */
#define TRUST_ARCHITECTURE  "Root of Authority (Dynamic Hyperlation)"

/* Helper: default capabilities for a given authority level */
static inline uint32_t trust_default_caps(uint32_t authority)
{
    switch (authority) {
    case TRUST_AUTH_KERNEL:  return TRUST_CAPS_KERNEL;
    case TRUST_AUTH_ADMIN:   return TRUST_CAPS_ADMIN;
    case TRUST_AUTH_SERVICE: return TRUST_CAPS_SERVICE;
    case TRUST_AUTH_USER:    return TRUST_CAPS_USER;
    default:                 return 0;
    }
}

/* Helper: default initial score for a given authority level */
static inline int32_t trust_default_score(uint32_t authority)
{
    switch (authority) {
    case TRUST_AUTH_KERNEL:  return TRUST_SCORE_MAX;
    case TRUST_AUTH_ADMIN:   return 700;
    case TRUST_AUTH_SERVICE: return 400;
    case TRUST_AUTH_USER:    return TRUST_SCORE_DEFAULT;
    default:                 return 0;
    }
}

/* ========================================================================
 * Session 31 Extended ISA (VEC, FUSED, predicate)
 *
 * Userspace-visible opcode constants and the predicate-bit layout
 * for the extended Trust RISC ISA.  Kernels that don't implement
 * these opcodes return -ENOSYS; libtrust should probe and fall back
 * to the scalar equivalents.
 *
 * Full layout + decoder helpers live in <trust_isa.h> (kernel- and
 * userland-safe).  This block is the minimal set needed by tools
 * that only want to *submit* extended instructions.
 * ======================================================================== */

/* Predicate bit = bit 31 of instruction word (0 = unconditional) */
#define TRUST_UAPI_PRED_BIT         31
#define TRUST_UAPI_PRED_MASK        0x80000000U
#define TRUST_UAPI_PRED_SENSE_BIT   30
#define TRUST_UAPI_PRED_SENSE_MASK  0x40000000U
#define TRUST_UAPI_PRED_COND_SHIFT  28
#define TRUST_UAPI_PRED_COND_MASK   0x30000000U

#define TRUST_UAPI_PCC_ZERO         0
#define TRUST_UAPI_PCC_NONZERO      1
#define TRUST_UAPI_PCC_NEG          2
#define TRUST_UAPI_PCC_POS          3

/* Extended family IDs (on top of TRUST_ISA_FAMILY_* in trust_types.h) */
#define TRUST_UAPI_FAMILY_VEC       6
#define TRUST_UAPI_FAMILY_FUSED     7

/* VEC opcodes */
#define TRUST_UAPI_VEC_DECAY             0
#define TRUST_UAPI_VEC_ESCALATE_CHECK    1
#define TRUST_UAPI_VEC_RES_XFER_FAN_IN   2
#define TRUST_UAPI_VEC_RES_XFER_FAN_OUT  3
#define TRUST_UAPI_VEC_GATE_EVAL         4
#define TRUST_UAPI_VEC_POLL_STATE        5
#define TRUST_UAPI_VEC_TOKEN_REGEN       6
#define TRUST_UAPI_VEC_SCORE_READ        7
#define TRUST_UAPI_VEC_CAP_CHECK         8
#define TRUST_UAPI_VEC_IMMUNE_EVAL       9
#define TRUST_UAPI_VEC_MAX              10

/* FUSED opcodes */
#define TRUST_UAPI_FUSED_AUTH_GATE      0
#define TRUST_UAPI_FUSED_TRUST_XFER     1
#define TRUST_UAPI_FUSED_DECAY_CHECK    2
#define TRUST_UAPI_FUSED_CHECK_RECORD   3
#define TRUST_UAPI_FUSED_BURN_AUDIT     4
#define TRUST_UAPI_FUSED_MAX            5

/* Variable-length batch stream magic (kept in sync with trust_isa.h) */
#define TRUST_UAPI_BATCH_MAGIC          0x5442U   /* 'TB' */
#define TRUST_UAPI_BATCH_F_DELTA        (1U << 0)
#define TRUST_UAPI_BATCH_F_ZIGZAG       (1U << 1)
#define TRUST_UAPI_BATCH_F_PRED         (1U << 16)
#define TRUST_UAPI_BATCH_HDR_SIZE       16U
#define TRUST_UAPI_BATCH_MAX_COUNT      1024U

/* Packed observer event (u32 sid + u8 type/cost/flags = 7 bytes) */
#define TRUST_UAPI_EVT_PACKED_SIZE      7U

#endif /* TRUST_UAPI_H */
