/*
 * trust_isa.h - Trust RISC ISA Extended Encoding (VEC, FUSED, predicate)
 *
 * This header defines the *extended* 32-bit Trust ISA instruction word
 * plus the two new families (VEC, FUSED) and the variable-length batch
 * encoding used for cache-dense command streams.
 *
 * The base encoding (AUTH/TRUST/GATE/RES/LIFE/META + 4-bit flags +
 * 4-bit nops + 16-bit imm) is defined in <trust_cmd.h>.  This file
 * layers NEW capabilities on top of it in a backward-compatible way:
 *
 *   * Predicate bit (bit 31):
 *       P=0 (legacy): instruction is unconditional (exact current
 *           behavior; the family field effectively uses bits 30:28).
 *       P=1 (new):    instruction executes only if the per-CPU
 *           predicate flag register matches the instruction's
 *           predicate-sense bit (bit 30).  Bit 29:28 carries the
 *           2-bit condition code; bit 27:24 carries the opcode.
 *
 *   * VEC family (0x6, legacy reserved slot after META=0x5):
 *       one instruction applies to N subjects in a packed array.
 *       Saves N-1 dispatch rounds.
 *
 *   * FUSED family (0x7):
 *       common hot pairs (AUTH+GATE, TRUST_CHECK+RES_XFER, ...)
 *       baked into a single 32-bit word.  Saves one dispatch round.
 *
 *   * Variable-length batch stream:
 *       consecutive same-family ops are delta-encoded with a
 *       `trust_isa_batch_t` preamble + varint deltas.  Typical
 *       batches shrink from N*4 bytes to N*1-2 bytes.
 *
 * Backward-compat rule:
 *   A kernel WITHOUT this header still dispatches the base ISA
 *   correctly.  Clients built against this header MUST fall back
 *   to scalar equivalents when the kernel lacks VEC/FUSED
 *   (detected via sysfs or ioctl probe).
 *
 * This header is safe for both kernel and userland inclusion.
 * It includes only <trust_types.h> and (for UAPI) <stdint.h>;
 * it does NOT pull in trust_internal.h.
 */

#ifndef TRUST_ISA_H
#define TRUST_ISA_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h>
#else
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#endif

#include "../include/trust_types.h"

/* ========================================================================
 * Extended Instruction Word Layout (backward-compatible)
 *
 *                       Unpredicated (P=0):
 *       31           28  27 26 25 24  23 22 21 20  19 18 17 16  15 .. 0
 *      +--------------+-------------+-------------+-------------+-------+
 *      |    FAMILY    |   OPCODE    |    FLAGS    |    NOPS     |  IMM  |
 *      +--------------+-------------+-------------+-------------+-------+
 *            4              4             4             4           16
 *
 *                       Predicated   (P=1):
 *       31  30 29 28  27 26 25 24  23 22 21 20  19 18 17 16  15 .. 0
 *      +---+---+-----+------------+------------+------------+--------+
 *      | 1 | S | CND |   OPCODE   |   FLAGS    |    NOPS    |  IMM   |
 *      +---+---+-----+------------+------------+------------+--------+
 *        1   1   2         4            4            4         16
 *
 *   Fields common to both encodings (OPCODE, FLAGS, NOPS, IMM) keep
 *   the same position, semantics, and width.  Only FAMILY bits
 *   [31:28] are repurposed when P=1.
 *
 *   Backward-compat: kernels that see bit 31 set but don't understand
 *   the predicate semantics should treat FAMILY = (instr >> 28) & 0xF
 *   which lands at 0x8-0xF (currently unused/reserved) and return
 *   -ENOSYS.  Userspace libraries probe the kernel's advertised
 *   capabilities before emitting predicated instructions.
 *
 *   Predicate semantics when P=1:
 *     * S (sense):  0 = normal; 1 = invert the match result.
 *     * CND (cond code, 2 bits):  PCC_ZERO | PCC_NONZERO | PCC_NEG |
 *                                 PCC_POS (see codes below).
 *     * FAMILY / OPCODE of the predicated instruction are taken from
 *       the *immediately previous* instruction in the dispatch stream
 *       that carried a family.  Predicated-only words act as a
 *       prefix gate on the NEXT op in the batch.
 *
 *   ALU-updated predicate register:
 *     * After every unpredicated op that has a meaningful return
 *       (score, balance, bitmap-count), the per-CPU pred_reg is set
 *       to the signed 64-bit result.
 *     * trust_isa_pred_reset() zeroes it at dispatch entry so stale
 *       state cannot leak across submits.
 *     * pred_reg does NOT survive a schedule (per-CPU; replaced by
 *       the next CPU's value upon migration).
 *
 * Predicate condition codes (2-bit, in bits 29:28 when P=1):
 * ======================================================================== */

/* Predicate bit position and mask (applies to instruction word) */
#define TRUST_ISA_PRED_BIT          31
#define TRUST_ISA_PRED_MASK         0x80000000U

/* When P=1: sense bit (30) inverts the match; cond code (29:28) */
#define TRUST_ISA_PRED_SENSE_BIT    30
#define TRUST_ISA_PRED_SENSE_MASK   0x40000000U
#define TRUST_ISA_PRED_COND_SHIFT   28
#define TRUST_ISA_PRED_COND_MASK    0x30000000U

/* Predicate condition codes */
#define TRUST_ISA_PCC_ZERO          0   /* pred_match == 0 (last result false) */
#define TRUST_ISA_PCC_NONZERO       1   /* pred_match != 0 (last result true) */
#define TRUST_ISA_PCC_NEG           2   /* last signed result < 0 */
#define TRUST_ISA_PCC_POS           3   /* last signed result >= 0 */

/*
 * trust_isa_instr_is_predicated() - Check if instruction has the
 * predicate bit set (non-zero return => pred_match must be evaluated).
 *
 * NOTE: this is independent of the family field; predicated VEC and
 * FUSED ops use the same bit.
 */
static inline int trust_isa_instr_is_predicated(uint32_t instr)
{
    return (instr & TRUST_ISA_PRED_MASK) ? 1 : 0;
}

static inline uint32_t trust_isa_pred_cond(uint32_t instr)
{
    return (instr & TRUST_ISA_PRED_COND_MASK) >> TRUST_ISA_PRED_COND_SHIFT;
}

static inline uint32_t trust_isa_pred_sense(uint32_t instr)
{
    return (instr & TRUST_ISA_PRED_SENSE_MASK) ? 1 : 0;
}

/*
 * trust_isa_pred_match() - Pure predicate evaluator.
 *
 * @cond_code:  one of TRUST_ISA_PCC_*
 * @sense:      0 = keep, 1 = invert
 * @flag_reg:   the per-CPU predicate flag register (last ALU result)
 *
 * Returns 1 if the instruction should execute, 0 if it should be
 * skipped.  Used by trust_risc_eval_predicated() and by userspace
 * test harnesses.
 */
static inline int trust_isa_pred_match(uint32_t cond_code, uint32_t sense,
                                       int64_t flag_reg)
{
    int m;
    switch (cond_code) {
    case TRUST_ISA_PCC_ZERO:    m = (flag_reg == 0); break;
    case TRUST_ISA_PCC_NONZERO: m = (flag_reg != 0); break;
    case TRUST_ISA_PCC_NEG:     m = (flag_reg < 0);  break;
    case TRUST_ISA_PCC_POS:     m = (flag_reg >= 0); break;
    default:                    m = 1;               break;
    }
    return sense ? !m : m;
}

/* ========================================================================
 * Extended Family IDs
 *
 * Families 0..5 are defined in trust_types.h (AUTH..META).  We extend
 * with:
 * ======================================================================== */

#define TRUST_ISA_FAMILY_VEC    6   /* VEC: batched policy ops */
#define TRUST_ISA_FAMILY_FUSED  7   /* FUSED: composed hot pairs */

/* Keep the legacy COUNT stable; new families are layered on top. */
#define TRUST_ISA_FAMILY_EXT_COUNT  8

/* ========================================================================
 * VEC family opcodes (family = 0x6)
 *
 * Layout semantics:
 *   OPCODE (4 bits) selects the VEC op.
 *   IMM    (16 bits) = count N of subjects (0..65535) OR, for small
 *                       batches (<= 8), a direct-packed index.
 *   NOPS  (4 bits) = number of trailing 64-bit operands which carry
 *                     the subject_id array (1 subject per operand's
 *                     low 32 bits plus one auxiliary operand of
 *                     shared parameter (amount/cap/etc.)).
 *
 * For batches > 15 subjects, userspace MUST use the variable-length
 * batch encoding (trust_isa_batch_t) which packs subjects as varint
 * deltas instead of full 64-bit operands.
 *
 * All VEC ops take the set-lock ONCE per TLB set touched (not once
 * per subject); a batch of 64 subjects typically touches <=20 sets.
 *
 * Per-op @param semantics for trust_isa_exec_vec():
 *   VEC_OP_DECAY            unused (0)
 *   VEC_OP_ESCALATE_CHECK   unused (0)
 *   VEC_OP_RES_XFER_FAN_IN  [63:32] sink sid,   [31:0] amount
 *   VEC_OP_RES_XFER_FAN_OUT [63:32] source sid, [31:0] amount
 *   VEC_OP_GATE_EVAL        [31:0]  action type
 *   VEC_OP_POLL_STATE       unused (0)
 *   VEC_OP_TOKEN_REGEN      unused (0)
 *   VEC_OP_SCORE_READ       unused (0); @out is int32[N] packed 2 per u64
 *   VEC_OP_CAP_CHECK        [31:0]  capability bitmask
 *   VEC_OP_IMMUNE_EVAL      unused (0)
 *
 * Return value: on success, number of subjects where the op had a
 * "positive" outcome (for bitmap ops: count of bits set; for decay/
 * regen: count actually processed).  Negative = -errno.
 * ======================================================================== */

#define VEC_OP_DECAY             0   /* Apply decay across N subjects */
#define VEC_OP_ESCALATE_CHECK    1   /* Threshold check across N; bitmap */
#define VEC_OP_RES_XFER_FAN_IN   2   /* N sources -> 1 sink, same amount */
#define VEC_OP_RES_XFER_FAN_OUT  3   /* 1 source -> N sinks, same amount */
#define VEC_OP_GATE_EVAL         4   /* Policy eval across N; bitmap */
#define VEC_OP_POLL_STATE        5   /* Pack state flags of N -> bitmap */
#define VEC_OP_TOKEN_REGEN       6   /* Regenerate N token balances */
#define VEC_OP_SCORE_READ        7   /* Read scores of N -> result[] */
#define VEC_OP_CAP_CHECK         8   /* Check one cap across N -> bitmap */
#define VEC_OP_IMMUNE_EVAL       9   /* Evaluate immune across N -> bitmap */

#define VEC_OP_MAX              10

/* ========================================================================
 * FUSED family opcodes (family = 0x7)
 *
 * Each fused op collapses a common two-instruction hot path into a
 * single 32-bit dispatch.  Operand layout is fixed per-opcode:
 *
 *   FUSED_AUTH_GATE       op0 = sid, op1 = cap; imm = action
 *   FUSED_TRUST_XFER      op0 = from, op1 = to;  imm = amount
 *   FUSED_DECAY_CHECK     op0 = sid; imm = action
 *   FUSED_CHECK_RECORD    op0 = sid, op1 = cap; imm = action_result
 *   FUSED_BURN_AUDIT      op0 = sid; imm = action
 *
 * Status/value semantics match the scalar equivalents; a fused failure
 * leaves the earlier side-effect visible (same as scalar would).
 * ======================================================================== */

#define FUSED_OP_AUTH_GATE      0   /* authorize then check gate */
#define FUSED_OP_TRUST_XFER     1   /* trust check then transfer */
#define FUSED_OP_DECAY_CHECK    2   /* decay + immediate threshold check */
#define FUSED_OP_CHECK_RECORD   3   /* cap check + record action */
#define FUSED_OP_BURN_AUDIT     4   /* token burn + audit emit */

#define FUSED_OP_MAX            5

/* ========================================================================
 * Variable-length batch serialization
 *
 * For cache-dense transport of many same-family instructions, batches
 * are wrapped with the following header and a stream of delta-encoded
 * subject IDs:
 *
 *   +----+-----+-----+---------+------------------+
 *   | M  | CNT | FLG | PARAM   | varint stream... |
 *   +----+-----+-----+---------+------------------+
 *    u16   u16   u32    u64       N * (1..5 bytes)
 *
 *   M    = TRUST_ISA_BATCH_MAGIC
 *   CNT  = number of subjects encoded in stream
 *   FLG  = bit 0: delta-coded (vs absolute); bit 1: zigzag;
 *          bits 8..11: family; bits 12..15: opcode;
 *          bit 16: has predicate (cond in bits 17..18, sense in bit 19);
 *          bits 20..23: reserved.
 *   PARAM= op-specific shared parameter (e.g. transfer amount).
 *
 * The stream then encodes N subject_ids.  If delta-coded, each entry
 * is the signed delta from the previous subject_id, zigzag-encoded
 * to a varint.  If absolute, each entry is the u32 subject_id
 * varint-encoded.
 *
 * Wire-size comparison on a typical VEC_DECAY of 64 subjects with
 * subject_ids sequential PIDs (e.g. 2001..2064):
 *   legacy (1 op per instruction): 64 * 12 bytes = 768 bytes
 *   base VEC (1 op, 64 NOPS):      4 + 64 * 8 = 516 bytes
 *   varlen batch (delta+varint):   16 + 64 * 1 = 80 bytes
 *                                   -> 9.6x reduction vs legacy,
 *                                   -> 6.4x reduction vs base VEC.
 * ======================================================================== */

#define TRUST_ISA_BATCH_MAGIC       0x5442U  /* 'TB' */
#define TRUST_ISA_BATCH_VERSION     1

#define TRUST_ISA_BATCH_F_DELTA     (1U << 0)
#define TRUST_ISA_BATCH_F_ZIGZAG    (1U << 1)
#define TRUST_ISA_BATCH_F_PRED      (1U << 16)

#define TRUST_ISA_BATCH_FAMILY_SHIFT 8
#define TRUST_ISA_BATCH_FAMILY_MASK  0x00000F00U
#define TRUST_ISA_BATCH_OPCODE_SHIFT 12
#define TRUST_ISA_BATCH_OPCODE_MASK  0x0000F000U

#ifdef __KERNEL__
typedef struct {
    u16 magic;          /* TRUST_ISA_BATCH_MAGIC */
    u16 count;          /* Number of subjects in stream */
    u32 flags;          /* TRUST_ISA_BATCH_F_* + family/opcode */
    u64 param;          /* op-specific parameter */
    /* varint stream follows */
} __attribute__((packed)) trust_isa_batch_t;
#else
typedef struct {
    uint16_t magic;
    uint16_t count;
    uint32_t flags;
    uint64_t param;
} __attribute__((packed)) trust_isa_batch_t;
#endif

#define TRUST_ISA_BATCH_HDR_SIZE    16U

/* Max subjects per batch (bounds kmalloc) */
#define TRUST_ISA_BATCH_MAX_COUNT   1024U

/*
 * Packed event stream element emitted kernel->user.
 * Shrinks the legacy 40-byte trust_audit_entry_t down to 7 bytes
 * for compact observer streams.  Total on-wire size is 7 bytes
 * (packed struct; no alignment padding).
 *
 *   +---------+-----+------+-------+
 *   |   SID   | TYP | COST | FLAGS |
 *   +---------+-----+------+-------+
 *     u32       u8    u8     u8      = 7 bytes
 *
 * Producers should emit a stream of these back-to-back; consumers
 * read fixed 7-byte records.  Big-endian-unsafe by design — this
 * format is only used between kernel and same-host userland.
 */
#ifdef __KERNEL__
typedef struct {
    u32 subject_id;
    u8  event_type;
    u8  cost;
    u8  flags;
} __attribute__((packed)) trust_event_packed_t;
#else
typedef struct {
    uint32_t subject_id;
    uint8_t  event_type;
    uint8_t  cost;
    uint8_t  flags;
} __attribute__((packed)) trust_event_packed_t;
#endif

#define TRUST_EVT_PACKED_SIZE       7U

/* ========================================================================
 * Varint (zigzag) helpers.  Shared; inline so both kernel and userland
 * libraries compile with no extra .o.
 *
 * Encoding:
 *   little-endian 7-bit groups, MSB=1 means continuation.  Max 5 bytes
 *   for a 32-bit value.
 * ======================================================================== */

/* Zigzag 32-bit encode: maps (-1,+1,-2,+2,...) to (1,2,3,4,...). */
static inline uint32_t trust_isa_zigzag32(int32_t v)
{
    return ((uint32_t)v << 1) ^ (uint32_t)(v >> 31);
}

static inline int32_t trust_isa_unzigzag32(uint32_t zz)
{
    /* equivalent to ((zz >> 1) ^ -(zz & 1)) but written without the
     * signed negation (-0 vs -1) that trips some strict compilers. */
    uint32_t mask = (uint32_t)0 - (zz & 1U);
    return (int32_t)((zz >> 1) ^ mask);
}

/*
 * trust_isa_varint_encode - Emit a varint to @buf, return bytes written.
 *
 * @buf:  destination (must have >= 5 bytes available)
 * @cap:  buffer capacity
 * @val:  value to encode
 *
 * Returns bytes written, or 0 on overflow.
 */
static inline unsigned int trust_isa_varint_encode(unsigned char *buf,
                                                   unsigned int cap,
                                                   uint32_t val)
{
    unsigned int i = 0;
    while (val >= 0x80U) {
        if (i >= cap) return 0;
        buf[i++] = (unsigned char)(val | 0x80U);
        val >>= 7;
    }
    if (i >= cap) return 0;
    buf[i++] = (unsigned char)val;
    return i;
}

/*
 * trust_isa_varint_decode - Parse one varint from @buf.
 *
 * @buf:    source
 * @avail:  bytes available at buf
 * @out:    decoded value
 *
 * Returns bytes consumed (1..5), or 0 if buffer truncated, or -1 on
 * overlong (bit-33 set) encoding.
 */
static inline int trust_isa_varint_decode(const unsigned char *buf,
                                          unsigned int avail,
                                          uint32_t *out)
{
    uint32_t v = 0;
    unsigned int shift = 0, i = 0;
    while (i < avail) {
        unsigned char b = buf[i++];
        v |= ((uint32_t)(b & 0x7FU)) << shift;
        if (!(b & 0x80U)) {
            *out = v;
            return (int)i;
        }
        shift += 7;
        if (shift >= 32)
            return -1;
    }
    return 0;
}

/* ========================================================================
 * Kernel-only: VEC/FUSED dispatch prototypes
 * ======================================================================== */

#ifdef __KERNEL__

/*
 * trust_isa_exec_vec - Execute a VEC-family op over N subjects.
 *
 * @op:        VEC_OP_*
 * @subjects:  array of subject IDs (must be non-NULL if count > 0)
 * @count:     number of subject IDs in @subjects
 * @param:     op-specific shared parameter (amount/cap/action/sink-sid)
 * @out:       destination for per-op result (bitmap or aggregate);
 *             must point to at least DIV_ROUND_UP(count, 64) u64s for
 *             bitmap-returning ops, or 1 u64 for aggregates.  May be
 *             NULL only if @out_len == 0.
 * @out_len:   capacity of @out in u64 units.
 *
 * Returns >=0 number of subjects processed successfully, or -errno.
 *
 * Lock discipline: acquires TLB set-locks with spin_lock_irqsave
 * (since decay is a softirq path); no nested locking outside the
 * existing RES_XFER pair-lock order.
 */
int trust_isa_exec_vec(u32 op, const u32 *subjects, u32 count,
                       u64 param, u64 *out, u32 out_len);

/*
 * trust_isa_exec_fused - Execute a FUSED-family op.
 *
 * @op:       FUSED_OP_*
 * @op0..op2: operand slots (u64; caller extracts u32/s32 as needed)
 * @imm:      16-bit immediate from instruction word
 * @out_val:  primary result (may be NULL)
 *
 * Returns 0 on success, -errno on failure.  On failure, partial
 * side-effects already applied are NOT rolled back (consistent with
 * scalar semantics).
 */
int trust_isa_exec_fused(u32 op, u64 op0, u64 op1, u64 op2,
                         u16 imm, u64 *out_val);

/*
 * trust_isa_decode_batch - Parse a varlen batch buffer into a VEC
 * subject array.
 *
 * @buf:        wire buffer pointing at a trust_isa_batch_t header
 * @buf_len:    bytes available at @buf
 * @subjects:   destination array (caller-allocated)
 * @max_count:  capacity of @subjects
 * @op_out:     extracted VEC opcode (may be NULL)
 * @param_out:  extracted shared parameter (may be NULL)
 *
 * Returns number of subjects decoded (may be 0), or -errno on
 * malformed buffer.  Caller invokes trust_isa_exec_vec() next.
 */
int trust_isa_decode_batch(const void *buf, u32 buf_len,
                           u32 *subjects, u32 max_count,
                           u32 *op_out, u64 *param_out);

/* Per-CPU predicate flag register (last ALU result). */
void trust_isa_pred_reset(void);
void trust_isa_pred_set(int64_t result);
int64_t trust_isa_pred_get(void);

#endif /* __KERNEL__ */

/* ========================================================================
 * Userland-reachable encode helper (safe in kernel too).
 *
 * trust_isa_encode_batch - build a wire-format batch into @buf.
 *
 * @buf:        destination
 * @buf_cap:    destination capacity
 * @family:     TRUST_ISA_FAMILY_* (typically VEC)
 * @opcode:     per-family opcode (VEC_OP_*)
 * @subjects:   subject ids
 * @count:      number of subjects (must be >0 and <= TRUST_ISA_BATCH_MAX_COUNT)
 * @param:      shared parameter
 * @delta:      nonzero => delta-code with zigzag; 0 => absolute varints
 *
 * Returns bytes written, or 0 on overflow / bad input.
 * ======================================================================== */

/*
 * NOTE: uses uint32_t/uint64_t throughout because these are aliases
 * for u32/u64 in the kernel via <linux/types.h>, and are the portable
 * userland types in <stdint.h>.  Either spelling compiles identically.
 */
static inline unsigned int trust_isa_encode_batch(unsigned char *buf,
                                                  unsigned int buf_cap,
                                                  uint32_t family,
                                                  uint32_t opcode,
                                                  const uint32_t *subjects,
                                                  uint32_t count,
                                                  uint64_t param,
                                                  int delta)
{
    trust_isa_batch_t h;
    unsigned int off = 0, wrote;
    uint32_t prev = 0;
    uint32_t i;

    if (!buf || !subjects || buf_cap < TRUST_ISA_BATCH_HDR_SIZE)
        return 0;
    if (count == 0 || count > TRUST_ISA_BATCH_MAX_COUNT)
        return 0;
    if (family > 0xFU || opcode > 0xFU)
        return 0;

    h.magic = TRUST_ISA_BATCH_MAGIC;
    h.count = (uint16_t)count;
    h.flags = (delta ? (TRUST_ISA_BATCH_F_DELTA | TRUST_ISA_BATCH_F_ZIGZAG) : 0U)
            | ((family & 0xFU) << TRUST_ISA_BATCH_FAMILY_SHIFT)
            | ((opcode & 0xFU) << TRUST_ISA_BATCH_OPCODE_SHIFT);
    h.param = param;

    /* byte-copy to keep packed layout robust across compilers */
    memcpy(buf, &h, TRUST_ISA_BATCH_HDR_SIZE);
    off = TRUST_ISA_BATCH_HDR_SIZE;

    for (i = 0; i < count; i++) {
        uint32_t v;
        if (delta) {
            int32_t d = (int32_t)(subjects[i] - prev);
            v = trust_isa_zigzag32(d);
        } else {
            v = subjects[i];
        }
        wrote = trust_isa_varint_encode(buf + off, buf_cap - off, v);
        if (!wrote)
            return 0;
        off += wrote;
        prev = subjects[i];
    }

    return off;
}

#endif /* TRUST_ISA_H */
