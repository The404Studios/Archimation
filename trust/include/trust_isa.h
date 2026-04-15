/*
 * trust_isa.h - Trust ISA extensions: VECTOR family, fused pairs, predicate,
 *               variable-length batch encoding, and binary event wire format.
 *
 * This header is SHARED between kernel (trust/kernel) and userspace
 * (trust/lib/libtrust_batch.c, trust/lib/libtrust_events.c). It layers on
 * top of trust_cmd.h (existing 32-bit-instruction command buffer protocol)
 * and adds:
 *
 *   1. VECTOR family (family 6): one instruction operates on N subjects
 *      (DECAY_VEC, ESCALATE_CHECK_VEC, BURN_VEC, ...).
 *
 *   2. Fused opcodes (per existing family): one instruction chains a
 *      common pair of primitives (AUTH_THEN_GATE, CHECK_AND_RECORD, ...).
 *
 *   3. Predicate bit: a 1-bit conditional that gates the instruction on
 *      the previous instruction's status/value, without needing
 *      TRUST_CMD_FLAG_CONDITIONAL on every op.
 *
 *   4. Variable-length batch wire format: a compact, self-describing
 *      container around a varint + delta-encoded operand stream. The
 *      classic trust_cmd_buffer_t is still accepted by the kernel for
 *      backward compat.
 *
 *   5. Binary event stream (trust_event_packed_t): 7-byte packed event
 *      record emitted by the kernel via the new events fd, consumed by
 *      libtrust_events_read.
 *
 * Ownership split:
 *   - Agent 7 (kernel): adds DECODE paths for (1)-(4), adds the events fd
 *     and EMIT path for (5), publishes TRUST_IOCTL_QUERY_CAPS so this
 *     library can probe for feature availability.
 *   - libtrust (this agent): adds ENCODE paths for (1)-(4) and the DECODE
 *     path for (5). Exposes typed C helpers so callers don't hand-build
 *     instruction words.
 *
 * If TRUST_IOCTL_QUERY_CAPS returns a capability mask lacking VEC or
 * fused opcodes, libtrust transparently lowers the batch to a sequence
 * of single-subject trust_cmd_entry_t's and submits via the existing
 * TRUST_IOC_CMD_SUBMIT path. This keeps binary compat for kernels that
 * haven't picked up Agent 7's changes yet.
 */

#ifndef TRUST_ISA_H
#define TRUST_ISA_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

/*
 * NOTE ON trust_cmd.h:
 *
 * We intentionally do NOT include trust_cmd.h from here. That header
 * has two pre-existing issues that surface under userspace -Wall:
 *   1. A block-comment containing the literal sequence that terminates
 *      a comment prematurely, so a large slab of its preamble is
 *      parsed as code.
 *   2. TRUST_OP_SCORE and TRUST_OP_THRESHOLD are defined twice (once
 *      as operand-type tags, once as opcode indices) with different
 *      values.
 *
 * Until those are fixed in the shared header, we re-declare below the
 * minimum subset libtrust needs, matching the kernel's wire format
 * exactly. When trust_cmd.h is corrected kernel-side, this block can
 * be replaced by a single include.
 */

#ifndef TRUST_CMD_H
/* Instruction word field positions and masks */
#define TRUST_CMD_FAMILY_SHIFT  28
#define TRUST_CMD_FAMILY_MASK   0xF0000000U
#define TRUST_CMD_OPCODE_SHIFT  24
#define TRUST_CMD_OPCODE_MASK   0x0F000000U
#define TRUST_CMD_FLAGS_SHIFT   20
#define TRUST_CMD_FLAGS_MASK    0x00F00000U
#define TRUST_CMD_NOPS_SHIFT    16
#define TRUST_CMD_NOPS_MASK     0x000F0000U
#define TRUST_CMD_IMM_MASK      0x0000FFFFU

#define TRUST_CMD_ENCODE(family, opcode, flags, nops, imm)              \
	((((uint32_t)(family) & 0xFU) << TRUST_CMD_FAMILY_SHIFT) |      \
	 (((uint32_t)(opcode) & 0xFU) << TRUST_CMD_OPCODE_SHIFT) |      \
	 (((uint32_t)(flags)  & 0xFU) << TRUST_CMD_FLAGS_SHIFT)  |      \
	 (((uint32_t)(nops)   & 0xFU) << TRUST_CMD_NOPS_SHIFT)   |      \
	 ((uint32_t)(imm) & TRUST_CMD_IMM_MASK))

#define TRUST_CMD_MAGIC         0x54525354U     /* "TRST" */
#define TRUST_CMD_VERSION       1

#define TRUST_CMD_FLAG_CHAIN        0x1
#define TRUST_CMD_FLAG_AUDIT        0x2
#define TRUST_CMD_FLAG_FENCE        0x4
#define TRUST_CMD_FLAG_CONDITIONAL  0x8

/* Operand type tags (the 60-bit value slot gets the tag in its top 4 bits) */
#define TRUST_OP_TAG_SUBJECT    0
#define TRUST_OP_TAG_CAP        1
#define TRUST_OP_TAG_SCORE      2
#define TRUST_OP_TAG_TOKEN      3
#define TRUST_OP_TAG_ACTION     4
#define TRUST_OP_TAG_DOMAIN     5
#define TRUST_OP_TAG_PROOF      6
#define TRUST_OP_TAG_THRESHOLD  7

#define TRUST_OP_TYPE_SHIFT     60
#define TRUST_OP_VAL_MASK       0x0FFFFFFFFFFFFFFFULL
#define TRUST_CMD_OPERAND(tag, value)                                   \
	((((uint64_t)(tag) & 0xFULL) << TRUST_OP_TYPE_SHIFT) |          \
	 ((uint64_t)(value) & TRUST_OP_VAL_MASK))

/* Family IDs (match trust_types.h TRUST_ISA_FAMILY_*) */
#define TRUST_FAMILY_AUTH       0
#define TRUST_FAMILY_TRUST      1
#define TRUST_FAMILY_GATE       2
#define TRUST_FAMILY_RES        3
#define TRUST_FAMILY_LIFE       4
#define TRUST_FAMILY_META       5

/* Opcodes (subset used by libtrust fallback path) */
#define AUTH_OP_VERIFY          3
#define TRUST_OP_DECAY          4
#define TRUST_OP_THRESHOLD      3      /* cmd family 1, opcode 3 */
#define GATE_OP_CHECK           0

/* Max nops per classic command entry */
#define TRUST_CMD_MAX_OPERANDS  15

/* Buffer flags */
#define TRUST_CMD_BUF_ATOMIC    (1U << 0)
#define TRUST_CMD_BUF_ORDERED   (1U << 1)
#define TRUST_CMD_BUF_ASYNC     (1U << 2)

/* Classic buffer header (mirrors trust_cmd.h layout 1:1). */
typedef struct {
	uint32_t magic;
	uint16_t version;
	uint16_t cmd_count;
	uint32_t total_size;
	uint32_t flags;
} trust_cmd_buffer_t;

/* Per-command result (matches trust_cmd.h layout). */
typedef struct {
	int32_t  status;
	uint32_t _padding;
	uint64_t value;
} trust_cmd_result_t;

/* Batch result header (matches trust_cmd.h layout). */
typedef struct {
	uint32_t commands_executed;
	uint32_t commands_succeeded;
	uint32_t commands_failed;
	uint32_t flags;
} trust_cmd_batch_result_t;

/* ioctl submission structure (matches trust_cmd.h layout). */
typedef struct {
	uint64_t cmd_buffer;
	uint64_t result_buffer;
	uint32_t cmd_buf_size;
	uint32_t res_buf_size;
} trust_ioc_cmd_submit_t;

#define TRUST_IOC_CMD_SUBMIT    _IOWR('T', 100, trust_ioc_cmd_submit_t)

#define TRUST_CMD_MAX_BATCH     256
#endif /* !TRUST_CMD_H */

/* ========================================================================
 * Capability probe (TRUST_IOCTL_QUERY_CAPS)
 *
 * Userspace issues this ioctl once at init to learn which ISA extensions
 * the running kernel supports. Missing bits cause libtrust to lower to
 * the backward-compat path.
 * ======================================================================== */

typedef struct {
	uint32_t version;       /* Output: TRUST_ISA_VERSION */
	uint32_t features;      /* Output: TRUST_FEAT_* bitmask */
	uint32_t max_batch_ops; /* Output: kernel-side max ops per batch */
	uint32_t max_vec_count; /* Output: kernel-side max subjects per VEC op */
} trust_ioc_query_caps_t;

#define TRUST_IOC_QUERY_CAPS   _IOR('T', 110, trust_ioc_query_caps_t)

#define TRUST_ISA_VERSION        2      /* Bumped from trust_cmd.h VERSION=1 */

#define TRUST_FEAT_VEC          (1U << 0) /* VECTOR family available */
#define TRUST_FEAT_FUSED        (1U << 1) /* Fused opcodes available */
#define TRUST_FEAT_PREDICATE    (1U << 2) /* Predicate bit respected */
#define TRUST_FEAT_VARLEN       (1U << 3) /* Variable-length encoding */
#define TRUST_FEAT_EVT_BINARY   (1U << 4) /* Binary event stream fd */

/* ========================================================================
 * VECTOR family (Family 6)
 *
 * One instruction word, N subject IDs, one broadcast result per subject.
 * Encoded in variable-length form (see "Batch wire format" below); the
 * traditional fixed trust_cmd_entry_t path cannot represent N>15 ops.
 * ======================================================================== */

#define TRUST_FAMILY_VEC        6

#define VEC_OP_DECAY            0   /* Apply decay tick to N subjects */
#define VEC_OP_ESCALATE_CHECK   1   /* Test escalation eligibility, return bitmap */
#define VEC_OP_BURN             2   /* Burn tokens for N subjects (same action) */
#define VEC_OP_REFRESH_TLB      3   /* Refresh TLB entries for N subjects */
#define VEC_OP_SCORE_SNAPSHOT   4   /* Return scores for N subjects */
#define VEC_OP_CAP_CHECK        5   /* Check same cap across N subjects */
#define VEC_OP_STARVE_CHECK     6   /* Return starvation bitmap */
#define VEC_OP_QUARANTINE_CHECK 7   /* Return quarantined bitmap */

/* ========================================================================
 * Fused opcodes (bit 0x8 of the opcode field, i.e. high opcodes 8..15
 * per family are fused variants). Unused in pre-ISA-v2 kernels so we
 * can safely claim that bit.
 * ======================================================================== */

#define TRUST_OPCODE_FUSED_BIT  0x8

/* AUTH family fused (0x8..) */
#define AUTH_OP_MINT_THEN_BURN    (TRUST_OPCODE_FUSED_BIT | 0x0) /* MINT then BURN in one */
#define AUTH_OP_VERIFY_THEN_GATE  (TRUST_OPCODE_FUSED_BIT | 0x1) /* VERIFY + GATE_CHECK */

/* TRUST family fused (0x8..) */
#define TRUST_OP_CHECK_AND_RECORD (TRUST_OPCODE_FUSED_BIT | 0x0) /* CHECK_CAP, record if true */
#define TRUST_OP_THRESH_ELEVATE   (TRUST_OPCODE_FUSED_BIT | 0x1) /* THRESHOLD, ELEVATE on DENY */

/* RES family fused (0x8..) */
#define RES_OP_BURN_THEN_REGEN    (TRUST_OPCODE_FUSED_BIT | 0x0) /* BURN + conditional REGEN */

/* LIFE family fused (0x8..) */
#define LIFE_OP_DIVIDE_THEN_GATE  (TRUST_OPCODE_FUSED_BIT | 0x0) /* DIVIDE + GATE_DOMAIN_ENTER */

/* ========================================================================
 * Predicate bit
 *
 * We steal the high bit of the flags nibble (0x8, which is
 * TRUST_CMD_FLAG_CONDITIONAL) and reinterpret it for VARLEN batches as a
 * "predicate enabled" bit; when set, a 1-byte predicate tag follows
 * the instruction word in the varlen stream:
 *
 *   predicate tag (u8):
 *     [7]   sense: 0 = execute if predicate TRUE, 1 = execute if FALSE
 *     [6]   source: 0 = prev status (>=0), 1 = prev value nonzero
 *     [5:0] stride: how many instructions back to test (0 = immediately prior)
 *
 * Classic fixed-format trust_cmd_buffer_t callers continue to use
 * TRUST_CMD_FLAG_CONDITIONAL (= always-prev) with the original semantics.
 * ======================================================================== */

#define TRUST_PRED_SENSE_FALSE   0x80
#define TRUST_PRED_SOURCE_VALUE  0x40
#define TRUST_PRED_STRIDE_MASK   0x3F

/* ========================================================================
 * Batch wire format (variable-length, submitted via TRUST_IOC_CMD_SUBMIT
 * when TRUST_CMDBUF_VARLEN is set in the header flags).
 *
 * On-wire layout:
 *
 *   +---------------------+
 *   | trust_cmd_buffer_t  |  magic=TRUST_CMD_MAGIC, version=TRUST_ISA_VERSION
 *   |  flags|=VARLEN      |  cmd_count = number of logical ops
 *   +---------------------+
 *   | varlen op stream    |  see per-op layout below
 *   +---------------------+
 *
 * Each op in the stream is:
 *
 *   uint32_t instruction   (unchanged 32-bit instruction word)
 *   uint8_t  predicate     (present iff TRUST_CMD_FLAG_CONDITIONAL AND VARLEN)
 *   varint   operand0_tagged   (operand: 4-bit type tag + varint value)
 *   varint   operand1_tagged
 *   ...
 *   (count = nops field of instruction)
 *
 * For VEC family, the instruction's `nops` field is reinterpreted as:
 *   nops = (0xF means >15 subjects follow; read u16 subject_count first)
 *
 * After the instruction + predicate, VEC reads:
 *   varint   subject_count         (or u16 if nops==0xF sentinel)
 *   u32      delta_base            (base subject_id, full 32-bit)
 *   for each subject after the first:
 *     varint zigzag(delta)         (signed delta from previous subject_id)
 *
 * This is the core compression:
 *   * varint: values <128 take 1 byte, <16384 take 2 bytes, etc.
 *   * delta: consecutive sorted IDs compress down to one varint per ID
 *            (typically 1 byte for dense PID ranges).
 *   * zigzag: signed deltas stay compact for unsorted batches too.
 *
 * The classic fixed-format (cmd_count * (4 + 8*nops)) still works — the
 * kernel picks format by inspecting trust_cmd_buffer_t.flags & VARLEN.
 * ======================================================================== */

#define TRUST_CMDBUF_VARLEN     (1U << 8)  /* Buffer flag: varlen encoding */
#define TRUST_CMDBUF_DELTA      (1U << 9)  /* Operand[0] stream uses delta+zigzag */

#define TRUST_VEC_NOPS_SENTINEL 0xF        /* In instruction.nops: read u16 count */

/* Operand tagged-varint layout:
 *
 *   First byte:
 *     [7]   continuation bit (as in standard varint)
 *     [6:3] 4-bit type tag (TRUST_OP_SUBJECT=0 .. TRUST_OP_THRESHOLD=7)
 *     [2:0] low 3 bits of value
 *   Subsequent bytes: standard varint (7 data bits + continuation bit).
 *
 * This lets a small subject_id (<8) fit in a single byte including the
 * type tag.
 */

/* ========================================================================
 * Binary event wire format
 *
 * The kernel opens an events fd per client (via TRUST_IOC_EVT_OPEN below)
 * and pushes 8-byte packed records. This is a compact audit stream — for
 * full structured audit use TRUST_IOC_GET_AUDIT which returns the richer
 * trust_audit_entry_t.
 *
 *   +------+------+-------------+-------------+-----------------+
 *   | type |flags |  subject_id |   cost/val  |   delta_ts_ns   |
 *   |  u8  |  u8  |    u16      |    u16      |       u16       |
 *   +------+------+-------------+-------------+-----------------+
 *   = 8 bytes on wire (naturally aligned — #pragma pack(1))
 *
 * Layout notes:
 *   - subject_id is truncated to u16. Full 32-bit IDs are available via
 *     TRUST_IOC_GET_AUDIT if you need them; events stream is sized for
 *     locality, not completeness.
 *   - delta_ts_ns is the nanosecond delta from the previous event in the
 *     stream (not an absolute timestamp). The first event in a read()
 *     returns ts_ns relative to the subscription open time.
 *   - cost is the post-TRC cost_multiplier metabolic cost of the action;
 *     useful for observers without re-computing the TRC state.
 *
 * Userspace API re-expands delta_ts_ns to absolute trust_event_t.ts_ns
 * using a per-fd cursor kept inside the trust_client_t.
 * ======================================================================== */

#define TRUST_EVT_MAGIC         0xE0  /* sanity check byte in flags bit[7:5]==0b111 */

/* Event type codes (low-8-bit subset of TRUST_ACTION_* + synthetic events) */
#define TRUST_EVT_ACTION        0x01  /* action recorded (type in bits[3:0]) */
#define TRUST_EVT_STARVE        0x02
#define TRUST_EVT_CANCER        0x03
#define TRUST_EVT_QUARANTINE    0x04
#define TRUST_EVT_APOPTOSIS     0x05
#define TRUST_EVT_PROOF_BREAK   0x06
#define TRUST_EVT_ESCALATE      0x07
#define TRUST_EVT_DOMAIN_CROSS  0x08

/* Event flags (bit-packed, 8 bits) */
#define TRUST_EVF_RESULT_FAIL   (1U << 0)  /* action returned non-zero */
#define TRUST_EVF_DENIED        (1U << 1)  /* policy denied the action */
#define TRUST_EVF_PROOF_VALID   (1U << 2)  /* proof chain still intact */
#define TRUST_EVF_XY_DIVERGENT  (1U << 3)  /* chromosomal sex != XX */
#define TRUST_EVF_TRC_ELEVATED  (1U << 4)  /* TRC != NORMAL */
#define TRUST_EVF_TS_ROLLOVER   (1U << 5)  /* ts delta saturated; caller should resync */
#define TRUST_EVF_BATCH_BOUND   (1U << 6)  /* event was part of a batch */
#define TRUST_EVF_RESERVED7     (1U << 7)

#pragma pack(push, 1)
typedef struct {
	uint8_t  type;          /* TRUST_EVT_* */
	uint8_t  flags;         /* TRUST_EVF_* */
	uint16_t subject_id;    /* low 16 bits of subject_id */
	uint16_t cost;          /* post-multiplier cost (clamped to u16) */
	uint16_t delta_ts_ns;   /* ns delta from prior event (saturated, see FLAG) */
} trust_event_packed_t;
#pragma pack(pop)

/* Open the events fd for this client */
typedef struct {
	uint32_t flags;       /* reserved, pass 0 */
	int32_t  evt_fd;      /* Output: event stream fd (use read()/poll()) */
} trust_ioc_evt_open_t;

#define TRUST_IOC_EVT_OPEN   _IOWR('T', 111, trust_ioc_evt_open_t)

/* ========================================================================
 * Max sizes (mirrored from kernel; used for bounds checks in the
 * userspace encoder). Kernel is authoritative via QUERY_CAPS.
 * ======================================================================== */

#define TRUST_ISA_MAX_BATCH_OPS  1024
#define TRUST_ISA_MAX_VEC_COUNT  256
#define TRUST_ISA_MAX_BATCH_BUF  (64U * 1024)  /* matches TRUST_CMD_MAX_BUF_SIZE */

/* Varint upper bound: a 64-bit value encodes to at most 10 bytes. */
#define TRUST_VARINT_MAX_BYTES   10

#endif /* TRUST_ISA_H */
