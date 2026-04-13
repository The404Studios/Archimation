/*
 * trust_cmd.h - Trust ISA Command Buffer Protocol
 *
 * Binary encoding for batch command submission to the Root of Authority
 * trust kernel module. This is NOT a virtual machine -- it is a direct
 * dispatch protocol analogous to GPU command buffers or io_uring SQEs.
 * Commands are encoded as 32-bit instruction words with trailing 64-bit
 * operands, packed into a flat buffer with a header. The kernel validates
 * the buffer, iterates commands, and dispatches each through a function
 * pointer table into the existing trust_risc_*/trust_fbc_*/trust_ape_*
 * kernel functions. Zero interpretation overhead.
 *
 * Instruction Word (32-bit):
 *   [31:28] Family   (4 bits) - AUTH=0, TRUST=1, GATE=2, RES=3, LIFE=4, META=5
 *   [27:24] Opcode   (4 bits) - per-family operation
 *   [23:20] Flags    (4 bits) - CHAIN=1, AUDIT=2, FENCE=4, CONDITIONAL=8
 *   [19:16] Operands (4 bits) - 0-15 operand count
 *   [15:0]  Immediate(16 bits)- inline small value
 *
 * Operand (64-bit):
 *   [63:60] Type  (4 bits) - SUBJECT=0, CAP=1, SCORE=2, TOKEN=3,
 *                             ACTION=4, DOMAIN=5, PROOF=6, THRESHOLD=7
 *   [59:0]  Value (60 bits)
 *
 * Shared between kernel and userspace.
 */

#ifndef TRUST_CMD_H
#define TRUST_CMD_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

#include "trust_types.h"

/* ========================================================================
 * Command buffer magic and version
 * ======================================================================== */

#define TRUST_CMD_MAGIC         0x54525354U     /* "TRST" */
#define TRUST_CMD_VERSION       1

/* ========================================================================
 * Instruction word field positions and masks
 * ======================================================================== */

#define TRUST_CMD_FAMILY_SHIFT  28
#define TRUST_CMD_FAMILY_MASK   0xF0000000U
#define TRUST_CMD_OPCODE_SHIFT  24
#define TRUST_CMD_OPCODE_MASK   0x0F000000U
#define TRUST_CMD_FLAGS_SHIFT   20
#define TRUST_CMD_FLAGS_MASK    0x00F00000U
#define TRUST_CMD_NOPS_SHIFT    16
#define TRUST_CMD_NOPS_MASK     0x000F0000U
#define TRUST_CMD_IMM_MASK      0x0000FFFFU

/* ========================================================================
 * Instruction word encode/decode macros
 * ======================================================================== */

/*
 * TRUST_CMD_ENCODE - Build a 32-bit instruction word.
 *
 * @family: ISA family (0-5)
 * @opcode: per-family operation (0-15)
 * @flags:  TRUST_CMD_FLAG_* bitmask (0-15)
 * @nops:   number of 64-bit operands following this word (0-15)
 * @imm:    16-bit inline immediate value
 */
#define TRUST_CMD_ENCODE(family, opcode, flags, nops, imm)              \
	((((uint32_t)(family) & 0xFU) << TRUST_CMD_FAMILY_SHIFT) |     \
	 (((uint32_t)(opcode) & 0xFU) << TRUST_CMD_OPCODE_SHIFT) |     \
	 (((uint32_t)(flags)  & 0xFU) << TRUST_CMD_FLAGS_SHIFT)  |     \
	 (((uint32_t)(nops)   & 0xFU) << TRUST_CMD_NOPS_SHIFT)   |     \
	 ((uint32_t)(imm) & TRUST_CMD_IMM_MASK))

/* Extract fields from an instruction word */
#define TRUST_CMD_FAMILY(word)  \
	(((uint32_t)(word) & TRUST_CMD_FAMILY_MASK) >> TRUST_CMD_FAMILY_SHIFT)
#define TRUST_CMD_OPCODE(word)  \
	(((uint32_t)(word) & TRUST_CMD_OPCODE_MASK) >> TRUST_CMD_OPCODE_SHIFT)
#define TRUST_CMD_FLAGS(word)   \
	(((uint32_t)(word) & TRUST_CMD_FLAGS_MASK) >> TRUST_CMD_FLAGS_SHIFT)
#define TRUST_CMD_NOPS(word)    \
	(((uint32_t)(word) & TRUST_CMD_NOPS_MASK) >> TRUST_CMD_NOPS_SHIFT)
#define TRUST_CMD_IMM(word)     \
	((uint32_t)(word) & TRUST_CMD_IMM_MASK)

/* ========================================================================
 * Instruction flags (4 bits, combinable)
 * ======================================================================== */

#define TRUST_CMD_FLAG_CHAIN        0x1  /* Output of this cmd feeds next */
#define TRUST_CMD_FLAG_AUDIT        0x2  /* Emit audit event for this cmd */
#define TRUST_CMD_FLAG_FENCE        0x4  /* Memory barrier before this cmd */
#define TRUST_CMD_FLAG_CONDITIONAL  0x8  /* Skip if previous cmd failed */

/* ========================================================================
 * Operand type tags (upper 4 bits of 64-bit operand)
 * ======================================================================== */

#define TRUST_OP_SUBJECT    0   /* Subject ID */
#define TRUST_OP_CAP        1   /* Capability bitmask */
#define TRUST_OP_SCORE      2   /* Trust score (signed, in low bits) */
#define TRUST_OP_TOKEN      3   /* Token amount */
#define TRUST_OP_ACTION     4   /* Action type (TRUST_ACTION_*) */
#define TRUST_OP_DOMAIN     5   /* Domain ID (TRUST_DOMAIN_*) */
#define TRUST_OP_PROOF      6   /* Proof chain value (hash) */
#define TRUST_OP_THRESHOLD  7   /* Threshold value */

#define TRUST_OP_TYPE_SHIFT 60
#define TRUST_OP_TYPE_MASK  0xF000000000000000ULL
#define TRUST_OP_VAL_MASK   0x0FFFFFFFFFFFFFFFULL

/*
 * TRUST_CMD_OPERAND - Build a 64-bit typed operand.
 *
 * @type:  TRUST_OP_* tag (0-7)
 * @value: 60-bit payload
 */
#define TRUST_CMD_OPERAND(type, value)                                  \
	((((uint64_t)(type) & 0xFULL) << TRUST_OP_TYPE_SHIFT) |        \
	 ((uint64_t)(value) & TRUST_OP_VAL_MASK))

/* Extract type and value from an operand */
#define TRUST_OP_TYPE(op)   \
	((uint32_t)(((uint64_t)(op) & TRUST_OP_TYPE_MASK) >> TRUST_OP_TYPE_SHIFT))
#define TRUST_OP_VALUE(op)  \
	((uint64_t)(op) & TRUST_OP_VAL_MASK)

/* Convenience: extract operand value as 32-bit (for IDs, action types, etc.) */
#define TRUST_OP_VALUE32(op)  ((uint32_t)TRUST_OP_VALUE(op))

/* ========================================================================
 * ISA Family IDs (matches trust_types.h TRUST_ISA_FAMILY_*)
 * ======================================================================== */

#define TRUST_FAMILY_AUTH   TRUST_ISA_FAMILY_AUTH    /* 0 */
#define TRUST_FAMILY_TRUST  TRUST_ISA_FAMILY_TRUST   /* 1 */
#define TRUST_FAMILY_GATE   TRUST_ISA_FAMILY_GATE    /* 2 */
#define TRUST_FAMILY_RES    TRUST_ISA_FAMILY_RES     /* 3 */
#define TRUST_FAMILY_LIFE   TRUST_ISA_FAMILY_LIFE    /* 4 */
#define TRUST_FAMILY_META   TRUST_ISA_FAMILY_META    /* 5 */

/* ========================================================================
 * AUTH family opcodes (Family 0)
 *
 * Self-consuming proof chain operations.
 * ======================================================================== */

#define AUTH_OP_MINT        0   /* Mint initial proof for subject */
#define AUTH_OP_BURN        1   /* Consume proof, advance chain */
#define AUTH_OP_CONSUME     2   /* Consume proof for specific action */
#define AUTH_OP_VERIFY      3   /* Verify proof chain integrity */
#define AUTH_OP_FENCE       4   /* Invalidate (fence) proof chain */
#define AUTH_OP_NONCE       5   /* Get current chain nonce */
#define AUTH_OP_CHAIN_LEN   6   /* Get proof chain length */
#define AUTH_OP_ROTATE      7   /* Rotate hash algorithm config */

/* ========================================================================
 * TRUST family opcodes (Family 1)
 *
 * Score, capability, and threshold management.
 * RISC fast-path: CHECK, SCORE, RECORD, THRESHOLD, DECAY, TRANSLATE.
 * FBC complex-path: ELEVATE, DEMOTE.
 * ======================================================================== */

#define TRUST_OP_CHECK      0   /* Check subject capability */
#define TRUST_OP_SCORE      1   /* Get subject trust score */
#define TRUST_OP_RECORD     2   /* Record action (apply delta) */
#define TRUST_OP_THRESHOLD  3   /* Check threshold for action */
#define TRUST_OP_DECAY      4   /* Trigger decay tick */
#define TRUST_OP_TRANSLATE  5   /* Translate capability across domains */
#define TRUST_OP_ELEVATE    6   /* Request authority elevation */
#define TRUST_OP_DEMOTE     7   /* Demote authority level */

/* ========================================================================
 * GATE family opcodes (Family 2)
 *
 * Cross-domain DNA Gate / IRNA Translator operations.
 * ======================================================================== */

#define GATE_OP_CHECK       0   /* Check gate permission */
#define GATE_OP_RAISE       1   /* Raise gate threshold */
#define GATE_OP_LOWER       2   /* Lower gate threshold */
#define GATE_OP_HYST        3   /* Set hysteresis window */
#define GATE_OP_TRANSLATE   4   /* Translate capabilities across gate */
#define GATE_OP_DOMAIN_ENTER 5  /* Enter trust domain */
#define GATE_OP_DOMAIN_LEAVE 6  /* Leave trust domain */
#define GATE_OP_BRIDGE      7   /* Bridge two domains */

/* ========================================================================
 * RES family opcodes (Family 3)
 *
 * Token economy / metabolic cost management.
 * ======================================================================== */

#define RES_OP_BALANCE      0   /* Get token balance */
#define RES_OP_BURN         1   /* Burn tokens for action */
#define RES_OP_MINT         2   /* Mint new tokens (admin) */
#define RES_OP_XFER         3   /* Transfer tokens between subjects */
#define RES_OP_COST         4   /* Query cost for action type */
#define RES_OP_REGEN        5   /* Trigger token regeneration */
#define RES_OP_STARVE_CHECK 6   /* Check if subject is token-starved */
#define RES_OP_SET_RATE     7   /* Set regeneration rate */

/* ========================================================================
 * LIFE family opcodes (Family 4)
 *
 * Lifecycle management: mitotic/meiotic operations, immune response.
 * ======================================================================== */

#define LIFE_OP_DIVIDE      0   /* Mitotic division (spawn child) */
#define LIFE_OP_COMBINE     1   /* Meiotic combination */
#define LIFE_OP_RELEASE     2   /* Release meiotic combination */
#define LIFE_OP_APOPTOSIS   3   /* Initiate controlled death */
#define LIFE_OP_IMMUNE_EVAL 4   /* Evaluate immune status */
#define LIFE_OP_QUARANTINE  5   /* Quarantine a subject */
#define LIFE_OP_RELEASE_Q   6   /* Release from quarantine */
#define LIFE_OP_GENERATION  7   /* Query generation depth */

/* ========================================================================
 * META family opcodes (Family 5)
 *
 * System-wide administrative and query operations.
 * ======================================================================== */

#define META_OP_FLUSH       0   /* Flush TLB cache */
#define META_OP_AUDIT       1   /* Emit manual audit entry */
#define META_OP_REPARTITION 2   /* Repartition authority boundaries */
#define META_OP_GET_SUBJECT 3   /* Get full subject state */
#define META_OP_GET_CHROMOSOME 4 /* Get chromosomal authority */
#define META_OP_GET_SEX     5   /* Get XY sex determination */
#define META_OP_IMMUNE_STATUS 6 /* Get immune response status */
#define META_OP_TRC_STATE   7   /* Get TRC state machine state */

/* Maximum opcodes per family */
#define TRUST_CMD_MAX_OPCODES   8

/* ========================================================================
 * Command entry (in-buffer representation)
 *
 * Each command is a 32-bit instruction word followed by 0-15 operands.
 * This struct represents the parsed form used by dispatch handlers.
 * ======================================================================== */

#define TRUST_CMD_MAX_OPERANDS  15

typedef struct {
	uint32_t instruction;                       /* Encoded instruction word */
	uint32_t operand_count;                     /* Decoded from instruction */
	uint64_t operands[TRUST_CMD_MAX_OPERANDS];  /* Typed operands */
} trust_cmd_entry_t;

/* ========================================================================
 * Per-command result
 * ======================================================================== */

typedef struct {
	int32_t  status;    /* 0 = success, negative = errno-style error */
	uint32_t _padding;
	uint64_t value;     /* Command-specific output value */
} trust_cmd_result_t;

/* ========================================================================
 * Command buffer header
 *
 * Submitted by userspace via TRUST_IOC_CMD_SUBMIT.
 * Commands are packed immediately after this header in the buffer.
 * Results are written to a separate userspace result buffer.
 * ======================================================================== */

/* Buffer flags */
#define TRUST_CMD_BUF_ATOMIC    (1U << 0)  /* All-or-nothing: rollback on first failure */
#define TRUST_CMD_BUF_ORDERED   (1U << 1)  /* Strict sequential execution (default) */
#define TRUST_CMD_BUF_ASYNC     (1U << 2)  /* Return immediately, poll for results */

typedef struct {
	uint32_t magic;         /* Must be TRUST_CMD_MAGIC (0x54525354) */
	uint16_t version;       /* Must be TRUST_CMD_VERSION (1) */
	uint16_t cmd_count;     /* Number of commands in buffer */
	uint32_t total_size;    /* Total buffer size in bytes (header + commands) */
	uint32_t flags;         /* TRUST_CMD_BUF_* flags */
	/* Packed commands follow immediately after this header.
	 *
	 * Wire format per command:
	 *   uint32_t instruction;
	 *   uint64_t operands[TRUST_CMD_NOPS(instruction)];
	 *
	 * Total command size = 4 + 8*nops bytes.
	 */
} trust_cmd_buffer_t;

/* ========================================================================
 * Batch result header
 *
 * Written to the userspace result buffer after execution.
 * ======================================================================== */

typedef struct {
	uint32_t commands_executed;  /* Number of commands that ran */
	uint32_t commands_succeeded; /* Number that returned status >= 0 */
	uint32_t commands_failed;    /* Number that returned status < 0 */
	uint32_t flags;              /* Reserved */
	/* trust_cmd_result_t results[cmd_count] follows */
} trust_cmd_batch_result_t;

/* ========================================================================
 * ioctl submission structure
 *
 * Userspace passes this to TRUST_IOC_CMD_SUBMIT.
 * ======================================================================== */

typedef struct {
	uint64_t cmd_buffer;    /* Pointer to trust_cmd_buffer_t (user address) */
	uint64_t result_buffer; /* Pointer to trust_cmd_batch_result_t (user address) */
	uint32_t cmd_buf_size;  /* Size of command buffer in bytes */
	uint32_t res_buf_size;  /* Size of result buffer in bytes */
} trust_ioc_cmd_submit_t;

#define TRUST_IOC_CMD_SUBMIT    _IOWR('T', 100, trust_ioc_cmd_submit_t)

/* ========================================================================
 * Size limits
 * ======================================================================== */

/* Maximum commands in a single batch */
#define TRUST_CMD_MAX_BATCH     256

/* Maximum buffer size (prevents DoS from huge allocations) */
#define TRUST_CMD_MAX_BUF_SIZE  (64U * 1024)  /* 64 KiB */

/* Size of the command buffer header */
#define TRUST_CMD_HEADER_SIZE   sizeof(trust_cmd_buffer_t)

/* Minimum command size: instruction word only, no operands */
#define TRUST_CMD_MIN_SIZE      sizeof(uint32_t)

/* Maximum single command size: instruction + 15 operands */
#define TRUST_CMD_ENTRY_MAX_SIZE \
	(sizeof(uint32_t) + TRUST_CMD_MAX_OPERANDS * sizeof(uint64_t))

/* ========================================================================
 * Helper: compute wire size of a command given its operand count
 * ======================================================================== */

static inline uint32_t trust_cmd_wire_size(uint32_t operand_count)
{
	return (uint32_t)(sizeof(uint32_t) +
			  operand_count * sizeof(uint64_t));
}

/* ========================================================================
 * Helper: compute required result buffer size for N commands
 * ======================================================================== */

static inline uint32_t trust_cmd_result_buf_size(uint16_t cmd_count)
{
	return (uint32_t)(sizeof(trust_cmd_batch_result_t) +
			  cmd_count * sizeof(trust_cmd_result_t));
}

/* ========================================================================
 * Kernel-only: dispatch function prototype
 * ======================================================================== */

#ifdef __KERNEL__

typedef int (*trust_cmd_handler_t)(const trust_cmd_entry_t *cmd,
				   trust_cmd_result_t *result);

/* Implemented in trust_dispatch.c */
int trust_cmd_submit(const trust_ioc_cmd_submit_t __user *submit);

#endif /* __KERNEL__ */

#endif /* TRUST_CMD_H */
