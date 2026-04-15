/*
 * trust_cmd.h - Trust ISA Command Buffer Protocol
 *
 * Binary encoding for batch command submission to the Root of Authority
 * trust kernel module. This is NOT a virtual machine; it is a direct
 * dispatch protocol analogous to GPU command buffers or io_uring SQEs.
 * Commands are encoded as 32-bit instruction words with trailing 64-bit
 * operands, packed into a flat buffer with a header. The kernel validates
 * the buffer, iterates commands, and dispatches each through a function
 * pointer table into the existing trust_risc, trust_fbc and trust_ape
 * kernel functions (note: prose form; no literal slashes inside this
 * comment body so no C-comment terminator can appear). Zero interpretation
 * overhead.
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
 * Shared between kernel and userspace. Use TRUST_OP_TAG_* for the operand
 * type tag namespace and the per-family opcode prefixes (AUTH_OP_*,
 * TRUST_OP_* where the prefix refers to the TRUST family, GATE_OP_*,
 * RES_OP_*, LIFE_OP_*, META_OP_*) for instruction opcodes. Historical
 * unprefixed operand-tag aliases (TRUST_OP_SUBJECT, TRUST_OP_CAP,
 * TRUST_OP_TOKEN, TRUST_OP_ACTION, TRUST_OP_DOMAIN, TRUST_OP_PROOF) are
 * retained for source-level backward compatibility. Unprefixed
 * TRUST_OP_SCORE and TRUST_OP_THRESHOLD name TRUST-family OPCODES
 * (values 1 and 3); the legacy operand-tag spellings TRUST_OP_SCORE=2
 * and TRUST_OP_THRESHOLD=7 (which collided) are intentionally removed.
 * Callers that need those tag values must use TRUST_OP_TAG_SCORE and
 * TRUST_OP_TAG_THRESHOLD.
 *
 * This header must compile clean when included alone AND when included
 * alongside trust_isa.h (in either order). All opcodes / tags are
 * #define-based to stay compatible with the vendored #ifndef TRUST_CMD_H
 * fallback block in trust/include/trust_isa.h.
 */

#ifndef TRUST_CMD_H
#define TRUST_CMD_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/stddef.h>   /* offsetof */
#else
#include <stdint.h>
#include <stddef.h>         /* offsetof */
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
 * Instruction word encode / decode macros
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

/* Flags are single-bit bitmask values, so they live as #defines (not enum
 * constants) to keep `flags |= TRUST_CMD_FLAG_*` natural and to support
 * #ifdef probing. _Static_asserts below lock the wire values. */
#define TRUST_CMD_FLAG_CHAIN        0x1  /* Output of this cmd feeds next */
#define TRUST_CMD_FLAG_AUDIT        0x2  /* Emit audit event for this cmd */
#define TRUST_CMD_FLAG_FENCE        0x4  /* Memory barrier before this cmd */
#define TRUST_CMD_FLAG_CONDITIONAL  0x8  /* Skip if previous cmd failed */

_Static_assert(TRUST_CMD_FLAG_CHAIN       == 0x1, "flag CHAIN wire value");
_Static_assert(TRUST_CMD_FLAG_AUDIT       == 0x2, "flag AUDIT wire value");
_Static_assert(TRUST_CMD_FLAG_FENCE       == 0x4, "flag FENCE wire value");
_Static_assert(TRUST_CMD_FLAG_CONDITIONAL == 0x8, "flag CONDITIONAL wire value");

/* Flag bits are power-of-two and non-overlapping; any pair ANDs to zero. */
_Static_assert((TRUST_CMD_FLAG_CHAIN       & TRUST_CMD_FLAG_AUDIT)       == 0, "flag CHAIN/AUDIT overlap");
_Static_assert((TRUST_CMD_FLAG_CHAIN       & TRUST_CMD_FLAG_FENCE)       == 0, "flag CHAIN/FENCE overlap");
_Static_assert((TRUST_CMD_FLAG_CHAIN       & TRUST_CMD_FLAG_CONDITIONAL) == 0, "flag CHAIN/CONDITIONAL overlap");
_Static_assert((TRUST_CMD_FLAG_AUDIT       & TRUST_CMD_FLAG_FENCE)       == 0, "flag AUDIT/FENCE overlap");
_Static_assert((TRUST_CMD_FLAG_AUDIT       & TRUST_CMD_FLAG_CONDITIONAL) == 0, "flag AUDIT/CONDITIONAL overlap");
_Static_assert((TRUST_CMD_FLAG_FENCE       & TRUST_CMD_FLAG_CONDITIONAL) == 0, "flag FENCE/CONDITIONAL overlap");

/* All flags fit in 4-bit flag nibble */
_Static_assert((TRUST_CMD_FLAG_CHAIN | TRUST_CMD_FLAG_AUDIT |
		TRUST_CMD_FLAG_FENCE | TRUST_CMD_FLAG_CONDITIONAL) <= 0xF,
	       "flags exceed 4-bit encoding width");

/* ========================================================================
 * Operand type tags (upper 4 bits of 64-bit operand)
 *
 * Authoritative names use the TRUST_OP_TAG_* prefix. Historical unprefixed
 * spellings are preserved as aliases EXCEPT for SCORE/THRESHOLD, which
 * collided with TRUST-family opcodes and are intentionally dropped from
 * the tag namespace.
 * ======================================================================== */

/* Operand-tag values (4-bit; fit in the upper nibble of a 64-bit operand).
 * These are #define'd rather than an enum so that trust/include/trust_isa.h's
 * vendored #ifndef TRUST_CMD_H fallback block can safely redefine the same
 * identifiers without triggering enum redeclaration errors when included
 * after this header. */
#define TRUST_OP_TAG_SUBJECT    0   /* Subject ID */
#define TRUST_OP_TAG_CAP        1   /* Capability bitmask */
#define TRUST_OP_TAG_SCORE      2   /* Trust score (signed, in low bits) */
#define TRUST_OP_TAG_TOKEN      3   /* Token amount */
#define TRUST_OP_TAG_ACTION     4   /* Action type (TRUST_ACTION_*) */
#define TRUST_OP_TAG_DOMAIN     5   /* Domain ID (TRUST_DOMAIN_*) */
#define TRUST_OP_TAG_PROOF      6   /* Proof chain value (hash) */
#define TRUST_OP_TAG_THRESHOLD  7   /* Threshold value */

/* Legacy operand-tag aliases. NONE of these must collide with a
 * TRUST_* family opcode name. SCORE and THRESHOLD were the two
 * historical collisions; those unprefixed spellings now refer to
 * TRUST-family opcodes below (values 1 and 3) and NOT to tag values
 * (which are 2 and 7). Callers that need the tag must use the
 * TRUST_OP_TAG_* spellings. */
#define TRUST_OP_SUBJECT    TRUST_OP_TAG_SUBJECT
#define TRUST_OP_CAP        TRUST_OP_TAG_CAP
#define TRUST_OP_TOKEN      TRUST_OP_TAG_TOKEN
#define TRUST_OP_ACTION     TRUST_OP_TAG_ACTION
#define TRUST_OP_DOMAIN     TRUST_OP_TAG_DOMAIN
#define TRUST_OP_PROOF      TRUST_OP_TAG_PROOF

#define TRUST_OP_TYPE_SHIFT 60
#define TRUST_OP_TYPE_MASK  0xF000000000000000ULL
#define TRUST_OP_VAL_MASK   0x0FFFFFFFFFFFFFFFULL

/*
 * TRUST_CMD_OPERAND - Build a 64-bit typed operand.
 *
 * @type:  TRUST_OP_TAG_* (0-7)
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

/* Operand-tag exhaustiveness and encoding-width checks. */
_Static_assert(TRUST_OP_TAG_SUBJECT   == 0, "tag SUBJECT wire value");
_Static_assert(TRUST_OP_TAG_CAP       == 1, "tag CAP wire value");
_Static_assert(TRUST_OP_TAG_SCORE     == 2, "tag SCORE wire value");
_Static_assert(TRUST_OP_TAG_TOKEN     == 3, "tag TOKEN wire value");
_Static_assert(TRUST_OP_TAG_ACTION    == 4, "tag ACTION wire value");
_Static_assert(TRUST_OP_TAG_DOMAIN    == 5, "tag DOMAIN wire value");
_Static_assert(TRUST_OP_TAG_PROOF     == 6, "tag PROOF wire value");
_Static_assert(TRUST_OP_TAG_THRESHOLD == 7, "tag THRESHOLD wire value");
_Static_assert(TRUST_OP_TAG_THRESHOLD <= 0xF, "operand tag exceeds 4-bit width");

/* Tag distinctness matrix: every pair of tags has a distinct value. */
_Static_assert(TRUST_OP_TAG_SUBJECT != TRUST_OP_TAG_CAP,       "tag collide SUBJECT/CAP");
_Static_assert(TRUST_OP_TAG_SUBJECT != TRUST_OP_TAG_SCORE,     "tag collide SUBJECT/SCORE");
_Static_assert(TRUST_OP_TAG_SUBJECT != TRUST_OP_TAG_TOKEN,     "tag collide SUBJECT/TOKEN");
_Static_assert(TRUST_OP_TAG_SUBJECT != TRUST_OP_TAG_ACTION,    "tag collide SUBJECT/ACTION");
_Static_assert(TRUST_OP_TAG_SUBJECT != TRUST_OP_TAG_DOMAIN,    "tag collide SUBJECT/DOMAIN");
_Static_assert(TRUST_OP_TAG_SUBJECT != TRUST_OP_TAG_PROOF,     "tag collide SUBJECT/PROOF");
_Static_assert(TRUST_OP_TAG_SUBJECT != TRUST_OP_TAG_THRESHOLD, "tag collide SUBJECT/THRESHOLD");
_Static_assert(TRUST_OP_TAG_CAP     != TRUST_OP_TAG_SCORE,     "tag collide CAP/SCORE");
_Static_assert(TRUST_OP_TAG_CAP     != TRUST_OP_TAG_TOKEN,     "tag collide CAP/TOKEN");
_Static_assert(TRUST_OP_TAG_CAP     != TRUST_OP_TAG_ACTION,    "tag collide CAP/ACTION");
_Static_assert(TRUST_OP_TAG_CAP     != TRUST_OP_TAG_DOMAIN,    "tag collide CAP/DOMAIN");
_Static_assert(TRUST_OP_TAG_CAP     != TRUST_OP_TAG_PROOF,     "tag collide CAP/PROOF");
_Static_assert(TRUST_OP_TAG_CAP     != TRUST_OP_TAG_THRESHOLD, "tag collide CAP/THRESHOLD");
_Static_assert(TRUST_OP_TAG_SCORE   != TRUST_OP_TAG_TOKEN,     "tag collide SCORE/TOKEN");
_Static_assert(TRUST_OP_TAG_SCORE   != TRUST_OP_TAG_ACTION,    "tag collide SCORE/ACTION");
_Static_assert(TRUST_OP_TAG_SCORE   != TRUST_OP_TAG_DOMAIN,    "tag collide SCORE/DOMAIN");
_Static_assert(TRUST_OP_TAG_SCORE   != TRUST_OP_TAG_PROOF,     "tag collide SCORE/PROOF");
_Static_assert(TRUST_OP_TAG_SCORE   != TRUST_OP_TAG_THRESHOLD, "tag collide SCORE/THRESHOLD");
_Static_assert(TRUST_OP_TAG_TOKEN   != TRUST_OP_TAG_ACTION,    "tag collide TOKEN/ACTION");
_Static_assert(TRUST_OP_TAG_TOKEN   != TRUST_OP_TAG_DOMAIN,    "tag collide TOKEN/DOMAIN");
_Static_assert(TRUST_OP_TAG_TOKEN   != TRUST_OP_TAG_PROOF,     "tag collide TOKEN/PROOF");
_Static_assert(TRUST_OP_TAG_TOKEN   != TRUST_OP_TAG_THRESHOLD, "tag collide TOKEN/THRESHOLD");
_Static_assert(TRUST_OP_TAG_ACTION  != TRUST_OP_TAG_DOMAIN,    "tag collide ACTION/DOMAIN");
_Static_assert(TRUST_OP_TAG_ACTION  != TRUST_OP_TAG_PROOF,     "tag collide ACTION/PROOF");
_Static_assert(TRUST_OP_TAG_ACTION  != TRUST_OP_TAG_THRESHOLD, "tag collide ACTION/THRESHOLD");
_Static_assert(TRUST_OP_TAG_DOMAIN  != TRUST_OP_TAG_PROOF,     "tag collide DOMAIN/PROOF");
_Static_assert(TRUST_OP_TAG_DOMAIN  != TRUST_OP_TAG_THRESHOLD, "tag collide DOMAIN/THRESHOLD");
_Static_assert(TRUST_OP_TAG_PROOF   != TRUST_OP_TAG_THRESHOLD, "tag collide PROOF/THRESHOLD");

/* ========================================================================
 * ISA Family IDs (matches trust_types.h TRUST_ISA_FAMILY_*)
 *
 * Authoritative legacy family 0..5. Families 6 (VEC) and 7 (FUSED) are
 * extended families defined by the kernel's trust_isa.h / the userspace
 * trust_isa.h; they are NOT redeclared here, but their slot (6-bit
 * family field width = 0..15) is reserved for them.
 * ======================================================================== */

/* Each family alias is guarded so that if a caller accidentally included
 * trust/include/trust_isa.h (which also defines TRUST_FAMILY_*) before us,
 * we skip re-defining it. Values are identical in both headers and are
 * locked by the _Static_asserts below regardless of source. */
#ifndef TRUST_FAMILY_AUTH
#define TRUST_FAMILY_AUTH   TRUST_ISA_FAMILY_AUTH    /* 0 */
#endif
#ifndef TRUST_FAMILY_TRUST
#define TRUST_FAMILY_TRUST  TRUST_ISA_FAMILY_TRUST   /* 1 */
#endif
#ifndef TRUST_FAMILY_GATE
#define TRUST_FAMILY_GATE   TRUST_ISA_FAMILY_GATE    /* 2 */
#endif
#ifndef TRUST_FAMILY_RES
#define TRUST_FAMILY_RES    TRUST_ISA_FAMILY_RES     /* 3 */
#endif
#ifndef TRUST_FAMILY_LIFE
#define TRUST_FAMILY_LIFE   TRUST_ISA_FAMILY_LIFE    /* 4 */
#endif
#ifndef TRUST_FAMILY_META
#define TRUST_FAMILY_META   TRUST_ISA_FAMILY_META    /* 5 */
#endif

_Static_assert(TRUST_FAMILY_AUTH  == 0, "family AUTH wire value");
_Static_assert(TRUST_FAMILY_TRUST == 1, "family TRUST wire value");
_Static_assert(TRUST_FAMILY_GATE  == 2, "family GATE wire value");
_Static_assert(TRUST_FAMILY_RES   == 3, "family RES wire value");
_Static_assert(TRUST_FAMILY_LIFE  == 4, "family LIFE wire value");
_Static_assert(TRUST_FAMILY_META  == 5, "family META wire value");

/* Family distinctness matrix: every pair has a distinct value.
 * (Pairwise for 6 legacy families = 15 asserts.) */
_Static_assert(TRUST_FAMILY_AUTH  != TRUST_FAMILY_TRUST, "family collide AUTH/TRUST");
_Static_assert(TRUST_FAMILY_AUTH  != TRUST_FAMILY_GATE,  "family collide AUTH/GATE");
_Static_assert(TRUST_FAMILY_AUTH  != TRUST_FAMILY_RES,   "family collide AUTH/RES");
_Static_assert(TRUST_FAMILY_AUTH  != TRUST_FAMILY_LIFE,  "family collide AUTH/LIFE");
_Static_assert(TRUST_FAMILY_AUTH  != TRUST_FAMILY_META,  "family collide AUTH/META");
_Static_assert(TRUST_FAMILY_TRUST != TRUST_FAMILY_GATE,  "family collide TRUST/GATE");
_Static_assert(TRUST_FAMILY_TRUST != TRUST_FAMILY_RES,   "family collide TRUST/RES");
_Static_assert(TRUST_FAMILY_TRUST != TRUST_FAMILY_LIFE,  "family collide TRUST/LIFE");
_Static_assert(TRUST_FAMILY_TRUST != TRUST_FAMILY_META,  "family collide TRUST/META");
_Static_assert(TRUST_FAMILY_GATE  != TRUST_FAMILY_RES,   "family collide GATE/RES");
_Static_assert(TRUST_FAMILY_GATE  != TRUST_FAMILY_LIFE,  "family collide GATE/LIFE");
_Static_assert(TRUST_FAMILY_GATE  != TRUST_FAMILY_META,  "family collide GATE/META");
_Static_assert(TRUST_FAMILY_RES   != TRUST_FAMILY_LIFE,  "family collide RES/LIFE");
_Static_assert(TRUST_FAMILY_RES   != TRUST_FAMILY_META,  "family collide RES/META");
_Static_assert(TRUST_FAMILY_LIFE  != TRUST_FAMILY_META,  "family collide LIFE/META");

/* Family encoding is 4-bit (0..15). All defined families fit. */
_Static_assert(TRUST_FAMILY_META <= 0xF, "family META exceeds 4-bit width");

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

/* AUTH family distinctness matrix (8 values, 28 pairs). */
_Static_assert(AUTH_OP_MINT      != AUTH_OP_BURN,      "AUTH collide MINT/BURN");
_Static_assert(AUTH_OP_MINT      != AUTH_OP_CONSUME,   "AUTH collide MINT/CONSUME");
_Static_assert(AUTH_OP_MINT      != AUTH_OP_VERIFY,    "AUTH collide MINT/VERIFY");
_Static_assert(AUTH_OP_MINT      != AUTH_OP_FENCE,     "AUTH collide MINT/FENCE");
_Static_assert(AUTH_OP_MINT      != AUTH_OP_NONCE,     "AUTH collide MINT/NONCE");
_Static_assert(AUTH_OP_MINT      != AUTH_OP_CHAIN_LEN, "AUTH collide MINT/CHAIN_LEN");
_Static_assert(AUTH_OP_MINT      != AUTH_OP_ROTATE,    "AUTH collide MINT/ROTATE");
_Static_assert(AUTH_OP_BURN      != AUTH_OP_CONSUME,   "AUTH collide BURN/CONSUME");
_Static_assert(AUTH_OP_BURN      != AUTH_OP_VERIFY,    "AUTH collide BURN/VERIFY");
_Static_assert(AUTH_OP_BURN      != AUTH_OP_FENCE,     "AUTH collide BURN/FENCE");
_Static_assert(AUTH_OP_BURN      != AUTH_OP_NONCE,     "AUTH collide BURN/NONCE");
_Static_assert(AUTH_OP_BURN      != AUTH_OP_CHAIN_LEN, "AUTH collide BURN/CHAIN_LEN");
_Static_assert(AUTH_OP_BURN      != AUTH_OP_ROTATE,    "AUTH collide BURN/ROTATE");
_Static_assert(AUTH_OP_CONSUME   != AUTH_OP_VERIFY,    "AUTH collide CONSUME/VERIFY");
_Static_assert(AUTH_OP_CONSUME   != AUTH_OP_FENCE,     "AUTH collide CONSUME/FENCE");
_Static_assert(AUTH_OP_CONSUME   != AUTH_OP_NONCE,     "AUTH collide CONSUME/NONCE");
_Static_assert(AUTH_OP_CONSUME   != AUTH_OP_CHAIN_LEN, "AUTH collide CONSUME/CHAIN_LEN");
_Static_assert(AUTH_OP_CONSUME   != AUTH_OP_ROTATE,    "AUTH collide CONSUME/ROTATE");
_Static_assert(AUTH_OP_VERIFY    != AUTH_OP_FENCE,     "AUTH collide VERIFY/FENCE");
_Static_assert(AUTH_OP_VERIFY    != AUTH_OP_NONCE,     "AUTH collide VERIFY/NONCE");
_Static_assert(AUTH_OP_VERIFY    != AUTH_OP_CHAIN_LEN, "AUTH collide VERIFY/CHAIN_LEN");
_Static_assert(AUTH_OP_VERIFY    != AUTH_OP_ROTATE,    "AUTH collide VERIFY/ROTATE");
_Static_assert(AUTH_OP_FENCE     != AUTH_OP_NONCE,     "AUTH collide FENCE/NONCE");
_Static_assert(AUTH_OP_FENCE     != AUTH_OP_CHAIN_LEN, "AUTH collide FENCE/CHAIN_LEN");
_Static_assert(AUTH_OP_FENCE     != AUTH_OP_ROTATE,    "AUTH collide FENCE/ROTATE");
_Static_assert(AUTH_OP_NONCE     != AUTH_OP_CHAIN_LEN, "AUTH collide NONCE/CHAIN_LEN");
_Static_assert(AUTH_OP_NONCE     != AUTH_OP_ROTATE,    "AUTH collide NONCE/ROTATE");
_Static_assert(AUTH_OP_CHAIN_LEN != AUTH_OP_ROTATE,    "AUTH collide CHAIN_LEN/ROTATE");
_Static_assert(AUTH_OP_ROTATE    <= 0xF,               "AUTH opcode exceeds 4-bit width");

/* ========================================================================
 * TRUST family opcodes (Family 1)
 *
 * Score, capability, and threshold management.
 * RISC fast-path: CHECK, SCORE, RECORD, THRESHOLD, DECAY, TRANSLATE.
 * FBC complex-path: ELEVATE, DEMOTE.
 *
 * NOTE: These share the TRUST_OP_* prefix with the (now deprecated)
 * operand-tag aliases for SCORE/THRESHOLD; the opcode meaning WINS
 * because the kernel's trust_dispatch.c function-pointer table is keyed
 * by these exact values (CHECK=0, SCORE=1, RECORD=2, THRESHOLD=3,
 * DECAY=4, TRANSLATE=5, ELEVATE=6, DEMOTE=7). Callers needing the
 * operand-tag equivalents must use TRUST_OP_TAG_SCORE / TRUST_OP_TAG_THRESHOLD.
 * ======================================================================== */

#define TRUST_OP_CHECK      0   /* Check subject capability */
#define TRUST_OP_SCORE      1   /* Get subject trust score */
#define TRUST_OP_RECORD     2   /* Record action (apply delta) */
#define TRUST_OP_THRESHOLD  3   /* Check threshold for action */
#define TRUST_OP_DECAY      4   /* Trigger decay tick */
#define TRUST_OP_TRANSLATE  5   /* Translate capability across domains */
#define TRUST_OP_ELEVATE    6   /* Request authority elevation */
#define TRUST_OP_DEMOTE     7   /* Demote authority level */

_Static_assert(TRUST_OP_CHECK     != TRUST_OP_SCORE,     "TRUST collide CHECK/SCORE");
_Static_assert(TRUST_OP_CHECK     != TRUST_OP_RECORD,    "TRUST collide CHECK/RECORD");
_Static_assert(TRUST_OP_CHECK     != TRUST_OP_THRESHOLD, "TRUST collide CHECK/THRESHOLD");
_Static_assert(TRUST_OP_CHECK     != TRUST_OP_DECAY,     "TRUST collide CHECK/DECAY");
_Static_assert(TRUST_OP_CHECK     != TRUST_OP_TRANSLATE, "TRUST collide CHECK/TRANSLATE");
_Static_assert(TRUST_OP_CHECK     != TRUST_OP_ELEVATE,   "TRUST collide CHECK/ELEVATE");
_Static_assert(TRUST_OP_CHECK     != TRUST_OP_DEMOTE,    "TRUST collide CHECK/DEMOTE");
_Static_assert(TRUST_OP_SCORE     != TRUST_OP_RECORD,    "TRUST collide SCORE/RECORD");
_Static_assert(TRUST_OP_SCORE     != TRUST_OP_THRESHOLD, "TRUST collide SCORE/THRESHOLD");
_Static_assert(TRUST_OP_SCORE     != TRUST_OP_DECAY,     "TRUST collide SCORE/DECAY");
_Static_assert(TRUST_OP_SCORE     != TRUST_OP_TRANSLATE, "TRUST collide SCORE/TRANSLATE");
_Static_assert(TRUST_OP_SCORE     != TRUST_OP_ELEVATE,   "TRUST collide SCORE/ELEVATE");
_Static_assert(TRUST_OP_SCORE     != TRUST_OP_DEMOTE,    "TRUST collide SCORE/DEMOTE");
_Static_assert(TRUST_OP_RECORD    != TRUST_OP_THRESHOLD, "TRUST collide RECORD/THRESHOLD");
_Static_assert(TRUST_OP_RECORD    != TRUST_OP_DECAY,     "TRUST collide RECORD/DECAY");
_Static_assert(TRUST_OP_RECORD    != TRUST_OP_TRANSLATE, "TRUST collide RECORD/TRANSLATE");
_Static_assert(TRUST_OP_RECORD    != TRUST_OP_ELEVATE,   "TRUST collide RECORD/ELEVATE");
_Static_assert(TRUST_OP_RECORD    != TRUST_OP_DEMOTE,    "TRUST collide RECORD/DEMOTE");
_Static_assert(TRUST_OP_THRESHOLD != TRUST_OP_DECAY,     "TRUST collide THRESHOLD/DECAY");
_Static_assert(TRUST_OP_THRESHOLD != TRUST_OP_TRANSLATE, "TRUST collide THRESHOLD/TRANSLATE");
_Static_assert(TRUST_OP_THRESHOLD != TRUST_OP_ELEVATE,   "TRUST collide THRESHOLD/ELEVATE");
_Static_assert(TRUST_OP_THRESHOLD != TRUST_OP_DEMOTE,    "TRUST collide THRESHOLD/DEMOTE");
_Static_assert(TRUST_OP_DECAY     != TRUST_OP_TRANSLATE, "TRUST collide DECAY/TRANSLATE");
_Static_assert(TRUST_OP_DECAY     != TRUST_OP_ELEVATE,   "TRUST collide DECAY/ELEVATE");
_Static_assert(TRUST_OP_DECAY     != TRUST_OP_DEMOTE,    "TRUST collide DECAY/DEMOTE");
_Static_assert(TRUST_OP_TRANSLATE != TRUST_OP_ELEVATE,   "TRUST collide TRANSLATE/ELEVATE");
_Static_assert(TRUST_OP_TRANSLATE != TRUST_OP_DEMOTE,    "TRUST collide TRANSLATE/DEMOTE");
_Static_assert(TRUST_OP_ELEVATE   != TRUST_OP_DEMOTE,    "TRUST collide ELEVATE/DEMOTE");
_Static_assert(TRUST_OP_DEMOTE    <= 0xF,                "TRUST opcode exceeds 4-bit width");

/* Lock the exact wire values the kernel dispatcher expects. */
_Static_assert(TRUST_OP_CHECK     == 0, "TRUST_OP_CHECK wire value");
_Static_assert(TRUST_OP_SCORE     == 1, "TRUST_OP_SCORE wire value");
_Static_assert(TRUST_OP_RECORD    == 2, "TRUST_OP_RECORD wire value");
_Static_assert(TRUST_OP_THRESHOLD == 3, "TRUST_OP_THRESHOLD wire value");
_Static_assert(TRUST_OP_DECAY     == 4, "TRUST_OP_DECAY wire value");
_Static_assert(TRUST_OP_TRANSLATE == 5, "TRUST_OP_TRANSLATE wire value");
_Static_assert(TRUST_OP_ELEVATE   == 6, "TRUST_OP_ELEVATE wire value");
_Static_assert(TRUST_OP_DEMOTE    == 7, "TRUST_OP_DEMOTE wire value");

/* ========================================================================
 * GATE family opcodes (Family 2)
 *
 * Cross-domain DNA Gate / IRNA Translator operations.
 * ======================================================================== */

#define GATE_OP_CHECK        0  /* Check gate permission */
#define GATE_OP_RAISE        1  /* Raise gate threshold */
#define GATE_OP_LOWER        2  /* Lower gate threshold */
#define GATE_OP_HYST         3  /* Set hysteresis window */
#define GATE_OP_TRANSLATE    4  /* Translate capabilities across gate */
#define GATE_OP_DOMAIN_ENTER 5  /* Enter trust domain */
#define GATE_OP_DOMAIN_LEAVE 6  /* Leave trust domain */
#define GATE_OP_BRIDGE       7  /* Bridge two domains */

_Static_assert(GATE_OP_CHECK        != GATE_OP_RAISE,        "GATE collide CHECK/RAISE");
_Static_assert(GATE_OP_CHECK        != GATE_OP_LOWER,        "GATE collide CHECK/LOWER");
_Static_assert(GATE_OP_CHECK        != GATE_OP_HYST,         "GATE collide CHECK/HYST");
_Static_assert(GATE_OP_CHECK        != GATE_OP_TRANSLATE,    "GATE collide CHECK/TRANSLATE");
_Static_assert(GATE_OP_CHECK        != GATE_OP_DOMAIN_ENTER, "GATE collide CHECK/DOMAIN_ENTER");
_Static_assert(GATE_OP_CHECK        != GATE_OP_DOMAIN_LEAVE, "GATE collide CHECK/DOMAIN_LEAVE");
_Static_assert(GATE_OP_CHECK        != GATE_OP_BRIDGE,       "GATE collide CHECK/BRIDGE");
_Static_assert(GATE_OP_RAISE        != GATE_OP_LOWER,        "GATE collide RAISE/LOWER");
_Static_assert(GATE_OP_RAISE        != GATE_OP_HYST,         "GATE collide RAISE/HYST");
_Static_assert(GATE_OP_RAISE        != GATE_OP_TRANSLATE,    "GATE collide RAISE/TRANSLATE");
_Static_assert(GATE_OP_RAISE        != GATE_OP_DOMAIN_ENTER, "GATE collide RAISE/DOMAIN_ENTER");
_Static_assert(GATE_OP_RAISE        != GATE_OP_DOMAIN_LEAVE, "GATE collide RAISE/DOMAIN_LEAVE");
_Static_assert(GATE_OP_RAISE        != GATE_OP_BRIDGE,       "GATE collide RAISE/BRIDGE");
_Static_assert(GATE_OP_LOWER        != GATE_OP_HYST,         "GATE collide LOWER/HYST");
_Static_assert(GATE_OP_LOWER        != GATE_OP_TRANSLATE,    "GATE collide LOWER/TRANSLATE");
_Static_assert(GATE_OP_LOWER        != GATE_OP_DOMAIN_ENTER, "GATE collide LOWER/DOMAIN_ENTER");
_Static_assert(GATE_OP_LOWER        != GATE_OP_DOMAIN_LEAVE, "GATE collide LOWER/DOMAIN_LEAVE");
_Static_assert(GATE_OP_LOWER        != GATE_OP_BRIDGE,       "GATE collide LOWER/BRIDGE");
_Static_assert(GATE_OP_HYST         != GATE_OP_TRANSLATE,    "GATE collide HYST/TRANSLATE");
_Static_assert(GATE_OP_HYST         != GATE_OP_DOMAIN_ENTER, "GATE collide HYST/DOMAIN_ENTER");
_Static_assert(GATE_OP_HYST         != GATE_OP_DOMAIN_LEAVE, "GATE collide HYST/DOMAIN_LEAVE");
_Static_assert(GATE_OP_HYST         != GATE_OP_BRIDGE,       "GATE collide HYST/BRIDGE");
_Static_assert(GATE_OP_TRANSLATE    != GATE_OP_DOMAIN_ENTER, "GATE collide TRANSLATE/DOMAIN_ENTER");
_Static_assert(GATE_OP_TRANSLATE    != GATE_OP_DOMAIN_LEAVE, "GATE collide TRANSLATE/DOMAIN_LEAVE");
_Static_assert(GATE_OP_TRANSLATE    != GATE_OP_BRIDGE,       "GATE collide TRANSLATE/BRIDGE");
_Static_assert(GATE_OP_DOMAIN_ENTER != GATE_OP_DOMAIN_LEAVE, "GATE collide DOMAIN_ENTER/DOMAIN_LEAVE");
_Static_assert(GATE_OP_DOMAIN_ENTER != GATE_OP_BRIDGE,       "GATE collide DOMAIN_ENTER/BRIDGE");
_Static_assert(GATE_OP_DOMAIN_LEAVE != GATE_OP_BRIDGE,       "GATE collide DOMAIN_LEAVE/BRIDGE");
_Static_assert(GATE_OP_BRIDGE       <= 0xF,                  "GATE opcode exceeds 4-bit width");

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

_Static_assert(RES_OP_BALANCE      != RES_OP_BURN,         "RES collide BALANCE/BURN");
_Static_assert(RES_OP_BALANCE      != RES_OP_MINT,         "RES collide BALANCE/MINT");
_Static_assert(RES_OP_BALANCE      != RES_OP_XFER,         "RES collide BALANCE/XFER");
_Static_assert(RES_OP_BALANCE      != RES_OP_COST,         "RES collide BALANCE/COST");
_Static_assert(RES_OP_BALANCE      != RES_OP_REGEN,        "RES collide BALANCE/REGEN");
_Static_assert(RES_OP_BALANCE      != RES_OP_STARVE_CHECK, "RES collide BALANCE/STARVE_CHECK");
_Static_assert(RES_OP_BALANCE      != RES_OP_SET_RATE,     "RES collide BALANCE/SET_RATE");
_Static_assert(RES_OP_BURN         != RES_OP_MINT,         "RES collide BURN/MINT");
_Static_assert(RES_OP_BURN         != RES_OP_XFER,         "RES collide BURN/XFER");
_Static_assert(RES_OP_BURN         != RES_OP_COST,         "RES collide BURN/COST");
_Static_assert(RES_OP_BURN         != RES_OP_REGEN,        "RES collide BURN/REGEN");
_Static_assert(RES_OP_BURN         != RES_OP_STARVE_CHECK, "RES collide BURN/STARVE_CHECK");
_Static_assert(RES_OP_BURN         != RES_OP_SET_RATE,     "RES collide BURN/SET_RATE");
_Static_assert(RES_OP_MINT         != RES_OP_XFER,         "RES collide MINT/XFER");
_Static_assert(RES_OP_MINT         != RES_OP_COST,         "RES collide MINT/COST");
_Static_assert(RES_OP_MINT         != RES_OP_REGEN,        "RES collide MINT/REGEN");
_Static_assert(RES_OP_MINT         != RES_OP_STARVE_CHECK, "RES collide MINT/STARVE_CHECK");
_Static_assert(RES_OP_MINT         != RES_OP_SET_RATE,     "RES collide MINT/SET_RATE");
_Static_assert(RES_OP_XFER         != RES_OP_COST,         "RES collide XFER/COST");
_Static_assert(RES_OP_XFER         != RES_OP_REGEN,        "RES collide XFER/REGEN");
_Static_assert(RES_OP_XFER         != RES_OP_STARVE_CHECK, "RES collide XFER/STARVE_CHECK");
_Static_assert(RES_OP_XFER         != RES_OP_SET_RATE,     "RES collide XFER/SET_RATE");
_Static_assert(RES_OP_COST         != RES_OP_REGEN,        "RES collide COST/REGEN");
_Static_assert(RES_OP_COST         != RES_OP_STARVE_CHECK, "RES collide COST/STARVE_CHECK");
_Static_assert(RES_OP_COST         != RES_OP_SET_RATE,     "RES collide COST/SET_RATE");
_Static_assert(RES_OP_REGEN        != RES_OP_STARVE_CHECK, "RES collide REGEN/STARVE_CHECK");
_Static_assert(RES_OP_REGEN        != RES_OP_SET_RATE,     "RES collide REGEN/SET_RATE");
_Static_assert(RES_OP_STARVE_CHECK != RES_OP_SET_RATE,     "RES collide STARVE_CHECK/SET_RATE");
_Static_assert(RES_OP_SET_RATE     <= 0xF,                 "RES opcode exceeds 4-bit width");

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

_Static_assert(LIFE_OP_DIVIDE      != LIFE_OP_COMBINE,     "LIFE collide DIVIDE/COMBINE");
_Static_assert(LIFE_OP_DIVIDE      != LIFE_OP_RELEASE,     "LIFE collide DIVIDE/RELEASE");
_Static_assert(LIFE_OP_DIVIDE      != LIFE_OP_APOPTOSIS,   "LIFE collide DIVIDE/APOPTOSIS");
_Static_assert(LIFE_OP_DIVIDE      != LIFE_OP_IMMUNE_EVAL, "LIFE collide DIVIDE/IMMUNE_EVAL");
_Static_assert(LIFE_OP_DIVIDE      != LIFE_OP_QUARANTINE,  "LIFE collide DIVIDE/QUARANTINE");
_Static_assert(LIFE_OP_DIVIDE      != LIFE_OP_RELEASE_Q,   "LIFE collide DIVIDE/RELEASE_Q");
_Static_assert(LIFE_OP_DIVIDE      != LIFE_OP_GENERATION,  "LIFE collide DIVIDE/GENERATION");
_Static_assert(LIFE_OP_COMBINE     != LIFE_OP_RELEASE,     "LIFE collide COMBINE/RELEASE");
_Static_assert(LIFE_OP_COMBINE     != LIFE_OP_APOPTOSIS,   "LIFE collide COMBINE/APOPTOSIS");
_Static_assert(LIFE_OP_COMBINE     != LIFE_OP_IMMUNE_EVAL, "LIFE collide COMBINE/IMMUNE_EVAL");
_Static_assert(LIFE_OP_COMBINE     != LIFE_OP_QUARANTINE,  "LIFE collide COMBINE/QUARANTINE");
_Static_assert(LIFE_OP_COMBINE     != LIFE_OP_RELEASE_Q,   "LIFE collide COMBINE/RELEASE_Q");
_Static_assert(LIFE_OP_COMBINE     != LIFE_OP_GENERATION,  "LIFE collide COMBINE/GENERATION");
_Static_assert(LIFE_OP_RELEASE     != LIFE_OP_APOPTOSIS,   "LIFE collide RELEASE/APOPTOSIS");
_Static_assert(LIFE_OP_RELEASE     != LIFE_OP_IMMUNE_EVAL, "LIFE collide RELEASE/IMMUNE_EVAL");
_Static_assert(LIFE_OP_RELEASE     != LIFE_OP_QUARANTINE,  "LIFE collide RELEASE/QUARANTINE");
_Static_assert(LIFE_OP_RELEASE     != LIFE_OP_RELEASE_Q,   "LIFE collide RELEASE/RELEASE_Q");
_Static_assert(LIFE_OP_RELEASE     != LIFE_OP_GENERATION,  "LIFE collide RELEASE/GENERATION");
_Static_assert(LIFE_OP_APOPTOSIS   != LIFE_OP_IMMUNE_EVAL, "LIFE collide APOPTOSIS/IMMUNE_EVAL");
_Static_assert(LIFE_OP_APOPTOSIS   != LIFE_OP_QUARANTINE,  "LIFE collide APOPTOSIS/QUARANTINE");
_Static_assert(LIFE_OP_APOPTOSIS   != LIFE_OP_RELEASE_Q,   "LIFE collide APOPTOSIS/RELEASE_Q");
_Static_assert(LIFE_OP_APOPTOSIS   != LIFE_OP_GENERATION,  "LIFE collide APOPTOSIS/GENERATION");
_Static_assert(LIFE_OP_IMMUNE_EVAL != LIFE_OP_QUARANTINE,  "LIFE collide IMMUNE_EVAL/QUARANTINE");
_Static_assert(LIFE_OP_IMMUNE_EVAL != LIFE_OP_RELEASE_Q,   "LIFE collide IMMUNE_EVAL/RELEASE_Q");
_Static_assert(LIFE_OP_IMMUNE_EVAL != LIFE_OP_GENERATION,  "LIFE collide IMMUNE_EVAL/GENERATION");
_Static_assert(LIFE_OP_QUARANTINE  != LIFE_OP_RELEASE_Q,   "LIFE collide QUARANTINE/RELEASE_Q");
_Static_assert(LIFE_OP_QUARANTINE  != LIFE_OP_GENERATION,  "LIFE collide QUARANTINE/GENERATION");
_Static_assert(LIFE_OP_RELEASE_Q   != LIFE_OP_GENERATION,  "LIFE collide RELEASE_Q/GENERATION");
_Static_assert(LIFE_OP_GENERATION  <= 0xF,                 "LIFE opcode exceeds 4-bit width");

/* ========================================================================
 * META family opcodes (Family 5)
 *
 * System-wide administrative and query operations.
 * ======================================================================== */

#define META_OP_FLUSH          0    /* Flush TLB cache */
#define META_OP_AUDIT          1    /* Emit manual audit entry */
#define META_OP_REPARTITION    2    /* Repartition authority boundaries */
#define META_OP_GET_SUBJECT    3    /* Get full subject state */
#define META_OP_GET_CHROMOSOME 4    /* Get chromosomal authority */
#define META_OP_GET_SEX        5    /* Get XY sex determination */
#define META_OP_IMMUNE_STATUS  6    /* Get immune response status */
#define META_OP_TRC_STATE      7    /* Get TRC state machine state */

_Static_assert(META_OP_FLUSH          != META_OP_AUDIT,          "META collide FLUSH/AUDIT");
_Static_assert(META_OP_FLUSH          != META_OP_REPARTITION,    "META collide FLUSH/REPARTITION");
_Static_assert(META_OP_FLUSH          != META_OP_GET_SUBJECT,    "META collide FLUSH/GET_SUBJECT");
_Static_assert(META_OP_FLUSH          != META_OP_GET_CHROMOSOME, "META collide FLUSH/GET_CHROMOSOME");
_Static_assert(META_OP_FLUSH          != META_OP_GET_SEX,        "META collide FLUSH/GET_SEX");
_Static_assert(META_OP_FLUSH          != META_OP_IMMUNE_STATUS,  "META collide FLUSH/IMMUNE_STATUS");
_Static_assert(META_OP_FLUSH          != META_OP_TRC_STATE,      "META collide FLUSH/TRC_STATE");
_Static_assert(META_OP_AUDIT          != META_OP_REPARTITION,    "META collide AUDIT/REPARTITION");
_Static_assert(META_OP_AUDIT          != META_OP_GET_SUBJECT,    "META collide AUDIT/GET_SUBJECT");
_Static_assert(META_OP_AUDIT          != META_OP_GET_CHROMOSOME, "META collide AUDIT/GET_CHROMOSOME");
_Static_assert(META_OP_AUDIT          != META_OP_GET_SEX,        "META collide AUDIT/GET_SEX");
_Static_assert(META_OP_AUDIT          != META_OP_IMMUNE_STATUS,  "META collide AUDIT/IMMUNE_STATUS");
_Static_assert(META_OP_AUDIT          != META_OP_TRC_STATE,      "META collide AUDIT/TRC_STATE");
_Static_assert(META_OP_REPARTITION    != META_OP_GET_SUBJECT,    "META collide REPARTITION/GET_SUBJECT");
_Static_assert(META_OP_REPARTITION    != META_OP_GET_CHROMOSOME, "META collide REPARTITION/GET_CHROMOSOME");
_Static_assert(META_OP_REPARTITION    != META_OP_GET_SEX,        "META collide REPARTITION/GET_SEX");
_Static_assert(META_OP_REPARTITION    != META_OP_IMMUNE_STATUS,  "META collide REPARTITION/IMMUNE_STATUS");
_Static_assert(META_OP_REPARTITION    != META_OP_TRC_STATE,      "META collide REPARTITION/TRC_STATE");
_Static_assert(META_OP_GET_SUBJECT    != META_OP_GET_CHROMOSOME, "META collide GET_SUBJECT/GET_CHROMOSOME");
_Static_assert(META_OP_GET_SUBJECT    != META_OP_GET_SEX,        "META collide GET_SUBJECT/GET_SEX");
_Static_assert(META_OP_GET_SUBJECT    != META_OP_IMMUNE_STATUS,  "META collide GET_SUBJECT/IMMUNE_STATUS");
_Static_assert(META_OP_GET_SUBJECT    != META_OP_TRC_STATE,      "META collide GET_SUBJECT/TRC_STATE");
_Static_assert(META_OP_GET_CHROMOSOME != META_OP_GET_SEX,        "META collide GET_CHROMOSOME/GET_SEX");
_Static_assert(META_OP_GET_CHROMOSOME != META_OP_IMMUNE_STATUS,  "META collide GET_CHROMOSOME/IMMUNE_STATUS");
_Static_assert(META_OP_GET_CHROMOSOME != META_OP_TRC_STATE,      "META collide GET_CHROMOSOME/TRC_STATE");
_Static_assert(META_OP_GET_SEX        != META_OP_IMMUNE_STATUS,  "META collide GET_SEX/IMMUNE_STATUS");
_Static_assert(META_OP_GET_SEX        != META_OP_TRC_STATE,      "META collide GET_SEX/TRC_STATE");
_Static_assert(META_OP_IMMUNE_STATUS  != META_OP_TRC_STATE,      "META collide IMMUNE_STATUS/TRC_STATE");
_Static_assert(META_OP_TRC_STATE      <= 0xF,                    "META opcode exceeds 4-bit width");

/* Maximum opcodes per family (each family is 4-bit wide, 8 opcodes used). */
#define TRUST_CMD_MAX_OPCODES   8

_Static_assert(TRUST_CMD_MAX_OPCODES == 8, "opcode count invariant");

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

/* trust_cmd_entry_t is in-memory scratch, not a wire type; still lock
 * layout so kernel and userspace never disagree. */
_Static_assert(sizeof(trust_cmd_entry_t) == 4 + 4 + 8 * TRUST_CMD_MAX_OPERANDS,
	       "trust_cmd_entry_t size");
_Static_assert(offsetof(trust_cmd_entry_t, instruction)   == 0,  "trust_cmd_entry_t.instruction offset");
_Static_assert(offsetof(trust_cmd_entry_t, operand_count) == 4,  "trust_cmd_entry_t.operand_count offset");
_Static_assert(offsetof(trust_cmd_entry_t, operands)      == 8,  "trust_cmd_entry_t.operands offset");

/* ========================================================================
 * Per-command result
 * ======================================================================== */

typedef struct {
	int32_t  status;    /* 0 = success, negative = errno-style error */
	uint32_t _padding;
	uint64_t value;     /* Command-specific output value */
} trust_cmd_result_t;

_Static_assert(sizeof(trust_cmd_result_t) == 16, "trust_cmd_result_t wire size");
_Static_assert(offsetof(trust_cmd_result_t, status)   == 0, "trust_cmd_result_t.status offset");
_Static_assert(offsetof(trust_cmd_result_t, _padding) == 4, "trust_cmd_result_t._padding offset");
_Static_assert(offsetof(trust_cmd_result_t, value)    == 8, "trust_cmd_result_t.value offset");

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

_Static_assert((TRUST_CMD_BUF_ATOMIC & TRUST_CMD_BUF_ORDERED) == 0, "buf flag ATOMIC/ORDERED overlap");
_Static_assert((TRUST_CMD_BUF_ATOMIC & TRUST_CMD_BUF_ASYNC)   == 0, "buf flag ATOMIC/ASYNC overlap");
_Static_assert((TRUST_CMD_BUF_ORDERED & TRUST_CMD_BUF_ASYNC)  == 0, "buf flag ORDERED/ASYNC overlap");

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

_Static_assert(sizeof(trust_cmd_buffer_t) == 16, "trust_cmd_buffer_t wire size");
_Static_assert(offsetof(trust_cmd_buffer_t, magic)      == 0,  "trust_cmd_buffer_t.magic offset");
_Static_assert(offsetof(trust_cmd_buffer_t, version)    == 4,  "trust_cmd_buffer_t.version offset");
_Static_assert(offsetof(trust_cmd_buffer_t, cmd_count)  == 6,  "trust_cmd_buffer_t.cmd_count offset");
_Static_assert(offsetof(trust_cmd_buffer_t, total_size) == 8,  "trust_cmd_buffer_t.total_size offset");
_Static_assert(offsetof(trust_cmd_buffer_t, flags)      == 12, "trust_cmd_buffer_t.flags offset");

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

_Static_assert(sizeof(trust_cmd_batch_result_t) == 16, "trust_cmd_batch_result_t wire size");
_Static_assert(offsetof(trust_cmd_batch_result_t, commands_executed)  == 0,  "trust_cmd_batch_result_t.commands_executed offset");
_Static_assert(offsetof(trust_cmd_batch_result_t, commands_succeeded) == 4,  "trust_cmd_batch_result_t.commands_succeeded offset");
_Static_assert(offsetof(trust_cmd_batch_result_t, commands_failed)    == 8,  "trust_cmd_batch_result_t.commands_failed offset");
_Static_assert(offsetof(trust_cmd_batch_result_t, flags)              == 12, "trust_cmd_batch_result_t.flags offset");

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

_Static_assert(sizeof(trust_ioc_cmd_submit_t) == 24, "trust_ioc_cmd_submit_t wire size");
_Static_assert(offsetof(trust_ioc_cmd_submit_t, cmd_buffer)    == 0,  "trust_ioc_cmd_submit_t.cmd_buffer offset");
_Static_assert(offsetof(trust_ioc_cmd_submit_t, result_buffer) == 8,  "trust_ioc_cmd_submit_t.result_buffer offset");
_Static_assert(offsetof(trust_ioc_cmd_submit_t, cmd_buf_size)  == 16, "trust_ioc_cmd_submit_t.cmd_buf_size offset");
_Static_assert(offsetof(trust_ioc_cmd_submit_t, res_buf_size)  == 20, "trust_ioc_cmd_submit_t.res_buf_size offset");

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

_Static_assert(TRUST_CMD_MAX_OPERANDS <= 0xF, "operand count exceeds 4-bit nops field");
_Static_assert(TRUST_CMD_ENTRY_MAX_SIZE == 4 + 15 * 8, "entry max size invariant");

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
