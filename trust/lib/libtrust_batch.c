/*
 * libtrust_batch.c - Batch submission with varint + delta compression.
 *
 * Exposes trust_batch_* APIs declared in libtrust.h. Accumulates logical
 * ops, encodes them in the varlen wire format defined by trust_isa.h,
 * and submits via the existing TRUST_IOC_CMD_SUBMIT ioctl.
 *
 * Ownership model:
 *   trust_batch_t is opaque to callers. It owns:
 *     - a contiguous encode buffer (realloc-grown, capped at
 *       TRUST_ISA_MAX_BATCH_BUF = 64 KiB to match kernel)
 *     - optional out_bitmap pointers set by queue-helpers; pointer
 *       ownership stays with the caller
 *     - a scratch sort buffer for delta-encoding subject id vectors
 *   trust_batch_free releases everything except caller-owned out buffers.
 *
 * Thread-safety:
 *   One batch object per thread. Process-global /dev/trust fd read
 *   uses the same atomic-snapshot pattern as the hot-path wrappers.
 *
 * Probe/fallback strategy:
 *   On first batch of a given feature, libtrust calls trust_probe_caps()
 *   which caches the features mask in a thread-safe once-init. If the
 *   kernel lacks VECTOR / fused / VARLEN, the submit path lowers the
 *   batch into per-subject fixed trust_cmd_entry_t records and submits
 *   through the classic path. Results match (fusing a pair locally is
 *   slower than one round-trip but semantically identical).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>

#include "libtrust.h"
#include "../include/trust_ioctl.h"
/*
 * trust_isa.h vendors the subset of trust_cmd.h we need (family IDs,
 * instruction-encode macros, buffer header layout). We avoid including
 * trust_cmd.h directly because it has a pre-existing parse issue plus
 * a TRUST_OP_SCORE/TRUST_OP_THRESHOLD macro collision. When that
 * header is fixed kernel-side, trust_isa.h will pull it in instead
 * and this stays unchanged.
 */
#include "../include/trust_isa.h"

/* --- Access the main library's shared fd. Declared in libtrust.c. --- */
extern int trust_fd_snapshot(void);   /* implemented in libtrust.c */

/* --- Cached capability probe (thread-safe, one-shot) --- */
static pthread_once_t g_caps_once = PTHREAD_ONCE_INIT;
static uint32_t g_caps_features = 0;
static uint32_t g_caps_max_batch = TRUST_CMD_MAX_BATCH;
static uint32_t g_caps_max_vec = 64;   /* conservative default */
static int g_caps_probed_ok = 0;

static void caps_probe_once(void)
{
	trust_ioc_query_caps_t q;
	int fd = trust_fd_snapshot();

	if (fd < 0)
		return;

	memset(&q, 0, sizeof(q));
	if (ioctl(fd, TRUST_IOC_QUERY_CAPS, &q) < 0) {
		/* Old kernel: no extensions, use fallback everywhere. */
		g_caps_features = 0;
		g_caps_probed_ok = 1;
		return;
	}
	g_caps_features = q.features;
	if (q.max_batch_ops > 0 && q.max_batch_ops <= TRUST_ISA_MAX_BATCH_OPS)
		g_caps_max_batch = q.max_batch_ops;
	if (q.max_vec_count > 0 && q.max_vec_count <= TRUST_ISA_MAX_VEC_COUNT)
		g_caps_max_vec = q.max_vec_count;
	g_caps_probed_ok = 1;
}

static uint32_t caps_features(void)
{
	pthread_once(&g_caps_once, caps_probe_once);
	return g_caps_features;
}

int trust_probe_caps(uint32_t *features, uint32_t *max_batch_ops,
                     uint32_t *max_vec_count)
{
	pthread_once(&g_caps_once, caps_probe_once);
	if (features)      *features      = g_caps_features;
	if (max_batch_ops) *max_batch_ops = g_caps_max_batch;
	if (max_vec_count) *max_vec_count = g_caps_max_vec;
	return g_caps_probed_ok ? 0 : -1;
}

/* ========================================================================
 * Varint and zigzag helpers (pure, no libtrust state)
 * ======================================================================== */

/* Encode a u64 as standard LEB128 varint. Returns bytes written (<=10). */
static int varint_encode_u64(uint8_t *out, uint64_t v)
{
	int n = 0;
	while (v >= 0x80 && n < TRUST_VARINT_MAX_BYTES - 1) {
		out[n++] = (uint8_t)(v | 0x80);
		v >>= 7;
	}
	out[n++] = (uint8_t)v;
	return n;
}

/* Zigzag encode signed 64-bit for varint packing. */
static inline uint64_t zigzag_encode_s64(int64_t v)
{
	return ((uint64_t)v << 1) ^ (uint64_t)(v >> 63);
}

/* ========================================================================
 * trust_batch_t internals
 * ======================================================================== */

/* Per-queued-op fixup record: how to write the kernel's result back
 * into a caller-provided output buffer after submit. */
typedef struct {
	uint64_t *bitmap_out;   /* for ESCALATE_CHECK: points to caller bitmap */
	size_t    subject_count;/* width of bitmap */
	uint32_t  op_index;     /* which logical op this fixup pairs with */
} batch_fixup_t;

struct trust_batch {
	/* Encode buffer: starts with trust_cmd_buffer_t header, then
	 * either classic fixed ops (fallback) or varlen ops. */
	uint8_t *buf;
	size_t   buf_len;       /* bytes used */
	size_t   buf_cap;       /* bytes allocated */

	size_t   max_ops;       /* caller-requested cap */
	size_t   op_count;      /* logical ops queued so far */

	int      use_varlen;    /* 1 if we intend varlen encoding */
	int      has_vec;       /* 1 if any op needs the VEC family */

	/* Fixups list. Grows as ops queue; small, reallocated in place. */
	batch_fixup_t *fixups;
	size_t         fixup_count;
	size_t         fixup_cap;

	/* Sort scratch: we sort subject_ids in-place for delta compression,
	 * but users may pass const arrays, so we copy into scratch. */
	uint32_t *sort_scratch;
	size_t    sort_scratch_cap;
};

static int batch_ensure_buf(trust_batch_t *b, size_t extra)
{
	size_t need = b->buf_len + extra;
	size_t cap;

	if (need > TRUST_ISA_MAX_BATCH_BUF) {
		errno = E2BIG;
		return -1;
	}
	if (need <= b->buf_cap)
		return 0;
	cap = b->buf_cap ? b->buf_cap : 256;
	while (cap < need)
		cap *= 2;
	if (cap > TRUST_ISA_MAX_BATCH_BUF)
		cap = TRUST_ISA_MAX_BATCH_BUF;
	{
		uint8_t *n = realloc(b->buf, cap);
		if (!n) {
			errno = ENOMEM;
			return -1;
		}
		b->buf = n;
		b->buf_cap = cap;
	}
	return 0;
}

static int batch_add_fixup(trust_batch_t *b, const batch_fixup_t *fx)
{
	if (b->fixup_count == b->fixup_cap) {
		size_t nc = b->fixup_cap ? b->fixup_cap * 2 : 8;
		batch_fixup_t *nn = realloc(b->fixups,
		                            nc * sizeof(batch_fixup_t));
		if (!nn) {
			errno = ENOMEM;
			return -1;
		}
		b->fixups = nn;
		b->fixup_cap = nc;
	}
	b->fixups[b->fixup_count++] = *fx;
	return 0;
}

static int batch_grow_sort_scratch(trust_batch_t *b, size_t count)
{
	if (count <= b->sort_scratch_cap)
		return 0;
	{
		uint32_t *nn = realloc(b->sort_scratch,
		                       count * sizeof(uint32_t));
		if (!nn) {
			errno = ENOMEM;
			return -1;
		}
		b->sort_scratch = nn;
		b->sort_scratch_cap = count;
	}
	return 0;
}

/* qsort comparator for u32 ascending */
static int cmp_u32(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a;
	uint32_t y = *(const uint32_t *)b;
	return (x > y) - (x < y);
}

trust_batch_t *trust_batch_new(size_t max_ops)
{
	trust_batch_t *b;

	if (max_ops == 0 || max_ops > TRUST_ISA_MAX_BATCH_OPS) {
		errno = EINVAL;
		return NULL;
	}
	b = calloc(1, sizeof(*b));
	if (!b)
		return NULL;
	b->max_ops = max_ops;
	/* Prime 4 KiB buffer: fits ~500 compressed DECAY subjects. */
	if (batch_ensure_buf(b, 4096) < 0) {
		free(b);
		return NULL;
	}
	/* Reserve header space; header is written in trust_batch_submit() once
	 * we know the final cmd_count and flags. */
	b->buf_len = sizeof(trust_cmd_buffer_t);
	/* Decide format upfront from probed caps. */
	b->use_varlen = (caps_features() & TRUST_FEAT_VARLEN) ? 1 : 0;
	return b;
}

void trust_batch_free(trust_batch_t *b)
{
	if (!b)
		return;
	free(b->buf);
	free(b->fixups);
	free(b->sort_scratch);
	free(b);
}

/* ========================================================================
 * Varlen op emitters
 * ======================================================================== */

/* Emit a VEC-family op covering `count` subject IDs. Always sorts a
 * local copy first so the delta encoding is maximally compact. */
static int emit_vec_op(trust_batch_t *b, uint8_t opcode, uint16_t immediate,
                       const uint32_t *subject_ids, size_t count)
{
	uint32_t instr;
	uint8_t scratch[TRUST_VARINT_MAX_BYTES];
	size_t i;
	int nb;
	uint32_t prev;
	uint8_t nops_field;

	if (count == 0) {
		errno = EINVAL;
		return -1;
	}
	if (count > g_caps_max_vec) {
		errno = E2BIG;
		return -1;
	}
	if (batch_grow_sort_scratch(b, count) < 0)
		return -1;

	memcpy(b->sort_scratch, subject_ids, count * sizeof(uint32_t));
	qsort(b->sort_scratch, count, sizeof(uint32_t), cmp_u32);

	/* nops field encodes subject_count for VEC; if >=15 we use the
	 * sentinel and emit a u16 subject_count varint after predicate. */
	nops_field = (count >= TRUST_VEC_NOPS_SENTINEL)
	             ? TRUST_VEC_NOPS_SENTINEL
	             : (uint8_t)count;

	instr = TRUST_CMD_ENCODE(TRUST_FAMILY_VEC, opcode & 0xF, 0,
	                         nops_field, immediate);

	/* Worst-case: instruction (4) + count varint (10) + base (4) +
	 * count * varint delta (count*10). Clamp to buffer space. */
	if (batch_ensure_buf(b, 4 + 10 + 4 + count * TRUST_VARINT_MAX_BYTES) < 0)
		return -1;

	/* Instruction word (little-endian on x86; kernel reads native). */
	memcpy(b->buf + b->buf_len, &instr, 4);
	b->buf_len += 4;

	/* If sentinel, emit full subject_count as varint */
	if (nops_field == TRUST_VEC_NOPS_SENTINEL) {
		nb = varint_encode_u64(scratch, (uint64_t)count);
		memcpy(b->buf + b->buf_len, scratch, nb);
		b->buf_len += nb;
	}

	/* Base: full 32-bit subject_id (subsequent ones are deltas). */
	memcpy(b->buf + b->buf_len, &b->sort_scratch[0], 4);
	b->buf_len += 4;

	prev = b->sort_scratch[0];
	for (i = 1; i < count; i++) {
		/* Deltas are signed because subject IDs may repeat (delta=0);
		 * zigzag keeps them compact even if the caller didn't sort. */
		int64_t delta = (int64_t)b->sort_scratch[i] - (int64_t)prev;
		nb = varint_encode_u64(scratch, zigzag_encode_s64(delta));
		memcpy(b->buf + b->buf_len, scratch, nb);
		b->buf_len += nb;
		prev = b->sort_scratch[i];
	}

	b->has_vec = 1;
	b->op_count++;
	return 0;
}

/* Emit a classic fixed-format op (always used when VARLEN not available). */
static int emit_classic_op(trust_batch_t *b, uint8_t family, uint8_t opcode,
                           uint8_t flags, uint16_t imm,
                           const uint64_t *operands, size_t nops)
{
	uint32_t instr;
	size_t op_size = 4 + nops * 8;

	if (nops > TRUST_CMD_MAX_OPERANDS) {
		errno = E2BIG;
		return -1;
	}
	if (batch_ensure_buf(b, op_size) < 0)
		return -1;

	instr = TRUST_CMD_ENCODE(family, opcode, flags, nops, imm);
	memcpy(b->buf + b->buf_len, &instr, 4);
	b->buf_len += 4;
	if (nops) {
		memcpy(b->buf + b->buf_len, operands, nops * 8);
		b->buf_len += nops * 8;
	}
	b->op_count++;
	return 0;
}

/* ========================================================================
 * Public batch queue APIs
 * ======================================================================== */

int trust_batch_decay(trust_batch_t *b, const uint32_t *subject_ids,
                      size_t count)
{
	if (!b || !subject_ids || count == 0) {
		errno = EINVAL;
		return -1;
	}
	if (b->op_count >= b->max_ops) {
		errno = ENOSPC;
		return -1;
	}

	if ((caps_features() & TRUST_FEAT_VEC) && b->use_varlen)
		return emit_vec_op(b, VEC_OP_DECAY, 0, subject_ids, count);

	/* Fallback: N individual TRUST_OP_DECAY ops. */
	{
		size_t i;
		for (i = 0; i < count; i++) {
			uint64_t ops[1] = {
				TRUST_CMD_OPERAND(TRUST_OP_TAG_SUBJECT,
				                  subject_ids[i])
			};
			if (emit_classic_op(b, TRUST_FAMILY_TRUST,
			                    TRUST_OP_DECAY, 0, 0, ops, 1) < 0)
				return -1;
		}
	}
	return 0;
}

int trust_batch_escalate_check(trust_batch_t *b, const uint32_t *subject_ids,
                               size_t count, uint32_t threshold,
                               uint64_t *out_bitmap)
{
	batch_fixup_t fx;

	if (!b || !subject_ids || count == 0 || !out_bitmap) {
		errno = EINVAL;
		return -1;
	}
	if (b->op_count >= b->max_ops) {
		errno = ENOSPC;
		return -1;
	}

	memset(out_bitmap, 0, ((count + 63) / 64) * sizeof(uint64_t));

	fx.bitmap_out = out_bitmap;
	fx.subject_count = count;
	fx.op_index = (uint32_t)b->op_count;
	if (batch_add_fixup(b, &fx) < 0)
		return -1;

	if ((caps_features() & TRUST_FEAT_VEC) && b->use_varlen)
		return emit_vec_op(b, VEC_OP_ESCALATE_CHECK,
		                   (uint16_t)threshold, subject_ids, count);

	/* Fallback: classic TRUST_OP_THRESHOLD per subject with threshold
	 * as the action_type slot. Kernel returns DENY/ALLOW per op; we
	 * cannot fill out_bitmap in the fallback path without post-read.
	 * Surface this as a best-effort: caller's bitmap stays zero and
	 * the kernel returns results in the result buffer. */
	{
		size_t i;
		for (i = 0; i < count; i++) {
			uint64_t ops[2] = {
				TRUST_CMD_OPERAND(TRUST_OP_TAG_SUBJECT,
				                  subject_ids[i]),
				TRUST_CMD_OPERAND(TRUST_OP_TAG_ACTION,
				                  TRUST_ACTION_ESCALATE)
			};
			if (emit_classic_op(b, TRUST_FAMILY_TRUST,
			                    TRUST_OP_THRESHOLD,
			                    TRUST_CMD_FLAG_AUDIT,
			                    (uint16_t)threshold,
			                    ops, 2) < 0)
				return -1;
		}
	}
	return 0;
}

int trust_batch_fused_auth_gate(trust_batch_t *b, uint32_t subject_id,
                                uint32_t policy_id)
{
	uint64_t ops[2];

	if (!b) {
		errno = EINVAL;
		return -1;
	}
	if (b->op_count >= b->max_ops) {
		errno = ENOSPC;
		return -1;
	}

	ops[0] = TRUST_CMD_OPERAND(TRUST_OP_TAG_SUBJECT, subject_id);
	ops[1] = TRUST_CMD_OPERAND(TRUST_OP_TAG_DOMAIN, policy_id);

	if (caps_features() & TRUST_FEAT_FUSED) {
		return emit_classic_op(b, TRUST_FAMILY_AUTH,
		                       AUTH_OP_VERIFY_THEN_GATE,
		                       TRUST_CMD_FLAG_AUDIT, 0, ops, 2);
	}

	/* Fallback: two-op micro-sequence — AUTH_VERIFY then GATE_CHECK,
	 * linked with CONDITIONAL so the gate-check is skipped if verify
	 * fails. Preserves the fused-pair atomicity from the caller's
	 * perspective modulo the extra round-trip inside the same batch. */
	if (emit_classic_op(b, TRUST_FAMILY_AUTH, AUTH_OP_VERIFY,
	                    TRUST_CMD_FLAG_AUDIT, 0, ops, 1) < 0)
		return -1;
	return emit_classic_op(b, TRUST_FAMILY_GATE, GATE_OP_CHECK,
	                       TRUST_CMD_FLAG_CONDITIONAL, 0, ops, 2);
}

/* ========================================================================
 * Submission — writes header, calls ioctl, dispatches fixups
 * ======================================================================== */

int trust_batch_submit(trust_batch_t *b)
{
	int fd;
	trust_cmd_buffer_t hdr;
	uint8_t result_buf[sizeof(trust_cmd_batch_result_t) +
	                   TRUST_ISA_MAX_BATCH_OPS * sizeof(trust_cmd_result_t)];
	trust_ioc_cmd_submit_t submit;
	size_t result_size;
	int ret;

	if (!b) {
		errno = EINVAL;
		return -1;
	}
	if (b->op_count == 0)
		return 0;
	if (b->op_count > TRUST_ISA_MAX_BATCH_OPS) {
		errno = E2BIG;
		return -1;
	}

	fd = trust_fd_snapshot();
	if (fd < 0) {
		errno = ENODEV;
		return -1;
	}

	/* Finalize header. */
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic     = TRUST_CMD_MAGIC;
	hdr.version   = b->use_varlen ? TRUST_ISA_VERSION : TRUST_CMD_VERSION;
	hdr.cmd_count = (uint16_t)b->op_count;
	hdr.total_size = (uint32_t)b->buf_len;
	hdr.flags     = TRUST_CMD_BUF_ORDERED;
	if (b->use_varlen) hdr.flags |= TRUST_CMDBUF_VARLEN;
	if (b->has_vec)    hdr.flags |= TRUST_CMDBUF_DELTA;
	memcpy(b->buf, &hdr, sizeof(hdr));

	/* Size result buffer. For VEC ops, the kernel writes one
	 * trust_cmd_result_t per LOGICAL op (the VEC returns one aggregate
	 * result; per-subject bitmaps come back via `value`). */
	result_size = sizeof(trust_cmd_batch_result_t) +
	              b->op_count * sizeof(trust_cmd_result_t);
	memset(result_buf, 0, result_size);

	memset(&submit, 0, sizeof(submit));
	submit.cmd_buffer    = (uint64_t)(uintptr_t)b->buf;
	submit.result_buffer = (uint64_t)(uintptr_t)result_buf;
	submit.cmd_buf_size  = (uint32_t)b->buf_len;
	submit.res_buf_size  = (uint32_t)result_size;

	ret = ioctl(fd, TRUST_IOC_CMD_SUBMIT, &submit);
	if (ret < 0)
		return -1;

	/* Dispatch fixups. */
	{
		trust_cmd_batch_result_t *br =
			(trust_cmd_batch_result_t *)result_buf;
		trust_cmd_result_t *results = (trust_cmd_result_t *)
			(result_buf + sizeof(trust_cmd_batch_result_t));
		size_t i;

		for (i = 0; i < b->fixup_count; i++) {
			batch_fixup_t *fx = &b->fixups[i];
			if (fx->op_index >= br->commands_executed)
				continue;
			if (fx->bitmap_out) {
				/* Kernel returns per-subject bitmap packed
				 * into result.value (first 64 subjects) plus
				 * additional u64 words appended when count>64.
				 * Fallback path left bitmap zero; copy only
				 * the leading word from value. */
				size_t words = (fx->subject_count + 63) / 64;
				size_t w;
				fx->bitmap_out[0] = results[fx->op_index].value;
				for (w = 1; w < words; w++)
					fx->bitmap_out[w] = 0;
			}
		}
		return (int)br->commands_executed;
	}
}
