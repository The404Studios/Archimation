/*
 * trust_dispatch.c - Trust ISA Command Buffer Dispatch Engine
 *
 * Kernel-side processor for batched command buffers submitted via
 * TRUST_IOC_CMD_SUBMIT. This is pure dispatch -- no interpretation.
 * Each command word maps through a [family][opcode] function pointer
 * table directly to the existing trust subsystem kernel functions.
 *
 * Protocol flow:
 *   1. Userspace builds a trust_cmd_buffer_t with packed commands.
 *   2. Submits via ioctl(fd, TRUST_IOC_CMD_SUBMIT, &submit).
 *   3. This module validates the buffer (magic, version, bounds).
 *   4. Iterates commands, dispatching each through the table.
 *   5. Supports CHAIN (output feeds next), CONDITIONAL (skip on fail),
 *      FENCE (memory barrier), and AUDIT (emit audit event) flags.
 *   6. Writes per-command results back to userspace.
 *   7. Returns number of commands successfully executed.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/bug.h>
#include <linux/ratelimit.h>
#include <linux/ktime.h>

#include "../include/trust_cmd.h"
#include "../include/trust_ioctl.h"
#include "trust_internal.h"
#include "trust_isa.h"
#include "trust_morphogen.h"  /* S74 Agent 5: tissue-field perturbation */

/* --- Session 32 wire-format constants mirrored from trust/include/trust_isa.h
 *
 * We cannot include the userspace-facing trust/include/trust_isa.h from the
 * kernel tree (it redefines macros that conflict with the kernel's header)
 * so we re-declare the small subset of constants needed to parse the
 * libtrust VARLEN wire format.  Keep these in sync with
 * trust/include/trust_isa.h lines ~302-316 and TRUST_FAMILY_VEC at 207.
 */
#ifndef TRUST_CMDBUF_VARLEN
#define TRUST_CMDBUF_VARLEN     (1U << 8)
#endif
#ifndef TRUST_CMDBUF_DELTA
#define TRUST_CMDBUF_DELTA      (1U << 9)
#endif
#ifndef TRUST_VEC_NOPS_SENTINEL
#define TRUST_VEC_NOPS_SENTINEL 0xF
#endif
#ifndef TRUST_CMD_FAMILY_VEC
#define TRUST_CMD_FAMILY_VEC    6
#endif
#ifndef TRUST_CMD_FAMILY_FUSED
#define TRUST_CMD_FAMILY_FUSED  7
#endif
/* ISA v2 bump in the trust_cmd_buffer_t.version field (libtrust sets this
 * when VARLEN is used so older kernels would reject the buffer). */
#ifndef TRUST_ISA_VERSION
#define TRUST_ISA_VERSION       2
#endif

/* ========================================================================
 * Operand extraction helpers
 *
 * Each handler needs to pull typed values from the operand array.
 * These fail gracefully if the operand index is out of range.
 * ======================================================================== */

static inline u32 cmd_get_subject(const trust_cmd_entry_t *cmd, u32 idx)
{
	if (idx >= cmd->operand_count)
		return 0;
	return (u32)(cmd->operands[idx] & TRUST_OP_VAL_MASK);
}

static inline u32 cmd_get_u32(const trust_cmd_entry_t *cmd, u32 idx)
{
	if (idx >= cmd->operand_count)
		return 0;
	return (u32)(cmd->operands[idx] & TRUST_OP_VAL_MASK);
}

static inline u16 cmd_get_u16(const trust_cmd_entry_t *cmd, u32 idx)
{
	if (idx >= cmd->operand_count)
		return 0;
	return (u16)(cmd->operands[idx] & TRUST_OP_VAL_MASK);
}

static inline int32_t cmd_get_s32(const trust_cmd_entry_t *cmd, u32 idx)
{
	if (idx >= cmd->operand_count)
		return 0;
	return (int32_t)(cmd->operands[idx] & TRUST_OP_VAL_MASK);
}

static inline u16 cmd_get_imm(const trust_cmd_entry_t *cmd)
{
	return (u16)TRUST_CMD_IMM(cmd->instruction);
}

/* ========================================================================
 * AUTH family handlers (Family 0)
 * ======================================================================== */

/* AUTH_MINT: Mint initial proof.  Operand 0 = subject_id */
static int cmd_auth_mint(const trust_cmd_entry_t *cmd,
			 trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u8 proof[TRUST_PROOF_SIZE];
	int ret;

	ret = trust_ape_consume_proof(sid, NULL, 0, proof);
	result->status = ret;
	result->value = (ret == 0) ? sid : 0;
	return ret;
}

/* AUTH_BURN: Consume proof, advance chain.  Op0 = subject_id */
static int cmd_auth_burn(const trust_cmd_entry_t *cmd,
			 trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u32 action = cmd_get_u32(cmd, 1);
	u8 req[8];
	u8 proof_out[TRUST_PROOF_SIZE];
	u32 action_result = 0;
	int ret;

	memcpy(req, &action, 4);
	memcpy(req + 4, &action_result, 4);
	ret = trust_ape_consume_proof(sid, req, sizeof(req), proof_out);
	result->status = ret;
	result->value = (ret == 0) ? sid : 0;
	return ret;
}

/* AUTH_CONSUME: Consume proof for specific action.  Op0 = sid, Op1 = action */
static int cmd_auth_consume(const trust_cmd_entry_t *cmd,
			    trust_cmd_result_t *result)
{
	/* Same as burn with explicit action parameter */
	return cmd_auth_burn(cmd, result);
}

/* AUTH_VERIFY: Verify proof chain integrity.  Op0 = subject_id */
static int cmd_auth_verify(const trust_cmd_entry_t *cmd,
			   trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	int ret;

	ret = trust_ape_verify_chain(sid);
	result->status = ret;
	result->value = (ret == 0) ? 1 : 0;
	return ret;
}

/* AUTH_FENCE: Invalidate proof chain.  Op0 = subject_id */
static int cmd_auth_fence(const trust_cmd_entry_t *cmd,
			  trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	int ret;

	ret = trust_ape_destroy_entity(sid);
	result->status = ret;
	result->value = 0;
	return ret;
}

/* AUTH_NONCE: Get current chain nonce.  Op0 = subject_id */
static int cmd_auth_nonce(const trust_cmd_entry_t *cmd,
			  trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u64 nonce = 0;
	int ret;

	ret = trust_ape_get_nonce(sid, &nonce);
	result->status = ret;
	result->value = nonce;
	return ret;
}

/* AUTH_CHAIN_LEN: Get proof chain length.  Op0 = subject_id */
static int cmd_auth_chain_len(const trust_cmd_entry_t *cmd,
			      trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u32 length = 0;
	int ret;

	ret = trust_ape_get_chain_length(sid, &length);
	result->status = ret;
	result->value = length;
	return ret;
}

/* AUTH_ROTATE: Rotate hash algorithm.  Op0 = subject_id, imm = new hash_cfg
 *
 * Actual hash rotation must go through APE (it requires invalidating
 * the existing proof chain and re-minting). The per-subject hash config
 * is not mutable via TLB alone. Until APE exposes a rotate entry point,
 * return -ENOSYS instead of a success no-op: a program that expects the
 * rotation to have taken effect must not get a false success. */
static int cmd_auth_rotate(const trust_cmd_entry_t *cmd,
			   trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u16 new_cfg = cmd_get_imm(cmd);
	trust_subject_t subj;
	int ret;

	/* Validate hash config so a malformed program fails loudly. */
	if (new_cfg >= TRUST_HASH_CFG_COUNT) {
		result->status = -EINVAL;
		result->value = 0;
		return -EINVAL;
	}

	ret = trust_tlb_lookup(sid, &subj);
	if (ret) {
		result->status = -ENOENT;
		result->value = 0;
		return -ENOENT;
	}

	result->status = -ENOSYS;
	result->value = 0;
	return -ENOSYS;
}

/* ========================================================================
 * TRUST family handlers (Family 1)
 * ======================================================================== */

/* TRUST_CHECK: Check subject capability.  Op0 = sid, Op1 = capability */
static int cmd_trust_check(const trust_cmd_entry_t *cmd,
			   trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u32 cap = cmd_get_u32(cmd, 1);
	int ret;

	ret = trust_risc_check_cap(sid, cap);
	result->status = 0;
	result->value = (u64)ret;
	return 0;
}

/* TRUST_SCORE: Get trust score.  Op0 = subject_id */
static int cmd_trust_score(const trust_cmd_entry_t *cmd,
			   trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	int32_t score;

	score = trust_risc_get_score(sid);
	result->status = 0;
	result->value = (u64)(u32)score;  /* Preserve bit pattern */
	return 0;
}

/* TRUST_RECORD: Record action.  Op0 = sid, Op1 = action_type, imm = result */
static int cmd_trust_record(const trust_cmd_entry_t *cmd,
			    trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u32 action = cmd_get_u32(cmd, 1);
	u32 action_result = (u32)cmd_get_imm(cmd);
	int32_t new_score;

	new_score = trust_risc_record_action(sid, action, action_result);
	result->status = 0;
	result->value = (u64)(u32)new_score;
	return 0;
}

/* TRUST_THRESHOLD: Threshold check.  Op0 = sid, Op1 = action_type */
static int cmd_trust_threshold(const trust_cmd_entry_t *cmd,
			       trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u32 action = cmd_get_u32(cmd, 1);
	int ret;

	ret = trust_risc_threshold_check(sid, action);
	result->status = 0;
	result->value = (u64)ret;  /* TRUST_RESULT_* */
	return 0;
}

/* TRUST_DECAY: Trigger decay tick.  No operands needed. */
static int cmd_trust_decay(const trust_cmd_entry_t *cmd,
			   trust_cmd_result_t *result)
{
	(void)cmd;
	trust_risc_decay_tick();
	result->status = 0;
	result->value = 0;
	return 0;
}

/* TRUST_TRANSLATE: Translate capability.  Op0 = cap, Op1 = from_domain, Op2 = to_domain */
static int cmd_trust_translate(const trust_cmd_entry_t *cmd,
			       trust_cmd_result_t *result)
{
	u32 cap = cmd_get_u32(cmd, 0);
	u16 from_dom = cmd_get_u16(cmd, 1);
	u16 to_dom = cmd_get_u16(cmd, 2);
	u32 translated;

	translated = trust_risc_translate_cap(cap, from_dom, to_dom);
	result->status = 0;
	result->value = (u64)translated;
	return 0;
}

/* TRUST_ELEVATE: Request authority elevation.  Op0 = sid, imm = requested level */
static int cmd_trust_elevate(const trust_cmd_entry_t *cmd,
			     trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u32 requested = (u32)cmd_get_imm(cmd);
	int ret;

	ret = trust_fbc_escalate(sid, requested, "cmd_submit_elevate");
	result->status = ret;
	result->value = (ret == 0) ? requested : 0;
	return ret;
}

/* TRUST_DEMOTE: Demote authority.  Op0 = sid, Op1 = delta (negative) */
static int cmd_trust_demote(const trust_cmd_entry_t *cmd,
			    trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	int32_t delta = cmd_get_s32(cmd, 1);

	/* Ensure delta is negative for demotion.
	 * Guard against the most-negative int32: negating it is UB. */
	if (delta == (int32_t)(-2147483647 - 1))
		delta = -2147483647;  /* saturate to most-negative representable */
	else if (delta > 0)
		delta = -delta;

	trust_fbc_propagate(sid, delta);
	result->status = 0;
	result->value = 0;
	return 0;
}

/* ========================================================================
 * GATE family handlers (Family 2)
 * ======================================================================== */

/* GATE_CHECK: Check gate permission.  Op0 = sid, Op1 = capability */
static int cmd_gate_check(const trust_cmd_entry_t *cmd,
			  trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u32 cap = cmd_get_u32(cmd, 1);
	int ret;

	ret = trust_dna_gate_check(sid, cap);
	result->status = 0;
	result->value = (u64)ret;
	return 0;
}

/* GATE_RAISE: Raise gate threshold.  Op0 = sid, imm = amount */
struct gate_raise_ctx { int32_t amount; int32_t new_high; };
static int _gate_raise_cb(trust_subject_t *subj, void *data) {
	struct gate_raise_ctx *c = data;
	subj->threshold_high += c->amount;
	subj->threshold_high = trust_clamp_score(subj->threshold_high);
	c->new_high = subj->threshold_high;
	return 0;
}
static int cmd_gate_raise(const trust_cmd_entry_t *cmd,
			  trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	struct gate_raise_ctx ctx = { .amount = (int32_t)cmd_get_imm(cmd) };
	int ret;

	ret = trust_tlb_modify(sid, _gate_raise_cb, &ctx);
	if (ret) {
		result->status = -ENOENT;
		return -ENOENT;
	}

	result->status = 0;
	result->value = (u64)(u32)ctx.new_high;
	return 0;
}

/* GATE_LOWER: Lower gate threshold.  Op0 = sid, imm = amount */
struct gate_lower_ctx { int32_t amount; int32_t new_low; };
static int _gate_lower_cb(trust_subject_t *subj, void *data) {
	struct gate_lower_ctx *c = data;
	subj->threshold_low -= c->amount;
	subj->threshold_low = trust_clamp_score(subj->threshold_low);
	c->new_low = subj->threshold_low;
	return 0;
}
static int cmd_gate_lower(const trust_cmd_entry_t *cmd,
			  trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	struct gate_lower_ctx ctx = { .amount = (int32_t)cmd_get_imm(cmd) };
	int ret;

	ret = trust_tlb_modify(sid, _gate_lower_cb, &ctx);
	if (ret) {
		result->status = -ENOENT;
		return -ENOENT;
	}

	result->status = 0;
	result->value = (u64)(u32)ctx.new_low;
	return 0;
}

/* GATE_HYST: Set hysteresis window.  Op0 = sid, Op1 = low, Op2 = high */
struct gate_hyst_ctx { int32_t low; int32_t high; };
static int _gate_hyst_cb(trust_subject_t *subj, void *data) {
	struct gate_hyst_ctx *c = data;
	subj->threshold_low = trust_clamp_score(c->low);
	subj->threshold_high = trust_clamp_score(c->high);
	c->low = subj->threshold_low;
	c->high = subj->threshold_high;
	return 0;
}
static int cmd_gate_hyst(const trust_cmd_entry_t *cmd,
			 trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	struct gate_hyst_ctx ctx = {
		.low = cmd_get_s32(cmd, 1),
		.high = cmd_get_s32(cmd, 2),
	};
	int ret;

	ret = trust_tlb_modify(sid, _gate_hyst_cb, &ctx);
	if (ret) {
		result->status = -ENOENT;
		return -ENOENT;
	}

	result->status = 0;
	result->value = ((u64)(u32)ctx.high << 32) |
			(u64)(u32)ctx.low;
	return 0;
}

/* GATE_TRANSLATE: Translate caps across gate.  Op0 = sid, Op1 = from, Op2 = to, Op3 = caps */
static int cmd_gate_translate(const trust_cmd_entry_t *cmd,
			      trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u16 from_dom = cmd_get_u16(cmd, 1);
	u16 to_dom = cmd_get_u16(cmd, 2);
	u32 caps = cmd_get_u32(cmd, 3);
	int ret;

	ret = trust_fbc_domain_transfer(sid, from_dom, to_dom, caps);
	result->status = ret;
	result->value = (ret == 0) ? caps : 0;
	return ret;
}

/* GATE_DOMAIN_ENTER: Enter domain.  Op0 = sid, Op1 = domain */
struct gate_domain_ctx { u16 domain; };
static int _gate_domain_enter_cb(trust_subject_t *subj, void *data) {
	struct gate_domain_ctx *c = data;
	subj->domain = c->domain;
	return 0;
}
static int cmd_gate_domain_enter(const trust_cmd_entry_t *cmd,
				 trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u16 domain = cmd_get_u16(cmd, 1);
	struct gate_domain_ctx ctx = { .domain = domain };
	int ret;

	if (domain >= TRUST_DOMAIN_MAX) {
		result->status = -EINVAL;
		return -EINVAL;
	}

	/* Use trust_tlb_modify to avoid TOCTOU: between lookup and insert
	 * another dispatch could mutate the subject (score, tokens, caps)
	 * and our stale insert would silently overwrite those updates. */
	ret = trust_tlb_modify(sid, _gate_domain_enter_cb, &ctx);
	if (ret) {
		result->status = -ENOENT;
		return -ENOENT;
	}

	result->status = 0;
	result->value = domain;
	return 0;
}

/* GATE_DOMAIN_LEAVE: Leave domain, return to LINUX.  Op0 = sid */
static int _gate_domain_leave_cb(trust_subject_t *subj, void *data) {
	(void)data;
	subj->domain = TRUST_DOMAIN_LINUX;
	return 0;
}
static int cmd_gate_domain_leave(const trust_cmd_entry_t *cmd,
				 trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	int ret;

	/* Same TOCTOU concern as enter: use modify to keep concurrent
	 * mutations to this subject consistent. */
	ret = trust_tlb_modify(sid, _gate_domain_leave_cb, NULL);
	if (ret) {
		result->status = -ENOENT;
		return -ENOENT;
	}

	result->status = 0;
	result->value = TRUST_DOMAIN_LINUX;
	return 0;
}

/* GATE_BRIDGE: Bridge two domains.  Op0 = sid, Op1 = domain_a, Op2 = domain_b, Op3 = caps */
static int cmd_gate_bridge(const trust_cmd_entry_t *cmd,
			   trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u16 dom_a = cmd_get_u16(cmd, 1);
	u16 dom_b = cmd_get_u16(cmd, 2);
	u32 caps = cmd_get_u32(cmd, 3);
	int ret;

	/* Bridge = bidirectional domain transfer */
	ret = trust_fbc_domain_transfer(sid, dom_a, dom_b, caps);
	if (ret == 0)
		ret = trust_fbc_domain_transfer(sid, dom_b, dom_a, caps);

	result->status = ret;
	result->value = (ret == 0) ? caps : 0;
	return ret;
}

/* ========================================================================
 * RES family handlers (Family 3)
 * ======================================================================== */

/* RES_BALANCE: Get token balance.  Op0 = subject_id */
static int cmd_res_balance(const trust_cmd_entry_t *cmd,
			   trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	trust_subject_t subj;
	int ret;

	ret = trust_tlb_lookup(sid, &subj);
	if (ret) {
		result->status = -ENOENT;
		result->value = 0;
		return -ENOENT;
	}

	result->status = 0;
	result->value = (u64)(u32)subj.tokens.balance;
	return 0;
}

/* RES_BURN: Burn tokens.  Op0 = sid, Op1 = action_type */
struct res_burn_ctx { u32 action; int status; int32_t balance; };
static int _res_burn_cb(trust_subject_t *subj, void *data) {
	struct res_burn_ctx *c = data;
	c->status = trust_token_burn(&subj->tokens, c->action);
	c->balance = subj->tokens.balance;
	return 0;
}
static int cmd_res_burn(const trust_cmd_entry_t *cmd,
			trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	struct res_burn_ctx ctx = { .action = cmd_get_u32(cmd, 1) };
	int ret;

	ret = trust_tlb_modify(sid, _res_burn_cb, &ctx);
	if (ret) {
		result->status = -ENOENT;
		return -ENOENT;
	}

	result->status = ctx.status;
	result->value = (u64)(u32)ctx.balance;
	return ctx.status;
}

/* RES_MINT: Mint tokens (admin).  Op0 = sid, imm = amount */
struct res_mint_ctx { int32_t amount; int32_t balance; };
static int _res_mint_cb(trust_subject_t *subj, void *data) {
	struct res_mint_ctx *c = data;
	/* Clamp-before-add to prevent signed int32 overflow when
	 * balance + amount exceeds INT32_MAX. Overflow is UB and on
	 * some ABIs would wrap negative, producing a burst of "free"
	 * starvation clears. */
	if (c->amount < 0)
		c->amount = 0;  /* imm is u16 so this can't happen, but be defensive */
	if (subj->tokens.balance > subj->tokens.max_balance - c->amount)
		subj->tokens.balance = subj->tokens.max_balance;
	else
		subj->tokens.balance += c->amount;
	/* Cap total_regenerated at UINT32_MAX to prevent overflow */
	if (subj->tokens.total_regenerated > UINT32_MAX - (u32)c->amount)
		subj->tokens.total_regenerated = UINT32_MAX;
	else
		subj->tokens.total_regenerated += (u32)c->amount;
	if (subj->tokens.starved && subj->tokens.balance > 0)
		subj->tokens.starved = 0;
	c->balance = subj->tokens.balance;
	return 0;
}
static int cmd_res_mint(const trust_cmd_entry_t *cmd,
			trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	struct res_mint_ctx ctx = { .amount = (int32_t)cmd_get_imm(cmd) };
	int ret;

	ret = trust_tlb_modify(sid, _res_mint_cb, &ctx);
	if (ret) {
		result->status = -ENOENT;
		return -ENOENT;
	}

	result->status = 0;
	result->value = (u64)(u32)ctx.balance;
	return 0;
}

/* RES_XFER: Transfer tokens.  Op0 = from_sid, Op1 = to_sid, imm = amount
 *
 * Must use spin_lock_irqsave on TLB set locks — those locks are also
 * acquired from softirq context by trust_decay_timer_fn -> decay/immune
 * ticks. Plain spin_lock() here would softirq-deadlock on the same CPU.
 */
static int cmd_res_xfer(const trust_cmd_entry_t *cmd,
			trust_cmd_result_t *result)
{
	u32 from_sid = cmd_get_subject(cmd, 0);
	u32 to_sid = cmd_get_u32(cmd, 1);
	int32_t amount = (int32_t)cmd_get_imm(cmd);
	u32 from_set_idx, to_set_idx;
	trust_tlb_set_t *set_a, *set_b;
	trust_subject_t *from_p = NULL, *to_p = NULL;
	unsigned long flags_a, flags_b = 0;
	int i;

	if (amount <= 0 || !g_trust_tlb.sets) {
		result->status = -EINVAL;
		return -EINVAL;
	}

	/* Reject self-transfer: would double-count total_burned AND
	 * total_regenerated on the same subject, corrupting lifetime
	 * accounting (and the aliased from_p/to_p pointer arithmetic
	 * below is only safe by coincidence, not design). */
	if (from_sid == to_sid) {
		result->status = -EINVAL;
		return -EINVAL;
	}

	/* Must match tlb_hash() in trust_tlb.c */
	from_set_idx = trust_tlb_set_of(from_sid);
	to_set_idx = trust_tlb_set_of(to_sid);

	/* Lock in consistent order to prevent deadlock */
	if (from_set_idx <= to_set_idx) {
		set_a = &g_trust_tlb.sets[from_set_idx];
		set_b = &g_trust_tlb.sets[to_set_idx];
		spin_lock_irqsave(&set_a->lock, flags_a);
		if (from_set_idx != to_set_idx)
			spin_lock_irqsave(&set_b->lock, flags_b);
	} else {
		set_a = &g_trust_tlb.sets[to_set_idx];
		set_b = &g_trust_tlb.sets[from_set_idx];
		spin_lock_irqsave(&set_a->lock, flags_a);
		spin_lock_irqsave(&set_b->lock, flags_b);
	}

	for (i = 0; i < TRUST_TLB_WAYS; i++) {
		trust_tlb_set_t *fs = &g_trust_tlb.sets[from_set_idx];
		if ((fs->valid_mask & (1U << i)) &&
		    fs->entries[i].subject_id == from_sid) {
			from_p = &fs->entries[i];
			break;
		}
	}
	for (i = 0; i < TRUST_TLB_WAYS; i++) {
		trust_tlb_set_t *ts = &g_trust_tlb.sets[to_set_idx];
		if ((ts->valid_mask & (1U << i)) &&
		    ts->entries[i].subject_id == to_sid) {
			to_p = &ts->entries[i];
			break;
		}
	}

	if (!from_p || !to_p) {
		if (from_set_idx != to_set_idx)
			spin_unlock_irqrestore(&set_b->lock, flags_b);
		spin_unlock_irqrestore(&set_a->lock, flags_a);
		result->status = -ENOENT;
		return -ENOENT;
	}

	if (from_p->tokens.balance < amount) {
		if (from_set_idx != to_set_idx)
			spin_unlock_irqrestore(&set_b->lock, flags_b);
		spin_unlock_irqrestore(&set_a->lock, flags_a);
		result->status = -ENOSPC;
		return -ENOSPC;
	}

	from_p->tokens.balance -= amount;
	/* Cap lifetime counters at UINT32_MAX to prevent silent overflow. */
	if (from_p->tokens.total_burned > UINT32_MAX - (u32)amount)
		from_p->tokens.total_burned = UINT32_MAX;
	else
		from_p->tokens.total_burned += (u32)amount;
	/* Clamp-before-add to avoid signed int32 overflow on huge amounts. */
	if (to_p->tokens.balance > to_p->tokens.max_balance - amount)
		to_p->tokens.balance = to_p->tokens.max_balance;
	else
		to_p->tokens.balance += amount;
	if (to_p->tokens.total_regenerated > UINT32_MAX - (u32)amount)
		to_p->tokens.total_regenerated = UINT32_MAX;
	else
		to_p->tokens.total_regenerated += (u32)amount;
	/* Clear starvation on recipient if balance becomes positive */
	if (to_p->tokens.starved && to_p->tokens.balance > 0)
		to_p->tokens.starved = 0;

	result->value = (u64)(u32)from_p->tokens.balance;

	if (from_set_idx != to_set_idx)
		spin_unlock_irqrestore(&set_b->lock, flags_b);
	spin_unlock_irqrestore(&set_a->lock, flags_a);

	result->status = 0;
	return 0;
}

/* RES_COST: Query cost for action type.  Op0 = action_type */
static int cmd_res_cost(const trust_cmd_entry_t *cmd,
			trust_cmd_result_t *result)
{
	u32 action = cmd_get_u32(cmd, 0);
	u32 cost;

	cost = trust_token_cost_for_action(action);
	result->status = 0;
	result->value = (u64)cost;
	return 0;
}

/* RES_REGEN: Trigger token regeneration.  Op0 = sid */
struct res_regen_ctx { int32_t balance; };
static int _res_regen_cb(trust_subject_t *subj, void *data) {
	struct res_regen_ctx *c = data;
	trust_token_regenerate(&subj->tokens);
	c->balance = subj->tokens.balance;
	return 0;
}
static int cmd_res_regen(const trust_cmd_entry_t *cmd,
			 trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	struct res_regen_ctx ctx = { 0 };
	int ret;

	ret = trust_tlb_modify(sid, _res_regen_cb, &ctx);
	if (ret) {
		result->status = -ENOENT;
		return -ENOENT;
	}

	result->status = 0;
	result->value = (u64)(u32)ctx.balance;
	return 0;
}

/* RES_STARVE_CHECK: Check if token-starved.  Op0 = sid */
static int cmd_res_starve_check(const trust_cmd_entry_t *cmd,
				trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	trust_subject_t subj;
	int ret;

	ret = trust_tlb_lookup(sid, &subj);
	if (ret) {
		result->status = -ENOENT;
		return -ENOENT;
	}

	result->status = 0;
	result->value = (u64)subj.tokens.starved;
	return 0;
}

/* RES_SET_RATE: Set regen rate.  Op0 = sid, imm = rate */
struct res_set_rate_ctx { u32 rate; };
static int _res_set_rate_cb(trust_subject_t *subj, void *data) {
	struct res_set_rate_ctx *c = data;
	subj->tokens.regen_rate = c->rate;
	return 0;
}
static int cmd_res_set_rate(const trust_cmd_entry_t *cmd,
			    trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	struct res_set_rate_ctx ctx = { .rate = (u32)cmd_get_imm(cmd) };
	int ret;

	ret = trust_tlb_modify(sid, _res_set_rate_cb, &ctx);
	if (ret) {
		result->status = -ENOENT;
		return -ENOENT;
	}

	result->status = 0;
	result->value = (u64)ctx.rate;
	return 0;
}

/* ========================================================================
 * LIFE family handlers (Family 4)
 * ======================================================================== */

/* LIFE_DIVIDE: Mitotic division.  Op0 = parent_id, Op1 = child_id */
static int cmd_life_divide(const trust_cmd_entry_t *cmd,
			   trust_cmd_result_t *result)
{
	u32 parent = cmd_get_subject(cmd, 0);
	u32 child = cmd_get_u32(cmd, 1);
	int ret;

	ret = trust_lifecycle_mitotic_divide(parent, child);
	if (ret == 0) {
		trust_subject_t child_subj;
		if (trust_tlb_lookup(child, &child_subj) == 0)
			result->value = (u64)(u32)child_subj.lifecycle.max_score;
		else
			result->value = 0;
	}

	result->status = ret;
	return ret;
}

/* LIFE_COMBINE: Meiotic combination.  Op0 = subject_a, Op1 = subject_b */
static int cmd_life_combine(const trust_cmd_entry_t *cmd,
			    trust_cmd_result_t *result)
{
	u32 sa = cmd_get_subject(cmd, 0);
	u32 sb = cmd_get_u32(cmd, 1);
	int ret;

	ret = trust_lifecycle_meiotic_combine(sa, sb);
	if (ret == 0) {
		trust_subject_t subj_a, subj_b;
		if (trust_tlb_lookup(sa, &subj_a) == 0 &&
		    trust_tlb_lookup(sb, &subj_b) == 0)
			result->value = (u64)(u32)(subj_a.trust_score < subj_b.trust_score ?
						   subj_a.trust_score : subj_b.trust_score);
	}

	result->status = ret;
	return ret;
}

/* LIFE_RELEASE: Release meiotic combination.  Op0 = subject_a, Op1 = subject_b */
static int cmd_life_release(const trust_cmd_entry_t *cmd,
			    trust_cmd_result_t *result)
{
	u32 sa = cmd_get_subject(cmd, 0);
	u32 sb = cmd_get_u32(cmd, 1);

	trust_lifecycle_meiotic_release(sa, sb);
	result->status = 0;
	result->value = 0;
	return 0;
}

/* LIFE_APOPTOSIS: Initiate controlled death.  Op0 = subject_id */
static int cmd_life_apoptosis(const trust_cmd_entry_t *cmd,
			      trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	int ret;

	ret = trust_lifecycle_apoptosis(sid);
	result->status = ret;
	result->value = 0;
	return ret;
}

/* LIFE_IMMUNE_EVAL: Evaluate immune status.  Op0 = subject_id */
static int cmd_life_immune_eval(const trust_cmd_entry_t *cmd,
				trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	int ret;

	ret = trust_immune_evaluate(sid);
	result->status = 0;
	result->value = (u64)ret;  /* TRUST_IMMUNE_* status */
	return 0;
}

/* LIFE_QUARANTINE: Quarantine subject.  Op0 = sid, Op1 = reason */
static int cmd_life_quarantine(const trust_cmd_entry_t *cmd,
			       trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u32 reason = cmd_get_u32(cmd, 1);
	int ret;

	ret = trust_immune_quarantine(sid, reason);
	result->status = ret;
	result->value = 0;
	return ret;
}

/* LIFE_RELEASE_Q: Release from quarantine.  Op0 = subject_id */
static int cmd_life_release_q(const trust_cmd_entry_t *cmd,
			      trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	int ret;

	ret = trust_immune_release_quarantine(sid);
	result->status = ret;
	result->value = 0;
	return ret;
}

/* LIFE_GENERATION: Query generation depth.  Op0 = subject_id */
static int cmd_life_generation(const trust_cmd_entry_t *cmd,
			       trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	trust_subject_t subj;
	int ret;

	ret = trust_tlb_lookup(sid, &subj);
	if (ret) {
		result->status = -ENOENT;
		return -ENOENT;
	}

	result->status = 0;
	result->value = (u64)subj.lifecycle.generation;
	return 0;
}

/* ========================================================================
 * META family handlers (Family 5)
 * ======================================================================== */

/* META_FLUSH: Flush TLB cache.  No operands. */
static int cmd_meta_flush(const trust_cmd_entry_t *cmd,
			  trust_cmd_result_t *result)
{
	(void)cmd;
	trust_tlb_flush();
	result->status = 0;
	result->value = 0;
	return 0;
}

/* META_AUDIT: Emit audit entry.  Op0 = sid, Op1 = action_type */
static int cmd_meta_audit(const trust_cmd_entry_t *cmd,
			  trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u32 action = cmd_get_u32(cmd, 1);
	trust_subject_t subj;

	if (trust_tlb_lookup(sid, &subj) == 0) {
		trust_fbc_audit(sid, action, subj.trust_score,
				subj.trust_score, subj.capabilities,
				subj.capabilities);
	}

	result->status = 0;
	result->value = 0;
	return 0;
}

/* META_REPARTITION: Repartition authority boundaries.  No operands. */
static int cmd_meta_repartition(const trust_cmd_entry_t *cmd,
				trust_cmd_result_t *result)
{
	(void)cmd;
	trust_fbc_repartition();
	result->status = 0;
	result->value = 0;
	return 0;
}

/* META_GET_SUBJECT: Get full subject.  Op0 = sid.  Returns subject_id in value. */
static int cmd_meta_get_subject(const trust_cmd_entry_t *cmd,
				trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	trust_subject_t subj;
	int ret;

	ret = trust_tlb_lookup(sid, &subj);
	if (ret) {
		result->status = -ENOENT;
		result->value = 0;
		return -ENOENT;
	}

	/* Return composite: score in low 32, caps in high 32 */
	result->status = 0;
	result->value = ((u64)subj.capabilities << 32) |
			(u64)(u32)subj.trust_score;
	return 0;
}

/* META_GET_CHROMOSOME: Get chromosome checksum.  Op0 = sid */
static int cmd_meta_get_chromosome(const trust_cmd_entry_t *cmd,
				   trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	trust_subject_t subj;
	int ret;

	ret = trust_tlb_lookup(sid, &subj);
	if (ret) {
		result->status = -ENOENT;
		return -ENOENT;
	}

	result->status = 0;
	result->value = (u64)trust_chromosome_checksum(&subj.chromosome);
	return 0;
}

/* META_GET_SEX: Get XY sex determination.  Op0 = sid */
static int cmd_meta_get_sex(const trust_cmd_entry_t *cmd,
			    trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	trust_subject_t subj;
	int ret;

	ret = trust_tlb_lookup(sid, &subj);
	if (ret) {
		result->status = -ENOENT;
		return -ENOENT;
	}

	result->status = 0;
	result->value = (u64)subj.chromosome.sex;
	return 0;
}

/* META_IMMUNE_STATUS: Get immune status.  Op0 = sid */
static int cmd_meta_immune_status(const trust_cmd_entry_t *cmd,
				  trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	trust_subject_t subj;
	int ret;

	ret = trust_tlb_lookup(sid, &subj);
	if (ret) {
		result->status = -ENOENT;
		return -ENOENT;
	}

	/* Pack status and suspicious count */
	result->status = 0;
	result->value = ((u64)subj.immune.suspicious_actions << 8) |
			(u64)subj.immune.status;
	return 0;
}

/* META_TRC_STATE: Get TRC state machine.  Op0 = sid */
static int cmd_meta_trc_state(const trust_cmd_entry_t *cmd,
			      trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	trust_subject_t subj;
	int ret;

	ret = trust_tlb_lookup(sid, &subj);
	if (ret) {
		result->status = -ENOENT;
		return -ENOENT;
	}

	/* Pack TRC state: state | resistance | cost_multiplier | threshold_bias */
	result->status = 0;
	result->value = ((u64)subj.trc.state) |
			((u64)subj.trc.resistance << 8) |
			((u64)subj.trc.cost_multiplier << 24) |
			((u64)(u32)subj.trc.threshold_bias << 40);
	return 0;
}

/* ========================================================================
 * VEC family handlers (Family 6)
 *
 * The classic fixed-format wire carries VEC subjects packed as u64
 * operands (one subject per low-32-bits slot) plus an auxiliary param
 * slot.  The VARLEN path delivers a sorted subject array already
 * decoded by the dispatcher's varlen walker; the shared `cmd_vec_run`
 * below takes the decoded array and calls trust_isa_exec_vec().
 *
 * Wire format (classic fixed, nops < 15):
 *   op[0..nops-2] = subject_ids   (one per 64-bit slot, low 32 bits)
 *   op[nops-1]    = aux param      (raw u64, op-specific meaning)
 *   imm           = unused (count is implied by nops)
 *
 * Fallback semantics: if nops is 0 we treat it as count=0 and return 0
 * (a no-op).  If nops is 15 the classic fixed path cannot represent
 * the count — callers must use VARLEN, we return -E2BIG so userspace
 * can lower.
 * ======================================================================== */

static int cmd_vec_run(u32 op, const u32 *subjects, u32 count,
		       u64 param, trust_cmd_result_t *result)
{
	u64 *out_bitmap = NULL;
	u32 out_len = 0;
	int ret;

	if (count == 0) {
		result->status = 0;
		result->value = 0;
		return 0;
	}

	/* Bitmap is returned via result->value when count <= 64; wider
	 * batches still set the first-64 bits there (callers who need
	 * more must use the VARLEN path which returns the full bitmap
	 * through the result extension — currently trimmed to first
	 * word on the classic path).
	 */
	{
		u64 scratch[1] = { 0 };
		u64 *words;
		u32 nwords = (count + 63U) / 64U;
		if (nwords <= 1) {
			words = scratch;
			out_len = 1;
		} else {
			words = kcalloc(nwords, sizeof(u64), GFP_KERNEL);
			if (!words) {
				result->status = -ENOMEM;
				return -ENOMEM;
			}
			out_len = nwords;
		}

		ret = trust_isa_exec_vec(op, subjects, count, param,
					 words, out_len);
		out_bitmap = words;

		if (ret < 0) {
			result->status = ret;
			result->value = 0;
			if (out_bitmap != scratch)
				kfree(out_bitmap);
			return ret;
		}

		/* Surface the count in `value` but keep the first bitmap
		 * word readable in the low 64 bits via a union-ish trick:
		 * if we have only one word, put that in value directly;
		 * otherwise return the count and drop the higher words. */
		if (nwords == 1)
			result->value = words[0];
		else
			result->value = words[0];

		result->status = 0;
		if (out_bitmap != scratch)
			kfree(out_bitmap);
		trust_stats_record_vec_hit(count);
		/* Update predicate register with the bitmap-count so the
		 * next predicated op can branch on "any matches". */
		trust_isa_pred_set((int64_t)ret);
		return ret;
	}
}

/*
 * cmd_vec_from_classic - Extract subject array from a classic
 * trust_cmd_entry_t and dispatch via cmd_vec_run().
 *
 * The classic wire carries at most 15 64-bit operands, so we can
 * batch up to 14 subjects here (one slot is reserved for the
 * aux param).  Larger batches MUST use VARLEN — we return -E2BIG.
 */
static int cmd_vec_from_classic(const trust_cmd_entry_t *cmd,
				trust_cmd_result_t *result)
{
	u32 op = TRUST_CMD_OPCODE(cmd->instruction);
	u32 nops = cmd->operand_count;
	u32 i, count;
	u64 param;
	u32 subjects_stack[TRUST_CMD_MAX_OPERANDS];

	if (nops == 0) {
		/* VEC op with no operands: treat as degenerate no-op
		 * so the caller's stats counter still fires but the
		 * underlying VEC path isn't invoked. */
		result->status = 0;
		result->value = 0;
		return 0;
	}

	/* Last operand is the aux param; everything else is subject ids. */
	count = nops - 1;
	param = cmd->operands[nops - 1] & TRUST_OP_VAL_MASK;

	if (count > TRUST_CMD_MAX_OPERANDS - 1) {
		result->status = -E2BIG;
		return -E2BIG;
	}

	for (i = 0; i < count; i++)
		subjects_stack[i] = (u32)(cmd->operands[i] & TRUST_OP_VAL_MASK);

	return cmd_vec_run(op, subjects_stack, count, param, result);
}

/* ========================================================================
 * FUSED family handlers (Family 7)
 *
 * Wire: op0..op2 = three 64-bit operands; imm = 16 bits.  The fused
 * handlers in trust_fused.c take (op0, op1, op2, imm, *out) directly;
 * we just unwrap the typed tags and forward.
 * ======================================================================== */

static int cmd_fused_run(const trust_cmd_entry_t *cmd,
			 trust_cmd_result_t *result)
{
	u32 op = TRUST_CMD_OPCODE(cmd->instruction);
	u64 op0 = (cmd->operand_count > 0) ? cmd->operands[0] & TRUST_OP_VAL_MASK : 0;
	u64 op1 = (cmd->operand_count > 1) ? cmd->operands[1] & TRUST_OP_VAL_MASK : 0;
	u64 op2 = (cmd->operand_count > 2) ? cmd->operands[2] & TRUST_OP_VAL_MASK : 0;
	u16 imm = (u16)TRUST_CMD_IMM(cmd->instruction);
	u64 out_val = 0;
	int ret;

	ret = trust_isa_exec_fused(op, op0, op1, op2, imm, &out_val);
	result->status = ret;
	result->value = (ret == 0) ? out_val : 0;
	if (ret == 0) {
		trust_stats_record_fused_hit();
		/* ALU-flow: expose the output to the predicate reg. */
		trust_isa_pred_set((int64_t)(u64)out_val);
	}
	return ret;
}

/* ========================================================================
 * Dispatch table: [family][opcode] -> handler
 *
 * NULL entries are unsupported operations (return -ENOSYS).
 *
 * Note: the 2D table only covers opcodes 0..7 per family (the classic
 * TRUST_CMD_MAX_OPCODES width).  Families 6 (VEC) and 7 (FUSED) have
 * more opcodes (VEC goes to 9, FUSED to 4) but only ops 0..4/5 fit
 * cleanly in the table.  The dispatcher routes VEC/FUSED via the
 * family-level fan-out in trust_cmd_submit() so opcodes 0..15 all
 * reach the right helper regardless of table width.
 * ======================================================================== */

static trust_cmd_handler_t dispatch_table[TRUST_STAT_FAMILY_SLOTS][TRUST_CMD_MAX_OPCODES] = {
	[TRUST_FAMILY_AUTH] = {
		[AUTH_OP_MINT]      = cmd_auth_mint,
		[AUTH_OP_BURN]      = cmd_auth_burn,
		[AUTH_OP_CONSUME]   = cmd_auth_consume,
		[AUTH_OP_VERIFY]    = cmd_auth_verify,
		[AUTH_OP_FENCE]     = cmd_auth_fence,
		[AUTH_OP_NONCE]     = cmd_auth_nonce,
		[AUTH_OP_CHAIN_LEN] = cmd_auth_chain_len,
		[AUTH_OP_ROTATE]    = cmd_auth_rotate,
	},
	[TRUST_FAMILY_TRUST] = {
		[TRUST_OP_CHECK]     = cmd_trust_check,
		[TRUST_OP_SCORE]     = cmd_trust_score,
		[TRUST_OP_RECORD]    = cmd_trust_record,
		[TRUST_OP_THRESHOLD] = cmd_trust_threshold,
		[TRUST_OP_DECAY]     = cmd_trust_decay,
		[TRUST_OP_TRANSLATE] = cmd_trust_translate,
		[TRUST_OP_ELEVATE]   = cmd_trust_elevate,
		[TRUST_OP_DEMOTE]    = cmd_trust_demote,
	},
	[TRUST_FAMILY_GATE] = {
		[GATE_OP_CHECK]        = cmd_gate_check,
		[GATE_OP_RAISE]        = cmd_gate_raise,
		[GATE_OP_LOWER]        = cmd_gate_lower,
		[GATE_OP_HYST]         = cmd_gate_hyst,
		[GATE_OP_TRANSLATE]    = cmd_gate_translate,
		[GATE_OP_DOMAIN_ENTER] = cmd_gate_domain_enter,
		[GATE_OP_DOMAIN_LEAVE] = cmd_gate_domain_leave,
		[GATE_OP_BRIDGE]       = cmd_gate_bridge,
	},
	[TRUST_FAMILY_RES] = {
		[RES_OP_BALANCE]      = cmd_res_balance,
		[RES_OP_BURN]         = cmd_res_burn,
		[RES_OP_MINT]         = cmd_res_mint,
		[RES_OP_XFER]         = cmd_res_xfer,
		[RES_OP_COST]         = cmd_res_cost,
		[RES_OP_REGEN]        = cmd_res_regen,
		[RES_OP_STARVE_CHECK] = cmd_res_starve_check,
		[RES_OP_SET_RATE]     = cmd_res_set_rate,
	},
	[TRUST_FAMILY_LIFE] = {
		[LIFE_OP_DIVIDE]      = cmd_life_divide,
		[LIFE_OP_COMBINE]     = cmd_life_combine,
		[LIFE_OP_RELEASE]     = cmd_life_release,
		[LIFE_OP_APOPTOSIS]   = cmd_life_apoptosis,
		[LIFE_OP_IMMUNE_EVAL] = cmd_life_immune_eval,
		[LIFE_OP_QUARANTINE]  = cmd_life_quarantine,
		[LIFE_OP_RELEASE_Q]   = cmd_life_release_q,
		[LIFE_OP_GENERATION]  = cmd_life_generation,
	},
	[TRUST_FAMILY_META] = {
		[META_OP_FLUSH]          = cmd_meta_flush,
		[META_OP_AUDIT]          = cmd_meta_audit,
		[META_OP_REPARTITION]    = cmd_meta_repartition,
		[META_OP_GET_SUBJECT]    = cmd_meta_get_subject,
		[META_OP_GET_CHROMOSOME] = cmd_meta_get_chromosome,
		[META_OP_GET_SEX]        = cmd_meta_get_sex,
		[META_OP_IMMUNE_STATUS]  = cmd_meta_immune_status,
		[META_OP_TRC_STATE]      = cmd_meta_trc_state,
	},
};

/* ========================================================================
 * Command buffer parser and executor
 * ======================================================================== */

/*
 * parse_one_command - Parse a single command from the wire buffer.
 *
 * @buf:      Pointer into kernel copy of command buffer.
 * @remaining: Bytes remaining in buffer from this point.
 * @entry:    Output parsed command entry.
 *
 * Returns number of bytes consumed, or negative error.
 */
static int parse_one_command(const u8 *buf, u32 remaining,
			     trust_cmd_entry_t *entry)
{
	u32 nops, wire_size;
	u32 i;

	if (remaining < sizeof(u32))
		return -EINVAL;

	memcpy(&entry->instruction, buf, sizeof(u32));
	nops = TRUST_CMD_NOPS(entry->instruction);

	if (nops > TRUST_CMD_MAX_OPERANDS)
		return -EINVAL;

	wire_size = trust_cmd_wire_size(nops);
	if (remaining < wire_size)
		return -EINVAL;

	entry->operand_count = nops;
	for (i = 0; i < nops; i++)
		memcpy(&entry->operands[i], buf + sizeof(u32) + i * sizeof(u64),
		       sizeof(u64));

	return (int)wire_size;
}

/* ==================================================================
 * LEB128 varint decode (local; matches libtrust encoder in
 * libtrust_batch.c varint_encode_u64()).  Max 10 bytes.
 * ================================================================== */

static int varint_decode_u64(const u8 *buf, u32 avail, u64 *out)
{
	u64 v = 0;
	u32 shift = 0, i = 0;
	while (i < avail) {
		u8 b = buf[i++];
		v |= ((u64)(b & 0x7FU)) << shift;
		if (!(b & 0x80U)) {
			*out = v;
			return (int)i;
		}
		shift += 7;
		if (shift >= 64)
			return -1;
	}
	return 0;
}

static inline int64_t zigzag_decode_s64(u64 v)
{
	return (int64_t)((v >> 1) ^ -(int64_t)(v & 1));
}

/*
 * parse_varlen_vec_op - Decode a VEC instruction from the libtrust
 * VARLEN wire format (see libtrust/libtrust_batch.c:emit_vec_op()).
 *
 * Wire:
 *   u32 instr
 *   [if TRUST_CMD_FLAG_CONDITIONAL in instr.flags AND VARLEN]: u8 pred tag
 *   [if nops == TRUST_VEC_NOPS_SENTINEL (0xF)]: varint count
 *   u32 base subject_id
 *   (count-1) * varint zigzag(signed delta)
 *
 * @buf/remaining: same meaning as parse_one_command.
 * @subjects:      output array, caller-allocated, length >= *count_out.
 * @max_subjects:  capacity of @subjects.
 * @count_out:     decoded subject count.
 * @param_out:     aux param (unused by VEC VARLEN wire; zero).
 * @instr_out:     decoded instruction word.
 * @pred_out:      predicate tag byte if present; 0 if absent.
 *
 * Returns bytes consumed, or -errno.
 */
static int parse_varlen_vec_op(const u8 *buf, u32 remaining,
			       u32 *subjects, u32 max_subjects,
			       u32 *count_out, u32 *instr_out,
			       u8 *pred_out)
{
	u32 off = 0;
	u32 instr;
	u32 nops_field;
	u32 count;
	u64 v;
	int n;
	u32 base;
	u32 prev;
	u32 i;

	if (remaining < sizeof(u32))
		return -EINVAL;

	memcpy(&instr, buf + off, sizeof(u32));
	off += sizeof(u32);

	if (pred_out) *pred_out = 0;
	if (TRUST_CMD_FLAGS(instr) & TRUST_CMD_FLAG_CONDITIONAL) {
		if (off + 1 > remaining)
			return -EINVAL;
		if (pred_out) *pred_out = buf[off];
		off += 1;
	}

	nops_field = TRUST_CMD_NOPS(instr);
	if (nops_field == TRUST_VEC_NOPS_SENTINEL) {
		n = varint_decode_u64(buf + off, remaining - off, &v);
		if (n <= 0)
			return -EINVAL;
		off += (u32)n;
		if (v == 0 || v > TRUST_ISA_BATCH_MAX_COUNT)
			return -EINVAL;
		count = (u32)v;
	} else {
		count = nops_field;
		if (count == 0)
			return -EINVAL;
	}

	if (count > max_subjects)
		return -ENOSPC;

	/* Base subject id (full u32). */
	if (off + sizeof(u32) > remaining)
		return -EINVAL;
	memcpy(&base, buf + off, sizeof(u32));
	off += sizeof(u32);
	subjects[0] = base;
	prev = base;

	for (i = 1; i < count; i++) {
		int64_t d;
		n = varint_decode_u64(buf + off, remaining - off, &v);
		if (n <= 0)
			return -EINVAL;
		off += (u32)n;
		d = zigzag_decode_s64(v);
		subjects[i] = (u32)((int64_t)prev + d);
		prev = subjects[i];
	}

	*instr_out = instr;
	*count_out = count;
	return (int)off;
}

/*
 * dispatch_fused - Route a FUSED family instruction to trust_fused.c.
 *
 * The FUSED table has opcodes 0..4 (FUSED_OP_MAX=5).  We don't go
 * through dispatch_table[] because FUSED_OP_MAX exceeds
 * TRUST_CMD_MAX_OPCODES on some future expansions; keep dispatch
 * direct.
 */
static int dispatch_fused(const trust_cmd_entry_t *entry,
			  trust_cmd_result_t *result)
{
	u32 opcode = TRUST_CMD_OPCODE(entry->instruction);
	if (opcode >= FUSED_OP_MAX) {
		result->status = -ENOSYS;
		return -ENOSYS;
	}
	return cmd_fused_run(entry, result);
}

/*
 * dispatch_vec_classic - Route a classic-format VEC instruction.
 *
 * Opcodes 0..9 (VEC_OP_MAX).  Bypasses dispatch_table[] for the same
 * reason as FUSED.
 */
static int dispatch_vec_classic(const trust_cmd_entry_t *entry,
				trust_cmd_result_t *result)
{
	u32 opcode = TRUST_CMD_OPCODE(entry->instruction);
	if (opcode >= VEC_OP_MAX) {
		result->status = -ENOSYS;
		return -ENOSYS;
	}
	return cmd_vec_from_classic(entry, result);
}

/*
 * trust_cmd_submit - Process a command buffer submitted via ioctl.
 *
 * @arg: Userspace pointer to trust_ioc_cmd_submit_t.
 *
 * Returns 0 on success (with results written back), or negative errno.
 */
int trust_cmd_submit(const trust_ioc_cmd_submit_t __user *arg)
{
	trust_ioc_cmd_submit_t submit;
	trust_cmd_buffer_t header;
	trust_cmd_batch_result_t batch_result;
	trust_cmd_result_t *results = NULL;
	u8 *cmd_buf = NULL;
	u32 offset, i;
	u64 chain_value = 0;
	int prev_status = 0;
	int ret = 0;

	/* Copy submission descriptor from userspace */
	if (copy_from_user(&submit, arg, sizeof(submit)))
		return -EFAULT;

	/* Sanity check buffer sizes */
	if (submit.cmd_buf_size < TRUST_CMD_HEADER_SIZE ||
	    submit.cmd_buf_size > TRUST_CMD_MAX_BUF_SIZE)
		return -EINVAL;

	/* Copy command buffer header from userspace */
	if (copy_from_user(&header,
			   (void __user *)(unsigned long)submit.cmd_buffer,
			   sizeof(header)))
		return -EFAULT;

	/* Validate header */
	if (header.magic != TRUST_CMD_MAGIC) {
		pr_warn_ratelimited("trust_cmd: bad magic 0x%08x (expected 0x%08x)\n",
			header.magic, TRUST_CMD_MAGIC);
		return -EINVAL;
	}

	/* Session 32: version 2 introduced for VARLEN batches.  Accept
	 * either: classic (v1) or ISA-extended (v2). */
	if (header.version != TRUST_CMD_VERSION &&
	    header.version != TRUST_ISA_VERSION) {
		pr_warn_ratelimited("trust_cmd: unsupported version %u\n", header.version);
		return -EINVAL;
	}

	if (header.cmd_count == 0)
		return 0;

	if (header.cmd_count > TRUST_CMD_MAX_BATCH) {
		pr_warn_ratelimited("trust_cmd: too many commands %u (max %u)\n",
			header.cmd_count, TRUST_CMD_MAX_BATCH);
		return -EINVAL;
	}

	if (header.total_size != submit.cmd_buf_size) {
		pr_warn_ratelimited("trust_cmd: size mismatch header=%u submit=%u\n",
			header.total_size, submit.cmd_buf_size);
		return -EINVAL;
	}

	/* Check result buffer can hold all results */
	if (submit.res_buf_size < trust_cmd_result_buf_size(header.cmd_count))
		return -EINVAL;

	/* Allocate kernel buffers */
	cmd_buf = kvmalloc(submit.cmd_buf_size, GFP_KERNEL);
	if (!cmd_buf)
		return -ENOMEM;

	results = kvmalloc_array(header.cmd_count, sizeof(trust_cmd_result_t),
				 GFP_KERNEL | __GFP_ZERO);
	if (!results) {
		kvfree(cmd_buf);
		return -ENOMEM;
	}

	/* Copy full command buffer from userspace */
	if (copy_from_user(cmd_buf,
			   (void __user *)(unsigned long)submit.cmd_buffer,
			   submit.cmd_buf_size)) {
		ret = -EFAULT;
		goto out;
	}

	/* Initialize batch result */
	memset(&batch_result, 0, sizeof(batch_result));

	/* Detect VARLEN wire format up front. */
	{
		int is_varlen = (header.flags & TRUST_CMDBUF_VARLEN) ? 1 : 0;
		u64 t_start_ns = ktime_get_ns();
		u32 varlen_bytes = is_varlen ? submit.cmd_buf_size : 0;

		trust_stats_record_cmdbuf_in(submit.cmd_buf_size, varlen_bytes);

	/* Iterate and dispatch commands */
	offset = TRUST_CMD_HEADER_SIZE;

	/* Session 34 R34: BATCH context entry.  Nested ops (a handler
	 * that loops back into trust_cmd_submit on the same CPU) will
	 * see TRUST_CTX_BATCH from trust_current_context() so meta
	 * table rows gated to TRUST_CTX_BATCH are permitted here and
	 * ONLY here.  The companion _exit() call sits on both success
	 * and failure paths below (see goto writeback / atomic_fail). */
	trust_ctx_batch_enter();

	/* Reset per-CPU predicate register AFTER pinning the CPU via
	 * trust_ctx_batch_enter() (migrate_disable).  If we reset before
	 * pinning, a migration between reset and the first dispatched
	 * command would let the new CPU's stale predicate register from
	 * a prior batch leak into this batch's predicated instructions. */
	trust_isa_pred_reset();

	for (i = 0; i < header.cmd_count; i++) {
		trust_cmd_entry_t entry;
		trust_cmd_handler_t handler;
		u32 family, opcode, flags;
		int consumed;
		u8 varlen_pred_tag = 0;
		u32 *vec_subjects = NULL;
		u32 vec_count = 0;
		int is_varlen_vec = 0;

		/* --- Parse phase ---
		 *
		 * VARLEN path: peek at the instruction word to decide
		 * whether this is a VEC op (variable-length payload)
		 * or a classic fixed-format op nested inside the
		 * varlen buffer.
		 */
		if (is_varlen) {
			u32 peek_instr;
			u32 peek_family;

			if (submit.cmd_buf_size - offset < sizeof(u32)) {
				pr_warn_ratelimited("trust_cmd: varlen EOF at cmd %u offset %u\n",
					i, offset);
				results[i].status = -EINVAL;
				if (header.flags & TRUST_CMD_BUF_ATOMIC)
					goto atomic_fail;
				batch_result.commands_executed = i + 1;
				batch_result.commands_failed++;
				break;
			}
			memcpy(&peek_instr, cmd_buf + offset, sizeof(u32));
			peek_family = TRUST_CMD_FAMILY(peek_instr);

			if (peek_family == TRUST_CMD_FAMILY_VEC) {
				/* VEC: decode subjects into a scratch
				 * array allocated below. */
				u32 max_subj = TRUST_ISA_BATCH_MAX_COUNT;
				vec_subjects = kmalloc_array(max_subj,
							     sizeof(u32),
							     GFP_KERNEL);
				if (!vec_subjects) {
					results[i].status = -ENOMEM;
					if (header.flags & TRUST_CMD_BUF_ATOMIC)
						goto atomic_fail;
					batch_result.commands_executed++;
					batch_result.commands_failed++;
					continue;
				}
				consumed = parse_varlen_vec_op(
					cmd_buf + offset,
					submit.cmd_buf_size - offset,
					vec_subjects, max_subj,
					&vec_count, &entry.instruction,
					&varlen_pred_tag);
				if (consumed < 0) {
					pr_warn_ratelimited("trust_cmd: varlen VEC parse error cmd %u offset %u rc=%d\n",
						i, offset, consumed);
					kfree(vec_subjects);
					results[i].status = consumed;
					if (header.flags & TRUST_CMD_BUF_ATOMIC)
						goto atomic_fail;
					batch_result.commands_executed++;
					batch_result.commands_failed++;
					continue;
				}
				entry.operand_count = 0;
				is_varlen_vec = 1;
			} else {
				/* Non-VEC ops in a varlen buffer still use
				 * the classic fixed per-op layout (libtrust
				 * falls back to that for non-VEC ops). */
				consumed = parse_one_command(
					cmd_buf + offset,
					submit.cmd_buf_size - offset,
					&entry);
				if (consumed < 0) {
					pr_warn_ratelimited("trust_cmd: parse error varlen-classic cmd %u offset %u\n",
						i, offset);
					results[i].status = -EINVAL;
					if (header.flags & TRUST_CMD_BUF_ATOMIC)
						goto atomic_fail;
					batch_result.commands_executed = i + 1;
					batch_result.commands_failed++;
					break;
				}
			}
		} else {
			/* Classic path. */
			consumed = parse_one_command(cmd_buf + offset,
						     submit.cmd_buf_size - offset,
						     &entry);
			if (consumed < 0) {
				pr_warn_ratelimited("trust_cmd: parse error at cmd %u offset %u\n",
					i, offset);
				results[i].status = -EINVAL;
				if (header.flags & TRUST_CMD_BUF_ATOMIC)
					goto atomic_fail;
				batch_result.commands_executed = i + 1;
				batch_result.commands_failed++;
				break;
			}
		}

		offset += consumed;

		/* Extract instruction fields */
		family = TRUST_CMD_FAMILY(entry.instruction);
		opcode = TRUST_CMD_OPCODE(entry.instruction);
		flags  = TRUST_CMD_FLAGS(entry.instruction);

		/* --- Predicate bit (ISA v2):
		 *
		 * Top bit of the instruction word gates execution on the
		 * per-CPU predicate register (last ALU-style result).
		 * This is evaluated BEFORE family dispatch so skipped
		 * instructions are truly free (no handler call, no stat
		 * bump beyond the skip counter).
		 *
		 * The predicate bit overlaps family bits 31:28 when
		 * FAMILY spans 4 bits, so we only honor it for families
		 * <= 7 (those leave bit 31 clear when P=0).  Agent 1's
		 * authoritative trust_cmd.h will reserve this correctly.
		 */
		if (trust_isa_instr_is_predicated(entry.instruction)) {
			if (!trust_risc_eval_predicated(entry.instruction)) {
				if (is_varlen_vec && vec_subjects)
					kfree(vec_subjects);
				trust_stats_record_predicate_skip();
				results[i].status = 0;
				results[i].value = 0;
				batch_result.commands_executed++;
				batch_result.commands_succeeded++;
				continue;
			}
			/* Re-read family/opcode AFTER stripping the
			 * predicate prefix: bits 30:28 in the predicated
			 * encoding carry sense + cond code, so the
			 * "real" family for P=1 ops is... TBD by Agent 1.
			 * Session 32 scoped this out; we keep family as
			 * decoded and require Agent 1's enum to confirm
			 * the layout.
			 */
		}

		/* VARLEN-only: 1-byte predicate tag after instruction
		 * word (present when TRUST_CMD_FLAG_CONDITIONAL+VARLEN).
		 * A nonzero tag here is an ADDITIONAL pre-condition
		 * beyond the bit-31 predicate: if either fails, we
		 * skip.  Current semantics: treat any nonzero tag as
		 * "skip iff previous command failed" (legacy
		 * CONDITIONAL behavior).  A future revision can decode
		 * the TRUST_PRED_* bits properly.
		 */
		if (is_varlen_vec && varlen_pred_tag && prev_status < 0) {
			if (vec_subjects) kfree(vec_subjects);
			results[i].status = -ECANCELED;
			results[i].value = 0;
			batch_result.commands_executed++;
			batch_result.commands_failed++;
			continue;
		}

		/* CONDITIONAL: skip if previous command failed */
		if ((flags & TRUST_CMD_FLAG_CONDITIONAL) && prev_status < 0) {
			if (is_varlen_vec && vec_subjects)
				kfree(vec_subjects);
			results[i].status = -ECANCELED;
			results[i].value = 0;
			batch_result.commands_executed++;
			batch_result.commands_failed++;
			continue;
		}

		/* FENCE: memory barrier */
		if (flags & TRUST_CMD_FLAG_FENCE)
			smp_mb();

		/* CHAIN: inject previous output as first operand */
		if ((flags & TRUST_CMD_FLAG_CHAIN) && i > 0 && !is_varlen_vec) {
			/*
			 * Shift existing operands right by one and insert
			 * the chained value at position 0.  Not meaningful
			 * for VEC ops (their operands are a subject array,
			 * not a per-op value slot) so we skip it there.
			 */
			if (entry.operand_count < TRUST_CMD_MAX_OPERANDS) {
				u32 j;
				for (j = entry.operand_count; j > 0; j--)
					entry.operands[j] = entry.operands[j - 1];
				entry.operands[0] = TRUST_CMD_OPERAND(
					TRUST_OP_SUBJECT, chain_value);
				entry.operand_count++;
			} else {
				pr_debug("trust_cmd: CHAIN flag on cmd %u dropped: "
					 "operand_count already at max (%u)\n",
					 i, TRUST_CMD_MAX_OPERANDS);
			}
		}

		/* --- Family fan-out ---
		 *
		 * Families 0-5: dispatch via the 2D table.
		 * Family 6 (VEC): varlen path calls trust_isa_exec_vec
		 *                 directly; classic path uses
		 *                 dispatch_vec_classic.
		 * Family 7 (FUSED): always via dispatch_fused.
		 */
		if (family >= TRUST_STAT_FAMILY_SLOTS) {
			if (is_varlen_vec && vec_subjects)
				kfree(vec_subjects);
			results[i].status = -ENOSYS;
			prev_status = -ENOSYS;
			batch_result.commands_executed++;
			batch_result.commands_failed++;
			trust_stats_record_scalar_fallback();
			if (header.flags & TRUST_CMD_BUF_ATOMIC)
				goto atomic_fail;
			continue;
		}

		trust_stats_record_dispatch(family);

		if (family == TRUST_CMD_FAMILY_VEC && is_varlen_vec) {
			/* VARLEN VEC: decoded subjects directly into
			 * vec_subjects.  Param is not carried in the VEC
			 * varlen wire (libtrust doesn't emit one; aux
			 * params are embedded in `imm` or the per-op
			 * instruction fields).  Derive param from imm. */
			u64 vec_param = (u64)TRUST_CMD_IMM(entry.instruction);
			results[i].status = 0;
			results[i].value = 0;
			prev_status = cmd_vec_run(opcode, vec_subjects,
						  vec_count, vec_param,
						  &results[i]);
			kfree(vec_subjects);
			vec_subjects = NULL;
			chain_value = results[i].value;
			batch_result.commands_executed++;
			if (prev_status < 0) {
				batch_result.commands_failed++;
				if (header.flags & TRUST_CMD_BUF_ATOMIC)
					goto atomic_fail;
			} else {
				batch_result.commands_succeeded++;
			}
			continue;
		}

		if (family == TRUST_CMD_FAMILY_VEC) {
			/* Classic-format VEC (nops-packed subjects). */
			results[i].status = 0;
			results[i].value = 0;
			prev_status = dispatch_vec_classic(&entry, &results[i]);
			chain_value = results[i].value;
			batch_result.commands_executed++;
			if (prev_status < 0) {
				batch_result.commands_failed++;
				if (header.flags & TRUST_CMD_BUF_ATOMIC)
					goto atomic_fail;
			} else {
				batch_result.commands_succeeded++;
			}
			continue;
		}

		if (family == TRUST_CMD_FAMILY_FUSED) {
			results[i].status = 0;
			results[i].value = 0;
			prev_status = dispatch_fused(&entry, &results[i]);
			chain_value = results[i].value;
			batch_result.commands_executed++;
			if (prev_status < 0) {
				batch_result.commands_failed++;
				if (header.flags & TRUST_CMD_BUF_ATOMIC)
					goto atomic_fail;
			} else {
				batch_result.commands_succeeded++;
			}
			continue;
		}

		/* Legacy families 0..5.
		 *
		 * Opcodes with bit 3 set (>= 8) on AUTH/TRUST/RES/LIFE are
		 * the "fused bit" form shipped by libtrust Session 32
		 * (TRUST_OPCODE_FUSED_BIT = 0x8 in trust/include/trust_isa.h).
		 * Reroute those to the FUSED family dispatcher so
		 * AUTH_OP_VERIFY_THEN_GATE (family=AUTH, opcode=0x9)
		 * reaches trust_isa_exec_fused(FUSED_OP_AUTH_GATE).
		 */
		if (opcode >= 0x8) {
			u32 fused_op = FUSED_OP_MAX;  /* invalid by default */
			if (family == TRUST_FAMILY_AUTH) {
				if (opcode == 0x9)        /* VERIFY_THEN_GATE */
					fused_op = FUSED_OP_AUTH_GATE;
				else if (opcode == 0x8)   /* MINT_THEN_BURN */
					fused_op = FUSED_OP_AUTH_GATE; /* best mapping */
			} else if (family == TRUST_FAMILY_TRUST) {
				if (opcode == 0x8)        /* CHECK_AND_RECORD */
					fused_op = FUSED_OP_CHECK_RECORD;
				else if (opcode == 0x9)   /* THRESH_ELEVATE */
					fused_op = FUSED_OP_DECAY_CHECK;
			} else if (family == TRUST_FAMILY_RES) {
				if (opcode == 0x8)        /* BURN_THEN_REGEN */
					fused_op = FUSED_OP_BURN_AUDIT;
			} else if (family == TRUST_FAMILY_LIFE) {
				if (opcode == 0x8)        /* DIVIDE_THEN_GATE */
					fused_op = FUSED_OP_TRUST_XFER;
			}

			if (fused_op < FUSED_OP_MAX) {
				trust_cmd_entry_t fe = entry;
				/* Rewrite the instruction word so cmd_fused_run
				 * sees opcode=fused_op.  Family field is ignored
				 * by cmd_fused_run. */
				fe.instruction = (entry.instruction &
					~(TRUST_CMD_OPCODE_MASK | TRUST_CMD_FAMILY_MASK)) |
					((u32)TRUST_CMD_FAMILY_FUSED << TRUST_CMD_FAMILY_SHIFT) |
					((u32)fused_op << TRUST_CMD_OPCODE_SHIFT);
				results[i].status = 0;
				results[i].value = 0;
				/* Count as a FUSED dispatch (not the original
				 * family) so the stats accurately report what
				 * the hardware path actually executed. */
				trust_stats_record_dispatch(TRUST_CMD_FAMILY_FUSED);
				prev_status = dispatch_fused(&fe, &results[i]);
				chain_value = results[i].value;
				batch_result.commands_executed++;
				if (prev_status < 0) {
					batch_result.commands_failed++;
					if (header.flags & TRUST_CMD_BUF_ATOMIC)
						goto atomic_fail;
				} else {
					batch_result.commands_succeeded++;
				}
				continue;
			}

			/* No fused mapping for this (family, opcode) pair. */
			results[i].status = -ENOSYS;
			prev_status = -ENOSYS;
			batch_result.commands_executed++;
			batch_result.commands_failed++;
			trust_stats_record_scalar_fallback();
			if (header.flags & TRUST_CMD_BUF_ATOMIC)
				goto atomic_fail;
			continue;
		}

		/* Legacy families 0..5, opcode 0..7. */
		if (opcode >= TRUST_CMD_MAX_OPCODES) {
			results[i].status = -ENOSYS;
			prev_status = -ENOSYS;
			batch_result.commands_executed++;
			batch_result.commands_failed++;
			trust_stats_record_scalar_fallback();
			if (header.flags & TRUST_CMD_BUF_ATOMIC)
				goto atomic_fail;
			continue;
		}

		/* Session 34 R34: context-mask gate.
		 *
		 * Every opcode in trust_opcode_meta[] carries a bitmap of
		 * contexts in which it is permitted to run.  The default
		 * (TRUST_CTX_ALL) preserves pre-R34 behavior; restricted
		 * masks (e.g. META.DUMP excluded from INTERRUPT) cause
		 * dispatch to return -EPERM and bump the context-mask
		 * reject counter.  Unknown (family, opcode) pairs are
		 * permissive -- the existing -ENOSYS path above and
		 * below catches those. */
		{
			u32 ctx_bit = trust_current_context();
			if (!trust_opcode_context_ok((u16)family,
						     (u16)opcode, ctx_bit)) {
				results[i].status = -EPERM;
				results[i].value = 0;
				prev_status = -EPERM;
				batch_result.commands_executed++;
				batch_result.commands_failed++;
				trust_stats_record_context_mask_reject();
				/* Bump predicate-skip too so downstream
				 * CONDITIONAL ops see the failure in the
				 * exact same way they see other skips. */
				trust_stats_record_predicate_skip();
				if (header.flags & TRUST_CMD_BUF_ATOMIC)
					goto atomic_fail;
				continue;
			}
		}

		handler = dispatch_table[family][opcode];
		if (!handler) {
			results[i].status = -ENOSYS;
			prev_status = -ENOSYS;
			batch_result.commands_executed++;
			batch_result.commands_failed++;
			trust_stats_record_scalar_fallback();
			if (header.flags & TRUST_CMD_BUF_ATOMIC)
				goto atomic_fail;
			continue;
		}

		/* Dispatch */
		results[i].status = 0;
		results[i].value = 0;
		prev_status = handler(&entry, &results[i]);
		chain_value = results[i].value;

		/* Expose the result to the predicate register so the
		 * NEXT predicated instruction can branch on this op. */
		trust_isa_pred_set((int64_t)(u64)results[i].value);

		batch_result.commands_executed++;
		if (prev_status < 0) {
			batch_result.commands_failed++;
			if (header.flags & TRUST_CMD_BUF_ATOMIC)
				goto atomic_fail;
		} else {
			batch_result.commands_succeeded++;
		}

		/* AUDIT: emit audit event after execution */
		if (flags & TRUST_CMD_FLAG_AUDIT) {
			u32 sid = cmd_get_subject(&entry, 0);
			trust_subject_t subj;

			if (trust_tlb_lookup(sid, &subj) == 0) {
				trust_fbc_audit(sid,
						family * 16 + opcode,
						subj.trust_score,
						subj.trust_score,
						subj.capabilities,
						subj.capabilities);
			}
		}

		/* S74 Agent 5: Perturb tissue field at the subject's cell.
		 * Non-blocking; silently drops for unplaced subjects. Maps
		 * dispatch success/failure to activator/inhibitor deltas so
		 * the 32x32 morphogen grid retains short-term memory of
		 * where stress recently landed — read by the cortex via
		 * /sys/kernel/morphogen/dump. */
		trust_morphogen_perturb(cmd_get_subject(&entry, 0),
					prev_status < 0 ? TRUST_MORPHOGEN_EVENT_AUTHZ_DENY
							: TRUST_MORPHOGEN_EVENT_AUTHZ_ALLOW,
					1U);
	}

		trust_stats_record_dispatch_time(ktime_get_ns() - t_start_ns);
	}

	/* Session 34 R34: BATCH context exit (success path). */
	trust_ctx_batch_exit();

	goto writeback;

atomic_fail:
	/*
	 * ATOMIC mode: we cannot truly roll back kernel state changes
	 * that already happened (TLB writes, etc.), but we report the
	 * failure point so userspace knows exactly which command failed.
	 * A real hardware implementation would use journaling.
	 */
	pr_info("trust_cmd: atomic batch failed at cmd %u\n",
		batch_result.commands_executed - 1);
	/* Session 34 R34: BATCH context exit (atomic-fail path).  Must
	 * pair with the enter() above on every return path that exits
	 * the main loop, otherwise per-CPU BATCH depth leaks and a
	 * future call on the same CPU would see stale BATCH context. */
	trust_ctx_batch_exit();

writeback:
	/* Copy batch result header to userspace */
	if (copy_to_user((void __user *)(unsigned long)submit.result_buffer,
			 &batch_result, sizeof(batch_result))) {
		ret = -EFAULT;
		goto out;
	}

	/* Copy per-command results to userspace */
	if (copy_to_user((void __user *)(unsigned long)submit.result_buffer +
			 sizeof(batch_result),
			 results,
			 header.cmd_count * sizeof(trust_cmd_result_t))) {
		ret = -EFAULT;
		goto out;
	}

	ret = 0;

out:
	kvfree(results);
	kvfree(cmd_buf);
	return ret;
}

/* ======================================================================
 * TRUST_IOC_QUERY_CAPS handler
 *
 * Reports the same capability bitmap advertised at /sys/kernel/trust/caps,
 * plus a version tag and size limits, so libtrust can bump from returning
 * 0 to reporting VEC / FUSED / VARLEN availability.  The ioctl ABI is
 * additive: existing fields are preserved; any new bits live in
 * high-order positions of `features`.
 *
 * Layout of trust_ioc_query_caps_t (see trust/include/trust_isa.h):
 *   uint32_t version;       output: TRUST_ISA_VERSION
 *   uint32_t features;      output: TRUST_STAT_CAP_BIT_* bitmap (low bits)
 *   uint32_t max_batch_ops; output: kernel's max ops per batch
 *   uint32_t max_vec_count; output: kernel's max subjects per VEC
 * ====================================================================== */

struct trust_ioc_query_caps_compat {
	u32 version;
	u32 features;
	u32 max_batch_ops;
	u32 max_vec_count;
};

int trust_cmd_query_caps(void __user *arg)
{
	struct trust_ioc_query_caps_compat q;

	memset(&q, 0, sizeof(q));
	q.version       = TRUST_ISA_VERSION;
	q.features      = (u32)trust_stats_caps_bitmap();
	q.max_batch_ops = TRUST_CMD_MAX_BATCH;
	q.max_vec_count = TRUST_ISA_BATCH_MAX_COUNT;

	if (copy_to_user(arg, &q, sizeof(q)))
		return -EFAULT;
	return 0;
}
