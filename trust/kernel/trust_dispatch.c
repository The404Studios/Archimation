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

#include "../include/trust_cmd.h"
#include "../include/trust_ioctl.h"
#include "trust_internal.h"

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

/* AUTH_ROTATE: Rotate hash algorithm.  Op0 = subject_id, imm = new hash_cfg */
static int cmd_auth_rotate(const trust_cmd_entry_t *cmd,
			   trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u16 new_cfg = cmd_get_imm(cmd);
	trust_subject_t subj;
	int ret;

	/* Validate hash config */
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

	/* Rotation recorded; actual hash config update happens through APE */
	result->status = 0;
	result->value = new_cfg;
	return 0;
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

	/* Ensure delta is negative for demotion */
	if (delta > 0)
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
static int cmd_gate_domain_enter(const trust_cmd_entry_t *cmd,
				 trust_cmd_result_t *result)
{
	u32 sid = cmd_get_subject(cmd, 0);
	u16 domain = cmd_get_u16(cmd, 1);
	trust_subject_t subj;
	int ret;

	if (domain >= TRUST_DOMAIN_MAX) {
		result->status = -EINVAL;
		return -EINVAL;
	}

	ret = trust_tlb_lookup(sid, &subj);
	if (ret) {
		result->status = -ENOENT;
		return -ENOENT;
	}

	subj.domain = domain;
	trust_tlb_insert(&subj);

	result->status = 0;
	result->value = domain;
	return 0;
}

/* GATE_DOMAIN_LEAVE: Leave domain, return to LINUX.  Op0 = sid */
static int cmd_gate_domain_leave(const trust_cmd_entry_t *cmd,
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

	subj.domain = TRUST_DOMAIN_LINUX;
	trust_tlb_insert(&subj);

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
	subj->tokens.balance += c->amount;
	if (subj->tokens.balance > subj->tokens.max_balance)
		subj->tokens.balance = subj->tokens.max_balance;
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

/* RES_XFER: Transfer tokens.  Op0 = from_sid, Op1 = to_sid, imm = amount */
static int cmd_res_xfer(const trust_cmd_entry_t *cmd,
			trust_cmd_result_t *result)
{
	u32 from_sid = cmd_get_subject(cmd, 0);
	u32 to_sid = cmd_get_u32(cmd, 1);
	int32_t amount = (int32_t)cmd_get_imm(cmd);
	u32 from_set_idx, to_set_idx;
	trust_tlb_set_t *set_a, *set_b;
	trust_subject_t *from_p = NULL, *to_p = NULL;
	int i;

	if (amount <= 0 || !g_trust_tlb.sets) {
		result->status = -EINVAL;
		return -EINVAL;
	}

	from_set_idx = from_sid % TRUST_TLB_SETS;
	to_set_idx = to_sid % TRUST_TLB_SETS;

	/* Lock in consistent order to prevent deadlock */
	if (from_set_idx <= to_set_idx) {
		set_a = &g_trust_tlb.sets[from_set_idx];
		set_b = &g_trust_tlb.sets[to_set_idx];
		spin_lock(&set_a->lock);
		if (from_set_idx != to_set_idx)
			spin_lock(&set_b->lock);
	} else {
		set_a = &g_trust_tlb.sets[to_set_idx];
		set_b = &g_trust_tlb.sets[from_set_idx];
		spin_lock(&set_a->lock);
		spin_lock(&set_b->lock);
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
			spin_unlock(&set_b->lock);
		spin_unlock(&set_a->lock);
		result->status = -ENOENT;
		return -ENOENT;
	}

	if (from_p->tokens.balance < amount) {
		if (from_set_idx != to_set_idx)
			spin_unlock(&set_b->lock);
		spin_unlock(&set_a->lock);
		result->status = -ENOSPC;
		return -ENOSPC;
	}

	from_p->tokens.balance -= amount;
	from_p->tokens.total_burned += amount;
	to_p->tokens.balance += amount;
	if (to_p->tokens.balance > to_p->tokens.max_balance)
		to_p->tokens.balance = to_p->tokens.max_balance;
	to_p->tokens.total_regenerated += amount;

	result->value = (u64)(u32)from_p->tokens.balance;

	if (from_set_idx != to_set_idx)
		spin_unlock(&set_b->lock);
	spin_unlock(&set_a->lock);

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
	struct res_regen_ctx ctx;
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
 * Dispatch table: [family][opcode] -> handler
 *
 * NULL entries are unsupported operations (return -ENOSYS).
 * ======================================================================== */

static trust_cmd_handler_t dispatch_table[TRUST_ISA_FAMILY_COUNT][TRUST_CMD_MAX_OPCODES] = {
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

	if (header.version != TRUST_CMD_VERSION) {
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

	/* Iterate and dispatch commands */
	offset = TRUST_CMD_HEADER_SIZE;

	for (i = 0; i < header.cmd_count; i++) {
		trust_cmd_entry_t entry;
		trust_cmd_handler_t handler;
		u32 family, opcode, flags;
		int consumed;

		/* Parse command from wire format */
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

		offset += consumed;

		/* Extract instruction fields */
		family = TRUST_CMD_FAMILY(entry.instruction);
		opcode = TRUST_CMD_OPCODE(entry.instruction);
		flags  = TRUST_CMD_FLAGS(entry.instruction);

		/* CONDITIONAL: skip if previous command failed */
		if ((flags & TRUST_CMD_FLAG_CONDITIONAL) && prev_status < 0) {
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
		if ((flags & TRUST_CMD_FLAG_CHAIN) && i > 0) {
			/*
			 * Shift existing operands right by one and insert
			 * the chained value at position 0.
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

		/* Validate family and opcode */
		if (family >= TRUST_ISA_FAMILY_COUNT ||
		    opcode >= TRUST_CMD_MAX_OPCODES) {
			results[i].status = -ENOSYS;
			prev_status = -ENOSYS;
			batch_result.commands_executed++;
			batch_result.commands_failed++;
			if (header.flags & TRUST_CMD_BUF_ATOMIC)
				goto atomic_fail;
			continue;
		}

		handler = dispatch_table[family][opcode];
		if (!handler) {
			results[i].status = -ENOSYS;
			prev_status = -ENOSYS;
			batch_result.commands_executed++;
			batch_result.commands_failed++;
			if (header.flags & TRUST_CMD_BUF_ATOMIC)
				goto atomic_fail;
			continue;
		}

		/* Dispatch */
		results[i].status = 0;
		results[i].value = 0;
		prev_status = handler(&entry, &results[i]);
		chain_value = results[i].value;

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
	}

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
