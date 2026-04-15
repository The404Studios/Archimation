/*
 * trust_token.c - Token Economy (Metabolic Cost System)
 *
 * Implements the metabolic cost system from the Root of Authority paper:
 * every privileged action burns tokens (ATP analog). Tokens regenerate
 * over time, bounding the damage from any compromise.
 *
 * From Theorem 6 (Metabolic Fairness):
 *   Max damage bounded by C(E)/Cmin operations
 *   where C(E) = entity's token balance, Cmin = cheapest action cost
 *
 * Token state is embedded in trust_subject_t (stored in the TLB).
 * These functions operate directly on the embedded trust_token_state_t.
 *
 * Key properties:
 *   - Higher-privilege actions cost more tokens
 *   - Token starvation suspends capabilities (doesn't revoke trust)
 *   - Tokens regenerate during idle periods (coupled hysteresis)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>

#include "../include/trust_types.h"
#include "trust_internal.h"

/*
 * Metabolic cost table, indexed directly by TRUST_ACTION_* (densely
 * numbered 1..TRUST_ACTION_MAX-1).  Replaces the previous linear scan
 * of a {action, cost} pair array.  This turns a 17-iteration loop on
 * the hot path (every trust_risc_record_action call) into a one-load
 * bounds check + one-load cost fetch — O(1) with a predictable cache
 * footprint on both old and new hardware.
 *
 * Zero entries indicate "use default 1 token" for actions without a
 * dedicated cost constant.  __read_mostly hint lets the linker park
 * the table in the read-mostly cacheline cluster — important on old
 * HW with tiny L1 where write traffic would otherwise evict it.
 */
static const u32 g_action_cost[TRUST_ACTION_MAX] __read_mostly = {
	[TRUST_ACTION_FILE_OPEN]         = TRUST_COST_FILE_READ,
	[TRUST_ACTION_FILE_WRITE]        = TRUST_COST_FILE_WRITE,
	[TRUST_ACTION_NET_CONNECT]       = TRUST_COST_NET_CONNECT,
	[TRUST_ACTION_NET_LISTEN]        = TRUST_COST_NET_LISTEN,
	[TRUST_ACTION_PROCESS_CREATE]    = TRUST_COST_PROCESS_CREATE,
	[TRUST_ACTION_PROCESS_SIGNAL]    = TRUST_COST_PROCESS_SIGNAL,
	[TRUST_ACTION_REGISTRY_READ]     = 1,
	[TRUST_ACTION_REGISTRY_WRITE]    = 2,
	[TRUST_ACTION_DEVICE_OPEN]       = TRUST_COST_DEVICE_ACCESS,
	[TRUST_ACTION_SERVICE_START]     = TRUST_COST_PROCESS_CREATE,
	[TRUST_ACTION_SERVICE_STOP]      = TRUST_COST_PROCESS_SIGNAL,
	[TRUST_ACTION_FIREWALL_CHANGE]   = TRUST_COST_FIREWALL_MODIFY,
	[TRUST_ACTION_TRUST_CHANGE]      = TRUST_COST_TRUST_MODIFY,
	[TRUST_ACTION_ESCALATE]          = TRUST_COST_ESCALATE,
	[TRUST_ACTION_DOMAIN_TRANSFER]   = TRUST_COST_DOMAIN_TRANSFER,
	[TRUST_ACTION_MITOTIC_DIVIDE]    = TRUST_COST_PROCESS_CREATE * 2,
	[TRUST_ACTION_MEIOTIC_COMBINE]   = TRUST_COST_PROCESS_CREATE,
};

/*
 * Get the metabolic cost for an action type.
 * O(1) direct-indexed lookup with bounds check.
 */
u32 trust_token_cost_for_action(u32 action_type)
{
	u32 cost;

	if (unlikely(action_type >= TRUST_ACTION_MAX))
		return 1;

	cost = g_action_cost[action_type];
	return cost ? cost : 1; /* Default: 1 token for unseeded entries */
}

/*
 * Initialize token state for a new subject.
 * Called during subject registration. Token capacity scales with authority.
 */
void trust_token_init(trust_token_state_t *tokens, u32 authority_level)
{
	memset(tokens, 0, sizeof(*tokens));

	switch (authority_level) {
	case TRUST_AUTH_KERNEL:
		tokens->balance = TRUST_TOKEN_MAX_DEFAULT;
		tokens->max_balance = TRUST_TOKEN_MAX_DEFAULT;
		tokens->regen_rate = TRUST_TOKEN_REGEN_DEFAULT * 4;
		break;
	case TRUST_AUTH_ADMIN:
		tokens->balance = TRUST_TOKEN_MAX_DEFAULT * 3 / 4;
		tokens->max_balance = TRUST_TOKEN_MAX_DEFAULT * 3 / 4;
		tokens->regen_rate = TRUST_TOKEN_REGEN_DEFAULT * 2;
		break;
	case TRUST_AUTH_SERVICE:
		tokens->balance = TRUST_TOKEN_MAX_DEFAULT / 2;
		tokens->max_balance = TRUST_TOKEN_MAX_DEFAULT / 2;
		tokens->regen_rate = TRUST_TOKEN_REGEN_DEFAULT;
		break;
	case TRUST_AUTH_USER:
	default:
		tokens->balance = TRUST_TOKEN_MAX_DEFAULT / 4;
		tokens->max_balance = TRUST_TOKEN_MAX_DEFAULT / 4;
		tokens->regen_rate = TRUST_TOKEN_REGEN_DEFAULT / 2;
		break;
	}

	tokens->last_regen_ts = ktime_get_ns();
}

/*
 * Check if a subject has enough tokens for an action.
 * Does NOT burn tokens — use trust_token_burn() for that.
 * Returns 0 if sufficient, -ENOSPC if starved.
 */
int trust_token_check(const trust_token_state_t *tokens, u32 action_type)
{
	u32 cost = trust_token_cost_for_action(action_type);

	if (tokens->balance < (int32_t)cost)
		return -ENOSPC;

	return 0;
}

/*
 * Burn tokens for an action (metabolic cost).
 * Returns 0 on success, -ENOSPC if insufficient tokens.
 *
 * Caller is responsible for writing the modified subject back to TLB.
 */
int trust_token_burn(trust_token_state_t *tokens, u32 action_type)
{
	u32 cost = trust_token_cost_for_action(action_type);

	if (tokens->balance < (int32_t)cost) {
		tokens->starved = 1;
		return -ENOSPC;
	}

	tokens->balance -= (int32_t)cost;
	tokens->total_burned += cost;

	if (tokens->balance <= 0)
		tokens->starved = 1;
	else
		tokens->starved = 0;

	return 0;
}

/*
 * Regenerate tokens for a subject.
 * Called periodically from trust_immune_tick().
 * Tokens regenerate at the subject's regen_rate per tick,
 * capped at max_balance.
 */
void trust_token_regenerate(trust_token_state_t *tokens)
{
	if (tokens->regen_rate == 0)
		return;

	if (tokens->balance < tokens->max_balance) {
		int32_t prev = tokens->balance;
		int32_t regen = (int32_t)tokens->regen_rate;
		tokens->balance += regen;
		if (tokens->balance > tokens->max_balance)
			tokens->balance = tokens->max_balance;
		/* Credit only what was actually added (post-clamp), not unclamped rate */
		if (tokens->balance > prev)
			tokens->total_regenerated += (u32)(tokens->balance - prev);
	}

	if (tokens->balance > 0)
		tokens->starved = 0;

	tokens->last_regen_ts = ktime_get_ns();
}
