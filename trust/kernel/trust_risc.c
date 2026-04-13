/*
 * trust_risc.c - RISC Layer: Fast-Path Trust Instructions
 *
 * Simple O(1) operations using the Trust/Capability TLB.
 * These are the "metabolized energy" — quick single-cycle decisions:
 *
 *   TRUST_CHECK_CAP   - TLB lookup: does subject have capability?
 *   TRUST_GET_SCORE   - TLB lookup: current trust score
 *   TRUST_RECORD      - Apply pre-computed delta, check threshold
 *   TRUST_THRESHOLD   - Fast compare: score >= rule.min_trust
 *   TRUST_DECAY       - Periodic: all scores drift toward neutral
 *   TRUST_TRANSLATE   - Static table: map capability across domains
 */

#include <linux/module.h>
#include <linux/slab.h>
#include "trust_internal.h"

/* --- TRUST_CHECK_CAP --- */
int trust_risc_check_cap(u32 subject_id, u32 capability)
{
    trust_subject_t subj;

    if (trust_tlb_lookup(subject_id, &subj) < 0)
        return 0; /* Unknown subject has no capabilities */

    if (subj.flags & (TRUST_FLAG_FROZEN | TRUST_FLAG_APOPTOTIC | TRUST_FLAG_CANCEROUS))
        return 0; /* Frozen/apoptotic/cancerous subjects can't do anything */

    /* Token starvation suspends capabilities (Metabolic Fairness) */
    if (subj.tokens.starved)
        return 0;

    /* Quarantined subjects have no capabilities */
    if (subj.immune.status == TRUST_IMMUNE_QUARANTINED)
        return 0;

    return (subj.capabilities & capability) ? 1 : 0;
}

/* --- TRUST_GET_SCORE --- */
int32_t trust_risc_get_score(u32 subject_id)
{
    trust_subject_t subj;

    if (trust_tlb_lookup(subject_id, &subj) < 0)
        return 0; /* Unknown subjects have neutral score */

    return subj.trust_score;
}

/* --- TRUST_RECORD --- */

/*
 * Context passed through trust_tlb_modify callback to avoid TOCTOU:
 * the subject is looked up and modified under the TLB set spinlock
 * so no concurrent modification can slip in between lookup and insert.
 */
struct record_action_ctx {
    u32     action;
    u32     result;
    u32     subject_id;
    int32_t old_score;
    u32     old_caps;
    int32_t new_score;
    u32     new_caps;
};

static int _record_action_cb(trust_subject_t *subj, void *data)
{
    struct record_action_ctx *ctx = data;
    trust_policy_rule_t *rule = NULL;
    int32_t delta;
    int i;

    ctx->old_score = subj->trust_score;
    ctx->old_caps = subj->capabilities;

    /* Find matching policy rule for this action.
     * Policy lock nests inside TLB set lock -- this is safe because
     * no code path takes them in the reverse order. */
    spin_lock(&g_trust_policy.lock);
    for (i = 0; i < g_trust_policy.count; i++) {
        if ((g_trust_policy.rules[i].domain == subj->domain ||
             g_trust_policy.rules[i].domain == 0xFFFFFFFF) &&
            g_trust_policy.rules[i].action_type == ctx->action) {
            rule = &g_trust_policy.rules[i];
            break;
        }
    }

    if (rule) {
        delta = (ctx->result == 0) ? rule->delta_on_success : rule->delta_on_failure;
    } else {
        delta = (ctx->result == 0) ? 1 : -5;
    }
    spin_unlock(&g_trust_policy.lock);

    /* Apply delta with clamping */
    subj->trust_score = trust_clamp_score(subj->trust_score + delta);
    subj->last_action_ts = trust_get_timestamp();

    /* --- TRC Integration: burn tokens with cost multiplier --- */
    {
        u32 raw_cost = trust_token_cost_for_action(ctx->action);
        /* Ensure cost_multiplier is at least 1.0x (256 in 8.8 fixed-point) to prevent bypass */
        u32 multiplier = subj->trc.cost_multiplier;
        if (multiplier < 256)
            multiplier = 256;  /* Floor at 1.0x — cannot reduce cost below base */
        u32 adjusted_cost = (u32)(((u64)raw_cost * multiplier) >> 8);
        if (adjusted_cost == 0 && raw_cost > 0)
            adjusted_cost = 1;  /* Never let a non-zero cost become free */
        if (subj->tokens.balance >= (int32_t)adjusted_cost) {
            subj->tokens.balance -= (int32_t)adjusted_cost;
            subj->tokens.total_burned += adjusted_cost;
        } else {
            subj->tokens.starved = 1;
        }
    }

    /* --- TRC Integration: threshold crossings use bias --- */
    {
        int32_t biased_low = subj->threshold_low + subj->trc.threshold_bias;
        int32_t biased_high = subj->threshold_high + subj->trc.threshold_bias;

        if (subj->trust_score <= biased_low) {
            subj->capabilities &= trust_default_caps(TRUST_AUTH_NONE);
            if (subj->authority_level > TRUST_AUTH_NONE)
                subj->authority_level = TRUST_AUTH_NONE;
        } else if (subj->trust_score >= biased_high) {
            subj->capabilities = trust_default_caps(subj->authority_level);
        }
    }

    /* --- TRC Integration: anomalous actions adjust TRC state --- */
    if (ctx->action == TRUST_ACTION_CANCER_DETECTED ||
        ctx->action == TRUST_ACTION_PROOF_BREAK)
        trust_trc_adjust(&subj->trc, ctx->action);
    else if (ctx->action == TRUST_ACTION_IMMUNE_TRIGGER)
        trust_trc_adjust(&subj->trc, ctx->action);
    else if (ctx->result == 0)
        trust_trc_adjust(&subj->trc, 0);

    /* --- Chromosomal Update: record action in behavioral DNA --- */
    trust_chromosome_update_a(&subj->chromosome, CHROMO_A_ACTION_HASH,
        trust_chromosome_rolling_hash(
            subj->chromosome.a_segments[CHROMO_A_ACTION_HASH], ctx->action));

    trust_chromosome_update_a(&subj->chromosome, CHROMO_A_TRUST_STATE,
        trust_chromosome_rolling_hash(
            subj->chromosome.a_segments[CHROMO_A_TRUST_STATE],
            (u32)subj->trust_score));

    subj->chromosome.a_segments[CHROMO_A_TOKEN_BALANCE] =
        (u32)subj->tokens.balance;

    trust_chromosome_update_a(&subj->chromosome, CHROMO_A_CAPABILITY_USE,
        trust_chromosome_rolling_hash(
            subj->chromosome.a_segments[CHROMO_A_CAPABILITY_USE],
            subj->capabilities));

    /* Enforce generational score ceiling */
    if (subj->lifecycle.max_score > 0 &&
        subj->trust_score > subj->lifecycle.max_score)
        subj->trust_score = subj->lifecycle.max_score;

    ctx->new_score = subj->trust_score;
    ctx->new_caps = subj->capabilities;
    return 0;
}

int32_t trust_risc_record_action(u32 subject_id, u32 action, u32 result)
{
    struct record_action_ctx ctx = {
        .action = action,
        .result = result,
        .subject_id = subject_id,
    };
    int ret;

    ret = trust_tlb_modify(subject_id, _record_action_cb, &ctx);
    if (ret == -ENOENT)
        return 0;

    /* Write audit record outside the TLB set lock (audit has its own lock) */
    trust_fbc_audit(subject_id, action, ctx.old_score, ctx.new_score,
                    ctx.old_caps, ctx.new_caps);

    return ctx.new_score;
}

/* --- TRUST_THRESHOLD --- */
int trust_risc_threshold_check(u32 subject_id, u32 action)
{
    trust_subject_t subj;
    int i;

    if (trust_tlb_lookup(subject_id, &subj) < 0)
        return TRUST_RESULT_DENY;

    if (subj.flags & TRUST_FLAG_FROZEN)
        return TRUST_RESULT_DENY;

    /* Token starvation suspends capabilities (Theorem 6) */
    if (subj.tokens.starved)
        return TRUST_RESULT_DENY;

    /* Fast-path: find matching policy rule and compare score */
    spin_lock(&g_trust_policy.lock);
    for (i = 0; i < g_trust_policy.count; i++) {
        if ((g_trust_policy.rules[i].domain == subj.domain ||
             g_trust_policy.rules[i].domain == 0xFFFFFFFF) &&
            g_trust_policy.rules[i].action_type == action) {
            int32_t min = g_trust_policy.rules[i].min_trust;
            u32 req_caps = g_trust_policy.rules[i].required_caps;
            spin_unlock(&g_trust_policy.lock);

            /* TRC Integration: apply threshold bias */
            min += subj.trc.threshold_bias;

            if (subj.trust_score < min)
                return TRUST_RESULT_DENY;
            if (req_caps && !(subj.capabilities & req_caps))
                return TRUST_RESULT_DENY;
            return TRUST_RESULT_ALLOW;
        }
    }
    spin_unlock(&g_trust_policy.lock);

    /* No specific rule found: allow if score is positive */
    return (subj.trust_score >= 0) ? TRUST_RESULT_ALLOW : TRUST_RESULT_DENY;
}

/* --- TRUST_DECAY --- */
void trust_risc_decay_tick(void)
{
    int set, way;
    u64 now = trust_get_timestamp();

    /*
     * Coupled hysteresis: all trust scores drift toward neutral (0).
     * Decay rate is configurable per subject.
     * Capabilities are NOT revoked by decay alone — only by
     * negative actions crossing thresholds.
     */
    for (set = 0; set < TRUST_TLB_SETS; set++) {
        trust_tlb_set_t *s = &g_trust_tlb.sets[set];

        spin_lock(&s->lock);
        for (way = 0; way < TRUST_TLB_WAYS; way++) {
            trust_subject_t *subj;

            if (!(s->valid_mask & (1U << way)))
                continue;

            subj = &s->entries[way];
            if (subj->flags & TRUST_FLAG_FROZEN)
                continue;

            if (subj->decay_rate == 0)
                continue;

            /* Check if enough time has passed (decay every ~1 second) */
            if (now - subj->last_action_ts < 1000000000ULL)
                continue;

            /* Drift toward neutral */
            if (subj->trust_score > 0) {
                subj->trust_score -= (int32_t)subj->decay_rate;
                if (subj->trust_score < 0)
                    subj->trust_score = 0;
            } else if (subj->trust_score < 0) {
                subj->trust_score += (int32_t)subj->decay_rate;
                if (subj->trust_score > 0)
                    subj->trust_score = 0;
            }

            /* TRC: decay resistance back toward normal */
            trust_trc_adjust(&subj->trc, 0);

            /* Update behavioral conformance chromosome (A22) */
            /* Score near zero = conformant, far from zero = divergent */
            {
                u32 conformance;
                int32_t abs_score = subj->trust_score >= 0 ?
                    subj->trust_score : -subj->trust_score;
                /* Map score to conformance: high score = high conformance */
                conformance = (u32)((abs_score * 255) / TRUST_SCORE_MAX);
                if (conformance > 255) conformance = 255;
                subj->chromosome.a_segments[CHROMO_A_CONFORMANCE] = conformance;
                subj->chromosome.a_segments[CHROMO_A_SEX] = conformance;
                subj->chromosome.sex =
                    trust_chromosome_determine_sex(&subj->chromosome);
            }

            subj->flags |= TRUST_FLAG_DECAYING;
        }
        spin_unlock(&s->lock);
    }
}

/* --- TRUST_TRANSLATE --- */
/*
 * Static capability translation between domains.
 * Maps a capability from one domain to the equivalent in another.
 * For most cases, capabilities are the same across domains.
 * Special cases handled by the DNA Gate.
 */
u32 trust_risc_translate_cap(u32 cap, u16 from_domain, u16 to_domain)
{
    (void)from_domain;
    (void)to_domain;

    /*
     * For now, capabilities are domain-agnostic.
     * The DNA Gate handles the actual privilege translation
     * (e.g., TRUST_CAP_NET_LISTEN -> Linux CAP_NET_BIND_SERVICE).
     * This RISC instruction does a fast 1:1 mapping.
     */
    return cap;
}

MODULE_LICENSE("GPL");
