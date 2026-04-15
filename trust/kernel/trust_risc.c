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
    int32_t delta_success = 1, delta_failure = -5;
    int have_rule = 0;
    int i, count;

    ctx->old_score = subj->trust_score;
    ctx->old_caps = subj->capabilities;

    /*
     * Policy rules are append-only after init (see trust_policy_add_rule)
     * and rule entries themselves are never mutated after insertion.  We
     * can snapshot the two fields we need (delta_on_success,
     * delta_on_failure) WITHOUT the policy spinlock, using READ_ONCE on
     * count for a monotonic fence.
     *
     * Rationale: the previous code took g_trust_policy.lock nested
     * inside the TLB set lock on every trust_risc_record_action call.
     * This serialized completely unrelated record-action calls across
     * every CPU core, wrecking scalability under fork+exec storms.
     * Eliminating the nested lock is worth dozens of % throughput on
     * many-core systems and still correct on single-core old HW.
     */
    count = READ_ONCE(g_trust_policy.count);
    if (count > TRUST_MAX_POLICIES)
        count = TRUST_MAX_POLICIES;
    /* Fence after the count read — ensure we see rule bytes written before
     * the producer's WRITE_ONCE(count, ...). */
    smp_rmb();

    for (i = 0; i < count; i++) {
        const trust_policy_rule_t *r = &g_trust_policy.rules[i];
        /* READ_ONCE on the action_type keyfield is enough — the rule
         * slot itself is immutable once published. */
        if ((r->domain == subj->domain || r->domain == 0xFFFFFFFF) &&
            READ_ONCE(r->action_type) == ctx->action) {
            delta_success = r->delta_on_success;
            delta_failure = r->delta_on_failure;
            have_rule = 1;
            break;
        }
    }
    (void)have_rule;

    /* Apply delta with clamping */
    {
        int32_t delta = (ctx->result == 0) ? delta_success : delta_failure;
        subj->trust_score = trust_clamp_score(subj->trust_score + delta);
    }
    subj->last_action_ts = trust_get_timestamp();

    /* --- TRC Integration: burn tokens with cost multiplier --- */
    {
        u32 raw_cost = trust_token_cost_for_action(ctx->action);
        /* Ensure cost_multiplier is at least 1.0x (256 in 8.8 fixed-point) to prevent bypass */
        u32 multiplier = subj->trc.cost_multiplier;
        u64 wide_cost;
        u32 adjusted_cost;

        if (multiplier < 256)
            multiplier = 256;  /* Floor at 1.0x — cannot reduce cost below base */

        /* Saturating fixed-point 8.8 multiply.  Previous code cast
         * the result of the u64 * u64 shift directly to u32, which
         * silently truncated above UINT32_MAX and through the later
         * `(int32_t)adjusted_cost` cast could produce a negative
         * cost that a clever attacker might use to _grow_ balance.
         * Saturate at S32_MAX (0x7fffffff) so the int32 path below
         * stays sane regardless of multiplier pathologies. */
        wide_cost = ((u64)raw_cost * multiplier) >> 8;
        if (wide_cost > 0x7fffffffULL)
            adjusted_cost = 0x7fffffffU;
        else
            adjusted_cost = (u32)wide_cost;

        if (adjusted_cost == 0 && raw_cost > 0)
            adjusted_cost = 1;  /* Never let a non-zero cost become free */

        if (subj->tokens.balance >= (int32_t)adjusted_cost) {
            subj->tokens.balance -= (int32_t)adjusted_cost;
            /* Cap lifetime counter at UINT32_MAX to match the caps in
             * cmd_res_xfer/cmd_res_mint. Silent wrap here would break
             * audit accounting for long-lived subjects. */
            if (subj->tokens.total_burned > UINT32_MAX - adjusted_cost)
                subj->tokens.total_burned = UINT32_MAX;
            else
                subj->tokens.total_burned += adjusted_cost;
            /* Successful burn with positive remaining balance clears
             * any stale starvation flag set by a previous failed burn
             * (e.g. after trust_token_regenerate topped us back up). */
            if (subj->tokens.starved && subj->tokens.balance > 0)
                subj->tokens.starved = 0;
        } else {
            subj->tokens.starved = 1;
        }
    }

    /* --- TRC Integration: threshold crossings use bias --- */
    {
        int32_t biased_low = trust_clamp_score(
            subj->threshold_low + subj->trc.threshold_bias);
        int32_t biased_high = trust_clamp_score(
            subj->threshold_high + subj->trc.threshold_bias);

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

    /* --- Chromosomal Update: record action in behavioral DNA ---
     * Use deferred updates to batch 3 segment writes into ONE CRC32
     * recompute at the end.  Previous code did 3 CRC32's per action. */
    trust_chromosome_update_a_deferred(&subj->chromosome, CHROMO_A_ACTION_HASH,
        trust_chromosome_rolling_hash(
            subj->chromosome.a_segments[CHROMO_A_ACTION_HASH], ctx->action));

    trust_chromosome_update_a_deferred(&subj->chromosome, CHROMO_A_TRUST_STATE,
        trust_chromosome_rolling_hash(
            subj->chromosome.a_segments[CHROMO_A_TRUST_STATE],
            (u32)subj->trust_score));

    /* TOKEN_BALANCE is a direct snapshot, not a hash; bypass the
     * helper entirely — it doesn't increment mutation_count on
     * idle-value reassignment, which matches prior semantics. */
    subj->chromosome.a_segments[CHROMO_A_TOKEN_BALANCE] =
        (u32)subj->tokens.balance;

    trust_chromosome_update_a_deferred(&subj->chromosome, CHROMO_A_CAPABILITY_USE,
        trust_chromosome_rolling_hash(
            subj->chromosome.a_segments[CHROMO_A_CAPABILITY_USE],
            subj->capabilities));

    /* Single CRC32 pass over the batched updates */
    trust_chromosome_finalize(&subj->chromosome);

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

    /* Fast-path: find matching policy rule and compare score.
     * Lock-free snapshot of append-only table (see trust_policy_add_rule). */
    {
        int count = READ_ONCE(g_trust_policy.count);
        if (count > TRUST_MAX_POLICIES)
            count = TRUST_MAX_POLICIES;
        smp_rmb();

        for (i = 0; i < count; i++) {
            const trust_policy_rule_t *r = &g_trust_policy.rules[i];
            if ((r->domain == subj.domain || r->domain == 0xFFFFFFFF) &&
                READ_ONCE(r->action_type) == action) {
                int32_t min = r->min_trust;
                u32 req_caps = r->required_caps;

                /* TRC Integration: apply threshold bias (clamped) */
                min = trust_clamp_score(min + subj.trc.threshold_bias);

                if (subj.trust_score < min)
                    return TRUST_RESULT_DENY;
                if (req_caps && !(subj.capabilities & req_caps))
                    return TRUST_RESULT_DENY;
                return TRUST_RESULT_ALLOW;
            }
        }
    }

    /* No specific rule found: allow if score is positive */
    return (subj.trust_score >= 0) ? TRUST_RESULT_ALLOW : TRUST_RESULT_DENY;
}

/* --- TRUST_DECAY --- */
void trust_risc_decay_tick(void)
{
    int set, way;
    unsigned long flags;
    u64 now = trust_get_timestamp();

    /*
     * Coupled hysteresis: all trust scores drift toward neutral (0).
     * Decay rate is configurable per subject.
     * Capabilities are NOT revoked by decay alone — only by
     * negative actions crossing thresholds.
     *
     * Called from trust_decay_timer_fn (softirq). Must use
     * spin_lock_irqsave so we don't deadlock against process-context
     * holders on the same CPU.
     *
     * Lock-free early-out: if a set's valid_mask is zero, no subjects
     * live there and we can skip without touching the cacheline hot.
     * Under a light load (hundreds of subjects across 1024 sets) this
     * turns a 1024-lock storm every second into tens of locks.  On
     * old HW with small L1, this keeps the timer off the hot path.
     */
    if (!g_trust_tlb.sets)
        return;

    for (set = 0; set < TRUST_TLB_SETS; set++) {
        trust_tlb_set_t *s = &g_trust_tlb.sets[set];

        if (READ_ONCE(s->valid_mask) == 0)
            continue;

        spin_lock_irqsave(&s->lock, flags);
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
                int chromo_dirty = 0;
                /* Map score to conformance: high score = high conformance */
                conformance = (u32)((abs_score * 255) / TRUST_SCORE_MAX);
                if (conformance > 255) conformance = 255;

                if (subj->chromosome.a_segments[CHROMO_A_CONFORMANCE] != conformance) {
                    subj->chromosome.a_segments[CHROMO_A_CONFORMANCE] = conformance;
                    chromo_dirty = 1;
                }
                if (subj->chromosome.a_segments[CHROMO_A_SEX] != conformance) {
                    subj->chromosome.a_segments[CHROMO_A_SEX] = conformance;
                    chromo_dirty = 1;
                }
                subj->chromosome.sex =
                    trust_chromosome_determine_sex(&subj->chromosome);
                /*
                 * Previously decay wrote to a_segments WITHOUT touching
                 * chromosome.checksum, leaving it stale.  The very next
                 * immune_evaluate would run trust_chromosome_verify(),
                 * find the stale checksum, and spuriously escalate the
                 * subject to TRUST_IMMUNE_SUSPICIOUS.  Refresh checksum
                 * only when segments actually changed — skips the ~200-
                 * byte CRC32 during idle periods.
                 */
                if (chromo_dirty)
                    trust_chromosome_finalize(&subj->chromosome);
            }

            subj->flags |= TRUST_FLAG_DECAYING;
        }
        spin_unlock_irqrestore(&s->lock, flags);
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
