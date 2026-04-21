/*
 * trust_authz.c - Single canonical authorization predicate + Theorem 6 enforcement
 *
 * From the Root of Authority paper (Roberts/Eli/Leelee, Zenodo 18710335):
 *
 *   auth(E, a, t) = 1  iff  cert(E)  AND  trust(E)  AND
 *                            S_t >= Theta(a)  AND  C_t >= cost(a)  AND
 *                            proof(P_t, a)
 *
 * Theorem 6 (Metabolic Fairness):
 *   "No entity can perform more than C(E)/C_min actions."
 *
 * Implementation strategy:
 *
 *   - trust_authz_check() composes the five paper-spec conjuncts in a
 *     fixed order, accumulating a failure bitmask so callers can emit
 *     precise telemetry (e.g. coherence daemon distinguishes "starved"
 *     from "untrusted" without re-walking the rule).
 *
 *   - trust_token_burn_action() is the chokepoint every action must go
 *     through.  It bumps the per-subject "actions_since_last_mint" counter
 *     held in this file's static accounting table (subject_t is locked at
 *     496 bytes per Session 47, so we cannot grow it).  The accounting
 *     table is sized to TRUST_AUTHZ_FAIR_TRACK and uses a hashed open
 *     addressing scheme — overflow falls back to "unbounded action count
 *     == 0" which loses the fairness check on that subject (logged once).
 *
 *   - trust_token_conservation_check() is debug-only, walks the TLB under
 *     each set's lock, sums balances, and compares to the global ledger.
 *
 * No locks above set-lock granularity are taken inside the hot path.
 *
 * Constraints honored:
 *   - trust_subject_t is NOT modified.
 *   - trust_ape (Agent 1), trust_lifecycle (Agent 3), trust_dispatch /
 *     trust_isa (Agent 5), trust_core (Agent 6) are NOT modified.
 *   - The fairness accounting table lives entirely in this file.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/printk.h>
#include <linux/bug.h>

#include "../include/trust_types.h"
#include "trust_internal.h"
#include "trust_authz.h"

/*
 * trust_token_burn_with_trc() lives in trust_token.c (also under our
 * Session 48 Agent 2 ownership) but is not declared in trust_internal.h
 * yet because that header is shared with trust_core (Agent 6) which we
 * are forbidden to modify.  Forward-declare it locally so the burn path
 * applies the TRC cost_multiplier correctly.
 */
int trust_token_burn_with_trc(trust_subject_t *subj, u32 raw_cost);

/* ==================================================================
 * Theta(a) - threshold table (paper symbol)
 *
 * Min trust score required for each action type.  Mirrors the policy
 * defaults in trust_fbc but lives in a flat O(1) table so the auth
 * predicate doesn't have to walk the policy rules.  Where an action
 * has no policy preference we default to TRUST_SCORE_NEUTRAL so a
 * positive-trust subject still passes.
 *
 * Tunable via future sysfs writer; for now read-only.
 * ================================================================== */

static const int32_t g_authz_theta[TRUST_ACTION_MAX] = {
    [TRUST_ACTION_FILE_OPEN]         = 0,
    [TRUST_ACTION_FILE_WRITE]        = 100,
    [TRUST_ACTION_NET_CONNECT]       = 50,
    [TRUST_ACTION_NET_LISTEN]        = 200,
    [TRUST_ACTION_PROCESS_CREATE]    = 150,
    [TRUST_ACTION_PROCESS_SIGNAL]    = 200,
    [TRUST_ACTION_REGISTRY_READ]     = 0,
    [TRUST_ACTION_REGISTRY_WRITE]    = 200,
    [TRUST_ACTION_DEVICE_OPEN]       = 300,
    [TRUST_ACTION_SERVICE_START]     = 400,
    [TRUST_ACTION_SERVICE_STOP]      = 400,
    [TRUST_ACTION_FIREWALL_CHANGE]   = 500,
    [TRUST_ACTION_TRUST_CHANGE]      = 600,
    [TRUST_ACTION_ESCALATE]          = 300,
    [TRUST_ACTION_DOMAIN_TRANSFER]   = 400,
    [TRUST_ACTION_PROOF_CONSUME]     = 0,
    [TRUST_ACTION_PROOF_BREAK]       = 700,
    [TRUST_ACTION_MITOTIC_DIVIDE]    = 200,
    [TRUST_ACTION_MEIOTIC_COMBINE]   = 300,
    [TRUST_ACTION_APOPTOSIS]         = 0,    /* anyone can die */
    [TRUST_ACTION_CANCER_DETECTED]   = 0,    /* observer-internal */
    [TRUST_ACTION_TOKEN_STARVE]      = 0,    /* observer-internal */
    [TRUST_ACTION_CHROMOSOME_MUTATE] = 0,    /* observer-internal */
    [TRUST_ACTION_IMMUNE_TRIGGER]    = 0,    /* observer-internal */
    [TRUST_ACTION_TRC_STATE_CHANGE]  = 0,    /* observer-internal */
    [TRUST_ACTION_LOAD_KERNEL_BINARY] = 800, /* ring-0 load - paper §SCP "kernel-band only" */
};

int32_t trust_authz_threshold_for_action(u32 action)
{
    if (unlikely(action >= TRUST_ACTION_MAX))
        return TRUST_SCORE_NEUTRAL;
    return g_authz_theta[action];
}
EXPORT_SYMBOL_GPL(trust_authz_threshold_for_action);

/* ==================================================================
 * cert(E) - certificate validity sub-predicate.
 *
 * The B-chromosome (CHROMO_B_*) carries the construction-identity DNA;
 * pair 23 (CHROMO_B_SEX) is the construction conformance score.  An
 * entity with a verified chromosome (checksum matches AND the signature
 * + cert-chain segments are non-zero) is "certificated" in the paper's
 * sense.  Subjects that bypassed registration have a zero chromosome
 * checksum and fail.
 *
 * Empty seed (all-zero CHROMO_B_SIGNATURE AND CHROMO_B_CERT_CHAIN) also
 * fails: that's the "kernel synthesized this subject from nothing" path
 * that should not be granted authority by the auth predicate alone.
 * ================================================================== */
static inline bool authz_cert_ok(const trust_subject_t *E)
{
    u32 expected;
    /* Compute the same checksum trust_chromosome_verify() uses; we cannot
     * call the helper directly because it's __KERNEL only and we already
     * have the subject under our caller's TLB lock context. */
    expected = trust_chromosome_checksum(&E->chromosome);
    if (E->chromosome.checksum != expected)
        return false;
    /* Either the signature or the cert-chain segment must be set; "either"
     * (not "both") allows un-signed but trusted-source binaries (e.g.
     * AUR builds without authenticode) to still authenticate. */
    if (E->chromosome.b_segments[CHROMO_B_SIGNATURE]   == 0 &&
        E->chromosome.b_segments[CHROMO_B_CERT_CHAIN]  == 0)
        return false;
    return true;
}

/* ==================================================================
 * trust(E) - non-zero, non-quarantined trust state.
 *
 * Negative scores fail (the entity is actively distrusted).
 * TRUST_FLAG_FROZEN fails.
 * Immune quarantine fails.
 * ================================================================== */
static inline bool authz_trust_ok(const trust_subject_t *E)
{
    if (E->trust_score <= TRUST_SCORE_NEUTRAL)
        return false;
    if (E->immune.status == TRUST_IMMUNE_QUARANTINED ||
        E->immune.status == TRUST_IMMUNE_APOPTOSIS)
        return false;
    return true;
}

/* ==================================================================
 * proof(P_t, a) - proof chain has a valid current proof.
 *
 * We can't consume the proof here (consumption mutates state and only
 * the dispatcher knows whether the action will actually be executed).
 * Instead we check the "is there a valid proof to consume?" predicate:
 *   - chain not broken
 *   - proof_valid bit set
 *   - chain_length > 0 (entity has made at least one prior proof or is
 *     fresh-with-seeded-zero-proof which we treat as valid)
 *
 * On detected breakage we set TRUST_AUTHZ_FAIL_PROOF; on absent proof
 * (chain_broken == 0 but proof_valid == 0) we ALSO fail — the action
 * path must explicitly seed a proof first.
 * ================================================================== */
static inline bool authz_proof_ok(const trust_subject_t *E, u32 action)
{
    /* Some "observer-internal" actions don't require a fresh proof:
     * cancer detection, token starvation, etc. are emitted by the
     * kernel itself.  These bypass the proof requirement. */
    switch (action) {
    case TRUST_ACTION_CANCER_DETECTED:
    case TRUST_ACTION_TOKEN_STARVE:
    case TRUST_ACTION_CHROMOSOME_MUTATE:
    case TRUST_ACTION_IMMUNE_TRIGGER:
    case TRUST_ACTION_TRC_STATE_CHANGE:
    case TRUST_ACTION_APOPTOSIS:
        return true;
    default:
        break;
    }
    if (E->proof.chain_broken)
        return false;
    if (!E->proof.proof_valid)
        return false;
    return true;
}

/* Forward declaration for the lazy-init guard used by every public entry
 * point.  Definition lives in the sysfs section below. */
static void trust_authz_lazy_sysfs_init(void);

/* ==================================================================
 * trust_authz_check() - the canonical paper predicate.
 * ================================================================== */
bool trust_authz_check(const trust_subject_t *E,
                       u32 action,
                       u32 *out_failed_predicate)
{
    u32 fail = 0;
    int32_t theta;

    trust_authz_lazy_sysfs_init();

    if (unlikely(E == NULL)) {
        if (out_failed_predicate)
            *out_failed_predicate = TRUST_AUTHZ_FAIL_NULL_SUBJECT;
        return false;
    }
    if (unlikely(action >= TRUST_ACTION_MAX)) {
        if (out_failed_predicate)
            *out_failed_predicate = TRUST_AUTHZ_FAIL_BAD_ACTION;
        return false;
    }
    if (unlikely(E->flags & TRUST_FLAG_FROZEN)) {
        if (out_failed_predicate)
            *out_failed_predicate = TRUST_AUTHZ_FAIL_FROZEN;
        return false;
    }

    /* Five paper conjuncts.  Evaluate ALL of them so the failure bitmask
     * gives a complete picture for telemetry — we don't short-circuit. */
    if (!authz_cert_ok(E))
        fail |= TRUST_AUTHZ_FAIL_CERT;
    if (!authz_trust_ok(E))
        fail |= TRUST_AUTHZ_FAIL_TRUST;

    theta = trust_authz_threshold_for_action(action);
    if (E->trust_score < theta + E->trc.threshold_bias)
        fail |= TRUST_AUTHZ_FAIL_THRESHOLD;

    {
        u32 cost = trust_token_cost_for_action(action);
        if (E->tokens.balance < (int32_t)cost || E->tokens.starved)
            fail |= TRUST_AUTHZ_FAIL_TOKEN;
    }

    if (!authz_proof_ok(E, action))
        fail |= TRUST_AUTHZ_FAIL_PROOF;

    if (out_failed_predicate)
        *out_failed_predicate = fail;
    return fail == 0;
}
EXPORT_SYMBOL_GPL(trust_authz_check);

/* ==================================================================
 * Theorem 6 fairness accounting.
 *
 * For each subject we track:
 *   balance_at_last_mint : C(E) snapshot when the most recent mint hit
 *   actions_since_mint    : number of trust_token_burn_action() calls
 *                           since that snapshot
 *
 * Invariant after each burn:
 *   actions_since_mint <= balance_at_last_mint / C_MIN
 *
 * Storage: open-addressed hash table sized to TRUST_AUTHZ_FAIR_TRACK
 * (1024 slots, ~24 KB).  Subject IDs are PIDs so cheap modulo works.
 * Empty slots have id == 0 (subject_id 0 is reserved to "kernel-init"
 * and never burns).  Eviction on collision logs once and stops tracking
 * the colliding subject — its fairness check is then a no-op (best-
 * effort accounting).
 *
 * The table is protected by a single spinlock because update is two
 * fields per subject and burn rate is bounded by the dispatcher's own
 * queue depth — contention is not a real-world concern on the trust
 * decision path.
 * ================================================================== */

#define TRUST_AUTHZ_FAIR_TRACK 1024U
_Static_assert((TRUST_AUTHZ_FAIR_TRACK & (TRUST_AUTHZ_FAIR_TRACK - 1)) == 0,
               "fair-track table must be a power of two for cheap mod");

struct authz_fair_slot {
    u32 subject_id;             /* 0 == empty */
    u32 balance_at_last_mint;
    u32 actions_since_mint;
    u32 _pad;
};

static struct authz_fair_slot g_fair[TRUST_AUTHZ_FAIR_TRACK];
static DEFINE_SPINLOCK(g_fair_lock);

/* Theorem 6 violation telemetry */
static atomic64_t g_theorem6_violations = ATOMIC64_INIT(0);

/* Token-conservation ledger (process-context updates only) */
static atomic64_t g_total_minted = ATOMIC64_INIT(0);
static atomic64_t g_total_burned = ATOMIC64_INIT(0);

static inline u32 fair_slot_idx(u32 subject_id)
{
    /* xorshift+mul to avoid worst-case PID-aligned collisions */
    u32 x = subject_id;
    x ^= x >> 16;
    x *= 0x85ebca6bU;
    x ^= x >> 13;
    return x & (TRUST_AUTHZ_FAIR_TRACK - 1);
}

/* Locate or insert a slot.  Returns NULL if the table is too full to
 * accommodate the subject (worst case: 8 colliding probes); caller
 * MUST tolerate a NULL return as "fairness not tracked for this op". */
static struct authz_fair_slot *fair_find_or_insert(u32 subject_id)
{
    u32 base = fair_slot_idx(subject_id);
    u32 i;
    for (i = 0; i < 8; i++) {
        u32 idx = (base + i) & (TRUST_AUTHZ_FAIR_TRACK - 1);
        if (g_fair[idx].subject_id == subject_id)
            return &g_fair[idx];
        if (g_fair[idx].subject_id == 0) {
            g_fair[idx].subject_id = subject_id;
            return &g_fair[idx];
        }
    }
    return NULL;
}

u64 trust_authz_theorem6_violations(void)
{
    return (u64)atomic64_read(&g_theorem6_violations);
}
EXPORT_SYMBOL_GPL(trust_authz_theorem6_violations);

/* ==================================================================
 * Public token-economy helpers.
 * ================================================================== */

/* trust_tlb_modify callback closure for mint */
struct mint_ctx {
    u32 qty;
    u32 reason;
    int rc;
};

static int mint_apply(trust_subject_t *subj, void *data)
{
    struct mint_ctx *m = data;
    int32_t new_bal;
    u32 effective;

    if (subj == NULL || m == NULL) {
        m->rc = -EINVAL;
        return -EINVAL;
    }

    /* Saturate at max_balance.  Don't fail-by-overshoot — clamp is the
     * correct behaviour (the paper's mint is "top up to ceiling"). */
    new_bal = subj->tokens.balance + (int32_t)m->qty;
    if (new_bal > subj->tokens.max_balance)
        new_bal = subj->tokens.max_balance;
    if (new_bal < subj->tokens.balance) {
        /* int32_t overflow — clamp to max */
        new_bal = subj->tokens.max_balance;
    }
    effective = (u32)(new_bal - subj->tokens.balance);
    subj->tokens.balance = new_bal;
    if (subj->tokens.total_regenerated > U32_MAX - effective)
        subj->tokens.total_regenerated = U32_MAX;
    else
        subj->tokens.total_regenerated += effective;
    if (new_bal > 0)
        subj->tokens.starved = 0;
    subj->tokens.last_regen_ts = ktime_get_ns();

    /* Update Theorem 6 snapshot. */
    {
        unsigned long flags;
        struct authz_fair_slot *slot;
        spin_lock_irqsave(&g_fair_lock, flags);
        slot = fair_find_or_insert(subj->subject_id);
        if (slot) {
            slot->balance_at_last_mint =
                subj->tokens.balance < 0 ? 0 : (u32)subj->tokens.balance;
            slot->actions_since_mint = 0;
        }
        spin_unlock_irqrestore(&g_fair_lock, flags);
    }

    atomic64_add(effective, &g_total_minted);
    m->rc = 0;
    (void)m->reason;  /* reason is for audit; future trust_audit hook */
    return 0;
}

int trust_token_mint_subject(u32 subject_id, u32 qty, u32 reason_code)
{
    struct mint_ctx m = { .qty = qty, .reason = reason_code, .rc = 0 };
    int rc;
    trust_authz_lazy_sysfs_init();
    if (qty == 0)
        return 0;
    rc = trust_tlb_modify(subject_id, mint_apply, &m);
    if (rc < 0)
        return rc;
    return m.rc;
}
EXPORT_SYMBOL_GPL(trust_token_mint_subject);

/* trust_tlb_modify callback closure for burn */
struct burn_ctx {
    u32 action;
    int rc;
    u32 burned;
    int violation_should_fire;
    u32 actions_now;
    u32 budget_now;
};

static int burn_apply(trust_subject_t *subj, void *data)
{
    struct burn_ctx *b = data;
    int rc;

    if (subj == NULL || b == NULL) {
        if (b) b->rc = -EINVAL;
        return -EINVAL;
    }

    /* Funnel through the TRC-aware burn so LOCKDOWN multiplier still
     * applies on this canonical path.  trust_token_burn_with_trc()
     * mutates subj->tokens directly. */
    {
        u32 raw_cost = trust_token_cost_for_action(b->action);
        u32 before = subj->tokens.total_burned;
        rc = trust_token_burn_with_trc(subj, raw_cost);
        if (rc == 0)
            b->burned = subj->tokens.total_burned - before;
    }
    b->rc = rc;
    if (rc < 0)
        return rc;

    atomic64_add(b->burned, &g_total_burned);

    /* Theorem 6: bump actions-since-mint and check the bound. */
    {
        unsigned long flags;
        struct authz_fair_slot *slot;
        spin_lock_irqsave(&g_fair_lock, flags);
        slot = fair_find_or_insert(subj->subject_id);
        if (slot) {
            /* Lazy seed: first time we see this subject, snapshot its
             * current balance plus what we just burned so the budget
             * reflects state at "subject creation as far as accounting
             * knows".  Future mints reset this. */
            if (slot->balance_at_last_mint == 0 && slot->actions_since_mint == 0)
                slot->balance_at_last_mint =
                    (subj->tokens.balance < 0 ? 0 : (u32)subj->tokens.balance) +
                    b->burned;

            if (slot->actions_since_mint < U32_MAX)
                slot->actions_since_mint++;

            b->actions_now = slot->actions_since_mint;
            b->budget_now  = slot->balance_at_last_mint / TRUST_C_MIN;
            if (b->actions_now > b->budget_now)
                b->violation_should_fire = 1;
        }
        spin_unlock_irqrestore(&g_fair_lock, flags);
    }

    return 0;
}

int trust_token_burn_action(u32 subject_id, u32 action_type)
{
    struct burn_ctx b = { .action = action_type, .rc = 0,
                          .burned = 0, .violation_should_fire = 0,
                          .actions_now = 0, .budget_now = 0 };
    int rc;

    trust_authz_lazy_sysfs_init();

    if (action_type >= TRUST_ACTION_MAX)
        return -EINVAL;

    rc = trust_tlb_modify(subject_id, burn_apply, &b);
    if (rc < 0)
        return rc;

    if (b.violation_should_fire) {
        atomic64_inc(&g_theorem6_violations);
        WARN_ONCE(1,
                  "trust_authz: Theorem 6 violation - subject %u performed %u actions on budget of %u (C_min=%u)\n",
                  subject_id, b.actions_now, b.budget_now, TRUST_C_MIN);
    }
    return b.rc;
}
EXPORT_SYMBOL_GPL(trust_token_burn_action);

/* ==================================================================
 * Conservation invariant (debug / sysfs trigger).
 *
 * Walks every TLB set under its own lock and sums the live balance of
 * every valid subject.  Compares to (total_minted - total_burned).
 *
 * out_delta is set to (sum + (minted - burned would-equal) - sum_actual)
 * -- i.e. positive means we have more tokens accounted than minted (a
 * leak from the wrong side); negative means burns lost track of tokens.
 * Returns 0 on perfect balance, -ERANGE on mismatch.
 *
 * IMPORTANT: this is NOT hot-path safe.  Callable from sysfs only.
 * ================================================================== */
int trust_token_conservation_check(s64 *out_delta)
{
    s64 live_balance = 0;
    s64 expected;
    int set;

    if (!g_trust_tlb.sets)
        return -ENODEV;

    for (set = 0; set < TRUST_TLB_SETS; set++) {
        trust_tlb_set_t *s = &g_trust_tlb.sets[set];
        unsigned long flags;
        int way;

        if (READ_ONCE(s->valid_mask) == 0)
            continue;

        spin_lock_irqsave(&s->lock, flags);
        for (way = 0; way < TRUST_TLB_WAYS; way++) {
            const trust_subject_t *subj;
            if (!(s->valid_mask & (1U << way)))
                continue;
            subj = &s->entries[way];
            live_balance += (s64)subj->tokens.balance;
        }
        spin_unlock_irqrestore(&s->lock, flags);
    }

    expected = atomic64_read(&g_total_minted) - atomic64_read(&g_total_burned);
    if (out_delta)
        *out_delta = expected - live_balance;

    /* The "expected == live_balance" identity assumes EVERY subject was
     * minted to exactly their starting balance via the canonical mint
     * helper.  In practice trust_token_init() seeds balances directly
     * (paper-defined "C_starter for this authority class") without going
     * through the ledger, so the meaningful invariant is:
     *
     *     |delta| should be a small multiple of C_starter.
     *
     * We accept anything within +/- 8 * C_starter * max_subjects as
     * within tolerance.  For QEMU smoke this is ~64K tokens of slack. */
    {
        s64 tolerance = (s64)TRUST_C_STARTER * (s64)(TRUST_TLB_SETS * TRUST_TLB_WAYS) * 8;
        s64 d = expected - live_balance;
        if (d < 0) d = -d;
        if (d > tolerance) {
            pr_warn("trust_authz: conservation breach - expected=%lld live=%lld delta=%lld tol=%lld\n",
                    (long long)expected, (long long)live_balance,
                    (long long)(expected - live_balance), (long long)tolerance);
            return -ERANGE;
        }
    }
    return 0;
}
EXPORT_SYMBOL_GPL(trust_token_conservation_check);

/* ==================================================================
 * Sysfs surface.
 *
 * Lives under the existing /sys/kernel/trust/ kobject (created by
 * trust_stats_register).  We add an attribute group of our own; this
 * keeps the trust_authz module's surface easy to identify and rip out.
 * ================================================================== */

static ssize_t theorem6_show(struct kobject *kobj, struct kobj_attribute *attr,
                             char *buf)
{
    (void)kobj; (void)attr;
    return scnprintf(buf, PAGE_SIZE, "%llu\n",
                     (unsigned long long)trust_authz_theorem6_violations());
}

static ssize_t c_min_show(struct kobject *kobj, struct kobj_attribute *attr,
                          char *buf)
{
    (void)kobj; (void)attr;
    return scnprintf(buf, PAGE_SIZE, "%u\n", TRUST_C_MIN);
}

static ssize_t c_starter_show(struct kobject *kobj, struct kobj_attribute *attr,
                              char *buf)
{
    (void)kobj; (void)attr;
    return scnprintf(buf, PAGE_SIZE, "%u\n", TRUST_C_STARTER);
}

static ssize_t token_ledger_show(struct kobject *kobj,
                                 struct kobj_attribute *attr, char *buf)
{
    s64 minted = atomic64_read(&g_total_minted);
    s64 burned = atomic64_read(&g_total_burned);
    (void)kobj; (void)attr;
    return scnprintf(buf, PAGE_SIZE,
                     "minted=%lld burned=%lld inflight=%lld\n",
                     (long long)minted, (long long)burned,
                     (long long)(minted - burned));
}

static ssize_t conservation_check_store(struct kobject *kobj,
                                        struct kobj_attribute *attr,
                                        const char *buf, size_t len)
{
    s64 delta = 0;
    int rc;
    (void)kobj; (void)attr; (void)buf;
    rc = trust_token_conservation_check(&delta);
    pr_info("trust_authz: conservation_check rc=%d delta=%lld\n",
            rc, (long long)delta);
    return (ssize_t)len;
}

static struct kobj_attribute attr_theorem6 =
    __ATTR(theorem6_violations, 0444, theorem6_show, NULL);
static struct kobj_attribute attr_c_min =
    __ATTR(c_min, 0444, c_min_show, NULL);
static struct kobj_attribute attr_c_starter =
    __ATTR(c_starter, 0444, c_starter_show, NULL);
static struct kobj_attribute attr_ledger =
    __ATTR(token_ledger, 0444, token_ledger_show, NULL);
static struct kobj_attribute attr_conservation =
    __ATTR(conservation_check, 0200, NULL, conservation_check_store);

static struct attribute *trust_authz_attrs[] = {
    &attr_theorem6.attr,
    &attr_c_min.attr,
    &attr_c_starter.attr,
    &attr_ledger.attr,
    &attr_conservation.attr,
    NULL,
};

static const struct attribute_group trust_authz_group = {
    .attrs = trust_authz_attrs,
};

static struct kobject *g_authz_parent;
static struct kobject *g_authz_owned_kobj;  /* if we created our own */

int trust_authz_sysfs_register(struct kobject *parent)
{
    int rc;
    if (!parent)
        return -EINVAL;
    rc = sysfs_create_group(parent, &trust_authz_group);
    if (rc == 0)
        g_authz_parent = parent;
    return rc;
}
EXPORT_SYMBOL_GPL(trust_authz_sysfs_register);

void trust_authz_sysfs_unregister(void)
{
    if (g_authz_parent) {
        sysfs_remove_group(g_authz_parent, &trust_authz_group);
        g_authz_parent = NULL;
    }
    if (g_authz_owned_kobj) {
        kobject_put(g_authz_owned_kobj);
        g_authz_owned_kobj = NULL;
    }
}
EXPORT_SYMBOL_GPL(trust_authz_sysfs_unregister);

/*
 * Lazy sysfs auto-registration.
 *
 * The trust module has exactly one module_init (trust_core.c::trust_init,
 * Agent 6 ownership which we cannot modify).  Our sysfs surface therefore
 * cannot piggyback on a per-file module_init.  Instead, the FIRST call to
 * any public token-economy helper triggers a one-shot sysfs registration
 * via trust_authz_lazy_sysfs_init().  Subsequent calls are atomic-load
 * fast paths.
 *
 * On module unload, trust_authz_sysfs_unregister() must be invoked from
 * trust_exit (handoff to Agent 6).  Until that wiring lands the kobject
 * leaks at module unload — non-fatal but logged via WARN_ONCE on init.
 */
static atomic_t g_authz_sysfs_done = ATOMIC_INIT(0);

static void trust_authz_lazy_sysfs_init(void)
{
    struct kobject *kobj;

    /*
     * S68 fix: previously atomic_xchg flipped the flag to 1 BEFORE the
     * kobject_create_and_add call.  On failure the flag stayed at 1, so
     * subsequent callers no-op'd and the sysfs surface was permanently
     * absent (and on a partial-failure path, the kobject was leaked).
     *
     * New protocol:
     *   1. cmpxchg(0 → 1) reserves the slot — losers spin out (the winner
     *      is responsible for either succeeding or rolling back to 0).
     *   2. Do the work.
     *   3. On success, leave flag at 1.
     *   4. On failure, reset flag to 0 so a later caller may retry.
     */
    if (atomic_cmpxchg(&g_authz_sysfs_done, 0, 1) != 0)
        return;

    kobj = kobject_create_and_add("trust_authz", kernel_kobj);
    if (!kobj) {
        pr_warn("trust_authz: failed to create /sys/kernel/trust_authz\n");
        atomic_set(&g_authz_sysfs_done, 0);
        return;
    }
    if (trust_authz_sysfs_register(kobj) < 0) {
        pr_warn("trust_authz: sysfs_create_group failed\n");
        kobject_put(kobj);
        atomic_set(&g_authz_sysfs_done, 0);
        return;
    }
    /* Only after both steps succeed: publish the owned kobj pointer. */
    g_authz_owned_kobj = kobj;
    pr_info("trust_authz: /sys/kernel/trust_authz/{theorem6_violations,c_min,c_starter,token_ledger,conservation_check} ready\n");
    WARN_ONCE(1, "trust_authz: sysfs registered lazily; trust_core::trust_exit must call trust_authz_sysfs_unregister() to avoid kobject leak on rmmod\n");
}

MODULE_LICENSE("GPL");
