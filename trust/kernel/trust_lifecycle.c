/*
 * trust_lifecycle.c - Mitotic/Meiotic Lifecycle and Immune Response
 *
 * Implements the biological lifecycle model from the Root of Authority paper:
 *
 * MITOTIC DIVISION (process spawning):
 *   - Child inherits parent's chromosomal DNA with generational decay
 *   - Smax(g) = alpha^g * Smax(0), where alpha ≈ 0.9
 *   - Each generation has a lower authority ceiling than its parent
 *   - Excessive spawning triggers cancer detection (runaway process)
 *   - Cancer → apoptotic cascade → controlled termination
 *
 * MEIOTIC COMBINATION (dual-entity cooperation):
 *   - Two entities combine to create a shared authority context
 *   - Combined authority bounded by min(S(EA), S(EB))
 *   - Requires mutual consent (both entities must approve)
 *   - Used for cross-domain operations (PE process + Linux service)
 *
 * IMMUNE RESPONSE:
 *   - Cancer detection: runaway spawning, excessive mutation
 *   - Apoptotic cascade: controlled death propagation
 *     - XX children (conformant) die with parent
 *     - XY children (divergent) survive, re-rooted to init
 *   - Orphan handling: parentless processes get adopted by init (PID 1)
 *   - Quarantine: suspicious subjects are isolated
 *
 * GENERATIONAL DECAY (from paper):
 *   Each generation g has a maximum authority score:
 *     Smax(g) = alpha^g * Smax(0)
 *   This ensures that authority naturally dilutes through successive
 *   process forks, preventing unbounded privilege propagation.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "trust_internal.h"

/* Maximum recursion depth for apoptotic cascade to prevent kernel stack overflow */
#define TRUST_CASCADE_MAX_DEPTH 4

/* Global lineage tracking */
trust_lineage_t g_trust_lineage;

/*
 * Initialize the lifecycle subsystem.
 */
void trust_lifecycle_init(void)
{
    memset(&g_trust_lineage, 0, sizeof(g_trust_lineage));
    spin_lock_init(&g_trust_lineage.lock);
    pr_info("trust_lifecycle: lifecycle subsystem initialized\n");
}

/*
 * Compute the maximum score ceiling for a given generation and base authority.
 * Uses the generational decay formula: Smax(g) = alpha^g * Smax(0)
 */
int trust_lifecycle_get_max_score(u8 generation, u32 base_authority)
{
    int32_t base_max;

    switch (base_authority) {
    case TRUST_AUTH_KERNEL:  base_max = TRUST_SCORE_MAX; break;
    case TRUST_AUTH_ADMIN:   base_max = 700; break;
    case TRUST_AUTH_SERVICE: base_max = 400; break;
    case TRUST_AUTH_USER:    base_max = 200; break;
    default:                 base_max = 0; break;
    }

    return trust_generation_decay(generation, base_max);
}

/*
 * Record a parent-child lineage entry.
 */
static int lineage_record(u32 parent_id, u32 child_id, u8 child_sex, u8 gen)
{
    trust_lineage_entry_t *entry;

    spin_lock(&g_trust_lineage.lock);
    if (g_trust_lineage.count >= TRUST_MAX_LINEAGE) {
        spin_unlock(&g_trust_lineage.lock);
        return -ENOSPC;
    }

    entry = &g_trust_lineage.entries[g_trust_lineage.count];
    entry->parent_id = parent_id;
    entry->child_id = child_id;
    entry->child_sex = child_sex;
    entry->generation = gen;
    g_trust_lineage.count++;

    spin_unlock(&g_trust_lineage.lock);
    return 0;
}

/*
 * Mitotic Division — process spawning.
 *
 * When a process creates a child:
 *   1. Look up parent in TLB
 *   2. Check cancer: has parent exceeded spawn limits?
 *   3. Create child chromosome inheriting from parent
 *   4. Apply generational decay to child's max score
 *   5. Create child's proof chain (new seed, fresh nonce)
 *   6. Initialize child's tokens at reduced capacity
 *   7. Record lineage for immune response tracking
 *   8. Burn parent's tokens for the division cost
 *
 * Returns 0 on success, -EPERM if cancer detected, -ENOENT if parent unknown.
 */
struct mitotic_parent_ctx {
    u64             now;
    int             outcome;      /* 0=ok, -EPERM cancer, -ENOSPC starved */
    trust_subject_t parent_snap;  /* snapshot for child derivation */
};

static int _mitotic_parent_cb(trust_subject_t *parent, void *data)
{
    struct mitotic_parent_ctx *ctx = data;
    int ret;

    /* Check frozen/apoptotic */
    if (parent->flags & (TRUST_FLAG_FROZEN | TRUST_FLAG_APOPTOTIC)) {
        ctx->outcome = -EPERM;
        ctx->parent_snap = *parent;
        return 0;
    }

    /* --- Cancer Detection --- */
    if (ctx->now - parent->lifecycle.spawn_window_start <
        TRUST_CANCER_SPAWN_WINDOW) {
        parent->lifecycle.spawn_count++;
        if (parent->lifecycle.spawn_count > TRUST_CANCER_SPAWN_LIMIT) {
            parent->flags |= TRUST_FLAG_CANCEROUS;
            parent->immune.status = TRUST_IMMUNE_CANCEROUS;
            parent->lifecycle.state = TRUST_LIFECYCLE_APOPTOTIC;
            trust_trc_adjust(&parent->trc, TRUST_ACTION_CANCER_DETECTED);
            ctx->outcome = -EPERM;
            ctx->parent_snap = *parent; /* for audit after lock release */
            return 0;
        }
    } else {
        parent->lifecycle.spawn_window_start = ctx->now;
        parent->lifecycle.spawn_count = 1;
    }

    /* Total spawn limit */
    parent->lifecycle.total_spawns++;
    if (parent->lifecycle.total_spawns > TRUST_CANCER_TOTAL_LIMIT) {
        parent->flags |= TRUST_FLAG_CANCEROUS;
        parent->immune.status = TRUST_IMMUNE_CANCEROUS;
        ctx->outcome = -EPERM;
        ctx->parent_snap = *parent;
        return 0;
    }

    /* Burn tokens */
    ret = trust_token_burn(&parent->tokens, TRUST_ACTION_MITOTIC_DIVIDE);
    if (ret) {
        ctx->outcome = -ENOSPC;
        ctx->parent_snap = *parent;
        return 0;
    }

    parent->lifecycle.last_division_ts = ctx->now;
    parent->lifecycle.state = TRUST_LIFECYCLE_ACTIVE;
    parent->chromosome.division_count++;

    trust_chromosome_update_a(&parent->chromosome, CHROMO_A_SPAWN_RATE,
        trust_chromosome_rolling_hash(
            parent->chromosome.a_segments[CHROMO_A_SPAWN_RATE],
            parent->lifecycle.spawn_count));

    ctx->outcome = 0;
    ctx->parent_snap = *parent;
    return 0;
}

int trust_lifecycle_mitotic_divide(u32 parent_id, u32 child_id)
{
    struct mitotic_parent_ctx ctx;
    trust_subject_t child;
    trust_subject_t *parent;
    u64 now;
    int ret;

    now = trust_get_timestamp();
    ctx.now = now;
    ctx.outcome = -EINVAL;

    /*
     * Atomic parent mutation: the spawn_count / total_spawns / token burn
     * all happen under the TLB set spinlock, eliminating the lookup-
     * modify-insert TOCTOU race on concurrent fork().
     */
    ret = trust_tlb_modify(parent_id, _mitotic_parent_cb, &ctx);
    if (ret != 0)
        return ret;  /* -ENOENT (no parent) or -ENOMEM (TLB not ready) */

    if (ctx.outcome == -EPERM) {
        /* Cancer or frozen — audit with post-state values */
        if (ctx.parent_snap.flags & TRUST_FLAG_CANCEROUS) {
            trust_fbc_audit(parent_id, TRUST_ACTION_CANCER_DETECTED,
                            ctx.parent_snap.trust_score,
                            ctx.parent_snap.trust_score,
                            ctx.parent_snap.capabilities, 0);
            pr_warn("trust_lifecycle: CANCER detected for subject %u "
                    "(%u spawns in window)\n",
                    parent_id, ctx.parent_snap.lifecycle.spawn_count);
        }
        return -EPERM;
    }
    if (ctx.outcome == -ENOSPC)
        return -ENOSPC;
    if (ctx.outcome != 0)
        return ctx.outcome;

    parent = &ctx.parent_snap;

    /* --- Create Child --- */
    memset(&child, 0, sizeof(child));
    child.subject_id = child_id;
    child.domain = parent->domain;

    /* Inherit chromosome with generational decay */
    trust_chromosome_inherit(&child.chromosome, &parent->chromosome,
                              parent->lifecycle.generation + 1);
    child.chromosome.parent_id = parent_id;

    /* Compute max score from generational decay */
    child.lifecycle.generation = parent->lifecycle.generation + 1;
    child.lifecycle.max_score = trust_lifecycle_get_max_score(
        child.lifecycle.generation, parent->authority_level);

    /* Child starts at reduced score (half of parent, capped by generation) */
    child.trust_score = parent->trust_score / 2;
    if (child.trust_score > child.lifecycle.max_score)
        child.trust_score = child.lifecycle.max_score;

    /* Child inherits parent's authority level (but with lower ceiling) */
    child.authority_level = parent->authority_level;
    child.capabilities = trust_default_caps(parent->authority_level);
    child.threshold_low = parent->threshold_low;
    child.threshold_high = parent->threshold_high;
    child.last_action_ts = now;
    child.decay_rate = parent->decay_rate;
    child.flags = TRUST_FLAG_NEW;

    /* Initialize child lifecycle */
    child.lifecycle.state = TRUST_LIFECYCLE_EMBRYONIC;
    child.lifecycle.parent_id = parent_id;
    child.lifecycle.birth_ts = now;
    child.lifecycle.spawn_window_start = now;

    /* Initialize child tokens at generation-decayed capacity */
    trust_token_init(&child.tokens, child.authority_level);
    child.tokens.max_balance = (child.tokens.max_balance *
        TRUST_GENERATION_ALPHA_NUM) / TRUST_GENERATION_ALPHA_DEN;
    if (child.tokens.balance > child.tokens.max_balance)
        child.tokens.balance = child.tokens.max_balance;

    /* Initialize child immune system */
    trust_immune_init(&child.immune);

    /* Initialize child TRC */
    trust_trc_init(&child.trc);

    /* Insert child into TLB */
    trust_tlb_insert(&child);

    /* Record lineage */
    lineage_record(parent_id, child_id, child.chromosome.sex,
                   child.lifecycle.generation);

    /* Create child's proof chain (fresh seed) */
    trust_ape_create_entity(child_id, NULL, 0);

    /* Audit */
    trust_fbc_audit(child_id, TRUST_ACTION_MITOTIC_DIVIDE,
                   0, child.trust_score, 0, child.capabilities);

    pr_info("trust_lifecycle: mitotic division %u → %u (gen=%u, max_score=%d)\n",
            parent_id, child_id, child.lifecycle.generation,
            child.lifecycle.max_score);

    return 0;
}

/*
 * Meiotic Combination — dual-entity cooperation.
 *
 * Two entities combine to create a shared authority context:
 *   - Combined score bounded by min(S(A), S(B))
 *   - Combined capabilities = intersection of both
 *   - Both entities are marked as MEIOTIC
 *   - Creates a dependency between them
 *
 * Returns 0 on success.
 *
 * Uses trust_tlb_modify on each subject independently. Since A and B may
 * live in different TLB sets, we cannot hold both set-locks simultaneously,
 * so we apply each mutation atomically in its own critical section. If
 * either pre-check fails the other is left untouched.
 */
struct meiotic_combine_ctx {
    u32     partner_id;
    int     outcome;        /* 0=ok, -EPERM frozen/apoptotic/cancerous */
    int32_t score;          /* snapshot score after mutation */
    u32     caps;           /* snapshot caps after mutation */
};

static int _meiotic_combine_cb(trust_subject_t *subj, void *data)
{
    struct meiotic_combine_ctx *c = data;

    if (subj->flags &
        (TRUST_FLAG_FROZEN | TRUST_FLAG_APOPTOTIC | TRUST_FLAG_CANCEROUS)) {
        c->outcome = -EPERM;
        c->score = subj->trust_score;
        c->caps  = subj->capabilities;
        return 0;
    }

    subj->flags |= TRUST_FLAG_MEIOTIC;
    subj->lifecycle.state = TRUST_LIFECYCLE_COMBINING;
    subj->lifecycle.meiotic_partner = c->partner_id;
    trust_token_burn(&subj->tokens, TRUST_ACTION_MEIOTIC_COMBINE);

    c->outcome = 0;
    c->score = subj->trust_score;
    c->caps  = subj->capabilities;
    return 0;
}

int trust_lifecycle_meiotic_combine(u32 subject_a, u32 subject_b)
{
    struct meiotic_combine_ctx ca = { .partner_id = subject_b, .outcome = -EINVAL };
    struct meiotic_combine_ctx cb = { .partner_id = subject_a, .outcome = -EINVAL };
    int ret;
    int32_t combined_score;

    ret = trust_tlb_modify(subject_a, _meiotic_combine_cb, &ca);
    if (ret != 0)
        return -ENOENT;
    if (ca.outcome == -EPERM)
        return -EPERM;

    ret = trust_tlb_modify(subject_b, _meiotic_combine_cb, &cb);
    if (ret != 0)
        return -ENOENT;
    if (cb.outcome == -EPERM)
        return -EPERM;

    /* Compute combined score: min(S(A), S(B)) */
    combined_score = ca.score < cb.score ? ca.score : cb.score;

    /* Create mutual dependency (has its own locking) */
    trust_dep_add(subject_a, subject_b);
    trust_dep_add(subject_b, subject_a);

    /* Audit */
    trust_fbc_audit(subject_a, TRUST_ACTION_MEIOTIC_COMBINE,
                   ca.score, combined_score,
                   ca.caps, ca.caps & cb.caps);

    pr_info("trust_lifecycle: meiotic combination %u + %u (combined_score=%d)\n",
            subject_a, subject_b, combined_score);

    return 0;
}

/*
 * Release a meiotic combination.
 */
static int _meiotic_release_cb(trust_subject_t *subj, void *data)
{
    (void)data;
    subj->flags &= ~TRUST_FLAG_MEIOTIC;
    subj->lifecycle.state = TRUST_LIFECYCLE_ACTIVE;
    subj->lifecycle.meiotic_partner = 0;
    return 0;
}

void trust_lifecycle_meiotic_release(u32 subject_a, u32 subject_b)
{
    (void)trust_tlb_modify(subject_a, _meiotic_release_cb, NULL);
    (void)trust_tlb_modify(subject_b, _meiotic_release_cb, NULL);

    trust_dep_remove(subject_a, subject_b);
    trust_dep_remove(subject_b, subject_a);
}

/*
 * Check for cancer (called periodically and during spawning).
 * Returns 1 if cancer detected, 0 if healthy.
 *
 * The detection + flag-set is performed atomically inside the callback
 * so concurrent spawn/mutation events cannot lose an increment to
 * suspicious_actions nor miss the CANCEROUS transition.
 */
struct check_cancer_ctx { int verdict; };

static int _check_cancer_cb(trust_subject_t *subj, void *data)
{
    struct check_cancer_ctx *c = data;

    if (subj->flags & TRUST_FLAG_CANCEROUS) {
        c->verdict = 1;
        return 0;
    }

    if (subj->lifecycle.spawn_count > TRUST_CANCER_SPAWN_LIMIT) {
        subj->flags |= TRUST_FLAG_CANCEROUS;
        subj->immune.status = TRUST_IMMUNE_CANCEROUS;
        c->verdict = 1;
        return 0;
    }

    if (subj->lifecycle.total_spawns > TRUST_CANCER_TOTAL_LIMIT) {
        subj->flags |= TRUST_FLAG_CANCEROUS;
        subj->immune.status = TRUST_IMMUNE_CANCEROUS;
        c->verdict = 1;
        return 0;
    }

    if (subj->chromosome.mutation_count > 1000) {
        subj->immune.status = TRUST_IMMUNE_SUSPICIOUS;
        subj->immune.suspicious_actions++;
        if (subj->immune.suspicious_actions > 100) {
            subj->flags |= TRUST_FLAG_CANCEROUS;
            subj->immune.status = TRUST_IMMUNE_CANCEROUS;
            c->verdict = 1;
        } else {
            c->verdict = 0;
        }
        return 0;
    }

    c->verdict = 0;
    return 0;
}

int trust_lifecycle_check_cancer(u32 subject_id)
{
    struct check_cancer_ctx ctx = { .verdict = 0 };

    if (trust_tlb_modify(subject_id, _check_cancer_cb, &ctx) != 0)
        return 0;

    return ctx.verdict;
}

/*
 * Internal apoptosis with depth tracking to prevent stack overflow.
 */
static int _trust_lifecycle_apoptosis(u32 subject_id, int depth);
static void _trust_lifecycle_apoptotic_cascade(u32 subject_id, int depth);

/*
 * Initiate apoptosis (controlled death) for a subject.
 * Sets state and begins cascade.
 */
int trust_lifecycle_apoptosis(u32 subject_id)
{
    return _trust_lifecycle_apoptosis(subject_id, 0);
}

struct apoptosis_ctx {
    u64              deadline;
    int              already_apoptotic;
    int32_t          prev_score;
    u32              prev_caps;
};

static int _apoptosis_cb(trust_subject_t *subj, void *data)
{
    struct apoptosis_ctx *c = data;

    c->prev_score = subj->trust_score;
    c->prev_caps  = subj->capabilities;

    /* Idempotent: if already apoptotic, no-op (caller still returns 0 but
     * skips the ape_destroy/audit/cascade work that was already done). */
    if (subj->flags & TRUST_FLAG_APOPTOTIC) {
        c->already_apoptotic = 1;
        return 0;
    }

    subj->flags |= TRUST_FLAG_APOPTOTIC;
    subj->lifecycle.state = TRUST_LIFECYCLE_APOPTOTIC;
    subj->capabilities = 0;
    subj->immune.status = TRUST_IMMUNE_APOPTOSIS;
    subj->immune.apoptosis_deadline = c->deadline;
    c->already_apoptotic = 0;
    return 0;
}

static int _trust_lifecycle_apoptosis(u32 subject_id, int depth)
{
    struct apoptosis_ctx ctx = { 0 };
    trust_subject_t snap;
    int have_snap;
    int ret;

    ctx.deadline = trust_get_timestamp() + 5000000000ULL;  /* 5s */

    ret = trust_tlb_modify(subject_id, _apoptosis_cb, &ctx);
    if (ret != 0)
        return -ENOENT;

    if (ctx.already_apoptotic) {
        /* Someone else already put this subject into apoptosis;
         * do not re-destroy the proof chain or re-cascade. */
        return 0;
    }

    /* Snapshot the subject BEFORE proof destruction so the absent pool
     * stores a coherent last-known-good copy. */
    have_snap = (trust_tlb_lookup(subject_id, &snap) == 0);

    /* Destroy proof chain — authority is irrecoverably lost.
     * Must be done outside the TLB set-lock: trust_ape has its own locks. */
    trust_ape_destroy_entity(subject_id);

    trust_fbc_audit(subject_id, TRUST_ACTION_APOPTOSIS,
                   ctx.prev_score, TRUST_SCORE_MIN,
                   ctx.prev_caps, 0);

    pr_info("trust_lifecycle: apoptosis initiated for subject %u\n", subject_id);

    /* Trigger cascade for children (allocates/recurses — outside lock) */
    _trust_lifecycle_apoptotic_cascade(subject_id, depth);

    /* Route the freed subject into the absent pool for fast resurrection
     * within the time + population budget.  MUST be the last call: double
     * entry would be wasted work but is idempotent (refresh semantics). */
    if (have_snap)
        trust_subject_pool_put(&snap);

    return 0;
}

/*
 * Apoptotic Cascade — propagate death to children.
 *
 * This implements the biological apoptotic cascade:
 *   - XX children (conformant): die with parent
 *   - XY/YX children (divergent): survive, re-rooted to init (PID 1)
 *   - YY children: also die (both segments divergent = untrustworthy)
 *
 * This ensures that well-behaved children of a compromised parent
 * survive, while conformant children (which may be compromised via
 * the same vector as the parent) are terminated.
 *
 * Implementation note: we snapshot children under lock first, then
 * process them without the lock to avoid iterator invalidation and
 * recursive deadlocks (apoptosis -> cascade -> apoptosis).
 *
 * Stack safety: children are heap-allocated (not stack) and recursion
 * depth is bounded by TRUST_CASCADE_MAX_DEPTH to prevent kernel stack
 * overflow from deep process trees.
 */
void trust_lifecycle_apoptotic_cascade(u32 subject_id)
{
    _trust_lifecycle_apoptotic_cascade(subject_id, 0);
}

static void _trust_lifecycle_apoptotic_cascade(u32 subject_id, int depth)
{
    struct cascade_child {
        u32 child_id;
        u8  child_sex;
    };
    struct cascade_child *children;
    int child_count = 0;
    int i;

    /* Prevent kernel stack overflow from deep process trees */
    if (depth >= TRUST_CASCADE_MAX_DEPTH) {
        pr_warn("trust_lifecycle: cascade depth limit (%d) reached at "
                "subject %u, marking remaining children apoptotic without "
                "recursion\n", TRUST_CASCADE_MAX_DEPTH, subject_id);
        /* Snapshot child IDs under lock, then process without lock */
        {
            u32 *child_ids;
            int child_count_depth = 0;

            child_ids = kmalloc_array(TRUST_MAX_LINEAGE, sizeof(u32), GFP_KERNEL);
            if (!child_ids) {
                pr_err("trust_lifecycle: failed to allocate depth-limit "
                       "snapshot for subject %u\n", subject_id);
                return;
            }

            spin_lock(&g_trust_lineage.lock);
            for (i = 0; i < g_trust_lineage.count; i++) {
                trust_lineage_entry_t *entry = &g_trust_lineage.entries[i];
                if (entry->parent_id == subject_id)
                    child_ids[child_count_depth++] = entry->child_id;
            }
            spin_unlock(&g_trust_lineage.lock);

            for (i = 0; i < child_count_depth; i++) {
                trust_subject_t child;
                if (trust_tlb_lookup(child_ids[i], &child) == 0) {
                    child.flags |= TRUST_FLAG_APOPTOTIC;
                    child.lifecycle.state = TRUST_LIFECYCLE_APOPTOTIC;
                    child.capabilities = 0;
                    child.immune.status = TRUST_IMMUNE_APOPTOSIS;
                    child.immune.apoptosis_deadline =
                        trust_get_timestamp() + 5000000000ULL;
                    trust_tlb_insert(&child);
                }
            }

            kfree(child_ids);
        }
        return;
    }

    /* Heap-allocate snapshot to avoid large stack arrays in recursive path */
    children = kmalloc_array(TRUST_MAX_LINEAGE, sizeof(*children), GFP_KERNEL);
    if (!children) {
        pr_err("trust_lifecycle: failed to allocate cascade snapshot for "
               "subject %u\n", subject_id);
        return;
    }

    /* Phase 1: snapshot children under lock */
    spin_lock(&g_trust_lineage.lock);
    for (i = 0; i < g_trust_lineage.count; i++) {
        trust_lineage_entry_t *entry = &g_trust_lineage.entries[i];
        if (entry->parent_id == subject_id) {
            children[child_count].child_id = entry->child_id;
            children[child_count].child_sex = entry->child_sex;
            child_count++;
        }
    }
    spin_unlock(&g_trust_lineage.lock);

    /* Phase 2: process children without holding the lock */
    {
        int needs_reroot = 0;
        for (i = 0; i < child_count; i++) {
            u32 cid = children[i].child_id;
            u8  sex = children[i].child_sex;

            switch (sex) {
            case CHROMO_SEX_XX:
            case CHROMO_SEX_YY:
                /*
                 * XX (conformant) and YY (strongly divergent) children
                 * die with parent. XX children likely share the same
                 * compromise vector. YY children are too divergent to trust.
                 */
                pr_info("trust_lifecycle: cascade apoptosis -> child %u (sex=%s)\n",
                        cid, sex == CHROMO_SEX_XX ? "XX" : "YY");
                _trust_lifecycle_apoptosis(cid, depth + 1);
                break;

            case CHROMO_SEX_XY:
            case CHROMO_SEX_YX:
                /*
                 * XY/YX (divergent) children survive and are re-rooted
                 * to init. They demonstrated behavioral independence from
                 * the parent, so they are likely not compromised.
                 * Defer the re-root to a single call after the loop —
                 * trust_lifecycle_handle_orphans re-roots ALL children
                 * of this parent, so calling it per-child wastes work.
                 */
                pr_info("trust_lifecycle: re-rooting child %u (sex=%s) to init\n",
                        cid, sex == CHROMO_SEX_XY ? "XY" : "YX");
                needs_reroot = 1;
                break;
            }
        }
        if (needs_reroot)
            trust_lifecycle_handle_orphans(subject_id);
    }

    kfree(children);
}

/*
 * Handle orphaned children of a dead parent.
 * Re-roots them to init (subject_id 1) and reduces their trust.
 *
 * Uses a two-phase approach: snapshot orphan IDs under lock, then
 * update TLB and lineage entries without risk of lock re-entrancy.
 */
void trust_lifecycle_handle_orphans(u32 dead_parent_id)
{
    u32 *orphan_ids;
    int orphan_count = 0;
    int i;

    /* Heap-allocate to avoid 2KB stack array */
    orphan_ids = kmalloc_array(TRUST_MAX_LINEAGE, sizeof(u32), GFP_KERNEL);
    if (!orphan_ids) {
        pr_err("trust_lifecycle: failed to allocate orphan list for "
               "parent %u\n", dead_parent_id);
        return;
    }

    /* Phase 1: collect orphan child IDs and re-root lineage under lock */
    spin_lock(&g_trust_lineage.lock);
    for (i = 0; i < g_trust_lineage.count; i++) {
        trust_lineage_entry_t *entry = &g_trust_lineage.entries[i];
        if (entry->parent_id == dead_parent_id) {
            orphan_ids[orphan_count++] = entry->child_id;
            entry->parent_id = 1;  /* re-root to init */
        }
    }
    spin_unlock(&g_trust_lineage.lock);

    /* Phase 2: update each orphan's TLB entry without holding the lock */
    for (i = 0; i < orphan_count; i++) {
        trust_subject_t child;

        if (trust_tlb_lookup(orphan_ids[i], &child))
            continue;
        if (child.flags & TRUST_FLAG_APOPTOTIC)
            continue;

        child.lifecycle.parent_id = 1;
        child.lifecycle.flags |= TRUST_LIFE_FLAG_ORPHAN | TRUST_LIFE_FLAG_REROOTED;

        /* Reduce trust score by 20% as an orphan penalty */
        child.trust_score = (child.trust_score * 80) / 100;
        child.trust_score = trust_clamp_score(child.trust_score);

        trust_tlb_insert(&child);
    }

    kfree(orphan_ids);
}

/* --- Immune Response --- */

/*
 * Initialize immune state for a new subject.
 */
void trust_immune_init(trust_immune_t *immune)
{
    memset(immune, 0, sizeof(*immune));
    immune->status = TRUST_IMMUNE_HEALTHY;
}

/*
 * Evaluate a subject's immune status.
 *
 * Previously this did multiple lookup/mutate/insert cycles under
 * different locks, opening TOCTOU windows where a concurrent mutation
 * (e.g. record_action bumping suspicious_actions) could be silently
 * clobbered by a trust_tlb_insert() of stale state.  Collapse all
 * reads and writes into a single trust_tlb_modify callback so every
 * mutation is atomic against decay ticks and record-action bursts.
 *
 * The quarantine promotion path still runs outside the lock because
 * trust_immune_quarantine takes the set lock itself and the
 * verdict only needs to be acted on once.
 */
struct immune_eval_ctx {
    int verdict;                /* TRUST_IMMUNE_* */
    int need_quarantine;        /* 1 => caller should quarantine */
    int already_cascading;      /* snapshot before mutation */
};

static int _immune_eval_cb(trust_subject_t *subj, void *data)
{
    struct immune_eval_ctx *c = data;

    c->need_quarantine = 0;

    /* Already in cascade: don't touch */
    if (subj->immune.status >= TRUST_IMMUNE_APOPTOSIS) {
        c->already_cascading = 1;
        c->verdict = subj->immune.status;
        return 0;
    }
    c->already_cascading = 0;

    /* Cancer detection (inline — avoids recursive TLB lock) */
    if (subj->flags & TRUST_FLAG_CANCEROUS) {
        subj->immune.status = TRUST_IMMUNE_CANCEROUS;
        c->verdict = TRUST_IMMUNE_CANCEROUS;
        return 0;
    }
    if (subj->lifecycle.spawn_count > TRUST_CANCER_SPAWN_LIMIT ||
        subj->lifecycle.total_spawns > TRUST_CANCER_TOTAL_LIMIT) {
        subj->flags |= TRUST_FLAG_CANCEROUS;
        subj->immune.status = TRUST_IMMUNE_CANCEROUS;
        c->verdict = TRUST_IMMUNE_CANCEROUS;
        return 0;
    }

    /* Chromosome integrity */
    if (trust_chromosome_verify(&subj->chromosome) != 0) {
        subj->immune.status = TRUST_IMMUNE_SUSPICIOUS;
        subj->immune.suspicious_actions += 10;
        trust_trc_adjust(&subj->trc, TRUST_ACTION_IMMUNE_TRIGGER);

        if (subj->immune.suspicious_actions > 50) {
            c->need_quarantine = 1;
            c->verdict = TRUST_IMMUNE_QUARANTINED;
            return 0;
        }
        c->verdict = TRUST_IMMUNE_SUSPICIOUS;
        return 0;
    }

    /* YY sex — always suspicious */
    if (subj->chromosome.sex == CHROMO_SEX_YY) {
        if (subj->immune.status < TRUST_IMMUNE_SUSPICIOUS)
            subj->immune.status = TRUST_IMMUNE_SUSPICIOUS;
        subj->immune.suspicious_actions++;
    } else if (subj->immune.status == TRUST_IMMUNE_SUSPICIOUS &&
               subj->immune.suspicious_actions > 0) {
        /* Decay suspicious count when behaving well */
        subj->immune.suspicious_actions--;
        if (subj->immune.suspicious_actions == 0)
            subj->immune.status = TRUST_IMMUNE_HEALTHY;
    }

    c->verdict = subj->immune.status;
    return 0;
}

int trust_immune_evaluate(u32 subject_id)
{
    struct immune_eval_ctx ctx = { .verdict = TRUST_IMMUNE_HEALTHY };

    if (trust_tlb_modify(subject_id, _immune_eval_cb, &ctx) != 0)
        return TRUST_IMMUNE_HEALTHY;

    /* Escalate to quarantine outside the lock (it takes the set lock itself). */
    if (ctx.need_quarantine) {
        trust_immune_quarantine(subject_id, TRUST_ACTION_CHROMOSOME_MUTATE);
        return TRUST_IMMUNE_QUARANTINED;
    }

    return ctx.verdict;
}

/*
 * Quarantine a subject — isolate it from performing any actions.
 */
struct quarantine_ctx {
    u32     reason;
    u64     ts;
    int32_t score;
};

static int _quarantine_cb(trust_subject_t *subj, void *data)
{
    struct quarantine_ctx *c = data;

    subj->immune.status = TRUST_IMMUNE_QUARANTINED;
    subj->immune.quarantine_reason = c->reason;
    subj->immune.quarantine_ts = c->ts;
    subj->flags |= TRUST_FLAG_FROZEN;
    subj->capabilities = 0;
    /* TRC Integration: quarantine → elevated resistance */
    trust_trc_adjust(&subj->trc, TRUST_ACTION_IMMUNE_TRIGGER);

    c->score = subj->trust_score;
    return 0;
}

int trust_immune_quarantine(u32 subject_id, u32 reason)
{
    struct quarantine_ctx ctx = {
        .reason = reason,
        .ts     = trust_get_timestamp(),
        .score  = 0,
    };
    int ret;

    ret = trust_tlb_modify(subject_id, _quarantine_cb, &ctx);
    if (ret != 0)
        return -ENOENT;

    trust_fbc_audit(subject_id, TRUST_ACTION_IMMUNE_TRIGGER,
                   ctx.score, ctx.score,
                   0, 0);

    pr_warn("trust_lifecycle: subject %u QUARANTINED (reason=%u)\n",
            subject_id, reason);
    return 0;
}

/*
 * Release a subject from quarantine (requires AI observer approval).
 */
struct release_quarantine_ctx { int outcome; };

static int _release_quarantine_cb(trust_subject_t *subj, void *data)
{
    struct release_quarantine_ctx *c = data;

    if (subj->immune.status != TRUST_IMMUNE_QUARANTINED) {
        c->outcome = -EINVAL;
        return 0;
    }

    subj->immune.status = TRUST_IMMUNE_HEALTHY;
    subj->immune.suspicious_actions = 0;
    subj->flags &= ~TRUST_FLAG_FROZEN;

    /* Restore basic capabilities only — elevated ones must be re-earned */
    subj->capabilities = trust_default_caps(TRUST_AUTH_USER);
    subj->authority_level = TRUST_AUTH_USER;

    c->outcome = 0;
    return 0;
}

int trust_immune_release_quarantine(u32 subject_id)
{
    struct release_quarantine_ctx ctx = { .outcome = -EINVAL };
    int ret;

    ret = trust_tlb_modify(subject_id, _release_quarantine_cb, &ctx);
    if (ret != 0)
        return -ENOENT;
    if (ctx.outcome != 0)
        return ctx.outcome;

    pr_info("trust_lifecycle: subject %u released from quarantine\n", subject_id);
    return 0;
}

/*
 * Periodic immune system tick.
 * Called from the decay timer to scan for anomalies.
 */
void trust_immune_tick(void)
{
    int set, way;
    unsigned long flags;
    u64 now = trust_get_timestamp();

    /*
     * Called from trust_decay_timer_fn (softirq). TLB set locks are also
     * taken in process context via ioctl handlers, so we must use
     * irqsave to avoid softirq-vs-process deadlock on the same CPU.
     */
    if (!g_trust_tlb.sets)
        return;

    for (set = 0; set < TRUST_TLB_SETS; set++) {
        trust_tlb_set_t *s = &g_trust_tlb.sets[set];

        /* Use READ_ONCE for SMP safety — the mask can be concurrently
         * mutated by insert/invalidate on another CPU. */
        if (READ_ONCE(s->valid_mask) == 0)
            continue;

        spin_lock_irqsave(&s->lock, flags);
        for (way = 0; way < TRUST_TLB_WAYS; way++) {
            trust_subject_t *subj;

            if (!(s->valid_mask & (1U << way)))
                continue;

            subj = &s->entries[way];

            /* Check apoptosis deadline */
            if (subj->immune.status == TRUST_IMMUNE_APOPTOSIS &&
                subj->immune.apoptosis_deadline &&
                now > subj->immune.apoptosis_deadline) {
                /* Deadline passed — force necrotic death */
                subj->lifecycle.state = TRUST_LIFECYCLE_NECROTIC;
                subj->capabilities = 0;
                subj->trust_score = TRUST_SCORE_MIN;
                pr_warn("trust_lifecycle: subject %u necrotic death "
                        "(apoptosis deadline passed)\n", subj->subject_id);
            }

            /* Regenerate tokens */
            trust_token_regenerate(&subj->tokens);

            /*
             * Update token balance chromosome segment.  Only refresh
             * the CRC32 checksum if the value actually changed — most
             * ticks leave a subject at max_balance with zero change,
             * so avoiding the CRC over ~200 bytes for every subject
             * every second is a meaningful old-HW win.  Leaving the
             * checksum stale here would cause trust_chromosome_verify
             * to fail and trigger spurious immune escalation.
             */
            {
                u32 new_bal = (u32)subj->tokens.balance;
                if (subj->chromosome.a_segments[CHROMO_A_TOKEN_BALANCE] != new_bal) {
                    subj->chromosome.a_segments[CHROMO_A_TOKEN_BALANCE] = new_bal;
                    trust_chromosome_finalize(&subj->chromosome);
                }
            }
        }
        spin_unlock_irqrestore(&s->lock, flags);
    }
}
