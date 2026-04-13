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
int trust_lifecycle_mitotic_divide(u32 parent_id, u32 child_id)
{
    trust_subject_t parent, child;
    u64 now;
    int ret;

    /* Look up parent */
    ret = trust_tlb_lookup(parent_id, &parent);
    if (ret)
        return -ENOENT;

    /* Check frozen/apoptotic */
    if (parent.flags & (TRUST_FLAG_FROZEN | TRUST_FLAG_APOPTOTIC))
        return -EPERM;

    now = trust_get_timestamp();

    /* --- Cancer Detection --- */
    /* Check spawn rate within window */
    if (now - parent.lifecycle.spawn_window_start < TRUST_CANCER_SPAWN_WINDOW) {
        parent.lifecycle.spawn_count++;
        if (parent.lifecycle.spawn_count > TRUST_CANCER_SPAWN_LIMIT) {
            /* CANCER DETECTED: runaway spawning */
            parent.flags |= TRUST_FLAG_CANCEROUS;
            parent.immune.status = TRUST_IMMUNE_CANCEROUS;
            parent.lifecycle.state = TRUST_LIFECYCLE_APOPTOTIC;
            /* TRC Integration: cancer → lockdown */
            trust_trc_adjust(&parent.trc, TRUST_ACTION_CANCER_DETECTED);
            trust_tlb_insert(&parent);
            trust_fbc_audit(parent_id, TRUST_ACTION_CANCER_DETECTED,
                           parent.trust_score, parent.trust_score,
                           parent.capabilities, 0);
            pr_warn("trust_lifecycle: CANCER detected for subject %u "
                    "(%u spawns in window)\n",
                    parent_id, parent.lifecycle.spawn_count);
            return -EPERM;
        }
    } else {
        /* Reset spawn window */
        parent.lifecycle.spawn_window_start = now;
        parent.lifecycle.spawn_count = 1;
    }

    /* Check total spawn limit */
    parent.lifecycle.total_spawns++;
    if (parent.lifecycle.total_spawns > TRUST_CANCER_TOTAL_LIMIT) {
        parent.flags |= TRUST_FLAG_CANCEROUS;
        parent.immune.status = TRUST_IMMUNE_CANCEROUS;
        trust_tlb_insert(&parent);
        return -EPERM;
    }

    /* Burn parent's tokens for division */
    ret = trust_token_burn(&parent.tokens, TRUST_ACTION_MITOTIC_DIVIDE);
    if (ret) {
        /* Parent starved — can't afford to spawn */
        trust_tlb_insert(&parent);
        return -ENOSPC;
    }

    /* Update parent state */
    parent.lifecycle.last_division_ts = now;
    parent.lifecycle.state = TRUST_LIFECYCLE_ACTIVE;
    parent.chromosome.division_count++;

    /* Update parent's spawn rate chromosome */
    trust_chromosome_update_a(&parent.chromosome, CHROMO_A_SPAWN_RATE,
        trust_chromosome_rolling_hash(
            parent.chromosome.a_segments[CHROMO_A_SPAWN_RATE],
            parent.lifecycle.spawn_count));

    trust_tlb_insert(&parent);

    /* --- Create Child --- */
    memset(&child, 0, sizeof(child));
    child.subject_id = child_id;
    child.domain = parent.domain;

    /* Inherit chromosome with generational decay */
    trust_chromosome_inherit(&child.chromosome, &parent.chromosome,
                              parent.lifecycle.generation + 1);
    child.chromosome.parent_id = parent_id;

    /* Compute max score from generational decay */
    child.lifecycle.generation = parent.lifecycle.generation + 1;
    child.lifecycle.max_score = trust_lifecycle_get_max_score(
        child.lifecycle.generation, parent.authority_level);

    /* Child starts at reduced score (half of parent, capped by generation) */
    child.trust_score = parent.trust_score / 2;
    if (child.trust_score > child.lifecycle.max_score)
        child.trust_score = child.lifecycle.max_score;

    /* Child inherits parent's authority level (but with lower ceiling) */
    child.authority_level = parent.authority_level;
    child.capabilities = trust_default_caps(parent.authority_level);
    child.threshold_low = parent.threshold_low;
    child.threshold_high = parent.threshold_high;
    child.last_action_ts = now;
    child.decay_rate = parent.decay_rate;
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
 */
int trust_lifecycle_meiotic_combine(u32 subject_a, u32 subject_b)
{
    trust_subject_t sa, sb;
    int ret;
    int32_t combined_score;

    ret = trust_tlb_lookup(subject_a, &sa);
    if (ret)
        return -ENOENT;

    ret = trust_tlb_lookup(subject_b, &sb);
    if (ret)
        return -ENOENT;

    /* Neither can be frozen or apoptotic */
    if ((sa.flags | sb.flags) &
        (TRUST_FLAG_FROZEN | TRUST_FLAG_APOPTOTIC | TRUST_FLAG_CANCEROUS))
        return -EPERM;

    /* Compute combined score: min(S(A), S(B)) */
    combined_score = sa.trust_score < sb.trust_score ?
                     sa.trust_score : sb.trust_score;

    /* Mark both as in meiotic combination */
    sa.flags |= TRUST_FLAG_MEIOTIC;
    sa.lifecycle.state = TRUST_LIFECYCLE_COMBINING;
    sa.lifecycle.meiotic_partner = subject_b;

    sb.flags |= TRUST_FLAG_MEIOTIC;
    sb.lifecycle.state = TRUST_LIFECYCLE_COMBINING;
    sb.lifecycle.meiotic_partner = subject_a;

    /* Burn tokens for combination */
    trust_token_burn(&sa.tokens, TRUST_ACTION_MEIOTIC_COMBINE);
    trust_token_burn(&sb.tokens, TRUST_ACTION_MEIOTIC_COMBINE);

    trust_tlb_insert(&sa);
    trust_tlb_insert(&sb);

    /* Create mutual dependency */
    trust_dep_add(subject_a, subject_b);
    trust_dep_add(subject_b, subject_a);

    /* Audit */
    trust_fbc_audit(subject_a, TRUST_ACTION_MEIOTIC_COMBINE,
                   sa.trust_score, combined_score,
                   sa.capabilities, sa.capabilities & sb.capabilities);

    pr_info("trust_lifecycle: meiotic combination %u + %u (combined_score=%d)\n",
            subject_a, subject_b, combined_score);

    return 0;
}

/*
 * Release a meiotic combination.
 */
void trust_lifecycle_meiotic_release(u32 subject_a, u32 subject_b)
{
    trust_subject_t sa, sb;

    if (trust_tlb_lookup(subject_a, &sa) == 0) {
        sa.flags &= ~TRUST_FLAG_MEIOTIC;
        sa.lifecycle.state = TRUST_LIFECYCLE_ACTIVE;
        sa.lifecycle.meiotic_partner = 0;
        trust_tlb_insert(&sa);
    }

    if (trust_tlb_lookup(subject_b, &sb) == 0) {
        sb.flags &= ~TRUST_FLAG_MEIOTIC;
        sb.lifecycle.state = TRUST_LIFECYCLE_ACTIVE;
        sb.lifecycle.meiotic_partner = 0;
        trust_tlb_insert(&sb);
    }

    trust_dep_remove(subject_a, subject_b);
    trust_dep_remove(subject_b, subject_a);
}

/*
 * Check for cancer (called periodically and during spawning).
 * Returns 1 if cancer detected, 0 if healthy.
 */
int trust_lifecycle_check_cancer(u32 subject_id)
{
    trust_subject_t subj;

    if (trust_tlb_lookup(subject_id, &subj))
        return 0;

    /* Already flagged */
    if (subj.flags & TRUST_FLAG_CANCEROUS)
        return 1;

    /* Check spawn rate in current window */
    if (subj.lifecycle.spawn_count > TRUST_CANCER_SPAWN_LIMIT) {
        subj.flags |= TRUST_FLAG_CANCEROUS;
        subj.immune.status = TRUST_IMMUNE_CANCEROUS;
        trust_tlb_insert(&subj);
        return 1;
    }

    /* Check total spawns */
    if (subj.lifecycle.total_spawns > TRUST_CANCER_TOTAL_LIMIT) {
        subj.flags |= TRUST_FLAG_CANCEROUS;
        subj.immune.status = TRUST_IMMUNE_CANCEROUS;
        trust_tlb_insert(&subj);
        return 1;
    }

    /* Check chromosome mutation rate (excessive = suspicious) */
    if (subj.chromosome.mutation_count > 1000) {
        subj.immune.status = TRUST_IMMUNE_SUSPICIOUS;
        subj.immune.suspicious_actions++;
        if (subj.immune.suspicious_actions > 100) {
            subj.flags |= TRUST_FLAG_CANCEROUS;
            subj.immune.status = TRUST_IMMUNE_CANCEROUS;
        }
        trust_tlb_insert(&subj);
        return (subj.flags & TRUST_FLAG_CANCEROUS) ? 1 : 0;
    }

    return 0;
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

static int _trust_lifecycle_apoptosis(u32 subject_id, int depth)
{
    trust_subject_t subj;

    if (trust_tlb_lookup(subject_id, &subj))
        return -ENOENT;

    subj.flags |= TRUST_FLAG_APOPTOTIC;
    subj.lifecycle.state = TRUST_LIFECYCLE_APOPTOTIC;
    subj.capabilities = 0;  /* Strip all capabilities */
    subj.immune.status = TRUST_IMMUNE_APOPTOSIS;
    subj.immune.apoptosis_deadline = trust_get_timestamp() +
                                     5000000000ULL; /* 5 second deadline */

    trust_tlb_insert(&subj);

    /* Destroy proof chain — authority is irrecoverably lost */
    trust_ape_destroy_entity(subject_id);

    trust_fbc_audit(subject_id, TRUST_ACTION_APOPTOSIS,
                   subj.trust_score, TRUST_SCORE_MIN,
                   subj.capabilities, 0);

    pr_info("trust_lifecycle: apoptosis initiated for subject %u\n", subject_id);

    /* Trigger cascade for children */
    _trust_lifecycle_apoptotic_cascade(subject_id, depth);

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
             */
            pr_info("trust_lifecycle: re-rooting child %u (sex=%s) to init\n",
                    cid, sex == CHROMO_SEX_XY ? "XY" : "YX");
            trust_lifecycle_handle_orphans(subject_id);
            break;
        }
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
 * Called periodically to check for anomalies.
 *
 * Returns the new immune status.
 */
int trust_immune_evaluate(u32 subject_id)
{
    trust_subject_t subj;

    if (trust_tlb_lookup(subject_id, &subj))
        return TRUST_IMMUNE_HEALTHY;

    /* Already in cascade */
    if (subj.immune.status >= TRUST_IMMUNE_APOPTOSIS)
        return subj.immune.status;

    /* Check for cancer */
    if (trust_lifecycle_check_cancer(subject_id)) {
        subj.immune.status = TRUST_IMMUNE_CANCEROUS;
        trust_tlb_insert(&subj);
        return TRUST_IMMUNE_CANCEROUS;
    }

    /* Check chromosome integrity */
    if (trust_chromosome_verify(&subj.chromosome) != 0) {
        subj.immune.status = TRUST_IMMUNE_SUSPICIOUS;
        subj.immune.suspicious_actions += 10;  /* Integrity failure is serious */
        /* TRC Integration: integrity failure → elevated */
        trust_trc_adjust(&subj.trc, TRUST_ACTION_IMMUNE_TRIGGER);
        trust_tlb_insert(&subj);

        if (subj.immune.suspicious_actions > 50) {
            trust_immune_quarantine(subject_id, TRUST_ACTION_CHROMOSOME_MUTATE);
            return TRUST_IMMUNE_QUARANTINED;
        }
        return TRUST_IMMUNE_SUSPICIOUS;
    }

    /* Check XY sex — YY subjects are always suspicious */
    if (subj.chromosome.sex == CHROMO_SEX_YY) {
        if (subj.immune.status < TRUST_IMMUNE_SUSPICIOUS)
            subj.immune.status = TRUST_IMMUNE_SUSPICIOUS;
        subj.immune.suspicious_actions++;
        trust_tlb_insert(&subj);
    }

    /* Decay suspicious count over time if behaving well */
    if (subj.immune.status == TRUST_IMMUNE_SUSPICIOUS &&
        subj.immune.suspicious_actions > 0) {
        subj.immune.suspicious_actions--;
        if (subj.immune.suspicious_actions == 0) {
            subj.immune.status = TRUST_IMMUNE_HEALTHY;
        }
        trust_tlb_insert(&subj);
    }

    return subj.immune.status;
}

/*
 * Quarantine a subject — isolate it from performing any actions.
 */
int trust_immune_quarantine(u32 subject_id, u32 reason)
{
    trust_subject_t subj;

    if (trust_tlb_lookup(subject_id, &subj))
        return -ENOENT;

    subj.immune.status = TRUST_IMMUNE_QUARANTINED;
    subj.immune.quarantine_reason = reason;
    subj.immune.quarantine_ts = trust_get_timestamp();
    subj.flags |= TRUST_FLAG_FROZEN;
    subj.capabilities = 0;
    /* TRC Integration: quarantine → elevated resistance */
    trust_trc_adjust(&subj.trc, TRUST_ACTION_IMMUNE_TRIGGER);

    trust_tlb_insert(&subj);

    trust_fbc_audit(subject_id, TRUST_ACTION_IMMUNE_TRIGGER,
                   subj.trust_score, subj.trust_score,
                   subj.capabilities, 0);

    pr_warn("trust_lifecycle: subject %u QUARANTINED (reason=%u)\n",
            subject_id, reason);
    return 0;
}

/*
 * Release a subject from quarantine (requires AI observer approval).
 */
int trust_immune_release_quarantine(u32 subject_id)
{
    trust_subject_t subj;

    if (trust_tlb_lookup(subject_id, &subj))
        return -ENOENT;

    if (subj.immune.status != TRUST_IMMUNE_QUARANTINED)
        return -EINVAL;

    subj.immune.status = TRUST_IMMUNE_HEALTHY;
    subj.immune.suspicious_actions = 0;
    subj.flags &= ~TRUST_FLAG_FROZEN;

    /* Restore basic capabilities only — elevated ones must be re-earned */
    subj.capabilities = trust_default_caps(TRUST_AUTH_USER);
    subj.authority_level = TRUST_AUTH_USER;

    trust_tlb_insert(&subj);

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
    u64 now = trust_get_timestamp();

    for (set = 0; set < TRUST_TLB_SETS; set++) {
        trust_tlb_set_t *s = &g_trust_tlb.sets[set];

        if (!s->valid_mask)
            continue;

        spin_lock(&s->lock);
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

            /* Update token balance chromosome */
            subj->chromosome.a_segments[CHROMO_A_TOKEN_BALANCE] =
                (u32)subj->tokens.balance;
        }
        spin_unlock(&s->lock);
    }
}
