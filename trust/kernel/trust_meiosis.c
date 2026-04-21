/*
 * trust_meiosis.c - Meiotic shared-authority entities (Session 48)
 *
 * Implements §Meiosis from "Root of Authority" (Roberts/Eli/Leelee, Zenodo
 * 18710335).  This is a NEW concept added to the trust kernel — entirely
 * distinct from the legacy trust_lifecycle_meiotic_combine() (which only
 * cross-links two existing subjects via mutual dependency, without minting
 * a third "shared" entity).
 *
 * High-level algorithm:
 *
 *   1. For each parent A and B, draw a 32-byte random_blind from
 *      get_random_bytes() — fresh per meiosis call, never reused.
 *   2. For each chromosome pair i in [0..22]:
 *        - Pick the dominant parent for THIS pair: the one with the
 *          higher trust_score at meiosis time.  Tie-break by id.
 *        - The chosen parent's a_segments[i] is hashed with
 *          SHA-256(seg_value_le ‖ random_blind) → 32-byte digest.
 *        - The first 4 bytes of the digest become the new shared
 *          subject's a_segments[i].  The b_segments[i] is mirrored
 *          from the same dominant parent, blinded the same way.
 *      This is the "blinded gamete" — neither parent's raw segment is
 *      observable in the shared subject.
 *   3. The shared subject's authority/score are bounded:
 *        S_max = min(S(A), S(B))
 *        token cap C = floor((C(A) + C(B)) / 4)
 *      and an INDEPENDENT proof chain is seeded via trust_ape (a fresh
 *      32-byte seed from get_random_bytes — NOT inherited from either
 *      parent).
 *   4. The shared subject is marked TRUST_FLAG_SHARED_R2 (kernel-only
 *      ring -2 sentinel).  A bond record is added to a side hashtable so
 *      apoptosis on EITHER parent will cascade to the shared subject.
 *
 * Lock order (no inversions): bond_table.lock → trust_tlb set lock.
 * We never hold the bond table lock while calling trust_lifecycle, the
 * APE, or any TLB-modify path that itself takes a set lock with
 * spin_lock_irqsave — apoptosis cascade in particular invokes back
 * into the TLB, which means re-entering meiosis_on_parent_apoptosis
 * (the bond hash-walk in apoptosis path is RCU-style: snapshot ids
 * under the lock, then drop the lock and apply per-id cascades).
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/random.h>
#include <linux/atomic.h>
#include <linux/crypto.h>
#include <linux/printk.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sched.h>            /* current */
#include <linux/err.h>
#include <crypto/hash.h>

#include "trust_internal.h"
#include "trust_meiosis.h"
#include "../include/trust_theorems.h"   /* Session 49 Agent C — Reconciler */

/* ---------------------------------------------------------------------
 * Subject-id allocation for shared subjects.
 *
 * User subjects live in pid-space (1..2^31).  Shared subjects must not
 * collide with any pid the kernel might assign, so we draw from the
 * upper half of the 32-bit id space below TRUST_SUBJECT_ID_RESERVED_MAX
 * (which is the APE tombstone sentinel and rejected by APE create).
 *
 * Allocation strategy: monotonic counter starting at 0xC0000000U,
 * wrapping with collision-detect against the TLB.  Up to 64 retries
 * before returning -EEXIST so callers can backoff and try again.
 * --------------------------------------------------------------------- */

#define TRUST_MEIOSIS_ID_BASE   0xC0000000U
#define TRUST_MEIOSIS_ID_LIMIT  0xFFFFFFFEU   /* -1 reserved by APE */
#define TRUST_MEIOSIS_ID_TRIES  64

static atomic_t g_meiosis_next_id = ATOMIC_INIT(TRUST_MEIOSIS_ID_BASE);

/* Allocate a probably-fresh shared subject id.  Caller verifies in TLB. */
static u32 meiosis_alloc_id(void)
{
    u32 id = (u32)atomic_inc_return(&g_meiosis_next_id);
    if (id >= TRUST_MEIOSIS_ID_LIMIT || id < TRUST_MEIOSIS_ID_BASE) {
        /* Wrap: reset under cmpxchg-style relaxed update.  Two callers
         * racing here both wrap to BASE+1; the TLB-collision retry below
         * catches the duplicate. */
        atomic_set(&g_meiosis_next_id, TRUST_MEIOSIS_ID_BASE);
        id = TRUST_MEIOSIS_ID_BASE;
    }
    return id;
}

/* ---------------------------------------------------------------------
 * Bond table — shared subjects bonded to (typically two) parents.
 *
 * Keyed by parent_id: each parent points to a list of shared subject_ids
 * that depend on it.  When the parent enters apoptosis we walk the list
 * and trigger apoptosis on each child.
 *
 * We use a separate-chained hashtable.  HASH_BITS=8 → 256 buckets,
 * sized for ~thousands of active bonds before collisions matter.  Each
 * bond_entry holds (parent_id, shared_id) so a single shared subject
 * with two parents has TWO entries in the table (one per parent), both
 * pointing at the same shared_id.
 *
 * lock: a single spinlock guards both the hashtable and the active_bonds
 * counter.  Apoptosis-time we must not hold this while calling back into
 * lifecycle/TLB/APE; the reader pattern is "snapshot under lock, drop
 * lock, apply".
 * --------------------------------------------------------------------- */

#define MEIOSIS_HASH_BITS 8

struct meiosis_bond {
    struct hlist_node node;     /* keyed on parent_id */
    u32 parent_id;
    u32 shared_id;
};

static DEFINE_HASHTABLE(g_meiosis_bonds, MEIOSIS_HASH_BITS);
static DEFINE_SPINLOCK(g_meiosis_bond_lock);

/* Counters.  atomic64 because they are read from sysfs (slow path) and
 * incremented from the meiosis hot path / apoptosis hook. */
static atomic64_t g_meiosis_count        = ATOMIC64_INIT(0);
static atomic64_t g_meiosis_active_bonds = ATOMIC64_INIT(0);
/* Session 49 Agent C — Evactor lifetime total (orphan bonds reaped). */
static atomic64_t g_meiosis_evacted_total = ATOMIC64_INIT(0);

u64 trust_meiosis_count(void)        { return (u64)atomic64_read(&g_meiosis_count); }
u64 trust_meiosis_active_bonds(void) { return (u64)atomic64_read(&g_meiosis_active_bonds); }
u64 trust_meiosis_evacted_total(void){ return (u64)atomic64_read(&g_meiosis_evacted_total); }
EXPORT_SYMBOL_GPL(trust_meiosis_count);
EXPORT_SYMBOL_GPL(trust_meiosis_active_bonds);
EXPORT_SYMBOL_GPL(trust_meiosis_evacted_total);

/* Add a bond record.  Caller has NOT taken the lock — we take it briefly. */
static int meiosis_bond_add(u32 parent_id, u32 shared_id)
{
    struct meiosis_bond *b = kmalloc(sizeof(*b), GFP_KERNEL);
    if (!b)
        return -ENOMEM;
    b->parent_id = parent_id;
    b->shared_id = shared_id;

    spin_lock(&g_meiosis_bond_lock);
    hash_add(g_meiosis_bonds, &b->node, parent_id);
    spin_unlock(&g_meiosis_bond_lock);
    atomic64_inc(&g_meiosis_active_bonds);
    return 0;
}

/* Snapshot (and unlink + free) all bonds for a given parent.  Returns the
 * number of shared_ids written into out_ids[] (capped by max_ids).  The
 * unlinked bonds are kfree'd here so callers don't have to worry about
 * the storage.  active_bonds is decremented per-removal. */
static int meiosis_bond_snapshot_and_remove(u32 parent_id,
                                            u32 *out_ids, int max_ids)
{
    struct meiosis_bond *b;
    struct hlist_node *tmp;
    int n = 0;

    spin_lock(&g_meiosis_bond_lock);
    hash_for_each_possible_safe(g_meiosis_bonds, b, tmp, node, parent_id) {
        if (b->parent_id != parent_id)
            continue;   /* hash collision in this bucket */
        if (n < max_ids)
            out_ids[n++] = b->shared_id;
        hash_del(&b->node);
        atomic64_dec(&g_meiosis_active_bonds);
        kfree(b);
        /* Note: there can be MORE than max_ids bonds; the apoptosis hook
         * loops until snapshot returns 0 to drain them.  We don't unlink
         * past max_ids on this iteration. */
        if (n >= max_ids)
            break;
    }
    spin_unlock(&g_meiosis_bond_lock);
    return n;
}

/* ---------------------------------------------------------------------
 * Blinded-gamete derivation.
 *
 * SHA-256 over (segment_value_le || random_blind) — 4 + 32 = 36 bytes
 * input, 32 bytes output.  We take the first 4 bytes of the digest
 * as the new u32 segment value.
 * --------------------------------------------------------------------- */

static int meiosis_blind_segment(u32 seg_value, const u8 random_blind[32],
                                 u32 *out_value)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    u8 input[4 + 32];
    u8 digest[32];
    int ret;

    /* Little-endian segment encoding for cross-arch determinism */
    input[0] = (u8)(seg_value       & 0xFF);
    input[1] = (u8)((seg_value >> 8)  & 0xFF);
    input[2] = (u8)((seg_value >> 16) & 0xFF);
    input[3] = (u8)((seg_value >> 24) & 0xFF);
    memcpy(input + 4, random_blind, 32);

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    desc->tfm = tfm;
    ret = crypto_shash_digest(desc, input, sizeof(input), digest);
    kfree(desc);
    crypto_free_shash(tfm);
    if (ret)
        return ret;

    /* Take first 4 bytes (LE-decode) as new segment value */
    *out_value = ((u32)digest[0])       |
                 ((u32)digest[1] <<  8) |
                 ((u32)digest[2] << 16) |
                 ((u32)digest[3] << 24);
    return 0;
}

/* ---------------------------------------------------------------------
 * Core meiosis.
 * --------------------------------------------------------------------- */

int trust_meiosis(trust_subject_t *A, trust_subject_t *B,
                  trust_subject_t **out_shared)
{
    trust_subject_t *shared = NULL;
    u8 blind[32];
    u8 ape_seed[TRUST_SEED_SIZE];
    u32 i;
    u32 shared_id = 0;
    int ret = 0;
    int tries;

    if (!A || !B || !out_shared)
        return -EINVAL;

    /* Refuse to meiose with apoptotic / cancerous parents — paper §Meiosis
     * requires both gametes come from healthy contributors. */
    if ((A->flags & (TRUST_FLAG_APOPTOTIC | TRUST_FLAG_CANCEROUS)) ||
        (B->flags & (TRUST_FLAG_APOPTOTIC | TRUST_FLAG_CANCEROUS)))
        return -EINVAL;

    /* Refuse cross-domain meiosis: a Linux subject and a Win32 subject
     * cannot share a chromosome (their B-segments mean different things). */
    if (A->domain != B->domain)
        return -EINVAL;

    shared = kzalloc(sizeof(*shared), GFP_KERNEL);
    if (!shared)
        return -ENOMEM;

    /* Allocate id with collision retry against the TLB. */
    for (tries = 0; tries < TRUST_MEIOSIS_ID_TRIES; tries++) {
        trust_subject_t probe;
        shared_id = meiosis_alloc_id();
        if (trust_tlb_lookup(shared_id, &probe) != 0) {
            /* Miss — id is free for our use. */
            break;
        }
        shared_id = 0;
    }
    if (shared_id == 0) {
        ret = -EEXIST;
        goto err_free;
    }

    /* Fresh per-meiosis blind for the chromosome derivation. */
    get_random_bytes(blind, sizeof(blind));

    /* Initialize identity fields first so callbacks have valid context. */
    shared->subject_id      = shared_id;
    shared->domain          = A->domain;
    shared->subject_class   = TRUST_SUBJECT_CLASS_UNKNOWN;
    shared->trust_score     = (A->trust_score < B->trust_score) ?
                              A->trust_score : B->trust_score;
    /* threshold mirrors authority — use the LOWER parent's bounds. */
    shared->threshold_low   = (A->threshold_low > B->threshold_low) ?
                              A->threshold_low : B->threshold_low;
    shared->threshold_high  = (A->threshold_high < B->threshold_high) ?
                              A->threshold_high : B->threshold_high;
    /* Caps: intersection — shared can never do something neither parent
     * could.  Belt-and-braces with the score cap above. */
    shared->capabilities    = A->capabilities & B->capabilities;
    /* Authority level: keep the lower; ring-(-2) is enforced via the flag. */
    shared->authority_level = (A->authority_level < B->authority_level) ?
                              A->authority_level : B->authority_level;
    shared->last_action_ts  = trust_get_timestamp();
    shared->decay_rate      = (A->decay_rate + B->decay_rate) / 2;
    shared->flags           = TRUST_FLAG_NEW | TRUST_FLAG_MEIOTIC |
                              TRUST_FLAG_SHARED_R2;

    /* Chromosome derivation: dominance-by-trust per pair. */
    for (i = 0; i < TRUST_CHROMOSOME_PAIRS; i++) {
        trust_subject_t *dom;
        u32 a_blinded, b_blinded;

        if (A->trust_score > B->trust_score)
            dom = A;
        else if (A->trust_score < B->trust_score)
            dom = B;
        else
            dom = (A->subject_id <= B->subject_id) ? A : B;

        ret = meiosis_blind_segment(dom->chromosome.a_segments[i], blind,
                                    &a_blinded);
        if (ret) goto err_free;
        ret = meiosis_blind_segment(dom->chromosome.b_segments[i], blind,
                                    &b_blinded);
        if (ret) goto err_free;

        shared->chromosome.a_segments[i] = a_blinded;
        shared->chromosome.b_segments[i] = b_blinded;
    }
    shared->chromosome.parent_id       = A->subject_id;  /* primary parent */
    shared->chromosome.generation      = (A->chromosome.generation >
                                          B->chromosome.generation ?
                                          A->chromosome.generation :
                                          B->chromosome.generation) + 1;
    shared->chromosome.birth_timestamp = trust_get_timestamp();
    shared->chromosome.division_count  = 0;
    shared->chromosome.mutation_count  = 0;
    /* Recompute checksum via the canonical helper (decl in trust_internal.h). */
    shared->chromosome.checksum =
        trust_chromosome_checksum(&shared->chromosome);

    /* Token allocation: floor((C(A) + C(B)) / 4) per paper. */
    {
        s64 ca = (s64)A->tokens.balance;
        s64 cb = (s64)B->tokens.balance;
        s64 cap_max = (s64)A->tokens.max_balance + (s64)B->tokens.max_balance;
        s64 alloc = (ca + cb) / 4;
        if (alloc < 0) alloc = 0;
        if (alloc > cap_max / 4) alloc = cap_max / 4;
        shared->tokens.balance        = (s32)alloc;
        shared->tokens.max_balance    = (s32)(cap_max / 4);
        shared->tokens.regen_rate     = (A->tokens.regen_rate +
                                         B->tokens.regen_rate) / 2;
        shared->tokens.last_regen_ts  = trust_get_timestamp();
        shared->tokens.starved        = (alloc <= 0) ? 1 : 0;
    }

    /* Lifecycle bookkeeping. */
    shared->lifecycle.state            = TRUST_LIFECYCLE_COMBINING;
    shared->lifecycle.generation       = shared->chromosome.generation;
    shared->lifecycle.parent_id        = A->subject_id;
    shared->lifecycle.meiotic_partner  = B->subject_id;
    shared->lifecycle.birth_ts         = trust_get_timestamp();
    shared->lifecycle.max_score        = shared->trust_score;
    shared->lifecycle.flags            = 0;

    /* Immune + TRC at defaults. */
    trust_immune_init(&shared->immune);
    trust_trc_init(&shared->trc);

    /* Install in TLB so subsequent lookups find it. */
    ret = trust_tlb_insert(shared);
    if (ret) {
        ret = -ENOMEM;
        goto err_free;
    }

    /* Independent proof chain — seed is FRESH, not inherited.  This is
     * the cryptographic guarantee that the shared entity cannot
     * impersonate either parent (no shared seed material). */
    get_random_bytes(ape_seed, sizeof(ape_seed));
    ret = trust_ape_create_entity(shared_id, ape_seed, sizeof(ape_seed));
    /* Wipe the seed buffer immediately — it lives only inside APE now. */
    memzero_explicit(ape_seed, sizeof(ape_seed));
    if (ret && ret != -EEXIST) {
        /* APE init failed — roll back TLB so we don't leave a half-formed
         * subject behind. */
        trust_tlb_invalidate(shared_id);
        ret = -EIO;
        goto err_free;
    }

    /* Bond both parents.  If the second add fails, we MUST tear down the
     * first and the entire shared subject — otherwise apoptosis on B
     * wouldn't propagate.  A partial shared subject is worse than none. */
    ret = meiosis_bond_add(A->subject_id, shared_id);
    if (ret) {
        trust_ape_destroy_entity(shared_id);
        trust_tlb_invalidate(shared_id);
        goto err_free;
    }
    ret = meiosis_bond_add(B->subject_id, shared_id);
    if (ret) {
        u32 tmp[1];
        (void)meiosis_bond_snapshot_and_remove(A->subject_id, tmp, 1);
        trust_ape_destroy_entity(shared_id);
        trust_tlb_invalidate(shared_id);
        goto err_free;
    }

    /* Wipe the per-meiosis blind from kernel memory.  Ephemeral randomness
     * — once the chromosome is derived, leaving the blind in stack
     * memory serves no purpose and slightly weakens forward secrecy. */
    memzero_explicit(blind, sizeof(blind));

    atomic64_inc(&g_meiosis_count);
    pr_info("trust_meiosis: shared subject %u from parents %u + %u "
            "(score=%d, gen=%u, ring=-2)\n",
            shared_id, A->subject_id, B->subject_id,
            shared->trust_score, shared->chromosome.generation);

    *out_shared = shared;

    /*
     * Session 49 Agent C — Reconciler hook.
     *
     * Theorem 4 (Bounded Authority Inheritance) for meiosis:
     *   S_max(shared) <= min(S_max(A), S_max(B)).
     *
     * Pass three subject pointers as `const void *` per trust_theorems.h.
     * The shared subject's max_score was set above to its own trust_score
     * (which is min(A->trust_score, B->trust_score)); the invariant
     * routine reads ->lifecycle.max_score on each.  All three pointers
     * are valid for the duration of this call: A and B are caller-owned
     * stack snapshots, shared is our just-allocated kzalloc.
     */
    trust_invariants_check_meiosis((const void *)A,
                                   (const void *)B,
                                   (const void *)shared);

    return 0;

err_free:
    memzero_explicit(blind, sizeof(blind));
    if (shared)
        kfree(shared);
    *out_shared = NULL;
    return ret;
}
EXPORT_SYMBOL_GPL(trust_meiosis);

/* ---------------------------------------------------------------------
 * ioctl wrapper — TRUST_IOC_MEIOSIS path.
 * --------------------------------------------------------------------- */

int trust_meiosis_request_by_id(u32 parent_a_id, u32 parent_b_id,
                                u32 *out_shared_id)
{
    trust_subject_t a_snap, b_snap;
    trust_subject_t *shared = NULL;
    int ret;

    if (!out_shared_id)
        return -EINVAL;
    if (parent_a_id == parent_b_id)
        return -EINVAL;
    /* Refuse the APE tombstone sentinel as either parent. */
    if (parent_a_id == TRUST_SUBJECT_ID_RESERVED_MAX ||
        parent_b_id == TRUST_SUBJECT_ID_RESERVED_MAX)
        return -EINVAL;

    /* Cap gate: caller (current process) needs TRUST_CAP_TRUST_MODIFY on
     * BOTH parents.  This mirrors the pattern in TRUST_IOC_SET_SUBJECT_CLASS:
     * we check the caller's own subject record, not the targets'.  An
     * unregistered caller fails the first check and gets -EPERM. */
    if (!trust_risc_check_cap((u32)current->pid, TRUST_CAP_TRUST_MODIFY))
        return -EPERM;

    if (trust_tlb_lookup(parent_a_id, &a_snap) != 0)
        return -ESRCH;
    if (trust_tlb_lookup(parent_b_id, &b_snap) != 0)
        return -ESRCH;

    /* Refuse if either parent is itself a ring-(-2) shared subject —
     * meiosis-of-meiosis would create unbounded bond depth. */
    if ((a_snap.flags | b_snap.flags) & TRUST_FLAG_SHARED_R2)
        return -EINVAL;

    ret = trust_meiosis(&a_snap, &b_snap, &shared);
    if (ret)
        return ret;

    *out_shared_id = shared->subject_id;
    /* trust_meiosis() already inserted shared into the TLB; the heap copy
     * was a working buffer.  Free it now — the canonical state is in TLB. */
    kfree(shared);
    return 0;
}
EXPORT_SYMBOL_GPL(trust_meiosis_request_by_id);

/* ---------------------------------------------------------------------
 * Apoptosis bond hook — called from trust_lifecycle.c (Agent 3).
 * --------------------------------------------------------------------- */

void trust_meiosis_on_parent_apoptosis(u32 parent_id)
{
    /* Drain in batches to keep stack usage bounded and the lock window
     * short.  A single shared subject may be bonded to many parents; we
     * only kill it once (apoptosis is idempotent in trust_lifecycle). */
    enum { BATCH = 16 };
    u32 ids[BATCH];
    int n;

    for (;;) {
        n = meiosis_bond_snapshot_and_remove(parent_id, ids, BATCH);
        if (n <= 0)
            return;
        while (n-- > 0) {
            int rc = trust_lifecycle_apoptosis(ids[n]);
            if (rc && rc != -ENOENT) {
                /* -ENOENT just means the shared subject was already gone. */
                pr_warn("trust_meiosis: apoptosis(shared=%u) on parent=%u "
                        "death returned %d\n", ids[n], parent_id, rc);
            } else if (rc == 0) {
                pr_info("trust_meiosis: shared %u died with parent %u\n",
                        ids[n], parent_id);
            }
        }
    }
}
EXPORT_SYMBOL_GPL(trust_meiosis_on_parent_apoptosis);

/* ---------------------------------------------------------------------
 * Session 49 Agent C — Evactor: meiotic-bond orphan eviction.
 *
 * Walks the bond hashtable.  For each bond, checks whether the parent
 * still exists in the TLB.  If the parent is gone, fires
 * trust_meiosis_on_parent_apoptosis(parent_id) which cascades apoptosis
 * to the bonded shared subject AND removes the bond entry.
 *
 * Bounded: at most TRUST_MEIOSIS_EVACT_CAP missing-parent ids per call.
 * Run from trust_lifecycle.c's delayed_work tick (every 30s).  Counter
 * exported as /sys/kernel/trust/meiosis_evacted_total.
 *
 * Lock policy: snapshot missing-parent ids under g_meiosis_bond_lock,
 * drop the lock, then dispatch — trust_meiosis_on_parent_apoptosis
 * re-takes the lock to remove its own bond entries; we MUST NOT hold
 * it across that call.  De-dup the snapshot so multiple bond entries
 * for the same dead parent only trigger one cascade.
 * --------------------------------------------------------------------- */
#define TRUST_MEIOSIS_EVACT_CAP 64

int trust_meiosis_evact_orphans(void)
{
    u32 missing_parents[TRUST_MEIOSIS_EVACT_CAP];
    int n_missing = 0;
    int processed = 0;
    struct meiosis_bond *b;
    struct hlist_node *tmp;
    int bkt, i, j, dup;
    trust_subject_t probe;

    /* Phase 1: snapshot bonds whose parent is gone.  We only read the
     * parent_id field; the TLB lookup happens after the lock is dropped
     * to avoid lock-order issues with trust_tlb's set spinlocks. */
    {
        u32 candidate_parents[TRUST_MEIOSIS_EVACT_CAP];
        int n_cand = 0;

        spin_lock(&g_meiosis_bond_lock);
        hash_for_each_safe(g_meiosis_bonds, bkt, tmp, b, node) {
            if (n_cand >= TRUST_MEIOSIS_EVACT_CAP)
                break;
            /* De-dup against already-snapshotted parents in this pass. */
            dup = 0;
            for (j = 0; j < n_cand; j++) {
                if (candidate_parents[j] == b->parent_id) { dup = 1; break; }
            }
            if (!dup)
                candidate_parents[n_cand++] = b->parent_id;
        }
        spin_unlock(&g_meiosis_bond_lock);

        /* Phase 2: outside the lock, query the TLB for each candidate. */
        for (i = 0; i < n_cand && n_missing < TRUST_MEIOSIS_EVACT_CAP; i++) {
            if (trust_tlb_lookup(candidate_parents[i], &probe) != 0)
                missing_parents[n_missing++] = candidate_parents[i];
        }
    }

    /* Phase 3: fire the cascade per missing parent.  This removes the
     * bond entry AND triggers apoptosis of the shared subject. */
    for (i = 0; i < n_missing; i++) {
        trust_meiosis_on_parent_apoptosis(missing_parents[i]);
        atomic64_inc(&g_meiosis_evacted_total);
        processed++;
    }

    return processed;
}
EXPORT_SYMBOL_GPL(trust_meiosis_evact_orphans);

/* ---------------------------------------------------------------------
 * sysfs nodes: /sys/kernel/trust/meiosis_count, /sys/kernel/trust/meiosis_active_bonds
 *
 * trust_stats.c owns the kobject at /sys/kernel/trust.  Rather than
 * coupling to its (file-static) handle, we look it up via kset_find_obj
 * on kernel_kobj's kset.  If the lookup fails (stats kobject not
 * created — possible during early init or in test fixtures) we fall
 * back to a private kobject "trust_meiosis" so the counters are still
 * observable, just at a different path.
 * --------------------------------------------------------------------- */

static ssize_t meiosis_count_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
    (void)kobj; (void)attr;
    return scnprintf(buf, PAGE_SIZE, "%llu\n",
                     (unsigned long long)trust_meiosis_count());
}
static ssize_t meiosis_active_bonds_show(struct kobject *kobj,
                                         struct kobj_attribute *attr, char *buf)
{
    (void)kobj; (void)attr;
    return scnprintf(buf, PAGE_SIZE, "%llu\n",
                     (unsigned long long)trust_meiosis_active_bonds());
}
/* Session 49 Agent C — Evactor counter sysfs node. */
static ssize_t meiosis_evacted_total_show(struct kobject *kobj,
                                          struct kobj_attribute *attr, char *buf)
{
    (void)kobj; (void)attr;
    return scnprintf(buf, PAGE_SIZE, "%llu\n",
                     (unsigned long long)trust_meiosis_evacted_total());
}

static struct kobj_attribute meiosis_count_attr =
    __ATTR(meiosis_count, 0444, meiosis_count_show, NULL);
static struct kobj_attribute meiosis_active_bonds_attr =
    __ATTR(meiosis_active_bonds, 0444, meiosis_active_bonds_show, NULL);
static struct kobj_attribute meiosis_evacted_total_attr =
    __ATTR(meiosis_evacted_total, 0444, meiosis_evacted_total_show, NULL);

static struct attribute *meiosis_sysfs_attrs[] = {
    &meiosis_count_attr.attr,
    &meiosis_active_bonds_attr.attr,
    &meiosis_evacted_total_attr.attr,
    NULL,
};
static const struct attribute_group meiosis_sysfs_group = {
    .attrs = meiosis_sysfs_attrs,
};

/* Owned-by-us fallback kobject only created if /sys/kernel/trust missing. */
static struct kobject *g_meiosis_fallback_kobj;
/* Whichever kobject we successfully attached to (for unregister). */
static struct kobject *g_meiosis_attached_kobj;

int trust_meiosis_register_sysfs(void)
{
    struct kobject *target = NULL;
    int ret;

    /* Try to find the kobject that trust_stats.c created.  kernel_kobj
     * is itself in a kset, and kobject_create_and_add adds children to
     * the parent's kset.  We walk the kset for "trust". */
    if (kernel_kobj && kernel_kobj->kset)
        target = kset_find_obj(kernel_kobj->kset, "trust");

    if (!target) {
        /* Stats kobject not present — make our own subdir.  This means
         * the counters appear under /sys/kernel/trust_meiosis instead of
         * under /sys/kernel/trust.  Operators reading a documented path
         * should still grep meiosis_count under /sys/kernel/trust*. */
        g_meiosis_fallback_kobj =
            kobject_create_and_add("trust_meiosis", kernel_kobj);
        if (!g_meiosis_fallback_kobj)
            return -ENOMEM;
        target = g_meiosis_fallback_kobj;
        kobject_get(target);   /* matched by put in unregister */
    }

    ret = sysfs_create_group(target, &meiosis_sysfs_group);
    if (ret) {
        kobject_put(target);
        if (g_meiosis_fallback_kobj == target) {
            kobject_put(g_meiosis_fallback_kobj);
            g_meiosis_fallback_kobj = NULL;
        }
        return ret;
    }

    g_meiosis_attached_kobj = target;
    return 0;
}
EXPORT_SYMBOL_GPL(trust_meiosis_register_sysfs);

void trust_meiosis_unregister_sysfs(void)
{
    if (g_meiosis_attached_kobj) {
        sysfs_remove_group(g_meiosis_attached_kobj, &meiosis_sysfs_group);
        kobject_put(g_meiosis_attached_kobj);
        g_meiosis_attached_kobj = NULL;
    }
    if (g_meiosis_fallback_kobj) {
        kobject_put(g_meiosis_fallback_kobj);
        g_meiosis_fallback_kobj = NULL;
    }
}
EXPORT_SYMBOL_GPL(trust_meiosis_unregister_sysfs);

/* ---------------------------------------------------------------------
 * init / cleanup
 * --------------------------------------------------------------------- */

int trust_meiosis_init(void)
{
    hash_init(g_meiosis_bonds);
    atomic64_set(&g_meiosis_count, 0);
    atomic64_set(&g_meiosis_active_bonds, 0);
    pr_info("trust_meiosis: initialized (ring -2 shared-authority subsystem)\n");
    return 0;
}
EXPORT_SYMBOL_GPL(trust_meiosis_init);

/* Session 49 Agent C — forward decl: stop the Reaper/Pruner/Evactor
 * delayed_work BEFORE we drain bonds.  If a tick fires concurrently
 * with the bond drain it would walk freed bond entries (use-after-free).
 * Defined in trust_lifecycle.c.  Called only here because trust_core.c
 * (Agent E's domain) does not yet wire a trust_lifecycle_cleanup. */
extern void trust_lifecycle_reaper_stop(void);

void trust_meiosis_cleanup(void)
{
    struct meiosis_bond *b;
    struct hlist_node *tmp;
    int bkt;

    /* Stop the janitor first so no concurrent tick can race the bond
     * drain below.  cancel_delayed_work_sync() drains any in-flight
     * tick. */
    trust_lifecycle_reaper_stop();

    /* Drain any remaining bonds — module-unload cleanup. */
    spin_lock(&g_meiosis_bond_lock);
    hash_for_each_safe(g_meiosis_bonds, bkt, tmp, b, node) {
        hash_del(&b->node);
        atomic64_dec(&g_meiosis_active_bonds);
        kfree(b);
    }
    spin_unlock(&g_meiosis_bond_lock);
    pr_info("trust_meiosis: cleanup complete (count=%llu, bonds=%llu)\n",
            (unsigned long long)atomic64_read(&g_meiosis_count),
            (unsigned long long)atomic64_read(&g_meiosis_active_bonds));
}
EXPORT_SYMBOL_GPL(trust_meiosis_cleanup);
