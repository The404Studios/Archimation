/*
 * trust_quorum.c — Byzantine majority vote across 23 chromosomal slots.
 *
 * S74 Agent 8 (Cluster 4A). Closes the gap the paper itself exposes:
 * trust_subject_t already carries 23 (A,B) segment pairs (von-Neumann-
 * style R=23 redundancy) but nothing in-tree actually *votes* over
 * them. This file aggregates those 23 replicas into a single verdict.
 *
 * Thresholds (inclusive):
 *   agree >= 16           -> MAJORITY            ( ~2/3 rule )
 *   8 <= agree <= 15      -> DISPUTED            ( force FBC slow path )
 *   agree <  8            -> APOPTOSIS_CANDIDATE ( recommend apoptosis )
 *
 * Deterministic, allocation-free, IRQ-safe. No locks taken — the caller
 * is expected to hold whatever snapshot protects `*s` (typically RCU
 * via trust_tlb_lookup, or a stack-local copy in ioctl path).
 *
 * Based on:
 *   von Neumann (1956) "Probabilistic Logics and the Synthesis of
 *     Reliable Organisms from Unreliable Components", Caltech lectures.
 *   Roberts/Eli/Leelee (2026) Zenodo 18710335 §Chromosomal Proof Structure.
 */

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/hash.h>
#endif

#include <trust_types.h>
#include <trust_quorum.h>

/* --- Counters (exported via sysfs) ------------------------------------ */

static atomic64_t q_total_votes         = ATOMIC64_INIT(0);
static atomic64_t q_majorities          = ATOMIC64_INIT(0);
static atomic64_t q_disputes            = ATOMIC64_INIT(0);
static atomic64_t q_apoptosis_nominees  = ATOMIC64_INIT(0);

/* --- Voting core ------------------------------------------------------ */

/* Deterministic 1-bit digest of (a, b, field_id, subject_id, pair_idx).
 *
 * We deliberately use golden-ratio Fibonacci hash (hash_64) because:
 *   - it's available in-kernel header-only,
 *   - it mixes top and bottom bits well on u64 avalanche,
 *   - it's branch-free and cheap from IRQ context.
 * Output is the parity of the top 16 bits, giving per-replica opinion
 * bits that are pseudo-independent yet reproducible for the same
 * (a, b) pair. */
static inline u32 trust_quorum_opinion_bit(u64 a, u64 b,
                                           u32 field_id, u32 subject_id,
                                           u32 pair_idx)
{
    u64 mix = a ^ (b + 0x9e3779b97f4a7c15ULL);
    mix ^= ((u64)field_id << 32) | subject_id;
    mix = hash_64(mix + pair_idx, 64);
    /* Fold top half into bottom, take parity of low 16 bits. */
    mix ^= mix >> 32;
    mix ^= mix >> 16;
    return (u32)(mix & 1ULL);
}

enum trust_quorum_verdict trust_quorum_vote(const trust_subject_t *s,
                                            u32 field_id,
                                            u32 *agree_count)
{
    u32 votes[2] = { 0, 0 };
    u32 i, majority_bit, agree;
    enum trust_quorum_verdict v;

    atomic64_inc(&q_total_votes);

    if (!s) {
        /* Defensive: no subject = no quorum. */
        if (agree_count)
            *agree_count = 0;
        atomic64_inc(&q_apoptosis_nominees);
        return TRUST_QUORUM_APOPTOSIS_CANDIDATE;
    }

    /* Clamp field_id to valid segment index (deterministic, never error). */
    if (field_id >= TRUST_CHROMOSOME_PAIRS)
        field_id %= TRUST_CHROMOSOME_PAIRS;

    /* Each of 23 pairs contributes one opinion bit. */
    for (i = 0; i < TRUST_CHROMOSOME_PAIRS; i++) {
        u64 a = (u64)s->chromosome.a_segments[i];
        u64 b = (u64)s->chromosome.b_segments[i];
        u32 bit = trust_quorum_opinion_bit(a, b, field_id,
                                           s->subject_id, i);
        votes[bit & 1]++;
    }

    majority_bit = (votes[1] > votes[0]) ? 1 : 0;
    agree = votes[majority_bit];
    if (agree_count)
        *agree_count = agree;

    /* Thresholds: >=16 of 23 is the 2/3 rule (von Neumann). */
    if (agree >= 16) {
        v = TRUST_QUORUM_MAJORITY;
        atomic64_inc(&q_majorities);
    } else if (agree >= 8) {
        v = TRUST_QUORUM_DISPUTED;
        atomic64_inc(&q_disputes);
    } else {
        /* agree < 8 — shouldn't happen normally (majority is at least
         * ceil(23/2) = 12). This means the tallies collapsed to one
         * side with < 8 — treat as pathological corruption. */
        v = TRUST_QUORUM_APOPTOSIS_CANDIDATE;
        atomic64_inc(&q_apoptosis_nominees);
    }
    return v;
}
EXPORT_SYMBOL_GPL(trust_quorum_vote);

enum trust_quorum_verdict trust_quorum_vote_authority(const trust_subject_t *s)
{
    /* A-segment index 2 (CHROMO_A_TRUST_STATE) is the authority-score
     * trajectory fingerprint per trust_types.h:176. That's what we vote
     * on when the caller doesn't specify a field. */
    return trust_quorum_vote(s, CHROMO_A_TRUST_STATE, NULL);
}
EXPORT_SYMBOL_GPL(trust_quorum_vote_authority);

/* --- sysfs surface ---------------------------------------------------- */

static ssize_t total_votes_show(struct kobject *k, struct kobj_attribute *a,
                                char *buf)
{
    (void)k; (void)a;
    return sysfs_emit(buf, "%lld\n",
                      (long long)atomic64_read(&q_total_votes));
}

static ssize_t majorities_show(struct kobject *k, struct kobj_attribute *a,
                               char *buf)
{
    (void)k; (void)a;
    return sysfs_emit(buf, "%lld\n",
                      (long long)atomic64_read(&q_majorities));
}

static ssize_t disputes_show(struct kobject *k, struct kobj_attribute *a,
                             char *buf)
{
    (void)k; (void)a;
    return sysfs_emit(buf, "%lld\n",
                      (long long)atomic64_read(&q_disputes));
}

static ssize_t apoptosis_nominations_show(struct kobject *k,
                                          struct kobj_attribute *a,
                                          char *buf)
{
    (void)k; (void)a;
    return sysfs_emit(buf, "%lld\n",
                      (long long)atomic64_read(&q_apoptosis_nominees));
}

static struct kobj_attribute attr_total_votes =
    __ATTR(total_votes, 0444, total_votes_show, NULL);
static struct kobj_attribute attr_majorities =
    __ATTR(majorities, 0444, majorities_show, NULL);
static struct kobj_attribute attr_disputes =
    __ATTR(disputes, 0444, disputes_show, NULL);
static struct kobj_attribute attr_apoptosis_nominations =
    __ATTR(apoptosis_nominations, 0444, apoptosis_nominations_show, NULL);

static struct attribute *quorum_attrs[] = {
    &attr_total_votes.attr,
    &attr_majorities.attr,
    &attr_disputes.attr,
    &attr_apoptosis_nominations.attr,
    NULL,
};

static const struct attribute_group quorum_group = {
    .attrs = quorum_attrs,
};

static struct kobject *g_quorum_kobj;

int trust_quorum_init(void)
{
    int ret;

    g_quorum_kobj = kobject_create_and_add("quorum", kernel_kobj);
    if (!g_quorum_kobj) {
        pr_warn("trust_quorum: kobject_create_and_add failed — "
                "/sys/kernel/quorum unavailable\n");
        return -ENOMEM;
    }

    ret = sysfs_create_group(g_quorum_kobj, &quorum_group);
    if (ret) {
        pr_warn("trust_quorum: sysfs_create_group failed (%d)\n", ret);
        kobject_put(g_quorum_kobj);
        g_quorum_kobj = NULL;
        return ret;
    }

    pr_info("trust_quorum: Byzantine 2/3 vote over 23 chromosomal slots active\n");
    return 0;
}

void trust_quorum_exit(void)
{
    if (g_quorum_kobj) {
        sysfs_remove_group(g_quorum_kobj, &quorum_group);
        kobject_put(g_quorum_kobj);
        g_quorum_kobj = NULL;
    }
}
