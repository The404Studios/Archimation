/*
 * trust_tlb.c - Trust/Capability TLB
 *
 * 4-way set-associative cache for trust subject lookups.
 * 1024 sets x 4 ways = 4096 entries max.
 * Each set has its own spinlock for fine-grained concurrency.
 *
 * Sets are vmalloc'd at init time (~2MB) to avoid bloating kernel BSS.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include "trust_internal.h"

trust_tlb_t g_trust_tlb;

/*
 * Hash function: Wang-style 32-bit integer mixer followed by mask.
 *
 * Previous `subject_id % 1024` trivially mapped sequential IDs (the
 * common PID case) to sequential sets with only the low 10 bits
 * distinguishing them. Adjacent subjects then collided into the same
 * 4-way set, thrashing LRU and causing hot-set contention that
 * serialized every lookup/modify across unrelated subjects.
 *
 * We delegate to the header inline trust_tlb_set_of() so cross-subject
 * code (token transfer) that must compute the set index directly sees
 * the same mapping as trust_tlb_insert().
 */
static inline u32 tlb_hash(u32 subject_id)
{
    return trust_tlb_set_of(subject_id);
}

int trust_tlb_init(void)
{
    int i;

    atomic_set(&g_trust_tlb.hit_count, 0);
    atomic_set(&g_trust_tlb.miss_count, 0);

    g_trust_tlb.sets = vzalloc(TRUST_TLB_SETS * sizeof(trust_tlb_set_t));
    if (!g_trust_tlb.sets) {
        pr_err("trust: failed to vmalloc TLB sets (%zu bytes)\n",
               (size_t)(TRUST_TLB_SETS * sizeof(trust_tlb_set_t)));
        return -ENOMEM;
    }

    for (i = 0; i < TRUST_TLB_SETS; i++) {
        spin_lock_init(&g_trust_tlb.sets[i].lock);
    }
    return 0;
}

void trust_tlb_cleanup(void)
{
    vfree(g_trust_tlb.sets);
    g_trust_tlb.sets = NULL;
}

int trust_tlb_lookup(u32 subject_id, trust_subject_t *out)
{
    u32 set_idx = tlb_hash(subject_id);
    trust_tlb_set_t *set;
    unsigned long flags;
    int i;

    if (!g_trust_tlb.sets)
        return -1;

    set = &g_trust_tlb.sets[set_idx];

    /*
     * Use irqsave: this lock is taken from both process context (ioctl
     * dispatch) and softirq context (trust_decay_timer_fn → trust_immune_tick
     * / trust_risc_decay_tick). Plain spin_lock() allows softirq to deadlock
     * on a lock held by preempted process context on the same CPU.
     */
    spin_lock_irqsave(&set->lock, flags);

    for (i = 0; i < TRUST_TLB_WAYS; i++) {
        if ((set->valid_mask & (1U << i)) &&
            set->entries[i].subject_id == subject_id) {
            /* Hit: update LRU and copy under lock */
            set->lru = (set->lru & ~(3U << (i * 2))) | ((u32)3 << (i * 2));
            atomic_inc(&g_trust_tlb.hit_count);
            if (out)
                *out = set->entries[i];
            spin_unlock_irqrestore(&set->lock, flags);
            return 0;
        }
    }

    atomic_inc(&g_trust_tlb.miss_count);
    spin_unlock_irqrestore(&set->lock, flags);
    return -1;
}

int trust_tlb_insert(const trust_subject_t *subject)
{
    u32 set_idx = tlb_hash(subject->subject_id);
    trust_tlb_set_t *set;
    unsigned long flags;
    int i, victim = -1;
    u32 min_lru = 4;

    if (!g_trust_tlb.sets)
        return -ENOMEM;

    set = &g_trust_tlb.sets[set_idx];

    spin_lock_irqsave(&set->lock, flags);

    /* Check if already present (update in place) */
    for (i = 0; i < TRUST_TLB_WAYS; i++) {
        if ((set->valid_mask & (1U << i)) &&
            set->entries[i].subject_id == subject->subject_id) {
            set->entries[i] = *subject;
            set->lru = (set->lru & ~(3U << (i * 2))) | ((u32)3 << (i * 2));
            spin_unlock_irqrestore(&set->lock, flags);
            return 0;
        }
    }

    /* Find an empty way */
    for (i = 0; i < TRUST_TLB_WAYS; i++) {
        if (!(set->valid_mask & (1U << i))) {
            victim = i;
            break;
        }
    }

    /* No empty way: evict LRU */
    if (victim < 0) {
        for (i = 0; i < TRUST_TLB_WAYS; i++) {
            u32 lru_val = (set->lru >> (i * 2)) & 3U;
            if (lru_val < min_lru) {
                min_lru = lru_val;
                victim = i;
            }
        }
    }

    if (victim < 0)
        victim = 0; /* Shouldn't happen */

    set->entries[victim] = *subject;
    set->valid_mask |= (1U << victim);
    set->lru = (set->lru & ~(3U << (victim * 2))) | ((u32)3 << (victim * 2));

    /* Age other entries' LRU counters */
    for (i = 0; i < TRUST_TLB_WAYS; i++) {
        if (i != victim) {
            u32 lru_val = (set->lru >> (i * 2)) & 3U;
            if (lru_val > 0) {
                set->lru = (set->lru & ~(3U << (i * 2))) |
                           ((lru_val - 1) << (i * 2));
            }
        }
    }

    spin_unlock_irqrestore(&set->lock, flags);
    return 0;
}

void trust_tlb_invalidate(u32 subject_id)
{
    u32 set_idx = tlb_hash(subject_id);
    trust_tlb_set_t *set;
    unsigned long flags;
    int i;

    if (!g_trust_tlb.sets)
        return;

    set = &g_trust_tlb.sets[set_idx];

    spin_lock_irqsave(&set->lock, flags);

    for (i = 0; i < TRUST_TLB_WAYS; i++) {
        if ((set->valid_mask & (1U << i)) &&
            set->entries[i].subject_id == subject_id) {
            set->valid_mask &= ~(1U << i);
            memset(&set->entries[i], 0, sizeof(trust_subject_t));
            break;
        }
    }

    spin_unlock_irqrestore(&set->lock, flags);
}

void trust_tlb_flush(void)
{
    unsigned long flags;
    int i;

    if (!g_trust_tlb.sets)
        return;

    for (i = 0; i < TRUST_TLB_SETS; i++) {
        trust_tlb_set_t *set = &g_trust_tlb.sets[i];
        spin_lock_irqsave(&set->lock, flags);
        set->valid_mask = 0;
        set->lru = 0;
        memset(set->entries, 0, sizeof(set->entries));
        spin_unlock_irqrestore(&set->lock, flags);
    }

    atomic_set(&g_trust_tlb.hit_count, 0);
    atomic_set(&g_trust_tlb.miss_count, 0);
}

/*
 * Atomic modify: lookup + callback + writeback under a single set lock hold.
 * Prevents TOCTOU races on read-modify-write patterns (e.g. token burn).
 * Returns the callback's return value, or -ENOENT if subject not found.
 */
int trust_tlb_modify(u32 subject_id, trust_tlb_modify_fn fn, void *data)
{
    u32 set_idx = tlb_hash(subject_id);
    trust_tlb_set_t *set;
    unsigned long flags;
    int i, ret = -ENOENT;

    if (!g_trust_tlb.sets)
        return -ENOMEM;

    set = &g_trust_tlb.sets[set_idx];

    spin_lock_irqsave(&set->lock, flags);

    for (i = 0; i < TRUST_TLB_WAYS; i++) {
        if ((set->valid_mask & (1U << i)) &&
            set->entries[i].subject_id == subject_id) {
            /* Update LRU */
            set->lru = (set->lru & ~(3U << (i * 2))) | ((u32)3 << (i * 2));
            /* Call modifier directly on the TLB entry (no copy) */
            ret = fn(&set->entries[i], data);
            break;
        }
    }

    spin_unlock_irqrestore(&set->lock, flags);
    return ret;
}

MODULE_LICENSE("GPL");
