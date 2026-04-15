/*
 * trust_vector.c - VEC family implementations and varlen batch decoder.
 *
 * Each VEC op amortizes per-subject overhead by grouping subjects that
 * hash to the same TLB set and taking the set-lock ONCE per set,
 * iterating the subjects within it before releasing.  This drops N
 * individual irqsave/irqrestore pairs to (number of distinct sets).
 *
 * Lock discipline:
 *   * Use spin_lock_irqsave for set-locks: these are shared with the
 *     decay softirq (see Session 21/30 notes).
 *   * Never hold more than one set-lock at a time in the common path.
 *     Fan-in / fan-out transfer locks two sets in ascending set-index
 *     order (matches cmd_res_xfer's discipline).
 *   * Policy reads are lock-free (append-only; READ_ONCE + smp_rmb).
 *
 * Backward-compat:
 *   All VEC ops have a scalar fallback at `trust_isa_exec_vec_scalar()`
 *   which loops through the individual trust_risc_* helpers.  If the
 *   batched path ever errors with -EOPNOTSUPP, callers can invoke the
 *   scalar version — output semantics are identical.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/bug.h>
#include <linux/module.h>

#include "trust_internal.h"
#include "trust_isa.h"

/*
 * Per-subject VEC work entry.  We group subjects by TLB set index
 * before taking set-locks so each set is visited exactly once,
 * independent of how userspace ordered the subject array.
 */
struct vec_work {
    u32 subject_id;
    u32 set_idx;
    u32 orig_pos;   /* Original index in caller's array */
};

/* comparator for sort by set_idx (ascending) */
static int vec_cmp_set(const void *a, const void *b)
{
    const struct vec_work *wa = a;
    const struct vec_work *wb = b;
    if (wa->set_idx < wb->set_idx) return -1;
    if (wa->set_idx > wb->set_idx) return 1;
    return 0;
}

/*
 * Set a bit in the output bitmap, thread-safe enough for single-cpu
 * serialized VEC execution (VEC ops don't interleave with themselves
 * since the ioctl path is serialized per-fd; decay timer is on a
 * separate codepath and doesn't touch @out).
 *
 * @out:      bitmap u64 array
 * @out_len:  capacity in u64 units
 * @bit:      which bit to set (0-based, original position)
 */
static inline void vec_bitmap_set(u64 *out, u32 out_len, u32 bit)
{
    u32 word = bit >> 6;
    u32 offset = bit & 63U;
    if (!out || word >= out_len)
        return;
    out[word] |= (1ULL << offset);
}

/*
 * Build a sorted-by-set work array from the caller's subject list.
 * Returns 0 on success, -ENOMEM on alloc failure.
 */
static int vec_prepare_work(const u32 *subjects, u32 count,
                            struct vec_work **out_work)
{
    struct vec_work *work;
    u32 i;

    if (!subjects || count == 0) {
        *out_work = NULL;
        return 0;
    }

    /*
     * Cap at TRUST_ISA_BATCH_MAX_COUNT (1024).  Each entry is 12 bytes
     * so max alloc is 12KiB via kmalloc_array, well under single-slab
     * limit.  We never hold a spinlock during this alloc.
     */
    if (count > TRUST_ISA_BATCH_MAX_COUNT)
        return -E2BIG;

    work = kmalloc_array(count, sizeof(*work), GFP_KERNEL);
    if (!work)
        return -ENOMEM;

    for (i = 0; i < count; i++) {
        work[i].subject_id = subjects[i];
        work[i].set_idx    = trust_tlb_set_of(subjects[i]);
        work[i].orig_pos   = i;
    }

    /*
     * Group by set index so one set-lock acquire covers multiple
     * subjects.  sort() from <linux/sort.h> is heapsort — O(n log n),
     * no recursion, safe in kernel.
     */
    sort(work, count, sizeof(*work), vec_cmp_set, NULL);

    *out_work = work;
    return 0;
}

/* ========================================================================
 * VEC_OP_DECAY — apply decay to N subjects
 *
 * Same math as trust_risc_decay_tick but targeted: only visits the
 * specified subjects, and respects the per-subject decay_rate.
 * Unlike trust_risc_decay_tick, does NOT update the conformance
 * chromosome (that's a per-tick system-wide concern; individual
 * VEC_DECAY is a policy primitive for observer-driven scrubs).
 * ======================================================================== */
static int vec_op_decay(const struct vec_work *work, u32 count,
                        u64 *out, u32 out_len)
{
    u32 processed = 0;
    u32 i = 0;

    while (i < count) {
        u32 this_set = work[i].set_idx;
        trust_tlb_set_t *s;
        unsigned long flags;
        u32 j;

        /* Skip empty subject IDs (set index out of range is impossible
         * because trust_tlb_set_of masks to TRUST_TLB_SETS). */
        s = &g_trust_tlb.sets[this_set];

        spin_lock_irqsave(&s->lock, flags);
        for (j = i; j < count && work[j].set_idx == this_set; j++) {
            u32 w;
            trust_subject_t *subj = NULL;
            for (w = 0; w < TRUST_TLB_WAYS; w++) {
                if ((s->valid_mask & (1U << w)) &&
                    s->entries[w].subject_id == work[j].subject_id) {
                    subj = &s->entries[w];
                    break;
                }
            }
            if (!subj)
                continue;
            if (subj->flags & TRUST_FLAG_FROZEN)
                continue;
            if (subj->decay_rate == 0)
                continue;

            if (subj->trust_score > 0) {
                subj->trust_score -= (int32_t)subj->decay_rate;
                if (subj->trust_score < 0)
                    subj->trust_score = 0;
            } else if (subj->trust_score < 0) {
                subj->trust_score += (int32_t)subj->decay_rate;
                if (subj->trust_score > 0)
                    subj->trust_score = 0;
            }
            trust_trc_adjust(&subj->trc, 0);
            subj->flags |= TRUST_FLAG_DECAYING;
            vec_bitmap_set(out, out_len, work[j].orig_pos);
            processed++;
        }
        spin_unlock_irqrestore(&s->lock, flags);

        i = j;
    }
    return (int)processed;
}

/* ========================================================================
 * VEC_OP_ESCALATE_CHECK — bitmap of subjects whose score > threshold_high
 *
 * Returns a bitmap (bit k = 1 iff subjects[orig_pos=k] is above their
 * biased threshold_high, i.e. eligible for escalation).
 * ======================================================================== */
static int vec_op_escalate_check(const struct vec_work *work, u32 count,
                                 u64 *out, u32 out_len)
{
    u32 hits = 0;
    u32 i = 0;

    while (i < count) {
        u32 this_set = work[i].set_idx;
        trust_tlb_set_t *s = &g_trust_tlb.sets[this_set];
        unsigned long flags;
        u32 j;

        spin_lock_irqsave(&s->lock, flags);
        for (j = i; j < count && work[j].set_idx == this_set; j++) {
            u32 w;
            for (w = 0; w < TRUST_TLB_WAYS; w++) {
                trust_subject_t *subj;
                int32_t bh;
                if (!(s->valid_mask & (1U << w)))
                    continue;
                if (s->entries[w].subject_id != work[j].subject_id)
                    continue;
                subj = &s->entries[w];
                bh = trust_clamp_score(subj->threshold_high + subj->trc.threshold_bias);
                if (subj->trust_score >= bh) {
                    vec_bitmap_set(out, out_len, work[j].orig_pos);
                    hits++;
                }
                break;
            }
        }
        spin_unlock_irqrestore(&s->lock, flags);
        i = j;
    }
    return (int)hits;
}

/* ========================================================================
 * VEC_OP_GATE_EVAL — policy/gate eval across N; bitmap of ALLOWs
 *
 * param (low 32 bits) = action type to check against.
 * ======================================================================== */
static int vec_op_gate_eval(const struct vec_work *work, u32 count,
                            u64 param, u64 *out, u32 out_len)
{
    u32 action = (u32)(param & 0xFFFFFFFFULL);
    u32 allows = 0;
    u32 i;

    /*
     * Reuse trust_risc_threshold_check for correctness (policy
     * snapshot lock-free).  We don't batch the set-lock here because
     * trust_risc_threshold_check takes its own short TLB lock; the
     * benefit comes from avoiding per-op syscall roundtrip.
     */
    for (i = 0; i < count; i++) {
        int r = trust_risc_threshold_check(work[i].subject_id, action);
        if (r == TRUST_RESULT_ALLOW) {
            vec_bitmap_set(out, out_len, work[i].orig_pos);
            allows++;
        }
    }
    return (int)allows;
}

/* ========================================================================
 * VEC_OP_POLL_STATE — read state flags packed into bitmap
 *
 * Sets each subject's bit iff (flags & TRUST_FLAG_DECAYING) or
 * trust_score below zero (a cheap liveness proxy).  Observers use
 * this for "who needs attention" scans.
 * ======================================================================== */
static int vec_op_poll_state(const struct vec_work *work, u32 count,
                             u64 *out, u32 out_len)
{
    u32 i = 0;
    u32 hits = 0;

    while (i < count) {
        u32 this_set = work[i].set_idx;
        trust_tlb_set_t *s = &g_trust_tlb.sets[this_set];
        unsigned long flags;
        u32 j;

        spin_lock_irqsave(&s->lock, flags);
        for (j = i; j < count && work[j].set_idx == this_set; j++) {
            u32 w;
            for (w = 0; w < TRUST_TLB_WAYS; w++) {
                trust_subject_t *subj;
                if (!(s->valid_mask & (1U << w)))
                    continue;
                if (s->entries[w].subject_id != work[j].subject_id)
                    continue;
                subj = &s->entries[w];
                if ((subj->flags & TRUST_FLAG_DECAYING) ||
                    subj->trust_score < 0 ||
                    subj->tokens.starved ||
                    (subj->flags & TRUST_FLAG_APOPTOTIC)) {
                    vec_bitmap_set(out, out_len, work[j].orig_pos);
                    hits++;
                }
                break;
            }
        }
        spin_unlock_irqrestore(&s->lock, flags);
        i = j;
    }
    return (int)hits;
}

/* ========================================================================
 * VEC_OP_CAP_CHECK — check one capability bit across N subjects
 *
 * param = capability bitmask (all bits must be present to count).
 * ======================================================================== */
static int vec_op_cap_check(const struct vec_work *work, u32 count,
                            u64 param, u64 *out, u32 out_len)
{
    u32 cap = (u32)(param & 0xFFFFFFFFULL);
    u32 hits = 0;
    u32 i;
    for (i = 0; i < count; i++) {
        if (trust_risc_check_cap(work[i].subject_id, cap)) {
            vec_bitmap_set(out, out_len, work[i].orig_pos);
            hits++;
        }
    }
    return (int)hits;
}

/* ========================================================================
 * VEC_OP_SCORE_READ — read N scores.  @out is treated as an array of
 * int32 packed into u64 words (2 scores per word).  Big batches of
 * observer "snapshot" reads benefit from locking each set once.
 * ======================================================================== */
static int vec_op_score_read(const struct vec_work *work, u32 count,
                             u64 *out, u32 out_len)
{
    u32 i = 0;
    u32 read = 0;
    /* out_len in u64 units; we need ceil(count/2) words to hold
     * count int32 scores. */
    u32 words_needed = (count + 1) / 2;

    if (out_len < words_needed)
        return -EINVAL;

    /* Caller's exec_vec() already memset() the buffer for bitmap ops;
     * we treat the buffer as score array here so the zero-init is
     * still the desired baseline (absent subjects => score 0). */
    if (out)
        memset(out, 0, (size_t)out_len * sizeof(u64));

    while (i < count) {
        u32 this_set = work[i].set_idx;
        trust_tlb_set_t *s = &g_trust_tlb.sets[this_set];
        unsigned long flags;
        u32 j;

        spin_lock_irqsave(&s->lock, flags);
        for (j = i; j < count && work[j].set_idx == this_set; j++) {
            u32 w;
            int32_t score = 0;
            for (w = 0; w < TRUST_TLB_WAYS; w++) {
                if ((s->valid_mask & (1U << w)) &&
                    s->entries[w].subject_id == work[j].subject_id) {
                    score = s->entries[w].trust_score;
                    break;
                }
            }
            {
                u32 pos = work[j].orig_pos;
                u32 word = pos >> 1;
                int shift = (pos & 1) ? 32 : 0;
                /* Preserve bit pattern of signed score in the u32 slot */
                u64 slot = ((u64)(u32)score) << shift;
                u64 mask = ((u64)0xFFFFFFFFULL) << shift;
                out[word] = (out[word] & ~mask) | slot;
                read++;
            }
        }
        spin_unlock_irqrestore(&s->lock, flags);
        i = j;
    }
    return (int)read;
}

/* ========================================================================
 * VEC_OP_TOKEN_REGEN — regenerate tokens for N subjects
 * ======================================================================== */
static int vec_op_token_regen(const struct vec_work *work, u32 count,
                              u64 *out, u32 out_len)
{
    u32 i = 0;
    u32 processed = 0;

    while (i < count) {
        u32 this_set = work[i].set_idx;
        trust_tlb_set_t *s = &g_trust_tlb.sets[this_set];
        unsigned long flags;
        u32 j;

        spin_lock_irqsave(&s->lock, flags);
        for (j = i; j < count && work[j].set_idx == this_set; j++) {
            u32 w;
            for (w = 0; w < TRUST_TLB_WAYS; w++) {
                if ((s->valid_mask & (1U << w)) &&
                    s->entries[w].subject_id == work[j].subject_id) {
                    trust_token_regenerate(&s->entries[w].tokens);
                    /* If regen lifted balance out of starvation, clear */
                    if (s->entries[w].tokens.starved &&
                        s->entries[w].tokens.balance > 0)
                        s->entries[w].tokens.starved = 0;
                    vec_bitmap_set(out, out_len, work[j].orig_pos);
                    processed++;
                    break;
                }
            }
        }
        spin_unlock_irqrestore(&s->lock, flags);
        i = j;
    }
    return (int)processed;
}

/* ========================================================================
 * VEC_OP_IMMUNE_EVAL — run immune evaluator per subject; bitmap of
 * QUARANTINED/SUSPICIOUS results.
 * ======================================================================== */
static int vec_op_immune_eval(const struct vec_work *work, u32 count,
                              u64 *out, u32 out_len)
{
    u32 flagged = 0;
    u32 i;
    for (i = 0; i < count; i++) {
        int s = trust_immune_evaluate(work[i].subject_id);
        if (s == TRUST_IMMUNE_QUARANTINED || s == TRUST_IMMUNE_SUSPICIOUS) {
            vec_bitmap_set(out, out_len, work[i].orig_pos);
            flagged++;
        }
    }
    return (int)flagged;
}

/* ========================================================================
 * VEC_OP_RES_XFER_FAN_IN — N sources -> 1 sink, same amount each.
 *
 * param layout: [63:32] = sink subject_id, [31:0] = amount (signed pos).
 *
 * Must not deadlock against decay softirq — uses irqsave on both
 * locks.  Uses the same cmd_res_xfer lock-ordering rule: lower set
 * index first.  Each source transaction is atomic w.r.t. that source
 * set; cross-source atomicity is NOT guaranteed (intentional — a
 * partial batch is acceptable for fan-in accounting).
 * ======================================================================== */
static int vec_res_xfer_one(u32 from_sid, u32 to_sid, int32_t amount)
{
    u32 from_set = trust_tlb_set_of(from_sid);
    u32 to_set   = trust_tlb_set_of(to_sid);
    trust_tlb_set_t *sa, *sb;
    trust_subject_t *fp = NULL, *tp = NULL;
    unsigned long fa, fb = 0;
    int i, rc;

    if (from_sid == to_sid || amount <= 0)
        return -EINVAL;

    if (from_set <= to_set) {
        sa = &g_trust_tlb.sets[from_set];
        sb = &g_trust_tlb.sets[to_set];
        spin_lock_irqsave(&sa->lock, fa);
        if (from_set != to_set)
            spin_lock_irqsave(&sb->lock, fb);
    } else {
        sa = &g_trust_tlb.sets[to_set];
        sb = &g_trust_tlb.sets[from_set];
        spin_lock_irqsave(&sa->lock, fa);
        spin_lock_irqsave(&sb->lock, fb);
    }

    for (i = 0; i < TRUST_TLB_WAYS; i++) {
        trust_tlb_set_t *fs = &g_trust_tlb.sets[from_set];
        if ((fs->valid_mask & (1U << i)) &&
            fs->entries[i].subject_id == from_sid) {
            fp = &fs->entries[i];
            break;
        }
    }
    for (i = 0; i < TRUST_TLB_WAYS; i++) {
        trust_tlb_set_t *ts = &g_trust_tlb.sets[to_set];
        if ((ts->valid_mask & (1U << i)) &&
            ts->entries[i].subject_id == to_sid) {
            tp = &ts->entries[i];
            break;
        }
    }

    if (!fp || !tp) {
        rc = -ENOENT;
        goto out;
    }

    if (fp->tokens.balance < amount) {
        rc = -ENOSPC;
        goto out;
    }

    fp->tokens.balance -= amount;
    if (fp->tokens.total_burned > UINT32_MAX - (u32)amount)
        fp->tokens.total_burned = UINT32_MAX;
    else
        fp->tokens.total_burned += (u32)amount;

    if (tp->tokens.balance > tp->tokens.max_balance - amount)
        tp->tokens.balance = tp->tokens.max_balance;
    else
        tp->tokens.balance += amount;
    if (tp->tokens.total_regenerated > UINT32_MAX - (u32)amount)
        tp->tokens.total_regenerated = UINT32_MAX;
    else
        tp->tokens.total_regenerated += (u32)amount;
    if (tp->tokens.starved && tp->tokens.balance > 0)
        tp->tokens.starved = 0;

    rc = 0;

out:
    if (from_set != to_set)
        spin_unlock_irqrestore(&sb->lock, fb);
    spin_unlock_irqrestore(&sa->lock, fa);
    return rc;
}

static int vec_op_res_xfer_fanin(const struct vec_work *work, u32 count,
                                 u64 param, u64 *out, u32 out_len)
{
    u32 sink = (u32)((param >> 32) & 0xFFFFFFFFULL);
    int32_t amount = (int32_t)(param & 0xFFFFFFFFULL);
    u32 ok = 0;
    u32 i;

    if (amount <= 0)
        return -EINVAL;

    for (i = 0; i < count; i++) {
        int rc = vec_res_xfer_one(work[i].subject_id, sink, amount);
        if (rc == 0) {
            vec_bitmap_set(out, out_len, work[i].orig_pos);
            ok++;
        }
    }
    return (int)ok;
}

static int vec_op_res_xfer_fanout(const struct vec_work *work, u32 count,
                                  u64 param, u64 *out, u32 out_len)
{
    u32 src = (u32)((param >> 32) & 0xFFFFFFFFULL);
    int32_t amount = (int32_t)(param & 0xFFFFFFFFULL);
    u32 ok = 0;
    u32 i;

    if (amount <= 0)
        return -EINVAL;

    for (i = 0; i < count; i++) {
        int rc = vec_res_xfer_one(src, work[i].subject_id, amount);
        if (rc == 0) {
            vec_bitmap_set(out, out_len, work[i].orig_pos);
            ok++;
        }
    }
    return (int)ok;
}

/* ========================================================================
 * Public entry point
 * ======================================================================== */

int trust_isa_exec_vec(u32 op, const u32 *subjects, u32 count,
                       u64 param, u64 *out, u32 out_len)
{
    struct vec_work *work = NULL;
    int ret;

    if (!g_trust_tlb.sets)
        return -ENODEV;
    if (count == 0)
        return 0;
    if (!subjects)
        return -EINVAL;
    if (op >= VEC_OP_MAX)
        return -ENOSYS;

    ret = vec_prepare_work(subjects, count, &work);
    if (ret < 0)
        return ret;

    /* Clear caller's bitmap slots (for bitmap-returning ops). */
    if (out && out_len && op != VEC_OP_SCORE_READ)
        memset(out, 0, (size_t)out_len * sizeof(u64));

    switch (op) {
    case VEC_OP_DECAY:
        ret = vec_op_decay(work, count, out, out_len);
        break;
    case VEC_OP_ESCALATE_CHECK:
        ret = vec_op_escalate_check(work, count, out, out_len);
        break;
    case VEC_OP_RES_XFER_FAN_IN:
        ret = vec_op_res_xfer_fanin(work, count, param, out, out_len);
        break;
    case VEC_OP_RES_XFER_FAN_OUT:
        ret = vec_op_res_xfer_fanout(work, count, param, out, out_len);
        break;
    case VEC_OP_GATE_EVAL:
        ret = vec_op_gate_eval(work, count, param, out, out_len);
        break;
    case VEC_OP_POLL_STATE:
        ret = vec_op_poll_state(work, count, out, out_len);
        break;
    case VEC_OP_TOKEN_REGEN:
        ret = vec_op_token_regen(work, count, out, out_len);
        break;
    case VEC_OP_SCORE_READ:
        ret = vec_op_score_read(work, count, out, out_len);
        break;
    case VEC_OP_CAP_CHECK:
        ret = vec_op_cap_check(work, count, param, out, out_len);
        break;
    case VEC_OP_IMMUNE_EVAL:
        ret = vec_op_immune_eval(work, count, out, out_len);
        break;
    default:
        ret = -ENOSYS;
    }

    kfree(work);
    return ret;
}

/* ========================================================================
 * Variable-length batch decoder.
 * ======================================================================== */
int trust_isa_decode_batch(const void *buf, u32 buf_len,
                           u32 *subjects, u32 max_count,
                           u32 *op_out, u64 *param_out)
{
    const unsigned char *p = (const unsigned char *)buf;
    trust_isa_batch_t h;
    u32 offset;
    u32 delta, zigzag, family;
    u32 prev = 0;
    u32 i;

    if (!buf || !subjects || buf_len < TRUST_ISA_BATCH_HDR_SIZE)
        return -EINVAL;

    memcpy(&h, p, TRUST_ISA_BATCH_HDR_SIZE);
    if (h.magic != TRUST_ISA_BATCH_MAGIC)
        return -EINVAL;
    if (h.count == 0 || h.count > TRUST_ISA_BATCH_MAX_COUNT)
        return -EINVAL;
    if (h.count > max_count)
        return -ENOSPC;

    family = (h.flags & TRUST_ISA_BATCH_FAMILY_MASK) >>
             TRUST_ISA_BATCH_FAMILY_SHIFT;
    if (family != TRUST_ISA_FAMILY_VEC)
        return -EINVAL;

    delta  = !!(h.flags & TRUST_ISA_BATCH_F_DELTA);
    zigzag = !!(h.flags & TRUST_ISA_BATCH_F_ZIGZAG);

    if (op_out)
        *op_out = (h.flags & TRUST_ISA_BATCH_OPCODE_MASK) >>
                  TRUST_ISA_BATCH_OPCODE_SHIFT;
    if (param_out)
        *param_out = h.param;

    offset = TRUST_ISA_BATCH_HDR_SIZE;

    for (i = 0; i < h.count; i++) {
        u32 v;
        int n = trust_isa_varint_decode(p + offset,
                                        buf_len - offset, &v);
        if (n <= 0)
            return -EINVAL;
        offset += (u32)n;

        if (delta) {
            int32_t d = zigzag ? trust_isa_unzigzag32(v) : (int32_t)v;
            subjects[i] = prev + (u32)d;
        } else {
            subjects[i] = v;
        }
        prev = subjects[i];
    }
    return (int)h.count;
}

MODULE_LICENSE("GPL");
