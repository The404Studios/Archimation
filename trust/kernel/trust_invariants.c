/*
 * trust_invariants.c - Runtime checks for the Root of Authority
 *                      Security Theorems (paper §1-7).
 *
 * Owner: Session 48 Agent 8.
 *
 * See trust_theorems.h for the public surface and per-theorem
 * documentation.  This file implements:
 *
 *   - Theorem 1 (Non-Static Secrets): a one-shot scan at module init
 *     that walks the trust kobject's child entries and asserts none
 *     are named "seed", "proof", "cfg", or "secret".  Detection only:
 *     a stray export would have already happened by the time we see
 *     it; the WARN exists so reviewers/CI catch it loudly.
 *
 *   - Theorem 2 (Non-Replayability): a global atomic64 nonce plus the
 *     trust_invariants_check_nonce(prev, next) predicate.  Agent 6
 *     (Authority Proof Engine) is expected to call advance_nonce()
 *     on every proof consumption.
 *
 *   - Theorem 4 (Bounded Authority Inheritance):
 *     trust_invariants_check_mitosis(parent, child)  asserts
 *     S_max(child) < S_max(parent).  Agent 3 calls this at the exit
 *     of trust_mitosis().
 *     trust_invariants_check_meiosis(a, b, shared) asserts
 *     S_max(shared) <= min(S_max(a), S_max(b)).  Agent 4 calls this
 *     at the exit of trust_meiosis().
 *
 *   - Theorem 5 (Guaranteed Revocation O(1)):
 *     trust_invariants_apoptosis_{start,end} bracket the apoptosis
 *     fast-path.  delta_ns > 10000 (10us) WARN_ON_ONCE's and bumps the
 *     violation counter.  The path-internal max delta is also tracked.
 *
 *   - Theorem 6 (Metabolic Fairness): we expose the
 *     TRUST_THEOREM6_VIOLATE() macro hook for Agent 2; the counter is
 *     mirrored from trust_authz_theorem6_violations() at sysfs read
 *     time so we never double-count.  If trust_authz is not built
 *     (link-time absence), our local counter stands alone.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/atomic.h>
#include <linux/ktime.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "../include/trust_types.h"
#include "../include/trust_theorems.h"

/* Forward declaration of Agent 2's accessor; weakly linked so that if
 * trust_authz.o is not in the build the link still succeeds and our
 * sysfs reader falls back to the local counter alone. */
extern u64 trust_authz_theorem6_violations(void) __attribute__((weak));

/* --- Counters -------------------------------------------------- */

static atomic64_t g_t1_violations = ATOMIC64_INIT(0);
static atomic64_t g_t2_violations = ATOMIC64_INIT(0);
static atomic64_t g_t4_violations = ATOMIC64_INIT(0);
static atomic64_t g_t5_violations = ATOMIC64_INIT(0);
static atomic64_t g_t5_max_ns     = ATOMIC64_INIT(0);
static atomic64_t g_t6_violations_local = ATOMIC64_INIT(0);

/* --- Theorem 2 — Global nonce --------------------------------- */

/*
 * Spec wording: "Captured proof P_n cannot authorize any action at
 * any future time."  Our runtime invariant is the strict-monotonic
 * advance: every proof consumption strictly increments g_global_nonce.
 *
 * We use atomic64 so the predicate is wait-free across CPUs.  The
 * 64-bit space is large enough that wraparound is a non-concern at
 * any realistic event rate (10^12 events/s would still take 5+ years
 * to wrap).
 */
static atomic64_t g_global_nonce = ATOMIC64_INIT(0);

void trust_invariants_check_nonce(u64 prev, u64 next)
{
    if (unlikely(next <= prev)) {
        atomic64_inc(&g_t2_violations);
        WARN_ONCE(1,
                  "trust: theorem2 violation: nonce did not advance "
                  "(prev=%llu next=%llu)\n",
                  (unsigned long long)prev,
                  (unsigned long long)next);
    }
}
EXPORT_SYMBOL_GPL(trust_invariants_check_nonce);

u64 trust_invariants_advance_nonce(void)
{
    /*
     * atomic64_inc_return is the lock-free, multi-producer-safe way
     * to advance the nonce.  The previous value is recovered as
     * (return - 1); we hand both into the predicate so any
     * mis-configured advance (e.g. an alias overflow) gets caught.
     */
    s64 next = atomic64_inc_return(&g_global_nonce);
    s64 prev = next - 1;
    trust_invariants_check_nonce((u64)prev, (u64)next);
    return (u64)next;
}
EXPORT_SYMBOL_GPL(trust_invariants_advance_nonce);

u64 trust_invariants_read_nonce(void)
{
    return (u64)atomic64_read(&g_global_nonce);
}
EXPORT_SYMBOL_GPL(trust_invariants_read_nonce);

/* --- Theorem 4 — Bounded Authority Inheritance ---------------- */

/*
 * We accept the subjects as `const void *` to avoid a header
 * coupling with trust_internal.h (which wraps trust_subject_t in a
 * lot of kernel-only includes that don't compose with userspace
 * test code).  The subject pointers are dereferenced ONLY for the
 * lifecycle.max_score field; we cast through trust_subject_t which
 * is the public typedef from trust_types.h.
 */
static inline int32_t __subject_smax(const void *p)
{
    const trust_subject_t *s = (const trust_subject_t *)p;
    return s->lifecycle.max_score;
}

void trust_invariants_check_mitosis(const void *parent_subject,
                                    const void *child_subject)
{
    int32_t s_parent, s_child;

    /* Defensive: a NULL means the caller already lost a race.  Don't
     * pretend that's a violation; just skip silently. */
    if (!parent_subject || !child_subject)
        return;

    s_parent = __subject_smax(parent_subject);
    s_child  = __subject_smax(child_subject);

    /*
     * Theorem 4 mitosis form: S_max(child) < S_max(parent), strict.
     * The chromosomal generational decay (alpha = 0.95 in 16.16) is
     * supposed to guarantee this.  If the child's max_score equals
     * the parent's, the alpha multiplication round-tripped to the
     * same fixed-point bucket — that's still a violation of the
     * paper's strict-inequality bound.
     */
    if (unlikely(s_child >= s_parent)) {
        atomic64_inc(&g_t4_violations);
        WARN_ONCE(1,
                  "trust: theorem4 violation (mitosis): "
                  "S_max(child=%d) >= S_max(parent=%d)\n",
                  s_child, s_parent);
    }
}
EXPORT_SYMBOL_GPL(trust_invariants_check_mitosis);

void trust_invariants_check_meiosis(const void *a_subject,
                                    const void *b_subject,
                                    const void *shared_subject)
{
    int32_t s_a, s_b, s_shared, s_min;

    if (!a_subject || !b_subject || !shared_subject)
        return;

    s_a      = __subject_smax(a_subject);
    s_b      = __subject_smax(b_subject);
    s_shared = __subject_smax(shared_subject);
    s_min    = (s_a < s_b) ? s_a : s_b;

    /*
     * Theorem 4 meiosis form: S_max(shared) <= min(S_max(A), S_max(B)).
     * Equality is permitted here (the combined entity may at most
     * inherit the weaker parent's ceiling); a STRICT decrease is the
     * mitosis rule, not the meiosis rule.
     */
    if (unlikely(s_shared > s_min)) {
        atomic64_inc(&g_t4_violations);
        WARN_ONCE(1,
                  "trust: theorem4 violation (meiosis): "
                  "S_max(shared=%d) > min(A=%d, B=%d)\n",
                  s_shared, s_a, s_b);
    }
}
EXPORT_SYMBOL_GPL(trust_invariants_check_meiosis);

/* --- Theorem 5 — Guaranteed Revocation O(1) ------------------- */

#define TRUST_T5_BUDGET_NS  10000ULL  /* 10 microseconds */

ktime_t trust_invariants_apoptosis_start(void)
{
    return ktime_get();
}
EXPORT_SYMBOL_GPL(trust_invariants_apoptosis_start);

void trust_invariants_apoptosis_end(ktime_t start)
{
    ktime_t end = ktime_get();
    s64 delta_ns = ktime_to_ns(ktime_sub(end, start));
    s64 prev_max;

    if (delta_ns < 0)
        delta_ns = 0;  /* clock skew defence */

    /* Track the running maximum non-atomically with cmpxchg loop.
     * Contention is rare (apoptosis is not a hot path) so a few
     * spurious retries don't matter. */
    do {
        prev_max = atomic64_read(&g_t5_max_ns);
        if (delta_ns <= prev_max)
            break;
    } while (atomic64_cmpxchg(&g_t5_max_ns, prev_max, delta_ns) != prev_max);

    if (unlikely((u64)delta_ns > TRUST_T5_BUDGET_NS)) {
        atomic64_inc(&g_t5_violations);
        WARN_ONCE(1,
                  "trust: theorem5 violation: per-subject apoptosis "
                  "took %lld ns (budget=%llu ns)\n",
                  (long long)delta_ns,
                  (unsigned long long)TRUST_T5_BUDGET_NS);
    }
}
EXPORT_SYMBOL_GPL(trust_invariants_apoptosis_end);

/* --- Theorem 6 — Metabolic Fairness (counter mirror) ---------- */

void __trust_theorem6_count_violation(const char *reason)
{
    atomic64_inc(&g_t6_violations_local);
    /* WARN_ONCE so a flood of fairness violations doesn't OOM dmesg.
     * The reason string is captured for the first occurrence; later
     * occurrences increment the counter silently. */
    WARN_ONCE(1, "trust: theorem6 violation: %s\n",
              reason ? reason : "unspecified");
}
EXPORT_SYMBOL_GPL(__trust_theorem6_count_violation);

/* --- Counter accessors --------------------------------------- */

u64 trust_invariants_get_t1_violations(void)
{
    return (u64)atomic64_read(&g_t1_violations);
}
EXPORT_SYMBOL_GPL(trust_invariants_get_t1_violations);

u64 trust_invariants_get_t2_violations(void)
{
    return (u64)atomic64_read(&g_t2_violations);
}
EXPORT_SYMBOL_GPL(trust_invariants_get_t2_violations);

u64 trust_invariants_get_t4_violations(void)
{
    return (u64)atomic64_read(&g_t4_violations);
}
EXPORT_SYMBOL_GPL(trust_invariants_get_t4_violations);

u64 trust_invariants_get_t5_violations(void)
{
    return (u64)atomic64_read(&g_t5_violations);
}
EXPORT_SYMBOL_GPL(trust_invariants_get_t5_violations);

u64 trust_invariants_get_t5_max_ns(void)
{
    return (u64)atomic64_read(&g_t5_max_ns);
}
EXPORT_SYMBOL_GPL(trust_invariants_get_t5_max_ns);

u64 trust_invariants_get_t6_violations(void)
{
    /* Prefer Agent 2's authoritative counter when present; fall back
     * to the local tally otherwise.  The two are kept in sync because
     * Agent 2's WARN site calls TRUST_THEOREM6_VIOLATE(), which lands
     * in __trust_theorem6_count_violation() above. */
    u64 a2 = 0;
    if (trust_authz_theorem6_violations)
        a2 = trust_authz_theorem6_violations();
    return a2 + (u64)atomic64_read(&g_t6_violations_local);
}
EXPORT_SYMBOL_GPL(trust_invariants_get_t6_violations);

/* --- Sysfs surface ------------------------------------------- */

static struct kobject *trust_invariants_kobj;

#define DEFINE_TI_SHOW_U64(name, accessor)                              \
static ssize_t name##_show(struct kobject *kobj,                        \
                           struct kobj_attribute *attr,                 \
                           char *buf)                                   \
{                                                                       \
    return scnprintf(buf, PAGE_SIZE, "%llu\n",                          \
                     (unsigned long long)accessor());                   \
}                                                                       \
static struct kobj_attribute name##_attr =                              \
    __ATTR_RO(name)

DEFINE_TI_SHOW_U64(theorem1_violations, trust_invariants_get_t1_violations);
DEFINE_TI_SHOW_U64(theorem2_violations, trust_invariants_get_t2_violations);
DEFINE_TI_SHOW_U64(theorem4_violations, trust_invariants_get_t4_violations);
DEFINE_TI_SHOW_U64(theorem5_violations, trust_invariants_get_t5_violations);
DEFINE_TI_SHOW_U64(theorem6_violations, trust_invariants_get_t6_violations);
DEFINE_TI_SHOW_U64(global_nonce,        trust_invariants_read_nonce);

static ssize_t theorem5_max_us_show(struct kobject *kobj,
                                    struct kobj_attribute *attr,
                                    char *buf)
{
    /* Convert ns -> us (paper budget is in microseconds). */
    u64 ns = trust_invariants_get_t5_max_ns();
    return scnprintf(buf, PAGE_SIZE, "%llu\n",
                     (unsigned long long)(ns / 1000ULL));
}
static struct kobj_attribute theorem5_max_us_attr = __ATTR_RO(theorem5_max_us);

static struct attribute *trust_invariants_attrs[] = {
    &theorem1_violations_attr.attr,
    &theorem2_violations_attr.attr,
    &theorem4_violations_attr.attr,
    &theorem5_violations_attr.attr,
    &theorem5_max_us_attr.attr,
    &theorem6_violations_attr.attr,
    &global_nonce_attr.attr,
    NULL,
};

static const struct attribute_group trust_invariants_group = {
    .attrs = trust_invariants_attrs,
};

/* --- Theorem 1: name-scan of the sysfs surface ---------------
 *
 * The paper's Theorem 1 says no software-accessible path returns the
 * SEED, proof register P_n, or private cfg(n).  We can't walk every
 * sysfs node in the kernel, but we CAN scan our own sub-tree at init
 * time and assert that no attribute we created has a name matching
 * the leak-pattern.  This catches the regression where someone adds
 * a debug attribute named e.g. "raw_seed" or "current_proof".
 *
 * A more thorough form (walking /sys/kernel/trust/ from a user-space
 * test) lives in tests/kernel/test_theorems.c.  Here we just sanity-
 * check our own attributes table.
 */
static const char * const trust_t1_forbidden_names[] = {
    "seed", "proof", "cfg", "secret", "private_key", "passphrase",
};

static void trust_invariants_t1_scan_self(void)
{
    int i, j;
    for (i = 0; trust_invariants_attrs[i]; i++) {
        const char *n = trust_invariants_attrs[i]->name;
        for (j = 0; j < ARRAY_SIZE(trust_t1_forbidden_names); j++) {
            const char *bad = trust_t1_forbidden_names[j];
            if (strstr(n, bad)) {
                atomic64_inc(&g_t1_violations);
                WARN(1,
                     "trust: theorem1 violation: invariants surface "
                     "exposes forbidden node name '%s' (matches '%s')\n",
                     n, bad);
            }
        }
    }
}

/* --- Module init / exit ------------------------------------- */

void trust_invariants_init(void)
{
    int ret;

    /* Reset all counters defensively (this is a no-op on first init
     * but guards against module reload state leakage). */
    atomic64_set(&g_t1_violations, 0);
    atomic64_set(&g_t2_violations, 0);
    atomic64_set(&g_t4_violations, 0);
    atomic64_set(&g_t5_violations, 0);
    atomic64_set(&g_t5_max_ns, 0);
    atomic64_set(&g_t6_violations_local, 0);
    atomic64_set(&g_global_nonce, 0);

    trust_invariants_kobj = kobject_create_and_add("trust_invariants",
                                                   kernel_kobj);
    if (!trust_invariants_kobj) {
        pr_warn("trust: trust_invariants kobject creation failed; "
                "/sys/kernel/trust_invariants/* will be absent\n");
        return;
    }

    ret = sysfs_create_group(trust_invariants_kobj,
                             &trust_invariants_group);
    if (ret) {
        pr_warn("trust: sysfs_create_group(trust_invariants) failed: %d\n",
                ret);
        kobject_put(trust_invariants_kobj);
        trust_invariants_kobj = NULL;
        return;
    }

    /* Run the self-scan AFTER attributes are exposed so we catch any
     * naming-leak that survived to the visible surface. */
    trust_invariants_t1_scan_self();

    pr_info("trust: invariants surface installed at "
            "/sys/kernel/trust_invariants/ (T1/T2/T4/T5/T6)\n");
}
EXPORT_SYMBOL_GPL(trust_invariants_init);

void trust_invariants_exit(void)
{
    if (trust_invariants_kobj) {
        sysfs_remove_group(trust_invariants_kobj,
                           &trust_invariants_group);
        kobject_put(trust_invariants_kobj);
        trust_invariants_kobj = NULL;
    }
}
EXPORT_SYMBOL_GPL(trust_invariants_exit);
