/*
 * trust_theorems.h - Runtime invariants for the Root of Authority
 *                    Security Theorems (paper §Security Theorems 1-7)
 *
 * Spec source: "Root of Authority" by Roberts/Eli/Leelee
 *              (Zenodo 18710335) §Security Theorems 1-7.
 *
 * Theorems 3 (Forward Secrecy via key derivation) and 7 (Statistical
 * Anomaly Detection bound) are not runtime-checkable as point predicates
 * — they are statistical statements over an indefinite history.  We
 * implement runtime invariants for the five testable theorems:
 *
 *   T1  Non-Static Secrets         (sysfs surface scan; no SEED/proof/cfg
 *                                    leak path exists)
 *   T2  Non-Replayability          (monotonic global nonce on every
 *                                    proof consumption)
 *   T4  Bounded Authority          (S_max(child) < S_max(parent),
 *       Inheritance                 S_max(shared) <= min(S_max(A),
 *                                                       S_max(B)))
 *   T5  Guaranteed Revocation O(1) (per-subject apoptosis duration
 *                                    bounded; default 10us)
 *   T6  Metabolic Fairness         (Agent 2 — trust_authz.c —
 *                                    increments via TRUST_THEOREM6_VIOLATE)
 *
 * Counter sysfs surface (created by trust_invariants_init()):
 *
 *   /sys/kernel/trust_invariants/theorem1_violations  (RO, u64)
 *   /sys/kernel/trust_invariants/theorem2_violations  (RO, u64)
 *   /sys/kernel/trust_invariants/theorem4_violations  (RO, u64)
 *   /sys/kernel/trust_invariants/theorem5_violations  (RO, u64)
 *   /sys/kernel/trust_invariants/theorem5_max_us      (RO, u64)
 *   /sys/kernel/trust_invariants/theorem6_violations  (RO, u64,
 *                                  mirror of trust_authz_theorem6_violations())
 *   /sys/kernel/trust_invariants/global_nonce         (RO, u64,
 *                                  current monotonically-advancing nonce)
 *
 * The counters are stored as atomic64_t so they are safe to bump from
 * any context (process, softirq, NMI-safe via atomic_inc).  The sysfs
 * surface is NOT installed on any subject's private kobject so it
 * cannot expose secret material — every node here is either a counter
 * or a tunable.
 *
 * Owner: Session 48 Agent 8 (Theorem invariants).  This file may be
 * included from both kernel-internal .c files (where struct
 * trust_subject is the kernel form) and from userspace test code (where
 * the typedef is trust_subject_t).  We forward-declare both forms.
 */

#ifndef TRUST_THEOREMS_H
#define TRUST_THEOREMS_H

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/atomic.h>

struct kobject;

/*
 * The subject type used by Theorem-4 hooks is the public typedef
 * `trust_subject_t` from trust_types.h (a struct typedef, not a
 * tagged struct).  We deliberately take the subject pointers as
 * `const void *` in the hook signatures below so this header has no
 * include-order dependency on trust_internal.h.  trust_invariants.c
 * casts to `const trust_subject_t *` internally.
 */

/* --- Public hooks --- */

/*
 * Module-init / module-exit.  Creates / tears down
 *   /sys/kernel/trust_invariants/...
 * and zeros the global nonce.  Non-fatal on registration failure;
 * counters still increment internally for in-tree WARN_ON_ONCE
 * detection, just without a sysfs surface.
 */
void trust_invariants_init(void);
void trust_invariants_exit(void);

/*
 * Theorem 4 — Bounded Authority Inheritance.
 *
 *   trust_invariants_check_mitosis(parent, child):
 *     Asserts S_max(child) < S_max(parent).  Bumps theorem4_violations
 *     and WARN_ON_ONCE on failure.  parent or child NULL is treated as
 *     a defensive no-op (does NOT count as a violation; the caller
 *     already lost the race).
 *
 *   trust_invariants_check_meiosis(a, b, shared):
 *     Asserts S_max(shared) <= min(S_max(a), S_max(b)).  Same
 *     defensive null-handling.
 *
 * Both functions read parent->lifecycle.max_score / child->lifecycle.max_score.
 * They take the SUBJECT POINTERS BY VALUE — they do NOT dereference any
 * lock or RCU pointer.  Callers must pass stack-local copies.
 */
void trust_invariants_check_mitosis(const void *parent_subject,
                                    const void *child_subject);
void trust_invariants_check_meiosis(const void *a_subject,
                                    const void *b_subject,
                                    const void *shared_subject);

/*
 * Theorem 2 — Non-Replayability.
 *
 *   trust_invariants_check_nonce(prev, next):
 *     Asserts next > prev.  Bumps theorem2_violations and
 *     WARN_ON_ONCE on failure.
 *
 *   trust_invariants_advance_nonce(void):
 *     Convenience: atomically advances the global nonce by 1 and
 *     returns the new value.  Equivalent to (and safer than) the
 *     caller doing prev=read,next=prev+1,write,check.  Use this on
 *     every proof consumption in trust_ape.c.
 */
void trust_invariants_check_nonce(u64 prev, u64 next);
u64  trust_invariants_advance_nonce(void);
u64  trust_invariants_read_nonce(void);

/*
 * Theorem 5 — Guaranteed Revocation O(1).
 *
 * Bracket the apoptosis fast-path with these calls.  The end-call
 * computes (now - start) in nanoseconds and:
 *   - records the running maximum into theorem5_max_us
 *   - if delta > 10000 ns (10us) for a SINGLE-SUBJECT apoptosis,
 *     bumps theorem5_violations and WARN_ON_ONCE
 *
 * If the apoptosis path performs a tree walk (cascade across N
 * children), the caller should bracket EACH per-subject leaf
 * individually — the bound is per-subject, not per-tree.
 */
ktime_t trust_invariants_apoptosis_start(void);
void    trust_invariants_apoptosis_end(ktime_t start);

/*
 * Theorem 6 — Metabolic Fairness.
 *
 * Agent 2 owns the actual detection logic in trust_authz.c.  Agent 2
 * calls TRUST_THEOREM6_VIOLATE("reason-string") at the violation site;
 * we increment the same counter Agent 2's own
 * trust_authz_theorem6_violations() returns, so userspace gets a
 * single coherent number whether it reads /sys/kernel/trust_invariants/
 * or /sys/kernel/trust/.
 */
void __trust_theorem6_count_violation(const char *reason);
#define TRUST_THEOREM6_VIOLATE(reason) \
    __trust_theorem6_count_violation(reason)

/*
 * Counter accessors (read by sysfs show() functions and unit tests).
 */
u64 trust_invariants_get_t1_violations(void);
u64 trust_invariants_get_t2_violations(void);
u64 trust_invariants_get_t4_violations(void);
u64 trust_invariants_get_t5_violations(void);
u64 trust_invariants_get_t5_max_ns(void);
u64 trust_invariants_get_t6_violations(void);

#endif /* __KERNEL__ */

#endif /* TRUST_THEOREMS_H */
