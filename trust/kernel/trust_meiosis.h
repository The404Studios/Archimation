/*
 * trust_meiosis.h - Meiotic shared-authority entities (Session 48)
 *
 * Implements §Meiosis from "Root of Authority" (Roberts/Eli/Leelee, Zenodo
 * 18710335).  Two parent subjects A and B contribute one chromosome from
 * each of their 23 pairs, blinded by SHA-256(seg ‖ random_blind), with
 * dominance by relative trust score.  The combined entity lives at the
 * kernel-internal ring (-2) and bonds to both parents: if EITHER parent
 * enters apoptosis, the shared entity does too.
 *
 * Public surface:
 *   trust_meiosis(A, B, &shared)
 *       Construct a new shared subject from two existing subjects.
 *
 *   trust_meiosis_request_by_id(id_a, id_b, &out_id)
 *       ioctl wrapper that resolves IDs via the TLB, performs
 *       capability checks, and returns the new subject_id.
 *
 *   trust_meiosis_on_parent_apoptosis(parent_id)
 *       MUST be invoked from trust_lifecycle.c's apoptosis path
 *       (Agent 3 owns that file).  Walks the bond table and triggers
 *       apoptosis on every shared subject bonded to this parent.
 *
 *   trust_meiosis_init / trust_meiosis_cleanup
 *       Module setup/teardown.  Called from trust_core.c module init/exit.
 *
 *   trust_meiosis_register_sysfs / trust_meiosis_unregister_sysfs
 *       Hook /sys/kernel/trust/meiosis_count and meiosis_active_bonds.
 *
 *   trust_meiosis_count() / trust_meiosis_active_bonds()
 *       Atomic counter accessors.  Safe from any context.
 *
 * Kernel-internal flags (private to trust_meiosis.c — never exposed to
 * userspace).  Bit 16+ are unused by trust_types.h's TRUST_FLAG_* set.
 */

#ifndef TRUST_MEIOSIS_H
#define TRUST_MEIOSIS_H

#ifdef __KERNEL__

#include <linux/types.h>
#include "../include/trust_types.h"

/* Kernel-only ring marker.  Userspace ring values are 0..4 (auth_level);
 * "ring -2" is a paper concept meaning "below kernel, never directly
 * addressable by user code".  We encode it as a high flag bit.  Subjects
 * with this bit set MUST NOT be returned to userspace through any
 * non-meiosis path, and the meiosis ioctl only returns their numeric id
 * (userspace cannot operate on them through the legacy register/get
 * paths because they are kept absent from the standard TLB-set-by-id
 * lookup tables — see trust_meiosis.c).
 */
#define TRUST_FLAG_SHARED_R2  (1U << 16)

/*
 * Wire struct for TRUST_IOC_MEIOSIS — duplicated here so kernel callers
 * don't have to include the userspace header.  Authoritative definition
 * is in trust_uapi.h; the _Static_assert in trust_ioctl.h pins the wire
 * size at 16 bytes.
 */
struct trust_ioc_meiosis_kernel {
    u32 parent_a_id;
    u32 parent_b_id;
    s32 result;             /* OUT: 0 ok, -EPERM caps, -ESRCH no parent, -EINVAL */
    u32 shared_subject_id;  /* OUT: id of new shared subject (0 on failure) */
};

/* --- Public API --- */

/* Initialize meiosis subsystem (bond table + counters).  Called from
 * trust_core.c::trust_init() AFTER trust_ape_init() and TLB init. */
int  trust_meiosis_init(void);
void trust_meiosis_cleanup(void);

/* sysfs registration — exposed separately so module init can sequence it
 * after trust_stats_register() has created /sys/kernel/trust. */
int  trust_meiosis_register_sysfs(void);
void trust_meiosis_unregister_sysfs(void);

/*
 * Core API — paper §Meiosis function signature.
 *
 * Caller passes two subject pointers (already located in the TLB; the
 * caller is responsible for snapshotting them coherently).  On success,
 * *out_shared receives a kmalloc'd subject the caller MAY copy from
 * (the canonical copy is also installed in the TLB and the bond table).
 *
 * Returns:
 *    0      on success (*out_shared populated)
 *  -EINVAL  null arguments, ring/domain mismatch, or dead parent
 *  -ENOMEM  bond-table or subject-table exhaustion
 *  -EEXIST  shared subject ID collision (transient — caller may retry)
 *  -EIO     APE seed init failed
 */
int trust_meiosis(trust_subject_t *A,
                  trust_subject_t *B,
                  trust_subject_t **out_shared);

/*
 * ioctl-side wrapper.  Resolves both parent IDs through the TLB,
 * enforces TRUST_CAP_TRUST_MODIFY on the calling process, then calls
 * trust_meiosis().  Writes the new shared subject_id into *out_shared_id.
 *
 * Returns the same errno set as trust_meiosis(), plus -ESRCH if either
 * parent_id does not resolve to a TLB entry, and -EPERM if the caller
 * lacks the modify cap on either parent.
 */
int trust_meiosis_request_by_id(u32 parent_a_id, u32 parent_b_id,
                                u32 *out_shared_id);

/*
 * Bond-dependency hook.  trust_lifecycle.c (Agent 3) MUST call this from
 * inside its apoptosis path AFTER the parent's apoptotic flag is set but
 * BEFORE returning.  Walks the bond table and triggers apoptosis on every
 * shared subject bonded to this parent.  Idempotent: safe to call on a
 * parent that is not bonded (no-op).  Internally uses trust_lifecycle's
 * own apoptosis API to ensure the cascade is depth-bounded.
 *
 * Recursion-safe: if the shared subject is itself a parent in another
 * meiosis bond, that secondary cascade is also triggered.  The
 * underlying trust_lifecycle_apoptosis() carries its own depth limit.
 */
void trust_meiosis_on_parent_apoptosis(u32 parent_id);

/* Counter accessors for sysfs / observability. */
u64 trust_meiosis_count(void);
u64 trust_meiosis_active_bonds(void);

/*
 * Session 49 Agent C — Evactor.  Walks the bond table and triggers
 * apoptosis cascade for any bond whose parent is no longer in the TLB.
 * Bounded at 64 missing-parent ids per call.  Returns the number of
 * cascades fired.  Called from trust_lifecycle.c's delayed_work tick.
 */
int  trust_meiosis_evact_orphans(void);
u64  trust_meiosis_evacted_total(void);

#endif /* __KERNEL__ */
#endif /* TRUST_MEIOSIS_H */
