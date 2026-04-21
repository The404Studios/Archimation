/*
 * trust_lifecycle.h - Mitotic Lifecycle + Cancer Detection (Session 48 / Agent 3)
 *
 * Paper-spec API per "Root of Authority" (Roberts/Eli/Leelee, Zenodo 18710335),
 * sections §Mitosis, §Cancer Detection, §Apoptosis Inheritance.
 *
 * This header layers a paper-faithful surface over the existing
 * trust_lifecycle.c primitives.  Implementation lives entirely in
 * trust_lifecycle.c — no new fields are added to trust_subject_t (locked
 * at 496 bytes per trust/include/trust_ioctl.h _Static_assert).
 *
 * --- Reserved bit positions (do NOT collide with trust_types.h) ---
 *
 *   Existing TRUST_FLAG_* in subj->flags     bits  0..7  (frozen, observed,
 *                                                          escalating, decaying,
 *                                                          new, apoptotic,
 *                                                          cancerous, meiotic)
 *   Existing TRUST_LIFE_FLAG_* in
 *           subj->lifecycle.flags (u32)      bits  0..3  (checkpoint, immune,
 *                                                          orphan, rerooted)
 *
 *   Session 48 / Agent 3 reservations (subj->lifecycle.flags only — keeps
 *   subj->flags open for Agent 6's sex-state machine):
 *     TRUST_LIFE_FLAG_QUARANTINED          bit 4  (cancer-quarantine latch)
 *     TRUST_LIFE_FLAG_CANCER_DESCENDED     bit 5  (descendant-tree apoptosis emitted)
 *     TRUST_LIFE_FLAG_GEN_CAP_DECAYED      bit 6  (S_max(g) cap applied at birth)
 *     TRUST_LIFE_FLAG_INHERITED_HALF_SMAX  bit 7  (XY child halved on parent apoptosis)
 *
 * --- Sex-field handoff to Agent 6 ---
 *
 * The paper requires reading the child's sex during apoptosis-inheritance.
 * Today the sex lives at subj->chromosome.sex with values CHROMO_SEX_XX/XY/YY/YX.
 * Agent 6's mission promises a top-level subj->sex with values TRUST_SEX_XX
 * and TRUST_SEX_XY.  We isolate the access through a single accessor macro
 * so Agent 6 can flip the implementation without touching trust_lifecycle.c:
 */
#ifndef TRUST_LIFECYCLE_H
#define TRUST_LIFECYCLE_H

#include "trust_internal.h"

/*
 * --- Lifecycle flag bits reserved by Agent 3 (Session 48) ---
 *
 * Bits 0..3 of trust_lifecycle_t.flags are owned by trust_types.h
 * (TRUST_LIFE_FLAG_CHECKPOINT/IMMUNE/ORPHAN/REROOTED).  Bits 4..7 are
 * reserved here.  Bits 8..31 remain free for future agents.
 */
#define TRUST_LIFE_FLAG_QUARANTINED         (1U << 4)
#define TRUST_LIFE_FLAG_CANCER_DESCENDED    (1U << 5)
#define TRUST_LIFE_FLAG_GEN_CAP_DECAYED     (1U << 6)
#define TRUST_LIFE_FLAG_INHERITED_HALF_SMAX (1U << 7)

/*
 * --- Sex-field accessor (Agent 6 handoff) ---
 *
 * Returns a CHROMO_SEX_* / TRUST_SEX_* value suitable for the apoptosis-
 * inheritance switch.  Until Agent 6 lands subj->sex, we read from the
 * chromosome.  When Agent 6 defines TRUST_SEX_XX, the macro short-circuits
 * to subj->sex — both sets of constants happen to share the canonical
 * values (XX=0, XY=1) so the cascade switch keeps working unchanged.
 */
#ifdef TRUST_SEX_XX
#  define TRUST_SUBJECT_SEX(s) ((s)->sex)
#else
#  define TRUST_SUBJECT_SEX(s) ((s)->chromosome.sex)
#  define TRUST_SEX_XX  CHROMO_SEX_XX
#  define TRUST_SEX_XY  CHROMO_SEX_XY
#endif

/*
 * --- Generational-decay constants (paper §Mitosis) ---
 *
 * S_max(g) = S_max(0) * alpha^g, alpha in (0,1).
 *
 * The paper recommends alpha = 0.95.  trust_types.h ships
 * TRUST_GENERATION_ALPHA_NUM=230 / _DEN=256 (~0.898) for the legacy
 * fixed-point path.  Agent 3 introduces a SECOND alpha specifically for
 * the new trust_mitosis() spec API so the legacy mitotic_divide path
 * stays bit-identical (no behavioral regression on existing tests).
 *
 * 0.95 in 16.16 fixed-point = 0.95 * 65536 = 62259 (rounded).
 */
#define TRUST_MITOSIS_ALPHA_Q16    62259U   /* 0.95 * 65536 */
#define TRUST_MITOSIS_ALPHA_SHIFT  16

/*
 * --- Cancer-detection window (paper §Cancer Detection) ---
 *
 * "16 mitoses in <100ms" is the spec default.  Tunable at runtime via
 * /sys/kernel/trust/cancer_threshold_ms.
 */
#define TRUST_CANCER_WINDOW_N             16     /* ring-buffer depth */
#define TRUST_CANCER_THRESHOLD_MS_DEFAULT 100

/*
 * --- Mitosis API (Agent 3 owned) ---
 *
 * trust_mitosis() is the paper-spec entry point.  parent must be a
 * pointer to a trust_subject_t that the caller has already located
 * (used for the B-segment copy + generation read); child_pid is the
 * new subject ID; out_child receives a snapshot of the freshly-
 * inserted child on success (NULL allowed).
 *
 * Returns 0 on success, -EPERM if the parent is in cancer/lockdown,
 * -ENOENT if parent disappeared during the call, -ENOMEM on TLB
 * insert failure.
 *
 * Bounded Authority Inheritance (Theorem 4): the post-condition
 *   S_max(child) < S_max(parent)
 * is asserted via WARN_ON_ONCE before return.  A violation indicates
 * a generational-decay coding error and never aborts the call (we
 * still want the child inserted so userspace doesn't end up with a
 * dangling pid).
 */
int trust_mitosis(trust_subject_t *parent,
                  pid_t child_pid,
                  trust_subject_t **out_child);

/*
 * Compatibility wrapper used by the fork/clone hook path.  Looks up
 * the parent in the TLB by id and dispatches to trust_mitosis().
 */
int trust_mitosis_by_id(u32 parent_id, pid_t child_pid);

/*
 * --- Apoptosis-Inheritance API (paper §Apoptosis) ---
 *
 * Walk the parent's child list during apoptosis:
 *   - children with TRUST_SUBJECT_SEX(child) == TRUST_SEX_XX  →  die with parent
 *   - children with TRUST_SUBJECT_SEX(child) == TRUST_SEX_XY  →  survive,
 *     S_max halved (lifecycle.max_score >>= 1)
 *
 * Idempotent: marks child with TRUST_LIFE_FLAG_INHERITED_HALF_SMAX after
 * the first halving so a second cascade tick doesn't quarter the cap.
 *
 * Returns the number of children processed (XX killed + XY halved).
 */
int trust_apoptosis_inherit(u32 parent_id);

/*
 * Public deferred-apoptosis trigger used by the cancer-detection path
 * to terminate a descendant subtree without recursing through the
 * whole _trust_lifecycle_apoptotic_cascade machinery (which is
 * depth-limited at 4 — too shallow for runaway cancer subtrees).
 *
 * Best-effort: ENOENT subjects are skipped silently.
 */
int trust_apoptosis_request(u32 subject_id);

/*
 * --- Cancer Detection API (paper §Cancer Detection) ---
 *
 * Records one mitosis timestamp into the parent's sliding window and
 * returns true if the (N=16) window's span is below the configured
 * threshold (default 100ms).  Caller is responsible for invoking the
 * full cancer-response path (quarantine + descendant-apoptosis +
 * audit + counter) — see trust_cancer_trigger() below.
 */
bool trust_cancer_record_mitosis(u32 parent_id, u64 now_ns);

/*
 * Full cancer-response sequence per paper §Cancer Detection:
 *   a) quarantine parent (TRUST_LIFE_FLAG_QUARANTINED)
 *   b) walk descendant tree → trust_apoptosis_request() on each
 *   c) emit TRUST_EVT_CANCER_DETECTED to audit ring
 *   d) bump /sys/kernel/trust/cancer_detections counter
 */
int trust_cancer_trigger(u32 parent_id);

/* --- sysfs registration --- */
int  trust_lifecycle_sysfs_register(struct kobject *parent_kobj);
void trust_lifecycle_sysfs_unregister(void);

/* Counter accessors (used by sysfs and tests). */
u64 trust_cancer_get_detection_count(void);
u32 trust_cancer_get_threshold_ms(void);
void trust_cancer_set_threshold_ms(u32 ms);

#endif /* TRUST_LIFECYCLE_H */
