/*
 * trust_morphogen.h - Turing reaction-diffusion tissue field for trust subjects
 *
 * S74 Agent 5 — implements S73 Cluster 1 convergence:
 *   Turing (1952, morphogenesis) +
 *   Wolfram (2002, spatial cellular automata) +
 *   Levin (2019, bioelectric communication)
 *
 * all independently predicted the same architectural gap: trust subjects
 * currently live as a free-floating population with no spatial extension.
 * Biology's 700Mya metazoan transition happened when free cells acquired
 * neighbors -> tissue -> differentiation. We build the minimum primitive
 * needed to compound that topology into trust_subject_t.
 *
 * Mechanism: a 32x32 grid of (activator, inhibitor) scalar cells.
 * Every trust subject is placed at (x,y) by fnv32(pid) % 32; collisions
 * resolve by linear probe. Events perturb the subject's local cell;
 * diffusion and reaction run every 100ms via delayed_work.
 *
 * Gray-Scott style reaction-diffusion with u16 fixed-point values
 * (0..65535 = 0.0..1.0). Constants tuned for spot patterns (reaction
 * localized, inhibitor diffusing faster) rather than dissolution or
 * saturation. See trust_morphogen.c head comment for values.
 *
 * The grid is NOT the moat. The grid is a *memory* of where stress
 * recently landed — the cortex (agent 6 active_inference.py) reads it
 * across the uapi and learns tissue-level anomaly patterns that a free
 * population could never exhibit.
 *
 * Reference implementation boundaries:
 *   - No per-cell dynamic allocation — the 32x32 grid is static.
 *   - No spinlock held across the full tick — the field is copied, then
 *     reacted double-buffered, then swapped under lock.
 *   - Architecture-portable: no __x86_64__ intrinsics.
 *   - Subject coords stored OUT-OF-BAND in a side-table keyed by subject_id,
 *     not in trust_subject_t (that struct is locked at 496 B per S48 audit).
 */

#ifndef TRUST_MORPHOGEN_H
#define TRUST_MORPHOGEN_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/kernel.h>
#include "../include/trust_types.h"  /* trust_subject_t typedef */
#endif

/* ---------------- Grid geometry ---------------- */
#define TRUST_MORPHOGEN_DIM          32U   /* 32 x 32 tissue */
#define TRUST_MORPHOGEN_CELLS        (TRUST_MORPHOGEN_DIM * TRUST_MORPHOGEN_DIM)
#define TRUST_MORPHOGEN_MAX_SUBJECTS TRUST_MORPHOGEN_CELLS /* 1024 */

/* ---------------- Event kinds (lightweight enum, not trust_action_t) ---------------- *
 * These abstract over the dispatcher's action_type so a future caller can
 * perturb the tissue without leaking the full ISA family/opcode code.
 * Values are stable (appended only).
 */
#define TRUST_MORPHOGEN_EVENT_AUTHZ_ALLOW   0U
#define TRUST_MORPHOGEN_EVENT_AUTHZ_DENY    1U   /* +A: stress */
#define TRUST_MORPHOGEN_EVENT_MITOSIS       2U   /* +A small: growth */
#define TRUST_MORPHOGEN_EVENT_APOPTOSIS     3U   /* +I: suppression */
#define TRUST_MORPHOGEN_EVENT_CANCER        4U   /* +A large: severe */
#define TRUST_MORPHOGEN_EVENT_QUARANTINE    5U   /* +I large: suppression */
#define TRUST_MORPHOGEN_EVENT_PROOF_BREAK   6U   /* +A severe */
#define TRUST_MORPHOGEN_EVENT_GENERIC       7U   /* +A mild: any other audit */
#define TRUST_MORPHOGEN_EVENT_MAX           8U

#ifdef __KERNEL__

/* ---------------- Public API ---------------- */

/*
 * Module lifecycle. Called from trust_core.c module_init/module_exit.
 * Both are safe to call if the opposite never was (no-op on double-free).
 */
int  trust_morphogen_init(void);
void trust_morphogen_fini(void);

/*
 * Assign (x,y) coordinates for a freshly-registered subject.
 * Uses fnv32(pid) % TRUST_MORPHOGEN_DIM for base cell; linear probe
 * through the row on collision.
 *
 * Returns  0 on success (coords written to *out_x/*out_y).
 * Returns -ENOSPC if the 32x32 grid is fully occupied.
 * Returns -EINVAL if s is NULL.
 *
 * Side-effect: registers the subject_id -> (x,y) mapping in the
 * morphogen side-table. Call trust_morphogen_remove_subject() when
 * the subject is apoptotic / necrotic / unregistered.
 */
int trust_morphogen_place_subject(const trust_subject_t *s,
                                  u8 *out_x, u8 *out_y);

/* Inverse of place: free the cell for future reuse. Idempotent. */
void trust_morphogen_remove_subject(u32 subject_id);

/*
 * Perturb the local tissue field at the cell owned by `subject_id`.
 * Non-blocking.  Maps event_kind -> (delta_A, delta_I) internally.
 * `severity` is a free-form multiplier (1..1000 typical).
 *
 * Silently ignores perturbations for unregistered subjects — a module
 * that's trying to emit events for a pid before it was placed is the
 * common case during early subject setup, not a bug worth logging.
 */
void trust_morphogen_perturb(u32 subject_id, u32 event_kind, u32 severity);

/*
 * Read one cell (test harness + cortex bridge).
 * out_activator/out_inhibitor are u16 fixed-point 0..65535.
 * Returns 0 on success, -EINVAL if (x,y) out of bounds.
 */
int trust_morphogen_peek(u8 x, u8 y, u16 *out_activator, u16 *out_inhibitor);

#endif /* __KERNEL__ */

#endif /* TRUST_MORPHOGEN_H */
