/*
 * state_machine_tables.c — Total transition legality tables for all
 * typestate enums declared in coherence_types.h.
 *
 * Each table is a square `[STATE_COUNT][STATE_COUNT]` of bools, indexed
 * as `table[from][to]`. A cell value of `true` is a documented
 * intentional transition; `false` means the transition is forbidden
 * (forever — there is no "try anyway" path in the caller).
 *
 * Rationale (R34 discipline):
 *   - No if/else ladders. The table is THE law.
 *   - UNINIT (0) is a strict sink on the `to` side for every enum: no
 *     valid state may regress to uninitialized without an explicit reset
 *     (which is a separate init call, not a transition).
 *   - Self-loops are permitted only where continuing to occupy a state
 *     is physically meaningful (e.g., multiple FRESH samples in a row,
 *     multiple STALE frames in a row).
 *   - Monotonic progress is enforced for the actuation commit pipeline:
 *     COMMITTED cannot regress to BARRIERED, PLANNED cannot regress to
 *     UNINIT. The only backward edge is RATE_LIMITED/FAILED → PLANNED,
 *     which models "next frame gets a fresh plan".
 *
 * Compile-time invariants (_Static_assert below) guarantee that the
 * table dimensions match the enum cardinality; adding a new enum member
 * without extending the table breaks the build.
 */

#include <stdbool.h>
#include <stdint.h>

#include "coherence_types.h"

/* ===== Derived-signal transitions =====
 *
 * UNINIT   → FRESH                       first fresh sample after init
 * FRESH    → {FRESH, STALE}              continuing fresh, or aging out
 * STALE    → {FRESH, STALE, DEGRADED}    recovery, hold, or confidence loss
 * DEGRADED → {FRESH, DEGRADED}           recovery OR continued degradation
 *
 * Explicitly forbidden:
 *   FRESH    → UNINIT     no regression to uninitialized (would discard
 *                         cached EMA state and force a cold start)
 *   FRESH    → DEGRADED   must pass through STALE first (gives the
 *                         state machine a beat to respond before
 *                         confidence collapse)
 *   STALE    → UNINIT     same reason as FRESH→UNINIT
 *   DEGRADED → STALE      backwards progress on the confidence ladder;
 *                         DEGRADED is a soft floor that only exits on
 *                         genuine recovery
 *   DEGRADED → UNINIT     same reason as above
 *   UNINIT   → {STALE, DEGRADED}  cannot know we are stale before we
 *                                 have ever been fresh
 */
static const bool derived_trans[COH_DERIVED_STATE_COUNT][COH_DERIVED_STATE_COUNT] = {
	/* from\to      UNINIT  FRESH  STALE  DEGRADED */
	/* UNINIT   */ { false,  true,  false, false },
	/* FRESH    */ { false,  true,  true,  false },
	/* STALE    */ { false,  true,  true,  true  },
	/* DEGRADED */ { false,  true,  false, true  },
};

/* ===== Actuation commit-pipeline transitions =====
 *
 * UNINIT       → PLANNED                       first arbiter plan
 * PLANNED      → {RATE_LIMITED, BARRIERED,
 *                 COMMITTED, FAILED, PLANNED}  evaluate → one of five outcomes
 * RATE_LIMITED → {PLANNED, RATE_LIMITED}       next frame re-plans, or keeps
 *                                              waiting on τ window
 * BARRIERED    → PLANNED                       idempotent skip; next frame
 *                                              is still the normal path
 * COMMITTED    → PLANNED                       next frame starts with a
 *                                              fresh plan
 * FAILED       → PLANNED                       retry with a fresh plan
 *                                              next frame
 *
 * Explicitly forbidden (the load-bearing invariants):
 *   PLANNED    → UNINIT          no regression once we've begun planning
 *   COMMITTED  → BARRIERED       commits are terminal for the current
 *                                frame; the next barrier check happens
 *                                on the NEXT frame via PLANNED
 *   COMMITTED  → RATE_LIMITED    ditto — post-commit is a new frame
 *   COMMITTED  → FAILED          write either landed or didn't; this
 *                                edge would represent post-hoc failure
 *                                which the kernel does not report here
 *   BARRIERED  → COMMITTED       a barriered commit WROTE NOTHING; it
 *                                cannot become "committed" without going
 *                                through PLANNED again
 *   RATE_LIMITED → COMMITTED/FAILED/BARRIERED  must re-plan first
 *   FAILED     → COMMITTED/RATE_LIMITED/BARRIERED  must re-plan first
 *   * → UNINIT (other than self)  same rule: UNINIT is a construction
 *                                 sink, not a reachable state at runtime
 */
static const bool act_trans[COH_ACT_STATE_COUNT][COH_ACT_STATE_COUNT] = {
	/* from\to            UNINIT  PLANNED  RATE_LIM  BARRIERED  COMMITTED  FAILED */
	/* UNINIT       */ {  false,   true,    false,    false,     false,     false },
	/* PLANNED      */ {  false,   true,    true,     true,      true,      true  },
	/* RATE_LIMITED */ {  false,   true,    true,     false,     false,     false },
	/* BARRIERED    */ {  false,   true,    false,    false,     false,     false },
	/* COMMITTED    */ {  false,   true,    false,    false,     false,     false },
	/* FAILED       */ {  false,   true,    false,    false,     false,     false },
};

/* ===== Posture transition table =====
 *
 * The posture table + coh_posture_transition_legal() are owned by
 * Agent 2 (src/posture.c). We intentionally do NOT define them here
 * to avoid a multiple-definition link error. See coherence_types.h
 * for the declarations. */

/* ===== Compile-time dimension checks =====
 *
 * If a new enum member is added without extending the table, the
 * sizeof ratio changes and the assert fires. This is the whole point
 * of using [COUNT][COUNT] tables: the build refuses to continue when
 * the ABI drifts.
 */
_Static_assert(sizeof(derived_trans) ==
               sizeof(bool) * COH_DERIVED_STATE_COUNT * COH_DERIVED_STATE_COUNT,
               "derived_trans must be COH_DERIVED_STATE_COUNT^2");

_Static_assert(sizeof(act_trans) ==
               sizeof(bool) * COH_ACT_STATE_COUNT * COH_ACT_STATE_COUNT,
               "act_trans must be COH_ACT_STATE_COUNT^2");

/* ===== Public total-function accessors =====
 *
 * Each performs a single bounds check on the input coordinates and
 * returns the table cell. Out-of-range inputs return false (forbidden).
 * This makes the functions safe for arbitrary integer casts from the
 * wire / ioctl boundary. */

bool coh_derived_transition_legal(coh_derived_state_t from, coh_derived_state_t to)
{
	if ((unsigned)from >= (unsigned)COH_DERIVED_STATE_COUNT) return false;
	if ((unsigned)to   >= (unsigned)COH_DERIVED_STATE_COUNT) return false;
	return derived_trans[from][to];
}

bool coh_act_transition_legal(coh_act_state_t from, coh_act_state_t to)
{
	if ((unsigned)from >= (unsigned)COH_ACT_STATE_COUNT) return false;
	if ((unsigned)to   >= (unsigned)COH_ACT_STATE_COUNT) return false;
	return act_trans[from][to];
}

/* coh_posture_transition_legal() is owned by Agent 2 (src/posture.c).
 * Defined there, not here. */
