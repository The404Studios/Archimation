/*
 * state_machine.h — 4-state arbiter with hysteresis + transition lockout.
 *
 * Transition rules (ChatGPT-derived; mirror docs/coherence-design.md):
 *
 *   NORMAL
 *     → LATENCY_CRITICAL    if D.latency_pressure > θL_enter for τ_hold
 *     → THERMAL_CONSTRAINED if D.thermal > θT_enter for τ_hold
 *
 *   LATENCY_CRITICAL
 *     → THERMAL_CONSTRAINED if D.thermal > θT_enter     (IMMEDIATE, thermal wins)
 *     → NORMAL              if D.latency_pressure < θL_exit for τ_hold
 *
 *   THERMAL_CONSTRAINED
 *     → NORMAL              if D.thermal < θT_exit for τ_hold
 *     → DEGRADED            if D.latency_pressure > θL_enter AND thermal still high
 *
 *   DEGRADED
 *     → NORMAL              if thermal < θT_exit AND latency_pressure < θL_exit for τ_hold
 *
 * Lockout: after every state change, arbiter->lockout_until_t_ms is set to
 * now + TRANSITION_LOCKOUT_MS. During lockout, `state_machine_evaluate`
 * still runs (to keep dwell counters warm) but WILL NOT change state.
 */
#ifndef COH_STATE_MACHINE_H
#define COH_STATE_MACHINE_H

#include <stdint.h>
#include <stdbool.h>

#include "coherence_types.h"
#include "config.h"

/* Per-arbiter private scratch that tracks how long each threshold has been
 * tripped. We keep this outside coh_arbiter_t so the simulator can snapshot
 * arbiter state without pulling in our dwell counters. */
typedef struct {
	/* Consecutive milliseconds each predicate has been true. */
	uint32_t lat_enter_dwell_ms;
	uint32_t lat_exit_dwell_ms;
	uint32_t therm_enter_dwell_ms;
	uint32_t therm_exit_dwell_ms;
	uint32_t both_clear_dwell_ms;    /* used by DEGRADED → NORMAL rule */

	/* Last evaluate() timestamp — used to compute dt for dwell accumulation. */
	uint64_t last_eval_t_ms;

	/* Count how many evaluate() calls were short-circuited by lockout. */
	uint64_t lockout_holds;
} coh_sm_scratch_t;

/* Initialise arbiter + scratch. Enters NORMAL with no lockout. */
void coh_sm_init(coh_arbiter_t *arb, coh_sm_scratch_t *scratch, uint64_t now_ms);

/*
 * Evaluate the transition predicates against the latest derived vector.
 *
 *   now_ms  — monotonic clock at the start of the decision phase
 *   d       — latest D(t). If d->valid == false, evaluate() returns early
 *             without updating state but still increments last_eval_t_ms.
 *
 * Returns true if the state changed, false otherwise. If in lockout,
 * counters are still advanced but state will not change.
 */
bool coh_sm_evaluate(coh_arbiter_t *arb,
                     coh_sm_scratch_t *scratch,
                     const coh_derived_t *d,
                     const coh_config_t *cfg,
                     uint64_t now_ms);

/*
 * Map the current state + latest D(t) into a next-actuation plan A(t).
 * Fills a_next in-place; the caller owns the memory. This routine does
 * NOT touch the system — commit is a separate barrier call owned by
 * actuation.c. cpuset/irq fields are left at {0}; agent 9 fills them
 * with NUMA-aware masks at configure time.
 */
void coh_sm_plan(const coh_arbiter_t *arb,
                 const coh_derived_t *d,
                 coh_actuation_t *a_next,
                 uint64_t now_ms);

/* Human-readable state name, for logs. Never NULL. */
const char *coh_sm_state_name(coh_state_t s);

#endif /* COH_STATE_MACHINE_H */
