/*
 * state_machine.c — 4-state arbiter with hysteresis + transition lockout.
 *
 * Rules (see state_machine.h for the full matrix):
 *
 *   NORMAL → LATENCY_CRITICAL       if D.latency_pressure > θL_enter for τ_hold
 *   NORMAL → THERMAL_CONSTRAINED    if D.thermal > θT_enter for τ_hold
 *
 *   LATENCY_CRITICAL → THERMAL_CONSTRAINED   if D.thermal > θT_enter (IMMEDIATE)
 *   LATENCY_CRITICAL → NORMAL                if D.latency_pressure < θL_exit for τ_hold
 *
 *   THERMAL_CONSTRAINED → NORMAL      if D.thermal < θT_exit for τ_hold
 *   THERMAL_CONSTRAINED → DEGRADED    if D.latency_pressure > θL_enter AND thermal high
 *
 *   DEGRADED → NORMAL                 if thermal < θT_exit AND lat < θL_exit for τ_hold
 *
 * Lockout: every transition sets arb->lockout_until_t_ms = now + lockout_ms.
 * In lockout, coh_sm_evaluate() advances dwell counters but refuses to change
 * state. This is how we avoid oscillation / bouncing.
 */

#include "state_machine.h"

#include <stdio.h>
#include <string.h>

/* --------- small helpers --------- */

static inline void coh_dwell_accum(uint32_t *dwell_ms, bool predicate, uint32_t dt_ms)
{
	if (predicate) {
		/* Saturate rather than wrap. */
		if (*dwell_ms > UINT32_MAX - dt_ms)
			*dwell_ms = UINT32_MAX;
		else
			*dwell_ms += dt_ms;
	} else {
		*dwell_ms = 0;
	}
}

static void coh_enter_state(coh_arbiter_t *arb,
                            coh_sm_scratch_t *scratch,
                            coh_state_t new_state,
                            const coh_config_t *cfg,
                            uint64_t now_ms)
{
	coh_state_t old = arb->state;
	arb->state = new_state;
	arb->state_enter_t_ms = now_ms;
	arb->lockout_until_t_ms = now_ms + cfg->transition_lockout_ms;
	arb->transitions_total++;
	arb->transitions_last_window++;

	/* Reset dwell counters — every new state starts fresh. */
	scratch->lat_enter_dwell_ms = 0;
	scratch->lat_exit_dwell_ms = 0;
	scratch->therm_enter_dwell_ms = 0;
	scratch->therm_exit_dwell_ms = 0;
	scratch->both_clear_dwell_ms = 0;

	fprintf(stderr,
	        "{\"event\":\"state_transition\",\"t_ms\":%llu,\"from\":\"%s\",\"to\":\"%s\",\"lockout_until\":%llu}\n",
	        (unsigned long long)now_ms,
	        coh_sm_state_name(old), coh_sm_state_name(new_state),
	        (unsigned long long)arb->lockout_until_t_ms);
}

/* --------- public API --------- */

void coh_sm_init(coh_arbiter_t *arb, coh_sm_scratch_t *scratch, uint64_t now_ms)
{
	if (!arb || !scratch) return;
	memset(arb, 0, sizeof(*arb));
	memset(scratch, 0, sizeof(*scratch));
	arb->state = COH_STATE_NORMAL;
	arb->state_enter_t_ms = now_ms;
	arb->lockout_until_t_ms = 0;        /* no lockout at boot */
	scratch->last_eval_t_ms = now_ms;
}

const char *coh_sm_state_name(coh_state_t s)
{
	switch (s) {
	case COH_STATE_NORMAL:              return "NORMAL";
	case COH_STATE_LATENCY_CRITICAL:    return "LATENCY_CRITICAL";
	case COH_STATE_THERMAL_CONSTRAINED: return "THERMAL_CONSTRAINED";
	case COH_STATE_DEGRADED:            return "DEGRADED";
	case COH_STATE_COUNT:               /* fallthrough */
	default:                            return "UNKNOWN";
	}
}

/* ===== R34 typestate stringifiers =====
 *
 * These are the RUNTIME SIDE of the declarations in coherence_types.h.
 * Discipline rules (non-negotiable):
 *   - Every named state has an explicit case.
 *   - Unknown / out-of-range inputs return the literal "INVALID".
 *   - Returned string is statically allocated; caller never frees.
 *   - _Static_assert below wires the switch coverage to the enum
 *     cardinality so adding an enum member without extending the
 *     stringifier fails the build.
 *
 * NOTE on the _Static_assert strategy: C11 does not give us a way to
 * assert switch-case coverage directly. We instead assert the total
 * STATE_COUNT so that the next developer who bumps the enum is forced
 * into this file via the build break on the updated count value. See
 * the sibling tests/test_typestate.c which exercises every value at
 * runtime.
 */

const char *coh_derived_state_str(coh_derived_state_t s)
{
	switch (s) {
	case COH_DERIVED_UNINIT:      return "UNINIT";
	case COH_DERIVED_FRESH:       return "FRESH";
	case COH_DERIVED_STALE:       return "STALE";
	case COH_DERIVED_DEGRADED:    return "DEGRADED";
	case COH_DERIVED_STATE_COUNT: /* fallthrough — not a real state */
	default:                      return "INVALID";
	}
}

const char *coh_act_state_str(coh_act_state_t s)
{
	switch (s) {
	case COH_ACT_UNINIT:       return "UNINIT";
	case COH_ACT_PLANNED:      return "PLANNED";
	case COH_ACT_RATE_LIMITED: return "RATE_LIMITED";
	case COH_ACT_BARRIERED:    return "BARRIERED";
	case COH_ACT_COMMITTED:    return "COMMITTED";
	case COH_ACT_FAILED:       return "FAILED";
	case COH_ACT_STATE_COUNT:  /* fallthrough */
	default:                   return "INVALID";
	}
}

/* coh_posture_state_str() is owned by Agent 2 (src/posture.c). We
 * deliberately do NOT define it here to avoid a multiple-definition
 * link error. The prototype is in coherence_types.h and is resolved
 * at link time by Agent 2's translation unit. */

/* Compile-time anchor: if a new enum member appears without being added
 * to the switch above, this assert will not fire on its own — but the
 * next developer should be forced to update the expected count here
 * and land in this file. Matching counts are the cheapest tripwire we
 * can build without reflection. */
_Static_assert(COH_DERIVED_STATE_COUNT == 4,
               "derived stringifier must cover exactly 4 named states");
_Static_assert(COH_ACT_STATE_COUNT == 6,
               "actuation stringifier must cover exactly 6 named states");

bool coh_sm_evaluate(coh_arbiter_t *arb,
                     coh_sm_scratch_t *scratch,
                     const coh_derived_t *d,
                     const coh_config_t *cfg,
                     uint64_t now_ms)
{
	if (!arb || !scratch || !d || !cfg) return false;

	/* Compute dt since last evaluate. Clamp to avoid runaway accumulation
	 * on wake-from-suspend or startup. */
	uint32_t dt_ms = 0;
	if (now_ms > scratch->last_eval_t_ms) {
		uint64_t raw_dt = now_ms - scratch->last_eval_t_ms;
		dt_ms = (raw_dt > (uint64_t)COH_DECISION_FRAME_MS * 4) ?
		        (uint32_t)(COH_DECISION_FRAME_MS * 4) : (uint32_t)raw_dt;
	}
	scratch->last_eval_t_ms = now_ms;

	/* If D is invalid, advance timestamp but leave predicates untouched.
	 * We do NOT want stale data to accumulate dwell. */
	if (!d->valid) {
		return false;
	}

	/* Evaluate all raw predicates. */
	bool lat_hi = d->latency_pressure > cfg->theta_latency_enter;
	bool lat_lo = d->latency_pressure < cfg->theta_latency_exit;
	bool therm_hi = d->thermal > cfg->theta_thermal_enter;
	bool therm_lo = d->thermal < cfg->theta_thermal_exit;

	/* Accumulate dwell counters BEFORE lockout check so counters keep
	 * current — this way a lockout doesn't reset hysteresis state,
	 * and the next opportunity to transition is immediate once lockout
	 * clears (assuming the predicate has held continuously). */
	coh_dwell_accum(&scratch->lat_enter_dwell_ms, lat_hi, dt_ms);
	coh_dwell_accum(&scratch->lat_exit_dwell_ms, lat_lo, dt_ms);
	coh_dwell_accum(&scratch->therm_enter_dwell_ms, therm_hi, dt_ms);
	coh_dwell_accum(&scratch->therm_exit_dwell_ms, therm_lo, dt_ms);
	coh_dwell_accum(&scratch->both_clear_dwell_ms, (lat_lo && therm_lo), dt_ms);

	/* Lockout gate: counters advance, state doesn't. */
	if (coh_in_lockout(arb, now_ms)) {
		scratch->lockout_holds++;
		return false;
	}

	const uint32_t hold = cfg->tau_hold_ms;
	coh_state_t target = arb->state;

	switch (arb->state) {
	case COH_STATE_NORMAL:
		/* Thermal takes precedence if both are elevated — thermal is a
		 * hardware constraint and we must relieve it first. */
		if (therm_hi && scratch->therm_enter_dwell_ms >= hold)
			target = COH_STATE_THERMAL_CONSTRAINED;
		else if (lat_hi && scratch->lat_enter_dwell_ms >= hold)
			target = COH_STATE_LATENCY_CRITICAL;
		break;

	case COH_STATE_LATENCY_CRITICAL:
		/* Thermal wins — immediate transition, no dwell gate. */
		if (therm_hi) {
			target = COH_STATE_THERMAL_CONSTRAINED;
			break;
		}
		if (lat_lo && scratch->lat_exit_dwell_ms >= hold)
			target = COH_STATE_NORMAL;
		break;

	case COH_STATE_THERMAL_CONSTRAINED:
		/* Exit to normal takes precedence over degrading — if thermal is
		 * resolved we prefer recovery. */
		if (therm_lo && scratch->therm_exit_dwell_ms >= hold) {
			target = COH_STATE_NORMAL;
			break;
		}
		/* Both problems present simultaneously → DEGRADED. Latency enter
		 * threshold must be cleanly held; thermal does not need
		 * additional dwell because we're already in THERMAL_CONSTRAINED. */
		if (lat_hi && scratch->lat_enter_dwell_ms >= hold && !therm_lo)
			target = COH_STATE_DEGRADED;
		break;

	case COH_STATE_DEGRADED:
		/* Both must clear simultaneously for the full hold period. */
		if (scratch->both_clear_dwell_ms >= hold)
			target = COH_STATE_NORMAL;
		break;

	case COH_STATE_COUNT:
	default:
		/* Shouldn't happen — recover to NORMAL and log. */
		fprintf(stderr, "{\"event\":\"state_invalid\",\"state\":%d}\n",
		        (int)arb->state);
		target = COH_STATE_NORMAL;
		break;
	}

	if (target != arb->state) {
		coh_enter_state(arb, scratch, target, cfg, now_ms);
		return true;
	}
	return false;
}

void coh_sm_plan(const coh_arbiter_t *arb,
                 const coh_derived_t *d,
                 coh_actuation_t *a_next,
                 uint64_t now_ms)
{
	if (!arb || !d || !a_next) return;

	/* Preserve cpuset/irq fields — these are owned by Agent 9 (NUMA
	 * topology configurator) at initialization time. We only touch the
	 * high-level mapping here. Start from zero only on first plan. */
	memset(a_next, 0, sizeof(*a_next));
	a_next->t_ms = now_ms;

	switch (arb->state) {
	case COH_STATE_NORMAL:
		a_next->epp = COH_EPP_BALANCE_PERF;
		a_next->min_perf_pct = 25;
		a_next->present_mode_override = COH_PRESENT_MAILBOX;
		a_next->use_gamescope = false;
		break;

	case COH_STATE_LATENCY_CRITICAL:
		a_next->epp = COH_EPP_PERFORMANCE;
		a_next->min_perf_pct = 70;
		/* IMMEDIATE is a recovery mode; only upgrade from MAILBOX if the
		 * measurement layer actually saw FIFO queued frames. D carries no
		 * direct signal for that here, so we stay on MAILBOX and let
		 * Agent 6 escalate based on observed present_mode_actual if it
		 * deems necessary (documented in docs/coherence-design.md §4.3). */
		a_next->present_mode_override = COH_PRESENT_MAILBOX;
		a_next->use_gamescope = false;
		break;

	case COH_STATE_THERMAL_CONSTRAINED:
		a_next->epp = COH_EPP_BALANCE_POWER;
		a_next->min_perf_pct = 30;
		a_next->present_mode_override = COH_PRESENT_MAILBOX;
		a_next->use_gamescope = false;
		break;

	case COH_STATE_DEGRADED:
		a_next->epp = COH_EPP_POWER;
		a_next->min_perf_pct = 10;
		/* FIFO enforces v-sync and gives the GPU a fixed budget — the
		 * right behavior when we've given up on responsiveness and want
		 * predictability. */
		a_next->present_mode_override = COH_PRESENT_FIFO;
		a_next->use_gamescope = true;  /* scale/cap to the rescue */
		break;

	case COH_STATE_COUNT:
	default:
		a_next->epp = COH_EPP_DEFAULT;
		a_next->min_perf_pct = -1;
		a_next->present_mode_override = COH_PRESENT_AUTO;
		a_next->use_gamescope = false;
		break;
	}

	/* sqpoll_cpu: -1 means "let Agent 6 pick from its NUMA topology". */
	a_next->sqpoll_cpu = -1;

	/* irq_count + cpuset strings stay {0} — Agent 9 fills at configure
	 * time from NUMA topology. We're intentionally leaving policy
	 * (cpuset mask strategy per state) to Agent 6.
	 *
	 * Silence unused-parameter warning for d without triggering -Wcast
	 * problems: we consume d implicitly by state only. */
	(void)d;
}
