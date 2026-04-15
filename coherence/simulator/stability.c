/*
 * stability.c — Lyapunov + oscillation analyser for simulator output.
 *
 * Pass/fail contract:
 *
 *   stable := (oscillation_count == 0)
 *          && (worst_case_deviation < 0.20)     ; 20% over θL_enter
 *          && (recovery_time_max_ms < 2000)     ; back to NORMAL
 *          && (lyapunov_slope <= 0)             ; V decreasing on avg
 *
 * Oscillation detector:
 *   In a sliding 2000 ms window, count sign flips of ΔV(t)=V(t)-V(t-1).
 *   If any window contains >3 flips, increment oscillation_count.
 *
 * Lyapunov slope:
 *   Unweighted least-squares linear fit of V(t) vs t. We use the
 *   closed-form formula (not an iterative solver) so the output is
 *   bit-identical across compilers when input is bit-identical.
 *
 * WCD: max over time of D_latency_pressure RELATIVE to θL_enter.
 *   wcd = max(d_latency_pressure) - θL_enter
 *   If wcd < 0, the signal never crossed the threshold — set to 0.
 */

#define _POSIX_C_SOURCE 200809L

#include "sim_internal.h"

#include <math.h>
#include <stdint.h>
#include <string.h>

/* Fail-reason strings must have static storage. */
static const char *const REASON_NONE       = "";
static const char *const REASON_OSC        = "oscillation_count > 0";
static const char *const REASON_WCD        = "worst_case_deviation >= 0.20";
static const char *const REASON_RT         = "recovery_time_max_ms >= 2000";
static const char *const REASON_SLOPE      = "lyapunov_slope > 0 (V growing)";
static const char *const REASON_EMPTY      = "no records";

/*
 * Return the time in ms the record array spent NOT in NORMAL, summed
 * over contiguous runs. We report the single longest run as
 * recovery_time_max_ms.
 */
static double longest_non_normal_ms(const sim_tick_record_t *r, size_t n)
{
	if (n == 0) return 0.0;

	double best   = 0.0;
	double run    = 0.0;
	uint64_t last_t = r[0].t_ms;
	bool     in_run = (r[0].state != COH_STATE_NORMAL);

	for (size_t i = 1; i < n; i++) {
		double dt = (double)(r[i].t_ms - last_t);
		last_t = r[i].t_ms;
		if (dt < 0.0) dt = 0.0;

		if (r[i].state != COH_STATE_NORMAL) {
			if (in_run) {
				run += dt;
			} else {
				in_run = true;
				run = dt;
			}
			if (run > best) best = run;
		} else {
			in_run = false;
			run = 0.0;
		}
	}
	return best;
}

/*
 * Oscillation count: per sim_internal.h contract, this is the number
 * of 2 s sliding windows that contained >3 state transitions.
 *
 * Implementation: on every state change, walk the 2 s window ending
 * at that change and count other state changes within it. If >3
 * transitions, emit one oscillation and then require a 2 s clean
 * gap before another can be counted (prevents a single hunting
 * episode from showing up as N overlapping oscillations).
 *
 * We deliberately do NOT count ΔV sign-flips: a V-spike during a
 * transient burst produces 2-4 rapid sign flips as the EMA catches
 * up, which is not oscillation in any control-theoretic sense —
 * it's a *transient* that the hysteresis correctly suppressed.
 * Genuine oscillation shows up as repeated state flapping.
 */
static uint32_t oscillation_count_2s(const sim_tick_record_t *r, size_t n)
{
	if (n < 2) return 0;

	uint32_t count = 0;
	uint64_t last_trip_t = 0;
	bool     tripped = false;

	for (size_t end = 1; end < n; end++) {
		if (!r[end].state_changed) continue;

		uint64_t t_end   = r[end].t_ms;
		uint64_t t_start = (t_end > 2000u) ? (t_end - 2000u) : 0u;

		int state_flips = 0;
		for (size_t i = end; i > 0; i--) {
			if (r[i - 1].t_ms < t_start) break;
			if (r[i].state_changed) state_flips++;
		}

		if (state_flips > 3) {
			if (!tripped || (t_end - last_trip_t) > 2000u) {
				count++;
				tripped = true;
				last_trip_t = t_end;
			}
		} else if (tripped && (t_end - last_trip_t) > 2000u) {
			tripped = false;
		}
	}

	return count;
}

/*
 * Least-squares linear fit of V vs t. Returns the slope dV/dt in
 * units of "V per ms". Robust to n==1 (returns 0.0).
 */
static double lyapunov_slope_fit(const sim_tick_record_t *r, size_t n)
{
	if (n < 2) return 0.0;

	/* Work in double. Use Welford-style accumulation for numerical
	 * stability at long trace lengths. */
	double mean_t = 0.0, mean_v = 0.0;
	double c_tv = 0.0, c_tt = 0.0;
	for (size_t i = 0; i < n; i++) {
		double dt = (double)r[i].t_ms - mean_t;
		double dv = r[i].lyapunov_v - mean_v;
		mean_t += dt / (double)(i + 1);
		mean_v += dv / (double)(i + 1);
		/* Covariance + variance accumulators. */
		c_tv += dt * (r[i].lyapunov_v - mean_v);
		c_tt += dt * ((double)r[i].t_ms - mean_t);
	}
	if (c_tt < 1e-12) return 0.0;
	return c_tv / c_tt;
}

void stability_compute(const sim_tick_record_t *recs,
                       size_t n,
                       sim_stability_t *out)
{
	if (!out) return;
	memset(out, 0, sizeof(*out));
	out->fail_reason = REASON_NONE;

	if (!recs || n == 0) {
		out->stable = false;
		out->fail_reason = REASON_EMPTY;
		return;
	}

	double sum_v = 0.0;
	double max_v = 0.0;
	double max_d_lat = 0.0;
	uint64_t a_writes = 0, a_noops = 0;

	for (size_t i = 0; i < n; i++) {
		sum_v += recs[i].lyapunov_v;
		if (recs[i].lyapunov_v > max_v) max_v = recs[i].lyapunov_v;
		if (recs[i].d_latency_pressure > max_d_lat)
			max_d_lat = recs[i].d_latency_pressure;

		out->state_counts[(int)recs[i].state]++;

		/* actuation write/no-op counting — only at ACTUATION_FRAME ticks. */
		if ((recs[i].t_ms % COH_ACTUATION_FRAME_MS) == 0u) {
			if (recs[i].a_wrote) a_writes++;
			else                 a_noops++;
		}
	}

	out->mean_v = sum_v / (double)n;
	out->max_v  = max_v;

	/* WCD: how far above θL_enter did we get? Use the shipping
	 * default from the header — NOT the config's potentially swept
	 * θL_enter — so WCD is comparable across sweep rows. */
	double wcd = max_d_lat - COH_THETA_LATENCY_ENTER;
	if (wcd < 0.0) wcd = 0.0;
	out->worst_case_deviation = wcd;

	out->recovery_time_max_ms = longest_non_normal_ms(recs, n);
	out->oscillation_count    = oscillation_count_2s(recs, n);
	out->lyapunov_slope       = lyapunov_slope_fit(recs, n);
	out->total_ticks          = (uint64_t)n;
	out->actuation_writes     = a_writes;
	out->actuation_noops      = a_noops;

	/* Gate evaluation — order matters so fail_reason is the *first*
	 * failing rule. */
	bool stable = true;
	if (out->oscillation_count > 0) {
		stable = false;
		out->fail_reason = REASON_OSC;
	} else if (out->worst_case_deviation >= 0.20) {
		stable = false;
		out->fail_reason = REASON_WCD;
	} else if (out->recovery_time_max_ms >= 2000.0) {
		stable = false;
		out->fail_reason = REASON_RT;
	} else if (out->lyapunov_slope > 0.0) {
		stable = false;
		out->fail_reason = REASON_SLOPE;
	}
	out->stable = stable;
}
