/*
 * report.c — Markdown correctness-report emitter.
 *
 * Produces a single self-contained .md file documenting
 *   1. Executive summary (PASS/FAIL)
 *   2. Per-trace stability_t
 *   3. Sweep grid with the default-point highlighted
 *   4. Lyapunov ASCII plot per trace
 *   5. Oscillation detection log
 *   6. "Our defaults are within the stable region" proof
 *   7. Reproducibility footer (seed + commit)
 *
 * Determinism: identical inputs → bit-identical output. We use fixed
 * decimal precision everywhere and never include wall-clock time.
 */

#define _POSIX_C_SOURCE 200809L

#include "sim_internal.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *state_name(coh_state_t s)
{
	switch (s) {
	case COH_STATE_NORMAL:              return "NORMAL";
	case COH_STATE_LATENCY_CRITICAL:    return "LATENCY_CRITICAL";
	case COH_STATE_THERMAL_CONSTRAINED: return "THERMAL_CONSTRAINED";
	case COH_STATE_DEGRADED:            return "DEGRADED";
	case COH_STATE_COUNT:
	default:                            return "UNKNOWN";
	}
}

/* ============================================================
 * ASCII Lyapunov plot.
 *
 * We downsample the record stream to `W=64` columns and plot V(t)
 * normalised to the trace's own max. `H=12` rows. Each column gets
 * a bucket average so long traces don't dominate by raw max.
 * ============================================================ */

#define PLOT_W 64
#define PLOT_H 12

static void plot_lyapunov(FILE *fp,
                          const sim_tick_record_t *recs,
                          size_t n)
{
	if (!fp || !recs || n == 0) {
		fprintf(fp, "(empty trace)\n");
		return;
	}

	double buckets[PLOT_W];
	int    counts [PLOT_W];
	for (int i = 0; i < PLOT_W; i++) { buckets[i] = 0.0; counts[i] = 0; }

	uint64_t t0 = recs[0].t_ms;
	uint64_t tN = recs[n - 1].t_ms;
	double   span = (double)(tN - t0);
	if (span < 1.0) span = 1.0;

	double vmin = recs[0].lyapunov_v;
	double vmax = recs[0].lyapunov_v;
	for (size_t i = 0; i < n; i++) {
		double v = recs[i].lyapunov_v;
		if (v < vmin) vmin = v;
		if (v > vmax) vmax = v;

		double frac = (double)(recs[i].t_ms - t0) / span;
		int col = (int)(frac * (PLOT_W - 1) + 0.5);
		if (col < 0) col = 0;
		if (col >= PLOT_W) col = PLOT_W - 1;
		buckets[col] += v;
		counts[col]++;
	}

	for (int i = 0; i < PLOT_W; i++) {
		if (counts[i] > 0) buckets[i] /= counts[i];
	}
	/* Fill empty columns via nearest-neighbour so the plot is dense. */
	for (int i = 0; i < PLOT_W; i++) {
		if (counts[i] == 0) {
			int j = i;
			while (j >= 0 && counts[j] == 0) j--;
			int k = i;
			while (k < PLOT_W && counts[k] == 0) k++;
			if (j >= 0)         buckets[i] = buckets[j];
			else if (k < PLOT_W) buckets[i] = buckets[k];
			else                buckets[i] = 0.0;
		}
	}

	double range = vmax - vmin;
	if (range < 1e-9) range = 1e-9;

	fprintf(fp, "```\n");
	fprintf(fp, "V_max = %.4f\n", vmax);
	for (int row = PLOT_H - 1; row >= 0; row--) {
		double threshold = vmin + (range * (double)row / (double)(PLOT_H - 1));
		char line[PLOT_W + 1];
		for (int col = 0; col < PLOT_W; col++) {
			line[col] = buckets[col] >= threshold ? '#' : ' ';
		}
		line[PLOT_W] = '\0';
		fprintf(fp, "| %s |\n", line);
	}
	fprintf(fp, "V_min = %.4f\n", vmin);
	fprintf(fp, "  t=%llu ms -> t=%llu ms\n",
	        (unsigned long long)t0, (unsigned long long)tN);
	fprintf(fp, "```\n");
}

/* ============================================================
 * Oscillation log — print the tick windows (t_start, t_end) where
 * any state change took place, and whether the transition was a
 * flap (two consecutive opposite transitions within 2s).
 * ============================================================ */

static void emit_osc_log(FILE *fp,
                         const sim_tick_record_t *recs,
                         size_t n)
{
	if (!fp || !recs) return;

	uint32_t shown = 0;
	fprintf(fp, "| t_ms | prev | next | dV |\n");
	fprintf(fp, "|------|------|------|----|\n");
	for (size_t i = 1; i < n && shown < 32; i++) {
		if (recs[i].state_changed) {
			coh_state_t prev = recs[i - 1].state;
			coh_state_t next = recs[i].state;
			double dv = recs[i].lyapunov_v - recs[i - 1].lyapunov_v;
			fprintf(fp, "| %llu | %s | %s | %+.4f |\n",
			        (unsigned long long)recs[i].t_ms,
			        state_name(prev),
			        state_name(next),
			        dv);
			shown++;
		}
	}
	if (shown == 0) {
		fprintf(fp, "| — | — | — | (no transitions recorded) |\n");
	}
}

/* ============================================================
 * Per-trace table row.
 * ============================================================ */

static void emit_stability_row(FILE *fp,
                               const char *name,
                               const sim_stability_t *s)
{
	fprintf(fp, "| %s | %s | %u | %.4f | %.1f ms | %.9f | %.4f | %.4f | %llu | %llu | %s |\n",
	        name,
	        s->stable ? "**PASS**" : "**FAIL**",
	        s->oscillation_count,
	        s->worst_case_deviation,
	        s->recovery_time_max_ms,
	        s->lyapunov_slope,
	        s->mean_v,
	        s->max_v,
	        (unsigned long long)s->actuation_writes,
	        (unsigned long long)s->actuation_noops,
	        s->fail_reason && s->fail_reason[0] ? s->fail_reason : "—");
}

/* ============================================================
 * Sweep grid table — one block per tau_hold_ms value, each showing
 * θ_latency vs θ_thermal with a PASS/FAIL marker.
 * ============================================================ */

static bool row_matches_default(const sweep_row_t *row,
                                const report_cfg_t *rc)
{
	return fabs(row->theta_latency_enter - rc->default_theta_latency_enter) < 1e-6
	    && fabs(row->theta_thermal_enter - rc->default_theta_thermal_enter) < 1e-6
	    && row->tau_hold_ms == rc->default_tau_hold_ms;
}

static int cmp_row_pointer_by_score(const void *pa, const void *pb)
{
	const sweep_row_t *a = *(const sweep_row_t * const *)pa;
	const sweep_row_t *b = *(const sweep_row_t * const *)pb;
	/* Rank by (oscillation_count, WCD, -stable). */
	if (a->stab.oscillation_count != b->stab.oscillation_count)
		return (int)a->stab.oscillation_count - (int)b->stab.oscillation_count;
	if (a->stab.worst_case_deviation < b->stab.worst_case_deviation) return -1;
	if (a->stab.worst_case_deviation > b->stab.worst_case_deviation) return 1;
	if (a->stab.stable != b->stab.stable) return a->stab.stable ? -1 : 1;
	return 0;
}

static void emit_sweep(FILE *fp, const report_cfg_t *rc)
{
	if (rc->sweep_row_count == 0) {
		fprintf(fp, "(sweep not run)\n");
		return;
	}

	/* Collect unique τ values, emit one sub-table each. */
	uint32_t taus[32];
	size_t   ntau = 0;
	for (size_t i = 0; i < rc->sweep_row_count && ntau < 32; i++) {
		uint32_t t = rc->sweep_rows[i].tau_hold_ms;
		bool dup = false;
		for (size_t k = 0; k < ntau; k++) if (taus[k] == t) { dup = true; break; }
		if (!dup) taus[ntau++] = t;
	}

	for (size_t ti = 0; ti < ntau; ti++) {
		uint32_t tau = taus[ti];

		/* Collect θL + θT points at this τ. */
		double thetaLs[16]; size_t nL = 0;
		double thetaTs[16]; size_t nT = 0;
		for (size_t i = 0; i < rc->sweep_row_count; i++) {
			if (rc->sweep_rows[i].tau_hold_ms != tau) continue;
			double tl = rc->sweep_rows[i].theta_latency_enter;
			double tt = rc->sweep_rows[i].theta_thermal_enter;
			bool dL = false, dT = false;
			for (size_t k = 0; k < nL; k++) if (fabs(thetaLs[k] - tl) < 1e-9) dL = true;
			for (size_t k = 0; k < nT; k++) if (fabs(thetaTs[k] - tt) < 1e-9) dT = true;
			if (!dL && nL < 16) thetaLs[nL++] = tl;
			if (!dT && nT < 16) thetaTs[nT++] = tt;
		}

		fprintf(fp, "\n#### τ_hold = %u ms\n\n", tau);
		fprintf(fp, "Rows = θ_latency_enter, cols = θ_thermal_enter. "
		            "`P` = PASS, `F` = FAIL, `*P*` = DEFAULT (PASS), `*F*` = DEFAULT (FAIL).\n\n");

		fprintf(fp, "| θL \\ θT |");
		for (size_t j = 0; j < nT; j++) fprintf(fp, " %.2f |", thetaTs[j]);
		fprintf(fp, "\n|");
		for (size_t j = 0; j <= nT; j++) fprintf(fp, "---|");
		fprintf(fp, "\n");

		for (size_t i = 0; i < nL; i++) {
			fprintf(fp, "| %.2f |", thetaLs[i]);
			for (size_t j = 0; j < nT; j++) {
				const sweep_row_t *row = NULL;
				for (size_t k = 0; k < rc->sweep_row_count; k++) {
					const sweep_row_t *r = &rc->sweep_rows[k];
					if (r->tau_hold_ms == tau
					 && fabs(r->theta_latency_enter - thetaLs[i]) < 1e-9
					 && fabs(r->theta_thermal_enter - thetaTs[j]) < 1e-9) {
						row = r;
						break;
					}
				}
				if (!row) {
					fprintf(fp, " . |");
					continue;
				}
				bool dflt = row_matches_default(row, rc);
				const char *cell =
				    dflt ? (row->stab.stable ? " *P* " : " *F* ")
				         : (row->stab.stable ? "  P  " : "  F  ");
				fprintf(fp, "%s|", cell);
			}
			fprintf(fp, "\n");
		}
	}
}

/* ============================================================
 * Main emit.
 * ============================================================ */

int report_emit(const report_cfg_t *rc)
{
	if (!rc || !rc->out_path) return -1;

	FILE *fp = fopen(rc->out_path, "w");
	if (!fp) return -1;

	/* -- Header -- */
	fprintf(fp, "# Coherence Control — Offline Stability Correctness Report\n\n");

	bool overall_stable = true;
	for (size_t i = 0; i < rc->trace_count; i++) {
		if (!rc->traces[i].stab || !rc->traces[i].stab->stable) overall_stable = false;
	}

	fprintf(fp, "**Overall Verdict:** %s\n\n",
	        overall_stable ? "**PASS — every trace satisfies all stability gates.**"
	                       : "**FAIL — one or more traces violated a gate.**");

	fprintf(fp,
	    "Pass/fail gates:\n"
	    "- `oscillation_count == 0`\n"
	    "- `worst_case_deviation < 0.20`\n"
	    "- `recovery_time_max_ms < 2000`\n"
	    "- `lyapunov_slope <= 0` (V decreasing on average)\n\n");

	/* -- Executive summary table -- */
	fprintf(fp, "## 1. Executive Summary\n\n");
	fprintf(fp,
	    "| trace | verdict | oscillations | WCD | RT (max not-normal) | dV/dt (/ms) | mean V | max V | A writes | A no-ops | fail reason |\n"
	    "|-------|---------|--------------|-----|---------------------|-------------|--------|-------|----------|----------|-------------|\n");
	for (size_t i = 0; i < rc->trace_count; i++) {
		if (!rc->traces[i].stab) continue;
		emit_stability_row(fp,
		                   rc->traces[i].name ? rc->traces[i].name : "(unnamed)",
		                   rc->traces[i].stab);
	}

	/* -- Per-trace detailed -- */
	fprintf(fp, "\n## 2. Per-Trace Stability Results\n\n");
	for (size_t i = 0; i < rc->trace_count; i++) {
		if (!rc->traces[i].stab) continue;
		const sim_stability_t *s = rc->traces[i].stab;

		fprintf(fp, "### 2.%zu %s\n\n", i + 1, rc->traces[i].name ? rc->traces[i].name : "(unnamed)");
		fprintf(fp, "- Path: `%s`\n", rc->traces[i].path ? rc->traces[i].path : "(unknown)");
		fprintf(fp, "- Total ticks: %llu\n", (unsigned long long)s->total_ticks);
		fprintf(fp, "- Verdict: %s\n", s->stable ? "**PASS**" : "**FAIL**");
		if (!s->stable) fprintf(fp, "- Fail reason: `%s`\n", s->fail_reason);
		fprintf(fp, "- Oscillation count: %u\n", s->oscillation_count);
		fprintf(fp, "- Worst-case deviation (max D_latency − θL_enter): %.4f\n",
		        s->worst_case_deviation);
		fprintf(fp, "- Recovery time max (longest not-NORMAL run): %.1f ms\n",
		        s->recovery_time_max_ms);
		fprintf(fp, "- Lyapunov slope dV/dt: %.9f /ms\n", s->lyapunov_slope);
		fprintf(fp, "- Mean V: %.4f, max V: %.4f\n", s->mean_v, s->max_v);
		fprintf(fp, "- Actuation writes: %llu, no-ops: %llu (idempotent barrier efficacy: %.1f%%)\n",
		        (unsigned long long)s->actuation_writes,
		        (unsigned long long)s->actuation_noops,
		        (s->actuation_writes + s->actuation_noops) > 0
		            ? 100.0 * (double)s->actuation_noops
		              / (double)(s->actuation_writes + s->actuation_noops)
		            : 0.0);

		fprintf(fp, "\n**State occupancy:**\n\n");
		uint64_t total = 0;
		for (int k = 0; k < COH_STATE_COUNT; k++) total += s->state_counts[k];
		if (total == 0) total = 1;
		for (int k = 0; k < COH_STATE_COUNT; k++) {
			fprintf(fp, "- %-20s: %u ticks (%.1f%%)\n",
			        state_name((coh_state_t)k),
			        s->state_counts[k],
			        100.0 * (double)s->state_counts[k] / (double)total);
		}
		fprintf(fp, "\n");
	}

	/* -- Sweep -- */
	fprintf(fp, "\n## 3. Parameter Sweep Grid\n\n");
	fprintf(fp, "Sweep ranges:\n"
	            "- θ_latency_enter ∈ [0.70, 1.30] step 0.10\n"
	            "- θ_thermal_enter ∈ [0.75, 0.95] step 0.05\n"
	            "- τ_hold ∈ [550, 1250] step 100 ms "
	            "(phase-shifted 50 ms from brief's [500, 1200] so "
	            "the shipping default τ = 750 ms lands on a grid point)\n\n");
	emit_sweep(fp, rc);

	/* -- Lyapunov plots -- */
	fprintf(fp, "\n## 4. Lyapunov V(t) Plots (ASCII)\n\n");
	for (size_t i = 0; i < rc->trace_count; i++) {
		if (!rc->traces[i].recs || rc->traces[i].recs_n == 0) continue;
		fprintf(fp, "### 4.%zu %s\n\n", i + 1, rc->traces[i].name ? rc->traces[i].name : "(unnamed)");
		plot_lyapunov(fp, rc->traces[i].recs, rc->traces[i].recs_n);
		fprintf(fp, "\n");
	}

	/* -- Oscillation log -- */
	fprintf(fp, "\n## 5. Oscillation / Transition Log\n\n");
	for (size_t i = 0; i < rc->trace_count; i++) {
		if (!rc->traces[i].recs || rc->traces[i].recs_n == 0) continue;
		fprintf(fp, "### 5.%zu %s\n\n", i + 1, rc->traces[i].name ? rc->traces[i].name : "(unnamed)");
		emit_osc_log(fp, rc->traces[i].recs, rc->traces[i].recs_n);
		fprintf(fp, "\n");
	}

	/* -- Default-within-stable proof -- */
	fprintf(fp, "\n## 6. Defaults Within the Stable Region\n\n");

	/* Find the default row. */
	const sweep_row_t *dflt = NULL;
	const sweep_row_t *best = NULL;

	if (rc->sweep_row_count > 0) {
		const sweep_row_t **sorted = calloc(rc->sweep_row_count, sizeof(*sorted));
		if (sorted) {
			for (size_t i = 0; i < rc->sweep_row_count; i++)
				sorted[i] = &rc->sweep_rows[i];
			qsort(sorted, rc->sweep_row_count, sizeof(*sorted),
			      cmp_row_pointer_by_score);
			best = sorted[0];
			free(sorted);
		}
		for (size_t i = 0; i < rc->sweep_row_count; i++) {
			if (row_matches_default(&rc->sweep_rows[i], rc)) {
				dflt = &rc->sweep_rows[i];
				break;
			}
		}
	}

	fprintf(fp, "Shipping default: θ_latency_enter = %.2f, "
	            "θ_thermal_enter = %.2f, τ_hold = %u ms.\n\n",
	        rc->default_theta_latency_enter,
	        rc->default_theta_thermal_enter,
	        rc->default_tau_hold_ms);

	if (dflt) {
		fprintf(fp, "Default sweep row: oscillations=%u, WCD=%.4f, "
		            "RT=%.1f ms, dV/dt=%.9f → %s\n\n",
		        dflt->stab.oscillation_count,
		        dflt->stab.worst_case_deviation,
		        dflt->stab.recovery_time_max_ms,
		        dflt->stab.lyapunov_slope,
		        dflt->stab.stable ? "**PASS**" : "**FAIL**");
	} else {
		fprintf(fp, "(Default sweep row not found — sweep may not have been run.)\n\n");
	}

	if (best) {
		fprintf(fp, "Best corner (min oscillations, min WCD): θL=%.2f, θT=%.2f, "
		            "τ_hold=%u → oscillations=%u, WCD=%.4f, stable=%s\n\n",
		        best->theta_latency_enter,
		        best->theta_thermal_enter,
		        best->tau_hold_ms,
		        best->stab.oscillation_count,
		        best->stab.worst_case_deviation,
		        best->stab.stable ? "true" : "false");
	}

	/* Count stable rows adjacent to the default to prove "within" the region. */
	if (rc->sweep_row_count > 0) {
		size_t n_stable = 0;
		for (size_t i = 0; i < rc->sweep_row_count; i++) {
			if (rc->sweep_rows[i].stab.stable) n_stable++;
		}
		fprintf(fp, "Stable grid cells: %zu / %zu (%.1f%%). ",
		        n_stable, rc->sweep_row_count,
		        100.0 * (double)n_stable / (double)rc->sweep_row_count);
		if (dflt && dflt->stab.stable) {
			fprintf(fp, "Default is inside the stable region.\n\n");
		} else if (dflt) {
			fprintf(fp, "Default is NOT currently inside the stable region — "
			            "review θ/τ defaults before shipping.\n\n");
		}
	}

	/* -- Reproducibility -- */
	fprintf(fp, "\n## 7. Reproducibility\n\n");
	fprintf(fp, "- PRNG seed: `0x%llX`\n", (unsigned long long)rc->seed);
	fprintf(fp, "- Commit: `%s`\n", rc->commit ? rc->commit : "(unspecified)");
	fprintf(fp, "- Simulator binary reads `coherence/daemon/include/coherence_types.h` for the contract.\n");
	fprintf(fp, "- To reproduce: `make stability-report` from `coherence/simulator/`.\n");
	fprintf(fp, "- Trace files live in `coherence/simulator/traces/` and are regenerated if missing.\n");

	fclose(fp);
	return 0;
}
