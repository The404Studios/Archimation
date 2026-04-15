/*
 * sweep.c — Parameter sweep engine for the offline stability simulator.
 *
 * Iterates over (θ_latency_enter, θ_thermal_enter, τ_hold) and, for
 * each grid point, runs the simulator on the configured trace, then
 * writes a CSV row + accumulates a row into the in-memory array the
 * report emitter consumes.
 *
 * The CSV schema is:
 *   theta_latency_enter,theta_thermal_enter,tau_hold_ms,
 *   oscillation_count,worst_case_deviation,recovery_time_max_ms,
 *   lyapunov_slope,mean_v,max_v,stable,fail_reason
 *
 * Determinism: every row uses the same seed for noise, so flipping
 * one cfg knob changes only what that knob changes.
 *
 * Cost model: steady-trace is 6000 frames. A full sweep is
 *   7 (θL) × 5 (θT) × 8 (τ)    = 280 runs × 6000 frames = 1.68M ticks.
 * On a modern desktop this is ~0.5-2 seconds, well within CI budget.
 */

#define _POSIX_C_SOURCE 200809L

#include "sim_internal.h"
#include "trace.h"
#include "noise.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int write_csv_header(FILE *fp)
{
	return fprintf(fp,
	    "theta_latency_enter,theta_thermal_enter,tau_hold_ms,"
	    "oscillation_count,worst_case_deviation,recovery_time_max_ms,"
	    "lyapunov_slope,mean_v,max_v,stable,fail_reason\n") < 0 ? -1 : 0;
}

static int write_csv_row(FILE *fp, const sweep_row_t *r)
{
	return fprintf(fp,
	    "%.3f,%.3f,%u,%u,%.6f,%.3f,%.9f,%.6f,%.6f,%s,%s\n",
	    r->theta_latency_enter,
	    r->theta_thermal_enter,
	    r->tau_hold_ms,
	    r->stab.oscillation_count,
	    r->stab.worst_case_deviation,
	    r->stab.recovery_time_max_ms,
	    r->stab.lyapunov_slope,
	    r->stab.mean_v,
	    r->stab.max_v,
	    r->stab.stable ? "true" : "false",
	    r->stab.fail_reason ? r->stab.fail_reason : "") < 0 ? -1 : 0;
}

/*
 * Count the number of integer steps from min to max inclusive with
 * the given positive step. Negative/zero step returns 1 so the sweep
 * still runs a single point at `min`.
 */
static size_t count_steps_d(double min, double max, double step)
{
	if (step <= 1e-12) return 1;
	if (max < min)     return 1;
	size_t n = 0;
	for (double v = min; v <= max + step * 0.5; v += step) n++;
	return n > 0 ? n : 1;
}

static size_t count_steps_u(uint32_t min, uint32_t max, uint32_t step)
{
	if (step == 0) return 1;
	if (max < min) return 1;
	return (size_t)((max - min) / step) + 1;
}

int sweep_run(const sweep_cfg_t *cfg,
              sweep_row_t **rows_out,
              size_t *rows_n)
{
	if (!cfg || !cfg->trace_path) return -1;

	sim_trace_frame_t *frames = NULL;
	size_t n_frames = 0;
	if (trace_load(cfg->trace_path, &frames, &n_frames) != 0) {
		fprintf(stderr, "sweep: cannot load trace %s\n", cfg->trace_path);
		return -1;
	}

	FILE *fp = NULL;
	if (cfg->csv_out_path && cfg->csv_out_path[0]) {
		fp = fopen(cfg->csv_out_path, "w");
		if (!fp) {
			fprintf(stderr, "sweep: cannot write %s: %s\n",
			        cfg->csv_out_path, strerror(errno));
			free(frames);
			return -1;
		}
		write_csv_header(fp);
	}

	size_t n_l = count_steps_d(cfg->theta_latency_enter_min,
	                           cfg->theta_latency_enter_max,
	                           cfg->theta_latency_enter_step);
	size_t n_t = count_steps_d(cfg->theta_thermal_enter_min,
	                           cfg->theta_thermal_enter_max,
	                           cfg->theta_thermal_enter_step);
	size_t n_h = count_steps_u(cfg->tau_hold_min,
	                           cfg->tau_hold_max,
	                           cfg->tau_hold_step);

	size_t total = n_l * n_t * n_h;
	sweep_row_t *rows = calloc(total, sizeof(*rows));
	if (!rows) {
		if (fp) fclose(fp);
		free(frames);
		return -1;
	}

	/* Shared record buffer — reuse across rows to avoid churn. */
	sim_tick_record_t *recs = calloc(n_frames, sizeof(*recs));
	if (!recs) {
		free(rows);
		if (fp) fclose(fp);
		free(frames);
		return -1;
	}

	size_t ri = 0;
	for (size_t il = 0; il < n_l; il++) {
		double theta_l = cfg->theta_latency_enter_min
		               + (double)il * cfg->theta_latency_enter_step;
		for (size_t it = 0; it < n_t; it++) {
			double theta_t = cfg->theta_thermal_enter_min
			               + (double)it * cfg->theta_thermal_enter_step;
			for (size_t ih = 0; ih < n_h; ih++) {
				uint32_t tau_h = cfg->tau_hold_min
				               + (uint32_t)ih * cfg->tau_hold_step;

				coh_config_t c;
				coh_config_defaults(&c);
				c.theta_latency_enter = theta_l;
				c.theta_thermal_enter = theta_t;
				c.tau_hold_ms         = tau_h;
				/* Keep exit thresholds consistent with enter so the
				 * hysteresis gap stays sensible across the sweep. */
				c.theta_latency_exit = theta_l - 0.35;
				if (c.theta_latency_exit < 0.10) c.theta_latency_exit = 0.10;
				c.theta_thermal_exit = theta_t - 0.15;
				if (c.theta_thermal_exit < 0.10) c.theta_thermal_exit = 0.10;
				/* Lockout proportional to hold so validator accepts. */
				c.transition_lockout_ms = tau_h * 2u;

				sim_noise_cfg_t noise;
				noise_cfg_defaults(&noise, cfg->noise_seed);

				sim_ctx_t ctx;
				memset(&ctx, 0, sizeof(ctx));
				ctx.frames       = frames;
				ctx.frame_count  = n_frames;
				ctx.cfg          = c;
				ctx.noise        = noise;
				ctx.out          = recs;
				ctx.out_capacity = n_frames;

				if (sim_run(&ctx) != 0) {
					/* Record a stub row so the grid stays rectangular. */
					rows[ri].theta_latency_enter = theta_l;
					rows[ri].theta_thermal_enter = theta_t;
					rows[ri].tau_hold_ms = tau_h;
					rows[ri].stab.stable = false;
					rows[ri].stab.fail_reason = "sim_run_failed";
					if (fp) write_csv_row(fp, &rows[ri]);
					ri++;
					continue;
				}

				sim_stability_t s;
				stability_compute(recs, ctx.out_count, &s);

				rows[ri].theta_latency_enter = theta_l;
				rows[ri].theta_thermal_enter = theta_t;
				rows[ri].tau_hold_ms = tau_h;
				rows[ri].stab = s;
				if (fp) write_csv_row(fp, &rows[ri]);
				ri++;
			}
		}
	}

	if (fp) fclose(fp);
	free(recs);
	free(frames);

	if (rows_out) *rows_out = rows;
	else free(rows);
	if (rows_n)   *rows_n = ri;

	return (int)ri;
}
