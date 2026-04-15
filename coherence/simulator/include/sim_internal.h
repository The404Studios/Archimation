/*
 * sim_internal.h — shared internal types for simulator subsystems.
 *
 * Private to the simulator binary. Not installed; not part of the
 * daemon's public API. The simulator is a *validation artifact* — it
 * re-implements the minimum subset of state_machine.c + derived.c
 * needed to replay traces in-process, so it remains self-contained
 * even when the daemon's .c files aren't available at link time.
 */
#ifndef COH_SIM_INTERNAL_H
#define COH_SIM_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "coherence_types.h"
#include "config.h"
#include "trace.h"
#include "noise.h"

/* ===== Recorded per-tick simulator output ===== */
typedef struct {
	uint64_t    t_ms;
	coh_state_t state;

	/* D(t) — subset of coh_derived_t we care about for reports. */
	double      d_latency_pressure;
	double      d_thermal;
	double      d_sched_instability;
	double      d_io_pressure;
	double      lyapunov_v;
	bool        d_valid;

	/* A(t) — condensed. Full struct recorded for barrier auditing. */
	coh_actuation_t a;
	bool        a_wrote;           /* true when actuation_commit actually wrote */

	/* Did the state change at this tick? */
	bool        state_changed;
} sim_tick_record_t;

/* ===== Stability result ===== */
typedef struct {
	double   mean_v;
	double   max_v;
	double   worst_case_deviation;   /* = max over time of D_latency_pressure */
	uint32_t oscillation_count;
	uint32_t state_counts[COH_STATE_COUNT];
	double   recovery_time_max_ms;
	double   lyapunov_slope;         /* linear fit dV/dt, units /ms */
	bool     stable;
	const char *fail_reason;

	/* Extra telemetry surfaced to reports. */
	uint64_t total_ticks;
	uint64_t actuation_writes;
	uint64_t actuation_noops;
} sim_stability_t;

/* ===== Simulator harness ===== */
typedef struct {
	const sim_trace_frame_t *frames;
	size_t                   frame_count;

	coh_config_t             cfg;
	sim_noise_cfg_t          noise;

	/* Output stream — caller supplies a buffer. */
	sim_tick_record_t       *out;
	size_t                   out_capacity;
	size_t                   out_count;
} sim_ctx_t;

/* Run a simulator pass over ctx->frames. Fills ctx->out with records
 * per CONTROL_FRAME boundary (one record per 100 ms). Returns 0 on
 * success, -1 on capacity overflow. */
int sim_run(sim_ctx_t *ctx);

/* ===== Stability analysis ===== */
void stability_compute(const sim_tick_record_t *recs,
                       size_t n,
                       sim_stability_t *out);

/* ===== Parameter sweep ===== */
typedef struct {
	double theta_latency_enter_min, theta_latency_enter_max, theta_latency_enter_step;
	double theta_thermal_enter_min, theta_thermal_enter_max, theta_thermal_enter_step;
	uint32_t tau_hold_min, tau_hold_max, tau_hold_step;

	const char *trace_path;        /* required; if NULL, caller supplies frames[] */
	const char *csv_out_path;      /* where to emit the sweep grid */
	uint64_t    noise_seed;
} sweep_cfg_t;

typedef struct {
	double theta_latency_enter;
	double theta_thermal_enter;
	uint32_t tau_hold_ms;
	sim_stability_t stab;
} sweep_row_t;

/* Run the full sweep. Returns -1 on error, else number of rows emitted.
 * If rows_out != NULL, *rows_out receives a heap-allocated array and
 * *rows_n its length; caller owns the buffer.
 */
int sweep_run(const sweep_cfg_t *cfg,
              sweep_row_t **rows_out,
              size_t *rows_n);

/* ===== Report emitter ===== */
typedef struct {
	const char *out_path;          /* markdown path */

	/* Per-trace inputs. */
	struct {
		const char *name;
		const char *path;
		const sim_stability_t *stab;
		const sim_tick_record_t *recs;
		size_t recs_n;
	} traces[8];
	size_t trace_count;

	/* Sweep data. */
	const sweep_row_t *sweep_rows;
	size_t             sweep_row_count;

	/* Provenance */
	uint64_t seed;
	const char *commit;
	const char *default_label;

	double default_theta_latency_enter;
	double default_theta_thermal_enter;
	uint32_t default_tau_hold_ms;
} report_cfg_t;

int report_emit(const report_cfg_t *rc);

/* ===== Synthetic trace helpers (used by simulator main if .bin absent) ===== */
int sim_ensure_trace(const char *path,
                     int (*gen)(sim_trace_frame_t **, size_t *, uint64_t),
                     uint64_t seed);

#endif /* COH_SIM_INTERNAL_H */
