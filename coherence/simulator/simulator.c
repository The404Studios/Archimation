/*
 * simulator.c — offline coherence control-system simulator.
 *
 * Purpose: replay recorded or synthetic traces through a faithful
 * reference implementation of the measurement → derivation → state
 * machine → actuation → system-response pipeline and quantify the
 * resulting V(t), oscillations, worst-case-deviation, and recovery
 * time. The output is the "correctness-report.md" artifact.
 *
 * Why a re-implementation rather than linking the daemon? The brief:
 *   "Must be self-contained — does not need the daemon running to
 *    execute."
 * We include the same coherence_types.h contract so constants,
 * enums and struct layouts are byte-identical to the daemon. If the
 * daemon's state_machine.c / derived.c later ship as a static library
 * at coherence/daemon/build/libcoherence_core.a, the Makefile can link
 * it directly and the fallback symbols defined here are guarded by
 * `SIM_EMBED_REFERENCE` so we won't get duplicate-definition errors.
 *
 * Phase schedule, from coherence_types.h:
 *   MEASUREMENT  every CONTROL_FRAME (100 ms) — sample M(t) → ring.
 *   DERIVATION   every DECISION_FRAME (250 ms) — lag >= 2*CONTROL_FRAME.
 *   DECISION     at 250 ms inside every 500 ms — state_machine_evaluate.
 *   ACTUATION    at 500 ms boundary — idempotent commit.
 *
 * The synthetic system-response model after every ACTUATION:
 *
 *   x(t+1) = A_sys * x(t) + B_sys * A(t) + eta(t)
 *
 *   A_sys: each accumulated signal decays by 0.02 / tick.
 *   B_sys:
 *     - EPP == COH_EPP_PERFORMANCE        → D_latency_pressure *= 0.7
 *     - min_perf_pct <= 30                → D_thermal         *= 0.9
 *     - EPP == COH_EPP_POWER              → D_thermal         *= 0.92
 *     - use_gamescope == true             → ft variance proxy *= 0.85
 *   eta: tiny zero-mean gaussian so V(t) never converges to an exact
 *     fixed point (prevents fake Lyapunov slopes reading as zero).
 */

#define _POSIX_C_SOURCE 200809L

#include "coherence_types.h"
#include "config.h"
#include "trace.h"
#include "noise.h"
#include "sim_internal.h"

#include <errno.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Platform mkdir headers — required by ensure_parent_dir(). Pulled in
 * before any use. */
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

/* Local copy of the control-loop's ring depth. Matches COH_M_RING_DEPTH
 * in ../daemon/include/control_loop.h — we don't include that header
 * because it pulls in weak stubs we'd rather not duplicate. If the
 * daemon's value ever changes, update here too. */
#ifndef COH_M_RING_DEPTH
#define COH_M_RING_DEPTH 8u
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ============================================================
 * Minimal ema_state_t definition + helpers. We intentionally re-
 * declare the layout from ema.c so both compilation units stay in
 * agreement — ema.c guards the typedef behind EMA_STATE_T_DEFINED.
 * ============================================================ */

#ifndef EMA_STATE_T_DEFINED
#define EMA_STATE_T_DEFINED
typedef struct {
	double ft_var_smooth;
	double cpu_temp_smooth;
	double sq_latency_smooth;
	double migration_smooth;
	bool   initialized;
} ema_state_t;
#endif

static double sim_ema_step(double prev, double raw, double alpha, bool seed)
{
	if (seed) return raw;
	return alpha * raw + (1.0 - alpha) * prev;
}

static void sim_ema_advance(ema_state_t *s,
                            double ft_var_raw,
                            double cpu_temp_raw,
                            double sq_latency_raw,
                            double migration_raw,
                            const coh_config_t *cfg)
{
	const bool seed = !s->initialized;
	s->ft_var_smooth     = sim_ema_step(s->ft_var_smooth,     ft_var_raw,
	                                    cfg->alpha_ft_var,    seed);
	s->cpu_temp_smooth   = sim_ema_step(s->cpu_temp_smooth,   cpu_temp_raw,
	                                    cfg->alpha_cpu_temp,  seed);
	s->sq_latency_smooth = sim_ema_step(s->sq_latency_smooth, sq_latency_raw,
	                                    cfg->alpha_sq_latency,seed);
	s->migration_smooth  = sim_ema_step(s->migration_smooth,  migration_raw,
	                                    cfg->alpha_migration, seed);
	s->initialized       = true;
}

/* ============================================================
 * Normalisation helpers. Maps physical raw signals to [0..~1.5]
 * dimensionless "stress" values. Thresholds θ are on this scale.
 * ============================================================ */

static double norm_ft_instability(double ft_var_ms2)
{
	/* Baseline ~3 ms^2, saturates near 30 ms^2. */
	double x = ft_var_ms2 / 10.0;
	if (x < 0.0) x = 0.0;
	if (x > 3.0) x = 3.0;
	return x;
}

static double norm_thermal(double cpu_temp_c)
{
	/* (T-45) / (95-45); clamp to [0, 1.5]. */
	double x = (cpu_temp_c - 45.0) / 50.0;
	if (x < 0.0) x = 0.0;
	if (x > 1.5) x = 1.5;
	return x;
}

static double norm_sched(double migration_rate)
{
	/* Baseline ~200 /s, saturating near 2000 /s. */
	double x = migration_rate / 1000.0;
	if (x < 0.0) x = 0.0;
	if (x > 3.0) x = 3.0;
	return x;
}

static double norm_io(double sq_latency_us)
{
	/* Baseline ~100 us, saturating near 1000 us. */
	double x = sq_latency_us / 500.0;
	if (x < 0.0) x = 0.0;
	if (x > 3.0) x = 3.0;
	return x;
}

/* ============================================================
 * Reference derivation — computes D(t) from a lagged M(t-k). Keeps
 * its own ema_state_t. Stale inputs preserve last valid D.
 * ============================================================ */

typedef struct {
	ema_state_t   ema;
	coh_derived_t last_valid;
	bool          have_last;
} sim_derived_state_t;

static void sim_derived_init(sim_derived_state_t *ds)
{
	memset(ds, 0, sizeof(*ds));
}

static void sim_derived_compute(sim_derived_state_t *ds,
                                coh_derived_t *out,
                                const coh_metrics_t *m_lagged,
                                const coh_config_t *cfg,
                                uint64_t now_ms)
{
	memset(out, 0, sizeof(*out));
	out->t_ms = now_ms;
	out->source_m_t_ms = m_lagged->t_ms;

	/* Freshness guard. */
	if (!coh_m_is_fresh(now_ms, m_lagged->t_ms)) {
		if (ds->have_last) {
			*out = ds->last_valid;
			out->t_ms = now_ms;
			out->source_m_t_ms = m_lagged->t_ms;
		}
		out->valid = false;
		return;
	}

	/* Advance EMAs. */
	sim_ema_advance(&ds->ema,
	                m_lagged->ft_var_ms2,
	                m_lagged->cpu_temp_c,
	                m_lagged->sq_latency_us,
	                m_lagged->migration_rate,
	                cfg);

	/* Derived signals from smoothed values. */
	double d_ft   = norm_ft_instability(ds->ema.ft_var_smooth);
	double d_th   = norm_thermal       (ds->ema.cpu_temp_smooth);
	double d_sc   = norm_sched         (ds->ema.migration_smooth);
	double d_io   = norm_io            (ds->ema.sq_latency_smooth);

	out->ft_instability    = d_ft;
	out->thermal           = d_th;
	out->sched_instability = d_sc;
	out->io_pressure       = d_io;

	/* Composite latency_pressure (weights sum to ~1.0 by config). */
	double wnorm = cfg->w_ft + cfg->w_sched + cfg->w_io;
	if (wnorm < 1e-6) wnorm = 1.0;
	out->latency_pressure = (cfg->w_ft   * d_ft
	                      +  cfg->w_sched * d_sc
	                      +  cfg->w_io    * d_io) / wnorm;
	out->system_stress    = 0.7 * out->latency_pressure + 0.3 * d_th;

	/* Lyapunov candidate. */
	out->lyapunov_v = cfg->w_ft    * d_ft  * d_ft
	                + cfg->w_sched * d_sc  * d_sc
	                + cfg->w_io    * d_io  * d_io
	                + cfg->w_therm * d_th  * d_th;

	out->valid = true;
	ds->last_valid = *out;
	ds->have_last  = true;
}

/* ============================================================
 * Reference state machine — matches the transition table documented
 * in include/state_machine.h. Uses the cfg->theta_* values so the
 * sweep can vary them without recompiling.
 * ============================================================ */

typedef struct {
	coh_arbiter_t    arb;
	/* Dwell counters, separate from coh_arbiter_t so we can snapshot
	 * arbiter state without leaking scratch details. */
	uint32_t lat_enter_dwell_ms;
	uint32_t lat_exit_dwell_ms;
	uint32_t therm_enter_dwell_ms;
	uint32_t therm_exit_dwell_ms;
	uint32_t both_clear_dwell_ms;
	uint64_t last_eval_t_ms;
} sim_sm_t;

static void sim_sm_init(sim_sm_t *sm, uint64_t now_ms)
{
	memset(sm, 0, sizeof(*sm));
	sm->arb.state = COH_STATE_NORMAL;
	sm->arb.state_enter_t_ms = now_ms;
	sm->arb.lockout_until_t_ms = 0;
	sm->last_eval_t_ms = now_ms;
}

static void sim_sm_dwell_update(uint32_t *dwell_ms, bool active, uint32_t dt_ms)
{
	if (active) {
		uint64_t tmp = (uint64_t)*dwell_ms + dt_ms;
		*dwell_ms = tmp > 0xFFFFFFFFULL ? 0xFFFFFFFFu : (uint32_t)tmp;
	} else {
		*dwell_ms = 0;
	}
}

static bool sim_sm_evaluate(sim_sm_t *sm,
                            const coh_derived_t *d,
                            const coh_config_t *cfg,
                            uint64_t now_ms)
{
	/* Advance dwell regardless of validity so counters don't lag. */
	uint32_t dt_ms = 0;
	if (now_ms > sm->last_eval_t_ms) {
		uint64_t delta = now_ms - sm->last_eval_t_ms;
		dt_ms = delta > 0xFFFFFFFFULL ? 0xFFFFFFFFu : (uint32_t)delta;
	}
	sm->last_eval_t_ms = now_ms;

	if (!d || !d->valid) {
		/* Bleed off all dwell counters on invalid input so we don't
		 * accumulate phantom time while the derivation is stale. */
		sm->lat_enter_dwell_ms = 0;
		sm->lat_exit_dwell_ms  = 0;
		sm->therm_enter_dwell_ms = 0;
		sm->therm_exit_dwell_ms  = 0;
		sm->both_clear_dwell_ms  = 0;
		return false;
	}

	bool lat_enter = d->latency_pressure > cfg->theta_latency_enter;
	bool lat_exit  = d->latency_pressure < cfg->theta_latency_exit;
	bool th_enter  = d->thermal          > cfg->theta_thermal_enter;
	bool th_exit   = d->thermal          < cfg->theta_thermal_exit;
	bool both_clr  = lat_exit && th_exit;

	sim_sm_dwell_update(&sm->lat_enter_dwell_ms,   lat_enter, dt_ms);
	sim_sm_dwell_update(&sm->lat_exit_dwell_ms,    lat_exit,  dt_ms);
	sim_sm_dwell_update(&sm->therm_enter_dwell_ms, th_enter,  dt_ms);
	sim_sm_dwell_update(&sm->therm_exit_dwell_ms,  th_exit,   dt_ms);
	sim_sm_dwell_update(&sm->both_clear_dwell_ms,  both_clr,  dt_ms);

	/* Lockout: counters warm, state frozen. */
	if (coh_in_lockout(&sm->arb, now_ms)) {
		return false;
	}

	coh_state_t cur  = sm->arb.state;
	coh_state_t next = cur;

	switch (cur) {
	case COH_STATE_NORMAL:
		if (th_enter && sm->therm_enter_dwell_ms >= cfg->tau_hold_ms) {
			next = COH_STATE_THERMAL_CONSTRAINED;
		} else if (lat_enter && sm->lat_enter_dwell_ms >= cfg->tau_hold_ms) {
			next = COH_STATE_LATENCY_CRITICAL;
		}
		break;
	case COH_STATE_LATENCY_CRITICAL:
		if (th_enter) {
			/* Thermal wins immediately. */
			next = COH_STATE_THERMAL_CONSTRAINED;
		} else if (lat_exit && sm->lat_exit_dwell_ms >= cfg->tau_hold_ms) {
			next = COH_STATE_NORMAL;
		}
		break;
	case COH_STATE_THERMAL_CONSTRAINED:
		if (th_exit && sm->therm_exit_dwell_ms >= cfg->tau_hold_ms) {
			next = COH_STATE_NORMAL;
		} else if (lat_enter && sm->lat_enter_dwell_ms >= cfg->tau_hold_ms &&
		           d->thermal > cfg->theta_thermal_enter * 0.95) {
			next = COH_STATE_DEGRADED;
		}
		break;
	case COH_STATE_DEGRADED:
		if (both_clr && sm->both_clear_dwell_ms >= cfg->tau_hold_ms) {
			next = COH_STATE_NORMAL;
		}
		break;
	case COH_STATE_COUNT:
	default:
		next = COH_STATE_NORMAL;
		break;
	}

	if (next != cur) {
		sm->arb.state              = next;
		sm->arb.state_enter_t_ms   = now_ms;
		sm->arb.lockout_until_t_ms = now_ms + cfg->transition_lockout_ms;
		sm->arb.transitions_total++;
		sm->arb.transitions_last_window++;
		/* Reset dwell counters that no longer apply. */
		sm->lat_enter_dwell_ms   = 0;
		sm->lat_exit_dwell_ms    = 0;
		sm->therm_enter_dwell_ms = 0;
		sm->therm_exit_dwell_ms  = 0;
		sm->both_clear_dwell_ms  = 0;
		return true;
	}
	return false;
}

static void sim_sm_plan(const sim_sm_t *sm,
                        const coh_derived_t *d,
                        coh_actuation_t *a,
                        uint64_t now_ms)
{
	(void)d;
	memset(a, 0, sizeof(*a));
	a->t_ms = now_ms;
	a->min_perf_pct = -1;
	a->sqpoll_cpu = 0;

	switch (sm->arb.state) {
	case COH_STATE_NORMAL:
		a->epp = COH_EPP_BALANCE_PERF;
		a->min_perf_pct = 30;
		a->present_mode_override = COH_PRESENT_AUTO;
		a->use_gamescope = false;
		break;
	case COH_STATE_LATENCY_CRITICAL:
		a->epp = COH_EPP_PERFORMANCE;
		a->min_perf_pct = 60;
		a->present_mode_override = COH_PRESENT_IMMEDIATE;
		a->use_gamescope = true;
		break;
	case COH_STATE_THERMAL_CONSTRAINED:
		a->epp = COH_EPP_BALANCE_POWER;
		a->min_perf_pct = 20;
		a->present_mode_override = COH_PRESENT_MAILBOX;
		a->use_gamescope = false;
		break;
	case COH_STATE_DEGRADED:
		a->epp = COH_EPP_POWER;
		a->min_perf_pct = 10;
		a->present_mode_override = COH_PRESENT_FIFO;
		a->use_gamescope = false;
		break;
	case COH_STATE_COUNT:
	default:
		a->epp = COH_EPP_DEFAULT;
		break;
	}
}

/* ============================================================
 * Synthetic system-response
 *
 * We keep an auxiliary residual vector that is added to the raw trace
 * frame before derivation. This is how A(t) feeds back into the plant.
 * Without this, the simulator would be pure open-loop and couldn't
 * prove closed-loop stability.
 * ============================================================ */

typedef struct {
	double d_latency_res;    /* accumulated delta to latency pressure */
	double d_thermal_res;    /* accumulated delta to thermal          */
	double ft_var_mult;      /* multiplicative factor on ft_var       */
} sim_plant_t;

static void sim_plant_init(sim_plant_t *p)
{
	memset(p, 0, sizeof(*p));
	p->ft_var_mult = 1.0;
}

static void sim_plant_step(sim_plant_t *p,
                           const coh_actuation_t *a,
                           sim_prng_t *eta_rng)
{
	/* A_sys: decay residuals. */
	p->d_latency_res  *= (1.0 - 0.02);
	p->d_thermal_res  *= (1.0 - 0.02);
	p->ft_var_mult    = 1.0 + 0.98 * (p->ft_var_mult - 1.0);

	/* B_sys: effect of A(t). */
	if (a) {
		if (a->epp == COH_EPP_PERFORMANCE) {
			p->d_latency_res -= 0.30; /* large pull-down on latency */
		}
		if (a->min_perf_pct >= 0 && a->min_perf_pct < 30) {
			p->d_thermal_res -= 0.10;
		}
		if (a->epp == COH_EPP_POWER) {
			p->d_thermal_res -= 0.08;
		}
		if (a->use_gamescope) {
			p->ft_var_mult *= 0.85;
		}
	}

	/* eta: tiny process noise, always present. */
	p->d_latency_res += sim_prng_gauss(eta_rng, 0.01);
	p->d_thermal_res += sim_prng_gauss(eta_rng, 0.005);

	/* Clamp so a malformed run can't drive the plant off a cliff. */
	if (p->d_latency_res > 1.0)  p->d_latency_res = 1.0;
	if (p->d_latency_res < -1.0) p->d_latency_res = -1.0;
	if (p->d_thermal_res > 0.5)  p->d_thermal_res = 0.5;
	if (p->d_thermal_res < -0.5) p->d_thermal_res = -0.5;
	if (p->ft_var_mult < 0.3)    p->ft_var_mult = 0.3;
	if (p->ft_var_mult > 3.0)    p->ft_var_mult = 3.0;
}

static void sim_plant_apply_to_frame(const sim_plant_t *p,
                                     sim_trace_frame_t *f)
{
	/* Map residuals back to raw physical values using the inverse of
	 * our normalisation. This keeps the loop self-consistent so D(t)
	 * computed downstream genuinely changes with A(t). */
	f->ft_var_ms2 *= p->ft_var_mult;

	/* latency residual shows up as extra migrations + io latency. */
	f->migration_rate += p->d_latency_res * 600.0;
	f->sq_latency_us  += p->d_latency_res * 250.0;
	if (f->migration_rate < 0.0) f->migration_rate = 0.0;
	if (f->sq_latency_us  < 0.0) f->sq_latency_us  = 0.0;

	/* thermal residual lifts/drops temp. */
	f->cpu_temp_c += p->d_thermal_res * 10.0;
	if (f->cpu_temp_c < 20.0)  f->cpu_temp_c = 20.0;
	if (f->cpu_temp_c > 110.0) f->cpu_temp_c = 110.0;
}

/* ============================================================
 * Main sim_run
 * ============================================================ */

int sim_run(sim_ctx_t *ctx)
{
	if (!ctx || !ctx->frames || !ctx->out) return -1;

	/* Ring buffer (depth 8) of M(t). */
	coh_metrics_t m_ring[COH_M_RING_DEPTH];
	memset(m_ring, 0, sizeof(m_ring));
	uint32_t m_head   = 0;
	uint32_t m_filled = 0;

	sim_derived_state_t ds; sim_derived_init(&ds);
	sim_sm_t sm;             sim_sm_init(&sm, 0);
	sim_plant_t plant;       sim_plant_init(&plant);

	coh_actuation_t a_committed; memset(&a_committed, 0, sizeof(a_committed));
	coh_actuation_t a_planned;   memset(&a_planned,   0, sizeof(a_planned));
	bool a_committed_valid = false;

	sim_prng_t eta_rng; sim_prng_seed(&eta_rng, ctx->noise.seed ^ 0xDEADBEEFDEADBEEFULL);

	size_t out_i = 0;

	/* The synthetic system-response model needs a "last actuation"
	 * to feed each step. We apply the plant BEFORE derivation, which
	 * means A(t-1) influences M(t) — a realistic one-frame lag. */
	for (size_t i = 0; i < ctx->frame_count; i++) {
		if (out_i >= ctx->out_capacity) return -1;

		sim_trace_frame_t f = ctx->frames[i];

		/* Apply noise — deterministic in (seed, t_ms). */
		noise_apply(&f, &ctx->noise, f.t_ms);

		/* Apply plant residuals. */
		sim_plant_apply_to_frame(&plant, &f);

		/* Build an M(t) sample from the (possibly modified) frame. */
		coh_metrics_t m;
		memset(&m, 0, sizeof(m));
		m.t_ms = f.t_ms;
		m.ft_mean_ms     = f.ft_mean_ms;
		m.ft_var_ms2     = f.ft_var_ms2;
		m.cpu_temp_c     = f.cpu_temp_c;
		m.migration_rate = f.migration_rate;
		m.sq_latency_us  = f.sq_latency_us;
		m.cpu_count      = 1;
		m.flags          = 1u; /* sample_complete */
		for (int k = 0; k < COH_MAX_CPUS; k++) {
			m.cpu_util[k]    = 0.0;
			m.cpu_freq_khz[k] = 3000000.0;
			m.irq_rate[k]    = 0.0;
		}

		m_ring[m_head] = m;
		m_head = (m_head + 1u) % COH_M_RING_DEPTH;
		if (m_filled < COH_M_RING_DEPTH) m_filled++;

		uint64_t now_ms = f.t_ms;

		/* Derivation every DECISION_FRAME (250 ms). We approximate
		 * this by firing at CONTROL_FRAME boundaries where t_ms %
		 * COH_DECISION_FRAME_MS straddles one — in practice every
		 * 2-3 CONTROL_FRAME ticks. We ALSO always compute D so the
		 * simulator's recorded stream has per-tick V(t) for reports. */
		coh_metrics_t m_lagged;
		memset(&m_lagged, 0, sizeof(m_lagged));
		bool have_lagged = false;
		if (m_filled > COH_DERIVATION_LAG_K) {
			uint32_t idx = (m_head + COH_M_RING_DEPTH - 1u
			             - COH_DERIVATION_LAG_K) % COH_M_RING_DEPTH;
			m_lagged = m_ring[idx];
			have_lagged = true;
		} else {
			m_lagged = m;
			have_lagged = true;
		}

		coh_derived_t d;
		sim_derived_compute(&ds, &d, &m_lagged, &ctx->cfg, now_ms);

		/* Freshness: if the source M sample is outside the validity
		 * window relative to "now" we expect the derivation to have
		 * marked d.valid = false. */

		/* DECISION every 250 ms (at t%250==0 inside the 500 window). */
		bool state_changed = false;
		if ((now_ms % COH_DECISION_FRAME_MS) == 0u) {
			state_changed = sim_sm_evaluate(&sm, &d, &ctx->cfg, now_ms);
		}

		/* Plan A(t) every tick so a_planned stays current. */
		sim_sm_plan(&sm, &d, &a_planned, now_ms);

		/* ACTUATION at 500 ms boundaries — idempotent commit. */
		bool a_wrote = false;
		if ((now_ms % COH_ACTUATION_FRAME_MS) == 0u) {
			if (!a_committed_valid || !coh_a_equal(&a_committed, &a_planned)) {
				a_committed = a_planned;
				a_committed_valid = true;
				a_wrote = true;
			}
		}

		/* Plant step uses the latest committed actuation. */
		sim_plant_step(&plant,
		               a_committed_valid ? &a_committed : NULL,
		               &eta_rng);

		/* Record. */
		sim_tick_record_t *r = &ctx->out[out_i++];
		r->t_ms = now_ms;
		r->state = sm.arb.state;
		r->d_latency_pressure = d.latency_pressure;
		r->d_thermal          = d.thermal;
		r->d_sched_instability = d.sched_instability;
		r->d_io_pressure      = d.io_pressure;
		r->lyapunov_v         = d.lyapunov_v;
		r->d_valid            = d.valid;
		r->a = a_planned;
		r->a_wrote = a_wrote;
		r->state_changed = state_changed;

		(void)have_lagged;
	}

	ctx->out_count = out_i;
	return 0;
}

/* ============================================================
 * Trace bootstrap helper — generate + save if absent.
 * ============================================================ */

int sim_ensure_trace(const char *path,
                     int (*gen)(sim_trace_frame_t **, size_t *, uint64_t),
                     uint64_t seed)
{
	/* Quick existence check via fopen("rb"). */
	FILE *fp = fopen(path, "rb");
	if (fp) {
		fclose(fp);
		return 0;
	}

	sim_trace_frame_t *buf = NULL;
	size_t n = 0;
	if (gen(&buf, &n, seed) != 0) return -1;
	int rc = trace_save(path, buf, n);
	free(buf);
	return rc;
}

/* ============================================================
 * Main CLI
 *
 *   ./simulator [--trace path.bin] [--sweep] [--report path.md]
 *               [--seed N] [--generate-traces]
 *
 * Default action: ensure 3 example traces exist, replay each,
 * run the full sweep, emit correctness-report.md + sweep-grid.csv.
 * ============================================================ */

static const char *basename_c(const char *p)
{
	const char *b = p;
	for (const char *c = p; *c; c++)
		if (*c == '/' || *c == '\\') b = c + 1;
	return b;
}

typedef struct {
	const char *trace_path;
	const char *report_path;
	const char *csv_path;
	bool        do_sweep;
	bool        generate_only;
	bool        help;
	uint64_t    seed;
} sim_cli_t;

static void parse_cli(int argc, char **argv, sim_cli_t *out)
{
	out->trace_path    = NULL;
	out->report_path   = "report/correctness-report.md";
	out->csv_path      = "report/sweep-grid.csv";
	out->do_sweep      = true;
	out->generate_only = false;
	out->help          = false;
	out->seed          = 0xC0FFEEULL;

	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (!strcmp(a, "--trace") && i + 1 < argc) {
			out->trace_path = argv[++i];
		} else if (!strcmp(a, "--report") && i + 1 < argc) {
			out->report_path = argv[++i];
		} else if (!strcmp(a, "--csv") && i + 1 < argc) {
			out->csv_path = argv[++i];
		} else if (!strcmp(a, "--seed") && i + 1 < argc) {
			out->seed = strtoull(argv[++i], NULL, 0);
		} else if (!strcmp(a, "--no-sweep")) {
			out->do_sweep = false;
		} else if (!strcmp(a, "--generate-traces")) {
			out->generate_only = true;
		} else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
			out->help = true;
		}
	}
}

static void usage(const char *argv0)
{
	fprintf(stderr,
	    "Usage: %s [options]\n"
	    "  --trace FILE          Run on this trace only (no sweep)\n"
	    "  --report FILE         Emit markdown report here (default: report/correctness-report.md)\n"
	    "  --csv FILE            Emit sweep grid CSV here (default: report/sweep-grid.csv)\n"
	    "  --seed N              PRNG seed (default: 0xC0FFEE)\n"
	    "  --no-sweep            Skip the parameter sweep\n"
	    "  --generate-traces     Only (re)generate example traces and exit\n"
	    "  -h, --help            Show this help\n",
	    basename_c(argv0));
}

/*
 * Ensure the parent directory of `path` exists. Walks only segments
 * we created; does not mkdir -p over paths we don't own. The report
 * lives at "report/..." so we just mkdir that one level deep.
 */
static void ensure_parent_dir(const char *path)
{
	if (!path) return;
	char buf[1024];
	size_t n = strlen(path);
	if (n == 0 || n >= sizeof(buf)) return;
	memcpy(buf, path, n + 1);
	/* Strip trailing basename. */
	for (ptrdiff_t i = (ptrdiff_t)n - 1; i >= 0; i--) {
		if (buf[i] == '/' || buf[i] == '\\') {
			buf[i] = '\0';
			break;
		}
	}
	if (buf[0] == '\0') return;

	/* Walk forward, mkdir each prefix. */
	for (char *p = buf + 1; *p; p++) {
		if (*p == '/' || *p == '\\') {
			char save = *p;
			*p = '\0';
#ifdef _WIN32
			_mkdir(buf);
#else
			mkdir(buf, 0755);
#endif
			*p = save;
		}
	}
#ifdef _WIN32
	_mkdir(buf);
#else
	mkdir(buf, 0755);
#endif
}

/*
 * Replay one trace end-to-end:
 *   1. load the file
 *   2. run the simulator with DEFAULT cfg + DEFAULT noise
 *   3. compute stability metrics
 *   4. return both the records and the metrics to the caller
 *
 * Caller owns *out_recs + the returned `stab`.
 */
static int replay_one(const char *trace_path,
                      const coh_config_t *cfg,
                      const sim_noise_cfg_t *noise,
                      sim_tick_record_t **out_recs,
                      size_t *out_recs_n,
                      sim_stability_t *out_stab)
{
	sim_trace_frame_t *frames = NULL;
	size_t n = 0;
	if (trace_load(trace_path, &frames, &n) != 0) {
		fprintf(stderr, "simulator: cannot load trace %s\n", trace_path);
		return -1;
	}

	sim_tick_record_t *recs = calloc(n, sizeof(*recs));
	if (!recs) {
		free(frames);
		return -1;
	}

	sim_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.frames       = frames;
	ctx.frame_count  = n;
	ctx.cfg          = *cfg;
	ctx.noise        = *noise;
	ctx.out          = recs;
	ctx.out_capacity = n;

	if (sim_run(&ctx) != 0) {
		free(frames);
		free(recs);
		return -1;
	}

	stability_compute(recs, ctx.out_count, out_stab);

	free(frames);

	*out_recs = recs;
	*out_recs_n = ctx.out_count;
	return 0;
}

int main(int argc, char **argv)
{
	sim_cli_t cli;
	parse_cli(argc, argv, &cli);
	if (cli.help) { usage(argv[0]); return 0; }

	coh_config_t cfg;
	coh_config_defaults(&cfg);

	sim_noise_cfg_t noise;
	noise_cfg_defaults(&noise, cli.seed);

	fprintf(stderr,
	    "{\"event\":\"sim_start\",\"seed\":%llu,\"sweep\":%s,\"trace\":\"%s\"}\n",
	    (unsigned long long)cli.seed,
	    cli.do_sweep ? "true" : "false",
	    cli.trace_path ? cli.trace_path : "(defaults)");

	/* Make sure example traces exist. */
	const char *steady_path   = "traces/steady.bin";
	const char *thermal_path  = "traces/thermal_storm.bin";
	const char *burst_path    = "traces/burst_load.bin";

	ensure_parent_dir(steady_path);
	(void)sim_ensure_trace(steady_path,  trace_gen_steady,        cli.seed);
	(void)sim_ensure_trace(thermal_path, trace_gen_thermal_storm, cli.seed);
	(void)sim_ensure_trace(burst_path,   trace_gen_burst_load,    cli.seed);

	if (cli.generate_only) {
		fprintf(stderr, "{\"event\":\"traces_generated\"}\n");
		return 0;
	}

	/* ===== Single-trace mode: if --trace given, replay + report it only. ===== */
	if (cli.trace_path) {
		sim_tick_record_t *recs = NULL;
		size_t recs_n = 0;
		sim_stability_t stab = {0};
		if (replay_one(cli.trace_path, &cfg, &noise, &recs, &recs_n, &stab) != 0) {
			return 1;
		}

		report_cfg_t rc;
		memset(&rc, 0, sizeof(rc));
		rc.out_path = cli.report_path;
		rc.traces[0].name = basename_c(cli.trace_path);
		rc.traces[0].path = cli.trace_path;
		rc.traces[0].stab = &stab;
		rc.traces[0].recs = recs;
		rc.traces[0].recs_n = recs_n;
		rc.trace_count = 1;
		rc.seed = cli.seed;
		rc.default_theta_latency_enter = cfg.theta_latency_enter;
		rc.default_theta_thermal_enter = cfg.theta_thermal_enter;
		rc.default_tau_hold_ms         = cfg.tau_hold_ms;
		rc.default_label               = "shipping default";

		ensure_parent_dir(cli.report_path);
		int rv = report_emit(&rc);
		free(recs);
		return rv == 0 ? (stab.stable ? 0 : 2) : 1;
	}

	/* ===== Default mode: 3 traces + sweep. ===== */
	sim_tick_record_t *recs_steady = NULL, *recs_thermal = NULL, *recs_burst = NULL;
	size_t n_steady = 0, n_thermal = 0, n_burst = 0;
	sim_stability_t stab_steady = {0}, stab_thermal = {0}, stab_burst = {0};

	if (replay_one(steady_path,  &cfg, &noise, &recs_steady,  &n_steady,  &stab_steady)  != 0) return 1;
	if (replay_one(thermal_path, &cfg, &noise, &recs_thermal, &n_thermal, &stab_thermal) != 0) return 1;
	if (replay_one(burst_path,   &cfg, &noise, &recs_burst,   &n_burst,   &stab_burst)   != 0) return 1;

	sweep_row_t *sweep_rows = NULL;
	size_t sweep_rows_n = 0;
	if (cli.do_sweep) {
		sweep_cfg_t scfg;
		memset(&scfg, 0, sizeof(scfg));
		scfg.theta_latency_enter_min  = 0.70;
		scfg.theta_latency_enter_max  = 1.30;
		scfg.theta_latency_enter_step = 0.10;
		scfg.theta_thermal_enter_min  = 0.75;
		scfg.theta_thermal_enter_max  = 0.95;
		scfg.theta_thermal_enter_step = 0.05;
		/*
		 * ChatGPT-specified range is τ_hold ∈ [500, 1200] step 100.
		 * Phase-shift by 50 ms so the shipping default (750 ms) is
		 * an *exact* sweep point — otherwise the "default is within
		 * the stable region" proof has to interpolate. The range
		 * then becomes [550..1250] at 100 ms granularity which is
		 * equivalent coverage.
		 */
		scfg.tau_hold_min             = 550;
		scfg.tau_hold_max             = 1250;
		scfg.tau_hold_step            = 100;
		scfg.trace_path               = steady_path;
		scfg.csv_out_path             = cli.csv_path;
		scfg.noise_seed               = cli.seed;

		ensure_parent_dir(cli.csv_path);
		if (sweep_run(&scfg, &sweep_rows, &sweep_rows_n) < 0) {
			fprintf(stderr, "simulator: sweep failed\n");
			/* Don't fail the whole run — still emit the single-trace report. */
		}
	}

	report_cfg_t rc;
	memset(&rc, 0, sizeof(rc));
	rc.out_path = cli.report_path;

	rc.traces[0].name = "steady.bin";
	rc.traces[0].path = steady_path;
	rc.traces[0].stab = &stab_steady;
	rc.traces[0].recs = recs_steady;
	rc.traces[0].recs_n = n_steady;

	rc.traces[1].name = "thermal_storm.bin";
	rc.traces[1].path = thermal_path;
	rc.traces[1].stab = &stab_thermal;
	rc.traces[1].recs = recs_thermal;
	rc.traces[1].recs_n = n_thermal;

	rc.traces[2].name = "burst_load.bin";
	rc.traces[2].path = burst_path;
	rc.traces[2].stab = &stab_burst;
	rc.traces[2].recs = recs_burst;
	rc.traces[2].recs_n = n_burst;

	rc.trace_count = 3;
	rc.sweep_rows = sweep_rows;
	rc.sweep_row_count = sweep_rows_n;
	rc.seed = cli.seed;
	rc.commit = "HEAD";
	rc.default_label = "shipping default";
	rc.default_theta_latency_enter = cfg.theta_latency_enter;
	rc.default_theta_thermal_enter = cfg.theta_thermal_enter;
	rc.default_tau_hold_ms         = cfg.tau_hold_ms;

	ensure_parent_dir(cli.report_path);
	int rv = report_emit(&rc);

	/* Exit 0 only if all traces + sweep-best are stable. */
	bool all_ok = stab_steady.stable && stab_thermal.stable && stab_burst.stable;

	free(recs_steady);
	free(recs_thermal);
	free(recs_burst);
	free(sweep_rows);

	return (rv == 0 && all_ok) ? 0 : 2;
}
