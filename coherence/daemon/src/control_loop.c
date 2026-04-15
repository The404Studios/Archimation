/*
 * control_loop.c — Multi-rate phase-atomic scheduler for the coherence daemon.
 *
 * Single-threaded 1 ms monotonic tick loop. See control_loop.h for the
 * phase diagram. Everything here is zero-alloc on the hot path — the
 * entire loop context is allocated once at init.
 *
 * Timing:
 *   - CLOCK_MONOTONIC everywhere. Never gettimeofday(), never time().
 *   - Drift-corrected sleep via clock_nanosleep(TIMER_ABSTIME) toward the
 *     next absolute 1 ms boundary. Never naive nanosleep().
 *   - Wake late → we skip to the next boundary and bump stats.tick_overruns.
 *
 * Phases, expressed as the offset (ms) inside a 500 ms ACTUATION_FRAME
 * (f = (now - anchor) % 500):
 *   f in [0, 100)     — MEASUREMENT window 0 → sample at t%100==0
 *   f in [100, 200)   — MEASUREMENT window 1 + start of DERIVATION
 *   f in [200, 300)   — DERIVATION continues + DECISION at t==250
 *   f in [300, 400)   — MEASUREMENT window 3 (DECISION already fired)
 *   f in [400, 500)   — MEASUREMENT window 4
 *   f == 0 (mod 500)  — ACTUATION COMMIT (single idempotent barrier)
 *
 * Note: measurement windows are every 100 ms (5× per actuation frame).
 * Derivation + decision fire once per frame. Actuation commit is the
 * single writeback edge at the 500 ms boundary.
 */

#define _POSIX_C_SOURCE 200809L

#include "control_loop.h"
#include "state_machine.h"
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* -------- time helpers -------- */

static inline uint64_t ts_to_ms(const struct timespec *ts)
{
	return (uint64_t)ts->tv_sec * 1000ULL + (uint64_t)ts->tv_nsec / 1000000ULL;
}

static inline void ms_to_ts(uint64_t ms, struct timespec *ts)
{
	ts->tv_sec = (time_t)(ms / 1000ULL);
	ts->tv_nsec = (long)((ms % 1000ULL) * 1000000ULL);
}

static uint64_t coh_now_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		/* Extremely unlikely — if it happens, return 0 and let the loop
		 * continue; overrun stats will scream. */
		return 0;
	}
	return ts_to_ms(&ts);
}

/* Sleep until an absolute monotonic deadline expressed in milliseconds.
 * EINTR-resumes automatically. Returns 0 on success, -errno otherwise. */
static int coh_sleep_until_ms(uint64_t deadline_ms)
{
	struct timespec ts;
	ms_to_ts(deadline_ms, &ts);
	int rc;
	do {
		rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
	} while (rc == EINTR);
	return rc == 0 ? 0 : -rc;
}

/* -------- weak stubs for Agents 4/5/6 ----------
 *
 * Declared __attribute__((weak)) so linking succeeds even if Agents 4/5/6
 * haven't landed yet. In a production build, the real symbols override
 * these at link time.
 *
 * These are NOT static — they match the public signatures in control_loop.h.
 */
__attribute__((weak))
int measurement_sample(coh_metrics_t *m, uint64_t now_ms)
{
	if (!m) return -EINVAL;
	memset(m, 0, sizeof(*m));
	m->t_ms = now_ms;
	m->flags = 0;                   /* sample_complete=0 → treat as absent */
	m->present_mode_actual = COH_PRESENT_AUTO;
	return 0;
}

__attribute__((weak))
int derived_compute(coh_derived_t *d, const coh_metrics_t *m_lagged, uint64_t now_ms)
{
	if (!d) return -EINVAL;
	memset(d, 0, sizeof(*d));
	d->t_ms = now_ms;
	if (!m_lagged) {
		d->valid = false;
		return 0;
	}
	d->source_m_t_ms = m_lagged->t_ms;
	d->valid = false;               /* weak stub can't compute — pretend stale */
	return 0;
}

/* actuation_commit is the strong symbol from actuation.c with signature
 * int actuation_commit(const coh_actuation_t *a_next, uint64_t now_ms).
 * The caller below must pass a monotonic-ms timestamp. Dry-run mode is
 * handled at the call site by skipping the commit entirely. */

/* -------- M(t) ring -------- */

static coh_metrics_t *coh_ring_push(coh_loop_ctx_t *ctx)
{
	coh_metrics_t *slot = &ctx->m_ring[ctx->m_head];
	ctx->m_head = (ctx->m_head + 1u) % COH_M_RING_DEPTH;
	if (ctx->m_filled < COH_M_RING_DEPTH)
		ctx->m_filled++;
	return slot;
}

/* Fetch M(t - k * CONTROL_FRAME). Returns NULL if the ring isn't yet
 * that deep or the lagged sample is stale.
 *
 * Indexing: the most recent sample is at (m_head - 1) mod DEPTH. The
 * k-frames-ago sample is at (m_head - 1 - k) mod DEPTH, provided
 * m_filled > k. */
static const coh_metrics_t *coh_ring_get_lagged(const coh_loop_ctx_t *ctx,
                                                uint32_t k,
                                                uint64_t now_ms)
{
	if (ctx->m_filled <= k)
		return NULL;

	uint32_t idx = (ctx->m_head + COH_M_RING_DEPTH - 1u - k) % COH_M_RING_DEPTH;
	const coh_metrics_t *m = &ctx->m_ring[idx];

	/* Freshness: lagged must fall inside the validity window. With
	 * k=2 and CONTROL_FRAME=100ms, the target sample is 200ms old —
	 * exactly the edge of VALIDITY_WINDOW=200ms. Allow equality to
	 * pass by using the helper. */
	if (!coh_m_is_fresh(now_ms, m->t_ms))
		return NULL;

	return m;
}

/* -------- init + teardown -------- */

static void coh_ensure_state_dir(const char *path)
{
	if (!path || !*path) return;
	/* mkdir -p, one level — /var/run/coherence */
	if (mkdir(path, 0755) != 0 && errno != EEXIST) {
		fprintf(stderr, "{\"event\":\"state_dir_error\",\"path\":\"%s\",\"errno\":%d}\n",
		        path, errno);
	}
}

int coh_loop_init(coh_loop_ctx_t *ctx, const coh_config_t *cfg)
{
	if (!ctx || !cfg) return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	memcpy(&ctx->cfg, cfg, sizeof(ctx->cfg));
	/* Copy with bounded snprintf to avoid -Wstringop-truncation on
	 * strncpy when source == destination size. */
	(void)snprintf(ctx->state_dir, sizeof(ctx->state_dir), "%s", cfg->state_dir);

	coh_ensure_state_dir(ctx->state_dir);

	uint64_t now = coh_now_ms();
	ctx->anchor_monotonic_ms = now;

	coh_sm_init(&ctx->arb, &ctx->sm_scratch, now);

	ctx->m_head = 0;
	ctx->m_filled = 0;

	ctx->d_have_last_valid = false;
	ctx->a_committed_valid = false;

	ctx->phase_measurement_done_for_window = false;
	ctx->current_control_window_idx = 0;
	ctx->phase_derivation_done = false;
	ctx->phase_decision_done = false;

	ctx->should_exit = false;
	ctx->should_reload = false;

	fprintf(stderr,
	        "{\"event\":\"loop_init\",\"anchor_ms\":%llu,\"ring_depth\":%u,\"dry_run\":%s}\n",
	        (unsigned long long)ctx->anchor_monotonic_ms,
	        COH_M_RING_DEPTH,
	        cfg->dry_run ? "true" : "false");
	return 0;
}

void coh_loop_request_exit(coh_loop_ctx_t *ctx)
{
	if (!ctx) return;
	ctx->should_exit = true;
}

void coh_loop_request_reload(coh_loop_ctx_t *ctx)
{
	if (!ctx) return;
	ctx->should_reload = true;
}

/* -------- phase dispatchers -------- */

/* MEASUREMENT: sample at the start of every 100ms control window. */
static void coh_phase_measurement(coh_loop_ctx_t *ctx,
                                  uint64_t frame_offset_ms,
                                  uint64_t now_ms)
{
	uint32_t window_idx = (uint32_t)(frame_offset_ms / COH_CONTROL_FRAME_MS);
	if (window_idx >= 5u) window_idx = 4u;   /* guard against edge case */

	/* Reset the "done" flag when we enter a new window. */
	if (window_idx != ctx->current_control_window_idx) {
		ctx->current_control_window_idx = window_idx;
		ctx->phase_measurement_done_for_window = false;
	}

	/* Sample exactly once at the START of each window (frame_offset % 100 == 0
	 * within a small tolerance — we match by "not yet done this window"). */
	if (ctx->phase_measurement_done_for_window)
		return;

	coh_metrics_t *slot = coh_ring_push(ctx);
	int rc = measurement_sample(slot, now_ms);
	if (rc < 0) {
		/* Overwrite the slot with a minimally valid but flagged sample
		 * so downstream knows it's absent, and log once. */
		memset(slot, 0, sizeof(*slot));
		slot->t_ms = now_ms;
		slot->flags = 0;
		fprintf(stderr, "{\"event\":\"measurement_error\",\"rc\":%d}\n", rc);
	}
	ctx->stats.measurement_calls++;
	ctx->phase_measurement_done_for_window = true;
}

/* DERIVATION: once per frame, at t == 100ms (top of the derivation phase).
 * Feeds the lagged M(t - k * CONTROL_FRAME). If lagged sample is stale,
 * D.valid=false and the last_valid snapshot is reused in the decision. */
static void coh_phase_derivation(coh_loop_ctx_t *ctx, uint64_t now_ms)
{
	if (ctx->phase_derivation_done)
		return;

	const coh_metrics_t *lagged = coh_ring_get_lagged(ctx, COH_DERIVATION_LAG_K, now_ms);
	int rc = derived_compute(&ctx->d_current, lagged, now_ms);
	if (rc < 0) {
		fprintf(stderr, "{\"event\":\"derivation_error\",\"rc\":%d}\n", rc);
		ctx->d_current.valid = false;
	}
	if (!lagged) {
		ctx->d_current.valid = false;
	}

	if (ctx->d_current.valid) {
		ctx->d_last_valid = ctx->d_current;
		ctx->d_have_last_valid = true;
	} else {
		ctx->stats.derivation_stale++;
	}
	ctx->stats.derivation_calls++;
	ctx->phase_derivation_done = true;
}

/* DECISION: once per frame, at t == 250ms. */
static void coh_phase_decision(coh_loop_ctx_t *ctx, uint64_t now_ms)
{
	if (ctx->phase_decision_done)
		return;

	/* Pick the D to feed the arbiter. If current is invalid, fall back
	 * to last_valid. If we have nothing valid yet, pass an invalid D
	 * and the arbiter will skip. */
	const coh_derived_t *d_use = &ctx->d_current;
	if (!ctx->d_current.valid && ctx->d_have_last_valid) {
		d_use = &ctx->d_last_valid;
	}

	bool changed = coh_sm_evaluate(&ctx->arb, &ctx->sm_scratch, d_use,
	                               &ctx->cfg, now_ms);
	(void)changed;
	if (coh_in_lockout(&ctx->arb, now_ms))
		ctx->stats.lockout_blocks++;

	coh_sm_plan(&ctx->arb, d_use, &ctx->a_next, now_ms);

	ctx->stats.decision_calls++;
	ctx->phase_decision_done = true;
}

/* ACTUATION: single idempotent commit at the frame boundary (f == 0). */
static void coh_phase_actuation(coh_loop_ctx_t *ctx, uint64_t now_ms)
{
	/* Skip if we haven't made a decision yet (e.g., first frame after
	 * boot). Also skip if the planned A equals the committed A — that's
	 * the idempotent barrier. */
	if (!ctx->phase_decision_done) {
		return;
	}

	if (ctx->a_committed_valid && coh_a_equal(&ctx->a_committed, &ctx->a_next)) {
		ctx->stats.actuation_noops++;
		/* Intentionally NOT calling commit again. */
		return;
	}

	if (ctx->cfg.dry_run) {
		/* Observation mode: record the planned A but do not touch the
		 * system. a_committed still advances so the idempotent barrier
		 * on the NEXT frame compares against what we WOULD have written. */
		ctx->stats.actuation_dry_skips++;
	} else {
		int rc = actuation_commit(&ctx->a_next, now_ms);
		if (rc < 0) {
			fprintf(stderr, "{\"event\":\"actuation_commit_error\",\"rc\":%d}\n", rc);
			/* Do not update a_committed — we'll retry next frame. */
			return;
		}
	}

	ctx->a_committed = ctx->a_next;
	ctx->a_committed_valid = true;
	ctx->arb.effective_actions++;
	ctx->stats.actuation_commits++;
}

/* -------- frame boundary reset -------- */

static void coh_reset_frame_flags(coh_loop_ctx_t *ctx)
{
	ctx->phase_measurement_done_for_window = false;
	ctx->current_control_window_idx = 0;
	ctx->phase_derivation_done = false;
	ctx->phase_decision_done = false;
}

/* -------- per-frame JSON telemetry -------- */

void coh_loop_emit_frame_json(const coh_loop_ctx_t *ctx)
{
	if (!ctx) return;

	const coh_derived_t *d = ctx->d_have_last_valid ? &ctx->d_last_valid : &ctx->d_current;

	fprintf(stderr,
	        "{\"event\":\"frame\","
	        "\"frame\":%llu,\"t_ms\":%llu,"
	        "\"state\":\"%s\",\"lockout\":%s,"
	        "\"d_valid\":%s,\"lat\":%.3f,\"therm\":%.3f,\"V\":%.3f,"
	        "\"epp\":%d,\"min_pct\":%d,\"present\":%d,"
	        "\"meas\":%llu,\"der\":%llu,\"der_stale\":%llu,"
	        "\"dec\":%llu,\"act\":%llu,\"act_noop\":%llu,"
	        "\"transitions\":%llu,\"overruns\":%llu}\n",
	        (unsigned long long)ctx->stats.frames_total,
	        (unsigned long long)coh_now_ms(),
	        coh_sm_state_name(ctx->arb.state),
	        coh_in_lockout(&ctx->arb, coh_now_ms()) ? "true" : "false",
	        d->valid ? "true" : "false",
	        d->latency_pressure, d->thermal, d->lyapunov_v,
	        (int)ctx->a_next.epp, ctx->a_next.min_perf_pct,
	        (int)ctx->a_next.present_mode_override,
	        (unsigned long long)ctx->stats.measurement_calls,
	        (unsigned long long)ctx->stats.derivation_calls,
	        (unsigned long long)ctx->stats.derivation_stale,
	        (unsigned long long)ctx->stats.decision_calls,
	        (unsigned long long)ctx->stats.actuation_commits,
	        (unsigned long long)ctx->stats.actuation_noops,
	        (unsigned long long)ctx->arb.transitions_total,
	        (unsigned long long)ctx->stats.tick_overruns);
}

/* -------- reload handling -------- */

static void coh_handle_reload(coh_loop_ctx_t *ctx, const char *config_path)
{
	if (!ctx->should_reload) return;
	ctx->should_reload = false;

	coh_config_t newcfg;
	coh_config_defaults(&newcfg);
	int err = coh_config_load(&newcfg, config_path);
	if (err < 0) {
		fprintf(stderr, "{\"event\":\"config_reload_failed\",\"err\":%d}\n", err);
		return;
	}
	if (coh_config_validate(&newcfg) < 0) {
		fprintf(stderr, "{\"event\":\"config_reload_invalid\"}\n");
		return;
	}

	/* Merge — dry_run is operator-controlled via CLI/env; we preserve
	 * whatever the running loop is already using so a SIGHUP doesn't
	 * flip observation mode into live mode silently. */
	bool saved_dry_run = ctx->cfg.dry_run;
	ctx->cfg = newcfg;
	ctx->cfg.dry_run = saved_dry_run;

	coh_config_log(&ctx->cfg);
	fprintf(stderr, "{\"event\":\"config_reloaded\"}\n");
}

/* -------- the run loop -------- */

int coh_loop_run(coh_loop_ctx_t *ctx)
{
	if (!ctx) return -EINVAL;

	/* The path we'll reload from if SIGHUP arrives. Main sets the env
	 * "COH_CONFIG_PATH" so the loop doesn't need to know the CLI args. */
	const char *config_path = getenv("COH_CONFIG_PATH");
	if (!config_path || !*config_path)
		config_path = "/etc/coherence/coherence.conf";

	const uint64_t TICK_MS = COH_BASE_TICK_MS;
	uint64_t next_tick = coh_now_ms() + TICK_MS;

	while (!ctx->should_exit) {
		/* Handle reload BEFORE computing phase so the new config kicks
		 * in on the next evaluate. */
		coh_handle_reload(ctx, config_path);

		int sleep_rc = coh_sleep_until_ms(next_tick);
		uint64_t now = coh_now_ms();

		if (sleep_rc != 0 || now > next_tick + (TICK_MS * 2)) {
			/* We overran by more than 2 ticks — skip to the next
			 * boundary and log. */
			ctx->stats.tick_overruns++;
			next_tick = now + TICK_MS;
			fprintf(stderr, "{\"event\":\"tick_overrun\",\"t_ms\":%llu}\n",
			        (unsigned long long)now);
		} else {
			next_tick += TICK_MS;
		}

		ctx->stats.ticks_total++;

		/* Compute phase from anchor. We use (now - anchor) so wraparound
		 * is moot for years of uptime, and so all phases line up on the
		 * same 500 ms grid from day zero. */
		uint64_t rel = now - ctx->anchor_monotonic_ms;
		uint64_t frame_idx = rel / COH_ACTUATION_FRAME_MS;
		uint64_t frame_offset = rel % COH_ACTUATION_FRAME_MS;

		/* --- Frame boundary: actuation commit THEN telemetry THEN reset. --- */
		if (frame_idx != ctx->stats.frames_total) {
			/* We crossed into a new frame. The ORDER is:
			 *   1) fire actuation commit for the old frame (if decision fired),
			 *   2) emit per-frame JSON telemetry,
			 *   3) reset phase flags,
			 *   4) bump frame counter.
			 *
			 * NOTE: actuation is the ONLY writeback call site. It cannot
			 * be called from any other phase — the `if` here guards that. */
			coh_phase_actuation(ctx, now);
			coh_loop_emit_frame_json(ctx);
			coh_reset_frame_flags(ctx);
			ctx->stats.frames_total = frame_idx;
		}

		/* --- Phase dispatch --- */
		if (frame_offset < COH_CONTROL_FRAME_MS) {
			/* [0, 100ms) — MEASUREMENT window 0 */
			coh_phase_measurement(ctx, frame_offset, now);
		} else if (frame_offset < COH_DECISION_FRAME_MS) {
			/* [100, 250ms) — DERIVATION phase AND continuing
			 * measurement (we also need to sample at windows 1..4).
			 * Measurement always fires first (at the window boundary),
			 * then derivation once per frame at the top of this band. */
			coh_phase_measurement(ctx, frame_offset, now);
			if (frame_offset >= COH_CONTROL_FRAME_MS)
				coh_phase_derivation(ctx, now);
		} else if (frame_offset < COH_ACTUATION_FRAME_MS) {
			/* [250, 500ms) — DECISION phase. Measurement windows 3+4
			 * also fall here and must still sample. Decision fires once
			 * at the top of this band. */
			coh_phase_measurement(ctx, frame_offset, now);
			if (!ctx->phase_decision_done && frame_offset >= COH_DECISION_FRAME_MS)
				coh_phase_decision(ctx, now);
		}
		/* frame_offset == 0 is handled at the top as the frame crossing,
		 * not as an in-frame phase. */
	}

	/* Flush one last telemetry line before exit. */
	fprintf(stderr, "{\"event\":\"loop_exit\",\"ticks\":%llu,\"frames\":%llu}\n",
	        (unsigned long long)ctx->stats.ticks_total,
	        (unsigned long long)ctx->stats.frames_total);

	return 0;
}
