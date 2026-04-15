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
#include "actuation.h"

/* Forward-declare coh_derived_current_state() from derived.h WITHOUT
 * pulling derived.h in — it conflicts with control_loop.h's weak-stub
 * signature of derived_compute (int vs void return). The accessor is
 * independent and stable. */
coh_derived_state_t coh_derived_current_state(void);

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

/* -------- R34 typestate transition helpers -------- */

bool coh_loop_derived_transition(coh_loop_ctx_t *ctx,
                                 coh_derived_state_t to,
                                 uint64_t now_ms)
{
	if (!ctx) return false;
	if (!coh_derived_transition_legal(ctx->d_state, to)) {
		fprintf(stderr,
		        "{\"event\":\"loop_derived_illegal\",\"t_ms\":%llu,"
		        "\"from\":\"%s\",\"to\":\"%s\"}\n",
		        (unsigned long long)now_ms,
		        coh_derived_state_str(ctx->d_state),
		        coh_derived_state_str(to));
		return false;
	}
	ctx->d_state = to;
	return true;
}

bool coh_loop_act_transition(coh_loop_ctx_t *ctx,
                             coh_act_state_t to,
                             uint64_t now_ms)
{
	if (!ctx) return false;
	if (!coh_act_transition_legal(ctx->a_state, to)) {
		fprintf(stderr,
		        "{\"event\":\"loop_act_illegal\",\"t_ms\":%llu,"
		        "\"from\":\"%s\",\"to\":\"%s\"}\n",
		        (unsigned long long)now_ms,
		        coh_act_state_str(ctx->a_state),
		        coh_act_state_str(to));
		return false;
	}
	ctx->a_state = to;
	return true;
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

__attribute__((weak))
coh_derived_state_t coh_derived_current_state(void)
{
	/* Weak stub — mirrors the derived-module behavior when nothing has
	 * been computed: UNINIT. Real derived.c provides a strong symbol. */
	return COH_DERIVED_UNINIT;
}

__attribute__((weak))
coh_act_state_t actuation_last_commit_state(void)
{
	/* Weak stub — UNINIT when actuation.c is not linked. The real
	 * symbol in actuation.c shadows this at link time. */
	return COH_ACT_UNINIT;
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

	/* R34 typestate init: both start in UNINIT. Contract requires
	 * COH_*_UNINIT == 0 so the memset above already satisfies this;
	 * we re-assign for explicitness (and to guard against someone
	 * reordering the memset away). */
	ctx->d_state = COH_DERIVED_UNINIT;
	ctx->a_state = COH_ACT_UNINIT;

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
 * derived_compute leaves d->valid=false and transitions the module-
 * static typestate to STALE (or DEGRADED after 3 stale in a row). We
 * mirror the typestate into ctx->d_state so downstream consumers
 * (decision phase, frame JSON) can branch on a single field.
 *
 * Transition table (ctx->d_state):
 *   UNINIT   → FRESH      first fresh compute
 *   FRESH    → FRESH      continuing fresh (self-loop)
 *   FRESH    → STALE      lagged M aged out
 *   STALE    → STALE      continued staleness below the degraded floor
 *   STALE    → DEGRADED   after 3 consecutive stale frames (module owns
 *                         the counter; we just observe the module state)
 *   STALE    → FRESH      recovered
 *   DEGRADED → FRESH      recovered (legal; table permits)
 *   DEGRADED → DEGRADED   continued (self-loop)
 *   FRESH    → UNINIT     FORBIDDEN (no regression to uninitialized)
 */
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

	/* Pull the module-owned typestate through into the loop ctx so
	 * downstream code can branch on ctx->d_state consistently. The
	 * derived module applied its own transition inside derived_compute;
	 * we reconcile via coh_loop_derived_transition which will log if
	 * the delta is illegal (should never happen). */
	coh_derived_state_t new_state = coh_derived_current_state();
	if (new_state != ctx->d_state) {
		(void)coh_loop_derived_transition(ctx, new_state, now_ms);
	}

	if (ctx->d_state == COH_DERIVED_FRESH) {
		ctx->d_last_fresh = ctx->d_current;
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

	/* Pick the D to feed the arbiter via R34 typestate:
	 *   FRESH     → use current
	 *   STALE     → fall back to last FRESH snapshot (carried EMA state)
	 *   DEGRADED  → fall back to last FRESH snapshot; state_machine will
	 *               still refuse to advance dwell because d->valid=false,
	 *               but logging downstream gets the DEGRADED label
	 *   UNINIT    → pass d_current (which is fully zero); arbiter skips
	 */
	const coh_derived_t *d_use = &ctx->d_current;
	switch (ctx->d_state) {
	case COH_DERIVED_FRESH:
		d_use = &ctx->d_current;
		break;
	case COH_DERIVED_STALE:
	case COH_DERIVED_DEGRADED:
		d_use = &ctx->d_last_fresh;
		break;
	case COH_DERIVED_UNINIT:
	case COH_DERIVED_STATE_COUNT:
	default:
		d_use = &ctx->d_current;
		break;
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

/* ACTUATION: single idempotent commit at the frame boundary (f == 0).
 *
 * Typestate transitions driven here (ctx->a_state):
 *   * → PLANNED          arbiter handed us a plan; we're about to commit
 *   PLANNED → BARRIERED  idempotent top-level barrier hit; no writes
 *   PLANNED → COMMITTED  actuation_commit reported success; A(t) landed
 *   PLANNED → FAILED     actuation_commit returned <0 at the top level
 *                        (e.g., -EAGAIN before init)
 *   PLANNED → RATE_LIMITED   every actuator was inside its τ window;
 *                            we read this back from
 *                            actuation_last_commit_state()
 * Dry-run: we still set PLANNED → COMMITTED because the loop WOULD have
 * written; the distinction is captured in the actuation_dry_skips counter.
 */
static void coh_phase_actuation(coh_loop_ctx_t *ctx, uint64_t now_ms)
{
	/* Skip if we haven't made a decision yet (e.g., first frame after
	 * boot). The loop ctx.a_state stays in its current state (UNINIT
	 * on the very first pass). */
	if (!ctx->phase_decision_done) {
		return;
	}

	/* Start commit: transition to PLANNED. Legal from UNINIT or from
	 * any of the prior terminal states (BARRIERED, COMMITTED, FAILED,
	 * RATE_LIMITED) per the transition table. */
	(void)coh_loop_act_transition(ctx, COH_ACT_PLANNED, now_ms);

	if (ctx->a_state == COH_ACT_PLANNED &&
	    ctx->arb.transitions_total > 0 &&
	    coh_a_equal(&ctx->a_committed, &ctx->a_next)) {
		/* We've committed before (transitions_total > 0 is a proxy;
		 * more precisely: a_state was in a post-commit terminal
		 * state before we bumped to PLANNED). Idempotent barrier. */
		ctx->stats.actuation_noops++;
		(void)coh_loop_act_transition(ctx, COH_ACT_BARRIERED, now_ms);
		return;
	}

	if (ctx->cfg.dry_run) {
		/* Observation mode: record the planned A but do not touch the
		 * system. a_committed still advances so the idempotent barrier
		 * on the NEXT frame compares against what we WOULD have written. */
		ctx->stats.actuation_dry_skips++;
		(void)coh_loop_act_transition(ctx, COH_ACT_COMMITTED, now_ms);
	} else {
		int rc = actuation_commit(&ctx->a_next, now_ms);
		if (rc < 0) {
			fprintf(stderr, "{\"event\":\"actuation_commit_error\",\"rc\":%d}\n", rc);
			/* Do not update a_committed — we'll retry next frame.
			 * Transition to FAILED so next frame's commit starts
			 * from a legal FAILED → PLANNED edge. */
			(void)coh_loop_act_transition(ctx, COH_ACT_FAILED, now_ms);
			return;
		}
		/* actuation_commit returned 0. Read back the granular outcome
		 * from the actuation module and mirror it into ctx->a_state. */
		coh_act_state_t module_state = actuation_last_commit_state();
		if (module_state != COH_ACT_PLANNED &&
		    module_state != COH_ACT_UNINIT) {
			(void)coh_loop_act_transition(ctx, module_state, now_ms);
		} else {
			/* Defensive fallback — the module is wedged mid-commit
			 * (shouldn't happen since commits are synchronous). Log
			 * and assume COMMITTED to let the loop keep moving. */
			(void)coh_loop_act_transition(ctx, COH_ACT_COMMITTED, now_ms);
		}
	}

	ctx->a_committed = ctx->a_next;
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

	/* Pick the D snapshot to report from. FRESH uses current; non-FRESH
	 * shows the last fresh values so the consumer sees the numeric view
	 * the arbiter actually saw, but the derived_state field says STALE
	 * / DEGRADED so the consumer can't mistake it for current. */
	const coh_derived_t *d;
	switch (ctx->d_state) {
	case COH_DERIVED_FRESH:
		d = &ctx->d_current;
		break;
	case COH_DERIVED_STALE:
	case COH_DERIVED_DEGRADED:
		d = &ctx->d_last_fresh;
		break;
	case COH_DERIVED_UNINIT:
	case COH_DERIVED_STATE_COUNT:
	default:
		d = &ctx->d_current;
		break;
	}

	fprintf(stderr,
	        "{\"event\":\"frame\","
	        "\"frame\":%llu,\"t_ms\":%llu,"
	        "\"state\":\"%s\",\"lockout\":%s,"
	        "\"derived_state\":\"%s\",\"act_state\":\"%s\","
	        "\"lat\":%.3f,\"therm\":%.3f,\"V\":%.3f,"
	        "\"epp\":%d,\"min_pct\":%d,\"present\":%d,"
	        "\"meas\":%llu,\"der\":%llu,\"der_stale\":%llu,"
	        "\"dec\":%llu,\"act\":%llu,\"act_noop\":%llu,"
	        "\"transitions\":%llu,\"overruns\":%llu}\n",
	        (unsigned long long)ctx->stats.frames_total,
	        (unsigned long long)coh_now_ms(),
	        coh_sm_state_name(ctx->arb.state),
	        coh_in_lockout(&ctx->arb, coh_now_ms()) ? "true" : "false",
	        coh_derived_state_str(ctx->d_state),
	        coh_act_state_str(ctx->a_state),
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
