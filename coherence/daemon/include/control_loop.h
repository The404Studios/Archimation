/*
 * control_loop.h — Multi-rate frame scheduler for the coherence daemon.
 *
 * Single-threaded 1 ms monotonic tick loop. Each tick resolves to one of
 * four phases derived from the relative position inside the 500 ms
 * ACTUATION_FRAME window:
 *
 *   [0, 100ms)   MEASUREMENT — call measurement_sample() once at the START
 *                of each 100 ms CONTROL_FRAME sub-window (5× per frame).
 *   [100, 250ms) DERIVATION  — call derived_compute() exactly once, fed the
 *                lagged M(t - k·CONTROL_FRAME), k >= COH_DERIVATION_LAG_K.
 *                If lagged sample is stale, D.valid=false and the previous
 *                snapshot is reused.
 *   [250, 500ms) DECISION    — call state_machine_evaluate + plan exactly
 *                once at t==250ms.
 *   [500ms]      ACTUATION   — single idempotent commit at the frame edge.
 *                NO other point may write to the system.
 *
 * Drift is killed with clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME)
 * toward an absolute next-tick time. No naive nanosleep() anywhere.
 */
#ifndef COH_CONTROL_LOOP_H
#define COH_CONTROL_LOOP_H

#include <stdint.h>
#include <stdbool.h>

#include "coherence_types.h"
#include "config.h"
#include "state_machine.h"

/* Depth of the M(t) ring. Must be > k so derivation can reach back.
 * 8 × 100 ms = 800 ms of history; k=2 samples back is always live. */
#define COH_M_RING_DEPTH      8u

/* Frame counters used for logging + coarse telemetry. */
typedef struct {
	uint64_t ticks_total;
	uint64_t frames_total;            /* 500 ms frames */
	uint64_t measurement_calls;
	uint64_t derivation_calls;
	uint64_t derivation_stale;
	uint64_t decision_calls;
	uint64_t actuation_commits;
	uint64_t actuation_noops;         /* idempotent barrier hits */
	uint64_t actuation_dry_skips;     /* dry-run skipped the sysfs writes */
	uint64_t tick_overruns;           /* wall time passed next-tick target */
	uint64_t lockout_blocks;
} coh_loop_stats_t;

/* Opaque runtime context for the loop. Allocated once at init, never
 * resized. All buffers live here so the hot path performs zero malloc. */
typedef struct {
	coh_config_t       cfg;
	coh_arbiter_t      arb;
	coh_sm_scratch_t   sm_scratch;

	/* M(t) ring — coh_metrics_t is ~1 KB, 8 slots = 8 KB static. */
	coh_metrics_t      m_ring[COH_M_RING_DEPTH];
	uint32_t           m_head;        /* next write slot */
	uint32_t           m_filled;      /* saturates at COH_M_RING_DEPTH */

	/* Latest derived snapshot + last *valid* derived snapshot. If the
	 * current one is stale, we plan against the last valid one. */
	coh_derived_t      d_current;
	coh_derived_t      d_last_valid;
	bool               d_have_last_valid;

	/* A(t-1) and A(t): committed vs. planned. */
	coh_actuation_t    a_committed;
	coh_actuation_t    a_next;
	bool               a_committed_valid;

	/* Per-frame gate flags — reset at frame boundary. */
	bool               phase_measurement_done_for_window;
	uint32_t           current_control_window_idx;   /* 0..4 inside a 500ms frame */
	bool               phase_derivation_done;
	bool               phase_decision_done;

	/* Monotonic anchor — the wall-clock ms we call "t=0". Never moves. */
	uint64_t           anchor_monotonic_ms;

	/* Statistics. */
	coh_loop_stats_t   stats;

	/* Signals. */
	volatile bool      should_exit;
	volatile bool      should_reload;

	/* State dir (copied from cfg at init). */
	char               state_dir[256];
} coh_loop_ctx_t;

/* Allocate + wire a new loop context. Does not start the loop. */
int coh_loop_init(coh_loop_ctx_t *ctx, const coh_config_t *cfg);

/* Run the scheduler until ctx->should_exit is set. Returns 0 on normal
 * exit (SIGTERM). On init failure returns negative errno. */
int coh_loop_run(coh_loop_ctx_t *ctx);

/* Request orderly shutdown. Safe to call from a signal handler. */
void coh_loop_request_exit(coh_loop_ctx_t *ctx);

/* Request config reload. Safe to call from a signal handler. */
void coh_loop_request_reload(coh_loop_ctx_t *ctx);

/* Emit one JSON status line per frame to stderr. Called internally at
 * every 500 ms frame boundary AFTER actuation. Exposed for testing. */
void coh_loop_emit_frame_json(const coh_loop_ctx_t *ctx);

/* ---- Integration points filled by Agents 4/5/6 ----
 *
 * These are declared here and referenced by the loop. Weak stubs live in
 * control_loop.c so -Werror builds without Agent 4/5/6 sources.
 *
 *   measurement_sample  — populate *m with a fresh M(t). Must set m->t_ms.
 *   derived_compute     — fill *d from the lagged metrics sample.
 *   actuation_plan      — [owned by state_machine.c — NOT a separate hook]
 *   actuation_commit    — apply *a to the system. Must be idempotent.
 *
 * All three return 0 on success, negative errno on failure. Failure is
 * logged but does not abort the daemon.
 */
int measurement_sample(coh_metrics_t *m, uint64_t now_ms);
int derived_compute(coh_derived_t *d, const coh_metrics_t *m_lagged, uint64_t now_ms);
int actuation_commit(const coh_actuation_t *a_next, uint64_t now_ms);

#endif /* COH_CONTROL_LOOP_H */
