/*
 * actuation.h — Actuation layer for the coherence daemon.
 *
 * The actuation layer is the ONLY point in the daemon permitted to write
 * to cgroup v2, sysfs, procfs, or io_uring coordination files. All writes
 * are funnelled through actuation_commit() which enforces:
 *
 *   1) An idempotent barrier: if A(t) == A(t-1) the entire commit is a
 *      no-op — no sysfs/cgroupfs/procfs writes are issued. This is MANDATORY
 *      because those filesystems are edge-triggered at the kernel side and
 *      re-writing the same value produces scheduler wakeups, kobject event
 *      emission, and IRQ rebalance churn.
 *
 *   2) Per-actuator rate limiting with the time-constants declared in
 *      coherence_types.h (COH_TAU_CPUSET_MS, COH_TAU_IRQ_MS,
 *      COH_TAU_SQPOLL_MS, plus internal windows for EPP and min_perf_pct).
 *      A rate-limited actuator is SKIPPED for this frame; the corresponding
 *      field in g_last_committed is left unchanged so the next frame retries.
 *
 *   3) A deterministic commit order:
 *        cgroup cpuset  →  IRQ affinity  →  EPP
 *        →  min_perf_pct →  SQPOLL retarget →  present_mode signal
 *
 * Ownership:
 *   actuation_commit() is single-writer. It MUST only be called by the
 *   control_loop.c frame scheduler at the 500 ms ACTUATION_FRAME boundary.
 *   The diagnostic helpers (actuation_get_last, actuation_effective_writes_since)
 *   are safe to call from any thread — they read snapshots behind a relaxed
 *   load; a torn read is acceptable for a human-readable /system/coherence.
 *
 * Return convention:
 *   0             — commit attempted (including the no-op / idempotent path).
 *   negative errno — setup failure (e.g. init not called).
 *
 * Per-actuator write errors are NEVER fatal. They are recorded in the
 * internal write_errors[] counter and deduplicated in the log to "one line
 * per failure per minute" so a missing sysfs path does not flood the journal.
 */
#ifndef COH_ACTUATION_H
#define COH_ACTUATION_H

#include <stdint.h>
#include <stdbool.h>

#include "coherence_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Actuator family indices for internal counter arrays. Public because the
 * simulator / test harness uses them to key on counters. */
typedef enum {
	COH_ACT_CPUSET       = 0,
	COH_ACT_IRQ          = 1,
	COH_ACT_EPP          = 2,
	COH_ACT_MIN_PERF_PCT = 3,
	COH_ACT_SQPOLL       = 4,
	COH_ACT_PRESENT_MODE = 5,
	COH_ACT_COUNT        = 6
} coh_actuator_id_t;

/* Internal rate-limit windows for the actuators not declared in
 * coherence_types.h. Chosen conservatively so cpufreq knobs don't thrash. */
#define COH_TAU_EPP_MS          500u
#define COH_TAU_MIN_PERF_MS     500u
#define COH_TAU_PRESENT_MODE_MS 250u

/*
 * Initialise the actuation layer. Validates that the state directory
 * (/var/run/coherence) exists or can be created. Detects which cpufreq
 * backend is present (intel_pstate / amd_pstate / neither) and caches the
 * result. Reads the current EPP values once so COH_EPP_DEFAULT knows what
 * to restore to.
 *
 * Returns 0 on success, -errno on fatal misconfiguration. Missing optional
 * paths (e.g. no amd_pstate sysfs on an Intel host) are not fatal.
 */
int  actuation_init(void);

/*
 * Commit A(t) to the system.
 *
 * Rules (implemented in actuation.c):
 *   - If coh_a_equal(&g_last_committed, a_next) → increment idempotent_skips
 *     and return 0 WITHOUT issuing any writes. This is the fast-path.
 *   - Otherwise walk the deterministic actuator order, rate-limit each,
 *     write only the fields that changed AND are outside their τ window.
 *   - Fields that are skipped this frame are NOT merged into
 *     g_last_committed, so the next frame sees them as still-different and
 *     will retry once the τ window elapses.
 *
 * now_ms MUST be a CLOCK_MONOTONIC timestamp in milliseconds. It is used
 * for the rate-limit comparison and for the per-actuator last-write record.
 *
 * Thread safety: single-writer (control-loop thread).
 */
int  actuation_commit(const coh_actuation_t *a_next, uint64_t now_ms);

/*
 * Release any state held by the actuation layer. Safe to call multiple
 * times. Does NOT revert the system to its pre-daemon state — that is the
 * responsibility of the control loop's shutdown hook.
 */
void actuation_shutdown(void);

/* =========================================================================
 * Diagnostics — exposed on /system/coherence via the AI-daemon bridge.
 * ========================================================================= */

/*
 * Copy the last-committed actuation vector into *out. Safe to call from
 * any thread; the snapshot is a byte-copy. Never fails.
 */
void actuation_get_last(coh_actuation_t *out);

/*
 * Count actuator WRITES (not commits) whose last-write timestamp is at or
 * after `since_ms`. An "effective write" is a sysfs/procfs write that we
 * actually issued — idempotent skips and rate-limit skips do NOT count.
 */
int  actuation_effective_writes_since(uint64_t since_ms);

/*
 * Internal counter access — exposed for tests and the /health endpoint.
 * All values are cumulative since actuation_init().
 */
typedef struct {
	uint64_t commits_total;
	uint64_t idempotent_skips;
	uint64_t rate_limited[COH_ACT_COUNT];
	uint64_t writes_ok[COH_ACT_COUNT];
	uint64_t write_errors[COH_ACT_COUNT];
	uint64_t last_write_ms[COH_ACT_COUNT];
} coh_actuation_stats_t;

void actuation_get_stats(coh_actuation_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* COH_ACTUATION_H */
