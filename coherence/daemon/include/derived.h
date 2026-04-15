/*
 * derived.h — Derived-signals layer of the coherence daemon.
 *
 * Consumes coh_metrics_t (raw M(t)) and produces coh_derived_t (D(t)) via:
 *   1. Stale-M freshness guard (reuses last valid D on stale input).
 *   2. Per-signal exponential moving average (EMA) smoothing.
 *   3. Normalized, dimensionless stress metrics (ft/thermal/sched/io).
 *   4. Weighted composite signals: latency_pressure + system_stress.
 *   5. Lyapunov candidate V(t) for the offline stability simulator.
 *
 * Thread-safety: Caller must serialize derived_compute; state is
 * process-wide. Expected single-writer is the control-loop thread.
 *
 * Determinism: Given the same sequence of M(t) inputs starting from a
 * freshly init'd module, the output D(t) sequence is byte-identical.
 * This is a hard requirement so the simulator can replay traces.
 *
 * Allocation: No malloc. All state is module-static.
 *
 * Public contract matches the phase model in coherence_types.h:
 *   derivation phase [100–250ms] consumes M(t - k*CONTROL_FRAME), k >= 2.
 */
#ifndef COH_DERIVED_H
#define COH_DERIVED_H

#include <stdint.h>

#include "coherence_types.h"

/* Initialize the derivation module.
 * Zeroes EMA state, clears the cached previous-D. Always succeeds.
 * Returns 0. */
int  derived_init(void);

/* Compute D(t) from a lagged M(t-k) snapshot.
 *
 *   out       : destination coh_derived_t; must be non-NULL.
 *   m_lagged  : lagged M-sample (expected lag k >= COH_DERIVATION_LAG_K
 *               frames). May be stale on cold start; the guard handles it.
 *   now_ms    : monotonic wall-clock at the derivation phase boundary.
 *
 * Stale behavior: if coh_m_is_fresh(now_ms, m_lagged->t_ms) is false,
 * *out is populated by zero-copying the last valid D (if any) with
 * updated t_ms + source_m_t_ms, and out->valid = false. EMA state is
 * NOT advanced on stale input (no ghost smoothing). If no prior valid
 * D exists (cold start + stale), *out is zero-initialized and valid=false.
 *
 * On fresh input, advances EMAs, computes all derived signals, sets
 * out->valid = true, and caches *out as the new "last valid" snapshot.
 */
void derived_compute(coh_derived_t *out,
                     const coh_metrics_t *m_lagged,
                     uint64_t now_ms);

/* Tear down module state. Currently just zeroes EMA buffers; present for
 * symmetry + future allocation-safety. */
void derived_shutdown(void);

/* R34 typestate accessor. Returns the current coh_derived_state_t.
 *
 * Valid states:
 *   COH_DERIVED_UNINIT   — derived_init called, no successful compute yet
 *   COH_DERIVED_FRESH    — last compute had a fresh M source + EMAs advanced
 *   COH_DERIVED_STALE    — last compute saw stale M; EMAs frozen
 *   COH_DERIVED_DEGRADED — COH_DEGRADED_STALE_THRESHOLD (=3) stale frames
 *                          in a row; confidence is below threshold
 *
 * Transition table: see state_machine_tables.c (derived_trans).
 * The state machine consumers should branch on this instead of the
 * legacy coh_derived_t.valid field (which remains for simulator ABI
 * compatibility). */
coh_derived_state_t coh_derived_current_state(void);

/* Introspection hook for the simulator and /system/coherence endpoint.
 *
 * Fills the 8-slot array with a live snapshot of internal state:
 *
 *   out[0] = ft_var_smooth       (EMA, α = 0.30)
 *   out[1] = cpu_temp_smooth     (EMA, α = 0.20)
 *   out[2] = sq_latency_smooth   (EMA, α = 0.40)
 *   out[3] = migration_smooth    (EMA, α = 0.30)
 *   out[4] = D_latency_pressure  (last composite)
 *   out[5] = D_system_stress     (last composite)
 *   out[6] = lyapunov_v          (last V(t))
 *   out[7] = last_t_ms as double (UNIX ms; 53-bit precision sufficient
 *                                 through year 287396)
 *
 * Safe to call from a different thread for read-only display purposes;
 * the fields are plain doubles and torn reads will at worst show a
 * momentarily inconsistent snapshot — never a crash. */
void derived_get_ema_state(double out_ema[8]);

#endif /* COH_DERIVED_H */
