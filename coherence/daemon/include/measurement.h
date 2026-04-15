/*
 * measurement.h — Public API for the coherence daemon measurement layer.
 *
 * Ownership:
 *   One and only one thread (the frame scheduler) calls measurement_sample()
 *   once per CONTROL_FRAME (100 ms). The Vulkan setters are called from
 *   whichever thread services the Agent-8 Vulkan layer; they are safe to
 *   invoke concurrently with sample() because we use a seqlock pattern.
 *
 * Contract:
 *   - measurement_init() must be called before any sample().
 *   - measurement_sample() never blocks on I/O beyond a non-blocking read of
 *     cached file descriptors; target wall-time budget is < 2 ms on a
 *     reasonable desktop, < 5 ms worst-case.
 *   - The produced coh_metrics_t::t_ms is timestamped at sample entry
 *     (earliest point in the sample window) so downstream consumers can apply
 *     the COH_VALIDITY_WINDOW_MS guard via coh_m_is_fresh().
 *   - On any single-source failure the function returns a full struct with
 *     the last-known value for the failed field; per-source health bits are
 *     recorded (see measurement_health()).
 *   - Returns 0 on success, -errno if the struct could not be populated at
 *     all (effectively only if init was skipped).
 *
 * Thread safety:
 *   measurement_vulkan_set_frametime() and measurement_vulkan_set_present_mode()
 *   are single-writer / single-reader safe via the sequence-counter
 *   (atomic_store_explicit(release) on the writer side, acquire load on the
 *   reader side). Do NOT call them from more than one writer thread at a time.
 */
#ifndef COH_MEASUREMENT_H
#define COH_MEASUREMENT_H

#include <stdint.h>

#include "coherence_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ===== Lifecycle ===== */

/*
 * Initialise the measurement layer.
 *
 *   game_slice_path: path to the game cgroup (e.g. "/sys/fs/cgroup/game.slice")
 *                    used by future per-slice counters. May be NULL; we only
 *                    record it for later lookup by other subsystems.
 *
 * Returns 0 on success, -errno on unrecoverable failure. Per-source open
 * failures are NOT fatal — they set a fallback and log once.
 */
int  measurement_init(const char *game_slice_path);

/*
 * Populate `out` with a fresh M(t) sample.
 *
 * The t_ms field is stamped at function entry (earliest observable point in
 * the sample window) so downstream consumers get the tightest possible
 * freshness estimate.
 *
 * Every field is always populated; on per-source failure the last good value
 * is reused and the corresponding health bit is cleared.
 *
 * Returns 0 on success. Non-zero only on catastrophic misuse (e.g. called
 * before init).
 */
int  measurement_sample(coh_metrics_t *out);

/*
 * Close all cached FDs, unmap any shared memory, reset internal state.
 */
void measurement_shutdown(void);

/* ===== Vulkan-layer bridge (Agent 8) ===== */

/*
 * Set the current frametime statistics produced by the Vulkan layer's
 * swap-chain tracker. Values are published via a seqlock so sample() always
 * reads a consistent pair.
 *
 *   mean_ms: mean frametime over the last CONTROL_FRAME window, ms
 *   var_ms2: variance over the same window, ms^2 (NOT stddev)
 */
void measurement_vulkan_set_frametime(double mean_ms, double var_ms2);

/*
 * Set the last observed present mode (from VkPresentInfoKHR). Also
 * published via the shared seqlock.
 */
void measurement_vulkan_set_present_mode(coh_present_mode_t mode);

/* ===== Diagnostics (for Agent 3's /health endpoint) ===== */

/*
 * Packed bitfield of per-source health. Bit N set = source N is healthy.
 *
 *   bit 0: /proc/stat (cpu_util, ctx_switch)
 *   bit 1: /sys/.../cpufreq (cpu_freq_khz)
 *   bit 2: /sys/class/thermal OR AI daemon (cpu_temp_c)
 *   bit 3: /proc/interrupts (irq_rate)
 *   bit 4: /proc/schedstat (migration_rate)
 *   bit 5: iouring_stats (sq_depth, sq_latency_us)
 *   bit 6: Vulkan shared-mem (ft_mean_ms, ft_var_ms2, present_mode)
 *   bit 7: /sys/class/drm (gpu_present bit in flags)
 */
uint32_t measurement_health(void);

#ifdef __cplusplus
}
#endif

#endif /* COH_MEASUREMENT_H */
