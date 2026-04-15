/*
 * trace.h — Offline simulator trace format.
 *
 * A trace is a sequence of sim_trace_frame_t records sampled at
 * COH_CONTROL_FRAME_MS (100 ms) cadence. The simulator replays traces
 * through its internal state-machine + derivation pipeline, applies
 * bounded stochastic noise, and emits a stability report.
 *
 * Binary layout (little-endian, tightly packed, no hidden padding inside
 * the header — struct padding inside the frame array is platform ABI
 * dependent but stable for the targeted x86_64 ABI):
 *
 *   offset  size  field
 *   ------  ----  ---------------------------------------
 *     0      4    magic          = 'C','O','H','T'
 *     4      4    version        = TRACE_VERSION (uint32 LE)
 *     8      4    count          = number of frames (uint32 LE)
 *    12      4    reserved       = 0
 *    16      N    frames[count]  = sim_trace_frame_t packed array
 *
 *   N = count * sizeof(sim_trace_frame_t)
 *
 * Reproducibility: trace_save is bit-identical for a given frame array.
 * trace_load validates magic+version and refuses anything else.
 */
#ifndef COH_SIM_TRACE_H
#define COH_SIM_TRACE_H

#include <stdint.h>
#include <stddef.h>

#define TRACE_MAGIC      0x54484F43u /* 'COHT' little-endian */
#define TRACE_VERSION    1u

/* Noise class tags carried on each frame so reports can show when the
 * simulator injected a perturbation that exercised a given code path. */
#define TRACE_NOISE_NONE        0u
#define TRACE_NOISE_BURST       1u
#define TRACE_NOISE_PERIODIC    2u
#define TRACE_NOISE_ADVERSARIAL 3u

/*
 * Canonical trace frame. Must stay fixed-size + stable on x86_64 for
 * the on-disk format to be reproducible. The explicit `reserved` pad
 * keeps total size at 64 bytes (8 + 48 + 8) with no hidden compiler
 * padding — this is what makes the on-disk file byte-stable across
 * toolchains.
 */
typedef struct {
	uint64_t t_ms;                    /* monotonic ms; strictly increasing */

	double   ft_mean_ms;              /* raw frametime mean              */
	double   ft_var_ms2;              /* raw frametime variance          */
	double   cpu_temp_c;              /* raw package temp, deg C         */
	double   migration_rate;          /* sched migrations per second     */
	double   sq_latency_us;           /* io_uring completion latency us  */
	double   irq_rate_sum;            /* aggregate IRQ rate / second     */

	uint32_t injected_noise_class;    /* TRACE_NOISE_*                   */
	uint32_t reserved;                /* pad to 8-byte alignment, = 0    */
} sim_trace_frame_t;

/*
 * Load a binary trace from `path`. On success, *out is heap-allocated
 * (caller frees with free()) and *count is set. Returns 0 on success,
 * -1 on any error (file missing, bad magic, bad version, truncated).
 *
 * On failure *out is set to NULL and *count to 0.
 */
int trace_load(const char *path, sim_trace_frame_t **out, size_t *count);

/*
 * Save `count` frames to `path`. Creates/overwrites atomically via a
 * .tmp-rename dance so partial writes can't corrupt a previously good
 * trace. Returns 0 on success, -1 on error.
 */
int trace_save(const char *path,
               const sim_trace_frame_t *frames,
               size_t count);

/*
 * Synthetic trace generators. Each produces a deterministic sequence
 * given the same seed; no I/O. Caller owns the returned buffer.
 *
 *   steady        : 10 min of gameplay-like M(t); ft=16ms mean, var 3ms^2.
 *   thermal_storm : 5  min with periodic thermal spikes to ~92 deg C.
 *   burst_load    : 5  min with migration bursts; exercises latency path.
 *
 * Return 0 on success, -1 on allocation failure.
 */
int trace_gen_steady(sim_trace_frame_t **out, size_t *count, uint64_t seed);
int trace_gen_thermal_storm(sim_trace_frame_t **out, size_t *count, uint64_t seed);
int trace_gen_burst_load(sim_trace_frame_t **out, size_t *count, uint64_t seed);

/* On-disk layout invariant. If this fails the format is no longer
 * byte-stable and every existing .bin must be regenerated. */
_Static_assert(sizeof(sim_trace_frame_t) == 64,
               "sim_trace_frame_t must be exactly 64 bytes on disk");

#endif /* COH_SIM_TRACE_H */
