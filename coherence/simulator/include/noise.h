/*
 * noise.h — Bounded deterministic perturbation model for the offline
 * stability simulator.
 *
 * The simulator calls noise_apply() on every trace frame BEFORE the frame
 * is fed into the measurement ring buffer. The transformation is
 *
 *   frame' = frame + gaussian(seed, sigma_per_field)
 *                  + burst_spike_if(rand01() < burst_prob)
 *                  + periodic_ripple(freq, amplitude, t)
 *
 * All random draws come from an xorshift64* PRNG seeded from
 * sim_noise_cfg_t::seed. Given the same seed + the same frame sequence
 * the output is bit-identical — the whole simulator report is therefore
 * reproducible.
 *
 * Bounds: the noise_apply routine clamps every field to physically
 * plausible values so the system-response model never explodes.
 */
#ifndef COH_SIM_NOISE_H
#define COH_SIM_NOISE_H

#include <stdint.h>

#include "trace.h"

typedef struct {
	uint64_t seed;                   /* PRNG seed — 0 is legal but boring */

	double   gaussian_sigma_ft;      /* ms       ; typical 2.0 – 4.0      */
	double   gaussian_sigma_temp;    /* deg C    ; typical 0.5 – 1.5      */
	double   gaussian_sigma_mig;     /* /s       ; typical 50  – 100      */
	double   gaussian_sigma_io;      /* us       ; typical 20  – 50       */

	double   burst_probability;      /* per-frame; typical 0.01           */
	double   burst_magnitude;        /* multiplier applied to ft+mig      */

	double   periodic_amplitude;     /* fraction of baseline; typ 0.10    */
	double   periodic_freq_hz;       /* typ 0.5 Hz (2 s period)           */
} sim_noise_cfg_t;

/* Populate cfg with sensible defaults (seed = `seed`). */
void noise_cfg_defaults(sim_noise_cfg_t *cfg, uint64_t seed);

/*
 * Mutate *f in place with the configured noise envelope, using `t_ms`
 * as the phase reference for the periodic component. Frame-by-frame
 * deterministic given (cfg, t_ms).
 */
void noise_apply(sim_trace_frame_t *f,
                 const sim_noise_cfg_t *cfg,
                 uint64_t t_ms);

/*
 * Convenience — seedable xorshift64* PRNG. Exposed so sweep.c + the
 * synthetic trace generators can re-use the exact same sequence.
 */
typedef struct { uint64_t s; } sim_prng_t;

void     sim_prng_seed(sim_prng_t *r, uint64_t seed);
uint64_t sim_prng_u64(sim_prng_t *r);
double   sim_prng_uniform01(sim_prng_t *r);   /* [0, 1) */
double   sim_prng_gauss(sim_prng_t *r, double sigma);

#endif /* COH_SIM_NOISE_H */
