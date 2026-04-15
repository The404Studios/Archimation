/*
 * noise.c — Deterministic stochastic perturbation for trace frames.
 *
 * PRNG: xorshift64* (Marsaglia). Period 2^64 - 1, passes BigCrush on
 * the low bits after the final multiply. We use it for uniform,
 * gaussian (Box-Muller), burst triggers and periodic phases.
 *
 * Determinism: every random draw is derived from r->s; no access to
 * clock, /dev/urandom, or thread-local state. Two invocations with
 * the same seed therefore produce bit-identical perturbed traces.
 *
 * Noise envelope per noise_apply() call:
 *   1. Gaussian micro-jitter on each of (ft_mean, ft_var, temp, mig, io).
 *   2. Bernoulli burst: with probability cfg->burst_probability, multiply
 *      ft_var + migration_rate by cfg->burst_magnitude.
 *   3. Periodic thermal ripple: sin(2*pi*f*t) * amplitude added to temp.
 *
 * Output is clamped to physically plausible ranges so a single noisy
 * sample can never propel the synthetic system-response model into
 * undefined territory.
 */

#define _POSIX_C_SOURCE 200809L

#include "noise.h"

#include <math.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ============================================================
 * xorshift64* PRNG
 * ============================================================ */

void sim_prng_seed(sim_prng_t *r, uint64_t seed)
{
	/* xorshift64* requires non-zero state. Splash 0 → nonzero. */
	r->s = seed ? seed : 0x9E3779B97F4A7C15ULL;
}

uint64_t sim_prng_u64(sim_prng_t *r)
{
	uint64_t x = r->s;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	r->s = x;
	return x * 0x2545F4914F6CDD1DULL;
}

double sim_prng_uniform01(sim_prng_t *r)
{
	/* 53-bit mantissa mapped to [0, 1). */
	uint64_t u = sim_prng_u64(r) >> 11;
	return (double)u * (1.0 / 9007199254740992.0);
}

/*
 * Box-Muller gaussian. Cached return avoids 2-for-1 waste.
 * Cache lives in a local static so it's *not* thread-safe — the
 * simulator is single-threaded and this is fine.
 */
double sim_prng_gauss(sim_prng_t *r, double sigma)
{
	static double cached = 0.0;
	static int    have_cached = 0;

	if (have_cached) {
		have_cached = 0;
		return cached * sigma;
	}

	double u1, u2;
	do {
		u1 = sim_prng_uniform01(r);
	} while (u1 < 1e-12);
	u2 = sim_prng_uniform01(r);

	double mag   = sqrt(-2.0 * log(u1));
	double z0    = mag * cos(2.0 * M_PI * u2);
	double z1    = mag * sin(2.0 * M_PI * u2);

	cached      = z1;
	have_cached = 1;

	return z0 * sigma;
}

/* ============================================================
 * Defaults
 * ============================================================ */

void noise_cfg_defaults(sim_noise_cfg_t *cfg, uint64_t seed)
{
	if (!cfg) return;
	memset(cfg, 0, sizeof(*cfg));
	cfg->seed                = seed;
	cfg->gaussian_sigma_ft   = 3.0;       /* ms */
	cfg->gaussian_sigma_temp = 1.0;       /* deg C */
	cfg->gaussian_sigma_mig  = 80.0;      /* /s */
	cfg->gaussian_sigma_io   = 35.0;      /* us */
	cfg->burst_probability   = 0.01;      /* 1 burst / 100 frames */
	cfg->burst_magnitude     = 2.5;       /* ft_var + mig doubled+ */
	cfg->periodic_amplitude  = 0.10;      /* 10% of baseline */
	cfg->periodic_freq_hz    = 0.5;       /* 2 s period */
}

/* ============================================================
 * Apply noise to a frame
 * ============================================================ */

static double clamp(double x, double lo, double hi)
{
	if (x < lo) return lo;
	if (x > hi) return hi;
	return x;
}

void noise_apply(sim_trace_frame_t *f,
                 const sim_noise_cfg_t *cfg,
                 uint64_t t_ms)
{
	if (!f || !cfg) return;

	/*
	 * Derive a per-frame PRNG state so the exact same (cfg, t_ms)
	 * always yields the same draws — independent of how many times
	 * noise_apply has been called on earlier frames.
	 *
	 * Mixing function: splitmix64-style on seed ^ t_ms so that
	 * neighbouring t_ms values don't produce correlated streams.
	 */
	uint64_t mix = cfg->seed ^ (t_ms * 0x9E3779B97F4A7C15ULL);
	sim_prng_t r; sim_prng_seed(&r, mix);

	/* 1. Gaussian micro-jitter. */
	f->ft_mean_ms     += sim_prng_gauss(&r, cfg->gaussian_sigma_ft);
	f->ft_var_ms2     += sim_prng_gauss(&r, cfg->gaussian_sigma_ft * 0.3);
	f->cpu_temp_c     += sim_prng_gauss(&r, cfg->gaussian_sigma_temp);
	f->migration_rate += sim_prng_gauss(&r, cfg->gaussian_sigma_mig);
	f->sq_latency_us  += sim_prng_gauss(&r, cfg->gaussian_sigma_io);
	f->irq_rate_sum   += sim_prng_gauss(&r, cfg->gaussian_sigma_mig * 2.0);

	/* 2. Burst spike. */
	if (sim_prng_uniform01(&r) < cfg->burst_probability) {
		f->ft_var_ms2     *= cfg->burst_magnitude;
		f->migration_rate *= cfg->burst_magnitude;
		f->sq_latency_us  *= 1.0 + (cfg->burst_magnitude - 1.0) * 0.5;
		if (f->injected_noise_class == TRACE_NOISE_NONE)
			f->injected_noise_class = TRACE_NOISE_BURST;
	}

	/* 3. Periodic thermal ripple. */
	if (cfg->periodic_amplitude > 0.0 && cfg->periodic_freq_hz > 0.0) {
		double t_s = (double)t_ms / 1000.0;
		double ripple = cfg->periodic_amplitude * f->cpu_temp_c
		              * sin(2.0 * M_PI * cfg->periodic_freq_hz * t_s);
		f->cpu_temp_c += ripple;
		if (f->injected_noise_class == TRACE_NOISE_NONE)
			f->injected_noise_class = TRACE_NOISE_PERIODIC;
	}

	/* 4. Clamp to physical ranges. */
	f->ft_mean_ms     = clamp(f->ft_mean_ms,     1.0,   200.0);
	f->ft_var_ms2     = clamp(f->ft_var_ms2,     0.01,  1.0e4);
	f->cpu_temp_c     = clamp(f->cpu_temp_c,     20.0,  110.0);
	f->migration_rate = clamp(f->migration_rate, 0.0,   5.0e4);
	f->sq_latency_us  = clamp(f->sq_latency_us,  0.0,   1.0e5);
	f->irq_rate_sum   = clamp(f->irq_rate_sum,   0.0,   1.0e6);
}
