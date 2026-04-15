/*
 * ema.c — Exponential-moving-average helpers for the derived-signals layer.
 *
 * Standard recurrence:
 *   x_hat[n] = α·x[n] + (1-α)·x_hat[n-1]
 *
 * On the first call after init (initialized == false), the smoothed value
 * is seeded to the raw sample (don't decay against a zero prior — that
 * artificially suppresses the first ~5 frames of signal).
 *
 * This translation unit is intentionally free of global state. State lives
 * in derived.c's module-static ema_state_t; these are pure helpers.
 *
 * No libm on the hot path. No malloc. -Wall -Wextra -Werror clean.
 */

#include <stdbool.h>
#include <stdint.h>

#include "derived.h"

/* Keep the struct definition local so it's shared with derived.c via this
 * translation unit's header. For build simplicity we expose it here as an
 * internal (non-public) header-less declaration; derived.c includes the
 * same layout.
 *
 * To avoid a header ping-pong, both .c files contain identical definitions
 * guarded by EMA_STATE_T_DEFINED. This is brittle but acceptable for a
 * 2-file module. If a third consumer appears, promote to an internal .h.
 */
#ifndef EMA_STATE_T_DEFINED
#define EMA_STATE_T_DEFINED
typedef struct {
	double ft_var_smooth;       /* α = COH_ALPHA_FT_VAR     = 0.30 */
	double cpu_temp_smooth;     /* α = COH_ALPHA_CPU_TEMP   = 0.20 */
	double sq_latency_smooth;   /* α = COH_ALPHA_SQ_LATENCY = 0.40 */
	double migration_smooth;    /* α = COH_ALPHA_MIGRATION  = 0.30 */
	bool   initialized;         /* false until first fresh sample */
} ema_state_t;
#endif

/* Core recurrence. Branchless when `init_seed` is false; the cold-start
 * branch is taken at most once per process. Inlined aggressively by -O2. */
static inline double ema_step(double prev, double raw, double alpha,
                              bool init_seed)
{
	if (init_seed) {
		return raw;
	}
	return alpha * raw + (1.0 - alpha) * prev;
}

/* Advance all four EMAs in `s` with the latest raw sample drawn from
 * `m`. On the first call after init, all four smoothed values are
 * seeded to their raw counterparts. After that, the standard decay
 * recurrence applies.
 *
 * This is the ONLY function that should ever mutate ema_state_t; both
 * the cold-start seeding and the normal decay path live here. */
void coh_ema_advance(ema_state_t *s, const coh_metrics_t *m);

void coh_ema_advance(ema_state_t *s, const coh_metrics_t *m)
{
	const bool seed = !s->initialized;

	s->ft_var_smooth     = ema_step(s->ft_var_smooth,
	                                m->ft_var_ms2,
	                                COH_ALPHA_FT_VAR,
	                                seed);
	s->cpu_temp_smooth   = ema_step(s->cpu_temp_smooth,
	                                m->cpu_temp_c,
	                                COH_ALPHA_CPU_TEMP,
	                                seed);
	s->sq_latency_smooth = ema_step(s->sq_latency_smooth,
	                                m->sq_latency_us,
	                                COH_ALPHA_SQ_LATENCY,
	                                seed);
	s->migration_smooth  = ema_step(s->migration_smooth,
	                                m->migration_rate,
	                                COH_ALPHA_MIGRATION,
	                                seed);

	s->initialized = true;
}

/* Zero every field, including the initialized flag. Must be called from
 * derived_init() / derived_shutdown(). Deterministic reset. */
void coh_ema_reset(ema_state_t *s);

void coh_ema_reset(ema_state_t *s)
{
	s->ft_var_smooth     = 0.0;
	s->cpu_temp_smooth   = 0.0;
	s->sq_latency_smooth = 0.0;
	s->migration_smooth  = 0.0;
	s->initialized       = false;
}
