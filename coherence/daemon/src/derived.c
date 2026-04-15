/*
 * derived.c — Primary implementation of the derived-signals layer.
 *
 * Responsibilities (in order of execution per derived_compute call):
 *
 *   1. Stale-M guard. If the supplied M(t-k) is older than
 *      COH_VALIDITY_WINDOW_MS, do not advance EMAs — reuse the last
 *      valid D(t) with updated t_ms. This prevents "ghost smoothing"
 *      where a frozen M sample gets repeatedly low-passed into a flat
 *      line that looks stable but is actually dead.
 *
 *   2. EMA smoothing (delegated to ema.c). Four signals:
 *        ft_var_ms2      — frametime variance (ms^2)
 *        cpu_temp_c      — package temperature (°C)
 *        sq_latency_us   — io_uring submission latency (µs)
 *        migration_rate  — task migrations per second
 *
 *   3. Normalized stress metrics (dimensionless):
 *        D_ft_instability = ft_var_smooth / ft_mean^2
 *                           (coefficient-of-variation-squared; scale-free
 *                           measure of frametime chaos)
 *        D_thermal        = (T - 45) / (95 - 45), clamped to [0, 1]
 *                           (0 at idle-warm, 1 at thermal limit)
 *        D_sched_instab   = migration_smooth / 300.0
 *                           (baseline 300 migrations/s ≈ healthy desktop)
 *        D_io_pressure    = sq_latency_smooth / 80.0
 *                           (baseline 80 µs ≈ nominal io_uring latency)
 *
 *      Upper clamps (D_sched ≤ 10, D_io ≤ 20) prevent a single ratty
 *      sample from dominating the composite. Nothing good happens if
 *      migration rate is 3000/s; we just need the signal to saturate.
 *
 *   4. Composite signals:
 *        D_latency_pressure =   COH_W_FT    * D_ft / 0.1
 *                             + COH_W_SCHED * D_sched / 2.5
 *                             + COH_W_IO    * D_io / 2.5
 *      Each divisor is the per-signal entry threshold, so when a single
 *      component is at its own entry threshold it contributes exactly
 *      its weight. When all three are simultaneously at threshold, the
 *      composite hits W_FT + W_SCHED + W_IO = 0.95 ≈ θ_latency_enter=1.0.
 *      This is what makes the threshold a meaningful scalar.
 *
 *        D_system_stress =  COH_W_FT    * D_latency_pressure
 *                         + COH_W_THERM * D_thermal * 10
 *      Thermal is rescaled by 10 so a fully-saturated thermal signal
 *      (D_thermal = 1.0) contributes on the same order as a saturated
 *      latency_pressure (~1.0). Prevents thermal from being dwarfed by
 *      W_THERM = 0.05.
 *
 *   5. Lyapunov candidate (for simulator Agent 7):
 *        V(t) =   w_ft    * D_ft^2
 *               + w_sched * D_sched^2
 *               + w_io    * D_io^2
 *               + w_therm * D_thermal^2
 *      Non-negative, bounded (clamps + 0 ≤ D_thermal ≤ 1). The simulator
 *      verifies E[ΔV] ≤ -αV + β across 500ms actuation frames to prove
 *      stochastic stability.
 *
 * Thread-safety: module-static state; caller must serialize.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "coherence_types.h"
#include "derived.h"

/* Pull in ema_state_t without a shared header (see note in ema.c). */
#ifndef EMA_STATE_T_DEFINED
#define EMA_STATE_T_DEFINED
typedef struct {
	double ft_var_smooth;       /* α = COH_ALPHA_FT_VAR     = 0.30 */
	double cpu_temp_smooth;     /* α = COH_ALPHA_CPU_TEMP   = 0.20 */
	double sq_latency_smooth;   /* α = COH_ALPHA_SQ_LATENCY = 0.40 */
	double migration_smooth;    /* α = COH_ALPHA_MIGRATION  = 0.30 */
	bool   initialized;
} ema_state_t;
#endif

/* Forward-declarations for the helpers that live in ema.c. */
void coh_ema_advance(ema_state_t *s, const coh_metrics_t *m);
void coh_ema_reset(ema_state_t *s);

/* ===== Module-static state ===== */

static ema_state_t          g_ema;
static coh_derived_t        g_last_valid;   /* cached last fresh D(t) */
static bool                 g_have_last;    /* false until first valid compute */

/*
 * R34 typestate tracker. `coh_derived_t.valid` remains in the struct
 * for ABI compatibility with the simulator and the state machine
 * (both of which read d->valid directly). This module-static state
 * carries the richer 4-state typestate and is queried via
 * coh_derived_current_state() by the control loop.
 *
 * Invariants (enforced below via coh_derived_transition_legal):
 *   valid == true  ⇔ state == FRESH
 *   valid == false ⇔ state ∈ {UNINIT, STALE, DEGRADED}
 *
 * g_stale_run counts consecutive stale frames since the last FRESH. Once
 * it reaches COH_DEGRADED_STALE_THRESHOLD, state promotes to DEGRADED.
 * A fresh sample resets it to 0.
 */
#define COH_DEGRADED_STALE_THRESHOLD 3u

static coh_derived_state_t g_derived_state = COH_DERIVED_UNINIT;
static uint32_t            g_stale_run     = 0;

/* Transition helper: log + apply with legality check. On an illegal
 * transition we log and ignore (daemon continues in current state).
 * This is a DIAGNOSTIC path; the table SHOULD make illegal transitions
 * unreachable when the rules below are written correctly. If we ever
 * see "derived_illegal_transition" in the journal, there is a rule bug
 * and it needs a fix. */
static void coh_derived_apply_transition(coh_derived_state_t to, uint64_t now_ms)
{
	if (!coh_derived_transition_legal(g_derived_state, to)) {
		fprintf(stderr,
		        "{\"event\":\"derived_illegal_transition\",\"t_ms\":%llu,"
		        "\"from\":\"%s\",\"to\":\"%s\"}\n",
		        (unsigned long long)now_ms,
		        coh_derived_state_str(g_derived_state),
		        coh_derived_state_str(to));
		return;
	}
	if (g_derived_state == to) {
		/* Self-loop; table permits. Silent (happens every frame). */
		return;
	}
	fprintf(stderr,
	        "{\"event\":\"derived_transition\",\"t_ms\":%llu,"
	        "\"from\":\"%s\",\"to\":\"%s\",\"stale_run\":%u}\n",
	        (unsigned long long)now_ms,
	        coh_derived_state_str(g_derived_state),
	        coh_derived_state_str(to),
	        g_stale_run);
	g_derived_state = to;
}

/* Public accessor. Safe to call from any thread — single atomic enum
 * read, torn-read-safe (aligned int). */
coh_derived_state_t coh_derived_current_state(void)
{
	return g_derived_state;
}

/* ===== Clamp/bounds helpers (branchless, no libm) ===== */

static inline double coh_clamp_d(double x, double lo, double hi)
{
	if (x < lo) return lo;
	if (x > hi) return hi;
	return x;
}

/* Guard: detect zero / near-zero / non-finite. We refuse to divide by
 * anything below 1e-9 ms^2 frametime mean (corresponds to a 1-ns frame,
 * clearly bogus). NaN/Inf handling via the self-not-equal trick to avoid
 * pulling in <math.h> just for isnan/isfinite. */
static inline bool coh_safe_denom(double x)
{
	/* NaN is the only value where x != x. Inf is > DBL_MAX; we compare
	 * against a huge constant rather than pulling DBL_MAX from <float.h>. */
	if (x != x) return false;                  /* NaN */
	if (x > 1e300 || x < -1e300) return false; /* Inf */
	if (x < 1e-9 && x > -1e-9) return false;   /* near-zero */
	return true;
}

/* ===== Public API ===== */

int derived_init(void)
{
	coh_ema_reset(&g_ema);
	memset(&g_last_valid, 0, sizeof(g_last_valid));
	g_have_last     = false;
	g_derived_state = COH_DERIVED_UNINIT;
	g_stale_run     = 0;
	return 0;
}

void derived_shutdown(void)
{
	coh_ema_reset(&g_ema);
	memset(&g_last_valid, 0, sizeof(g_last_valid));
	g_have_last     = false;
	g_derived_state = COH_DERIVED_UNINIT;
	g_stale_run     = 0;
}

void derived_compute(coh_derived_t *out,
                     const coh_metrics_t *m_lagged,
                     uint64_t now_ms)
{
	if (!out || !m_lagged) {
		/* Defensive: never crash on NULL even though contract says non-NULL.
		 * No state transition — we have no information to act on. */
		if (out) {
			memset(out, 0, sizeof(*out));
			out->t_ms = now_ms;
			out->valid = false;
		}
		return;
	}

	/* ========== Phase A: Stale-M freshness guard ========== */
	if (!coh_m_is_fresh(now_ms, m_lagged->t_ms)) {
		if (g_have_last) {
			/* Zero-copy last valid D. Refresh only t_ms + source tag
			 * + valid flag. EMAs are NOT advanced — this is critical
			 * to avoid baking a stale signal into the filter history. */
			*out = g_last_valid;
			out->t_ms          = now_ms;
			out->source_m_t_ms = m_lagged->t_ms;
			out->valid         = false;
		} else {
			/* Cold start + stale M: return a clean zero-init. The
			 * state machine will see valid=false and keep whatever
			 * state it's in (typically NORMAL with no dwell). */
			memset(out, 0, sizeof(*out));
			out->t_ms          = now_ms;
			out->source_m_t_ms = m_lagged->t_ms;
			out->valid         = false;
		}

		/* ===== Typestate transition on stale input =====
		 *   UNINIT   → UNINIT      still no first fresh sample seen
		 *   FRESH    → STALE       aged out
		 *   STALE    → STALE       continuing to age (bump run counter)
		 *   STALE    → DEGRADED    after COH_DEGRADED_STALE_THRESHOLD
		 *                          consecutive stale frames, confidence
		 *                          has collapsed
		 *   DEGRADED → DEGRADED    continued degradation
		 *
		 * Note UNINIT → STALE is forbidden by the table; on cold start
		 * with no prior fresh sample we remain in UNINIT. */
		if (g_derived_state == COH_DERIVED_UNINIT) {
			/* no transition — cold start */
			return;
		}
		g_stale_run++;
		if (g_derived_state == COH_DERIVED_FRESH) {
			coh_derived_apply_transition(COH_DERIVED_STALE, now_ms);
		} else if (g_derived_state == COH_DERIVED_STALE) {
			if (g_stale_run >= COH_DEGRADED_STALE_THRESHOLD) {
				coh_derived_apply_transition(COH_DERIVED_DEGRADED, now_ms);
			}
			/* else: STALE self-loop, silent */
		}
		/* DEGRADED: stays DEGRADED until a fresh sample arrives. */
		return;
	}

	/* ========== Phase B: EMA smoothing ========== */
	coh_ema_advance(&g_ema, m_lagged);

	/* ========== Phase C: Normalized stress metrics ========== */

	/* D_ft_instability = variance / mean^2. Dimensionless (ms^2 / ms^2).
	 * Guard against zero/negative mean — a mean frametime of 0 implies
	 * no frames were rendered (not present mode issue — sampling issue)
	 * and we report 0 instability rather than Inf. */
	double d_ft = 0.0;
	{
		const double ft_mean = m_lagged->ft_mean_ms;
		if (coh_safe_denom(ft_mean)) {
			const double denom = ft_mean * ft_mean;
			if (coh_safe_denom(denom)) {
				d_ft = g_ema.ft_var_smooth / denom;
				if (d_ft < 0.0) d_ft = 0.0; /* variance can't be negative
				                             * after smoothing; belt + braces */
			}
		}
	}

	/* D_thermal = (T - 45) / 50, clamped to [0, 1]. Division is a
	 * compile-time constant, so this reduces to a subtract + multiply. */
	const double d_thermal = coh_clamp_d((g_ema.cpu_temp_smooth - 45.0)
	                                     * (1.0 / 50.0),
	                                     0.0, 1.0);

	/* D_sched_instability — migrations/s normalized to 300/s baseline.
	 * Upper-clamp to 10 so a single 3000/s outlier can't dominate the
	 * composite (would produce latency_pressure ≈ 2.5 on its own). */
	double d_sched = g_ema.migration_smooth * (1.0 / 300.0);
	d_sched = coh_clamp_d(d_sched, 0.0, 10.0);

	/* D_io_pressure — io_uring latency normalized to 80µs baseline.
	 * Upper-clamp to 20 (≈1600µs) for the same reason as d_sched. */
	double d_io = g_ema.sq_latency_smooth * (1.0 / 80.0);
	d_io = coh_clamp_d(d_io, 0.0, 20.0);

	/* ========== Phase D: Composite signals ========== */

	/* Each component is divided by its own entry threshold, so 1.0
	 * per-component ≈ weight contribution. At all-three-at-threshold
	 * simultaneously, latency_pressure ≈ W_FT+W_SCHED+W_IO = 0.95 ≈ 1.0. */
	const double d_latency_pressure =
		  COH_W_FT    * (d_ft    * (1.0 / 0.1))
		+ COH_W_SCHED * (d_sched * (1.0 / 2.5))
		+ COH_W_IO    * (d_io    * (1.0 / 2.5));

	/* system_stress folds the already-composite latency_pressure with
	 * thermal. Thermal is ×10 to bring its [0,1] range into parity with
	 * latency_pressure's ~[0, 1+] range so W_THERM=0.05 actually matters. */
	const double d_system_stress =
		  COH_W_FT    * d_latency_pressure
		+ COH_W_THERM * d_thermal * 10.0;

	/* ========== Phase E: Lyapunov candidate ========== */

	/* V(t) = Σ w_i * D_i^2. All terms non-negative; bounded above by
	 *   W_FT*100 + W_SCHED*100 + W_IO*400 + W_THERM*1 ≈ 140 with our clamps.
	 * The simulator tests E[ΔV] ≤ -αV + β over 500ms actuation frames. */
	const double lyapunov_v =
		  COH_W_FT    * d_ft      * d_ft
		+ COH_W_SCHED * d_sched   * d_sched
		+ COH_W_IO    * d_io      * d_io
		+ COH_W_THERM * d_thermal * d_thermal;

	/* ========== Phase F: Emit D(t) ========== */

	out->t_ms              = now_ms;
	out->source_m_t_ms     = m_lagged->t_ms;
	out->ft_instability    = d_ft;
	out->thermal           = d_thermal;
	out->sched_instability = d_sched;
	out->io_pressure       = d_io;
	out->latency_pressure  = d_latency_pressure;
	out->system_stress     = d_system_stress;
	out->lyapunov_v        = lyapunov_v;
	out->valid             = true;

	/* Cache as last valid snapshot for the next stale-M guard. */
	g_last_valid = *out;
	g_have_last  = true;

	/* ===== Typestate transition on fresh input =====
	 *   UNINIT   → FRESH     first fresh sample after init
	 *   FRESH    → FRESH     continuing fresh (self-loop, silent)
	 *   STALE    → FRESH     recovered
	 *   DEGRADED → FRESH     clean recovery from soft-floor
	 *
	 * Reset the consecutive-stale run counter unconditionally — any
	 * fresh sample clears the confidence-loss countdown. */
	g_stale_run = 0;
	coh_derived_apply_transition(COH_DERIVED_FRESH, now_ms);
}

void derived_get_ema_state(double out_ema[8])
{
	if (!out_ema) return;

	out_ema[0] = g_ema.ft_var_smooth;
	out_ema[1] = g_ema.cpu_temp_smooth;
	out_ema[2] = g_ema.sq_latency_smooth;
	out_ema[3] = g_ema.migration_smooth;
	out_ema[4] = g_have_last ? g_last_valid.latency_pressure : 0.0;
	out_ema[5] = g_have_last ? g_last_valid.system_stress    : 0.0;
	out_ema[6] = g_have_last ? g_last_valid.lyapunov_v       : 0.0;
	/* t_ms as double — 53-bit mantissa represents integer ms losslessly
	 * until well past year 287396 (9e15 ms). Safe cast. */
	out_ema[7] = g_have_last ? (double)g_last_valid.t_ms : 0.0;
}
