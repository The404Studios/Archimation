/*
 * coh_markov.c — Empirical Markov chain over the arbiter's 4 base named
 *                states (NORMAL, LATENCY_CRITICAL, THERMAL_CONSTRAINED,
 *                DEGRADED). Purely observational; no actuator side
 *                effects. Hooked from state_machine.c immediately after
 *                the `arb->state = new_state` assignment in
 *                coh_enter_state.
 *
 * Concurrency model:
 *   - g_counts cells are bumped with __atomic_fetch_add(RELAXED). The
 *     scheduler is single-writer per arbiter today (S33+) but
 *     pool_metrics.c spawns a 1-Hz aggregator thread (see Makefile
 *     comment) and JSON readers may run from another context, so we
 *     pay the (negligible) atomic cost rather than rely on a
 *     contingent invariant.
 *   - g_initialized uses release/acquire ordering so a late init
 *     racing with an early observe() either fully observes the zeroed
 *     matrix or skips the bump entirely.
 *   - matrix() / stationary() / to_json() take a snapshot via
 *     __atomic_load_n(RELAXED) per cell; the resulting matrix is
 *     therefore not strictly transactionally consistent across all 16
 *     cells but each cell is itself torn-read-free, which is what
 *     matters for empirical reporting at human timescales.
 */

#include "coh_markov.h"

#include <stdio.h>
#include <string.h>

/* --------- module state --------- */

static uint64_t g_counts[COH_MARKOV_N][COH_MARKOV_N];
static int      g_initialized;  /* 0 = unarmed, 1 = armed */

/* --------- helpers --------- */

static inline int coh_markov_in_range(coh_state_t s)
{
	/* coh_state_t is an enum; cast through int to avoid signed-vs-
	 * unsigned warnings under -Wsign-compare. NORMAL = 0; out-of-range
	 * covers both GAME_FOREGROUND (4), COH_STATE_COUNT (5), and any
	 * future or corrupted value. */
	int v = (int)s;
	return (v >= 0) && (v < COH_MARKOV_N);
}

static uint64_t coh_markov_total_observations(void)
{
	uint64_t total = 0;
	for (int i = 0; i < COH_MARKOV_N; i++) {
		for (int j = 0; j < COH_MARKOV_N; j++) {
			total += __atomic_load_n(&g_counts[i][j], __ATOMIC_RELAXED);
		}
	}
	return total;
}

static void coh_markov_snapshot(uint64_t snap[COH_MARKOV_N][COH_MARKOV_N])
{
	for (int i = 0; i < COH_MARKOV_N; i++) {
		for (int j = 0; j < COH_MARKOV_N; j++) {
			snap[i][j] = __atomic_load_n(&g_counts[i][j],
			                             __ATOMIC_RELAXED);
		}
	}
}

/* --------- public API --------- */

void coh_markov_init(void)
{
	/* Idempotent: if another caller already armed the chain, leave the
	 * accumulated counts intact. The zero on first arm is provided by
	 * BSS — we just need the publication barrier so observers see
	 * g_initialized = 1 only after any prior writes have drained. */
	if (__atomic_load_n(&g_initialized, __ATOMIC_ACQUIRE) != 0)
		return;
	memset(g_counts, 0, sizeof(g_counts));
	__atomic_store_n(&g_initialized, 1, __ATOMIC_RELEASE);
}

void coh_markov_observe(coh_state_t prev, coh_state_t next)
{
	if (__atomic_load_n(&g_initialized, __ATOMIC_ACQUIRE) == 0)
		return;
	if (!coh_markov_in_range(prev) || !coh_markov_in_range(next))
		return;
	__atomic_fetch_add(&g_counts[(int)prev][(int)next], 1u,
	                   __ATOMIC_RELAXED);
}

uint64_t coh_markov_count(coh_state_t prev, coh_state_t next)
{
	if (!coh_markov_in_range(prev) || !coh_markov_in_range(next))
		return 0;
	return __atomic_load_n(&g_counts[(int)prev][(int)next],
	                       __ATOMIC_RELAXED);
}

int coh_markov_matrix(double out[COH_MARKOV_N][COH_MARKOV_N])
{
	if (!out) return -1;

	uint64_t snap[COH_MARKOV_N][COH_MARKOV_N];
	coh_markov_snapshot(snap);

	uint64_t total = 0;
	for (int i = 0; i < COH_MARKOV_N; i++) {
		for (int j = 0; j < COH_MARKOV_N; j++) {
			total += snap[i][j];
		}
	}
	if (total == 0) {
		/* No data — leave caller's buffer in a known-zero state and
		 * report failure so they can distinguish "no data yet" from
		 * "uniform-noise legitimate distribution". */
		memset(out, 0, sizeof(double) * COH_MARKOV_N * COH_MARKOV_N);
		return -1;
	}

	for (int i = 0; i < COH_MARKOV_N; i++) {
		uint64_t row_total = 0;
		for (int j = 0; j < COH_MARKOV_N; j++) {
			row_total += snap[i][j];
		}
		if (row_total == 0) {
			/* This state has never been observed as `prev`; emit a
			 * zero row rather than an absorbing-self loop, which
			 * would lie about the empirical evidence. Power
			 * iteration treats this as an absorbing-zero row, which
			 * is correct: an unobserved source contributes no mass. */
			for (int j = 0; j < COH_MARKOV_N; j++) {
				out[i][j] = 0.0;
			}
		} else {
			double inv = 1.0 / (double)row_total;
			for (int j = 0; j < COH_MARKOV_N; j++) {
				out[i][j] = (double)snap[i][j] * inv;
			}
		}
	}
	return 0;
}

int coh_markov_stationary(double out[COH_MARKOV_N])
{
	if (!out) return -1;

	double P[COH_MARKOV_N][COH_MARKOV_N];
	if (coh_markov_matrix(P) != 0) {
		for (int i = 0; i < COH_MARKOV_N; i++) out[i] = 0.0;
		return -1;
	}

	/* Power method on the LEFT (row) eigenvector: π_{k+1} = π_k · P.
	 * Start from uniform; renormalize after every iteration so any
	 * mass dropped through zero rows is redistributed proportionally
	 * to the surviving probability mass. 64 iterations >> mixing time
	 * for a 4x4 chain with reasonable spectral gap. */
	double pi[COH_MARKOV_N];
	double next[COH_MARKOV_N];
	for (int i = 0; i < COH_MARKOV_N; i++) pi[i] = 1.0 / (double)COH_MARKOV_N;

	for (int iter = 0; iter < 64; iter++) {
		for (int j = 0; j < COH_MARKOV_N; j++) next[j] = 0.0;
		for (int i = 0; i < COH_MARKOV_N; i++) {
			for (int j = 0; j < COH_MARKOV_N; j++) {
				next[j] += pi[i] * P[i][j];
			}
		}
		double norm = 0.0;
		for (int j = 0; j < COH_MARKOV_N; j++) norm += next[j];
		if (norm <= 0.0) {
			/* All mass leaked into zero rows. Surface as failure
			 * rather than emit a bogus uniform vector. */
			for (int j = 0; j < COH_MARKOV_N; j++) out[j] = 0.0;
			return -1;
		}
		double inv = 1.0 / norm;
		for (int j = 0; j < COH_MARKOV_N; j++) pi[j] = next[j] * inv;
	}

	for (int i = 0; i < COH_MARKOV_N; i++) out[i] = pi[i];
	return 0;
}

int coh_markov_to_json(char *buf, size_t buflen)
{
	if (!buf || buflen == 0) return -1;

	double P[COH_MARKOV_N][COH_MARKOV_N];
	double pi[COH_MARKOV_N];
	int has_matrix = (coh_markov_matrix(P) == 0);
	int has_stat   = has_matrix && (coh_markov_stationary(pi) == 0);
	uint64_t total = coh_markov_total_observations();

	/* If we have no data, emit a null matrix/stationary so consumers
	 * can detect the cold-start case without parser-special-casing. */
	if (!has_matrix) {
		for (int i = 0; i < COH_MARKOV_N; i++) {
			for (int j = 0; j < COH_MARKOV_N; j++) P[i][j] = 0.0;
		}
	}
	if (!has_stat) {
		for (int i = 0; i < COH_MARKOV_N; i++) pi[i] = 0.0;
	}

	size_t off = 0;
	int rc;

	rc = snprintf(buf + off, buflen - off,
	              "{\"observations\":%llu,\"matrix\":[",
	              (unsigned long long)total);
	if (rc < 0 || (size_t)rc >= buflen - off) return -1;
	off += (size_t)rc;

	for (int i = 0; i < COH_MARKOV_N; i++) {
		rc = snprintf(buf + off, buflen - off, "%s[", i == 0 ? "" : ",");
		if (rc < 0 || (size_t)rc >= buflen - off) return -1;
		off += (size_t)rc;
		for (int j = 0; j < COH_MARKOV_N; j++) {
			rc = snprintf(buf + off, buflen - off, "%s%.6f",
			              j == 0 ? "" : ",", P[i][j]);
			if (rc < 0 || (size_t)rc >= buflen - off) return -1;
			off += (size_t)rc;
		}
		rc = snprintf(buf + off, buflen - off, "]");
		if (rc < 0 || (size_t)rc >= buflen - off) return -1;
		off += (size_t)rc;
	}

	rc = snprintf(buf + off, buflen - off, "],\"stationary\":[");
	if (rc < 0 || (size_t)rc >= buflen - off) return -1;
	off += (size_t)rc;

	for (int i = 0; i < COH_MARKOV_N; i++) {
		rc = snprintf(buf + off, buflen - off, "%s%.6f",
		              i == 0 ? "" : ",", pi[i]);
		if (rc < 0 || (size_t)rc >= buflen - off) return -1;
		off += (size_t)rc;
	}

	rc = snprintf(buf + off, buflen - off, "]}");
	if (rc < 0 || (size_t)rc >= buflen - off) return -1;
	off += (size_t)rc;

	return (int)off;
}
