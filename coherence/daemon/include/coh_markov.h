/*
 * coh_markov.h — Empirical Markov chain over the arbiter's 4 base named
 *                states (NORMAL, LATENCY_CRITICAL, THERMAL_CONSTRAINED,
 *                DEGRADED).
 *
 * GAME_FOREGROUND (enum value 4) is intentionally OUT OF SCOPE for this
 * observational chain — it is not signal-driven, it is operator-driven by
 * the cortex CoherenceBridge, and including it would conflate two
 * distinct generative processes in one transition matrix.
 *
 * Pure observation: this module reads no system state, writes no
 * actuation, allocates no memory after init, and never blocks. Safe to
 * call from the multi-rate scheduler's inner loop.
 */
#ifndef COH_MARKOV_H
#define COH_MARKOV_H

#include <stdint.h>
#include <stddef.h>

#include "state_machine.h"  /* coh_state_t */

/* The 4 base states form the matrix; values >= COH_MARKOV_N are dropped
 * silently in coh_markov_observe (GAME_FOREGROUND, COH_STATE_COUNT). */
#define COH_MARKOV_N 4

/* Idempotent zero-init. May be called more than once; subsequent calls
 * are a no-op once the chain is armed. */
void coh_markov_init(void);

/* Record one prev → next transition. Out-of-range states (>= 4) are
 * silently ignored so callers do not need to filter GAME_FOREGROUND
 * before invoking us. Atomic increment — multi-threader-safe. */
void coh_markov_observe(coh_state_t prev, coh_state_t next);

/* Read the raw count for a single cell. Returns 0 for out-of-range. */
uint64_t coh_markov_count(coh_state_t prev, coh_state_t next);

/* Compute the row-normalized empirical transition matrix.
 * Returns 0 on success, -1 if no observations have ever been recorded.
 * Empty rows (state never observed as `prev`) are zero-filled. */
int coh_markov_matrix(double out[COH_MARKOV_N][COH_MARKOV_N]);

/* Power-iterate the empirical matrix to recover its stationary
 * distribution (left eigenvector for eigenvalue 1). Starts from the
 * uniform distribution and runs 64 iterations — sufficient for the
 * 4-state chain to settle within IEEE-754 noise on any non-degenerate
 * matrix. Returns 0 on success, -1 if the matrix has no transitions. */
int coh_markov_stationary(double out[COH_MARKOV_N]);

/* Serialise the current chain as JSON:
 *   {"observations":N,"matrix":[[...]],"stationary":[...]}
 * Returns bytes written (excluding trailing NUL) on success, or -1 if
 * the buffer would have been truncated. */
int coh_markov_to_json(char *buf, size_t buflen);

#endif /* COH_MARKOV_H */
