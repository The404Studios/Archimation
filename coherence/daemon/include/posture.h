/*
 * posture.h — Composite, atomically-validated actuator.
 *
 * A "posture" is the unit of configuration that MUST be applied together:
 *
 *     game_cpuset + system_cpuset + sqpoll_cpu + epp + min_perf_pct + numa_node
 *
 * These fields have cross-field invariants (e.g. SQPOLL must NOT live on a
 * game-cpuset CPU, game/system cpusets must be disjoint). The earlier design
 * validated each actuator independently; that permits commits where, for
 * example, the SQPOLL cpu was recently-allocated to the game cpuset.
 *
 * `coh_posture_t` replaces that pattern with a typestate machine:
 *
 *     UNINIT → UNVALIDATED (posture_build)
 *     UNVALIDATED → VALIDATED (posture_validate — atomic invariant check)
 *     VALIDATED → COMMITTED (posture_commit_atomic — all-or-nothing write)
 *
 * A failed commit reverts ALL writes it issued, then moves state back to
 * UNVALIDATED so the caller can fix the underlying issue (e.g. a transient
 * EPERM on sysfs) and retry.
 *
 * DRY-RUN MODE:
 *   Set COH_POSTURE_DRY_RUN=1 in the environment to redirect all sysfs /
 *   procfs writes to /tmp/coh_posture_dry/. Used by the test harness and by
 *   the simulator to exercise commit logic without touching the real kernel.
 *
 * THREADING:
 *   posture_commit_atomic() is single-writer. It may sleep on sysfs writes
 *   (frame-edge path, not hot path). The other functions (build/validate/
 *   equal) are pure and reentrant.
 */
#ifndef COH_POSTURE_H
#define COH_POSTURE_H

#include <stdbool.h>
#include <stdint.h>

#include "coherence_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Error codes ----
 *
 * Negative so callers can do `if (rc < 0) { ... }`. Each code names the
 * exact invariant that was violated, so diagnostics can point a human at
 * the offending field without a post-hoc log scrape. */
#define COH_POSTURE_ERR_SQPOLL_IN_GAME_CPUSET  (-1)
#define COH_POSTURE_ERR_CPUSET_OVERLAP         (-2)
#define COH_POSTURE_ERR_MIN_PERF_PCT_RANGE     (-3)
#define COH_POSTURE_ERR_EPP_INVALID            (-4)
#define COH_POSTURE_ERR_NUMA_OUT_OF_RANGE      (-5)
#define COH_POSTURE_ERR_CPUSET_EMPTY           (-6)
#define COH_POSTURE_ERR_STATE                  (-7)
#define COH_POSTURE_ERR_SQPOLL_RANGE           (-8)
#define COH_POSTURE_ERR_CPUSET_SYNTAX          (-9)
#define COH_POSTURE_ERR_WRITE                  (-10)

/*
 * posture_build — populate an UNVALIDATED posture from components.
 *
 * Does NOT validate. The caller is expected to call posture_validate()
 * next. Copies all string fields with bounded length; strings longer than
 * COH_CPUMASK_STRLEN-1 are truncated (defensive — the arbiter never emits
 * more than "0-63" plus delimiters).
 *
 * Zero-initialises all unused trailing bytes so memcmp-based equality
 * (via posture_equal) is deterministic.
 */
void posture_build(coh_posture_t *p,
                   const char *game_cpuset,
                   const char *system_cpuset,
                   int sqpoll_cpu,
                   coh_epp_t epp,
                   int min_perf_pct,
                   int numa_node);

/*
 * posture_validate — enforce ALL cross-field invariants atomically.
 *
 * On success:
 *   - state transitions UNVALIDATED → VALIDATED
 *   - validated_at_ms = now_ms
 *   - returns 0
 *
 * On failure:
 *   - state is left UNVALIDATED
 *   - validated_at_ms is not touched
 *   - returns one of COH_POSTURE_ERR_* (negative)
 *
 * If the current state is not UNVALIDATED (or VALIDATED — re-validate
 * allowed as a no-op that refreshes the timestamp), returns
 * COH_POSTURE_ERR_STATE.
 *
 * Invariants checked, in order (the FIRST to fail is the one reported):
 *   1. epp is in [COH_EPP_DEFAULT, COH_EPP_PERFORMANCE]
 *   2. min_perf_pct is in [0, 100]
 *   3. numa_node is in [-1, 63]    (cap matches COH_MAX_CPUS cpumask width)
 *   4. game_cpuset parses to a non-empty CPU set
 *   5. sqpoll_cpu is -1 or in [0, COH_MAX_CPUS)
 *   6. sqpoll_cpu (if >= 0) is NOT a member of game_cpuset
 *   7. game_cpuset and system_cpuset are disjoint
 */
int posture_validate(coh_posture_t *p, uint64_t now_ms);

/*
 * posture_commit_atomic — write the validated posture to the kernel.
 *
 * Either ALL writes succeed and state transitions VALIDATED → COMMITTED,
 * or NONE of the writes persist and state reverts to UNVALIDATED (so the
 * caller may fix and retry).
 *
 * Write order (chosen so the MOST recoverable writes happen first):
 *     1. game.slice/cpuset.cpus
 *     2. system.slice/cpuset.cpus
 *     3. sqpoll-target (atomic rename)
 *     4. energy_performance_preference (per CPU)
 *     5. min_perf_pct
 *
 * On failure at step N, steps 1..N-1 are ROLLED BACK to the captured
 * pre-commit values. The rollback is best-effort; if rollback ITSELF fails
 * the daemon logs LOUDLY and leaves the state in "half-posture" with an
 * alert — this is very unlikely (the same write that worked moments ago
 * would have to start failing) but we do not silently absorb it.
 *
 * Requires current state == VALIDATED. Returns COH_POSTURE_ERR_STATE
 * otherwise.
 *
 * Honours COH_POSTURE_DRY_RUN=1 to redirect writes under /tmp/coh_posture_dry/.
 */
int posture_commit_atomic(coh_posture_t *p);

/*
 * posture_equal — field-wise equality, ignoring state + validated_at_ms.
 *
 * Used by the idempotent barrier at the posture level. The caller skips
 * commit entirely when next-posture compares equal to last-committed.
 */
bool posture_equal(const coh_posture_t *a, const coh_posture_t *b);

/*
 * posture_error_str — human-readable name for a COH_POSTURE_ERR_* code.
 *
 * Never NULL. Unknown codes return "UNKNOWN".
 * Zero (success) returns "OK".
 */
const char *posture_error_str(int err);

#ifdef __cplusplus
}
#endif

#endif /* COH_POSTURE_H */
