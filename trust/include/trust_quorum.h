/*
 * trust_quorum.h — 23-slot chromosomal integrity witness (CFT+, not BFT).
 *
 * S74 Agent 8, Cluster 4A. Implements von Neumann's 1956 "Probabilistic
 * Logics and the Synthesis of Reliable Organisms from Unreliable Components"
 * over the paper's existing 23-fold chromosomal redundancy: when we need to
 * decide an authority question we hash across the 23 (A,B) segment pairs
 * rather than trusting any single replica.
 *
 * IMPORTANT — these verdicts are CFT+ integrity witnesses, not BFT votes.
 * ---------------------------------------------------------------------
 * Research-G (docs/research/s74_g_reliability_consensus.md §0) classifies
 * trust_quorum_vote() as a **crash/bit-flip-tolerant chi-square-style
 * consistency check**: replicas are deterministic hashes of a shared
 * chromosomal snapshot, not independent voters with conflicting states.
 * The verdict enum below is therefore named in the language of integrity
 * (CONSISTENT / DISCREPANT / DIVERGENT) rather than consensus
 * (majority / disputed / apoptosis). This closes the S75 §3 Decision 4
 * naming gap flagged by research-G — peer reviewers at USENIX Security /
 * S&P / CCS would (justly) push back on BFT-evocative names for a
 * mechanism that has no actual Byzantine fault model.
 *
 * Verdict meanings:
 *   CONSISTENT  — >=16/23 replicas agree on the bit-state (~2/3 rule);
 *                 quorum is coherent; proceed normally.
 *   DISCREPANT  — 8..15 disagree; single-flip / localized-corruption
 *                 suspect; force FBC slow-path re-evaluation.
 *   DIVERGENT   — <8 agree (tallies collapsed to one side with severe
 *                 disagreement); unrecoverable corruption; recommend
 *                 apoptosis or subject restart.
 *
 * The call is deterministic, non-sleeping, and allocation-free so it is
 * safe on the authz fast-path.
 *
 * See docs/architecture-meta-exploit-s73.md §Cluster 4A and
 *     docs/research/s74_g_reliability_consensus.md §0, §2.3, §2.4.
 */

#ifndef TRUST_QUORUM_H
#define TRUST_QUORUM_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <trust_types.h>        /* trust_subject_t */

enum trust_quorum_verdict {
    TRUST_QUORUM_CONSISTENT = 0,
    TRUST_QUORUM_DISCREPANT = 1,
    TRUST_QUORUM_DIVERGENT  = 2,
};

/* Vote over a single chromosomal field index (0..22).
 *
 * Semantics: produce 23 per-pair "opinion bits" by mixing
 * (A[i], B[i], field_id, subject_id) and counting the majority bit.
 * Returns verdict + fills *agree_count if non-NULL (in 0..23).
 *
 * Out-of-range field_id is clamped to 0..22 (deterministic). */
enum trust_quorum_verdict trust_quorum_vote(const trust_subject_t *s,
                                            u32 field_id,
                                            u32 *agree_count);

/* Specialised vote on the paper's authority score field. */
enum trust_quorum_verdict trust_quorum_vote_authority(const trust_subject_t *s);

/* Init/exit. Registers /sys/kernel/trust/quorum/* counters.
 * Non-fatal on sysfs failure (voting still works). */
int  trust_quorum_init(void);
void trust_quorum_exit(void);

#endif /* __KERNEL__ */

#endif /* TRUST_QUORUM_H */
