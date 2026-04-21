/*
 * trust_quorum.h — Byzantine 2f+1 voting across 23 chromosomal slots.
 *
 * S74 Agent 8, Cluster 4A. Implements von Neumann's 1956 "Probabilistic
 * Logics and the Synthesis of Reliable Organisms from Unreliable Components"
 * over the paper's existing 23-fold chromosomal redundancy: when we need to
 * decide an authority question we vote across the 23 (A,B) segment pairs
 * rather than trusting any single replica.
 *
 * Verdict meanings:
 *   MAJORITY             — >= 16/23 agree (~2/3); proceed normally
 *   DISPUTED             — 8..15 dissent; force FBC slow-path re-evaluation
 *   APOPTOSIS_CANDIDATE  —  >7 dissent; recommend immune response
 *
 * The call is deterministic, non-sleeping, and allocation-free so it is
 * safe on the authz fast-path.
 *
 * See docs/architecture-meta-exploit-s73.md §Cluster 4A.
 */

#ifndef TRUST_QUORUM_H
#define TRUST_QUORUM_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <trust_types.h>        /* trust_subject_t */

enum trust_quorum_verdict {
    TRUST_QUORUM_MAJORITY            = 0,
    TRUST_QUORUM_DISPUTED            = 1,
    TRUST_QUORUM_APOPTOSIS_CANDIDATE = 2,
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
