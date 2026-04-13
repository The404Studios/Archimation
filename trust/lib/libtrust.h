/*
 * libtrust.h - Root of Authority Userspace Library
 *
 * Wraps the /dev/trust ioctl interface for C callers.
 * Used by the PE loader, SCM daemon, and AI control daemon.
 *
 * Provides access to all RoA subsystems:
 *   - RISC fast-path (capability checks, scores)
 *   - FBC complex-path (policy, escalation, propagation)
 *   - Authority Proof Engine (self-consuming proof chain)
 *   - Token Economy (metabolic cost)
 *   - Lifecycle (mitotic division, meiotic combination)
 *   - Immune Response (quarantine, status)
 *   - Chromosome queries (DNA segments, sex determination)
 */

#ifndef LIBTRUST_H
#define LIBTRUST_H

#include <stdint.h>
#include "../include/trust_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize the trust library (opens /dev/trust).
 * Returns 0 on success, -1 on error (e.g., kernel module not loaded).
 */
int trust_init(void);

/*
 * Close the trust library.
 */
void trust_cleanup(void);

/*
 * Check if the library is initialized and /dev/trust is available.
 */
int trust_available(void);

/* --- RISC fast-path operations --- */

/*
 * Check if a subject has a capability.
 * Returns 1 if capable, 0 if not, -1 on error.
 */
int trust_check_capability(uint32_t subject_id, uint32_t capability);

/*
 * Get the current trust score for a subject.
 * Returns the score, or 0 on error.
 */
int32_t trust_get_score(uint32_t subject_id);

/*
 * Record an action performed by a subject.
 * Returns the new trust score after the action, or 0 on error.
 */
int32_t trust_record_action(uint32_t subject_id, uint32_t action, int result);

/*
 * Fast threshold check: can the subject perform this action?
 * Returns TRUST_RESULT_ALLOW (0), TRUST_RESULT_DENY (1), or
 * TRUST_RESULT_ESCALATE (2).
 */
int trust_threshold_check(uint32_t subject_id, uint32_t action);

/* --- FBC complex-path operations --- */

/*
 * Register a new trust subject.
 * Returns 0 on success, -1 on error.
 */
int trust_register_subject(uint32_t subject_id, uint16_t domain,
                           uint32_t authority);

/*
 * Register a subject with a specific initial trust score.
 */
int trust_register_subject_ex(uint32_t subject_id, uint16_t domain,
                              uint32_t authority, int32_t initial_score);

/*
 * Unregister a trust subject.
 */
int trust_unregister_subject(uint32_t subject_id);

/*
 * Request authority escalation.
 * Returns 0 if granted, -1 if denied.
 */
int trust_request_escalation(uint32_t subject_id, uint32_t authority);

/*
 * Full policy evaluation.
 * Returns TRUST_RESULT_ALLOW/DENY/ESCALATE.
 */
int trust_policy_eval(uint32_t subject_id, uint32_t action);

/*
 * Request cross-domain capability transfer via DNA Gate.
 * Returns 0 on success, -1 on denial.
 */
int trust_domain_transfer(uint32_t subject_id, uint16_t from_domain,
                          uint16_t to_domain, uint32_t capabilities);

/*
 * Get full subject information.
 * Returns 0 on success, -1 on error.
 */
int trust_get_subject(uint32_t subject_id, trust_subject_t *out);

/*
 * Propagate a trust delta to a subject (and its dependents).
 * Returns 0 on success, -1 on error.
 */
int trust_propagate(uint32_t subject_id, int32_t delta);

/*
 * Repartition authority boundaries across all subjects.
 * Admin operation. Returns 0 on success, -1 on error.
 */
int trust_repartition(void);

/*
 * Flush the entire trust TLB.
 * Admin operation. Returns 0 on success, -1 on error.
 */
int trust_flush_tlb(void);

/*
 * Read audit entries from the kernel ring buffer.
 * buf must point to space for max_entries audit entries.
 * Returns number of entries read, or -1 on error.
 */
int trust_get_audit(trust_audit_entry_t *buf, uint32_t max_entries);

/* --- Dependency graph operations --- */

/*
 * Add a dependency: subject_id depends on depends_on.
 * When depends_on's trust changes via propagate(), subject_id
 * is also affected (cascading feedback).
 * Returns 0 on success, -1 on error (table full).
 */
int trust_dep_add(uint32_t subject_id, uint32_t depends_on);

/*
 * Remove a dependency.
 * Returns 0 on success, -1 if not found.
 */
int trust_dep_remove(uint32_t subject_id, uint32_t depends_on);

/* --- Escalation queue operations (for AI observer) --- */

/*
 * Poll for a pending escalation request.
 * Fills the output parameters if a request is available.
 * Returns 1 if a request was dequeued, 0 if empty, -1 on error.
 */
int trust_escalation_poll(uint32_t *subject_id, uint32_t *requested_authority,
                          char *justification, uint32_t justification_size,
                          int32_t *current_score, uint32_t *seq);

/*
 * Respond to an escalation request.
 * seq is the sequence number from trust_escalation_poll().
 * approved: 1 = grant escalation, 0 = deny.
 * Returns 0 on success, -1 on error.
 */
int trust_escalation_respond(uint32_t seq, int approved);

/* === Root of Authority: Self-Consuming Proof Chain === */

/*
 * Mint an initial proof token for a subject.
 * proof_out must point to TRUST_PROOF_SIZE (32) bytes.
 * Returns 0 on success, -1 on error.
 */
int trust_proof_mint(uint32_t subject_id, uint8_t *proof_out);

/*
 * Consume proof and get the next one (AUTH_BURN).
 * current_proof is the proof to consume (32 bytes).
 * next_proof_out receives the new proof (32 bytes).
 * Returns 0 on success, -1 if chain is broken.
 */
int trust_proof_consume(uint32_t subject_id, const uint8_t *current_proof,
                         uint32_t action_type, uint32_t action_result,
                         uint8_t *next_proof_out);

/*
 * Invalidate/fence a proof chain (AUTH_FENCE).
 * The subject's authority is irrecoverably destroyed.
 */
int trust_proof_fence(uint32_t subject_id);

/*
 * Verify that a subject's proof chain is intact (read-only).
 * Returns 0 if valid, -1 if broken/invalid.
 */
int trust_proof_verify(uint32_t subject_id);

/*
 * Get the monotonic nonce for a subject's proof chain.
 */
int trust_proof_get_nonce(uint32_t subject_id, uint64_t *nonce_out);

/* === Root of Authority: Token Economy === */

/*
 * Get a subject's token balance.
 * Returns balance, or 0 on error.
 */
int32_t trust_token_balance(uint32_t subject_id);

/*
 * Get a subject's maximum token capacity.
 */
int32_t trust_token_max_balance(uint32_t subject_id);

/*
 * Burn tokens for an action. Returns 0 on success, -ENOSPC if starved.
 * remaining_out receives the balance after burn.
 */
int trust_token_burn_action(uint32_t subject_id, uint32_t action_type,
                             int32_t *remaining_out);

/*
 * Transfer tokens between subjects.
 * Returns 0 on success, -1 on error.
 */
int trust_token_transfer(uint32_t from_subject, uint32_t to_subject,
                          int32_t amount);

/*
 * Get the metabolic cost for an action type.
 */
uint32_t trust_token_get_cost(uint32_t action_type);

/* === Root of Authority: Lifecycle === */

/*
 * Mitotic division: parent spawns child with generational decay.
 * child_max_score_out receives the child's score ceiling.
 * Returns 0 on success, -EPERM if cancer detected, -ENOSPC if starved.
 */
int trust_mitotic_divide(uint32_t parent_id, uint32_t child_id,
                          int32_t *child_max_score_out);

/*
 * Meiotic combination: two entities cooperate.
 * combined_score_out receives min(S(A), S(B)).
 * Returns 0 on success.
 */
int trust_meiotic_combine(uint32_t subject_a, uint32_t subject_b,
                            int32_t *combined_score_out);

/*
 * Release a meiotic combination.
 */
int trust_meiotic_release(uint32_t subject_a, uint32_t subject_b);

/*
 * Initiate apoptosis (controlled death) for a subject.
 * Triggers apoptotic cascade for children.
 */
int trust_apoptosis(uint32_t subject_id);

/* === Root of Authority: Chromosome Queries === */

/*
 * Get full chromosome for a subject.
 * Returns 0 on success, -1 on error.
 */
int trust_get_chromosome(uint32_t subject_id, trust_chromosome_t *out);

/*
 * Get sex determination for a subject.
 * Returns CHROMO_SEX_XX/XY/YX/YY, or -1 on error.
 */
int trust_get_sex(uint32_t subject_id);

/* === Root of Authority: Immune Response === */

/*
 * Get immune status for a subject.
 * Returns TRUST_IMMUNE_* status, or -1 on error.
 */
int trust_immune_status(uint32_t subject_id);

/*
 * Quarantine a subject. Requires elevated privileges.
 * Returns 0 on success, -1 on error.
 */
int trust_quarantine(uint32_t subject_id, uint32_t reason);

/*
 * Release a subject from quarantine.
 * Returns 0 on success, -1 on error.
 */
int trust_release_quarantine(uint32_t subject_id);

#ifdef __cplusplus
}
#endif

#endif /* LIBTRUST_H */
