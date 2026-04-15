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

/* ====================================================================
 * Library version & ABI contract
 *
 * LIBTRUST_ABI_MAJOR is bumped on incompatible ABI changes (soname bump).
 * LIBTRUST_ABI_MINOR is bumped on additive changes (same soname).
 *
 * Session history:
 *   v1.0 - initial (ioctl wrappers only)
 *   v1.1 - atomic-fd-snapshot hot path (Session 30)
 *   v1.2 - batch submission, binary event stream, compressed event log,
 *          typed predicate/VEC/fused helpers (this session)
 * ==================================================================== */

#define LIBTRUST_ABI_MAJOR      1
#define LIBTRUST_ABI_MINOR      2

/*
 * trust_library_version - Return ABI version encoded as (major<<16)|minor.
 *
 * Ownership: returns a scalar, no allocation.
 * Thread-safety: safe, reads compile-time constants.
 */
uint32_t trust_library_version(void);

/*
 * trust_probe_caps - Populate *features with TRUST_FEAT_* bitmask for the
 * running kernel. Returns 0 on success, -1 if /dev/trust is not open or
 * the kernel predates the QUERY_CAPS ioctl (in which case *features is
 * cleared, letting callers treat "unknown" as "no extensions").
 *
 * Ownership: caller provides pointer, libtrust fills it.
 * Thread-safety: safe; result is a per-call ioctl snapshot.
 */
int trust_probe_caps(uint32_t *features,
                     uint32_t *max_batch_ops,
                     uint32_t *max_vec_count);

/* ====================================================================
 * (A) Batch submission
 *
 * Accumulate up to `max_ops` logical operations, then submit in one
 * ioctl round-trip. Internally uses varint + delta encoding (and the
 * VECTOR family if the kernel supports it); falls back to one
 * trust_cmd_entry_t per logical op otherwise.
 *
 * Lifetime:   caller owns the trust_batch_t*; must free with
 *             trust_batch_free() even after a failed submit.
 * Threading:  a trust_batch_t* is NOT thread-safe; each thread should
 *             own its own batch. The submit path re-uses the
 *             process-global /dev/trust fd which is already shared-safe.
 * ==================================================================== */

typedef struct trust_batch trust_batch_t;

/*
 * trust_batch_new - Allocate a new batch that can hold up to `max_ops`
 * logical operations. Returns NULL on OOM or if max_ops > TRUST_ISA_MAX_BATCH_OPS.
 */
trust_batch_t *trust_batch_new(size_t max_ops);

/*
 * trust_batch_decay - Queue a VEC_OP_DECAY across `count` subject IDs
 * (auto-sorted internally for best delta compression). Returns 0 on
 * success, -1 on overflow or invalid args.
 */
int trust_batch_decay(trust_batch_t *b, const uint32_t *subject_ids,
                      size_t count);

/*
 * trust_batch_escalate_check - Queue VEC_OP_ESCALATE_CHECK; kernel
 * returns a bitmap (one bit per subject, LSB=subject_ids[0]) of subjects
 * eligible for escalation at the given threshold. out_bitmap is written
 * on submit.
 *
 * out_bitmap must be caller-provided, long enough for (count+63)/64 u64
 * words; libtrust writes at most (count+63)/64 words on submit.
 *
 * Returns 0 on success, -1 on overflow.
 */
int trust_batch_escalate_check(trust_batch_t *b, const uint32_t *subject_ids,
                               size_t count, uint32_t threshold,
                               uint64_t *out_bitmap);

/*
 * trust_batch_fused_auth_gate - Queue AUTH_OP_VERIFY_THEN_GATE (fused
 * pair). Atomically verifies the subject's proof chain and, if valid,
 * checks cross-domain gate permission for `policy_id`. Much cheaper
 * than two round-trips.
 *
 * Returns 0 on success, -1 on overflow.
 */
int trust_batch_fused_auth_gate(trust_batch_t *b, uint32_t subject_id,
                                uint32_t policy_id);

/*
 * trust_batch_submit - Submit the accumulated ops in ONE ioctl. After
 * return, any out_* pointers previously registered (e.g. out_bitmap)
 * are populated.
 *
 * Returns number of ops the kernel executed (>=0), or -1 on ioctl error
 * (errno preserved). Zero-op batches return 0 without calling ioctl.
 */
int trust_batch_submit(trust_batch_t *b);

/*
 * trust_batch_free - Release a trust_batch_t and any internal buffers
 * it owns. Safe to call with NULL.
 */
void trust_batch_free(trust_batch_t *b);

/* ====================================================================
 * (B) Binary event stream
 *
 * Opens a per-client events fd and unpacks 8-byte wire records into
 * trust_event_t structs. Falls back gracefully if the kernel lacks
 * TRUST_FEAT_EVT_BINARY: trust_events_open returns -1 with errno=ENOTSUP.
 *
 * Lifetime:   the events fd is closed by trust_cleanup() along with the
 *             main /dev/trust fd.
 * Threading:  single-reader per fd; multiple threads sharing a fd must
 *             serialize reads themselves.
 * ==================================================================== */

typedef struct {
	uint8_t  type;        /* TRUST_EVT_* */
	uint8_t  flags;       /* TRUST_EVF_* bit-packed */
	uint16_t _padding;
	uint32_t subject;     /* subject_id (upper bits zero if kernel sent u16) */
	uint32_t cost;        /* post-multiplier metabolic cost */
	uint64_t ts_ns;       /* absolute timestamp (ns since open) */
} trust_event_t;

/*
 * trust_events_open - Open the per-client events fd via ioctl.
 * Returns 0 on success, -1 on error. On ENOTSUP callers should fall
 * back to polling trust_get_audit().
 */
int trust_events_open(void);

/*
 * trust_events_read - Read and decode up to `max_events` packed records
 * from the events fd into `ev[]`. Returns the count read (may be 0 if
 * the fd is non-blocking and nothing is pending), or -1 on error.
 *
 * The call consumes an exact multiple of sizeof(trust_event_packed_t)
 * bytes from the fd to avoid splitting a record across reads.
 */
int trust_events_read(trust_event_t *ev, int max_events);

/*
 * trust_events_close - Close the events fd. Idempotent.
 */
void trust_events_close(void);

/* ====================================================================
 * (C) Compressed event log
 *
 * Persist a rotating series of binary event segments to disk. The live
 * segment is raw for fast appends; rotated segments are zstd-compressed
 * at level 3 by default (~300 MB/s on P4-era CPUs; 3-5x shrink on the
 * low-entropy event data).
 *
 * Lifetime:   caller owns trust_log_t*; must close with trust_log_close.
 * Threading:  a trust_log_t* is NOT thread-safe. Wrap with a mutex if
 *             multiple threads append.
 * ==================================================================== */

typedef struct trust_log trust_log_t;

#define TRUST_LOG_ZSTD          (1U << 0)  /* compress rotated segments */
#define TRUST_LOG_SYNC          (1U << 1)  /* fsync on each append (slow) */
#define TRUST_LOG_TRUNCATE      (1U << 2)  /* truncate existing log on open */

/*
 * Rotation threshold in bytes. Rotation is triggered on append past this.
 * Set via env LIBTRUST_LOG_ROTATE_BYTES or defaults to 4 MiB.
 */
#define TRUST_LOG_DEFAULT_ROTATE  (4U * 1024U * 1024U)

/*
 * trust_log_open - Create or open a log directory at `path`.
 * `path` is a directory; segments land at {path}/trust.evt.NNN.
 * Compressed segments are {path}/trust.evt.NNN.zst (kept alongside).
 *
 * Returns a handle on success, NULL on failure (errno set).
 */
trust_log_t *trust_log_open(const char *path, int flags);

/*
 * trust_log_append - Append one event to the current segment. If the
 * segment crosses the rotation threshold, the segment is rotated
 * automatically (which may zstd-compress the outgoing segment if the
 * log was opened with TRUST_LOG_ZSTD).
 *
 * Returns 0 on success, -1 on error (errno preserved).
 */
int trust_log_append(trust_log_t *l, const trust_event_t *ev);

/*
 * trust_log_rotate - Manually trigger rotation. Useful for log shippers
 * that want a deterministic boundary. Idempotent for empty segments.
 *
 * Returns 0 on success, -1 on error.
 */
int trust_log_rotate(trust_log_t *l);

/*
 * trust_log_close - Close the log. Flushes the current segment but does
 * NOT compress it — callers should trust_log_rotate() first if the
 * tail should be compressed.
 */
void trust_log_close(trust_log_t *l);

#ifdef __cplusplus
}
#endif

#endif /* LIBTRUST_H */
