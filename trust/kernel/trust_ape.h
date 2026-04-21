/*
 * trust_ape.h - Authority Proof Engine internal/public API
 *
 * Spec: "Root of Authority" by Roberts/Eli/Leelee
 *       (Zenodo 18710335, DOI 10.5281/zenodo.18710335), §SCP / §APE.
 *
 * The canonical Self-Consuming Proof formula (paper §SCP eq. (1)) is:
 *
 *   P_{n+1} = H_{cfg(n)}(P_n || R_n || SEED || N_n || T_n || S_n)
 *
 * where:
 *   P_n  = current proof (consumed and destroyed atomically on use)
 *   R_n  = hash(actual_result_n) — entanglement of the n-th action's result
 *   SEED = write-once entity identity (no read path; verify via call-graph)
 *   N_n  = monotonic public nonce
 *   T_n  = timestamp
 *   S_n  = behavioral state snapshot (chromosome checksum) — see "Moat"
 *          note below.
 *   H_cfg(n) = reconfigurable hash whose configuration cfg(n) is extracted
 *              from the bits of the destroyed P_n (Theorem 3 — Reconfig
 *              Unpredictability):
 *
 *     cfg(n) = ( perm(P_n[7:0]),       // 8-bit selector → 720 fixed perms
 *                window(P_n[15:8]),    // 8-bit hash window size
 *                mask(P_n[19:16]),     // 4-bit mask pattern
 *                rot(P_n[24:20]) )     // 5-bit pre-rotation
 *
 * Total distinct configurations: 720 * 256 * 16 * 32 = 94,371,840
 * (APE_CFG_TOTAL, below — asserted with BUILD_BUG_ON in
 *  trust_ape.c:trust_ape_build_asserts()).
 *
 * The 720 permutations are the first 720 of 8! = 40,320 entries enumerated
 * by Heap's algorithm.  This truncation is intentional: 720 fits in a
 * compact 720*8 = 5760-byte table and produces enough variety for the
 * downstream entanglement (the perm output is XOR-mixed into the SHA-256
 * input, not the only source of entropy).
 *
 * ---------------------------------------------------------------------
 * IMPLEMENTATION REALITY (as of S75+).
 *
 *   The 94,371,840-configuration reconfigurable hash IS implemented in
 *   the shipping kernel module.  Concretely:
 *
 *     • ape_perm_table[720][8]            at trust_ape.c:145
 *     • heap_permute_init()               at trust_ape.c:148
 *     • decode_cfg()                      at trust_ape.c:195
 *     • apply_reconfigurable_hash()       at trust_ape.c:225
 *     • compute_proof_v2()                at trust_ape.c:302
 *     • BUILD_BUG_ON(APE_CFG_TOTAL        at trust_ape.c:528
 *         != 94371840ULL)
 *
 *   compute_proof_v2() is the cfg-aware SHA kernel invoked by both the
 *   create-entity path (trust_ape.c:668) and the v2 consume path
 *   (trust_ape.c:975).  trust_ape_consume_proof_v2() at trust_ape.c:825
 *   threads R_n through the proof per paper §SCP eq. (1); the legacy
 *   trust_ape_consume_proof() at trust_ape.c:1067 forwards to v2 with
 *   a 32-byte zero R_n for back-compat.
 *
 *   Archaeology: an earlier S49→S50-era working-tree regression reduced
 *   apply_reconfigurable_hash() to a 3-algorithm SHA cycle (SHA-256 /
 *   BLAKE2b-256 / SHA3-256 only, i.e. 3 configurations — a
 *   7-order-of-magnitude gap against the paper's 94M claim).  The full
 *   implementation was recovered in S74 from dangling-stash commit
 *   9b04ca1 via restoration commit faf6d8e4 ("S74 recovery: APE
 *   bring-back from dangling commit 9b04ca1 (+605 LOC restored)").  See
 *   docs/ape-regression-archaeology.md for the full forensics and
 *   docs/roa-conformance.md §"APE configuration history" for the
 *   timeline.  The BUILD_BUG_ON above exists precisely to prevent a
 *   silent re-regression — any edit that weakens APE_CFG_TOTAL will
 *   compile-fail.
 *
 * ---------------------------------------------------------------------
 * MOAT NOTE (research-D §3.1 synthesis, confirmed S74/S78).
 *
 *   The 94,371,840 configuration count is a *richness* contribution:
 *   it raises an adversary's per-step prediction probability from
 *   1/3 (3-algo cycle) to 1/94,371,840 (~2^-26.5).  Real and useful.
 *
 *   However, per research-D §3.1, it is NOT the genuine novelty of APE.
 *   The hash-chain shape itself (P_{n+1} = H(P_n || ctx) with
 *   destroy-on-use) is a rediscovery of Lamport 1981 / PayWord 1996 /
 *   sponge constructions (Bertoni 2008); the reconfigurable-hash twist,
 *   while novel, is in the same family.
 *
 *   The GENUINE APE NOVELTY is the S_n term — binding proof
 *   advancement to a behavioral fingerprint (chromosome checksum) at
 *   consume time.  No cryptographic primitive in the prior literature
 *   entangles chain integrity with an application-semantic behavioral
 *   state.  A forged or replayed proof whose S_n does not match the
 *   subject's current chromosomal state cannot pass verification,
 *   regardless of how well the attacker modeled P_n or cfg(n).
 *
 *   Docs/roa-conformance.md §2 and docs/paper-vs-implementation.md §1
 *   (row 4 + §2.T-ape-novelty) describe the claim hierarchy in detail.
 *   Peer reviewers should read the behavioral-state-binding framing as
 *   the primary contribution; the 94M count as a richness bound.
 * ---------------------------------------------------------------------
 */
#ifndef _TRUST_APE_H
#define _TRUST_APE_H

#include "trust_internal.h"

/* ---------------------------------------------------------------- *
 * Reconfigurable-hash config layout (extracted from destroyed P_n) *
 * ---------------------------------------------------------------- */
#define APE_CFG_PERM_COUNT     720U   /* size of the fixed permutation table */
#define APE_CFG_WINDOW_COUNT   256U   /* P_n[15:8]  — 8 bits */
#define APE_CFG_MASK_COUNT      16U   /* P_n[19:16] — 4 bits */
#define APE_CFG_ROT_COUNT       32U   /* P_n[24:20] — 5 bits */

/* Total reconfigurable-hash configurations (paper §APE — Theorem 3). */
#define APE_CFG_TOTAL \
    ((u64)APE_CFG_PERM_COUNT * APE_CFG_WINDOW_COUNT * \
     APE_CFG_MASK_COUNT      * APE_CFG_ROT_COUNT)

/*
 * Result-entanglement hash length — paper-spec R_n = hash(actual_result_n).
 * We treat callers that pass NULL as "no result yet" with an all-zero
 * 32-byte buffer, preserving the pre-S48 wire output for legacy paths.
 */
#define APE_RESULT_HASH_LEN    32U

/* ---------------------------------------------------------------- *
 *                     Public APE API (§APE)                        *
 * ---------------------------------------------------------------- *
 * All declarations also live in trust_internal.h for layering, but
 * this header is the canonical place new APE-aware code should
 * include.  Callers SHOULD use the _v2 variant and pass a real R_n
 * derived from the action's actual result.
 */

/*
 * trust_ape_consume_proof_v2 — extended self-consuming proof step.
 *
 * @subject_id:        subject whose chain to advance
 * @request:           R_n input bytes (request payload)         [opt]
 * @req_len:           length of @request (clamped to 256)
 * @action_result_hash: hash(actual_result_n), APE_RESULT_HASH_LEN bytes
 *                     If NULL, treated as a 32-byte zero buffer
 *                     (back-compat shim — emits a warn-once).
 * @hashlen:           length of @action_result_hash (must be
 *                     APE_RESULT_HASH_LEN if non-NULL).
 * @proof_out:         receives the consumed P_n (32 bytes)       [opt]
 *
 * Returns 0 on success, -ENOENT if no entity, -EINVAL if chain broken,
 * -EALREADY if double-consume (P_n was already 0 — apoptosis is
 * additionally requested via the force-apoptosis flag), -ESTALE if the
 * subject was rotated mid-compute, or a negative crypto errno.
 */
int trust_ape_consume_proof_v2(u32 subject_id,
                               const u8 *request, u32 req_len,
                               const u8 *action_result_hash, size_t hashlen,
                               u8 *proof_out);

/*
 * trust_ape_check_force_apoptosis — non-destructive read of the
 * force-apoptosis flag stamped by the double-read trap.
 *
 * Returns 1 if the subject has been marked for forced apoptosis as a
 * direct consequence of a P_n double-consume, 0 otherwise, or a
 * negative errno on lookup failure.  Designed to be polled from
 * trust_lifecycle's apoptosis sweep.
 */
int trust_ape_check_force_apoptosis(u32 subject_id);

/*
 * trust_ape_clear_force_apoptosis — clear the force-apoptosis flag,
 * called by trust_lifecycle after acting on it.  Returns 0 on success.
 *
 * Kept here (not exposed to userspace) so the lifecycle path can
 * acknowledge the flag without re-creating the entity.
 */
int trust_ape_clear_force_apoptosis(u32 subject_id);

/*
 * trust_ape_double_read_count — sum the per-CPU double-read trap
 * counters into a single u64.  Used by /sys/kernel/trust/stats.
 * Returns 0 (never fails).
 */
u64 trust_ape_double_read_count(void);

/*
 * trust_ape_seq_advances_total — sum the per-CPU sequencer-advance
 * counters into a single u64.  This is the count of successful
 * proof-consume operations that have advanced the global monotonic
 * nonce maintained by trust_invariants.c (Session 49 / Agent B
 * wiring of Theorem 2 — Non-Replayability — to runtime-enforced
 * status).  Use alongside trust_invariants_read_nonce() to compare
 * APE-attributable advances against the absolute global nonce.
 * Returns 0 (never fails).
 */
u64 trust_ape_seq_advances_total(void);

/*
 * trust_ape_sequencer_selfcheck — module-load smoke test for the
 * global-nonce wiring.  Reads, advances, re-reads
 * trust_invariants_read_nonce()/advance_nonce() and pr_info's a
 * confirmation if monotonic, pr_err's if not.  Intentionally
 * non-static so a future ktest harness can re-invoke it without a
 * module reload.  Called automatically from trust_ape_init().
 */
void trust_ape_sequencer_selfcheck(void);

/*
 * trust_ape_markov_validator — Theorem 3 statistical point-test.
 *
 * Spec: Theorem 3 (Reconfiguration Unpredictability) claims
 *
 *   Pr[adversary predicts cfg(n+1)] <= 1/|Config| + negl(lambda)
 *
 * which is unprovable in C but admits a runtime point-test: feed many
 * independent random inputs through the underlying SHA primitive used
 * by the proof chain and chi-square the byte-distribution of the
 * outputs against uniform on { 0..255 }.
 *
 * Implemented in trust_ape_markov.c.  Self-contained — does NOT touch
 * any APE state (no proof_state, no per-CPU counters, no SEED).  Safe
 * to call any time after the kernel crypto API is up.
 *
 * Process context only (uses GFP_KERNEL + crypto_alloc_shash, may
 * sleep).  Idempotent — invoke once per module load (or repeatedly
 * from a future ktest harness).
 *
 * Logs verdict to dmesg.  NEVER fails module load on a chi-square
 * miss; never returns failure to the caller.
 *
 * SESSION 59 WIRING NOTE: this prototype is exposed but the symbol is
 * NOT invoked from anywhere yet — Session 58 forbade modifying
 * trust_ape.c (Agent 1 lock).  Session 59 should add a single call
 * site at the tail of trust_ape_init() in trust_ape.c, after
 * trust_ape_sequencer_selfcheck():
 *
 *     trust_ape_sequencer_selfcheck();
 *     trust_ape_markov_validator();      // <-- add here
 *
 * Until that call is added, this is dead code (~1.5 KB in trust.ko).
 */
void trust_ape_markov_validator(void);

#endif /* _TRUST_APE_H */
