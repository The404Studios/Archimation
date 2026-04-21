/*
 * trust_authz.h - Single canonical authorization predicate
 *
 * Implements the Root of Authority paper's auth(E, a, t) decision rule:
 *
 *   auth(E, a, t) = 1  iff
 *     cert(E)  AND  trust(E)  AND
 *     S_t >= Theta(a)  AND  C_t >= cost(a)  AND
 *     proof(P_t, a)
 *
 * Five conjuncts, each a separate predicate, OR'd into a per-call failure
 * bitmask so callers can emit precise telemetry without re-walking the rule.
 *
 * This consolidates checks that were previously scattered across
 * trust_risc_threshold_check / trust_token_check / trust_ape_consume_proof
 * paths.  None of those legacy entry points are removed; they still exist
 * for the sub-checks they own.  trust_authz_check() is the ONE call that
 * a serializer / dispatcher should make if it wants the full paper-spec
 * authorization decision.
 *
 * Theorem 6 (Metabolic Fairness) invariant: each successful trust_token_burn()
 * checks that the subject has not exceeded C(E)_at_last_mint / C_min actions
 * since its last mint.  Violations are WARN_ON_ONCE'd and surfaced via
 * /sys/kernel/trust/theorem6_violations.
 *
 * Owner: Session 48 Agent 2 (Authorization + Token Economy + Theorem 6).
 */

#ifndef TRUST_AUTHZ_H
#define TRUST_AUTHZ_H

#include <linux/types.h>
#include "../include/trust_types.h"

/* --- Failure-predicate bitmask returned from trust_authz_check() --- */
#define TRUST_AUTHZ_OK                  0x00U
#define TRUST_AUTHZ_FAIL_CERT           (1U << 0)   /* cert(E)             */
#define TRUST_AUTHZ_FAIL_TRUST          (1U << 1)   /* trust(E) non-zero   */
#define TRUST_AUTHZ_FAIL_THRESHOLD      (1U << 2)   /* S_t >= Theta(a)     */
#define TRUST_AUTHZ_FAIL_TOKEN          (1U << 3)   /* C_t >= cost(a)      */
#define TRUST_AUTHZ_FAIL_PROOF          (1U << 4)   /* proof(P_t, a)       */
#define TRUST_AUTHZ_FAIL_NULL_SUBJECT   (1U << 5)   /* defensive: subj == NULL */
#define TRUST_AUTHZ_FAIL_BAD_ACTION     (1U << 6)   /* action >= TRUST_ACTION_MAX */
#define TRUST_AUTHZ_FAIL_FROZEN         (1U << 7)   /* TRUST_FLAG_FROZEN set   */

/* --- Token economy paper constants ---
 *
 * C_min  : cheapest action cost (Theorem 6 denominator).  Defined as 1
 *          token because TRUST_COST_FILE_READ is the floor and equals 1.
 *          Exposed via /sys/kernel/trust/c_min (read-only) so coherence
 *          telemetry can read the same constant the kernel uses.
 *
 * C_starter : starting balance for a fresh subject of unknown class.
 *             Matches TRUST_TOKEN_MAX_DEFAULT/4 (the user-tier seed used
 *             in trust_token_init()).  Exported so userspace stays in
 *             sync with kernel sizing.
 */
#define TRUST_C_MIN                     1U
#define TRUST_C_STARTER                 (TRUST_TOKEN_MAX_DEFAULT / 4)

/* --- Mint reason codes (audit / chromosome correlation) --- */
#define TRUST_MINT_REASON_INIT          1U   /* trust_token_init seed     */
#define TRUST_MINT_REASON_REGEN         2U   /* periodic regeneration     */
#define TRUST_MINT_REASON_REWARD        3U   /* positive-action reward    */
#define TRUST_MINT_REASON_ESCALATION    4U   /* observer-approved grant   */
#define TRUST_MINT_REASON_INHERIT       5U   /* mitotic inheritance       */

/*
 * Authorization predicate.
 *
 *   E              : subject (must be a stack-local copy from trust_tlb_lookup;
 *                    the function does NOT take a TLB lock and must NOT be
 *                    handed a TLB-resident pointer).
 *   action         : TRUST_ACTION_* from trust_types.h
 *   out_failed_predicate : if non-NULL, set on return to the OR of all
 *                    TRUST_AUTHZ_FAIL_* bits that were violated.  Set to
 *                    TRUST_AUTHZ_OK on success.  Caller may pass NULL.
 *
 * Returns:  true if every conjunct held, false otherwise.
 */
bool trust_authz_check(const trust_subject_t *E,
                       u32 action,
                       u32 *out_failed_predicate);

/*
 * Stable threshold table accessor (paper symbol Theta(a)).
 * Returns 0 for "no specific threshold; default to TRUST_SCORE_NEUTRAL"
 * when the action is unknown.  Used internally by trust_authz_check()
 * AND exposed for telemetry / unit tests.
 */
int32_t trust_authz_threshold_for_action(u32 action);

/* --- Public token-economy helpers ---
 *
 * Every trust-tracked action MUST burn through trust_token_burn_action()
 * so the Theorem 6 invariant fires.  trust_token_state_t.balance manipulation
 * outside of this helper is a Theorem 6 hole.
 *
 * trust_token_mint_subject(): adds 'qty' to the subject's balance, capped
 *   at max_balance, records reason for the audit trail, and resets the
 *   actions-since-mint counter so the next fairness window starts fresh.
 *
 * Both helpers return 0 on success, -errno on failure.  They lock the
 * subject's TLB set internally via trust_tlb_modify().
 */
int trust_token_mint_subject(u32 subject_id, u32 qty, u32 reason_code);
int trust_token_burn_action(u32 subject_id, u32 action_type);

/*
 * Theorem 6 violation counter, aggregated across CPUs on read.
 * Bumped by trust_token_burn_action() via WARN_ON_ONCE when a subject
 * exceeds C(E)_at_last_mint / C_min actions since its last mint.
 */
u64 trust_authz_theorem6_violations(void);

/*
 * Conservation invariant (debug-only, slow): walks the entire TLB summing
 * per-subject balances and compares against the global mint/burn ledger.
 * Returns 0 if Sum(C_t) + tokens_in_flight == total_minted - total_burned,
 * -ERANGE on mismatch.  Callable from sysfs trigger only — DO NOT invoke
 * from a hot path.
 */
int trust_token_conservation_check(s64 *out_delta);

/*
 * Sysfs registration (called from trust_init() AFTER trust_stats_register()).
 * Adds:
 *   /sys/kernel/trust/theorem6_violations  (RO, u64)
 *   /sys/kernel/trust/c_min                (RO, u32)
 *   /sys/kernel/trust/c_starter            (RO, u32)
 *   /sys/kernel/trust/conservation_check   (WO, write any value to trigger;
 *                                           result logged via pr_warn on mismatch)
 *   /sys/kernel/trust/token_ledger         (RO, "minted=N burned=N inflight=N")
 *
 * Returns 0 on success, -errno on failure.  Non-fatal at module load.
 */
int  trust_authz_sysfs_register(struct kobject *parent);
void trust_authz_sysfs_unregister(void);

#endif /* TRUST_AUTHZ_H */
