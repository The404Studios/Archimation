/*
 * trust_ioctl.h - ioctl definitions for /dev/trust
 *
 * User-kernel interface for the Root of Trust system.
 * RISC operations are fast-path (single TLB lookup).
 * FBC operations are complex multi-step.
 */

#ifndef TRUST_IOCTL_H
#define TRUST_IOCTL_H

#include "trust_types.h"

#ifdef __KERNEL__
#include <linux/ioctl.h>
#else
#include <sys/ioctl.h>
#endif

#define TRUST_IOC_MAGIC 'T'

/* --- RISC fast-path ioctls --- */

/* Check if subject has a capability (returns 0=yes, -1=no) */
typedef struct {
    uint32_t subject_id;
    uint32_t capability;    /* Single TRUST_CAP_* bit */
    int32_t  result;        /* Output: 1=has cap, 0=no */
    uint32_t _padding;
} trust_ioc_check_cap_t;
#define TRUST_IOC_CHECK_CAP     _IOWR(TRUST_IOC_MAGIC, 1, trust_ioc_check_cap_t)

/* Get trust score for a subject */
typedef struct {
    uint32_t subject_id;
    int32_t  score;         /* Output: current trust score */
} trust_ioc_get_score_t;
#define TRUST_IOC_GET_SCORE     _IOWR(TRUST_IOC_MAGIC, 2, trust_ioc_get_score_t)

/* Record an action (applies delta, checks thresholds) */
typedef struct {
    uint32_t subject_id;
    uint32_t action_type;   /* TRUST_ACTION_* */
    uint32_t result;        /* 0=success, else error */
    int32_t  new_score;     /* Output: new trust score after action */
} trust_ioc_record_t;
#define TRUST_IOC_RECORD_ACTION _IOWR(TRUST_IOC_MAGIC, 3, trust_ioc_record_t)

/* Fast threshold check (score >= rule.min_trust?) */
typedef struct {
    uint32_t subject_id;
    uint32_t action_type;
    int32_t  result;        /* Output: TRUST_RESULT_* */
    uint32_t _padding;
} trust_ioc_threshold_t;
#define TRUST_IOC_THRESHOLD     _IOWR(TRUST_IOC_MAGIC, 4, trust_ioc_threshold_t)

/* --- FBC complex-path ioctls --- */

/* Register a new trust subject */
typedef struct {
    uint32_t subject_id;
    uint16_t domain;        /* TRUST_DOMAIN_* */
    uint16_t _padding;
    uint32_t authority;     /* Initial TRUST_AUTH_* level */
    int32_t  initial_score; /* Initial trust score (0 = use default) */
} trust_ioc_register_t;
#define TRUST_IOC_REGISTER      _IOW(TRUST_IOC_MAGIC, 10, trust_ioc_register_t)

/* Unregister a subject */
typedef struct {
    uint32_t subject_id;
} trust_ioc_unregister_t;
#define TRUST_IOC_UNREGISTER    _IOW(TRUST_IOC_MAGIC, 11, trust_ioc_unregister_t)

/* Request authority escalation (FBC operation) */
typedef struct {
    uint32_t subject_id;
    uint32_t requested_authority;   /* Target TRUST_AUTH_* level */
    int32_t  result;                /* Output: 0=granted, -1=denied */
    uint32_t _padding;
    char     justification[256];    /* Why the escalation is needed */
} trust_ioc_escalate_t;
#define TRUST_IOC_ESCALATE      _IOWR(TRUST_IOC_MAGIC, 12, trust_ioc_escalate_t)

/* Full policy evaluation (FBC operation) */
typedef struct {
    uint32_t subject_id;
    uint32_t action_type;
    int32_t  result;            /* Output: TRUST_RESULT_* */
    uint32_t matching_rule_idx; /* Output: index of matching rule */
} trust_ioc_policy_eval_t;
#define TRUST_IOC_POLICY_EVAL   _IOWR(TRUST_IOC_MAGIC, 13, trust_ioc_policy_eval_t)

/* Cross-domain capability transfer via DNA Gate */
typedef struct {
    uint32_t subject_id;
    uint16_t from_domain;
    uint16_t to_domain;
    uint32_t capabilities;  /* TRUST_CAP_* bits to transfer */
    int32_t  result;        /* Output: 0=success, -1=denied */
} trust_ioc_domain_transfer_t;
#define TRUST_IOC_DOMAIN_TRANSFER _IOWR(TRUST_IOC_MAGIC, 14, trust_ioc_domain_transfer_t)

/* Propagate trust delta to a subject (cascades to dependents) */
typedef struct {
    uint32_t subject_id;
    int32_t  delta;
} trust_ioc_propagate_t;
#define TRUST_IOC_PROPAGATE     _IOW(TRUST_IOC_MAGIC, 15, trust_ioc_propagate_t)

/* Repartition authority boundaries (admin operation) */
#define TRUST_IOC_REPARTITION   _IO(TRUST_IOC_MAGIC, 16)

/* Get full subject info */
typedef struct {
    uint32_t subject_id;
    trust_subject_t subject; /* Output */
} trust_ioc_get_subject_t;
#define TRUST_IOC_GET_SUBJECT   _IOWR(TRUST_IOC_MAGIC, 20, trust_ioc_get_subject_t)

/* Flush the TLB (admin operation) */
#define TRUST_IOC_FLUSH_TLB     _IO(TRUST_IOC_MAGIC, 30)

/* Get audit ring buffer entries */
typedef struct {
    uint32_t max_entries;
    uint32_t returned;          /* Output: actual entries returned */
    trust_audit_entry_t *buf;   /* Userspace buffer */
} trust_ioc_audit_t;
#define TRUST_IOC_GET_AUDIT     _IOWR(TRUST_IOC_MAGIC, 31, trust_ioc_audit_t)

/* --- Dependency graph management --- */

/* Add a dependency: subject_id depends on depends_on */
typedef struct {
    uint32_t subject_id;
    uint32_t depends_on;
    int32_t  result;        /* Output: 0=ok, -1=full */
} trust_ioc_dep_add_t;
#define TRUST_IOC_DEP_ADD       _IOWR(TRUST_IOC_MAGIC, 40, trust_ioc_dep_add_t)

/* Remove a dependency */
typedef struct {
    uint32_t subject_id;
    uint32_t depends_on;
} trust_ioc_dep_remove_t;
#define TRUST_IOC_DEP_REMOVE    _IOW(TRUST_IOC_MAGIC, 41, trust_ioc_dep_remove_t)

/* --- Escalation queue (AI observer approval flow) --- */

/* Dequeue a pending escalation request (for AI observer to poll) */
typedef struct {
    uint32_t subject_id;        /* Output */
    uint32_t requested_authority; /* Output */
    char     justification[128]; /* Output */
    uint64_t timestamp;         /* Output */
    int32_t  current_score;     /* Output */
    uint32_t seq;               /* Output: sequence number for responding */
    int32_t  has_pending;       /* Output: 1=got request, 0=queue empty */
} trust_ioc_escalation_poll_t;
#define TRUST_IOC_ESCALATION_POLL _IOR(TRUST_IOC_MAGIC, 50, trust_ioc_escalation_poll_t)

/* Respond to an escalation request */
typedef struct {
    uint32_t seq;               /* Sequence number from poll */
    uint32_t approved;          /* 1=approved, 0=denied */
} trust_ioc_escalation_respond_t;
#define TRUST_IOC_ESCALATION_RESPOND _IOW(TRUST_IOC_MAGIC, 51, trust_ioc_escalation_respond_t)

/* --- Self-Consuming Proof Chain (Authority Proof Engine) --- */

/* Mint initial proof for a subject (AUTH_MINT) */
typedef struct {
    uint32_t subject_id;
    uint8_t  proof[TRUST_PROOF_SIZE];   /* Output: initial proof token */
    int32_t  result;                     /* Output: 0=ok, <0=error */
} trust_ioc_proof_mint_t;
#define TRUST_IOC_PROOF_MINT    _IOWR(TRUST_IOC_MAGIC, 60, trust_ioc_proof_mint_t)

/* Consume proof and get next (AUTH_BURN) */
typedef struct {
    uint32_t subject_id;
    uint8_t  current_proof[TRUST_PROOF_SIZE]; /* Input: proof to consume */
    uint32_t action_type;                      /* Action being authorized */
    uint32_t action_result;                    /* 0=success, else error */
    uint8_t  next_proof[TRUST_PROOF_SIZE];    /* Output: next proof token */
    int32_t  result;                           /* Output: 0=ok, <0=error */
} trust_ioc_proof_consume_t;
#define TRUST_IOC_PROOF_CONSUME _IOWR(TRUST_IOC_MAGIC, 61, trust_ioc_proof_consume_t)

/* Invalidate proof chain (AUTH_FENCE) */
typedef struct {
    uint32_t subject_id;
    int32_t  result;                    /* Output: 0=ok */
} trust_ioc_proof_fence_t;
#define TRUST_IOC_PROOF_FENCE   _IOWR(TRUST_IOC_MAGIC, 62, trust_ioc_proof_fence_t)

/* Verify proof without consuming (read-only check) */
typedef struct {
    uint32_t subject_id;
    uint8_t  proof[TRUST_PROOF_SIZE];   /* Input: proof to verify */
    int32_t  result;                     /* Output: 0=valid, <0=error */
} trust_ioc_proof_verify_t;
#define TRUST_IOC_PROOF_VERIFY  _IOWR(TRUST_IOC_MAGIC, 63, trust_ioc_proof_verify_t)

/* Get proof chain nonce (monotonic counter) */
typedef struct {
    uint32_t subject_id;
    uint64_t nonce;                     /* Output: current nonce value */
} trust_ioc_proof_nonce_t;
#define TRUST_IOC_PROOF_NONCE   _IOWR(TRUST_IOC_MAGIC, 64, trust_ioc_proof_nonce_t)

/* --- Token Economy (Metabolic Cost) --- */

/* Get token balance (AUTH_BAL) */
typedef struct {
    uint32_t subject_id;
    int32_t  balance;                   /* Output: current balance */
    int32_t  max_balance;               /* Output: maximum capacity */
} trust_ioc_token_balance_t;
#define TRUST_IOC_TOKEN_BALANCE _IOWR(TRUST_IOC_MAGIC, 70, trust_ioc_token_balance_t)

/* Burn tokens for an action */
typedef struct {
    uint32_t subject_id;
    uint32_t action_type;               /* TRUST_ACTION_* */
    int32_t  result;                    /* Output: 0=ok, -ENOSPC=starved */
    int32_t  remaining;                 /* Output: remaining balance */
} trust_ioc_token_burn_t;
#define TRUST_IOC_TOKEN_BURN    _IOWR(TRUST_IOC_MAGIC, 71, trust_ioc_token_burn_t)

/* Transfer tokens between subjects (AUTH_XFER) */
typedef struct {
    uint32_t from_subject;
    uint32_t to_subject;
    int32_t  amount;
    int32_t  result;                    /* Output: 0=ok, <0=error */
} trust_ioc_token_xfer_t;
#define TRUST_IOC_TOKEN_XFER    _IOWR(TRUST_IOC_MAGIC, 72, trust_ioc_token_xfer_t)

/* Get metabolic cost for an action */
typedef struct {
    uint32_t action_type;
    uint32_t cost;                      /* Output: token cost */
} trust_ioc_token_cost_t;
#define TRUST_IOC_TOKEN_COST    _IOWR(TRUST_IOC_MAGIC, 73, trust_ioc_token_cost_t)

/* --- Lifecycle (Mitotic/Meiotic) --- */

/* Mitotic division: parent spawns child */
typedef struct {
    uint32_t parent_id;
    uint32_t child_id;
    int32_t  result;                    /* Output: 0=ok, -EPERM=cancer */
    int32_t  child_max_score;           /* Output: child's score ceiling */
} trust_ioc_mitotic_divide_t;
#define TRUST_IOC_MITOTIC_DIVIDE _IOWR(TRUST_IOC_MAGIC, 80, trust_ioc_mitotic_divide_t)

/* Meiotic combination: two entities cooperate */
typedef struct {
    uint32_t subject_a;
    uint32_t subject_b;
    int32_t  result;                    /* Output: 0=ok */
    int32_t  combined_score;            /* Output: min(S(A), S(B)) */
} trust_ioc_meiotic_combine_t;
#define TRUST_IOC_MEIOTIC_COMBINE _IOWR(TRUST_IOC_MAGIC, 81, trust_ioc_meiotic_combine_t)

/* Meiotic release: end cooperation */
typedef struct {
    uint32_t subject_a;
    uint32_t subject_b;
} trust_ioc_meiotic_release_t;
#define TRUST_IOC_MEIOTIC_RELEASE _IOW(TRUST_IOC_MAGIC, 82, trust_ioc_meiotic_release_t)

/* Initiate apoptosis for a subject */
typedef struct {
    uint32_t subject_id;
    int32_t  result;                    /* Output: 0=ok */
} trust_ioc_apoptosis_t;
#define TRUST_IOC_APOPTOSIS _IOWR(TRUST_IOC_MAGIC, 83, trust_ioc_apoptosis_t)

/* --- Chromosome queries --- */

/* Get chromosome for a subject */
typedef struct {
    uint32_t subject_id;
    trust_chromosome_t chromosome;      /* Output */
    int32_t  result;                    /* Output: 0=ok */
} trust_ioc_get_chromosome_t;
#define TRUST_IOC_GET_CHROMOSOME _IOWR(TRUST_IOC_MAGIC, 90, trust_ioc_get_chromosome_t)

/* Get sex determination for a subject */
typedef struct {
    uint32_t subject_id;
    uint8_t  sex;                       /* Output: CHROMO_SEX_* */
    uint8_t  _padding[3];
    int32_t  result;
} trust_ioc_get_sex_t;
#define TRUST_IOC_GET_SEX _IOWR(TRUST_IOC_MAGIC, 91, trust_ioc_get_sex_t)

/* --- Immune Response --- */

/* Get immune status */
typedef struct {
    uint32_t subject_id;
    uint8_t  status;                    /* Output: TRUST_IMMUNE_* */
    uint8_t  _padding[3];
    uint32_t suspicious_actions;        /* Output */
    int32_t  result;
} trust_ioc_immune_status_t;
#define TRUST_IOC_IMMUNE_STATUS _IOWR(TRUST_IOC_MAGIC, 95, trust_ioc_immune_status_t)

/* Quarantine a subject */
typedef struct {
    uint32_t subject_id;
    uint32_t reason;                    /* TRUST_ACTION_* that triggered it */
    int32_t  result;
} trust_ioc_quarantine_t;
#define TRUST_IOC_QUARANTINE _IOWR(TRUST_IOC_MAGIC, 96, trust_ioc_quarantine_t)

/* Release from quarantine (requires elevated privileges) */
typedef struct {
    uint32_t subject_id;
    int32_t  result;
} trust_ioc_release_quarantine_t;
#define TRUST_IOC_RELEASE_QUARANTINE _IOWR(TRUST_IOC_MAGIC, 97, trust_ioc_release_quarantine_t)

#endif /* TRUST_IOCTL_H */
