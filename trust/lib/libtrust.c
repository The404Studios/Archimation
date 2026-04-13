/*
 * libtrust.c - Userspace Trust System Library
 *
 * Wraps /dev/trust ioctl calls for C callers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <pthread.h>

#include "libtrust.h"
#include "../include/trust_ioctl.h"

static int g_trust_fd = -1;
static pthread_mutex_t g_trust_lock = PTHREAD_MUTEX_INITIALIZER;

int trust_init(void)
{
    int fd;

    pthread_mutex_lock(&g_trust_lock);
    if (g_trust_fd >= 0) {
        pthread_mutex_unlock(&g_trust_lock);
        return 0; /* Already initialized */
    }

    fd = open("/dev/trust", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        /* Not fatal — trust module may not be loaded */
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    g_trust_fd = fd;
    pthread_mutex_unlock(&g_trust_lock);
    return 0;
}

void trust_cleanup(void)
{
    int fd;

    pthread_mutex_lock(&g_trust_lock);
    fd = g_trust_fd;
    g_trust_fd = -1;
    pthread_mutex_unlock(&g_trust_lock);

    if (fd >= 0)
        close(fd);
}

int trust_available(void)
{
    return (g_trust_fd >= 0) ? 1 : 0;
}

/* --- RISC fast-path --- */

int trust_check_capability(uint32_t subject_id, uint32_t capability)
{
    trust_ioc_check_cap_t req;

    if (g_trust_fd < 0) return 1; /* No trust module = allow all */

    memset(&req, 0, sizeof(req));
    req.subject_id = subject_id;
    req.capability = capability;
    req.result = 0;

    if (ioctl(g_trust_fd, TRUST_IOC_CHECK_CAP, &req) < 0)
        return 0; /* Error = deny (fail-closed for security) */

    return req.result;
}

int32_t trust_get_score(uint32_t subject_id)
{
    trust_ioc_get_score_t req;

    if (g_trust_fd < 0) return TRUST_SCORE_DEFAULT;

    req.subject_id = subject_id;
    req.score = 0;

    if (ioctl(g_trust_fd, TRUST_IOC_GET_SCORE, &req) < 0)
        return 0;

    return req.score;
}

int32_t trust_record_action(uint32_t subject_id, uint32_t action, int result)
{
    trust_ioc_record_t req;

    if (g_trust_fd < 0) return 0;

    req.subject_id = subject_id;
    req.action_type = action;
    req.result = (uint32_t)result;
    req.new_score = 0;

    if (ioctl(g_trust_fd, TRUST_IOC_RECORD_ACTION, &req) < 0)
        return 0;

    return req.new_score;
}

int trust_threshold_check(uint32_t subject_id, uint32_t action)
{
    trust_ioc_threshold_t req;

    if (g_trust_fd < 0) return TRUST_RESULT_ALLOW;

    memset(&req, 0, sizeof(req));
    req.subject_id = subject_id;
    req.action_type = action;
    req.result = TRUST_RESULT_DENY;

    if (ioctl(g_trust_fd, TRUST_IOC_THRESHOLD, &req) < 0)
        return TRUST_RESULT_DENY; /* Error = deny (fail-closed for security) */

    return req.result;
}

/* --- FBC complex-path --- */

int trust_register_subject(uint32_t subject_id, uint16_t domain,
                           uint32_t authority)
{
    return trust_register_subject_ex(subject_id, domain, authority, 0);
}

int trust_register_subject_ex(uint32_t subject_id, uint16_t domain,
                              uint32_t authority, int32_t initial_score)
{
    trust_ioc_register_t req;

    if (g_trust_fd < 0) return 0; /* No trust module = success (no-op) */

    req.subject_id = subject_id;
    req.domain = domain;
    req._padding = 0;
    req.authority = authority;
    req.initial_score = initial_score;

    if (ioctl(g_trust_fd, TRUST_IOC_REGISTER, &req) < 0)
        return -1;

    return 0;
}

int trust_unregister_subject(uint32_t subject_id)
{
    trust_ioc_unregister_t req;

    if (g_trust_fd < 0) return 0;

    req.subject_id = subject_id;

    if (ioctl(g_trust_fd, TRUST_IOC_UNREGISTER, &req) < 0)
        return -1;

    return 0;
}

int trust_request_escalation(uint32_t subject_id, uint32_t authority)
{
    trust_ioc_escalate_t req;

    if (g_trust_fd < 0) return 0;

    memset(&req, 0, sizeof(req));
    req.subject_id = subject_id;
    req.requested_authority = authority;
    strncpy(req.justification, "userspace escalation request",
            sizeof(req.justification) - 1);

    if (ioctl(g_trust_fd, TRUST_IOC_ESCALATE, &req) < 0)
        return -1;

    return req.result;
}

int trust_policy_eval(uint32_t subject_id, uint32_t action)
{
    trust_ioc_policy_eval_t req;

    if (g_trust_fd < 0) return TRUST_RESULT_ALLOW;

    req.subject_id = subject_id;
    req.action_type = action;
    req.result = TRUST_RESULT_DENY;

    if (ioctl(g_trust_fd, TRUST_IOC_POLICY_EVAL, &req) < 0)
        return TRUST_RESULT_DENY; /* Error = deny (fail-closed for security) */

    return req.result;
}

int trust_domain_transfer(uint32_t subject_id, uint16_t from_domain,
                          uint16_t to_domain, uint32_t capabilities)
{
    trust_ioc_domain_transfer_t req;

    if (g_trust_fd < 0) return 0;

    req.subject_id = subject_id;
    req.from_domain = from_domain;
    req.to_domain = to_domain;
    req.capabilities = capabilities;
    req.result = -1;

    if (ioctl(g_trust_fd, TRUST_IOC_DOMAIN_TRANSFER, &req) < 0)
        return -1;

    return req.result;
}

int trust_get_subject(uint32_t subject_id, trust_subject_t *out)
{
    trust_ioc_get_subject_t req;

    if (g_trust_fd < 0 || !out) return -1;

    req.subject_id = subject_id;
    memset(&req.subject, 0, sizeof(req.subject));

    if (ioctl(g_trust_fd, TRUST_IOC_GET_SUBJECT, &req) < 0)
        return -1;

    *out = req.subject;
    return 0;
}

int trust_propagate(uint32_t subject_id, int32_t delta)
{
    trust_ioc_propagate_t req;

    if (g_trust_fd < 0) return 0;

    req.subject_id = subject_id;
    req.delta = delta;

    if (ioctl(g_trust_fd, TRUST_IOC_PROPAGATE, &req) < 0)
        return -1;

    return 0;
}

int trust_repartition(void)
{
    if (g_trust_fd < 0) return 0;

    if (ioctl(g_trust_fd, TRUST_IOC_REPARTITION, 0) < 0)
        return -1;

    return 0;
}

int trust_flush_tlb(void)
{
    if (g_trust_fd < 0) return 0;

    if (ioctl(g_trust_fd, TRUST_IOC_FLUSH_TLB, 0) < 0)
        return -1;

    return 0;
}

int trust_get_audit(trust_audit_entry_t *buf, uint32_t max_entries)
{
    trust_ioc_audit_t req;

    if (g_trust_fd < 0 || !buf) return -1;

    req.max_entries = max_entries;
    req.returned = 0;
    req.buf = buf;

    if (ioctl(g_trust_fd, TRUST_IOC_GET_AUDIT, &req) < 0)
        return -1;

    return (int)req.returned;
}

/* --- Dependency graph --- */

int trust_dep_add(uint32_t subject_id, uint32_t depends_on)
{
    trust_ioc_dep_add_t req;

    if (g_trust_fd < 0) return 0;

    req.subject_id = subject_id;
    req.depends_on = depends_on;
    req.result = -1;

    if (ioctl(g_trust_fd, TRUST_IOC_DEP_ADD, &req) < 0)
        return -1;

    return req.result;
}

int trust_dep_remove(uint32_t subject_id, uint32_t depends_on)
{
    trust_ioc_dep_remove_t req;

    if (g_trust_fd < 0) return 0;

    req.subject_id = subject_id;
    req.depends_on = depends_on;

    if (ioctl(g_trust_fd, TRUST_IOC_DEP_REMOVE, &req) < 0)
        return -1;

    return 0;
}

/* --- Escalation queue --- */

int trust_escalation_poll(uint32_t *subject_id, uint32_t *requested_authority,
                          char *justification, uint32_t justification_size,
                          int32_t *current_score, uint32_t *seq)
{
    trust_ioc_escalation_poll_t req;

    if (g_trust_fd < 0) return 0;

    memset(&req, 0, sizeof(req));

    if (ioctl(g_trust_fd, TRUST_IOC_ESCALATION_POLL, &req) < 0)
        return -1;

    if (!req.has_pending)
        return 0;

    if (subject_id) *subject_id = req.subject_id;
    if (requested_authority) *requested_authority = req.requested_authority;
    if (justification && justification_size > 0) {
        strncpy(justification, req.justification, justification_size - 1);
        justification[justification_size - 1] = '\0';
    }
    if (current_score) *current_score = req.current_score;
    if (seq) *seq = req.seq;

    return 1;
}

int trust_escalation_respond(uint32_t seq, int approved)
{
    trust_ioc_escalation_respond_t req;

    if (g_trust_fd < 0) return 0;

    req.seq = seq;
    req.approved = approved ? 1 : 0;

    if (ioctl(g_trust_fd, TRUST_IOC_ESCALATION_RESPOND, &req) < 0)
        return -1;

    return 0;
}

/* === Root of Authority: Self-Consuming Proof Chain === */

int trust_proof_mint(uint32_t subject_id, uint8_t *proof_out)
{
    trust_ioc_proof_mint_t req;

    if (g_trust_fd < 0 || !proof_out) return -1;

    memset(&req, 0, sizeof(req));
    req.subject_id = subject_id;

    if (ioctl(g_trust_fd, TRUST_IOC_PROOF_MINT, &req) < 0)
        return -1;

    if (req.result < 0)
        return req.result;

    memcpy(proof_out, req.proof, TRUST_PROOF_SIZE);
    return 0;
}

int trust_proof_consume(uint32_t subject_id, const uint8_t *current_proof,
                         uint32_t action_type, uint32_t action_result,
                         uint8_t *next_proof_out)
{
    trust_ioc_proof_consume_t req;

    if (g_trust_fd < 0 || !current_proof || !next_proof_out) return -1;

    memset(&req, 0, sizeof(req));
    req.subject_id = subject_id;
    memcpy(req.current_proof, current_proof, TRUST_PROOF_SIZE);
    req.action_type = action_type;
    req.action_result = action_result;

    if (ioctl(g_trust_fd, TRUST_IOC_PROOF_CONSUME, &req) < 0)
        return -1;

    if (req.result < 0)
        return req.result;

    memcpy(next_proof_out, req.next_proof, TRUST_PROOF_SIZE);
    return 0;
}

int trust_proof_fence(uint32_t subject_id)
{
    trust_ioc_proof_fence_t req;

    if (g_trust_fd < 0) return -1;

    req.subject_id = subject_id;
    req.result = 0;

    if (ioctl(g_trust_fd, TRUST_IOC_PROOF_FENCE, &req) < 0)
        return -1;

    return req.result;
}

int trust_proof_verify(uint32_t subject_id)
{
    trust_ioc_proof_verify_t req;

    if (g_trust_fd < 0) return -1;

    memset(&req, 0, sizeof(req));
    req.subject_id = subject_id;

    if (ioctl(g_trust_fd, TRUST_IOC_PROOF_VERIFY, &req) < 0)
        return -1;

    return req.result;
}

int trust_proof_get_nonce(uint32_t subject_id, uint64_t *nonce_out)
{
    trust_ioc_proof_nonce_t req;

    if (g_trust_fd < 0 || !nonce_out) return -1;

    req.subject_id = subject_id;
    req.nonce = 0;

    if (ioctl(g_trust_fd, TRUST_IOC_PROOF_NONCE, &req) < 0)
        return -1;

    *nonce_out = req.nonce;
    return 0;
}

/* === Root of Authority: Token Economy === */

int32_t trust_token_balance(uint32_t subject_id)
{
    trust_ioc_token_balance_t req;

    if (g_trust_fd < 0) return TRUST_TOKEN_MAX_DEFAULT;

    req.subject_id = subject_id;
    req.balance = 0;
    req.max_balance = 0;

    if (ioctl(g_trust_fd, TRUST_IOC_TOKEN_BALANCE, &req) < 0)
        return 0;

    return req.balance;
}

int32_t trust_token_max_balance(uint32_t subject_id)
{
    trust_ioc_token_balance_t req;

    if (g_trust_fd < 0) return TRUST_TOKEN_MAX_DEFAULT;

    req.subject_id = subject_id;
    req.balance = 0;
    req.max_balance = 0;

    if (ioctl(g_trust_fd, TRUST_IOC_TOKEN_BALANCE, &req) < 0)
        return TRUST_TOKEN_MAX_DEFAULT;

    return req.max_balance;
}

int trust_token_burn_action(uint32_t subject_id, uint32_t action_type,
                             int32_t *remaining_out)
{
    trust_ioc_token_burn_t req;

    if (g_trust_fd < 0) return 0;

    req.subject_id = subject_id;
    req.action_type = action_type;
    req.result = 0;
    req.remaining = 0;

    if (ioctl(g_trust_fd, TRUST_IOC_TOKEN_BURN, &req) < 0)
        return -1;

    if (remaining_out)
        *remaining_out = req.remaining;

    return req.result;
}

int trust_token_transfer(uint32_t from_subject, uint32_t to_subject,
                          int32_t amount)
{
    trust_ioc_token_xfer_t req;

    if (g_trust_fd < 0) return -1;

    req.from_subject = from_subject;
    req.to_subject = to_subject;
    req.amount = amount;
    req.result = 0;

    if (ioctl(g_trust_fd, TRUST_IOC_TOKEN_XFER, &req) < 0)
        return -1;

    return req.result;
}

uint32_t trust_token_get_cost(uint32_t action_type)
{
    trust_ioc_token_cost_t req;

    if (g_trust_fd < 0) return 0;

    req.action_type = action_type;
    req.cost = 0;

    if (ioctl(g_trust_fd, TRUST_IOC_TOKEN_COST, &req) < 0)
        return 0;

    return req.cost;
}

/* === Root of Authority: Lifecycle === */

int trust_mitotic_divide(uint32_t parent_id, uint32_t child_id,
                          int32_t *child_max_score_out)
{
    trust_ioc_mitotic_divide_t req;

    if (g_trust_fd < 0) return -1;

    req.parent_id = parent_id;
    req.child_id = child_id;
    req.result = 0;
    req.child_max_score = 0;

    if (ioctl(g_trust_fd, TRUST_IOC_MITOTIC_DIVIDE, &req) < 0)
        return -1;

    if (child_max_score_out)
        *child_max_score_out = req.child_max_score;

    return req.result;
}

int trust_meiotic_combine(uint32_t subject_a, uint32_t subject_b,
                            int32_t *combined_score_out)
{
    trust_ioc_meiotic_combine_t req;

    if (g_trust_fd < 0) return -1;

    req.subject_a = subject_a;
    req.subject_b = subject_b;
    req.result = 0;
    req.combined_score = 0;

    if (ioctl(g_trust_fd, TRUST_IOC_MEIOTIC_COMBINE, &req) < 0)
        return -1;

    if (combined_score_out)
        *combined_score_out = req.combined_score;

    return req.result;
}

int trust_meiotic_release(uint32_t subject_a, uint32_t subject_b)
{
    trust_ioc_meiotic_release_t req;

    if (g_trust_fd < 0) return -1;

    req.subject_a = subject_a;
    req.subject_b = subject_b;

    if (ioctl(g_trust_fd, TRUST_IOC_MEIOTIC_RELEASE, &req) < 0)
        return -1;

    return 0;
}

int trust_apoptosis(uint32_t subject_id)
{
    trust_ioc_apoptosis_t req;

    if (g_trust_fd < 0) return -1;

    req.subject_id = subject_id;
    req.result = 0;

    if (ioctl(g_trust_fd, TRUST_IOC_APOPTOSIS, &req) < 0)
        return -1;

    return req.result;
}

/* === Root of Authority: Chromosome Queries === */

int trust_get_chromosome(uint32_t subject_id, trust_chromosome_t *out)
{
    trust_ioc_get_chromosome_t req;

    if (g_trust_fd < 0 || !out) return -1;

    memset(&req, 0, sizeof(req));
    req.subject_id = subject_id;

    if (ioctl(g_trust_fd, TRUST_IOC_GET_CHROMOSOME, &req) < 0)
        return -1;

    if (req.result < 0)
        return req.result;

    *out = req.chromosome;
    return 0;
}

int trust_get_sex(uint32_t subject_id)
{
    trust_ioc_get_sex_t req;

    if (g_trust_fd < 0) return -1;

    memset(&req, 0, sizeof(req));
    req.subject_id = subject_id;

    if (ioctl(g_trust_fd, TRUST_IOC_GET_SEX, &req) < 0)
        return -1;

    if (req.result < 0)
        return -1;

    return (int)req.sex;
}

/* === Root of Authority: Immune Response === */

int trust_immune_status(uint32_t subject_id)
{
    trust_ioc_immune_status_t req;

    if (g_trust_fd < 0) return -1;

    memset(&req, 0, sizeof(req));
    req.subject_id = subject_id;

    if (ioctl(g_trust_fd, TRUST_IOC_IMMUNE_STATUS, &req) < 0)
        return -1;

    if (req.result < 0)
        return -1;

    return (int)req.status;
}

int trust_quarantine(uint32_t subject_id, uint32_t reason)
{
    trust_ioc_quarantine_t req;

    if (g_trust_fd < 0) return -1;

    req.subject_id = subject_id;
    req.reason = reason;
    req.result = 0;

    if (ioctl(g_trust_fd, TRUST_IOC_QUARANTINE, &req) < 0)
        return -1;

    return req.result;
}

int trust_release_quarantine(uint32_t subject_id)
{
    trust_ioc_release_quarantine_t req;

    if (g_trust_fd < 0) return -1;

    req.subject_id = subject_id;
    req.result = 0;

    if (ioctl(g_trust_fd, TRUST_IOC_RELEASE_QUARANTINE, &req) < 0)
        return -1;

    return req.result;
}
