/*
 * trust_core.c - Root of Authority Kernel Module
 *
 * Creates /dev/trust character device with ioctl interface.
 * Dispatches operations across all RoA subsystems:
 *   - RISC fast-path (TLB-based trust checks)
 *   - FBC complex-path (policy evaluation, escalation)
 *   - Authority Proof Engine (self-consuming proof chain)
 *   - Token Economy (metabolic cost)
 *   - Lifecycle (mitotic/meiotic, immune response)
 *   - Chromosome queries
 *
 * Runs a periodic timer for:
 *   - Trust decay (coupled hysteresis)
 *   - Token regeneration
 *   - Immune system scanning
 *   - Authority repartitioning
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/capability.h>

#include "../include/trust_ioctl.h"
#include "../include/trust_cmd.h"
#include "trust_internal.h"
#include "trust_memory.h"
#include "trust_syscall.h"
#include "trust_attest.h"

#define DEVICE_NAME "trust"
#define CLASS_NAME  "trust"

/* Device state */
static dev_t         trust_dev;
static struct cdev   trust_cdev;
static struct class *trust_class;

/* Decay timer */
static struct timer_list trust_decay_timer;
static u32 trust_decay_tick_count;
#define TRUST_DECAY_INTERVAL_MS 1000  /* 1 second */
#define TRUST_REPARTITION_TICKS 60    /* Repartition every 60 seconds */
#define TRUST_IMMUNE_TICKS      10    /* Immune scan every 10 seconds */

/* --- Timer callback: coupled hysteresis decay + token regen + immune --- */
static void trust_decay_timer_fn(struct timer_list *t)
{
    (void)t;
    trust_risc_decay_tick();
    trust_immune_tick();  /* Token regen + immune scanning */

    trust_decay_tick_count++;

    /* Periodically repartition authority boundaries */
    if (trust_decay_tick_count % TRUST_REPARTITION_TICKS == 0)
        trust_fbc_repartition();

    mod_timer(&trust_decay_timer,
              jiffies + msecs_to_jiffies(TRUST_DECAY_INTERVAL_MS));
}

/* --- Atomic token helpers using trust_tlb_modify (no TOCTOU) --- */

struct token_burn_args {
    u32     action_type;
    int32_t remaining;
    int     result;
};

static int _token_burn_cb(trust_subject_t *subj, void *data)
{
    struct token_burn_args *args = data;
    args->result = trust_token_burn(&subj->tokens, args->action_type);
    args->remaining = subj->tokens.balance;
    return 0;
}

static int subject_token_burn(u32 subject_id, u32 action_type, int32_t *remaining)
{
    struct token_burn_args args = { .action_type = action_type };
    int ret;

    ret = trust_tlb_modify(subject_id, _token_burn_cb, &args);
    if (ret == -ENOENT)
        return -ENOENT;

    if (remaining)
        *remaining = args.remaining;
    return args.result;
}

static int32_t subject_token_balance(u32 subject_id)
{
    trust_subject_t subj;
    if (trust_tlb_lookup(subject_id, &subj))
        return 0;
    return subj.tokens.balance;
}

static int32_t subject_token_max(u32 subject_id)
{
    trust_subject_t subj;
    if (trust_tlb_lookup(subject_id, &subj))
        return TRUST_TOKEN_MAX_DEFAULT;
    return subj.tokens.max_balance;
}

/*
 * Atomic token transfer between two subjects.
 * Acquires both TLB set locks in consistent order (lower set index first)
 * to prevent deadlocks and TOCTOU races.
 *
 * MUST use spin_lock_irqsave: the TLB set locks are taken from softirq
 * context by trust_decay_timer_fn (-> trust_risc_decay_tick /
 * trust_immune_tick). A plain spin_lock() here allows a softirq to
 * deadlock on a lock held by preempted process context on the same CPU.
 */
static int subject_token_transfer(u32 from_id, u32 to_id, int32_t amount)
{
    u32 from_set_idx, to_set_idx;
    trust_tlb_set_t *set_a, *set_b;
    trust_subject_t *from_p = NULL, *to_p = NULL;
    unsigned long flags_a, flags_b = 0;
    int i;

    if (amount <= 0)
        return -EINVAL;
    if (!g_trust_tlb.sets)
        return -ENOMEM;
    /* Reject self-transfer: would double-count total_burned AND
     * total_regenerated on the same subject via aliased from_p/to_p. */
    if (from_id == to_id)
        return -EINVAL;

    /* Must match tlb_hash() inside trust_tlb.c */
    from_set_idx = trust_tlb_set_of(from_id);
    to_set_idx = trust_tlb_set_of(to_id);

    /* Lock sets in consistent order (lower index first) to prevent deadlock */
    if (from_set_idx <= to_set_idx) {
        set_a = &g_trust_tlb.sets[from_set_idx];
        set_b = &g_trust_tlb.sets[to_set_idx];
        spin_lock_irqsave(&set_a->lock, flags_a);
        if (from_set_idx != to_set_idx)
            spin_lock_irqsave(&set_b->lock, flags_b);
    } else {
        set_a = &g_trust_tlb.sets[to_set_idx];
        set_b = &g_trust_tlb.sets[from_set_idx];
        spin_lock_irqsave(&set_a->lock, flags_a);
        spin_lock_irqsave(&set_b->lock, flags_b);
    }

    /* Find source subject */
    for (i = 0; i < TRUST_TLB_WAYS; i++) {
        trust_tlb_set_t *fs = &g_trust_tlb.sets[from_set_idx];
        if ((fs->valid_mask & (1U << i)) &&
            fs->entries[i].subject_id == from_id) {
            from_p = &fs->entries[i];
            break;
        }
    }

    /* Find destination subject */
    for (i = 0; i < TRUST_TLB_WAYS; i++) {
        trust_tlb_set_t *ts = &g_trust_tlb.sets[to_set_idx];
        if ((ts->valid_mask & (1U << i)) &&
            ts->entries[i].subject_id == to_id) {
            to_p = &ts->entries[i];
            break;
        }
    }

    if (!from_p || !to_p) {
        if (from_set_idx != to_set_idx)
            spin_unlock_irqrestore(&set_b->lock, flags_b);
        spin_unlock_irqrestore(&set_a->lock, flags_a);
        return -ENOENT;
    }

    if (from_p->tokens.balance < amount) {
        if (from_set_idx != to_set_idx)
            spin_unlock_irqrestore(&set_b->lock, flags_b);
        spin_unlock_irqrestore(&set_a->lock, flags_a);
        return -ENOSPC;
    }

    from_p->tokens.balance -= amount;
    /* Cap lifetime counters at UINT32_MAX to prevent silent overflow. */
    if (from_p->tokens.total_burned > UINT32_MAX - (u32)amount)
        from_p->tokens.total_burned = UINT32_MAX;
    else
        from_p->tokens.total_burned += (u32)amount;
    /* Prevent signed overflow: clamp before addition */
    if (to_p->tokens.balance > to_p->tokens.max_balance - amount)
        to_p->tokens.balance = to_p->tokens.max_balance;
    else
        to_p->tokens.balance += amount;
    if (to_p->tokens.total_regenerated > UINT32_MAX - (u32)amount)
        to_p->tokens.total_regenerated = UINT32_MAX;
    else
        to_p->tokens.total_regenerated += (u32)amount;
    /* Clear starvation if balance becomes positive */
    if (to_p->tokens.starved && to_p->tokens.balance > 0)
        to_p->tokens.starved = 0;

    if (from_set_idx != to_set_idx)
        spin_unlock_irqrestore(&set_b->lock, flags_b);
    spin_unlock_irqrestore(&set_a->lock, flags_a);
    return 0;
}

/* --- ioctl dispatch --- */
static long trust_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    (void)file;

    /* TRUST_IOC_QUERY_CAPS (T, 110): match by _IOC nr so we stay
     * ABI-compatible with whichever header version libtrust was built
     * against.  The struct definition lives in userspace headers
     * (trust/include/trust_isa.h); we don't need to redefine it
     * kernel-side — just copy out 16 bytes of fixed layout.
     * Allowed for any caller that can open /dev/trust. */
    if (_IOC_TYPE(cmd) == 'T' && _IOC_NR(cmd) == 110 &&
        _IOC_DIR(cmd) == _IOC_READ &&
        _IOC_SIZE(cmd) == 16 /* sizeof(trust_ioc_query_caps_t) */) {
        return trust_cmd_query_caps((void __user *)arg);
    }

    /* Require CAP_SYS_ADMIN for privileged (write) operations.
     * Read-only queries (GET_SCORE, GET_SUBJECT, etc.) are allowed
     * for any process that can open /dev/trust. */
    switch (cmd) {
    case TRUST_IOC_REGISTER:
    case TRUST_IOC_UNREGISTER:
    case TRUST_IOC_ESCALATE:
    case TRUST_IOC_QUARANTINE:
    case TRUST_IOC_RELEASE_QUARANTINE:
    case TRUST_IOC_REPARTITION:
    case TRUST_IOC_FLUSH_TLB:
    case TRUST_IOC_CMD_SUBMIT:
    case TRUST_IOC_TMS_REGISTER_SECTION:
    case TRUST_IOC_TMS_ADD_PATTERN:
    case TRUST_IOC_TMS_SCAN_REGION:
    case TRUST_IOC_TSC_START_TRACE:
    case TRUST_IOC_TSC_STOP_TRACE:
        if (!capable(CAP_SYS_ADMIN))
            return -EPERM;
        break;
    default:
        break;
    }

    switch (cmd) {

    /* === RISC fast-path === */

    case TRUST_IOC_CHECK_CAP: {
        trust_ioc_check_cap_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.result = trust_risc_check_cap(req.subject_id, req.capability);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_GET_SCORE: {
        trust_ioc_get_score_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.score = trust_risc_get_score(req.subject_id);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_RECORD_ACTION: {
        trust_ioc_record_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.new_score = trust_risc_record_action(req.subject_id,
                                                  req.action_type,
                                                  req.result);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_THRESHOLD: {
        trust_ioc_threshold_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.result = trust_risc_threshold_check(req.subject_id,
                                                 req.action_type);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    /* === FBC complex-path === */

    case TRUST_IOC_REGISTER: {
        trust_ioc_register_t req;
        trust_subject_t subj;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        memset(&subj, 0, sizeof(subj));
        subj.subject_id = req.subject_id;
        subj.domain = req.domain;
        subj.authority_level = req.authority;
        subj.trust_score = req.initial_score ? req.initial_score
                                             : TRUST_SCORE_DEFAULT;
        subj.capabilities = trust_default_caps(req.authority);
        subj.threshold_low = -100 - (int32_t)(req.authority * 100);
        subj.threshold_high = 100 + (int32_t)(req.authority * 200);
        subj.decay_rate = 1;
        subj.flags = TRUST_FLAG_NEW;
        subj.last_action_ts = trust_get_timestamp();

        /* Initialize Root of Authority fields */
        trust_chromosome_init(&subj.chromosome, req.subject_id, 0, 0);
        trust_token_init(&subj.tokens, req.authority);
        trust_immune_init(&subj.immune);
        trust_trc_init(&subj.trc);

        /* Lifecycle */
        subj.lifecycle.state = TRUST_LIFECYCLE_EMBRYONIC;
        subj.lifecycle.generation = 0;
        subj.lifecycle.parent_id = 0;
        subj.lifecycle.birth_ts = trust_get_timestamp();
        subj.lifecycle.max_score = TRUST_SCORE_MAX;

        trust_tlb_insert(&subj);

        /* Create proof chain for this subject.  If the APE pool is full we
         * still allow registration but warn loudly — proof-using ops will
         * return -ENOENT later. */
        {
            int ape_ret = trust_ape_create_entity(req.subject_id, NULL, 0);
            if (ape_ret && ape_ret != -EEXIST)
                pr_warn("trust: proof chain not created for subject %u (%d)\n",
                        req.subject_id, ape_ret);
        }

        pr_info("trust: registered subject %u domain=%u auth=%u score=%d "
                "(RoA: chromosome+proof+tokens initialized)\n",
                req.subject_id, req.domain, req.authority, subj.trust_score);
        return 0;
    }

    case TRUST_IOC_UNREGISTER: {
        trust_ioc_unregister_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        trust_tlb_invalidate(req.subject_id);
        trust_ape_destroy_entity(req.subject_id);
        pr_info("trust: unregistered subject %u\n", req.subject_id);
        return 0;
    }

    case TRUST_IOC_ESCALATE: {
        trust_ioc_escalate_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.justification[sizeof(req.justification) - 1] = '\0';
        req.result = trust_fbc_escalate(req.subject_id,
                                         req.requested_authority,
                                         req.justification);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_POLICY_EVAL: {
        trust_ioc_policy_eval_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.result = trust_fbc_policy_eval(req.subject_id,
                                            req.action_type,
                                            &req.matching_rule_idx);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_DOMAIN_TRANSFER: {
        trust_ioc_domain_transfer_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.result = trust_fbc_domain_transfer(req.subject_id,
                                                req.from_domain,
                                                req.to_domain,
                                                req.capabilities);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_GET_SUBJECT: {
        trust_ioc_get_subject_t req;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        if (trust_tlb_lookup(req.subject_id, &req.subject) < 0)
            return -ENOENT;

        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_PROPAGATE: {
        trust_ioc_propagate_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        trust_fbc_propagate(req.subject_id, req.delta);
        return 0;
    }

    case TRUST_IOC_REPARTITION:
        trust_fbc_repartition();
        return 0;

    case TRUST_IOC_FLUSH_TLB:
        trust_tlb_flush();
        return 0;

    /* === Dependency graph === */

    case TRUST_IOC_DEP_ADD: {
        trust_ioc_dep_add_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.result = trust_dep_add(req.subject_id, req.depends_on);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_DEP_REMOVE: {
        trust_ioc_dep_remove_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        trust_dep_remove(req.subject_id, req.depends_on);
        return 0;
    }

    /* === Escalation queue === */

    case TRUST_IOC_ESCALATION_POLL: {
        trust_ioc_escalation_poll_t req;
        trust_escalation_request_t esc_req;

        memset(&req, 0, sizeof(req));
        if (trust_escalation_dequeue(&esc_req) == 0) {
            req.subject_id = esc_req.subject_id;
            req.requested_authority = esc_req.requested_authority;
            memcpy(req.justification, esc_req.justification,
                   sizeof(req.justification));
            req.timestamp = esc_req.timestamp;
            req.current_score = esc_req.current_score;
            req.seq = esc_req.seq;
            req.has_pending = 1;
        } else {
            req.has_pending = 0;
        }

        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_ESCALATION_RESPOND: {
        trust_ioc_escalation_respond_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        return trust_escalation_respond(req.seq, req.approved);
    }

    /* === Self-Consuming Proof Chain (Authority Proof Engine) === */

    case TRUST_IOC_PROOF_MINT: {
        trust_ioc_proof_mint_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        /* APE entity already created at registration.
         * Consume the initial proof and return it as the "mint". */
        req.result = trust_ape_consume_proof(req.subject_id,
                                              NULL, 0, req.proof);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_PROOF_CONSUME: {
        trust_ioc_proof_consume_t req;
        u8 request_data[8]; /* action_type + result as request */

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        /* Build request from action type and result */
        memcpy(request_data, &req.action_type, 4);
        memcpy(request_data + 4, &req.action_result, 4);

        req.result = trust_ape_consume_proof(req.subject_id,
                                              request_data,
                                              sizeof(request_data),
                                              req.next_proof);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_PROOF_FENCE: {
        trust_ioc_proof_fence_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.result = trust_ape_destroy_entity(req.subject_id);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_PROOF_VERIFY: {
        trust_ioc_proof_verify_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.result = trust_ape_verify_chain(req.subject_id);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_PROOF_NONCE: {
        trust_ioc_proof_nonce_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        if (trust_ape_get_nonce(req.subject_id, &req.nonce))
            return -ENOENT;
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    /* === Token Economy (Metabolic Cost) === */

    case TRUST_IOC_TOKEN_BALANCE: {
        trust_ioc_token_balance_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.balance = subject_token_balance(req.subject_id);
        req.max_balance = subject_token_max(req.subject_id);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_TOKEN_BURN: {
        trust_ioc_token_burn_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.result = subject_token_burn(req.subject_id, req.action_type,
                                         &req.remaining);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_TOKEN_XFER: {
        trust_ioc_token_xfer_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.result = subject_token_transfer(req.from_subject, req.to_subject,
                                             req.amount);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_TOKEN_COST: {
        trust_ioc_token_cost_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.cost = trust_token_cost_for_action(req.action_type);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    /* === Lifecycle (Mitotic/Meiotic) === */

    case TRUST_IOC_MITOTIC_DIVIDE: {
        trust_ioc_mitotic_divide_t req;
        trust_subject_t child;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.result = trust_lifecycle_mitotic_divide(req.parent_id, req.child_id);
        if (req.result == 0 && trust_tlb_lookup(req.child_id, &child) == 0)
            req.child_max_score = child.lifecycle.max_score;
        else
            req.child_max_score = 0;
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_MEIOTIC_COMBINE: {
        trust_ioc_meiotic_combine_t req;
        trust_subject_t sa, sb;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.result = trust_lifecycle_meiotic_combine(req.subject_a,
                                                       req.subject_b);
        if (req.result == 0) {
            if (trust_tlb_lookup(req.subject_a, &sa) == 0 &&
                trust_tlb_lookup(req.subject_b, &sb) == 0)
                req.combined_score = sa.trust_score < sb.trust_score ?
                                     sa.trust_score : sb.trust_score;
        }
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_MEIOTIC_RELEASE: {
        trust_ioc_meiotic_release_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        trust_lifecycle_meiotic_release(req.subject_a, req.subject_b);
        return 0;
    }

    case TRUST_IOC_APOPTOSIS: {
        trust_ioc_apoptosis_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.result = trust_lifecycle_apoptosis(req.subject_id);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    /* === Chromosome queries === */

    case TRUST_IOC_GET_CHROMOSOME: {
        trust_ioc_get_chromosome_t req;
        trust_subject_t subj;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        if (trust_tlb_lookup(req.subject_id, &subj)) {
            req.result = -ENOENT;
        } else {
            req.chromosome = subj.chromosome;
            req.result = 0;
        }
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_GET_SEX: {
        trust_ioc_get_sex_t req;
        trust_subject_t subj;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        if (trust_tlb_lookup(req.subject_id, &subj)) {
            req.result = -ENOENT;
        } else {
            req.sex = subj.chromosome.sex;
            req.result = 0;
        }
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    /* === Immune Response === */

    case TRUST_IOC_IMMUNE_STATUS: {
        trust_ioc_immune_status_t req;
        trust_subject_t subj;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        if (trust_tlb_lookup(req.subject_id, &subj)) {
            req.result = -ENOENT;
        } else {
            req.status = subj.immune.status;
            req.suspicious_actions = subj.immune.suspicious_actions;
            req.result = 0;
        }
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_QUARANTINE: {
        trust_ioc_quarantine_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.result = trust_immune_quarantine(req.subject_id, req.reason);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_RELEASE_QUARANTINE: {
        trust_ioc_release_quarantine_t req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.result = trust_immune_release_quarantine(req.subject_id);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    /* === Audit === */

    case TRUST_IOC_GET_AUDIT: {
        trust_ioc_audit_t req;
        u32 count, i, snap_count;
        trust_audit_entry_t *snap;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        if (req.max_entries == 0 || req.max_entries > TRUST_AUDIT_SIZE)
            req.max_entries = TRUST_AUDIT_SIZE;

        /* Snapshot entries under the lock to avoid race with concurrent writes.
         * We copy entries to a kernel buffer first, then copy_to_user outside
         * the lock (copy_to_user can sleep). */
        snap = kvmalloc_array(req.max_entries, sizeof(trust_audit_entry_t), GFP_KERNEL);
        if (!snap)
            return -ENOMEM;

        snap_count = 0;
        spin_lock(&g_trust_audit.lock);
        i = g_trust_audit.tail;
        while (i != g_trust_audit.head && snap_count < req.max_entries) {
            snap[snap_count++] = g_trust_audit.entries[i];
            i = (i + 1) % TRUST_AUDIT_SIZE;
        }
        spin_unlock(&g_trust_audit.lock);

        /* Copy snapshot to userspace outside the lock */
        count = 0;
        for (i = 0; i < snap_count; i++) {
            if (copy_to_user(&req.buf[i], &snap[i], sizeof(trust_audit_entry_t))) {
                kvfree(snap);
                return -EFAULT;
            }
            count++;
        }
        kvfree(snap);

        req.returned = count;
        /*
         * Only copy back the 'returned' count field, NOT the entire struct.
         * trust_ioc_audit_t contains an embedded __user pointer (buf) which
         * must not be copied back to userspace -- it was already valid there
         * and copying kernel-side copy back could leak kernel pointer bits
         * or confuse userspace.  The 'returned' field sits at offset 4.
         */
        if (copy_to_user((void __user *)arg + offsetof(trust_ioc_audit_t, returned),
                         &req.returned, sizeof(req.returned)))
            return -EFAULT;
        return 0;
    }

    /* === Batch command buffer submission === */

    case TRUST_IOC_CMD_SUBMIT:
        return trust_cmd_submit(
            (const trust_ioc_cmd_submit_t __user *)arg);

    /* === Trust Syscall Tracer (TSC) === */

    case TRUST_IOC_TSC_START_TRACE:
    case TRUST_IOC_TSC_STOP_TRACE:
    case TRUST_IOC_TSC_GET_STATS:
    case TRUST_IOC_TSC_GET_EVENTS:
        return tsc_ioctl(cmd, arg);

    /* === Trust Memory Scanner (TMS) === */

    case TRUST_IOC_TMS_QUERY_MAP:
    case TRUST_IOC_TMS_REGISTER_SECTION:
    case TRUST_IOC_TMS_ADD_PATTERN:
    case TRUST_IOC_TMS_SCAN_REGION:
        return tms_ioctl(cmd, arg);

    default:
        return -ENOTTY;
    }
}

/* --- File operations --- */
static int trust_open(struct inode *inode, struct file *file)
{
    (void)inode;
    (void)file;
    return 0;
}

static int trust_release(struct inode *inode, struct file *file)
{
    (void)inode;
    (void)file;
    return 0;
}

/*
 * 32-bit compat ioctl: not supported.
 * The trust ioctl structs contain embedded pointers (e.g. trust_ioc_audit_t.buf)
 * and 64-bit fields that would need proper thunking for 32-bit userspace.
 * Until that is implemented, reject cleanly.
 */
static long trust_compat_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    (void)f; (void)cmd; (void)arg;
    pr_warn("trust: 32-bit ioctl not supported\n");
    return -ENOTTY;
}

static const struct file_operations trust_fops = {
    .owner          = THIS_MODULE,
    .open           = trust_open,
    .release        = trust_release,
    .unlocked_ioctl = trust_ioctl,
    .compat_ioctl   = trust_compat_ioctl,
};

/* --- Module init/exit --- */
static int __init trust_init(void)
{
    int ret;
    struct device *dev;

    pr_info("trust: Root of Authority module loading...\n");

    /*
     * Boot attestation MUST run first.  If the PCR 11 measurement
     * does not match the value provisioned by the bootc image build,
     * we refuse to create /dev/trust — authority operations silently
     * disable.  On hardware without a TPM 2.0 chip (or with explicit
     * trust.attest=skip), we degrade to SOFTWARE mode and continue,
     * but with a prominent dmesg warning that userspace can see.
     * See trust/kernel/trust_attest.c and docs/research/s72_gamma_tpm2_attest.md.
     */
    ret = trust_attest_init();
    if (ret != 0) {
        pr_err("trust: attestation FAILED — module refusing to initialize (rc=%d)\n",
               ret);
        trust_attest_cleanup();
        return -EACCES;
    }
    pr_info("trust: attestation mode = %s\n",
            trust_attest_mode_name(trust_attest_mode()));

    /* Initialize all subsystems */
    ret = trust_tlb_init();
    if (ret < 0) {
        pr_err("trust: TLB init failed\n");
        return ret;
    }
    trust_policy_init_defaults();
    trust_dna_gate_init();
    trust_dep_graph_init();
    trust_escalation_queue_init();
    trust_ape_init();
    trust_lifecycle_init();

    /* Initialize Trust Memory Scanner */
    ret = tms_init();
    if (ret < 0) {
        pr_err("trust: TMS init failed (%d)\n", ret);
        trust_tlb_cleanup();
        return ret;
    }

    /* Initialize Trust Syscall Tracer */
    ret = tsc_init();
    if (ret < 0) {
        pr_err("trust: TSC init failed (%d)\n", ret);
        tms_cleanup();
        trust_tlb_cleanup();
        return ret;
    }

    /* Register character device */
    ret = alloc_chrdev_region(&trust_dev, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_err("trust: failed to allocate chrdev region\n");
        tsc_cleanup();
        tms_cleanup();
        trust_tlb_cleanup();
        return ret;
    }

    cdev_init(&trust_cdev, &trust_fops);
    trust_cdev.owner = THIS_MODULE;
    ret = cdev_add(&trust_cdev, trust_dev, 1);
    if (ret < 0) {
        unregister_chrdev_region(trust_dev, 1);
        tsc_cleanup();
        tms_cleanup();
        trust_tlb_cleanup();
        pr_err("trust: failed to add cdev\n");
        return ret;
    }

    trust_class = class_create(CLASS_NAME);
    if (IS_ERR(trust_class)) {
        cdev_del(&trust_cdev);
        unregister_chrdev_region(trust_dev, 1);
        tsc_cleanup();
        tms_cleanup();
        trust_tlb_cleanup();
        pr_err("trust: failed to create class\n");
        return PTR_ERR(trust_class);
    }

    dev = device_create(trust_class, NULL, trust_dev, NULL, DEVICE_NAME);
    if (IS_ERR(dev)) {
        class_destroy(trust_class);
        cdev_del(&trust_cdev);
        unregister_chrdev_region(trust_dev, 1);
        tsc_cleanup();
        tms_cleanup();
        trust_tlb_cleanup();
        pr_err("trust: failed to create device\n");
        return PTR_ERR(dev);
    }

    /* Start decay timer */
    timer_setup(&trust_decay_timer, trust_decay_timer_fn, 0);
    mod_timer(&trust_decay_timer,
              jiffies + msecs_to_jiffies(TRUST_DECAY_INTERVAL_MS));

    /* Register /sys/kernel/trust/{stats,caps}.  Non-fatal on failure:
     * the module stays functional (dispatcher still runs) but the
     * observability surface is hidden.  Logged once for admins. */
    if (trust_stats_register() < 0)
        pr_warn("trust: stats sysfs registration failed; /sys/kernel/trust/{stats,caps} will be absent\n");

    pr_info("trust: Root of Authority module loaded - /dev/trust created\n");
    pr_info("trust: Architecture: Dynamic Hyperlation with Self-Consuming Proof Chain\n");
    pr_info("trust: TLB: %d sets x %d ways = %d entries\n",
            TRUST_TLB_SETS, TRUST_TLB_WAYS, TRUST_TLB_SETS * TRUST_TLB_WAYS);
    pr_info("trust: APE: %d max proof chain entities\n", TRUST_APE_MAX_ENTITIES);
    pr_info("trust: Chromosomes: %d segment pairs per subject\n",
            TRUST_CHROMOSOME_PAIRS);
    pr_info("trust: ISA families: AUTH TRUST GATE RES LIFE META (%d families)\n",
            TRUST_ISA_FAMILY_COUNT);
    pr_info("trust: AUTH: MINT, BURN, FENCE, VERIFY, NONCE (proof chain)\n");
    pr_info("trust: TRUST: CHECK_CAP, GET_SCORE, RECORD, THRESHOLD, DECAY, "
            "TRANSLATE, POLICY_EVAL, ESCALATE, PROPAGATE\n");
    pr_info("trust: GATE: TRANSLATE, CHECK (DNA Gate + IRNA Translator)\n");
    pr_info("trust: RES: BALANCE, BURN, XFER, COST (token economy)\n");
    pr_info("trust: LIFE: DIVIDE, COMBINE, RELEASE, APOPTOSIS, "
            "IMMUNE_EVAL, QUARANTINE, RELEASE_Q\n");
    pr_info("trust: META: REPARTITION, AUDIT, FLUSH, GET_SUBJECT, "
            "GET_CHROMOSOME, GET_SEX, IMMUNE_STATUS\n");
    pr_info("trust: TRC: resistance=%u threshold_bias=%d cost_multiplier=%u "
            "state=NORMAL\n", 100, 0, 256);
    pr_info("trust: TMS: memory scanner active, %u subject slots, "
            "netlink proto %d\n", TMS_MAX_SUBJECTS, TMS_NETLINK_PROTO);
    pr_info("trust: TSC: syscall tracer active, %u subject slots, "
            "netlink proto %d\n", TSC_MAX_SUBJECTS, TSC_NETLINK_PROTO);

    return 0;
}

static void __exit trust_exit(void)
{
    timer_shutdown_sync(&trust_decay_timer);
    trust_stats_unregister();
    tsc_cleanup();
    tms_cleanup();
    device_destroy(trust_class, trust_dev);
    class_destroy(trust_class);
    cdev_del(&trust_cdev);
    unregister_chrdev_region(trust_dev, 1);
    /* Release the RCU-published policy snapshot allocated by
     * trust_policy_init_defaults (and any republish from
     * trust_policy_add_rule).  Must happen after the decay timer is
     * shut down (no more softirq readers) and after the chrdev is
     * torn down (no more ioctl paths will call into policy). */
    trust_policy_cleanup();
    trust_tlb_cleanup();
    trust_attest_cleanup();
    pr_info("trust: Root of Authority module unloaded\n");
}

module_init(trust_init);
module_exit(trust_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("AI Arch Linux Project / Elijah Isaiah Roberts (RoA architecture)");
MODULE_DESCRIPTION("Root of Authority - Dynamic Hyperlation Trust Architecture");
MODULE_VERSION("1.0.0");
