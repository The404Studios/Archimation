/*
 * trust_fbc.c - FBC (Feedback Control) Layer: Complex Trust Instructions
 *
 * Multi-step operations requiring policy evaluation, cross-domain
 * negotiation, and AI observer consultation. These are the "feedback
 * control" layer — slower but more powerful:
 *
 *   TRUST_POLICY_EVAL     - Walk policy chain, evaluate conditions
 *   TRUST_ESCALATE        - Multi-step authority escalation
 *   TRUST_DOMAIN_TRANSFER - Cross-domain trust via DNA Gate
 *   TRUST_PROPAGATE       - Cascade trust changes to dependents
 *   TRUST_REPARTITION     - Recompute authority boundaries
 *   TRUST_AUDIT           - Write to audit ring buffer
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/wait.h>
#include "trust_internal.h"

trust_policy_table_t g_trust_policy;
trust_audit_ring_t   g_trust_audit;
trust_dep_graph_t    g_trust_deps;
trust_escalation_queue_t g_trust_escalations;

/* --- Policy Initialization --- */

void trust_policy_init_defaults(void)
{
    spin_lock_init(&g_trust_policy.lock);
    spin_lock_init(&g_trust_audit.lock);
    g_trust_policy.count = 0;
    g_trust_audit.head = 0;
    g_trust_audit.tail = 0;

    /* Default policy rules for each action type */
    static const trust_policy_rule_t defaults[] = {
        /* domain,        action,                    min_trust, req_caps,          +ok, -fail, -viol */
        { 0xFFFFFFFF, TRUST_ACTION_FILE_OPEN,         0,   TRUST_CAP_FILE_READ,      1,  -2,  -10, 0 },
        { 0xFFFFFFFF, TRUST_ACTION_FILE_WRITE,       100,  TRUST_CAP_FILE_WRITE,     1,  -5,  -20, 0 },
        { 0xFFFFFFFF, TRUST_ACTION_NET_CONNECT,      100,  TRUST_CAP_NET_CONNECT,    2,  -5,  -15, 0 },
        { 0xFFFFFFFF, TRUST_ACTION_NET_LISTEN,       300,  TRUST_CAP_NET_LISTEN,     3,  -10, -25, 0 },
        { 0xFFFFFFFF, TRUST_ACTION_PROCESS_CREATE,   200,  TRUST_CAP_PROCESS_CREATE, 2,  -10, -30, 0 },
        { 0xFFFFFFFF, TRUST_ACTION_PROCESS_SIGNAL,   300,  TRUST_CAP_PROCESS_SIGNAL, 1,  -15, -40, 0 },
        { 0xFFFFFFFF, TRUST_ACTION_REGISTRY_READ,      0,  TRUST_CAP_REGISTRY_READ,  0,  -1,  -5,  0 },
        { 0xFFFFFFFF, TRUST_ACTION_REGISTRY_WRITE,   200,  TRUST_CAP_REGISTRY_WRITE, 1,  -5,  -15, 0 },
        { 0xFFFFFFFF, TRUST_ACTION_DEVICE_OPEN,      500,  TRUST_CAP_DEVICE_ACCESS,  3,  -20, -50, 0 },
        { 0xFFFFFFFF, TRUST_ACTION_SERVICE_START,    300,  TRUST_CAP_SERVICE_CONTROL,2,  -10, -30, 0 },
        { 0xFFFFFFFF, TRUST_ACTION_SERVICE_STOP,     300,  TRUST_CAP_SERVICE_CONTROL,1,  -10, -30, 0 },
        { 0xFFFFFFFF, TRUST_ACTION_FIREWALL_CHANGE,  500,  TRUST_CAP_FIREWALL_MODIFY,3,  -20, -50, 0 },
        { 0xFFFFFFFF, TRUST_ACTION_TRUST_CHANGE,     700,  TRUST_CAP_TRUST_MODIFY,   5,  -30, -80, 0 },
        { 0xFFFFFFFF, TRUST_ACTION_ESCALATE,         500,  0,                        0,  -20, -50, 0 },
        { 0xFFFFFFFF, TRUST_ACTION_DOMAIN_TRANSFER,  400,  0,                        2,  -15, -40, 0 },
    };

    int i;
    spin_lock(&g_trust_policy.lock);
    for (i = 0; i < (int)(sizeof(defaults) / sizeof(defaults[0])); i++) {
        if (g_trust_policy.count < TRUST_MAX_POLICIES) {
            g_trust_policy.rules[g_trust_policy.count++] = defaults[i];
        }
    }
    spin_unlock(&g_trust_policy.lock);
}

int trust_policy_add_rule(const trust_policy_rule_t *rule)
{
    int ret = -1;
    spin_lock(&g_trust_policy.lock);
    if (g_trust_policy.count < TRUST_MAX_POLICIES) {
        g_trust_policy.rules[g_trust_policy.count++] = *rule;
        ret = 0;
    }
    spin_unlock(&g_trust_policy.lock);
    return ret;
}

/* --- TRUST_POLICY_EVAL --- */
int trust_fbc_policy_eval(u32 subject_id, u32 action, u32 *matching_rule_idx)
{
    trust_subject_t subj;
    int i;
    int result = TRUST_RESULT_DENY;

    if (trust_tlb_lookup(subject_id, &subj) < 0) {
        if (matching_rule_idx) *matching_rule_idx = 0xFFFFFFFF;
        return TRUST_RESULT_DENY;
    }

    if (subj.flags & TRUST_FLAG_FROZEN) {
        if (matching_rule_idx) *matching_rule_idx = 0xFFFFFFFF;
        return TRUST_RESULT_DENY;
    }

    /* Token starvation suspends capabilities (Theorem 6) */
    if (subj.tokens.starved) {
        if (matching_rule_idx) *matching_rule_idx = 0xFFFFFFFF;
        return TRUST_RESULT_DENY;
    }

    spin_lock(&g_trust_policy.lock);
    for (i = 0; i < g_trust_policy.count; i++) {
        trust_policy_rule_t *rule = &g_trust_policy.rules[i];

        /* Check domain match (0xFFFFFFFF = all domains) */
        if (rule->domain != 0xFFFFFFFF && rule->domain != subj.domain)
            continue;

        /* Check action match */
        if (rule->action_type != action)
            continue;

        /* Found matching rule */
        if (matching_rule_idx) *matching_rule_idx = (u32)i;

        /* TRC Integration: apply threshold bias to min_trust */
        {
            /* Clamp threshold_bias to prevent overflow from flipping the comparison */
            int32_t bias = subj.trc.threshold_bias;
            if (bias > 50) bias = 50;
            if (bias < -50) bias = -50;
            int32_t biased_min = rule->min_trust + bias;
            /* Clamp result to valid trust range [0, 100] */
            if (biased_min < 0) biased_min = 0;
            if (biased_min > 100) biased_min = 100;

            if (subj.trust_score < biased_min) {
                result = TRUST_RESULT_DENY;
                break;
            }
        }

        /* Check required capabilities */
        if (rule->required_caps &&
            (subj.capabilities & rule->required_caps) != rule->required_caps) {
            /* Missing capabilities: might need escalation */
            result = TRUST_RESULT_ESCALATE;
            break;
        }

        result = TRUST_RESULT_ALLOW;
        break;
    }
    spin_unlock(&g_trust_policy.lock);

    return result;
}

/* --- TRUST_ESCALATE --- */
int trust_fbc_escalate(u32 subject_id, u32 requested_authority,
                       const char *justification)
{
    trust_subject_t subj;
    int32_t required_score;

    if (trust_tlb_lookup(subject_id, &subj) < 0)
        return -1;

    if (subj.flags & TRUST_FLAG_FROZEN)
        return -1;

    /* Already at or above requested level */
    if (subj.authority_level >= requested_authority)
        return 0;

    /* Score requirements for escalation */
    switch (requested_authority) {
    case TRUST_AUTH_USER:    required_score = 100; break;
    case TRUST_AUTH_SERVICE: required_score = 300; break;
    case TRUST_AUTH_ADMIN:   required_score = 600; break;
    case TRUST_AUTH_KERNEL:  required_score = 900; break;
    default:                 return -1;
    }

    /* TRC Integration: apply threshold bias to escalation requirements */
    required_score += subj.trc.threshold_bias;

    if (subj.trust_score < required_score) {
        /* Denied: apply penalty */
        subj.trust_score = trust_clamp_score(subj.trust_score - 20);
        trust_tlb_insert(&subj);
        return -1;
    }

    /*
     * For ADMIN and KERNEL escalations, require AI observer approval.
     * Queue the request and return -EAGAIN to indicate pending.
     * The AI daemon polls the escalation queue and responds.
     * USER and SERVICE escalations are auto-granted if score is sufficient.
     */
    if (requested_authority >= TRUST_AUTH_ADMIN) {
        subj.flags |= TRUST_FLAG_ESCALATING;
        trust_tlb_insert(&subj);

        if (trust_escalation_enqueue(subject_id, requested_authority,
                                      justification, subj.trust_score) == 0) {
            pr_info("trust: subject %u escalation to %u queued for AI approval (score=%d)\n",
                    subject_id, requested_authority, subj.trust_score);
            return -EAGAIN; /* Pending AI approval */
        }
        /* Queue full: DENY escalation rather than auto-grant (security) */
        subj.flags &= ~TRUST_FLAG_ESCALATING;
        trust_tlb_insert(&subj);
        pr_warn("trust: escalation queue full, DENYING subject %u escalation to %u\n",
                subject_id, requested_authority);
        return -EAGAIN;
    }

    /* Grant escalation (auto-grant for USER/SERVICE, or queue-full fallback) */
    subj.authority_level = requested_authority;
    subj.capabilities = trust_default_caps(requested_authority);
    subj.flags &= ~TRUST_FLAG_ESCALATING;
    trust_tlb_insert(&subj);

    pr_info("trust: subject %u escalated to authority %u (score=%d)\n",
            subject_id, requested_authority, subj.trust_score);

    return 0;
}

/* --- TRUST_DOMAIN_TRANSFER --- */
int trust_fbc_domain_transfer(u32 subject_id, u16 from, u16 to, u32 caps)
{
    /* Delegate to DNA Gate for the actual translation */
    return trust_dna_gate_translate(subject_id, caps, from, to);
}

/* --- TRUST_PROPAGATE --- */

/*
 * Find all subjects that depend on the given subject_id.
 * Returns the number of dependents found (up to max_out).
 * Must be called with g_trust_deps.lock held.
 */
static int _find_dependents(u32 subject_id, u32 *out, int max_out)
{
    int i, j, count = 0;

    for (i = 0; i < g_trust_deps.count && count < max_out; i++) {
        trust_dep_entry_t *e = &g_trust_deps.entries[i];
        for (j = 0; j < (int)e->dep_count; j++) {
            if (e->depends_on[j] == subject_id) {
                out[count++] = e->subject_id;
                break;
            }
        }
    }
    return count;
}

void trust_fbc_propagate(u32 subject_id, int32_t delta)
{
    trust_subject_t subj;
    u32 dependents[32];
    int dep_count, i;
    int32_t scaled_delta;
    u32 old_caps;
    int32_t old_score;

    /* Step 1: Apply delta to the originating subject */
    if (trust_tlb_lookup(subject_id, &subj) < 0)
        return;

    old_score = subj.trust_score;
    old_caps = subj.capabilities;
    subj.trust_score = trust_clamp_score(subj.trust_score + delta);
    subj.last_action_ts = trust_get_timestamp();
    trust_tlb_insert(&subj);

    trust_fbc_audit(subject_id, TRUST_ACTION_TRUST_CHANGE,
                    old_score, subj.trust_score, old_caps, subj.capabilities);

    /* Step 2: Find subjects that depend on this one and cascade */
    spin_lock(&g_trust_deps.lock);
    dep_count = _find_dependents(subject_id, dependents, 32);
    spin_unlock(&g_trust_deps.lock);

    if (dep_count == 0)
        return;

    /*
     * Apply scaled delta to dependents (50% of original).
     * This implements the feedback loop: trust changes cascade through
     * the dependency graph with diminishing impact.
     * We only go one level deep to prevent runaway propagation.
     */
    scaled_delta = delta / 2;
    if (scaled_delta == 0)
        scaled_delta = (delta > 0) ? 1 : -1;

    for (i = 0; i < dep_count; i++) {
        trust_subject_t dep_subj;

        if (trust_tlb_lookup(dependents[i], &dep_subj) < 0)
            continue;

        if (dep_subj.flags & TRUST_FLAG_FROZEN)
            continue;

        old_score = dep_subj.trust_score;
        old_caps = dep_subj.capabilities;
        dep_subj.trust_score = trust_clamp_score(dep_subj.trust_score + scaled_delta);
        dep_subj.last_action_ts = trust_get_timestamp();

        /* Check threshold crossings on dependents */
        if (dep_subj.trust_score <= dep_subj.threshold_low) {
            dep_subj.capabilities &= trust_default_caps(TRUST_AUTH_NONE);
            if (dep_subj.authority_level > TRUST_AUTH_NONE)
                dep_subj.authority_level = TRUST_AUTH_NONE;
        }

        trust_tlb_insert(&dep_subj);

        trust_fbc_audit(dependents[i], TRUST_ACTION_TRUST_CHANGE,
                        old_score, dep_subj.trust_score, old_caps,
                        dep_subj.capabilities);

        pr_debug("trust: propagated %+d to dependent %u (new score=%d)\n",
                 scaled_delta, dependents[i], dep_subj.trust_score);
    }

    pr_debug("trust: propagated delta %+d from subject %u to %d dependents\n",
             delta, subject_id, dep_count);
}

/* --- TRUST_REPARTITION --- */
void trust_fbc_repartition(void)
{
    /*
     * Dynamic authority partitioning: recompute authority boundaries
     * based on current trust landscape. This is the "emergent governance"
     * mechanism — the system self-organizes trust relationships.
     *
     * In a full implementation, this would:
     * 1. Scan all active subjects
     * 2. Compute percentile boundaries
     * 3. Adjust threshold_low/threshold_high per subject
     * 4. Promote/demote subjects whose scores crossed new boundaries
     */
    int set, way;

    for (set = 0; set < TRUST_TLB_SETS; set++) {
        trust_tlb_set_t *s = &g_trust_tlb.sets[set];

        spin_lock(&s->lock);
        for (way = 0; way < TRUST_TLB_WAYS; way++) {
            trust_subject_t *subj;

            if (!(s->valid_mask & (1U << way)))
                continue;

            subj = &s->entries[way];

            /* Adjust thresholds based on current score and authority */
            subj->threshold_low = -100 - (int32_t)(subj->authority_level * 100);
            subj->threshold_high = 100 + (int32_t)(subj->authority_level * 200);
        }
        spin_unlock(&s->lock);
    }
}

/* --- TRUST_AUDIT --- */
void trust_fbc_audit(u32 subject_id, u32 action, int32_t old_score,
                     int32_t new_score, u32 old_caps, u32 new_caps)
{
    trust_audit_entry_t entry;

    entry.timestamp = trust_get_timestamp();
    entry.subject_id = subject_id;
    entry.action_type = action;
    entry.old_score = old_score;
    entry.new_score = new_score;
    entry.old_caps = old_caps;
    entry.new_caps = new_caps;
    entry.result = (new_score >= old_score) ? 0 : 1;
    entry._padding = 0;

    spin_lock(&g_trust_audit.lock);
    g_trust_audit.entries[g_trust_audit.head] = entry;
    g_trust_audit.head = (g_trust_audit.head + 1) % TRUST_AUDIT_SIZE;
    if (g_trust_audit.head == g_trust_audit.tail)
        g_trust_audit.tail = (g_trust_audit.tail + 1) % TRUST_AUDIT_SIZE;
    spin_unlock(&g_trust_audit.lock);
}

/* ================================================================
 * Dependency Graph Management
 * ================================================================ */

void trust_dep_graph_init(void)
{
    spin_lock_init(&g_trust_deps.lock);
    g_trust_deps.count = 0;
}

/* Find or create a dependency entry for subject_id. Lock must be held. */
static trust_dep_entry_t *_dep_find_or_create(u32 subject_id)
{
    int i;

    for (i = 0; i < g_trust_deps.count; i++) {
        if (g_trust_deps.entries[i].subject_id == subject_id)
            return &g_trust_deps.entries[i];
    }

    /* Create new entry */
    if (g_trust_deps.count >= TRUST_MAX_DEP_ENTRIES)
        return NULL;

    i = g_trust_deps.count++;
    g_trust_deps.entries[i].subject_id = subject_id;
    g_trust_deps.entries[i].dep_count = 0;
    return &g_trust_deps.entries[i];
}

int trust_dep_add(u32 subject_id, u32 depends_on)
{
    trust_dep_entry_t *e;
    int ret = -1;
    u32 i;

    spin_lock(&g_trust_deps.lock);
    e = _dep_find_or_create(subject_id);
    if (!e) {
        spin_unlock(&g_trust_deps.lock);
        return -1;
    }

    /* Check for duplicate */
    for (i = 0; i < e->dep_count; i++) {
        if (e->depends_on[i] == depends_on) {
            spin_unlock(&g_trust_deps.lock);
            return 0; /* Already exists */
        }
    }

    if (e->dep_count < TRUST_MAX_DEPS) {
        e->depends_on[e->dep_count++] = depends_on;
        ret = 0;
    }
    spin_unlock(&g_trust_deps.lock);

    if (ret == 0)
        pr_debug("trust: dep added: %u depends on %u\n", subject_id, depends_on);
    return ret;
}

int trust_dep_remove(u32 subject_id, u32 depends_on)
{
    int i;
    u32 j;

    spin_lock(&g_trust_deps.lock);
    for (i = 0; i < g_trust_deps.count; i++) {
        trust_dep_entry_t *e = &g_trust_deps.entries[i];
        if (e->subject_id != subject_id)
            continue;

        for (j = 0; j < e->dep_count; j++) {
            if (e->depends_on[j] == depends_on) {
                /* Shift remaining entries */
                e->dep_count--;
                for (; j < e->dep_count; j++)
                    e->depends_on[j] = e->depends_on[j + 1];
                spin_unlock(&g_trust_deps.lock);
                return 0;
            }
        }
    }
    spin_unlock(&g_trust_deps.lock);
    return -1;
}

/* ================================================================
 * Escalation Queue (AI Observer Approval Flow)
 * ================================================================ */

void trust_escalation_queue_init(void)
{
    spin_lock_init(&g_trust_escalations.lock);
    g_trust_escalations.head = 0;
    g_trust_escalations.tail = 0;
    g_trust_escalations.seq_counter = 1;
    init_waitqueue_head(&g_trust_escalations.waitq);
}

int trust_escalation_enqueue(u32 subject_id, u32 authority,
                              const char *justification, int32_t score)
{
    trust_escalation_request_t *req;
    u32 next_head;

    spin_lock(&g_trust_escalations.lock);
    next_head = (g_trust_escalations.head + 1) % TRUST_ESCALATION_QUEUE_SIZE;

    if (next_head == g_trust_escalations.tail) {
        /* Queue full */
        spin_unlock(&g_trust_escalations.lock);
        return -1;
    }

    req = &g_trust_escalations.entries[g_trust_escalations.head];
    req->subject_id = subject_id;
    req->requested_authority = authority;
    req->timestamp = trust_get_timestamp();
    req->current_score = score;
    req->status = 0; /* pending */
    req->seq = g_trust_escalations.seq_counter++;

    if (justification) {
        strscpy(req->justification, justification, sizeof(req->justification));
    } else {
        req->justification[0] = '\0';
    }

    g_trust_escalations.head = next_head;
    spin_unlock(&g_trust_escalations.lock);

    /* Wake any userspace process waiting for escalation requests */
    wake_up_interruptible(&g_trust_escalations.waitq);

    return 0;
}

int trust_escalation_dequeue(trust_escalation_request_t *out)
{
    spin_lock(&g_trust_escalations.lock);

    if (g_trust_escalations.head == g_trust_escalations.tail) {
        spin_unlock(&g_trust_escalations.lock);
        return -1; /* Empty */
    }

    *out = g_trust_escalations.entries[g_trust_escalations.tail];
    g_trust_escalations.tail =
        (g_trust_escalations.tail + 1) % TRUST_ESCALATION_QUEUE_SIZE;

    spin_unlock(&g_trust_escalations.lock);
    return 0;
}

int trust_escalation_respond(u32 seq, u32 approved)
{
    trust_subject_t subj;
    u32 i;

    /*
     * Walk the recent queue to find the request with this sequence number.
     * Since we've already dequeued, we scan the TLB for the subject and
     * apply the approval.
     */

    /* Find the escalating subject by scanning TLB for ESCALATING flag */
    spin_lock(&g_trust_escalations.lock);

    /* Search recent entries (they may have been dequeued already) */
    for (i = 0; i < TRUST_ESCALATION_QUEUE_SIZE; i++) {
        if (g_trust_escalations.entries[i].seq == seq) {
            trust_escalation_request_t *req = &g_trust_escalations.entries[i];
            u32 sid = req->subject_id;
            u32 auth = req->requested_authority;

            req->status = approved ? 1 : 2;
            spin_unlock(&g_trust_escalations.lock);

            if (trust_tlb_lookup(sid, &subj) < 0)
                return -1;

            if (approved) {
                subj.authority_level = auth;
                subj.capabilities = trust_default_caps(auth);
                subj.flags &= ~TRUST_FLAG_ESCALATING;
                trust_tlb_insert(&subj);

                pr_info("trust: AI approved escalation for subject %u to authority %u\n",
                        sid, auth);
            } else {
                subj.trust_score = trust_clamp_score(subj.trust_score - 30);
                subj.flags &= ~TRUST_FLAG_ESCALATING;
                trust_tlb_insert(&subj);

                pr_info("trust: AI denied escalation for subject %u (penalty applied)\n",
                        sid);
            }
            return 0;
        }
    }

    spin_unlock(&g_trust_escalations.lock);
    return -1; /* Request not found */
}

MODULE_LICENSE("GPL");
