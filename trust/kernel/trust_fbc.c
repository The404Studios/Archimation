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
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/lockdep.h>
#include "trust_internal.h"

trust_policy_table_t g_trust_policy;
trust_audit_ring_t   g_trust_audit;
trust_dep_graph_t    g_trust_deps;
trust_escalation_queue_t g_trust_escalations;

/*
 * Session 33: RCU-published snapshot of the policy table.  Readers
 * take rcu_read_lock / rcu_dereference, writers publish via
 * rcu_assign_pointer under g_trust_policy_write_lock and kfree_rcu
 * the old snapshot after a grace period.  The snapshot's rules_ref
 * aliases g_trust_policy.rules (an append-only array that is never
 * reallocated) so the only thing the snapshot owns exclusively is
 * the (rule_count, rcu_head) pair.
 */
trust_policy_snapshot_t __rcu *g_trust_policy_rcu;
DEFINE_MUTEX(g_trust_policy_write_lock);

/*
 * Publish helper.  Caller MUST hold g_trust_policy_write_lock.
 * Allocates a new snapshot, stamps it with the current rule count,
 * publishes via rcu_assign_pointer, and schedules the old snapshot
 * for release via kfree_rcu (no synchronous stall; readers that
 * already hold the old pointer drain naturally under the next RCU
 * grace period).
 */
static int _trust_policy_publish_snapshot(int rule_count)
{
    trust_policy_snapshot_t *new_snap, *old_snap;

    lockdep_assert_held(&g_trust_policy_write_lock);

    new_snap = kzalloc(sizeof(*new_snap), GFP_KERNEL);
    if (!new_snap)
        return -ENOMEM;

    new_snap->rule_count = rule_count;
    new_snap->rules_ref  = g_trust_policy.rules;

    /*
     * rcu_dereference_protected tells lockdep we hold the writer
     * lock, so it won't warn about a raw pointer fetch outside
     * rcu_read_lock.
     */
    old_snap = rcu_dereference_protected(g_trust_policy_rcu,
                lockdep_is_held(&g_trust_policy_write_lock));

    rcu_assign_pointer(g_trust_policy_rcu, new_snap);

    if (old_snap)
        kfree_rcu(old_snap, rcu);

    return 0;
}

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
    int final_count;
    /*
     * Policy rules are append-only from this point on.  Legacy
     * readers (trust_risc.c, not editable) snapshot count via
     * READ_ONCE() with an smp_rmb fence — that path still works.
     * RCU readers (trust_fbc.c) use rcu_dereference(g_trust_policy_rcu)
     * and see the published snapshot.  Writer takes BOTH the
     * outer mutex (for lockdep-checked RCU publish) and the legacy
     * spinlock (for the array append).
     */
    mutex_lock(&g_trust_policy_write_lock);
    spin_lock(&g_trust_policy.lock);
    for (i = 0; i < (int)(sizeof(defaults) / sizeof(defaults[0])); i++) {
        int slot = g_trust_policy.count;
        if (slot < TRUST_MAX_POLICIES) {
            g_trust_policy.rules[slot] = defaults[i];
            smp_wmb();
            WRITE_ONCE(g_trust_policy.count, slot + 1);
        }
    }
    final_count = g_trust_policy.count;
    spin_unlock(&g_trust_policy.lock);

    /* One RCU publish covers all default rules.  Ignore -ENOMEM here:
     * the fallback (rcu pointer still NULL) just means RCU readers see
     * no rules, which is still safe (default DENY).  Callers of
     * trust_policy_add_rule later will retry publishing. */
    (void)_trust_policy_publish_snapshot(final_count);
    mutex_unlock(&g_trust_policy_write_lock);
}

int trust_policy_add_rule(const trust_policy_rule_t *rule)
{
    int ret = -1;
    int slot, final_count;
    mutex_lock(&g_trust_policy_write_lock);
    spin_lock(&g_trust_policy.lock);
    slot = g_trust_policy.count;
    if (slot < TRUST_MAX_POLICIES) {
        g_trust_policy.rules[slot] = *rule;
        /* Publish the rule bytes before the count bump so lockless
         * legacy readers never observe a partially-initialized rule. */
        smp_wmb();
        WRITE_ONCE(g_trust_policy.count, slot + 1);
        ret = 0;
    }
    final_count = g_trust_policy.count;
    spin_unlock(&g_trust_policy.lock);

    /*
     * Republish the RCU snapshot so rcu_dereference readers pick up
     * the new rule count.  Old snapshot is freed after grace period
     * via kfree_rcu — no synchronous stall on the publisher.
     */
    if (ret == 0)
        (void)_trust_policy_publish_snapshot(final_count);
    mutex_unlock(&g_trust_policy_write_lock);
    return ret;
}

/*
 * trust_policy_cleanup - Free the RCU-published policy snapshot on module
 * unload.  Paired with trust_policy_init_defaults() which publishes the
 * first snapshot.  Without this, the snapshot allocated in init (and any
 * subsequent republishes from trust_policy_add_rule) leaks ~16 bytes per
 * module load cycle.
 *
 * Callable only from module exit (synchronous unload context): readers
 * must have already drained and no new writers can appear.
 */
void trust_policy_cleanup(void)
{
    trust_policy_snapshot_t *snap;

    mutex_lock(&g_trust_policy_write_lock);
    snap = rcu_dereference_protected(g_trust_policy_rcu,
                lockdep_is_held(&g_trust_policy_write_lock));
    rcu_assign_pointer(g_trust_policy_rcu, NULL);
    mutex_unlock(&g_trust_policy_write_lock);

    if (snap) {
        /* synchronize_rcu + kfree is safe in module_exit; kfree_rcu is
         * also fine but we want the free to complete before the module
         * text disappears. */
        synchronize_rcu();
        kfree(snap);
    }
}

/* --- TRUST_POLICY_EVAL --- */
int trust_fbc_policy_eval(u32 subject_id, u32 action, u32 *matching_rule_idx)
{
    trust_subject_t subj;
    int i;
    int result = TRUST_RESULT_DENY;
    const trust_policy_snapshot_t *snap;
    const trust_policy_rule_t *rules;
    int count;

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

    /*
     * Session 33: full RCU read section.  rcu_dereference pairs with
     * rcu_assign_pointer on the publish side; the read-side critical
     * section ensures the snapshot and the rules[] it aliases are
     * kept alive for the duration of the loop.
     *
     * Fallback: if no snapshot has been published yet (pre-init or
     * -ENOMEM on publish) treat the policy as empty and fall through
     * to the default DENY.
     */
    rcu_read_lock();
    /* Lockdep hook: confirm we're actually inside an RCU reader. */
    RCU_LOCKDEP_WARN(!rcu_read_lock_held(),
                     "trust_fbc_policy_eval called without rcu_read_lock");

    snap = rcu_dereference(g_trust_policy_rcu);
    if (!snap) {
        rcu_read_unlock();
        return TRUST_RESULT_DENY;
    }

    count = snap->rule_count;
    rules = snap->rules_ref;
    if (count > TRUST_MAX_POLICIES)
        count = TRUST_MAX_POLICIES;

    for (i = 0; i < count; i++) {
        const trust_policy_rule_t *rule = &rules[i];

        /* Check domain match (0xFFFFFFFF = all domains) */
        if (rule->domain != 0xFFFFFFFF && rule->domain != subj.domain)
            continue;

        /* Check action match */
        if (READ_ONCE(rule->action_type) != action)
            continue;

        /* Found matching rule */
        if (matching_rule_idx) *matching_rule_idx = (u32)i;

        /* TRC Integration: apply threshold bias to min_trust */
        {
            /* Clamp threshold_bias to prevent overflow from flipping the comparison */
            int32_t bias = subj.trc.threshold_bias;
            int32_t biased_min;
            if (bias > 50) bias = 50;
            if (bias < -50) bias = -50;
            biased_min = rule->min_trust + bias;
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
    rcu_read_unlock();

    return result;
}

/* --- TRUST_ESCALATE --- */

/*
 * Escalate decision is a read-then-modify cycle on subject state that
 * is concurrent with record_action, decay, and propagate. Using the
 * old lookup / copy / insert pattern let another writer's changes (to
 * trust_score, capabilities, flags) be silently overwritten.
 *
 * We run the mutation through trust_tlb_modify so the subject stays
 * pinned under its set-lock for the duration of the decision.
 */
enum escalate_outcome {
    ESC_OUT_GRANTED,
    ESC_OUT_DENIED_SCORE,
    ESC_OUT_PENDING_AI,
    ESC_OUT_FROZEN,
    ESC_OUT_BAD_AUTH,
    ESC_OUT_NOOP_ALREADY,
};

struct escalate_ctx {
    u32                    requested_authority;
    int32_t                score_snapshot;
    enum escalate_outcome  outcome;
};

static int _escalate_decide_cb(trust_subject_t *subj, void *data)
{
    struct escalate_ctx *c = data;
    int32_t required;

    if (subj->flags & TRUST_FLAG_FROZEN) {
        c->outcome = ESC_OUT_FROZEN;
        c->score_snapshot = subj->trust_score;
        return 0;
    }

    if (subj->authority_level >= c->requested_authority) {
        c->outcome = ESC_OUT_NOOP_ALREADY;
        c->score_snapshot = subj->trust_score;
        return 0;
    }

    switch (c->requested_authority) {
    case TRUST_AUTH_USER:    required = 100; break;
    case TRUST_AUTH_SERVICE: required = 300; break;
    case TRUST_AUTH_ADMIN:   required = 600; break;
    case TRUST_AUTH_KERNEL:  required = 900; break;
    default:
        c->outcome = ESC_OUT_BAD_AUTH;
        c->score_snapshot = subj->trust_score;
        return 0;
    }

    /* Apply TRC threshold bias */
    required += subj->trc.threshold_bias;

    if (subj->trust_score < required) {
        /* Denied: apply penalty atomically */
        subj->trust_score = trust_clamp_score(subj->trust_score - 20);
        c->outcome = ESC_OUT_DENIED_SCORE;
        c->score_snapshot = subj->trust_score;
        return 0;
    }

    /* High-authority escalations require AI approval: mark pending */
    if (c->requested_authority >= TRUST_AUTH_ADMIN) {
        subj->flags |= TRUST_FLAG_ESCALATING;
        c->outcome = ESC_OUT_PENDING_AI;
        c->score_snapshot = subj->trust_score;
        return 0;
    }

    /* Auto-grant USER/SERVICE */
    subj->authority_level = c->requested_authority;
    subj->capabilities = trust_default_caps(c->requested_authority);
    subj->flags &= ~TRUST_FLAG_ESCALATING;
    c->outcome = ESC_OUT_GRANTED;
    c->score_snapshot = subj->trust_score;
    return 0;
}

/* Rollback ESCALATING flag when queue is full (runs atomically too). */
static int _escalate_rollback_cb(trust_subject_t *subj, void *data)
{
    (void)data;
    subj->flags &= ~TRUST_FLAG_ESCALATING;
    return 0;
}

int trust_fbc_escalate(u32 subject_id, u32 requested_authority,
                       const char *justification)
{
    struct escalate_ctx ctx = { .requested_authority = requested_authority };
    int ret;

    ret = trust_tlb_modify(subject_id, _escalate_decide_cb, &ctx);
    if (ret == -ENOENT)
        return -1;
    if (ret != 0)
        return ret;

    switch (ctx.outcome) {
    case ESC_OUT_FROZEN:
    case ESC_OUT_BAD_AUTH:
    case ESC_OUT_DENIED_SCORE:
        return -1;

    case ESC_OUT_NOOP_ALREADY:
        return 0;

    case ESC_OUT_GRANTED:
        pr_info("trust: subject %u escalated to authority %u (score=%d)\n",
                subject_id, requested_authority, ctx.score_snapshot);
        return 0;

    case ESC_OUT_PENDING_AI:
        if (trust_escalation_enqueue(subject_id, requested_authority,
                                     justification,
                                     ctx.score_snapshot) == 0) {
            pr_info("trust: subject %u escalation to %u queued for AI approval (score=%d)\n",
                    subject_id, requested_authority, ctx.score_snapshot);
            return -EAGAIN;
        }
        /* Queue full: roll back the ESCALATING flag */
        trust_tlb_modify(subject_id, _escalate_rollback_cb, NULL);
        pr_warn("trust: escalation queue full, DENYING subject %u escalation to %u\n",
                subject_id, requested_authority);
        return -EAGAIN;
    }
    return -1;
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

/*
 * Apply a delta atomically inside the subject's TLB set lock.
 * Used by both the origin subject and each dependent, eliminating the
 * previous lookup-copy-insert TOCTOU race.
 */
struct propagate_ctx {
    int32_t delta;
    int     check_threshold;    /* 1 = also enforce low threshold */
    int     skip_frozen;        /* 1 = skip if frozen (no mutation) */
    int     frozen_skipped;     /* out: 1 if skipped due to frozen */
    int32_t old_score;          /* out */
    u32     old_caps;           /* out */
    int32_t new_score;          /* out */
    u32     new_caps;           /* out */
};

static int _propagate_cb(trust_subject_t *subj, void *data)
{
    struct propagate_ctx *c = data;

    c->old_score = subj->trust_score;
    c->old_caps  = subj->capabilities;
    c->frozen_skipped = 0;

    if (c->skip_frozen && (subj->flags & TRUST_FLAG_FROZEN)) {
        c->frozen_skipped = 1;
        c->new_score = subj->trust_score;
        c->new_caps  = subj->capabilities;
        return 0;
    }

    subj->trust_score = trust_clamp_score(subj->trust_score + c->delta);
    subj->last_action_ts = trust_get_timestamp();

    if (c->check_threshold &&
        subj->trust_score <= subj->threshold_low) {
        subj->capabilities &= trust_default_caps(TRUST_AUTH_NONE);
        if (subj->authority_level > TRUST_AUTH_NONE)
            subj->authority_level = TRUST_AUTH_NONE;
    }

    c->new_score = subj->trust_score;
    c->new_caps  = subj->capabilities;
    return 0;
}

void trust_fbc_propagate(u32 subject_id, int32_t delta)
{
    struct propagate_ctx origin_ctx = {
        .delta = delta,
        .check_threshold = 0,
        .skip_frozen = 0,
    };
    u32 dependents[32];
    int dep_count, i, ret;
    int32_t scaled_delta;

    /* Step 1: Apply delta to the originating subject atomically */
    ret = trust_tlb_modify(subject_id, _propagate_cb, &origin_ctx);
    if (ret != 0)
        return;

    trust_fbc_audit(subject_id, TRUST_ACTION_TRUST_CHANGE,
                    origin_ctx.old_score, origin_ctx.new_score,
                    origin_ctx.old_caps, origin_ctx.new_caps);

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
        struct propagate_ctx dep_ctx = {
            .delta = scaled_delta,
            .check_threshold = 1,
            .skip_frozen = 1,
        };

        if (trust_tlb_modify(dependents[i], _propagate_cb, &dep_ctx) != 0)
            continue;
        if (dep_ctx.frozen_skipped)
            continue;

        trust_fbc_audit(dependents[i], TRUST_ACTION_TRUST_CHANGE,
                        dep_ctx.old_score, dep_ctx.new_score,
                        dep_ctx.old_caps, dep_ctx.new_caps);

        pr_debug("trust: propagated %+d to dependent %u (new score=%d)\n",
                 scaled_delta, dependents[i], dep_ctx.new_score);
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
     * Called from both process context (ioctl) and softirq context
     * (trust_decay_timer_fn). TLB set locks are also held across these
     * two contexts, so we MUST use irqsave or risk softirq-vs-process
     * deadlock on the same CPU.
     *
     * We also skip empty sets via a lock-free READ_ONCE check to avoid
     * thrashing 1024 cachelines when most sets are empty at boot.
     */
    int set, way;
    unsigned long flags;

    if (!g_trust_tlb.sets)
        return;

    for (set = 0; set < TRUST_TLB_SETS; set++) {
        trust_tlb_set_t *s = &g_trust_tlb.sets[set];

        /* Skip empty sets without acquiring the lock */
        if (READ_ONCE(s->valid_mask) == 0)
            continue;

        spin_lock_irqsave(&s->lock, flags);
        for (way = 0; way < TRUST_TLB_WAYS; way++) {
            trust_subject_t *subj;

            if (!(s->valid_mask & (1U << way)))
                continue;

            subj = &s->entries[way];

            /* Adjust thresholds based on current score and authority */
            subj->threshold_low = -100 - (int32_t)(subj->authority_level * 100);
            subj->threshold_high = 100 + (int32_t)(subj->authority_level * 200);
        }
        spin_unlock_irqrestore(&s->lock, flags);
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

/*
 * Apply escalation response atomically to the subject.  Closes the
 * previous TOCTOU: record_action / propagate could mutate the subject
 * between the lookup and the insert below, silently dropping those
 * updates.  trust_tlb_modify holds the TLB set lock across the whole
 * mutation.
 */
struct esc_respond_ctx {
    u32 auth;
    u32 approved;
};

static int _esc_respond_cb(trust_subject_t *subj, void *data)
{
    struct esc_respond_ctx *c = data;

    if (c->approved) {
        subj->authority_level = c->auth;
        subj->capabilities = trust_default_caps(c->auth);
    } else {
        subj->trust_score = trust_clamp_score(subj->trust_score - 30);
    }
    subj->flags &= ~TRUST_FLAG_ESCALATING;
    return 0;
}

int trust_escalation_respond(u32 seq, u32 approved)
{
    struct esc_respond_ctx ctx = { .approved = approved };
    u32 sid = 0, auth = 0;
    int found = 0;
    u32 i;

    /*
     * Reject seq == 0 explicitly — uninitialized queue slots have seq=0,
     * which would otherwise let a caller "respond" to a nonexistent
     * escalation and grant authority.  seq_counter starts at 1.
     */
    if (seq == 0)
        return -EINVAL;

    /* Find the request by seq and mark it answered under the queue lock. */
    spin_lock(&g_trust_escalations.lock);
    for (i = 0; i < TRUST_ESCALATION_QUEUE_SIZE; i++) {
        if (g_trust_escalations.entries[i].seq == seq &&
            g_trust_escalations.entries[i].status == 0) {
            trust_escalation_request_t *req = &g_trust_escalations.entries[i];
            sid = req->subject_id;
            auth = req->requested_authority;
            req->status = approved ? 1 : 2;
            found = 1;
            break;
        }
    }
    spin_unlock(&g_trust_escalations.lock);

    if (!found)
        return -1;

    ctx.auth = auth;
    if (trust_tlb_modify(sid, _esc_respond_cb, &ctx) != 0)
        return -1;

    if (approved)
        pr_info("trust: AI approved escalation for subject %u to authority %u\n",
                sid, auth);
    else
        pr_info("trust: AI denied escalation for subject %u (penalty applied)\n",
                sid);
    return 0;
}

MODULE_LICENSE("GPL");
