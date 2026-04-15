/*
 * trust_internal.h - Kernel-internal declarations for the Root of Authority module
 *
 * Includes all subsystem prototypes: TLB, RISC, FBC, DNA Gate,
 * Authority Proof Engine (APE), Chromosomal Authority, Token Economy,
 * Lifecycle (Mitotic/Meiotic), and Immune Response.
 */

#ifndef TRUST_INTERNAL_H
#define TRUST_INTERNAL_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/time64.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include "../include/trust_types.h"

/* Forward declaration for TMS region tags (full definition in trust_memory.h) */
enum tms_region_tag;

/* --- TLB Configuration --- */
#define TRUST_TLB_SETS  1024
#define TRUST_TLB_WAYS  4

typedef struct {
    trust_subject_t entries[TRUST_TLB_WAYS];
    u32             valid_mask;     /* Bitmask: which ways are valid */
    u32             lru;            /* LRU tracking (2 bits per way) */
    spinlock_t      lock;
} trust_tlb_set_t;

typedef struct {
    trust_tlb_set_t *sets;  /* vmalloc'd, TRUST_TLB_SETS entries */
    atomic_t        hit_count;
    atomic_t        miss_count;
} trust_tlb_t;

/* --- Policy Table --- */
#define TRUST_MAX_POLICIES 256

typedef struct {
    trust_policy_rule_t rules[TRUST_MAX_POLICIES];
    int                 count;
    spinlock_t          lock;
} trust_policy_table_t;

/* --- Audit Ring Buffer --- */
#define TRUST_AUDIT_SIZE 4096

typedef struct {
    trust_audit_entry_t entries[TRUST_AUDIT_SIZE];
    u32                 head;
    u32                 tail;
    spinlock_t          lock;
} trust_audit_ring_t;

/* --- DNA Gate Translation Entry --- */
typedef struct {
    u32     trust_cap;      /* TRUST_CAP_* */
    int     linux_cap;      /* Linux capability number (-1 = none needed) */
    int32_t min_score;      /* Minimum trust score for this translation */
} cap_translation_entry_t;

/* --- Dependency Graph (for trust propagation) --- */
#define TRUST_MAX_DEPS          8       /* Max dependencies per subject */
#define TRUST_MAX_DEP_ENTRIES   256     /* Max tracked subjects with deps */

typedef struct {
    u32     subject_id;
    u32     depends_on[TRUST_MAX_DEPS]; /* Subject IDs this depends on */
    u32     dep_count;
} trust_dep_entry_t;

typedef struct {
    trust_dep_entry_t entries[TRUST_MAX_DEP_ENTRIES];
    int               count;
    spinlock_t        lock;
} trust_dep_graph_t;

/* --- Escalation Queue (for AI observer approval) --- */
#define TRUST_ESCALATION_QUEUE_SIZE 32

typedef struct {
    u32      subject_id;
    u32      requested_authority;
    char     justification[128];
    u64      timestamp;
    int32_t  current_score;
    u32      status;            /* 0=pending, 1=approved, 2=denied */
    u32      seq;               /* Sequence number for deduplication */
} trust_escalation_request_t;

typedef struct {
    trust_escalation_request_t entries[TRUST_ESCALATION_QUEUE_SIZE];
    u32        head;
    u32        tail;
    u32        seq_counter;
    spinlock_t lock;
    wait_queue_head_t waitq;    /* For blocking poll from userspace */
} trust_escalation_queue_t;

/* --- Authority Proof Engine (APE) --- */
#define TRUST_APE_MAX_ENTITIES  1024

typedef struct {
    u32                  subject_id;
    trust_proof_state_t  state;
    spinlock_t           lock;
} trust_ape_entry_t;

typedef struct {
    trust_ape_entry_t    entries[TRUST_APE_MAX_ENTITIES];
    int                  count;
    spinlock_t           lock;
} trust_ape_t;

/* --- Metabolic Cost Table --- */
typedef struct {
    u32     action_type;    /* TRUST_ACTION_* */
    u32     base_cost;      /* Base token cost */
} trust_metabolic_cost_t;

/* --- Lineage Tracking (for immune response) --- */
#define TRUST_MAX_LINEAGE   512

typedef struct {
    u32 parent_id;
    u32 child_id;
    u8  child_sex;     /* CHROMO_SEX_* at time of division */
    u8  generation;
    u16 _padding;
} trust_lineage_entry_t;

typedef struct {
    trust_lineage_entry_t entries[TRUST_MAX_LINEAGE];
    int                   count;
    spinlock_t            lock;
} trust_lineage_t;

/* --- Global State --- */
extern trust_tlb_t               g_trust_tlb;
extern trust_policy_table_t      g_trust_policy;
extern trust_audit_ring_t        g_trust_audit;
extern trust_dep_graph_t         g_trust_deps;
extern trust_escalation_queue_t  g_trust_escalations;
extern trust_ape_t               g_trust_ape;
extern trust_lineage_t           g_trust_lineage;

/* --- TLB operations (trust_tlb.c) --- */
int              trust_tlb_lookup(u32 subject_id, trust_subject_t *out);
int              trust_tlb_insert(const trust_subject_t *subject);
void             trust_tlb_invalidate(u32 subject_id);
void             trust_tlb_flush(void);
int              trust_tlb_init(void);
void             trust_tlb_cleanup(void);

/*
 * Map a subject_id to its TLB set index. MUST be kept in sync with the
 * internal tlb_hash() in trust_tlb.c, otherwise cross-set operations
 * (token transfer, two-subject lookups) won't find entries that
 * trust_tlb_insert() placed at the hashed set index.
 */
static inline u32 trust_tlb_set_of(u32 subject_id)
{
    u32 x = subject_id;
    x = (x ^ (x >> 16)) * 0x85ebca6bU;
    x = (x ^ (x >> 13)) * 0xc2b2ae35U;
    x ^= (x >> 16);
#if (TRUST_TLB_SETS & (TRUST_TLB_SETS - 1)) == 0
    return x & (TRUST_TLB_SETS - 1);
#else
    return x % TRUST_TLB_SETS;
#endif
}

/* Atomic modify: lookup + callback + writeback under set lock (prevents TOCTOU) */
typedef int (*trust_tlb_modify_fn)(trust_subject_t *subj, void *data);
int              trust_tlb_modify(u32 subject_id, trust_tlb_modify_fn fn, void *data);

/* --- RISC operations (trust_risc.c) --- */
int     trust_risc_check_cap(u32 subject_id, u32 capability);
int32_t trust_risc_get_score(u32 subject_id);
int32_t trust_risc_record_action(u32 subject_id, u32 action, u32 result);
int     trust_risc_threshold_check(u32 subject_id, u32 action);
void    trust_risc_decay_tick(void);
u32     trust_risc_translate_cap(u32 cap, u16 from_domain, u16 to_domain);

/* --- FBC operations (trust_fbc.c) --- */
int  trust_fbc_policy_eval(u32 subject_id, u32 action, u32 *matching_rule_idx);
int  trust_fbc_escalate(u32 subject_id, u32 requested_authority, const char *justification);
int  trust_fbc_domain_transfer(u32 subject_id, u16 from, u16 to, u32 caps);
void trust_fbc_propagate(u32 subject_id, int32_t delta);
void trust_fbc_repartition(void);
void trust_fbc_audit(u32 subject_id, u32 action, int32_t old_score,
                     int32_t new_score, u32 old_caps, u32 new_caps);

/* --- DNA Gate operations (trust_dna_gate.c) --- */
int  trust_dna_gate_translate(u32 subject_id, u32 trust_cap, u16 from_domain, u16 to_domain);
int  trust_dna_gate_check(u32 subject_id, u32 trust_cap);
void trust_dna_gate_init(void);

/* --- Policy management --- */
int  trust_policy_add_rule(const trust_policy_rule_t *rule);
void trust_policy_init_defaults(void);

/* --- Dependency graph operations (trust_fbc.c) --- */
void trust_dep_graph_init(void);
int  trust_dep_add(u32 subject_id, u32 depends_on);
int  trust_dep_remove(u32 subject_id, u32 depends_on);

/* --- Escalation queue operations (trust_fbc.c) --- */
void trust_escalation_queue_init(void);
int  trust_escalation_enqueue(u32 subject_id, u32 authority,
                               const char *justification, int32_t score);
int  trust_escalation_dequeue(trust_escalation_request_t *out);
int  trust_escalation_respond(u32 seq, u32 approved);

/* --- Authority Proof Engine operations (trust_ape.c) ---
 *
 * Software emulation of Ring -2 hardware proof engine.
 * Self-consuming proof chain:
 *   Pn+1 = Hcfg(n)(Pn || Rn || SEED || NONCEn || TSn || Sn)
 */
void trust_ape_init(void);
int  trust_ape_create_entity(u32 subject_id, const u8 *seed, u32 seed_len);
int  trust_ape_destroy_entity(u32 subject_id);
int  trust_ape_consume_proof(u32 subject_id, const u8 *request, u32 req_len,
                              u8 *proof_out);
int  trust_ape_verify_chain(u32 subject_id);
int  trust_ape_get_nonce(u32 subject_id, u64 *nonce_out);
int  trust_ape_get_chain_length(u32 subject_id, u32 *length_out);

/* --- Chromosomal Authority operations (trust_chromosome.c) ---
 *
 * 23 segment pairs per subject. Continuously updated behavioral/identity DNA.
 * XY sex determination on the 23rd pair drives authority transitions.
 */
void trust_chromosome_init(trust_chromosome_t *chromo, u32 subject_id,
                            u32 parent_id, u8 generation);
void trust_chromosome_update_a(trust_chromosome_t *chromo, u32 segment_idx,
                                u32 new_value);
void trust_chromosome_update_b(trust_chromosome_t *chromo, u32 segment_idx,
                                u32 new_value);
u8   trust_chromosome_determine_sex(const trust_chromosome_t *chromo);
u32  trust_chromosome_checksum(const trust_chromosome_t *chromo);
int  trust_chromosome_verify(const trust_chromosome_t *chromo);
void trust_chromosome_inherit(trust_chromosome_t *child,
                               const trust_chromosome_t *parent, u8 gen);
u32  trust_chromosome_rolling_hash(u32 hash_state, u32 new_input);
/* Deferred-update variants: skip the checksum recompute on each call.
 * Caller MUST call trust_chromosome_finalize() before publishing the
 * chromosome (e.g. before releasing the TLB set lock). */
void trust_chromosome_update_a_deferred(trust_chromosome_t *chromo,
                                         u32 segment_idx, u32 new_value);
void trust_chromosome_finalize(trust_chromosome_t *chromo);

/* --- Token Economy operations (trust_token.c) ---
 *
 * Embedded metabolic cost system. Token state lives inside trust_subject_t.
 * Actions burn tokens; tokens regenerate over time.
 * Bounds damage from compromise to C(E)/Cmin operations (Theorem 6).
 */
void trust_token_init(trust_token_state_t *tokens, u32 authority_level);
int  trust_token_burn(trust_token_state_t *tokens, u32 action_type);
void trust_token_regenerate(trust_token_state_t *tokens);
int  trust_token_check(const trust_token_state_t *tokens, u32 action_type);
u32  trust_token_cost_for_action(u32 action_type);

/* --- Lifecycle operations (trust_lifecycle.c) ---
 *
 * Mitotic division, meiotic combination, generational decay,
 * cancer detection, apoptotic cascade, orphan handling.
 */
void trust_lifecycle_init(void);
int  trust_lifecycle_mitotic_divide(u32 parent_id, u32 child_id);
int  trust_lifecycle_meiotic_combine(u32 subject_a, u32 subject_b);
void trust_lifecycle_meiotic_release(u32 subject_a, u32 subject_b);
int  trust_lifecycle_check_cancer(u32 subject_id);
int  trust_lifecycle_apoptosis(u32 subject_id);
void trust_lifecycle_apoptotic_cascade(u32 subject_id);
void trust_lifecycle_handle_orphans(u32 dead_parent_id);
int  trust_lifecycle_get_max_score(u8 generation, u32 base_authority);

/* --- Immune Response operations (trust_lifecycle.c) --- */
void trust_immune_init(trust_immune_t *immune);
int  trust_immune_evaluate(u32 subject_id);
int  trust_immune_quarantine(u32 subject_id, u32 reason);
int  trust_immune_release_quarantine(u32 subject_id);
void trust_immune_tick(void);

/* --- Trust Syscall Tracer operations (trust_syscall.c) ---
 *
 * Syscall interception for trust-tracked PE processes.
 * kprobe + kretprobe hooks on key __x64_sys_* entry points.
 * PID bitmap for O(1) filtering, per-PID ring buffers.
 * Netlink event emission and behavioral analysis support.
 */
int  tsc_init(void);
void tsc_cleanup(void);
int  tsc_start_trace(u32 subject_id, pid_t pid, u8 category_mask);
void tsc_stop_trace(pid_t pid);
int  tsc_is_pid_traced(pid_t pid);
long tsc_ioctl(unsigned int cmd, unsigned long arg);

/* --- Trust Memory Scanner operations (trust_memory.c) ---
 *
 * Per-subject memory region tracking for PE processes.
 * kprobe-based mmap/munmap/mprotect interception.
 * Netlink event emission and byte-pattern scanning.
 */
int  tms_init(void);
void tms_cleanup(void);
int  tms_register_subject(u32 subject_id, pid_t pid);
void tms_unregister_subject(u32 subject_id);
int  tms_register_section(u32 subject_id, u64 va_start, u64 size,
                           enum tms_region_tag tag, const char *label);
void tms_on_mmap(pid_t pid, u64 addr, u64 len, u32 prot);
void tms_on_munmap(pid_t pid, u64 addr, u64 len);
void tms_on_mprotect(pid_t pid, u64 addr, u64 len, u32 prot);
int  tms_scan_region(u32 subject_id, u64 va_start, u64 va_end);
int  tms_add_pattern(const u8 *bytes, const u8 *mask, u16 len,
                      const char *name, u16 id, enum tms_region_tag tag);
long tms_ioctl(unsigned int cmd, unsigned long arg);

/* --- Utility --- */
static inline u64 trust_get_timestamp(void)
{
    return ktime_get_ns();
}

/* Clamp trust score to valid range */
static inline int32_t trust_clamp_score(int32_t score)
{
    if (score < TRUST_SCORE_MIN) return TRUST_SCORE_MIN;
    if (score > TRUST_SCORE_MAX) return TRUST_SCORE_MAX;
    return score;
}

/* Get default capabilities for an authority level */
static inline u32 trust_default_caps(u32 authority)
{
    switch (authority) {
    case TRUST_AUTH_NONE:    return 0;
    case TRUST_AUTH_USER:    return TRUST_CAPS_USER;
    case TRUST_AUTH_SERVICE: return TRUST_CAPS_SERVICE;
    case TRUST_AUTH_ADMIN:   return TRUST_CAPS_ADMIN;
    case TRUST_AUTH_KERNEL:  return TRUST_CAPS_KERNEL;
    default:                 return 0;
    }
}

/* Generational decay: compute max score for generation g with base authority */
static inline int32_t trust_generation_decay(u8 generation, int32_t base_max)
{
    int32_t result = base_max;
    u8 g;
    for (g = 0; g < generation && g < TRUST_GENERATION_MAX; g++) {
        result = (result * TRUST_GENERATION_ALPHA_NUM) / TRUST_GENERATION_ALPHA_DEN;
    }
    return result;
}

/* --- Trust Regulation Core (TRC) inlines --- */

static inline void trust_trc_init(trust_trc_t *trc)
{
    trc->resistance = 100;
    trc->threshold_bias = 0;
    trc->cost_multiplier = 256;     /* 1.0 in fixed-point 8.8 */
    trc->state = TRUST_TRC_NORMAL;
    trc->flow_in = 0;
    trc->flow_out = 0;
    trc->resistance_decay = 1;
}

static inline void trust_trc_adjust(trust_trc_t *trc, u32 event)
{
    switch (event) {
    case TRUST_ACTION_CANCER_DETECTED:
    case TRUST_ACTION_PROOF_BREAK:
        trc->state = TRUST_TRC_LOCKDOWN;
        trc->resistance = 1000;
        trc->cost_multiplier = 512;  /* 2.0x costs */
        trc->threshold_bias = 200;
        break;
    case TRUST_ACTION_IMMUNE_TRIGGER:
        if (trc->state < TRUST_TRC_ELEVATED) {
            trc->state = TRUST_TRC_ELEVATED;
            trc->resistance = 500;
            trc->cost_multiplier = 384;  /* 1.5x costs */
            trc->threshold_bias = 100;
        }
        break;
    default:
        if (trc->resistance > 100) {
            trc->resistance -= trc->resistance_decay;
            if (trc->resistance <= 100) {
                trc->state = TRUST_TRC_NORMAL;
                trc->resistance = 100;
                trc->cost_multiplier = 256;
                trc->threshold_bias = 0;
            }
        }
        break;
    }
}

#endif /* TRUST_INTERNAL_H */
