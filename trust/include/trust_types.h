/*
 * trust_types.h - Root of Authority data structures
 *
 * Implements the biologically-inspired Dynamic Hyperlation architecture:
 * - Self-Consuming Proof Chain (authority is metabolized, not stored)
 * - Chromosomal Authority Model (23 segment pairs: runtime + construction DNA)
 * - XY Sex Determination (conformant vs divergent behavior classification)
 * - Token Economy (metabolic cost bounds damage from compromise)
 * - Mitotic/Meiotic Lifecycle (process spawning with generational decay)
 * - Immune Response (cancer detection, apoptotic cascade)
 * - Trust Regulation Core state machine (R, Th, C, S, F)
 *
 * Based on: "Root of Authority: A Biologically-Inspired Dynamic Trust
 * Architecture for Hardware-Rooted Privilege Metabolism"
 * by Elijah Isaiah Roberts
 */

#ifndef TRUST_TYPES_H
#define TRUST_TYPES_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/* ========================================================================
 * ROOT OF AUTHORITY — Instruction Set Architecture (ISA)
 *
 * The RoA ISA organizes all trust operations into 6 families:
 *   AUTH  — Authority proof chain (identity/authentication)
 *   TRUST — Score and capability management (RISC fast-path)
 *   GATE  — Cross-domain translation (DNA Gate / IRNA Translator)
 *   RES   — Resource/token management (Metabolic Cost)
 *   LIFE  — Lifecycle management (Mitotic/Meiotic/Immune)
 *   META  — System-wide operations (audit, repartition, TRC)
 *
 * RISC family (O(1) TLB-based operations):
 *   TRUST.CHECK_CAP, TRUST.GET_SCORE, TRUST.RECORD, TRUST.THRESHOLD,
 *   TRUST.DECAY, TRUST.TRANSLATE, RES.COST
 *
 * FBC family (multi-step policy/feedback operations):
 *   AUTH.MINT, AUTH.BURN, AUTH.FENCE, AUTH.VERIFY, AUTH.NONCE,
 *   TRUST.POLICY_EVAL, TRUST.ESCALATE, TRUST.PROPAGATE,
 *   GATE.TRANSLATE, GATE.CHECK,
 *   RES.BALANCE, RES.BURN, RES.XFER,
 *   LIFE.DIVIDE, LIFE.COMBINE, LIFE.RELEASE, LIFE.APOPTOSIS,
 *   LIFE.IMMUNE_EVAL, LIFE.QUARANTINE, LIFE.RELEASE_Q,
 *   META.REPARTITION, META.AUDIT, META.FLUSH, META.GET_SUBJECT,
 *   META.GET_CHROMOSOME, META.GET_SEX, META.IMMUNE_STATUS
 * ======================================================================== */
#define TRUST_ISA_FAMILY_AUTH    0   /* Authority proof chain */
#define TRUST_ISA_FAMILY_TRUST  1   /* Score/capability RISC layer */
#define TRUST_ISA_FAMILY_GATE   2   /* Cross-domain DNA Gate */
#define TRUST_ISA_FAMILY_RES    3   /* Resource/token economy */
#define TRUST_ISA_FAMILY_LIFE   4   /* Lifecycle (mitosis/meiosis/immune) */
#define TRUST_ISA_FAMILY_META   5   /* System-wide meta operations */
#define TRUST_ISA_FAMILY_COUNT  6

/* Trust domains */
#define TRUST_DOMAIN_LINUX      0
#define TRUST_DOMAIN_WIN32      1
#define TRUST_DOMAIN_AI         2
#define TRUST_DOMAIN_SERVICE    3
#define TRUST_DOMAIN_MAX        4

/* Authority levels (dynamic, not static rings) */
#define TRUST_AUTH_NONE          0
#define TRUST_AUTH_USER          1
#define TRUST_AUTH_SERVICE       2
#define TRUST_AUTH_ADMIN         3
#define TRUST_AUTH_KERNEL        4

/* Capability flags (14 capabilities) */
#define TRUST_CAP_FILE_READ         (1U <<  0)
#define TRUST_CAP_FILE_WRITE        (1U <<  1)
#define TRUST_CAP_NET_CONNECT       (1U <<  2)
#define TRUST_CAP_NET_LISTEN        (1U <<  3)
#define TRUST_CAP_PROCESS_CREATE    (1U <<  4)
#define TRUST_CAP_PROCESS_SIGNAL    (1U <<  5)
#define TRUST_CAP_REGISTRY_READ     (1U <<  6)
#define TRUST_CAP_REGISTRY_WRITE    (1U <<  7)
#define TRUST_CAP_DEVICE_ACCESS     (1U <<  8)
#define TRUST_CAP_SERVICE_CONTROL   (1U <<  9)
#define TRUST_CAP_FIREWALL_MODIFY   (1U << 10)
#define TRUST_CAP_TRUST_MODIFY      (1U << 11)
#define TRUST_CAP_AI_CONTROL        (1U << 12)
#define TRUST_CAP_KERNEL_CALL       (1U << 13)

/* Default capability sets per authority level */
#define TRUST_CAPS_USER     (TRUST_CAP_FILE_READ | TRUST_CAP_FILE_WRITE | \
                             TRUST_CAP_NET_CONNECT | TRUST_CAP_REGISTRY_READ)
#define TRUST_CAPS_SERVICE  (TRUST_CAPS_USER | TRUST_CAP_NET_LISTEN | \
                             TRUST_CAP_PROCESS_CREATE | TRUST_CAP_SERVICE_CONTROL | \
                             TRUST_CAP_REGISTRY_WRITE)
#define TRUST_CAPS_ADMIN    (TRUST_CAPS_SERVICE | TRUST_CAP_DEVICE_ACCESS | \
                             TRUST_CAP_FIREWALL_MODIFY | TRUST_CAP_PROCESS_SIGNAL | \
                             TRUST_CAP_TRUST_MODIFY)
#define TRUST_CAPS_KERNEL   (0xFFFFFFFFU) /* All capabilities */

/* Action types */
#define TRUST_ACTION_FILE_OPEN          1
#define TRUST_ACTION_FILE_WRITE         2
#define TRUST_ACTION_NET_CONNECT        3
#define TRUST_ACTION_NET_LISTEN         4
#define TRUST_ACTION_PROCESS_CREATE     5
#define TRUST_ACTION_PROCESS_SIGNAL     6
#define TRUST_ACTION_REGISTRY_READ      7
#define TRUST_ACTION_REGISTRY_WRITE     8
#define TRUST_ACTION_DEVICE_OPEN        9
#define TRUST_ACTION_SERVICE_START      10
#define TRUST_ACTION_SERVICE_STOP       11
#define TRUST_ACTION_FIREWALL_CHANGE    12
#define TRUST_ACTION_TRUST_CHANGE       13
#define TRUST_ACTION_ESCALATE           14
#define TRUST_ACTION_DOMAIN_TRANSFER    15
/* Root of Authority action types */
#define TRUST_ACTION_PROOF_CONSUME      16  /* Proof chain consumed */
#define TRUST_ACTION_PROOF_BREAK        17  /* Proof chain broken (critical) */
#define TRUST_ACTION_MITOTIC_DIVIDE     18  /* Process spawned child */
#define TRUST_ACTION_MEIOTIC_COMBINE    19  /* Dual-entity cooperation */
#define TRUST_ACTION_APOPTOSIS          20  /* Controlled death initiated */
#define TRUST_ACTION_CANCER_DETECTED    21  /* Runaway spawning detected */
#define TRUST_ACTION_TOKEN_STARVE       22  /* Token balance exhausted */
#define TRUST_ACTION_CHROMOSOME_MUTATE  23  /* Chromosome segment changed */
#define TRUST_ACTION_IMMUNE_TRIGGER     24  /* Immune response triggered */
#define TRUST_ACTION_TRC_STATE_CHANGE   25  /* TRC state transition */
#define TRUST_ACTION_MAX                26

/* Subject flags */
#define TRUST_FLAG_FROZEN       (1U << 0)   /* Subject frozen (no actions allowed) */
#define TRUST_FLAG_OBSERVED     (1U << 1)   /* AI observer is watching this subject */
#define TRUST_FLAG_ESCALATING   (1U << 2)   /* Escalation in progress */
#define TRUST_FLAG_DECAYING     (1U << 3)   /* Subject is in decay (hysteresis) */
#define TRUST_FLAG_NEW          (1U << 4)   /* Newly registered, probation period */
#define TRUST_FLAG_APOPTOTIC    (1U << 5)   /* Marked for apoptotic cascade */
#define TRUST_FLAG_CANCEROUS    (1U << 6)   /* Cancer detected (runaway spawning) */
#define TRUST_FLAG_MEIOTIC      (1U << 7)   /* In meiotic combination with another entity */

/* Trust score bounds */
#define TRUST_SCORE_MIN     (-1000)
#define TRUST_SCORE_MAX     ( 1000)
#define TRUST_SCORE_NEUTRAL 0
#define TRUST_SCORE_DEFAULT 200     /* New user-level subjects start here */

/* Policy evaluation results */
#define TRUST_RESULT_ALLOW      0
#define TRUST_RESULT_DENY       1
#define TRUST_RESULT_ESCALATE   2   /* Requires AI observer approval */

/* ========================================================================
 * ROOT OF AUTHORITY — Dynamic Hyperlation Architecture
 * ======================================================================== */

/*
 * --- Chromosomal Authority Model ---
 *
 * Every subject carries 23 pairs of chromosomal segments:
 *   A-segments (1-23): Runtime behavioral DNA — computed from live behavior
 *   B-segments (1-23): Construction identity DNA — computed from static properties
 *
 * The 23rd pair is special (XY Sex Determination):
 *   A23 = behavioral conformance score
 *   B23 = construction conformance score
 *   XX (both conformant) = maintain/renew authority
 *   XY (divergent)       = promote/demote based on deviation direction
 *   YY (strongly divergent) = apoptosis candidate
 */

#define TRUST_CHROMOSOME_PAIRS   23
#define TRUST_CHROMOSOME_TOTAL   (TRUST_CHROMOSOME_PAIRS * 2)  /* 46 segments */

/* A-segment indices (runtime behavioral DNA) */
#define CHROMO_A_ACTION_HASH     0   /* Rolling hash of recent action sequence */
#define CHROMO_A_TOKEN_BALANCE   1   /* Current metabolic token state */
#define CHROMO_A_TRUST_STATE     2   /* Trust score trajectory fingerprint */
#define CHROMO_A_THERMAL         3   /* CPU/resource usage intensity */
#define CHROMO_A_MEMORY          4   /* Memory allocation pattern hash */
#define CHROMO_A_SYSCALL_CACHE   5   /* Syscall frequency distribution hash */
#define CHROMO_A_EXEC_PATH       6   /* Code execution path hash */
#define CHROMO_A_NET_PATTERN     7   /* Network behavior pattern hash */
#define CHROMO_A_FILE_PATTERN    8   /* File access pattern hash */
#define CHROMO_A_IPC_PATTERN     9   /* IPC/signal pattern hash */
#define CHROMO_A_TIMING          10  /* Timing behavior hash (jitter profile) */
#define CHROMO_A_ERROR_RATE      11  /* Error/failure rate fingerprint */
#define CHROMO_A_ESCALATION      12  /* Escalation request pattern hash */
#define CHROMO_A_SPAWN_RATE      13  /* Process spawning rate fingerprint */
#define CHROMO_A_IO_PATTERN      14  /* I/O access pattern hash */
#define CHROMO_A_CAPABILITY_USE  15  /* Capability usage distribution hash */
#define CHROMO_A_DOMAIN_CROSS    16  /* Cross-domain transfer frequency hash */
#define CHROMO_A_AUDIT_TRAIL     17  /* Audit trail signature hash */
#define CHROMO_A_DEPENDENCY      18  /* Dependency graph position hash */
#define CHROMO_A_LIFETIME        19  /* Process lifetime behavior hash */
#define CHROMO_A_ENTROPY         20  /* Behavioral entropy measurement */
#define CHROMO_A_CONFORMANCE     21  /* Rolling conformance score */
#define CHROMO_A_SEX             22  /* 23rd pair: behavioral conformance (XY det) */

/* B-segment indices (construction identity DNA) */
#define CHROMO_B_BINARY_HASH     0   /* Executable binary hash */
#define CHROMO_B_LIBRARY_DEPS    1   /* Library dependency chain hash */
#define CHROMO_B_CONFIG_HASH     2   /* Configuration/registry hash */
#define CHROMO_B_INSTALL_SRC     3   /* Package/install source fingerprint */
#define CHROMO_B_SIGNATURE       4   /* Code signature verification hash */
#define CHROMO_B_PERMISSIONS     5   /* File permission state hash */
#define CHROMO_B_OWNER           6   /* Owner uid/gid fingerprint */
#define CHROMO_B_SECTION_HASH    7   /* PE/ELF section layout hash */
#define CHROMO_B_IMPORT_TABLE    8   /* Import address table hash */
#define CHROMO_B_EXPORT_TABLE    9   /* Export table hash */
#define CHROMO_B_RESOURCE_HASH   10  /* Embedded resource hash */
#define CHROMO_B_MANIFEST        11  /* Application manifest hash */
#define CHROMO_B_CERT_CHAIN      12  /* Certificate chain fingerprint */
#define CHROMO_B_RELOCATION      13  /* Relocation table hash */
#define CHROMO_B_DEBUG_INFO      14  /* Debug/symbol info hash */
#define CHROMO_B_COMPILER_ID     15  /* Compiler/toolchain fingerprint */
#define CHROMO_B_ABI_COMPAT      16  /* ABI compatibility hash */
#define CHROMO_B_FUSE_STATE      17  /* Hardware fuse/efuse state (or emulated) */
#define CHROMO_B_BOOT_CHAIN      18  /* Boot chain verification hash */
#define CHROMO_B_TPM_STATE       19  /* TPM/measured boot state hash */
#define CHROMO_B_HW_IDENTITY     20  /* Hardware identity fingerprint */
#define CHROMO_B_FIRMWARE        21  /* Firmware version/hash */
#define CHROMO_B_SEX             22  /* 23rd pair: construction conformance (XY det) */

/* XY Sex Determination thresholds */
#define CHROMO_CONFORMANCE_THETA  128  /* Threshold: >= theta = X, < theta = Y */

/* Sex types — determined by pair 23 */
#define CHROMO_SEX_XX   0   /* Conformant: both A23 >= theta AND B23 >= theta → maintain */
#define CHROMO_SEX_XY   1   /* Behaviorally divergent: A23 < theta, B23 >= theta → demote */
#define CHROMO_SEX_YX   2   /* Constructionally divergent: A23 >= theta, B23 < theta → promote */
#define CHROMO_SEX_YY   3   /* Strongly divergent: both < theta → apoptosis candidate */

/*
 * trust_chromosome_t - Full chromosomal authority for one subject
 *
 * Each segment is a 32-bit hash/value capturing one facet of identity.
 * Segments are continuously updated as the entity acts and changes.
 */
typedef struct {
    uint32_t a_segments[TRUST_CHROMOSOME_PAIRS];  /* Runtime behavioral DNA */
    uint32_t b_segments[TRUST_CHROMOSOME_PAIRS];  /* Construction identity DNA */
    uint8_t  sex;                                  /* CHROMO_SEX_XX/XY/YX/YY */
    uint8_t  generation;                           /* Mitotic generation counter */
    uint16_t division_count;                       /* Times this entity has divided */
    uint32_t parent_id;                            /* Parent subject ID (0 = root) */
    uint64_t birth_timestamp;                      /* When chromosome was created */
    uint32_t mutation_count;                       /* Number of segment mutations */
    uint32_t checksum;                             /* Integrity checksum over all segments */
} trust_chromosome_t;

/*
 * --- Self-Consuming Proof Chain ---
 *
 * Authority exists only as a continuously metabolized flow:
 *   Pn+1 = Hcfg(n)(Pn || Rn || SEED || NONCEn || TSn || Sn)
 *
 * Where:
 *   Pn = current proof (consumed and destroyed on use)
 *   Rn = request (the action being authorized)
 *   SEED = write-once entity identity seed
 *   NONCEn = monotonic counter (never repeats)
 *   TSn = timestamp
 *   Sn = behavioral state snapshot
 *   Hcfg(n) = hash function whose config is derived from consumed proof
 *
 * The proof is atomically consumed (read-and-zero) on each use.
 * If the proof chain breaks, authority is irrecoverably lost.
 */

#define TRUST_PROOF_SIZE        32  /* SHA-256 proof size in bytes */
#define TRUST_SEED_SIZE         32  /* Entity identity seed size */

/* Hash algorithm configurations (derived from consumed proof) */
#define TRUST_HASH_CFG_SHA256   0
#define TRUST_HASH_CFG_BLAKE2B  1
#define TRUST_HASH_CFG_SHA3     2
#define TRUST_HASH_CFG_COUNT    3

/*
 * trust_proof_state_t - Per-subject proof chain state
 *
 * Emulates the Authority Proof Engine (APE) in software:
 * - seed: write-once, set at entity creation, never readable after
 * - proof: current proof value (consumed atomically on use)
 * - nonce: monotonically increasing counter
 * - hash_cfg: which hash algorithm to use next (derived from last proof)
 */
typedef struct {
    uint8_t  seed[TRUST_SEED_SIZE];     /* Write-once entity identity seed */
    uint8_t  proof[TRUST_PROOF_SIZE];   /* Current proof (read-and-zero) */
    uint64_t nonce;                      /* Monotonic counter */
    uint64_t last_proof_ts;              /* Timestamp of last proof consumption */
    uint32_t hash_cfg;                   /* TRUST_HASH_CFG_* for next proof */
    uint32_t chain_length;               /* Number of proofs consumed so far */
    uint8_t  seed_set;                   /* 1 if seed has been written */
    uint8_t  proof_valid;                /* 1 if current proof is valid */
    uint8_t  chain_broken;               /* 1 if proof chain was broken */
    uint8_t  _padding;
} trust_proof_state_t;

/*
 * --- Token Economy (Metabolic Cost) ---
 *
 * Every privileged action burns tokens. Tokens regenerate over time.
 * This bounds the damage from any compromise to C(E)/Cmin operations.
 *
 * Key properties:
 * - Higher-privilege actions cost more tokens
 * - Token balance is part of the chromosomal state (A2)
 * - Metabolic fairness: no entity can monopolize authority indefinitely
 * - Token starvation triggers capability suspension, not revocation
 */

#define TRUST_TOKEN_MAX_DEFAULT     1000
#define TRUST_TOKEN_REGEN_DEFAULT   10      /* Tokens regenerated per tick */
#define TRUST_TOKEN_MIN             0

/* Metabolic cost table indices */
#define TRUST_COST_FILE_READ        1
#define TRUST_COST_FILE_WRITE       2
#define TRUST_COST_NET_CONNECT      3
#define TRUST_COST_NET_LISTEN       5
#define TRUST_COST_PROCESS_CREATE   10
#define TRUST_COST_PROCESS_SIGNAL   8
#define TRUST_COST_DEVICE_ACCESS    20
#define TRUST_COST_FIREWALL_MODIFY  25
#define TRUST_COST_TRUST_MODIFY     30
#define TRUST_COST_ESCALATE         50
#define TRUST_COST_KERNEL_CALL      100
#define TRUST_COST_DOMAIN_TRANSFER  15

typedef struct {
    int32_t  balance;           /* Current token balance */
    int32_t  max_balance;       /* Maximum token capacity */
    uint32_t regen_rate;        /* Tokens regenerated per tick */
    uint32_t total_burned;      /* Lifetime tokens consumed */
    uint32_t total_regenerated; /* Lifetime tokens regenerated */
    uint64_t last_regen_ts;     /* Timestamp of last regeneration */
    uint8_t  starved;           /* 1 if balance <= 0 (caps suspended) */
    uint8_t  _padding[7];
} trust_token_state_t;

/*
 * --- Lifecycle State (Mitotic/Meiotic) ---
 *
 * Mitotic Division (process spawning):
 *   - Child inherits parent's chromosome with generational decay
 *   - Smax(g) = alpha^g * Smax(0), where alpha < 1 (default 0.9)
 *   - Excessive spawning triggers cancer detection
 *
 * Meiotic Combination (dual-entity cooperation):
 *   - Two entities combine to create shared authority context
 *   - Combined authority bounded by min(S(EA), S(EB))
 *   - Requires mutual consent (both entities must approve)
 *
 * Lifecycle states:
 */
#define TRUST_LIFECYCLE_EMBRYONIC   0   /* Just created, not yet verified */
#define TRUST_LIFECYCLE_ACTIVE      1   /* Running normally */
#define TRUST_LIFECYCLE_DIVIDING    2   /* In mitotic division (spawning) */
#define TRUST_LIFECYCLE_COMBINING   3   /* In meiotic combination */
#define TRUST_LIFECYCLE_SENESCENT   4   /* Aged out, reduced capabilities */
#define TRUST_LIFECYCLE_APOPTOTIC   5   /* Undergoing controlled death */
#define TRUST_LIFECYCLE_NECROTIC    6   /* Uncontrolled death (crash/kill) */

/* Generational decay: Smax(g) = ALPHA^g * Smax(0) */
/* Using fixed-point: alpha = 230/256 ≈ 0.898 */
#define TRUST_GENERATION_ALPHA_NUM  230
#define TRUST_GENERATION_ALPHA_DEN  256
#define TRUST_GENERATION_MAX        16  /* Max generation depth */

/* Cancer detection thresholds */
#define TRUST_CANCER_SPAWN_WINDOW   5000000000ULL  /* 5 seconds in ns */
#define TRUST_CANCER_SPAWN_LIMIT    20   /* Max spawns in window before cancer flag */
#define TRUST_CANCER_TOTAL_LIMIT    1000 /* Absolute spawn lifetime limit */

typedef struct {
    uint8_t  state;                 /* TRUST_LIFECYCLE_* */
    uint8_t  generation;            /* Mitotic generation (0 = original) */
    uint16_t spawn_count;           /* Children spawned in current window */
    uint32_t total_spawns;          /* Lifetime children spawned */
    uint32_t parent_id;             /* Parent subject ID (0 = root process) */
    uint32_t meiotic_partner;       /* Partner subject ID in meiotic combination */
    uint64_t spawn_window_start;    /* Start of current spawn rate window */
    uint64_t birth_ts;              /* When this entity was created */
    uint64_t last_division_ts;      /* Timestamp of last mitotic division */
    int32_t  max_score;             /* Score ceiling: alpha^g * Smax(0) */
    uint32_t flags;                 /* Lifecycle-specific flags */
} trust_lifecycle_t;

/* Lifecycle flags */
#define TRUST_LIFE_FLAG_CHECKPOINT  (1U << 0)  /* Checkpoint verified */
#define TRUST_LIFE_FLAG_IMMUNE      (1U << 1)  /* Protected from apoptosis */
#define TRUST_LIFE_FLAG_ORPHAN      (1U << 2)  /* Parent died */
#define TRUST_LIFE_FLAG_REROOTED    (1U << 3)  /* Orphan re-rooted to init */

/*
 * --- Immune Response ---
 *
 * Cancer detection: runaway process spawning
 * Apoptotic cascade: controlled death propagation
 *   - XX children (conformant) die with parent
 *   - XY children (divergent) survive, re-rooted to init
 * Orphan handling: parentless processes get adopted
 */
#define TRUST_IMMUNE_HEALTHY        0
#define TRUST_IMMUNE_SUSPICIOUS     1   /* Elevated monitoring */
#define TRUST_IMMUNE_CANCEROUS      2   /* Cancer confirmed, apoptosis pending */
#define TRUST_IMMUNE_APOPTOSIS      3   /* Controlled death in progress */
#define TRUST_IMMUNE_QUARANTINED    4   /* Isolated, no actions allowed */

typedef struct {
    uint8_t  status;                /* TRUST_IMMUNE_* */
    uint8_t  apoptosis_cascade;     /* Depth of cascade (0 = origin) */
    uint16_t suspicious_actions;    /* Count of suspicious actions */
    uint32_t quarantine_reason;     /* Action type that triggered quarantine */
    uint64_t quarantine_ts;         /* When quarantine began */
    uint64_t apoptosis_deadline;    /* Hard deadline for cleanup */
} trust_immune_t;

/*
 * --- Trust Regulation Core (TRC) ---
 *
 * State machine: TRC = (R, Th, C, S, F)
 *   R  = Resistance: how hard it is to change authority
 *   Th = Threshold: current threshold configuration
 *   C  = Cost: metabolic cost multiplier
 *   S  = State: current TRC state
 *   F  = Flow: rate of authority change
 *
 * The TRC sits between the RISC fast-path and FBC complex-path,
 * dynamically adjusting how much "resistance" the system has to
 * authority changes.
 */
#define TRUST_TRC_NORMAL        0   /* Normal operating mode */
#define TRUST_TRC_ELEVATED      1   /* Elevated resistance (after anomaly) */
#define TRUST_TRC_LOCKDOWN      2   /* Maximum resistance (under attack) */
#define TRUST_TRC_PERMISSIVE    3   /* Reduced resistance (trusted period) */

typedef struct {
    uint32_t resistance;        /* Higher = harder to change authority (1-1000) */
    int32_t  threshold_bias;    /* Added to all threshold checks */
    uint32_t cost_multiplier;   /* Multiply token costs (fixed-point 8.8) */
    uint8_t  state;             /* TRUST_TRC_* */
    uint8_t  _padding[3];
    uint32_t flow_in;           /* Authority flow into subject (per tick) */
    uint32_t flow_out;          /* Authority flow out of subject (per tick) */
    uint32_t resistance_decay;  /* How fast resistance returns to normal */
} trust_trc_t;

/*
 * trust_subject_t - Core trust subject (extended with RoA fields)
 *
 * Every process, service, or AI agent is a subject in the trust system.
 * The subject's trust score determines what capabilities it has, creating
 * a dynamic, biologically-inspired privilege system.
 *
 * The chromosome, proof chain, tokens, lifecycle, immune state, and TRC
 * together implement the full Root of Authority model: authority is not
 * granted or stored, but continuously metabolized through self-consuming
 * proof chains and behavioral observation.
 */
typedef struct {
    /* --- Core identity --- */
    uint32_t subject_id;        /* PID or subsystem ID */
    uint16_t domain;            /* TRUST_DOMAIN_* */
    uint16_t _padding;
    int32_t  trust_score;       /* -1000 to +1000 (signed, with hysteresis) */
    int32_t  threshold_low;     /* Below: revoke capabilities */
    int32_t  threshold_high;    /* Above: grant new capabilities */
    uint32_t capabilities;      /* Bitmask of TRUST_CAP_* */
    uint32_t authority_level;   /* TRUST_AUTH_* */
    uint64_t last_action_ts;    /* Timestamp of last trust-affecting action (ns) */
    uint32_t decay_rate;        /* Score points lost per decay tick */
    uint32_t flags;             /* TRUST_FLAG_* */

    /* --- Root of Authority extensions --- */
    trust_chromosome_t   chromosome;   /* 23 segment pairs (DNA) */
    trust_proof_state_t  proof;        /* Self-consuming proof chain */
    trust_token_state_t  tokens;       /* Metabolic token economy */
    trust_lifecycle_t    lifecycle;     /* Mitotic/meiotic lifecycle */
    trust_immune_t       immune;       /* Immune response state */
    trust_trc_t          trc;          /* Trust Regulation Core */
} trust_subject_t;

/*
 * trust_action_t - Trust action event
 *
 * Recorded when a subject performs a trust-affecting action.
 * The trust delta is applied and thresholds are checked.
 */
typedef struct {
    uint32_t actor_id;          /* Subject performing the action */
    uint32_t target_id;         /* Target subject (0 for system actions) */
    uint32_t action_type;       /* TRUST_ACTION_* */
    int32_t  trust_delta;       /* How much trust changes */
    uint64_t timestamp;         /* Nanosecond timestamp */
    uint32_t result;            /* 0=success, else error code */
    uint32_t _padding;
} trust_action_t;

/*
 * trust_policy_rule_t - Policy rule
 *
 * Maps actions to trust requirements and consequences.
 * Multiple rules can match; the strictest wins.
 */
typedef struct {
    uint32_t domain;            /* Which domain this rule applies to */
    uint32_t action_type;       /* TRUST_ACTION_* */
    int32_t  min_trust;         /* Minimum score to allow */
    uint32_t required_caps;     /* Required TRUST_CAP_* bits */
    int32_t  delta_on_success;  /* Trust change on successful action */
    int32_t  delta_on_failure;  /* Trust change on failed/denied action */
    int32_t  delta_on_violation;/* Trust change on policy violation */
    uint32_t flags;             /* Reserved */
} trust_policy_rule_t;

/*
 * trust_audit_entry_t - Audit log entry
 *
 * Written to the audit ring buffer on every trust-affecting event.
 */
typedef struct {
    uint64_t timestamp;
    uint32_t subject_id;
    uint32_t action_type;
    int32_t  old_score;
    int32_t  new_score;
    uint32_t old_caps;
    uint32_t new_caps;
    uint32_t result;
    uint32_t _padding;
} trust_audit_entry_t;

#endif /* TRUST_TYPES_H */
