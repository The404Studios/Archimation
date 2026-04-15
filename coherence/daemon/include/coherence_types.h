/*
 * coherence_types.h — Shared type + constant contract for the coherence
 * control system. Authoritative single-source; all daemon modules
 * (measurement, derivation, state, actuation) and the offline simulator
 * include this header.
 *
 * Do not add implementation here. Struct layouts and constants only.
 *
 * Timing model (ChatGPT-derived, grounded on observed Linux behavior):
 *   Base tick              =   1 ms
 *   CONTROL_FRAME          = 100 ms  (measurement aggregation window)
 *   DECISION_FRAME         = 250 ms  (derivation + arbiter evaluation)
 *   ACTUATION_FRAME        = 500 ms  (system writeback boundary)
 *   VALIDITY_WINDOW        = 200 ms  (= 2 * CONTROL_FRAME)
 *   TAU_HOLD               = 750 ms  (state-machine dwell time)
 *   TRANSITION_LOCKOUT     = 1500 ms (= 2 * TAU_HOLD)
 *   TAU_CPUSET             = 500 ms
 *   TAU_IRQ                = 1000 ms
 *   TAU_SQPOLL             = 250 ms
 *
 * Phase ordering (hard constraint — NO cross-phase execution):
 *   [0–100ms]   measurement phase (sample M(t))
 *   [100–250ms] derivation phase (D(t) = f(M(t-k)), k >= 2, validity check)
 *   [250–500ms] decision phase (evaluate V(t), compute A(t), arbitrate)
 *   [500ms]     actuation phase (single atomic commit; idempotent barrier)
 */
#ifndef COHERENCE_TYPES_H
#define COHERENCE_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>   /* for memcmp in coh_a_equal */

/* ===== Timing constants (milliseconds) ===== */
#define COH_BASE_TICK_MS              1u
#define COH_CONTROL_FRAME_MS          100u
#define COH_DECISION_FRAME_MS         250u
#define COH_ACTUATION_FRAME_MS        500u
#define COH_VALIDITY_WINDOW_MS        200u   /* = 2 * CONTROL_FRAME */
#define COH_TAU_HOLD_MS               750u
#define COH_TRANSITION_LOCKOUT_MS     1500u  /* = 2 * TAU_HOLD */
#define COH_TAU_CPUSET_MS             500u
#define COH_TAU_IRQ_MS                1000u
#define COH_TAU_SQPOLL_MS             250u
#define COH_DERIVATION_LAG_K          2u     /* minimum M-frame lag for D(t) */

/* ===== Thresholds (dimensionless, grounded on hardware noise floors) ===== */
#define COH_THETA_LATENCY_ENTER       1.00
#define COH_THETA_LATENCY_EXIT        0.65
#define COH_THETA_THERMAL_ENTER       0.85  /* ~87 C on (T-45)/(95-45) scale */
#define COH_THETA_THERMAL_EXIT        0.70  /* ~80 C */

/* ===== Composite-signal weights ===== */
#define COH_W_FT                      0.55  /* frametime dominates perception */
#define COH_W_SCHED                   0.25
#define COH_W_IO                      0.15
#define COH_W_THERM                   0.05  /* constraint, not optimisation */

/* ===== EMA smoothing coefficients (per-signal) ===== */
#define COH_ALPHA_FT_VAR              0.30
#define COH_ALPHA_CPU_TEMP            0.20
#define COH_ALPHA_SQ_LATENCY          0.40
#define COH_ALPHA_MIGRATION           0.30

/* ===== Sizes ===== */
#define COH_MAX_CPUS                  64
#define COH_MAX_IRQS                  512
#define COH_CPUMASK_STRLEN            128   /* enough for "0-63" syntax + NUL */

/* ===== Enums ===== */
typedef enum {
    COH_STATE_NORMAL              = 0,
    COH_STATE_LATENCY_CRITICAL    = 1,
    COH_STATE_THERMAL_CONSTRAINED = 2,
    COH_STATE_DEGRADED            = 3,
    COH_STATE_COUNT               = 4
} coh_state_t;

typedef enum {
    COH_EPP_DEFAULT       = 0,
    COH_EPP_POWER         = 1,
    COH_EPP_BALANCE_POWER = 2,
    COH_EPP_BALANCE_PERF  = 3,
    COH_EPP_PERFORMANCE   = 4
} coh_epp_t;

typedef enum {
    COH_PRESENT_AUTO      = 0,
    COH_PRESENT_MAILBOX   = 1,
    COH_PRESENT_IMMEDIATE = 2,
    COH_PRESENT_FIFO      = 3
} coh_present_mode_t;

/* ===== M(t) : measurement vector ===== */
typedef struct {
    uint64_t t_ms;                 /* wall-clock monotonic ms at sample time */

    double   ft_mean_ms;           /* frametime mean over CONTROL_FRAME */
    double   ft_var_ms2;           /* frametime variance (ms^2) */

    double   cpu_util[COH_MAX_CPUS];
    double   cpu_freq_khz[COH_MAX_CPUS];
    int      cpu_count;

    double   cpu_temp_c;           /* package temp, °C */

    double   irq_rate[COH_MAX_CPUS];
    double   ctx_switch_rate;
    double   migration_rate;

    double   sq_depth;             /* io_uring submission queue depth */
    double   sq_latency_us;        /* io_uring completion latency µs */

    coh_present_mode_t present_mode_actual;  /* as observed by Vulkan layer */

    uint32_t flags;                /* bit 0 = sample_complete, 1 = gpu_present */
} coh_metrics_t;

/* ===== D(t) : derived signals (smoothed + normalised) ===== */
typedef struct {
    uint64_t t_ms;
    uint64_t source_m_t_ms;        /* timestamp of the M(t-k) used */

    double   ft_instability;
    double   thermal;
    double   sched_instability;
    double   io_pressure;

    double   latency_pressure;     /* composite */
    double   system_stress;        /* composite of latency + thermal */

    /* Lyapunov candidate V(t) = w1*D_lat^2 + w2*D_sched^2 + w3*D_io^2 + w4*D_therm^2 */
    double   lyapunov_v;

    bool     valid;                /* false if source M was stale */
} coh_derived_t;

/* ===== A(t) : actuation vector ===== */
typedef struct {
    uint64_t t_ms;

    /* cgroup v2 */
    char     game_cpuset[COH_CPUMASK_STRLEN];
    char     system_cpuset[COH_CPUMASK_STRLEN];

    /* IRQ affinity — masks per IRQ number; only IRQs in irq_list are written */
    int      irq_list[COH_MAX_IRQS];
    char     irq_affinity[COH_MAX_IRQS][COH_CPUMASK_STRLEN];
    int      irq_count;

    /* io_uring */
    int      sqpoll_cpu;

    /* cpufreq */
    coh_epp_t epp;
    int       min_perf_pct;        /* [0, 100]; <0 = unchanged */

    /* Vulkan layer */
    coh_present_mode_t present_mode_override;

    /* gamescope */
    bool     use_gamescope;
} coh_actuation_t;

/* ===== Arbiter runtime state ===== */
typedef struct {
    coh_state_t state;
    uint64_t    state_enter_t_ms;
    uint64_t    lockout_until_t_ms;

    /* Rolling stats used by the simulator + /system/coherence endpoint */
    uint64_t    transitions_total;
    uint64_t    transitions_last_window;
    uint64_t    ineffective_actions;
    uint64_t    effective_actions;
} coh_arbiter_t;

/* ===== Freshness / idempotency helpers ===== */
static inline bool coh_m_is_fresh(uint64_t now_ms, uint64_t sample_t_ms)
{
    return (now_ms - sample_t_ms) <= COH_VALIDITY_WINDOW_MS;
}

static inline bool coh_in_lockout(const coh_arbiter_t *a, uint64_t now_ms)
{
    return now_ms < a->lockout_until_t_ms;
}

/* Actuation equality — used by the idempotent-barrier rule in actuation.c.
 * Two A(t) vectors are equal for commit purposes when every actuator value
 * matches; timestamps are ignored. */
static inline bool coh_a_equal(const coh_actuation_t *a, const coh_actuation_t *b)
{
    if (!a || !b) return false;
    if (a->epp != b->epp) return false;
    if (a->min_perf_pct != b->min_perf_pct) return false;
    if (a->sqpoll_cpu != b->sqpoll_cpu) return false;
    if (a->present_mode_override != b->present_mode_override) return false;
    if (a->use_gamescope != b->use_gamescope) return false;
    if (a->irq_count != b->irq_count) return false;
    for (int i = 0; i < a->irq_count; i++) {
        if (a->irq_list[i] != b->irq_list[i]) return false;
    }
    /* String masks compared via memcmp (NUL-terminated, fixed buffer).
     * memcmp declaration comes via <string.h> included at top of header. */
    if (memcmp(a->game_cpuset, b->game_cpuset, COH_CPUMASK_STRLEN)) return false;
    if (memcmp(a->system_cpuset, b->system_cpuset, COH_CPUMASK_STRLEN)) return false;
    if (memcmp(a->irq_affinity, b->irq_affinity, sizeof(a->irq_affinity))) return false;
    return true;
}

/* ===== R34 typestate contract =====
 *
 * Typestate pattern: the state IS the permission. Instead of a bool
 * validity flag plus a separate "is this committable?" check, the
 * structure carries an enum that encodes what it is AND what it may do.
 * Every new state enum MUST:
 *   (1) use 0 as the UNINIT (invalid / uninitialized) variant
 *   (2) publish a total transition table as `static const` (see *_TRANSITIONS)
 *   (3) ship a debug stringifier coh_*_str()
 *   (4) use EXPLICIT integer values for ABI stability
 * If a transition is not in the table, it is forbidden. No "default fallback".
 */

/* Derived signal state. Replaces the earlier `bool valid` on coh_derived_t.
 * FRESH = M source was in validity window; EMAs advanced.
 * STALE = M source outside validity window; EMAs frozen; cached snapshot.
 * DEGRADED = multiple stale frames in a row; confidence below threshold.
 */
typedef enum {
    COH_DERIVED_UNINIT   = 0,
    COH_DERIVED_FRESH    = 1,
    COH_DERIVED_STALE    = 2,
    COH_DERIVED_DEGRADED = 3,
    COH_DERIVED_STATE_COUNT = 4
} coh_derived_state_t;

/* Actuation commit pipeline. Replaces ad-hoc flag checks in actuation.c.
 * PLANNED      = arbiter filled in fields; not yet validated.
 * RATE_LIMITED = at least one actuator missed its τ window; queued for retry.
 * BARRIERED    = equal to last committed A; idempotent skip recorded.
 * COMMITTED    = writes succeeded; g_last_committed updated.
 * FAILED       = at least one write returned < 0; g_last_committed unchanged.
 */
typedef enum {
    COH_ACT_UNINIT       = 0,
    COH_ACT_PLANNED      = 1,
    COH_ACT_RATE_LIMITED = 2,
    COH_ACT_BARRIERED    = 3,
    COH_ACT_COMMITTED    = 4,
    COH_ACT_FAILED       = 5,
    COH_ACT_STATE_COUNT  = 6
} coh_act_state_t;

/* Posture: an atomically validated composite actuator. Replaces the
 * pattern where cpuset/IRQ/SQPOLL/EPP were validated independently and
 * could be committed in inconsistent combinations.
 *
 * UNVALIDATED = fields filled in, invariants not yet checked.
 * VALIDATED   = cross-field invariants hold (e.g., SQPOLL cpu ∉ game cpuset).
 * COMMITTED   = atomically written to the kernel at frame edge.
 */
typedef enum {
    COH_POSTURE_UNINIT      = 0,
    COH_POSTURE_UNVALIDATED = 1,
    COH_POSTURE_VALIDATED   = 2,
    COH_POSTURE_COMMITTED   = 3,
    COH_POSTURE_STATE_COUNT = 4
} coh_posture_state_t;

/* Composite posture struct. Atomic unit of actuator configuration.
 * All fields must agree; validation is all-or-nothing. */
typedef struct {
    coh_posture_state_t state;
    char     game_cpuset[COH_CPUMASK_STRLEN];
    char     system_cpuset[COH_CPUMASK_STRLEN];
    int      sqpoll_cpu;              /* MUST NOT overlap game_cpuset when validated */
    coh_epp_t epp;
    int       min_perf_pct;
    int       numa_node;              /* -1 for no NUMA preference */
    uint64_t  validated_at_ms;        /* 0 if state < VALIDATED */
} coh_posture_t;

/* Stringifier prototypes. Implementations live in state_machine.c (Agent 1)
 * and posture.c (Agent 2). Never NULL; unknown inputs return "INVALID". */
const char *coh_derived_state_str(coh_derived_state_t s);
const char *coh_act_state_str(coh_act_state_t s);
const char *coh_posture_state_str(coh_posture_state_t s);

/* Transition legality helpers. Total-function: returns false for any
 * transition not in the published table. Callers must branch on the
 * return value; there is no "try anyway" path. */
bool coh_derived_transition_legal(coh_derived_state_t from, coh_derived_state_t to);
bool coh_act_transition_legal(coh_act_state_t from, coh_act_state_t to);
bool coh_posture_transition_legal(coh_posture_state_t from, coh_posture_state_t to);

/* ===== Compile-time invariants ===== */
_Static_assert(COH_VALIDITY_WINDOW_MS == 2 * COH_CONTROL_FRAME_MS,
               "validity window must equal 2x control frame");
_Static_assert(COH_TRANSITION_LOCKOUT_MS == 2 * COH_TAU_HOLD_MS,
               "transition lockout must equal 2x tau_hold");
_Static_assert(COH_ACTUATION_FRAME_MS > COH_DECISION_FRAME_MS,
               "actuation frame must strictly follow decision frame");
_Static_assert(COH_DECISION_FRAME_MS > COH_CONTROL_FRAME_MS,
               "decision frame must strictly follow control frame");
_Static_assert(COH_DERIVATION_LAG_K >= 2,
               "derivation lag k must be >= 2 to prevent instantaneous loops");
_Static_assert(COH_DERIVED_UNINIT == 0, "UNINIT must be zero variant");
_Static_assert(COH_ACT_UNINIT == 0, "UNINIT must be zero variant");
_Static_assert(COH_POSTURE_UNINIT == 0, "UNINIT must be zero variant");

#endif /* COHERENCE_TYPES_H */
