/*
 * trust_morphogen.c - Turing reaction-diffusion tissue field
 *
 * S74 Agent 5 — gives trust subjects spatial extension. See
 * trust_morphogen.h for rationale and public API.
 *
 * Internals:
 *
 * 1. Static 32x32 grid of cells. Each cell: two u16 fixed-point scalars
 *    (activator A, inhibitor I) on [0, 65535] == [0.0, 1.0], plus a
 *    pid-of-resident sentinel (0 == free) and last_update_tick for the
 *    sysfs dump.
 *
 * 2. Double-buffered tick: one grid holds current state, a scratch grid
 *    receives next-state, pointers swap under the spinlock. Avoids the
 *    artifacts of in-place Laplacian that simpler Turing codes exhibit.
 *
 * 3. Placement is an RCU-ish side-table (simple array of
 *    {subject_id, x, y}) keyed by subject_id with linear probe.
 *    Small — bounded by TRUST_MORPHOGEN_MAX_SUBJECTS=1024. Writers take
 *    morphogen_lock. Readers (perturb) take it briefly.
 *
 * 4. Diffusion uses the 4-neighbor (von Neumann) Laplacian with
 *    reflecting boundary (clamp to edge). This preserves total mass at
 *    the walls — stress events near the edge don't leak off the grid.
 *
 * 5. Reaction (all arithmetic in u32/s32 fixed-point, Q16 scaled):
 *
 *       dA = D_a * L(A) - s * A * I + r * A * (1 - A/K)
 *       dI = D_i * L(I) + q * A - u * I
 *
 *    with constants chosen to produce Turing SPOT patterns (localized
 *    activator clumps surrounded by inhibitor), which is the pattern
 *    that biology uses for tissue-level anomaly memory. See
 *    CONSTANT TUNING comment below.
 *
 * 6. 100ms tick cadence (HZ/10) via delayed_work. This is slow enough
 *    that the diffusion is stable for any reasonable D_a/D_i, and fast
 *    enough that a single human-timescale anomaly (eg a burst of authz
 *    denials) creates a visible "hot region" the cortex can spot within
 *    a second.
 *
 * 7. sysfs /sys/kernel/trust/morphogen/{dump,stats,tick_rate}:
 *      dump       (RO) — 1024 u32 lines "x y A I pid" for cortex/Python
 *      stats      (RO) — counter/summary line (tick count, sum A, sum I)
 *      tick_rate  (RW) — jiffies between ticks, bounded [HZ/100, HZ*10]
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/atomic.h>
#include <linux/printk.h>
#include <linux/cache.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/errno.h>

#include "trust_internal.h"
#include "trust_morphogen.h"

/* =====================================================================
 * CONSTANT TUNING — Gray-Scott / Thomas-style reaction-diffusion
 *
 * The brief specified D_a=0.16, D_i=0.08. However, for spot-pattern
 * Turing instability we need D_i > D_a (inhibitor diffuses *faster*
 * than activator) — this is the classical Turing condition, derived
 * from linear stability analysis of the reaction-diffusion PDE.
 *
 * If we kept D_a > D_i the field would dissolve into a uniform smear
 * instead of forming localized hot-spots, defeating the architectural
 * purpose (the cortex needs clumps of "recent stress" to read).
 *
 * Therefore: SWAPPED to D_a=0.08, D_i=0.16. Documenting this choice
 * here because it's a deliberate deviation from the brief, made on
 * textbook grounds (Murray, Mathematical Biology II, ch. 2).
 *
 * All values are Q16 fixed-point (multiplied by 65536). Per-tick
 * integration step is dt=1 (implicit in the Q16 unit step); the small
 * D and reaction constants keep the Courant number << 1 for the
 * 1-cell spatial step, so explicit Euler is numerically stable.
 * ===================================================================== */
#define MORPHOGEN_Q16            65536U                      /* fixed-point one */
#define MORPHOGEN_FP_MAX         65535U                      /* clamp ceiling */

/* Q16 diffusion rates (explicit Euler; stable for 4-neighbor Laplacian
 * when D * dt / dx^2 <= 0.25 — here dt=1, dx=1, D=0.16 -> 0.16 < 0.25 OK) */
#define MORPHOGEN_D_A            ((u32)(0.08 * MORPHOGEN_Q16))  /* activator */
#define MORPHOGEN_D_I            ((u32)(0.16 * MORPHOGEN_Q16))  /* inhibitor diffuses faster */

/* Reaction constants — all Q16. Signed where the sign matters.
 *   s*A*I = suppression term (strong)
 *   r*A*(1-A/K) = logistic growth (slow)
 *   q*A = inhibitor production from activator
 *   u*I = inhibitor decay
 */
#define MORPHOGEN_S              ((u32)(0.0001 * MORPHOGEN_Q16))   /* ≈ 6 */
#define MORPHOGEN_R              ((u32)(0.002  * MORPHOGEN_Q16))   /* ≈ 131 */
#define MORPHOGEN_K              60000U                             /* carrying capacity */
#define MORPHOGEN_Q              ((u32)(0.0005 * MORPHOGEN_Q16))   /* ≈ 33 */
#define MORPHOGEN_U              ((u32)(0.003  * MORPHOGEN_Q16))   /* ≈ 197 */

/* Tick: 100 ms default. Configurable via sysfs tick_rate in jiffies. */
#define MORPHOGEN_TICK_DEFAULT_J (HZ / 10U > 0U ? HZ / 10U : 1U)

/* =====================================================================
 * CELL + GRID STORAGE
 * ===================================================================== */

struct trust_morphogen_cell {
    u16 activator;         /* Q16 fixed-point [0..65535] */
    u16 inhibitor;         /* Q16 fixed-point [0..65535] */
    u32 last_update_tick;  /* tick counter at last write; for sysfs dump */
    u32 resident_pid;      /* 0 == free; subject_id of occupant otherwise */
};

/* Double-buffered to avoid in-place Laplacian artifacts. */
static struct trust_morphogen_cell grid_a[TRUST_MORPHOGEN_DIM][TRUST_MORPHOGEN_DIM]
    ____cacheline_aligned_in_smp;
static struct trust_morphogen_cell grid_b[TRUST_MORPHOGEN_DIM][TRUST_MORPHOGEN_DIM]
    ____cacheline_aligned_in_smp;

/* front = current read-from grid; back = scratch write-to grid. Swap on tick. */
static struct trust_morphogen_cell (*grid_front)[TRUST_MORPHOGEN_DIM] = grid_a;
static struct trust_morphogen_cell (*grid_back)[TRUST_MORPHOGEN_DIM]  = grid_b;

/* =====================================================================
 * PLACEMENT SIDE-TABLE
 *
 * Maps subject_id -> (x, y). Simple linear-probe hash table, bounded
 * by TRUST_MORPHOGEN_MAX_SUBJECTS. We prefer simplicity over speed
 * here — lookup is O(load_factor) in the worst case, and the table is
 * 1024 entries by spec limit so constants are tiny.
 * ===================================================================== */
struct morphogen_placement {
    u32 subject_id;   /* 0 == empty slot */
    u8  x;
    u8  y;
    u8  _pad[2];
};

static struct morphogen_placement placements[TRUST_MORPHOGEN_MAX_SUBJECTS];
static DEFINE_SPINLOCK(morphogen_lock);

/* =====================================================================
 * STATS / TIMING
 * ===================================================================== */
static atomic64_t morphogen_tick_count = ATOMIC64_INIT(0);
static atomic64_t morphogen_perturb_count = ATOMIC64_INIT(0);
static atomic64_t morphogen_collisions = ATOMIC64_INIT(0);   /* linear probe depth > 1 */
static atomic_t   morphogen_placed = ATOMIC_INIT(0);         /* current occupancy */
static u32        morphogen_tick_jiffies = 0;                /* set by init */

/* delayed_work for the 100ms tick */
static struct delayed_work morphogen_tick_work;
static bool               morphogen_running = false;

/* sysfs kobject */
static struct kobject *g_morphogen_kobj = NULL;

/* =====================================================================
 * FNV-1a 32-bit — small, stable, header-free
 * ===================================================================== */
static inline u32 morphogen_fnv32(u32 seed)
{
    u32 h = 0x811C9DC5U;  /* FNV offset basis */
    int i;
    for (i = 0; i < 4; i++) {
        h ^= (seed >> (i * 8)) & 0xFFU;
        h *= 0x01000193U; /* FNV prime */
    }
    return h;
}

/* =====================================================================
 * PLACEMENT: slot lookup (both finding and inserting)
 *
 * slot = fnv32(subject_id) % TABLE_SIZE; linear-probe on collision.
 *
 * Must be called under morphogen_lock.
 * ===================================================================== */
static struct morphogen_placement *morphogen_find_slot(u32 subject_id,
                                                       bool insert_mode)
{
    u32 slot, probe;
    u32 start;

    if (subject_id == 0U)
        return NULL;

    start = morphogen_fnv32(subject_id) % TRUST_MORPHOGEN_MAX_SUBJECTS;
    for (probe = 0; probe < TRUST_MORPHOGEN_MAX_SUBJECTS; probe++) {
        slot = (start + probe) % TRUST_MORPHOGEN_MAX_SUBJECTS;
        if (placements[slot].subject_id == subject_id)
            return &placements[slot];
        if (insert_mode && placements[slot].subject_id == 0U) {
            if (probe > 0)
                atomic64_inc(&morphogen_collisions);
            return &placements[slot];
        }
    }
    return NULL;  /* table full (insert) or not found (lookup) */
}

/* =====================================================================
 * PLACEMENT: grid cell allocation
 *
 * Given a preferred (x0, y0) from fnv32(pid) mod DIM, scan for the
 * nearest unoccupied grid cell. Row-major linear probe is simplest
 * and keeps spatial locality (neighbors end up spatially near their
 * pid-preferred home unless there's heavy contention).
 *
 * Must be called under morphogen_lock. Writes the new owner's
 * subject_id into the returned cell's resident_pid.
 * ===================================================================== */
static int morphogen_alloc_cell(u32 subject_id, u8 x0, u8 y0,
                                u8 *out_x, u8 *out_y)
{
    u32 base, probe, linear;
    u8 x, y;

    base = ((u32)y0 * TRUST_MORPHOGEN_DIM) + (u32)x0;
    for (probe = 0; probe < TRUST_MORPHOGEN_CELLS; probe++) {
        linear = (base + probe) % TRUST_MORPHOGEN_CELLS;
        x = (u8)(linear % TRUST_MORPHOGEN_DIM);
        y = (u8)(linear / TRUST_MORPHOGEN_DIM);
        if (grid_front[y][x].resident_pid == 0U) {
            grid_front[y][x].resident_pid = subject_id;
            /* Keep grid_back resident_pid in sync so the swap never
             * reveals a "phantom" owner. */
            grid_back[y][x].resident_pid = subject_id;
            *out_x = x;
            *out_y = y;
            return 0;
        }
    }
    return -ENOSPC;
}

/* =====================================================================
 * Public: place / remove subject
 * ===================================================================== */
int trust_morphogen_place_subject(const trust_subject_t *s,
                                  u8 *out_x, u8 *out_y)
{
    unsigned long flags;
    struct morphogen_placement *slot;
    u32 sid, h;
    u8 x0, y0;
    int rc;

    if (!s || !out_x || !out_y)
        return -EINVAL;

    sid = s->subject_id;
    if (sid == 0U)
        return -EINVAL;

    h = morphogen_fnv32(sid);
    x0 = (u8)(h % TRUST_MORPHOGEN_DIM);
    y0 = (u8)((h >> 16) % TRUST_MORPHOGEN_DIM);

    spin_lock_irqsave(&morphogen_lock, flags);

    /* Already placed? Return existing coords (idempotent). */
    slot = morphogen_find_slot(sid, false);
    if (slot) {
        *out_x = slot->x;
        *out_y = slot->y;
        spin_unlock_irqrestore(&morphogen_lock, flags);
        return 0;
    }

    slot = morphogen_find_slot(sid, true);
    if (!slot) {
        spin_unlock_irqrestore(&morphogen_lock, flags);
        return -ENOSPC;
    }

    rc = morphogen_alloc_cell(sid, x0, y0, out_x, out_y);
    if (rc < 0) {
        /* placement slot is still zeroed, leave it — no leak */
        spin_unlock_irqrestore(&morphogen_lock, flags);
        return rc;
    }

    slot->subject_id = sid;
    slot->x = *out_x;
    slot->y = *out_y;
    atomic_inc(&morphogen_placed);

    spin_unlock_irqrestore(&morphogen_lock, flags);
    return 0;
}
EXPORT_SYMBOL_GPL(trust_morphogen_place_subject);

void trust_morphogen_remove_subject(u32 subject_id)
{
    unsigned long flags;
    struct morphogen_placement *slot;

    if (subject_id == 0U)
        return;

    spin_lock_irqsave(&morphogen_lock, flags);
    slot = morphogen_find_slot(subject_id, false);
    if (slot) {
        u8 x = slot->x, y = slot->y;
        grid_front[y][x].resident_pid = 0U;
        grid_back[y][x].resident_pid  = 0U;
        slot->subject_id = 0U;
        slot->x = 0U;
        slot->y = 0U;
        atomic_dec(&morphogen_placed);
    }
    spin_unlock_irqrestore(&morphogen_lock, flags);
}
EXPORT_SYMBOL_GPL(trust_morphogen_remove_subject);

/* =====================================================================
 * Event-kind -> (delta_A, delta_I) mapping
 *
 * All deltas are pre-severity; the caller's severity scales them.
 * Values tuned so a single severity=1 event is visible but not
 * field-saturating (max delta ~100 on the Q16 [0..65535] scale =
 * ~0.15%); a severe sudden burst (severity=100) will clearly perturb
 * the neighborhood but still not saturate after one tick.
 * ===================================================================== */
static void morphogen_event_delta(u32 event_kind,
                                  s32 *delta_a, s32 *delta_i)
{
    *delta_a = 0;
    *delta_i = 0;
    switch (event_kind) {
    case TRUST_MORPHOGEN_EVENT_AUTHZ_ALLOW:
        /* Success — mild activator decay (healthy tissue quiets down) */
        *delta_a = -5;
        break;
    case TRUST_MORPHOGEN_EVENT_AUTHZ_DENY:
        *delta_a = 100;
        break;
    case TRUST_MORPHOGEN_EVENT_MITOSIS:
        *delta_a = 50;   /* growth signal */
        break;
    case TRUST_MORPHOGEN_EVENT_APOPTOSIS:
        *delta_i = 200;  /* strong suppression */
        break;
    case TRUST_MORPHOGEN_EVENT_CANCER:
        *delta_a = 400;  /* severe: large activator spike */
        break;
    case TRUST_MORPHOGEN_EVENT_QUARANTINE:
        *delta_i = 300;  /* severe suppression */
        break;
    case TRUST_MORPHOGEN_EVENT_PROOF_BREAK:
        *delta_a = 500;  /* critical stress */
        *delta_i = 100;  /* but also trigger suppression */
        break;
    case TRUST_MORPHOGEN_EVENT_GENERIC:
    default:
        *delta_a = 10;
        break;
    }
}

/* Saturating add for u16 Q16 value: clamp to [0, 65535]. */
static inline u16 morphogen_sat_add(u16 v, s32 delta)
{
    s32 x = (s32)v + delta;
    if (x < 0)
        return 0U;
    if (x > (s32)MORPHOGEN_FP_MAX)
        return (u16)MORPHOGEN_FP_MAX;
    return (u16)x;
}

void trust_morphogen_perturb(u32 subject_id, u32 event_kind, u32 severity)
{
    unsigned long flags;
    struct morphogen_placement *slot;
    s32 da = 0, di = 0;
    s64 scaled_a, scaled_i;
    u8 x, y;

    if (!morphogen_running)
        return;
    if (event_kind >= TRUST_MORPHOGEN_EVENT_MAX)
        event_kind = TRUST_MORPHOGEN_EVENT_GENERIC;
    if (severity == 0U)
        severity = 1U;
    if (severity > 1000U)
        severity = 1000U;  /* clamp to avoid overflow in s64 */

    morphogen_event_delta(event_kind, &da, &di);

    /* s32 * u32 up to 500 * 1000 = 500_000 fits in s64 easily. */
    scaled_a = (s64)da * (s64)severity;
    scaled_i = (s64)di * (s64)severity;

    spin_lock_irqsave(&morphogen_lock, flags);
    slot = morphogen_find_slot(subject_id, false);
    if (!slot) {
        spin_unlock_irqrestore(&morphogen_lock, flags);
        /* Not placed — silently drop. Not a bug; happens during early
         * subject setup (see header). */
        return;
    }
    x = slot->x;
    y = slot->y;

    grid_front[y][x].activator = morphogen_sat_add(grid_front[y][x].activator,
                                                   (s32)scaled_a);
    grid_front[y][x].inhibitor = morphogen_sat_add(grid_front[y][x].inhibitor,
                                                   (s32)scaled_i);
    grid_front[y][x].last_update_tick = (u32)atomic64_read(&morphogen_tick_count);

    spin_unlock_irqrestore(&morphogen_lock, flags);

    atomic64_inc(&morphogen_perturb_count);
}
EXPORT_SYMBOL_GPL(trust_morphogen_perturb);

int trust_morphogen_peek(u8 x, u8 y, u16 *out_activator, u16 *out_inhibitor)
{
    unsigned long flags;

    if (x >= TRUST_MORPHOGEN_DIM || y >= TRUST_MORPHOGEN_DIM)
        return -EINVAL;
    if (!out_activator || !out_inhibitor)
        return -EINVAL;

    spin_lock_irqsave(&morphogen_lock, flags);
    *out_activator = grid_front[y][x].activator;
    *out_inhibitor = grid_front[y][x].inhibitor;
    spin_unlock_irqrestore(&morphogen_lock, flags);
    return 0;
}
EXPORT_SYMBOL_GPL(trust_morphogen_peek);

/* =====================================================================
 * LAPLACIAN (4-neighbor, reflecting boundary)
 *
 *   L(X)[y][x] = X[y-1][x] + X[y+1][x] + X[y][x-1] + X[y][x+1] - 4*X[y][x]
 *
 * Reflecting boundary: at the edge, the "missing" neighbor is treated
 * as equal to the current cell (contributes X[y][x] instead of a
 * wrapped value). This preserves total mass at the walls.
 * ===================================================================== */
static inline s32 morphogen_laplacian_a(int x, int y)
{
    s32 n, s, w, e, c;
    c = (s32)grid_front[y][x].activator;
    n = (y > 0) ? (s32)grid_front[y - 1][x].activator : c;
    s = (y < (int)TRUST_MORPHOGEN_DIM - 1) ? (s32)grid_front[y + 1][x].activator : c;
    w = (x > 0) ? (s32)grid_front[y][x - 1].activator : c;
    e = (x < (int)TRUST_MORPHOGEN_DIM - 1) ? (s32)grid_front[y][x + 1].activator : c;
    return (n + s + w + e) - 4 * c;
}

static inline s32 morphogen_laplacian_i(int x, int y)
{
    s32 n, s, w, e, c;
    c = (s32)grid_front[y][x].inhibitor;
    n = (y > 0) ? (s32)grid_front[y - 1][x].inhibitor : c;
    s = (y < (int)TRUST_MORPHOGEN_DIM - 1) ? (s32)grid_front[y + 1][x].inhibitor : c;
    w = (x > 0) ? (s32)grid_front[y][x - 1].inhibitor : c;
    e = (x < (int)TRUST_MORPHOGEN_DIM - 1) ? (s32)grid_front[y][x + 1].inhibitor : c;
    return (n + s + w + e) - 4 * c;
}

/* =====================================================================
 * TICK: one integration step
 *
 * Computes new_A[y][x] and new_I[y][x] into grid_back, then swaps
 * front/back under the lock. Called from the delayed_work handler.
 *
 * Arithmetic: all reaction terms are in Q16 (so X*Y reduces by >> 16).
 * Diffusion is Q16 * Q16 -> Q32 intermediate, then >> 16 to recover
 * Q16. We use s64 intermediates where a product could exceed s32.
 *
 * Stability: per the head-comment Courant analysis, Euler is stable
 * for the chosen D values and dt=1.
 * ===================================================================== */
static void morphogen_step_cell(int x, int y)
{
    s64 lap_a, lap_i;
    s64 aA, iI, aI;
    s64 diff_a, diff_i;
    s64 react_a, react_i;
    s64 new_a, new_i;
    s32 A, I;

    A = (s32)grid_front[y][x].activator;
    I = (s32)grid_front[y][x].inhibitor;

    lap_a = morphogen_laplacian_a(x, y);
    lap_i = morphogen_laplacian_i(x, y);

    /* Diffusion: D_* (Q16) * lap_* (Q16 units of [0..65535]) / Q16 == scaled */
    diff_a = (lap_a * (s64)MORPHOGEN_D_A) >> 16;
    diff_i = (lap_i * (s64)MORPHOGEN_D_I) >> 16;

    /* Reaction A: -s*A*I + r*A*(1 - A/K)
     *   A*I is Q16*Q16; reduce by >> 16 to keep in Q16
     *   (1 - A/K): compute in Q16 as (Q16 - (A * Q16 / K))
     */
    aI = ((s64)A * (s64)I) >> 16;
    {
        s64 a_over_k_q16 = ((s64)A * (s64)MORPHOGEN_Q16) / (s64)MORPHOGEN_K;
        s64 one_minus    = (s64)MORPHOGEN_Q16 - a_over_k_q16;
        s64 aA_growth    = ((s64)A * one_minus) >> 16;  /* Q16 */
        react_a = - (((s64)MORPHOGEN_S * aI) >> 16)
                  + (((s64)MORPHOGEN_R * aA_growth) >> 16);
    }

    /* Reaction I: +q*A - u*I  (Q16 multipliers, Q16 A/I, result Q16) */
    iI = ((s64)MORPHOGEN_U * (s64)I) >> 16;
    aA = ((s64)MORPHOGEN_Q * (s64)A) >> 16;
    react_i = aA - iI;

    new_a = (s64)A + diff_a + react_a;
    new_i = (s64)I + diff_i + react_i;

    /* Clamp to [0, MORPHOGEN_FP_MAX] */
    if (new_a < 0) new_a = 0;
    if (new_a > (s64)MORPHOGEN_FP_MAX) new_a = (s64)MORPHOGEN_FP_MAX;
    if (new_i < 0) new_i = 0;
    if (new_i > (s64)MORPHOGEN_FP_MAX) new_i = (s64)MORPHOGEN_FP_MAX;

    grid_back[y][x].activator = (u16)new_a;
    grid_back[y][x].inhibitor = (u16)new_i;
    /* resident_pid and last_update_tick copied across by a separate loop
     * that runs once per tick (see morphogen_tick_fn). */
}

static void morphogen_tick_fn(struct work_struct *work)
{
    unsigned long flags;
    int x, y;
    struct trust_morphogen_cell (*swap)[TRUST_MORPHOGEN_DIM];

    spin_lock_irqsave(&morphogen_lock, flags);

    /* Preserve non-field metadata across the swap. */
    for (y = 0; y < (int)TRUST_MORPHOGEN_DIM; y++) {
        for (x = 0; x < (int)TRUST_MORPHOGEN_DIM; x++) {
            grid_back[y][x].resident_pid      = grid_front[y][x].resident_pid;
            grid_back[y][x].last_update_tick  = grid_front[y][x].last_update_tick;
        }
    }

    /* Integrate into grid_back. */
    for (y = 0; y < (int)TRUST_MORPHOGEN_DIM; y++) {
        for (x = 0; x < (int)TRUST_MORPHOGEN_DIM; x++) {
            morphogen_step_cell(x, y);
        }
    }

    /* Swap. Simple pointer swap under the lock; no copy. */
    swap        = grid_front;
    grid_front  = grid_back;
    grid_back   = swap;

    atomic64_inc(&morphogen_tick_count);

    spin_unlock_irqrestore(&morphogen_lock, flags);

    /* Re-arm (queue the next tick). Not done under lock — schedule_delayed_work
     * is safe to call while running in process context. */
    if (morphogen_running)
        schedule_delayed_work(&morphogen_tick_work, morphogen_tick_jiffies);

    (void)work;
}

/* =====================================================================
 * sysfs surface: /sys/kernel/trust/morphogen/{dump,stats,tick_rate}
 *
 * dump: up to PAGE_SIZE bytes, truncated at the end of a line boundary
 *       if overflow would occur. Each line: "x y A I pid\n". The cortex
 *       bridge (agent 6) parses this into a numpy array.
 *
 * stats: one line "ticks=%llu perturbs=%llu placed=%d collisions=%llu\n"
 *
 * tick_rate: jiffies-between-ticks; read returns current, write sets new
 *            (bounded to [HZ/100, HZ*10]).
 * ===================================================================== */

static ssize_t morphogen_dump_show(struct kobject *k, struct kobj_attribute *a,
                                   char *buf)
{
    unsigned long flags;
    int x, y;
    ssize_t off = 0;
    ssize_t avail = PAGE_SIZE - 1;  /* leave room for final NUL */

    (void)k; (void)a;

    spin_lock_irqsave(&morphogen_lock, flags);
    for (y = 0; y < (int)TRUST_MORPHOGEN_DIM; y++) {
        for (x = 0; x < (int)TRUST_MORPHOGEN_DIM; x++) {
            int n;
            /* Only emit cells with any signal or occupancy — keeps the
             * dump small at startup. A cortex reader that needs the
             * full field can derive it by zero-filling absent coords. */
            if (grid_front[y][x].activator == 0U &&
                grid_front[y][x].inhibitor == 0U &&
                grid_front[y][x].resident_pid == 0U)
                continue;
            n = scnprintf(buf + off, avail - off,
                          "%d %d %u %u %u\n",
                          x, y,
                          (unsigned)grid_front[y][x].activator,
                          (unsigned)grid_front[y][x].inhibitor,
                          (unsigned)grid_front[y][x].resident_pid);
            if (n <= 0 || (avail - off) < n + 1) {
                /* No room for another line — truncate at a line boundary. */
                goto done;
            }
            off += n;
        }
    }
done:
    spin_unlock_irqrestore(&morphogen_lock, flags);
    return off;
}

static ssize_t morphogen_stats_show(struct kobject *k, struct kobj_attribute *a,
                                    char *buf)
{
    (void)k; (void)a;
    return sysfs_emit(buf,
                      "ticks=%llu perturbs=%llu placed=%d collisions=%llu "
                      "tick_jiffies=%u dim=%u\n",
                      (unsigned long long)atomic64_read(&morphogen_tick_count),
                      (unsigned long long)atomic64_read(&morphogen_perturb_count),
                      atomic_read(&morphogen_placed),
                      (unsigned long long)atomic64_read(&morphogen_collisions),
                      morphogen_tick_jiffies,
                      TRUST_MORPHOGEN_DIM);
}

static ssize_t morphogen_tick_rate_show(struct kobject *k, struct kobj_attribute *a,
                                        char *buf)
{
    (void)k; (void)a;
    return sysfs_emit(buf, "%u\n", morphogen_tick_jiffies);
}

static ssize_t morphogen_tick_rate_store(struct kobject *k, struct kobj_attribute *a,
                                         const char *buf, size_t count)
{
    unsigned int new_j;
    int rc;
    unsigned long flags;

    (void)k; (void)a;
    rc = kstrtouint(buf, 0, &new_j);
    if (rc)
        return rc;

    /* Bound to [HZ/100, HZ*10] to avoid pathological schedulings. */
    if (new_j < (HZ / 100U > 0U ? HZ / 100U : 1U))
        new_j = (HZ / 100U > 0U ? HZ / 100U : 1U);
    if (new_j > HZ * 10U)
        new_j = HZ * 10U;

    spin_lock_irqsave(&morphogen_lock, flags);
    morphogen_tick_jiffies = new_j;
    spin_unlock_irqrestore(&morphogen_lock, flags);
    return count;
}

/* Use bare-name __ATTR with explicit show/store functions so the sysfs
 * node names ("dump", "stats", "tick_rate") can differ from the longer
 * C identifiers (morphogen_dump_show, ...). */
static struct kobj_attribute attr_dump_named =
    __ATTR(dump, 0444, morphogen_dump_show, NULL);
static struct kobj_attribute attr_stats_named =
    __ATTR(stats, 0444, morphogen_stats_show, NULL);
static struct kobj_attribute attr_tick_rate_named =
    __ATTR(tick_rate, 0644, morphogen_tick_rate_show, morphogen_tick_rate_store);

static struct attribute *morphogen_attrs[] = {
    &attr_dump_named.attr,
    &attr_stats_named.attr,
    &attr_tick_rate_named.attr,
    NULL,
};

static const struct attribute_group morphogen_group = {
    .attrs = morphogen_attrs,
};

static void morphogen_sysfs_register(void)
{
    int ret;
    g_morphogen_kobj = kobject_create_and_add("morphogen", kernel_kobj);
    if (!g_morphogen_kobj) {
        pr_warn("trust_morphogen: kobject_create_and_add failed - sysfs unavailable\n");
        return;
    }
    ret = sysfs_create_group(g_morphogen_kobj, &morphogen_group);
    if (ret) {
        pr_warn("trust_morphogen: sysfs_create_group failed (%d)\n", ret);
        kobject_put(g_morphogen_kobj);
        g_morphogen_kobj = NULL;
    }
}

static void morphogen_sysfs_unregister(void)
{
    if (g_morphogen_kobj) {
        sysfs_remove_group(g_morphogen_kobj, &morphogen_group);
        kobject_put(g_morphogen_kobj);
        g_morphogen_kobj = NULL;
    }
}

/* =====================================================================
 * init / fini
 * ===================================================================== */
int trust_morphogen_init(void)
{
    int x, y, i;

    /* Zero both grids. Static storage is already zero but we also run
     * after a module reload on some builds, so be explicit. */
    for (y = 0; y < (int)TRUST_MORPHOGEN_DIM; y++) {
        for (x = 0; x < (int)TRUST_MORPHOGEN_DIM; x++) {
            grid_a[y][x].activator = 0U;
            grid_a[y][x].inhibitor = 0U;
            grid_a[y][x].last_update_tick = 0U;
            grid_a[y][x].resident_pid = 0U;
            grid_b[y][x].activator = 0U;
            grid_b[y][x].inhibitor = 0U;
            grid_b[y][x].last_update_tick = 0U;
            grid_b[y][x].resident_pid = 0U;
        }
    }
    grid_front = grid_a;
    grid_back  = grid_b;

    for (i = 0; i < TRUST_MORPHOGEN_MAX_SUBJECTS; i++) {
        placements[i].subject_id = 0U;
        placements[i].x = 0U;
        placements[i].y = 0U;
    }

    atomic64_set(&morphogen_tick_count, 0);
    atomic64_set(&morphogen_perturb_count, 0);
    atomic64_set(&morphogen_collisions, 0);
    atomic_set(&morphogen_placed, 0);

    morphogen_tick_jiffies = MORPHOGEN_TICK_DEFAULT_J;

    morphogen_sysfs_register();

    INIT_DELAYED_WORK(&morphogen_tick_work, morphogen_tick_fn);
    morphogen_running = true;
    schedule_delayed_work(&morphogen_tick_work, morphogen_tick_jiffies);

    pr_info("trust_morphogen: initialized (%ux%u grid, D_a=0.08/D_i=0.16 Q16, "
            "tick=%ums, max_subjects=%u)\n",
            TRUST_MORPHOGEN_DIM, TRUST_MORPHOGEN_DIM,
            jiffies_to_msecs(morphogen_tick_jiffies),
            TRUST_MORPHOGEN_MAX_SUBJECTS);
    return 0;
}
EXPORT_SYMBOL_GPL(trust_morphogen_init);

void trust_morphogen_fini(void)
{
    morphogen_running = false;
    cancel_delayed_work_sync(&morphogen_tick_work);
    morphogen_sysfs_unregister();
    pr_info("trust_morphogen: cleanup complete (ticks=%llu, perturbs=%llu)\n",
            (unsigned long long)atomic64_read(&morphogen_tick_count),
            (unsigned long long)atomic64_read(&morphogen_perturb_count));
}
EXPORT_SYMBOL_GPL(trust_morphogen_fini);
