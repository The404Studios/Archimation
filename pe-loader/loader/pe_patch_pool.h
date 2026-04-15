/*
 * pe_patch_pool.h - Bounded absent pool for PE patch plans
 *
 * Purpose: a typed, fixed-size pool that holds RECENTLY-INVALIDATED
 * patch plans for fast resurrection within a time + population budget.
 * NOT a caching layer. NOT a GC. Just: "if an image unloaded N ms ago
 * and someone asks for an equivalent, skip the scan".
 *
 * Disciplined absence-pool rules (R34):
 *   1. Pool entry state is an explicit enum with UNINIT = 0
 *   2. Transition table exposed as `static const` in the .c file
 *   3. Stringifier for every state
 *   4. MAX_POOL_POPULATION is a compile-time constant; never grows
 *   5. A failing benchmark proves reuse is faster than fresh-alloc
 *   6. Weighted points per entry cap memory footprint
 *
 * Integration:
 *   - pe_patch_pool_put() called when a PE image unloads (pe_patch.c).
 *   - pe_patch_pool_try_get() called on cache-miss path before rescan.
 *   - Metrics scraped by coherence daemon's pool_metrics.c writer.
 */

#ifndef PE_PATCH_POOL_H
#define PE_PATCH_POOL_H

#include <stdint.h>
#include <stddef.h>
#include "pe_patch.h"   /* pe_patch_plan_t / pe_patch_entry_t */

#ifdef __cplusplus
extern "C" {
#endif

/* --- Compile-time budget --- */
#define PE_PATCH_POOL_MAX             32u
/* 1 point per 100 bytes of patch data, rounded up.  With 32 entries
 * each up to ~1.6 KB, 512 gives headroom for a plausible worst-case
 * plan mix. */
#define PE_PATCH_POOL_MAX_POINTS      512u

/* Half-life (ms).  After this, state transitions from ACTIVE -> AGED on
 * the next put/get or sweep; reuse is still permitted but the entry is
 * preferred for eviction.
 * Full death (AGED -> EVICTED) at 2x half-life. */
#define PE_PATCH_POOL_HALF_LIFE_MS    5000u
#define PE_PATCH_POOL_FULL_LIFE_MS    15000u

/* --- State enum --- */
typedef enum {
    POOL_ENTRY_UNINIT  = 0,  /* zero-init slot; reusable */
    POOL_ENTRY_ACTIVE  = 1,  /* populated; reuse cheap */
    POOL_ENTRY_AGED    = 2,  /* past half-life; reuse but demote */
    POOL_ENTRY_EVICTED = 3,  /* kicked out; slot reusable */
    POOL_ENTRY_STATE_COUNT = 4
} pool_entry_state_t;

const char *pool_entry_state_str(pool_entry_state_t s);

/* --- Pool entry (POD; array-allocated; NO dynamic alloc) --- */
typedef struct {
    uint8_t            sha_prefix[16];    /* first 16 bytes of SHA-256 */
    uint16_t           section_count;     /* PE section count (key) */
    uint16_t           dxvk_tag;          /* DXVK version tag (key) */
    uint32_t           _pad;
    uint64_t           last_used_ns;      /* CLOCK_MONOTONIC in ns */
    uint64_t           put_ns;            /* insertion time */
    uint32_t           hit_count;
    uint32_t           age_bucket;        /* 0..2 coarse aging */
    uint16_t           points;            /* weighted points cost */
    uint16_t           state;             /* pool_entry_state_t */

    /* Resurrectable payload -- owned by this entry while ACTIVE/AGED. */
    uint32_t           plan_count;
    uint32_t           plan_capacity;
    pe_patch_entry_t  *plan_entries;      /* malloc'd (owned) */
} pe_patch_pool_entry_t;

/* --- Stats snapshot (read by pool_metrics.c) --- */
typedef struct {
    uint32_t population;
    uint32_t max_population;
    uint32_t points;
    uint32_t max_points;
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    uint64_t avg_age_on_hit_ns;
} pe_patch_pool_stats_t;

/* --- Public API --- */
void pe_patch_pool_init(void);
void pe_patch_pool_shutdown(void);

/* Put a cloned plan into the pool.  `plan` is read-only; this function
 * allocates its own copy of the entries.  Safe to call with count==0
 * (becomes a no-op).  Evicts LRU if full. */
int  pe_patch_pool_put(const uint8_t sha_prefix[16],
                       uint16_t section_count,
                       uint16_t dxvk_tag,
                       const pe_patch_plan_t *plan);

/* Try to retrieve a plan.  On hit:
 *   - Copies the plan into `out` (out->entries is malloc'd; caller owns).
 *   - Increments hit_count on the entry, updates last_used_ns.
 *   - If entry was AGED, transitions it to EVICTED after the copy (so
 *     hit_count survives the lookup but the slot frees).
 * On miss: returns -1 and `out` is unchanged.  NEVER allocates on miss. */
int  pe_patch_pool_try_get(const uint8_t sha_prefix[16],
                           uint16_t section_count,
                           uint16_t dxvk_tag,
                           pe_patch_plan_t *out);

/* Copy stats for external observers.  Lock-safe. */
void pe_patch_pool_get_stats(pe_patch_pool_stats_t *out);

/* Force a sweep: demote ACTIVE -> AGED past half-life, evict AGED past
 * full-life.  Called opportunistically on put/get; exposed for tests. */
void pe_patch_pool_sweep(uint64_t now_ns);

/* Test-only: deterministic clock injection.  If non-zero, overrides
 * the real clock_gettime(CLOCK_MONOTONIC) reading.  Set to 0 to return
 * to real clock.  Allows benchmarks to be reproducible. */
void pe_patch_pool_set_clock_override_ns(uint64_t override_ns);

/* Rate-limited snapshot writer.  path defaults to
 * "/var/run/coherence/pe_patch_pool.stats".  Coherence daemon's
 * pool_metrics.c consumes the file.  Safe to call from hot paths;
 * a 1-second floor prevents filesystem thrash. */
void pe_patch_pool_write_stats_file(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* PE_PATCH_POOL_H */
