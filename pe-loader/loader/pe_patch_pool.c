/*
 * pe_patch_pool.c - Bounded absent pool for recently-invalidated PE patch
 * plans.
 *
 * R34 discipline:
 *   - POD entries, preallocated array, pthread_mutex around put/get.
 *   - State enum + transition table + stringifier.
 *   - Static assert on struct size so future field bloat breaks the build.
 *   - Eviction score: (age_ms/1000) + (10 - min(hit_count, 10))
 *       higher = evict first.  Tiebreak by oldest last_used_ns.
 *   - Weighted points: 1 per 100 bytes of patch data (rounded up),
 *     plus 1 floor.  Pool max_points caps memory cost independent of
 *     population.
 *
 * Memory footprint (static upper bound):
 *   sizeof(pe_patch_pool_entry_t) ~ 64 B (POD body)
 *   plus up to PE_PATCH_MAX_ENTRIES * sizeof(pe_patch_entry_t) = 4096*16 = 64 KB
 *   for a pathological single entry.  Budget is enforced in POINTS, not bytes,
 *   but we also bound total plan_capacity per entry via PE_PATCH_MAX_ENTRIES.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "pe_patch_pool.h"

/* --- Entry state transition table -----------------------------------------
 *
 * Rows = current state, columns = event:
 *   EV_PUT     : an entry is inserted / re-inserted at this slot
 *   EV_GET_HIT : try_get matched this slot
 *   EV_AGE     : sweep discovered age > half-life
 *   EV_EXPIRE  : sweep discovered age > full-life
 *   EV_EVICT   : picked by eviction scoring
 *
 * The table is `static const`.  Any state not listed stays put.  UNINIT is
 * the only entry point created by zero-init. */

typedef enum {
    EV_PUT      = 0,
    EV_GET_HIT  = 1,
    EV_AGE      = 2,
    EV_EXPIRE   = 3,
    EV_EVICT    = 4,
    EV_COUNT    = 5
} pool_event_t;

static const pool_entry_state_t g_pool_tx[POOL_ENTRY_STATE_COUNT][EV_COUNT] = {
    /*               EV_PUT              EV_GET_HIT         EV_AGE             EV_EXPIRE          EV_EVICT */
    [POOL_ENTRY_UNINIT]  = { POOL_ENTRY_ACTIVE,  POOL_ENTRY_UNINIT, POOL_ENTRY_UNINIT, POOL_ENTRY_UNINIT, POOL_ENTRY_UNINIT  },
    [POOL_ENTRY_ACTIVE]  = { POOL_ENTRY_ACTIVE,  POOL_ENTRY_ACTIVE, POOL_ENTRY_AGED,   POOL_ENTRY_EVICTED,POOL_ENTRY_EVICTED },
    [POOL_ENTRY_AGED]    = { POOL_ENTRY_ACTIVE,  POOL_ENTRY_EVICTED,POOL_ENTRY_AGED,   POOL_ENTRY_EVICTED,POOL_ENTRY_EVICTED },
    [POOL_ENTRY_EVICTED] = { POOL_ENTRY_ACTIVE,  POOL_ENTRY_EVICTED,POOL_ENTRY_EVICTED,POOL_ENTRY_EVICTED,POOL_ENTRY_EVICTED },
};

const char *pool_entry_state_str(pool_entry_state_t s)
{
    switch (s) {
    case POOL_ENTRY_UNINIT:      return "UNINIT";
    case POOL_ENTRY_ACTIVE:      return "ACTIVE";
    case POOL_ENTRY_AGED:        return "AGED";
    case POOL_ENTRY_EVICTED:     return "EVICTED";
    case POOL_ENTRY_STATE_COUNT: /* fallthrough */
    default:                     return "INVALID";
    }
}

/* Compile-time anchor -- adding a new enum value without updating the
 * stringifier/transition table breaks the build here. */
_Static_assert(POOL_ENTRY_STATE_COUNT == 4,
               "pe_patch_pool: stringifier must cover exactly 4 named states");
_Static_assert(EV_COUNT == 5,
               "pe_patch_pool: transition table must cover exactly 5 events");

/* --- Pool storage (bounded) --- */
typedef struct {
    pthread_mutex_t          lock;
    pe_patch_pool_entry_t    slots[PE_PATCH_POOL_MAX];
    /* stats are u64 so they never wrap during a process lifetime */
    uint64_t                 hits;
    uint64_t                 misses;
    uint64_t                 evictions;
    uint64_t                 total_age_on_hit_ns;  /* running sum */
    uint32_t                 population;
    uint32_t                 points;
    uint64_t                 clock_override_ns;    /* 0 = use real clock */
    int                      inited;
} pe_patch_pool_t;

/* Hard memory cap -- 16 KiB of pool control.  The plan_entries arrays hang
 * off-slab and are counted in the POINTS budget, not here. */
_Static_assert(sizeof(pe_patch_pool_t) <= 16u * 1024u,
               "pe_patch_pool_t exceeds 16KB hard cap");

static pe_patch_pool_t g_pool;

/* --- Clock helper --- */
static uint64_t now_ns_locked(void)
{
    if (g_pool.clock_override_ns != 0)
        return g_pool.clock_override_ns;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Compute weighted points for a plan. */
static uint16_t points_for_plan(const pe_patch_plan_t *plan)
{
    if (!plan || plan->count == 0) return 1;
    /* 1 point per 100 bytes of entry data, rounded up. */
    size_t bytes = (size_t)plan->count * sizeof(pe_patch_entry_t);
    size_t pts = (bytes + 99) / 100;
    if (pts < 1) pts = 1;
    if (pts > UINT16_MAX) pts = UINT16_MAX;
    return (uint16_t)pts;
}

/* Eviction score (higher = evict first).  MUST be deterministic. */
static uint64_t eviction_score(const pe_patch_pool_entry_t *e, uint64_t now)
{
    if (e->state == POOL_ENTRY_UNINIT || e->state == POOL_ENTRY_EVICTED)
        return UINT64_MAX;   /* prefer to reuse these slots */
    uint64_t age_ms = (now > e->last_used_ns) ?
                      (now - e->last_used_ns) / 1000000ULL : 0;
    uint32_t hits_capped = e->hit_count > 10u ? 10u : e->hit_count;
    uint64_t heat_penalty = 10u - hits_capped;
    return (age_ms / 1000u) + heat_penalty;
}

static void free_entry_payload(pe_patch_pool_entry_t *e)
{
    if (e->plan_entries) {
        free(e->plan_entries);
        e->plan_entries = NULL;
    }
    e->plan_count = 0;
    e->plan_capacity = 0;
}

static void clear_entry(pe_patch_pool_entry_t *e)
{
    free_entry_payload(e);
    memset(e, 0, sizeof(*e));
    e->state = POOL_ENTRY_UNINIT;
}

/* Must be called with lock held. */
static void sweep_locked(uint64_t now_ns)
{
    for (uint32_t i = 0; i < PE_PATCH_POOL_MAX; i++) {
        pe_patch_pool_entry_t *e = &g_pool.slots[i];
        if (e->state == POOL_ENTRY_UNINIT ||
            e->state == POOL_ENTRY_EVICTED)
            continue;
        uint64_t age_ns = (now_ns > e->put_ns) ? (now_ns - e->put_ns) : 0;
        uint64_t age_ms = age_ns / 1000000ULL;
        if (age_ms >= PE_PATCH_POOL_FULL_LIFE_MS) {
            /* EXPIRE */
            e->state = g_pool_tx[e->state][EV_EXPIRE];
            if (e->state == POOL_ENTRY_EVICTED) {
                if (g_pool.population > 0) g_pool.population--;
                if (g_pool.points >= e->points) g_pool.points -= e->points;
                free_entry_payload(e);
            }
        } else if (age_ms >= PE_PATCH_POOL_HALF_LIFE_MS &&
                   e->state == POOL_ENTRY_ACTIVE) {
            e->state = g_pool_tx[POOL_ENTRY_ACTIVE][EV_AGE];
            e->age_bucket = 1;
        }
    }
}

/* Pick a victim slot.  Returns index; always succeeds because POOL_MAX > 0. */
static uint32_t pick_victim_locked(uint64_t now_ns)
{
    uint32_t best = 0;
    uint64_t best_score = 0;
    uint64_t best_age = 0;
    /* Prefer UNINIT / EVICTED slots first. */
    for (uint32_t i = 0; i < PE_PATCH_POOL_MAX; i++) {
        pool_entry_state_t s = (pool_entry_state_t)g_pool.slots[i].state;
        if (s == POOL_ENTRY_UNINIT || s == POOL_ENTRY_EVICTED)
            return i;
    }
    /* Scan for highest score. */
    for (uint32_t i = 0; i < PE_PATCH_POOL_MAX; i++) {
        const pe_patch_pool_entry_t *e = &g_pool.slots[i];
        uint64_t sc = eviction_score(e, now_ns);
        uint64_t age = (now_ns > e->last_used_ns) ?
                       (now_ns - e->last_used_ns) : 0;
        if (sc > best_score || (sc == best_score && age > best_age)) {
            best = i;
            best_score = sc;
            best_age = age;
        }
    }
    return best;
}

/* --- Public API --- */

void pe_patch_pool_init(void)
{
    if (g_pool.inited) return;
    pthread_mutex_init(&g_pool.lock, NULL);
    for (uint32_t i = 0; i < PE_PATCH_POOL_MAX; i++)
        clear_entry(&g_pool.slots[i]);
    g_pool.hits = 0;
    g_pool.misses = 0;
    g_pool.evictions = 0;
    g_pool.total_age_on_hit_ns = 0;
    g_pool.population = 0;
    g_pool.points = 0;
    g_pool.clock_override_ns = 0;
    g_pool.inited = 1;
}

void pe_patch_pool_shutdown(void)
{
    if (!g_pool.inited) return;
    pthread_mutex_lock(&g_pool.lock);
    for (uint32_t i = 0; i < PE_PATCH_POOL_MAX; i++)
        clear_entry(&g_pool.slots[i]);
    g_pool.population = 0;
    g_pool.points = 0;
    pthread_mutex_unlock(&g_pool.lock);
    pthread_mutex_destroy(&g_pool.lock);
    g_pool.inited = 0;
}

void pe_patch_pool_set_clock_override_ns(uint64_t override_ns)
{
    if (!g_pool.inited) pe_patch_pool_init();
    pthread_mutex_lock(&g_pool.lock);
    g_pool.clock_override_ns = override_ns;
    pthread_mutex_unlock(&g_pool.lock);
}

void pe_patch_pool_sweep(uint64_t now_ns)
{
    if (!g_pool.inited) pe_patch_pool_init();
    pthread_mutex_lock(&g_pool.lock);
    if (now_ns == 0) now_ns = now_ns_locked();
    sweep_locked(now_ns);
    pthread_mutex_unlock(&g_pool.lock);
}

static int plan_clone_into(pe_patch_pool_entry_t *e, const pe_patch_plan_t *plan)
{
    if (!plan || plan->count == 0) {
        e->plan_count = 0;
        e->plan_capacity = 0;
        e->plan_entries = NULL;
        return 0;
    }
    size_t bytes = (size_t)plan->count * sizeof(pe_patch_entry_t);
    pe_patch_entry_t *buf = (pe_patch_entry_t *)malloc(bytes);
    if (!buf) return -1;
    memcpy(buf, plan->entries, bytes);
    e->plan_entries = buf;
    e->plan_count = plan->count;
    e->plan_capacity = plan->count;
    return 0;
}

int pe_patch_pool_put(const uint8_t sha_prefix[16],
                      uint16_t section_count,
                      uint16_t dxvk_tag,
                      const pe_patch_plan_t *plan)
{
    if (!g_pool.inited) pe_patch_pool_init();
    if (!sha_prefix || !plan) return -1;

    uint16_t want_points = points_for_plan(plan);

    pthread_mutex_lock(&g_pool.lock);
    uint64_t now = now_ns_locked();
    sweep_locked(now);

    /* If a matching entry already exists, refresh it. */
    uint32_t slot = UINT32_MAX;
    for (uint32_t i = 0; i < PE_PATCH_POOL_MAX; i++) {
        pe_patch_pool_entry_t *e = &g_pool.slots[i];
        if ((e->state == POOL_ENTRY_ACTIVE || e->state == POOL_ENTRY_AGED) &&
            e->section_count == section_count &&
            e->dxvk_tag == dxvk_tag &&
            memcmp(e->sha_prefix, sha_prefix, 16) == 0) {
            slot = i;
            break;
        }
    }

    if (slot == UINT32_MAX) {
        /* Evict if we'd exceed either cap. */
        int need_evict = (g_pool.population >= PE_PATCH_POOL_MAX) ||
                         ((uint32_t)g_pool.points + want_points >
                          PE_PATCH_POOL_MAX_POINTS);
        slot = pick_victim_locked(now);
        pe_patch_pool_entry_t *victim = &g_pool.slots[slot];
        if (need_evict &&
            (victim->state == POOL_ENTRY_ACTIVE ||
             victim->state == POOL_ENTRY_AGED)) {
            /* EVICT */
            victim->state = g_pool_tx[victim->state][EV_EVICT];
            if (g_pool.population > 0) g_pool.population--;
            if (g_pool.points >= victim->points)
                g_pool.points -= victim->points;
            g_pool.evictions++;
            free_entry_payload(victim);
        } else if (victim->state == POOL_ENTRY_EVICTED) {
            free_entry_payload(victim);
        }
    }

    pe_patch_pool_entry_t *e = &g_pool.slots[slot];
    /* Drop old payload if overwriting an existing live entry. */
    if (e->state == POOL_ENTRY_ACTIVE || e->state == POOL_ENTRY_AGED) {
        if (g_pool.points >= e->points) g_pool.points -= e->points;
        if (g_pool.population > 0) g_pool.population--;
        free_entry_payload(e);
    }
    memcpy(e->sha_prefix, sha_prefix, 16);
    e->section_count = section_count;
    e->dxvk_tag = dxvk_tag;
    e->put_ns = now;
    e->last_used_ns = now;
    e->hit_count = 0;
    e->age_bucket = 0;
    e->points = want_points;

    if (plan_clone_into(e, plan) != 0) {
        /* Allocation failed: leave slot as EVICTED, do not count. */
        memset(e, 0, sizeof(*e));
        e->state = POOL_ENTRY_EVICTED;
        pthread_mutex_unlock(&g_pool.lock);
        return -1;
    }

    e->state = g_pool_tx[POOL_ENTRY_UNINIT][EV_PUT];
    g_pool.population++;
    g_pool.points += want_points;
    pthread_mutex_unlock(&g_pool.lock);
    return 0;
}

int pe_patch_pool_try_get(const uint8_t sha_prefix[16],
                          uint16_t section_count,
                          uint16_t dxvk_tag,
                          pe_patch_plan_t *out)
{
    if (!g_pool.inited) pe_patch_pool_init();
    if (!sha_prefix || !out) return -1;

    pthread_mutex_lock(&g_pool.lock);
    uint64_t now = now_ns_locked();
    sweep_locked(now);

    for (uint32_t i = 0; i < PE_PATCH_POOL_MAX; i++) {
        pe_patch_pool_entry_t *e = &g_pool.slots[i];
        if (e->state != POOL_ENTRY_ACTIVE && e->state != POOL_ENTRY_AGED)
            continue;
        if (e->section_count != section_count) continue;
        if (e->dxvk_tag != dxvk_tag) continue;
        if (memcmp(e->sha_prefix, sha_prefix, 16) != 0) continue;

        /* HIT.  Clone payload out before state transition. */
        size_t bytes = (size_t)e->plan_count * sizeof(pe_patch_entry_t);
        pe_patch_entry_t *copy = NULL;
        if (bytes > 0) {
            copy = (pe_patch_entry_t *)malloc(bytes);
            if (!copy) {
                g_pool.misses++;
                pthread_mutex_unlock(&g_pool.lock);
                return -1;
            }
            memcpy(copy, e->plan_entries, bytes);
        }
        out->entries = copy;
        out->count = e->plan_count;
        out->capacity = e->plan_count;

        e->hit_count++;
        uint64_t age = (now > e->put_ns) ? (now - e->put_ns) : 0;
        g_pool.total_age_on_hit_ns += age;
        g_pool.hits++;
        e->last_used_ns = now;

        /* Transition.  AGED hits demote to EVICTED on this read; ACTIVE stays. */
        pool_entry_state_t prev = (pool_entry_state_t)e->state;
        pool_entry_state_t next = g_pool_tx[prev][EV_GET_HIT];
        e->state = next;
        if (next == POOL_ENTRY_EVICTED) {
            if (g_pool.population > 0) g_pool.population--;
            if (g_pool.points >= e->points) g_pool.points -= e->points;
            g_pool.evictions++;
            free_entry_payload(e);
        }

        pthread_mutex_unlock(&g_pool.lock);
        return 0;
    }

    g_pool.misses++;
    pthread_mutex_unlock(&g_pool.lock);
    return -1;
}

void pe_patch_pool_get_stats(pe_patch_pool_stats_t *out)
{
    if (!g_pool.inited) pe_patch_pool_init();
    if (!out) return;
    pthread_mutex_lock(&g_pool.lock);
    out->population = g_pool.population;
    out->max_population = PE_PATCH_POOL_MAX;
    out->points = g_pool.points;
    out->max_points = PE_PATCH_POOL_MAX_POINTS;
    out->hits = g_pool.hits;
    out->misses = g_pool.misses;
    out->evictions = g_pool.evictions;
    out->avg_age_on_hit_ns = (g_pool.hits > 0)
        ? (g_pool.total_age_on_hit_ns / g_pool.hits) : 0;
    pthread_mutex_unlock(&g_pool.lock);
}

/* Rate-limited writer for /var/run/coherence/pe_patch_pool.stats.
 * Called opportunistically from pool hot paths; the 1s minimum interval
 * prevents put/get spam from thrashing the filesystem.  The file is
 * atomic-tmp-rename'd so coherence daemon readers never see a torn write. */
static uint64_t g_last_write_ns = 0;

void pe_patch_pool_write_stats_file(const char *path)
{
    if (!g_pool.inited) return;

    pthread_mutex_lock(&g_pool.lock);
    uint64_t now = now_ns_locked();
    if (now - g_last_write_ns < 1000000000ULL) {
        pthread_mutex_unlock(&g_pool.lock);
        return;
    }
    g_last_write_ns = now;
    pe_patch_pool_stats_t s = {
        .population = g_pool.population,
        .max_population = PE_PATCH_POOL_MAX,
        .points = g_pool.points,
        .max_points = PE_PATCH_POOL_MAX_POINTS,
        .hits = g_pool.hits,
        .misses = g_pool.misses,
        .evictions = g_pool.evictions,
        .avg_age_on_hit_ns = (g_pool.hits > 0)
            ? (g_pool.total_age_on_hit_ns / g_pool.hits) : 0,
    };
    pthread_mutex_unlock(&g_pool.lock);

    if (!path) path = "/var/run/coherence/pe_patch_pool.stats";
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    double hit_rate = 0.0;
    uint64_t total = s.hits + s.misses;
    if (total > 0) hit_rate = (double)s.hits / (double)total;
    fprintf(f, "{\"population\":%u,\"max\":%u,\"points\":%u,\"max_points\":%u,"
               "\"hits\":%llu,\"misses\":%llu,\"hit_rate\":%.4f,"
               "\"evictions\":%llu,\"avg_age_on_hit_ns\":%llu}\n",
            s.population, s.max_population, s.points, s.max_points,
            (unsigned long long)s.hits, (unsigned long long)s.misses,
            hit_rate,
            (unsigned long long)s.evictions,
            (unsigned long long)s.avg_age_on_hit_ns);
    fclose(f);
    if (rename(tmp, path) != 0) {
        /* Best-effort: leave tmp behind, coherence daemon won't read it. */
        (void)unlink(tmp);
    }
}
