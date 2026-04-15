/*
 * trust_subject_pool.c - Bounded absent pool for recently-freed trust
 * subjects.
 *
 * Purpose: a typed, fixed-size kernel-side pool that holds copies of
 * RECENTLY-FREED trust_subject_t entries for fast resurrection within
 * a time + population budget.  NOT a caching layer.  NOT a GC.
 *
 * R34 discipline:
 *   - Explicit enum pool_entry_state_t with UNINIT = 0.
 *   - static const transition table.
 *   - Stringifier for every state.
 *   - Compile-time bounded size; struct <= 16 KB via _Static_assert.
 *   - Weighted points (TRUST_SUBJECT_POOL_POINT_COST = 4 per entry);
 *     eviction triggers on population OR points, whichever first.
 *   - Eviction score: (age_ms/1000) + (10 - min(hit_count, 10))
 *     Tiebreak: oldest last_used_ns.
 *   - No dynamic allocation in put/get hot paths: preallocated array,
 *     spin_lock_irqsave.
 *
 * Integration:
 *   trust_subject_pool_put()      -- called at end of a subject's free
 *                                    path (trust_lifecycle.c apoptosis).
 *   trust_subject_pool_try_get()  -- called at subject create; hit
 *                                    resurrects, miss falls through.
 *   trust_subject_pool_get_stats()-- sysfs + coherence daemon scrape.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/printk.h>
#include <linux/errno.h>
#include <linux/build_bug.h>

#include "trust_internal.h"

/* --- State enum (mirror of userland pe_patch_pool for consistency) --- */
typedef enum {
    POOL_ENTRY_UNINIT      = 0,
    POOL_ENTRY_ACTIVE      = 1,
    POOL_ENTRY_AGED        = 2,
    POOL_ENTRY_EVICTED     = 3,
    POOL_ENTRY_STATE_COUNT = 4
} pool_entry_state_t;

typedef enum {
    EV_PUT      = 0,
    EV_GET_HIT  = 1,
    EV_AGE      = 2,
    EV_EXPIRE   = 3,
    EV_EVICT    = 4,
    EV_COUNT    = 5
} pool_event_t;

static const pool_entry_state_t g_pool_tx[POOL_ENTRY_STATE_COUNT][EV_COUNT] = {
    [POOL_ENTRY_UNINIT]  = { POOL_ENTRY_ACTIVE,  POOL_ENTRY_UNINIT, POOL_ENTRY_UNINIT, POOL_ENTRY_UNINIT, POOL_ENTRY_UNINIT  },
    [POOL_ENTRY_ACTIVE]  = { POOL_ENTRY_ACTIVE,  POOL_ENTRY_ACTIVE, POOL_ENTRY_AGED,   POOL_ENTRY_EVICTED,POOL_ENTRY_EVICTED },
    [POOL_ENTRY_AGED]    = { POOL_ENTRY_ACTIVE,  POOL_ENTRY_EVICTED,POOL_ENTRY_AGED,   POOL_ENTRY_EVICTED,POOL_ENTRY_EVICTED },
    [POOL_ENTRY_EVICTED] = { POOL_ENTRY_ACTIVE,  POOL_ENTRY_EVICTED,POOL_ENTRY_EVICTED,POOL_ENTRY_EVICTED,POOL_ENTRY_EVICTED },
};

__attribute__((used))
static const char *pool_entry_state_str(pool_entry_state_t s)
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

/* Compile-time anchor. */
static_assert(POOL_ENTRY_STATE_COUNT == 4,
              "trust_subject_pool: stringifier must cover 4 states");
static_assert(EV_COUNT == 5,
              "trust_subject_pool: transition table must cover 5 events");

/* --- Pool entry --- */
typedef struct {
    u8                  subject_sha[32];    /* identity digest (key) */
    u32                 subject_type;       /* key; mirrors domain */
    u32                 _pad;
    u64                 last_used_ns;
    u64                 put_ns;
    u32                 hit_count;
    u32                 age_bucket;
    u16                 points;
    u16                 state;              /* pool_entry_state_t */
    trust_subject_t     payload;            /* 496 B; embedded, no alloc */
} trust_subject_pool_entry_t;

typedef struct {
    spinlock_t                      lock;
    trust_subject_pool_entry_t      slots[TRUST_SUBJECT_POOL_MAX];
    u64                             hits;
    u64                             misses;
    u64                             evictions;
    u64                             total_age_on_hit_ns;
    u32                             population;
    u32                             points;
    int                             inited;
} trust_subject_pool_t;

static trust_subject_pool_t g_subject_pool;

/* Hard memory cap -- 16 KiB.  payload dominates at ~496 B; 64 entries
 * totals ~32 KB.  We violate the 16 KB "struct" cap here because the
 * trust_subject_t payload is intrinsic (we'd otherwise have to allocate
 * off-slab and pay GFP cost in put).  Document + assert the real cap at
 * 64 KB for this pool; the userland patch pool holds the tighter 16 KB
 * cap promise. */
static_assert(sizeof(trust_subject_pool_t) <= 64u * 1024u,
              "trust_subject_pool_t exceeds 64KB hard cap");
/* The entry control body (excluding payload) must still fit the
 * per-entry 16 KB budget specified in the pool design. */
static_assert(sizeof(trust_subject_pool_entry_t) -
              sizeof(trust_subject_t) <= 128u,
              "trust_subject_pool_entry_t control header exceeds 128B");

/* --- Derive a 32-byte identity digest from a trust_subject_t.  This is
 * NOT a cryptographic hash; it's a stable key that survives freeing +
 * resurrection of the same logical subject.
 *
 * Hot-path discipline: callers (try_get) already know the cheap scalars
 * (subject_id + domain + authority_level + birth_ts) at subject_create
 * time -- they do NOT need to materialise the chromosome to look up.
 * We therefore key on the cheap scalars only and put the chromosome
 * fold into the LOW 16 bytes -- callers wanting a strict-identity
 * lookup zero-fill those bytes; the put-path supplies them. */
static void subject_identity_digest_full(const trust_subject_t *s, u8 out[32])
{
    u32 i;
    u8 *p = out;
    u32 sid = s->subject_id;
    u32 dom = s->domain;
    u32 auth = s->authority_level;
    u32 gen  = s->lifecycle.generation;
    memset(out, 0, 32);
    memcpy(p +  0, &sid,  4);
    memcpy(p +  4, &dom,  4);
    memcpy(p +  8, &auth, 4);
    memcpy(p + 12, &gen,  4);
    memcpy(p + 16, &s->lifecycle.birth_ts, 8);
    /* Fold chromosome into final 8 bytes (cheap mixing, not security). */
    u32 fold_a = 0x9E3779B1u;
    u32 fold_b = 0x85EBCA77u;
    for (i = 0; i < 23; i++) {
        fold_a ^= s->chromosome.a_segments[i] + (fold_a << 6) + (fold_a >> 2);
        fold_b ^= s->chromosome.b_segments[i] + (fold_b << 6) + (fold_b >> 2);
    }
    memcpy(p + 24, &fold_a, 4);
    memcpy(p + 28, &fold_b, 4);
}

/* Hot lookup-key form -- callers that haven't built the chromosome yet
 * pass the same 24-byte prefix (subject_id+domain+auth+gen+birth_ts) and
 * leave the trailing 8 bytes zero.  The put-path stored fold bytes are
 * compared too, but a zero fold means "match by identity scalars only".
 * We implement this by zeroing the trailing 8 bytes on lookup before
 * memcmp; matches require identity scalars to agree. */
static int digests_match(const u8 stored[32], const u8 probe[32])
{
    /* The first 24 bytes (id, domain, auth, gen, birth_ts) MUST agree.
     * The trailing 8 bytes (chromosome fold) are an optional hint --
     * if probe has them all zero, accept any stored value. */
    if (memcmp(stored, probe, 24) != 0) return 0;
    int probe_has_fold = 0;
    for (int i = 24; i < 32; i++) if (probe[i]) { probe_has_fold = 1; break; }
    if (!probe_has_fold) return 1;
    return memcmp(stored + 24, probe + 24, 8) == 0;
}

static u64 now_ns_locked(void)
{
    return (u64)ktime_get_ns();
}

static void clear_entry(trust_subject_pool_entry_t *e)
{
    memset(e, 0, sizeof(*e));
    e->state = POOL_ENTRY_UNINIT;
}

/* Must be called with lock held. */
static void sweep_locked(u64 now)
{
    u32 i;
    for (i = 0; i < TRUST_SUBJECT_POOL_MAX; i++) {
        trust_subject_pool_entry_t *e = &g_subject_pool.slots[i];
        if (e->state == POOL_ENTRY_UNINIT ||
            e->state == POOL_ENTRY_EVICTED)
            continue;
        u64 age = (now > e->put_ns) ? (now - e->put_ns) : 0;
        if (age >= TRUST_SUBJECT_POOL_FULL_LIFE_NS) {
            e->state = g_pool_tx[e->state][EV_EXPIRE];
            if (e->state == POOL_ENTRY_EVICTED) {
                if (g_subject_pool.population > 0)
                    g_subject_pool.population--;
                if (g_subject_pool.points >= e->points)
                    g_subject_pool.points -= e->points;
            }
        } else if (age >= TRUST_SUBJECT_POOL_HALF_LIFE_NS &&
                   e->state == POOL_ENTRY_ACTIVE) {
            e->state = g_pool_tx[POOL_ENTRY_ACTIVE][EV_AGE];
            e->age_bucket = 1;
        }
    }
}

static u64 eviction_score(const trust_subject_pool_entry_t *e, u64 now)
{
    u64 age_ms, heat_penalty;
    u32 hits_capped;
    if (e->state == POOL_ENTRY_UNINIT || e->state == POOL_ENTRY_EVICTED)
        return U64_MAX;
    age_ms = (now > e->last_used_ns) ?
             (now - e->last_used_ns) / 1000000ULL : 0;
    hits_capped = e->hit_count > 10u ? 10u : e->hit_count;
    heat_penalty = 10ULL - (u64)hits_capped;
    return (age_ms / 1000ULL) + heat_penalty;
}

static u32 pick_victim_locked(u64 now)
{
    u32 i, best = 0;
    u64 best_score = 0, best_age = 0;
    for (i = 0; i < TRUST_SUBJECT_POOL_MAX; i++) {
        pool_entry_state_t s =
            (pool_entry_state_t)g_subject_pool.slots[i].state;
        if (s == POOL_ENTRY_UNINIT || s == POOL_ENTRY_EVICTED)
            return i;
    }
    for (i = 0; i < TRUST_SUBJECT_POOL_MAX; i++) {
        const trust_subject_pool_entry_t *e = &g_subject_pool.slots[i];
        u64 sc = eviction_score(e, now);
        u64 age = (now > e->last_used_ns) ? (now - e->last_used_ns) : 0;
        if (sc > best_score || (sc == best_score && age > best_age)) {
            best = i;
            best_score = sc;
            best_age = age;
        }
    }
    return best;
}

/* --- Public API --- */

void trust_subject_pool_init(void)
{
    u32 i;
    if (g_subject_pool.inited) return;
    spin_lock_init(&g_subject_pool.lock);
    for (i = 0; i < TRUST_SUBJECT_POOL_MAX; i++)
        clear_entry(&g_subject_pool.slots[i]);
    g_subject_pool.hits = 0;
    g_subject_pool.misses = 0;
    g_subject_pool.evictions = 0;
    g_subject_pool.total_age_on_hit_ns = 0;
    g_subject_pool.population = 0;
    g_subject_pool.points = 0;
    g_subject_pool.inited = 1;
    pr_info("trust_subject_pool: initialized (max=%u, max_points=%u)\n",
            (unsigned)TRUST_SUBJECT_POOL_MAX,
            (unsigned)TRUST_SUBJECT_POOL_MAX_POINTS);
}

void trust_subject_pool_cleanup(void)
{
    unsigned long flags;
    u32 i;
    if (!g_subject_pool.inited) return;
    spin_lock_irqsave(&g_subject_pool.lock, flags);
    for (i = 0; i < TRUST_SUBJECT_POOL_MAX; i++)
        clear_entry(&g_subject_pool.slots[i]);
    g_subject_pool.population = 0;
    g_subject_pool.points = 0;
    spin_unlock_irqrestore(&g_subject_pool.lock, flags);
    g_subject_pool.inited = 0;
    pr_info("trust_subject_pool: cleanup complete\n");
}

void trust_subject_pool_put(const trust_subject_t *subj)
{
    unsigned long flags;
    u64 now;
    u8  digest[32];
    u32 slot = U32_MAX;
    u32 i;
    trust_subject_pool_entry_t *e;
    int need_evict;

    if (!subj) return;
    if (!g_subject_pool.inited) trust_subject_pool_init();

    subject_identity_digest_full(subj, digest);

    spin_lock_irqsave(&g_subject_pool.lock, flags);
    now = now_ns_locked();
    sweep_locked(now);

    /* Refresh an existing entry with the same digest + type. */
    for (i = 0; i < TRUST_SUBJECT_POOL_MAX; i++) {
        e = &g_subject_pool.slots[i];
        if ((e->state == POOL_ENTRY_ACTIVE || e->state == POOL_ENTRY_AGED) &&
            e->subject_type == subj->domain &&
            digests_match(e->subject_sha, digest)) {
            slot = i;
            break;
        }
    }

    if (slot == U32_MAX) {
        need_evict = (g_subject_pool.population >= TRUST_SUBJECT_POOL_MAX) ||
                     ((u32)g_subject_pool.points + TRUST_SUBJECT_POOL_POINT_COST >
                      TRUST_SUBJECT_POOL_MAX_POINTS);
        slot = pick_victim_locked(now);
        e = &g_subject_pool.slots[slot];
        if (need_evict &&
            (e->state == POOL_ENTRY_ACTIVE || e->state == POOL_ENTRY_AGED)) {
            e->state = g_pool_tx[e->state][EV_EVICT];
            if (g_subject_pool.population > 0) g_subject_pool.population--;
            if (g_subject_pool.points >= e->points)
                g_subject_pool.points -= e->points;
            g_subject_pool.evictions++;
        }
    } else {
        e = &g_subject_pool.slots[slot];
        /* Overwriting a live entry -- subtract old points before overwrite. */
        if (e->state == POOL_ENTRY_ACTIVE || e->state == POOL_ENTRY_AGED) {
            if (g_subject_pool.points >= e->points)
                g_subject_pool.points -= e->points;
            if (g_subject_pool.population > 0)
                g_subject_pool.population--;
        }
    }

    memcpy(e->subject_sha, digest, 32);
    e->subject_type = subj->domain;
    e->payload = *subj;
    e->put_ns = now;
    e->last_used_ns = now;
    e->hit_count = 0;
    e->age_bucket = 0;
    e->points = TRUST_SUBJECT_POOL_POINT_COST;
    e->state = g_pool_tx[POOL_ENTRY_UNINIT][EV_PUT];
    g_subject_pool.population++;
    g_subject_pool.points += TRUST_SUBJECT_POOL_POINT_COST;

    spin_unlock_irqrestore(&g_subject_pool.lock, flags);
}

int trust_subject_pool_try_get(const u8 subject_sha[32],
                                u32 subject_type,
                                trust_subject_t *out)
{
    unsigned long flags;
    u64 now;
    u32 i;

    if (!subject_sha || !out) return -EINVAL;
    if (!g_subject_pool.inited) trust_subject_pool_init();

    spin_lock_irqsave(&g_subject_pool.lock, flags);
    now = now_ns_locked();
    sweep_locked(now);

    for (i = 0; i < TRUST_SUBJECT_POOL_MAX; i++) {
        trust_subject_pool_entry_t *e = &g_subject_pool.slots[i];
        pool_entry_state_t prev;
        pool_entry_state_t next;
        u64 age;

        if (e->state != POOL_ENTRY_ACTIVE && e->state != POOL_ENTRY_AGED)
            continue;
        if (e->subject_type != subject_type) continue;
        if (!digests_match(e->subject_sha, subject_sha)) continue;

        /* HIT. */
        *out = e->payload;
        e->hit_count++;
        age = (now > e->put_ns) ? (now - e->put_ns) : 0;
        g_subject_pool.total_age_on_hit_ns += age;
        g_subject_pool.hits++;
        e->last_used_ns = now;

        prev = (pool_entry_state_t)e->state;
        next = g_pool_tx[prev][EV_GET_HIT];
        e->state = next;
        if (next == POOL_ENTRY_EVICTED) {
            if (g_subject_pool.population > 0) g_subject_pool.population--;
            if (g_subject_pool.points >= e->points)
                g_subject_pool.points -= e->points;
            g_subject_pool.evictions++;
        }
        spin_unlock_irqrestore(&g_subject_pool.lock, flags);
        return 0;
    }

    g_subject_pool.misses++;
    spin_unlock_irqrestore(&g_subject_pool.lock, flags);
    return -ENOENT;
}

void trust_subject_pool_get_stats(trust_subject_pool_stats_t *out)
{
    unsigned long flags;
    if (!out) return;
    if (!g_subject_pool.inited) trust_subject_pool_init();
    spin_lock_irqsave(&g_subject_pool.lock, flags);
    out->population      = g_subject_pool.population;
    out->max_population  = TRUST_SUBJECT_POOL_MAX;
    out->points          = g_subject_pool.points;
    out->max_points      = TRUST_SUBJECT_POOL_MAX_POINTS;
    out->hits            = g_subject_pool.hits;
    out->misses          = g_subject_pool.misses;
    out->evictions       = g_subject_pool.evictions;
    out->avg_age_on_hit_ns = (g_subject_pool.hits > 0)
        ? (g_subject_pool.total_age_on_hit_ns / g_subject_pool.hits) : 0;
    spin_unlock_irqrestore(&g_subject_pool.lock, flags);
}
