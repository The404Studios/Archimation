/*
 * bench_patch_pool.c - Reproducible microbenchmark for pe_patch_pool.
 *
 * Simulates 5000 PE load/unload cycles over 10 unique PE sha256 prefixes.
 * Measures two paths:
 *   A) "fresh" -- every cycle pays a simulated rescan cost (memcpy of the
 *       would-be plan, same size as the pool payload).  Models what
 *       pe_patch_apply's scan_image() path costs when there is no cache.
 *   B) "pool"  -- first occurrence of a sha misses and pays the rescan,
 *       subsequent occurrences hit pe_patch_pool_try_get and skip rescan.
 *
 * R34: no concept survives without a benchmark.  This file MUST fail
 * the build if pool-hit is not at least 3x faster than fresh-rescan
 * across the trace.  Seeded PRNG makes the trace deterministic.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "pe_patch.h"
#include "pe_patch_pool.h"

#define N_CYCLES       5000u
#define N_UNIQUE_SHAS  10u
/* Plausible plan size: 96 CRT imports.  sizeof(pe_patch_entry_t) = 16. */
#define PLAN_ENTRIES   96u

/* xorshift64 -- reproducible. */
static uint64_t g_prng;
static uint64_t xor64(void)
{
    uint64_t x = g_prng;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    g_prng = x;
    return x;
}

static uint64_t clk_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Simulate the cost of scan_image() + plan build: deterministic work
 * roughly proportional to PE_PATCH_MAX entries.  We do real memory work
 * (allocation + touches) so the compiler cannot optimize it away. */
static int simulate_fresh_scan(pe_patch_plan_t *out)
{
    out->count = PLAN_ENTRIES;
    out->capacity = PLAN_ENTRIES;
    out->entries = (pe_patch_entry_t *)malloc(
        sizeof(pe_patch_entry_t) * PLAN_ENTRIES);
    if (!out->entries) return -1;
    /* Mimic the name-lookup + IAT walk: a small work loop per entry. */
    for (uint32_t i = 0; i < PLAN_ENTRIES; i++) {
        out->entries[i].iat_rva = 0x1000ULL + (uint64_t)i * 8ULL;
        out->entries[i].replacement_idx = i & 0x7f;
        out->entries[i].flags = 0;
        /* Volatile-ish compute to simulate name hashing. */
        volatile uint32_t v = i;
        for (int k = 0; k < 32; k++) v = (v * 2654435761u) ^ (v >> 16);
        (void)v;
    }
    return 0;
}

static void free_plan(pe_patch_plan_t *p)
{
    if (p && p->entries) {
        free(p->entries);
        p->entries = NULL;
        p->count = 0;
        p->capacity = 0;
    }
}

typedef struct {
    uint64_t ns_total;
    uint64_t hits;
    uint64_t misses;
} bench_result_t;

static void gen_sha(uint8_t out[16], uint32_t id)
{
    /* Deterministic hash-ish bytes. */
    memset(out, 0, 16);
    for (int i = 0; i < 16; i++) out[i] = (uint8_t)((id * 0x9E3779B9u) >> (i & 7));
    out[0] = (uint8_t)id;
}

static bench_result_t run_fresh(void)
{
    bench_result_t r = {0};
    uint64_t t0 = clk_ns();
    for (uint32_t i = 0; i < N_CYCLES; i++) {
        uint32_t which = (uint32_t)(xor64() % N_UNIQUE_SHAS);
        (void)which;   /* fresh path doesn't care which */
        pe_patch_plan_t plan = {0};
        simulate_fresh_scan(&plan);
        /* simulate apply doing a memcpy-sized pass over the plan data */
        volatile uint64_t accum = 0;
        for (uint32_t j = 0; j < plan.count; j++) accum += plan.entries[j].iat_rva;
        (void)accum;
        free_plan(&plan);
        r.misses++;
    }
    r.ns_total = clk_ns() - t0;
    return r;
}

static bench_result_t run_pool(void)
{
    bench_result_t r = {0};
    pe_patch_pool_init();
    uint64_t t0 = clk_ns();
    for (uint32_t i = 0; i < N_CYCLES; i++) {
        uint32_t which = (uint32_t)(xor64() % N_UNIQUE_SHAS);
        uint8_t sha[16];
        gen_sha(sha, which);

        pe_patch_plan_t plan = {0};
        if (pe_patch_pool_try_get(sha, 12, 0x200, &plan) == 0) {
            /* Hit -- apply plan. */
            volatile uint64_t accum = 0;
            for (uint32_t j = 0; j < plan.count; j++) accum += plan.entries[j].iat_rva;
            (void)accum;
            free_plan(&plan);
            r.hits++;
        } else {
            simulate_fresh_scan(&plan);
            volatile uint64_t accum = 0;
            for (uint32_t j = 0; j < plan.count; j++) accum += plan.entries[j].iat_rva;
            (void)accum;
            pe_patch_pool_put(sha, 12, 0x200, &plan);
            free_plan(&plan);
            r.misses++;
        }
    }
    r.ns_total = clk_ns() - t0;
    pe_patch_pool_shutdown();
    return r;
}

int main(void)
{
    g_prng = 0xDEADBEEFCAFEBABEULL;
    bench_result_t fresh = run_fresh();

    g_prng = 0xDEADBEEFCAFEBABEULL;  /* reset for identical trace */
    bench_result_t pool = run_pool();

    double fresh_ns_per = (double)fresh.ns_total / (double)N_CYCLES;
    double pool_ns_per  = (double)pool.ns_total / (double)N_CYCLES;

    printf("pe_patch_pool benchmark -- %u cycles over %u unique SHAs\n",
           N_CYCLES, N_UNIQUE_SHAS);
    printf("  fresh-rescan : %12llu ns total  |  %9.1f ns/op  |  misses=%llu\n",
           (unsigned long long)fresh.ns_total, fresh_ns_per,
           (unsigned long long)fresh.misses);
    printf("  pool-hit     : %12llu ns total  |  %9.1f ns/op  |  hits=%llu misses=%llu\n",
           (unsigned long long)pool.ns_total, pool_ns_per,
           (unsigned long long)pool.hits, (unsigned long long)pool.misses);

    /* R34 gate: pool path must be at least 3x faster. */
    double speedup = fresh_ns_per / (pool_ns_per > 0 ? pool_ns_per : 1.0);
    printf("  speedup      : %.2fx (gate: 3.0x)\n", speedup);
    if (speedup < 3.0) {
        fprintf(stderr, "FAIL: pe_patch_pool did not achieve 3x speedup "
                "(actual %.2fx). Concept does not survive.\n", speedup);
        return 1;
    }
    /* Sanity: hit rate must be high because trace has only 10 unique SHAs
     * cycling 5000 times. */
    if (pool.hits < (N_CYCLES - 2u * N_UNIQUE_SHAS)) {
        fprintf(stderr, "FAIL: pool hit count %llu below expected "
                "(at least %u). Pool may be evicting too aggressively.\n",
                (unsigned long long)pool.hits,
                (unsigned)(N_CYCLES - 2u * N_UNIQUE_SHAS));
        return 1;
    }
    printf("PASS\n");
    return 0;
}
