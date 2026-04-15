/*
 * pe_patch.c - PE load-time CRT patching orchestrator
 *
 * Responsibilities:
 *   1. Probe the trust gate: pe_patch_enabled(sha256) tells us whether
 *      this binary's policy allows body substitution.  Code-integrity
 *      sensitive apps can opt out.
 *   2. Try loading a cached patch plan (pe_patch_cache_load).  Cache
 *      hits skip the scan entirely -- O(count) writes only.
 *   3. On miss, walk the import directory, identify CRT functions by
 *      name (pe_patch_lookup_name), record the IAT slot RVAs, and
 *      rewrite them with addresses from the replacement table.
 *   4. Persist the plan to disk (pe_patch_cache_save).
 *   5. Emit PE_EVT_LOAD-style audit event with patch count.
 *
 * Memory safety: every ILT/IAT access is bounds-checked against the
 * mapped image size.  A malformed import directory never causes an
 * out-of-range write.
 *
 * The IAT page may have been mprotect()ed read-only by
 * pe_restore_section_protections.  We do NOT call that until after
 * pe_patch_apply runs -- see main.c ordering -- so the IAT is still
 * writable at patch time.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/mman.h>

#include "pe_patch.h"
#include "pe_patch_pool.h"
#include "pe/pe_patch_abi.h"
#include "pe/pe_header.h"
#include "pe/pe_import.h"
#include "pe/pe_types.h"

/* Event bus for audit trail. */
#include "eventbus/pe_event.h"

#define LOG_PREFIX "[pe_patch] "

/* Initialisation flag. */
static int g_patch_init_done = 0;

/* Verbose flag -- inherited from PE_DIAG env so debug builds see the
 * per-patch log lines without adding a new knob. */
static int g_verbose = 0;

/* Audit payload mirrors pe_evt_dll_load_t roughly but carries patch
 * count; reusing unimplemented event type (0x10) would collide, so we
 * piggy-back on the existing PE_EVT_DLL_LOAD with a synthetic dll_name
 * ("__pe_patch__") to avoid expanding the event enum here.  The cortex
 * side already accepts arbitrary dll_name strings. */
static void emit_patch_event(uint32_t applied, uint32_t scanned)
{
    pe_evt_dll_load_t evt;
    memset(&evt, 0, sizeof(evt));
    strncpy(evt.dll_name, "__pe_patch__", sizeof(evt.dll_name) - 1);
    evt.resolved   = applied;
    evt.unresolved = (scanned > applied) ? (scanned - applied) : 0;
    pe_event_emit(PE_EVT_DLL_LOAD, &evt, sizeof(evt));
}

/* Bounded RVA -> pointer check used by the scan loop.  We duplicate
 * the PE_RVA_VALID logic from pe_import.c here so this TU doesn't
 * depend on its private helpers. */
static inline int rva_valid(uint64_t rva, uint64_t len, uint64_t image_size)
{
    return (rva + len) <= image_size;
}

/* Decode first 16 bytes of a 64-char hex sha256 into a byte prefix.
 * Returns 0 on success, -1 on bad input.  Used to key the pe_patch_pool
 * without pulling in a full hex decoder. */
static int sha256_hex_prefix16(const char *hex, uint8_t out[16])
{
    if (!hex) return -1;
    for (int i = 0; i < 16; i++) {
        char h = hex[2 * i], l = hex[2 * i + 1];
        if (h == 0 || l == 0) return -1;
        int hv = (h >= '0' && h <= '9') ? h - '0'
               : (h >= 'a' && h <= 'f') ? h - 'a' + 10
               : (h >= 'A' && h <= 'F') ? h - 'A' + 10 : -1;
        int lv = (l >= '0' && l <= '9') ? l - '0'
               : (l >= 'a' && l <= 'f') ? l - 'a' + 10
               : (l >= 'A' && l <= 'F') ? l - 'A' + 10 : -1;
        if (hv < 0 || lv < 0) return -1;
        out[i] = (uint8_t)((hv << 4) | lv);
    }
    return 0;
}

int pe_patch_init(void)
{
    if (g_patch_init_done) return 0;
    const char *env = getenv("PE_DIAG");
    if (env && *env == '1') g_verbose = 1;
    /* Cache dir is created lazily by the cache TU on first save/load. */
    pe_patch_pool_init();
    g_patch_init_done = 1;
    return 0;
}

void pe_patch_shutdown(void)
{
    /* Drain the absent pool so leaked entries don't count against
     * a future embedder's teardown accounting. */
    pe_patch_pool_shutdown();
    g_patch_init_done = 0;
}

int pe_patch_enabled(const char *image_sha256_hex)
{
    /* Default policy: patching enabled unless:
     *   - Environment variable PE_PATCH_DISABLE=1
     *   - (Future) trust_gate policy lookup by sha256
     *
     * The sha256 argument is threaded through for future trust rules;
     * unused today.  We explicitly silence the unused-parameter warning. */
    (void)image_sha256_hex;
    const char *env = getenv("PE_PATCH_DISABLE");
    if (env && *env == '1') return 0;
    return 1;
}

/* Apply a plan to the mapped image in memory. */
static int apply_plan(pe_image_t *image, const pe_patch_plan_t *plan)
{
    if (!image || !plan || plan->count == 0) return 0;
    uint64_t mapped_sz = image->mapped_size;
    uint32_t applied = 0;

    for (uint32_t i = 0; i < plan->count; i++) {
        const pe_patch_entry_t *e = &plan->entries[i];
        if (!rva_valid(e->iat_rva, sizeof(uint64_t), mapped_sz))
            continue;
        void *repl = pe_patch_replacement_by_idx(e->replacement_idx);
        if (!repl) continue;

        /* The IAT page should already be writable (pe_restore_section_protections
         * runs AFTER us), but guard against early-hardened loaders by
         * unprotecting just in case.  1 page covers any plausible IAT
         * block boundary within a single call. */
        uint8_t *p = (uint8_t *)image->mapped_base + e->iat_rva;
        /* Align to page boundary and set RW; harmless if already writable. */
        uintptr_t page = (uintptr_t)p & ~(uintptr_t)0xFFFu;
        if (mprotect((void *)page, 0x1000,
                     PROT_READ | PROT_WRITE) != 0) {
            /* If the IAT page is not writable and mprotect failed, skip
             * this slot; do NOT crash.  We log once then move on. */
            if (g_verbose)
                fprintf(stderr, LOG_PREFIX "mprotect RW failed @ RVA 0x%lx: %s\n",
                        (unsigned long)e->iat_rva, strerror(errno));
            continue;
        }
        *(void **)p = repl;
        applied++;
    }
    return (int)applied;
}

/* Scan the import directory and build a plan.  Returns 0 on ok (plan
 * populated; may have count=0), -1 on parse error. */
static int scan_image(pe_image_t *image, pe_patch_plan_t *plan)
{
    memset(plan, 0, sizeof(*plan));

    if (image->number_of_rva_and_sizes <= PE_DIR_IMPORT)
        return 0;
    pe_data_directory_t *idir = &image->data_directory[PE_DIR_IMPORT];
    if (idir->virtual_address == 0 || idir->size == 0)
        return 0;

    /* Grow in 64-entry chunks. */
    plan->capacity = 64;
    plan->entries  = (pe_patch_entry_t *)calloc(plan->capacity,
                                                sizeof(pe_patch_entry_t));
    if (!plan->entries) return -1;

    const uint8_t *base = image->mapped_base;
    uint64_t mapped_sz  = image->mapped_size;

    if (!rva_valid(idir->virtual_address, idir->size, mapped_sz)) {
        pe_patch_plan_free(plan); return -1;
    }

    const pe_import_descriptor_t *desc =
        (const pe_import_descriptor_t *)(base + idir->virtual_address);
    const uint8_t *desc_end = base + idir->virtual_address + idir->size;

    while ((const uint8_t *)(desc + 1) <= desc_end && desc->name_rva) {
        uint32_t ilt_rva = desc->import_lookup_table_rva;
        uint32_t iat_rva = desc->import_address_table_rva;
        if (ilt_rva == 0) ilt_rva = iat_rva;

        if (!iat_rva || !ilt_rva) { desc++; continue; }

        /* 64-bit path only -- PE32+ is the only subset we patch. */
        if (!image->is_pe32plus) { desc++; continue; }

        if (!rva_valid(ilt_rva, sizeof(uint64_t), mapped_sz) ||
            !rva_valid(iat_rva, sizeof(uint64_t), mapped_sz)) {
            desc++; continue;
        }

        const uint64_t *ilt = (const uint64_t *)(base + ilt_rva);
        /* iat consumed via RVA arithmetic; no cached pointer needed. */

        uint64_t ilt_max_bytes = mapped_sz - ilt_rva;
        uint64_t iat_max_bytes = mapped_sz - iat_rva;
        uint64_t cap_bytes = (ilt_max_bytes < iat_max_bytes)
                             ? ilt_max_bytes : iat_max_bytes;
        uint64_t cap = cap_bytes / sizeof(uint64_t);
        if (cap > 65536) cap = 65536;

        for (uint64_t i = 0; i < cap && ilt[i] != 0; i++) {
            if (ilt[i] & PE_IMPORT_ORDINAL_FLAG64)
                continue; /* Ordinal imports have no name to match. */
            uint32_t hint_rva = (uint32_t)(ilt[i] & 0x7FFFFFFFu);
            if (!rva_valid(hint_rva, sizeof(pe_import_by_name_t), mapped_sz))
                continue;
            /* pe_import_by_name_t layout: u16 hint followed by NUL-terminated
             * name.  Validate at least one byte reachable and scan for a
             * NUL within a reasonable window. */
            uint64_t name_off = (uint64_t)hint_rva + sizeof(uint16_t);
            if (name_off >= mapped_sz) continue;
            const char *name = (const char *)(base + name_off);
            size_t max_scan = (size_t)(mapped_sz - name_off);
            if (max_scan > 128) max_scan = 128;
            size_t name_len = 0;
            while (name_len < max_scan && name[name_len]) name_len++;
            if (name_len == 0 || name_len >= max_scan) continue;

            int idx = pe_patch_lookup_name(name);
            if (idx < 0) continue;

            /* Grow if needed. */
            if (plan->count >= plan->capacity) {
                if (plan->capacity >= PE_PATCH_MAX_ENTRIES) break;
                uint32_t ncap = plan->capacity * 2u;
                if (ncap > PE_PATCH_MAX_ENTRIES) ncap = PE_PATCH_MAX_ENTRIES;
                pe_patch_entry_t *ne = (pe_patch_entry_t *)realloc(
                    plan->entries,
                    sizeof(pe_patch_entry_t) * ncap);
                if (!ne) { /* keep what we have */ break; }
                plan->entries  = ne;
                plan->capacity = ncap;
            }

            plan->entries[plan->count].iat_rva =
                (uint64_t)iat_rva + (uint64_t)i * sizeof(uint64_t);
            plan->entries[plan->count].replacement_idx = (uint32_t)idx;
            plan->entries[plan->count].flags = 0;
            plan->count++;
        }

        desc++;
    }
    return 0;
}

int pe_patch_apply(pe_image_t *image, const char *image_sha256_hex)
{
    if (!image || !image->mapped_base) return -1;
    if (!g_patch_init_done) pe_patch_init();

    /* Trust gate check. */
    if (image_sha256_hex && !pe_patch_enabled(image_sha256_hex)) {
        if (g_verbose)
            printf(LOG_PREFIX "Patching disabled by trust policy\n");
        return 0;
    }

    pe_patch_plan_t plan;
    memset(&plan, 0, sizeof(plan));

    /* Extract a 16-byte pool key from the hex sha.  We also need a
     * section_count + dxvk_tag to disambiguate re-signed binaries that
     * happen to collide on the prefix.  section_count is on image;
     * dxvk_tag is a stable build tag -- we use PE_PATCH_CACHE_VERSION as
     * a stand-in so a cache-format bump also invalidates the pool. */
    uint8_t sha_prefix[16];
    int have_pool_key = 0;
    uint16_t section_count = (uint16_t)(image->num_sections & 0xFFFFu);
    uint16_t dxvk_tag = (uint16_t)(PE_PATCH_CACHE_VERSION & 0xFFFFu);
    if (image_sha256_hex &&
        sha256_hex_prefix16(image_sha256_hex, sha_prefix) == 0)
        have_pool_key = 1;

    /* Try the pool first -- it holds recently-invalidated plans and is
     * the hottest path.  Misses fall through to the on-disk cache. */
    int from_pool = 0;
    int from_cache = 0;
    if (have_pool_key &&
        pe_patch_pool_try_get(sha_prefix, section_count, dxvk_tag,
                              &plan) == 0) {
        from_pool = 1;
        if (g_verbose)
            printf(LOG_PREFIX "Pool hit: %u patches\n", plan.count);
    } else if (image_sha256_hex &&
               pe_patch_cache_load(image_sha256_hex, &plan) == 0) {
        from_cache = 1;
        if (g_verbose)
            printf(LOG_PREFIX "Cache hit: %u patches from %.16s...\n",
                   plan.count, image_sha256_hex);
    } else {
        if (scan_image(image, &plan) < 0) {
            pe_patch_plan_free(&plan);
            return -1;
        }
        if (g_verbose)
            printf(LOG_PREFIX "Scan: %u CRT imports identified\n", plan.count);
    }

    int applied = apply_plan(image, &plan);
    uint32_t scanned = plan.count;

    /* Persist on miss.  Don't regress a good cache on partial-apply
     * failure: if we applied at least half, assume the plan is valid. */
    if (!from_cache && !from_pool && image_sha256_hex && scanned > 0 &&
        (uint32_t)applied >= scanned / 2) {
        if (pe_patch_cache_save(image_sha256_hex, &plan) != 0) {
            /* Non-fatal: we still applied the patches. */
            if (g_verbose)
                fprintf(stderr, LOG_PREFIX "Failed to write cache\n");
        }
    }

    /* Route the freshly-validated plan into the absent pool for fast
     * resurrection if this image reloads soon.  Skip on pool-hit path
     * to avoid thrashing the entry's hit_count. */
    if (!from_pool && have_pool_key && scanned > 0 &&
        (uint32_t)applied >= scanned / 2) {
        (void)pe_patch_pool_put(sha_prefix, section_count, dxvk_tag, &plan);
    }

    pe_patch_plan_free(&plan);

    if (applied > 0) {
        const char *src = from_pool ? " (pool)"
                        : from_cache ? " (cache)" : "";
        printf(LOG_PREFIX "Applied %d CRT body patches%s\n", applied, src);
        emit_patch_event((uint32_t)applied, scanned);
    } else if (g_verbose) {
        printf(LOG_PREFIX "No CRT imports matched; nothing to patch\n");
    }

    /* Publish pool stats for coherence daemon (rate-limited internally). */
    pe_patch_pool_write_stats_file(NULL);
    return applied;
}
