/*
 * pe_patch.h - PE load-time CRT body patching API
 *
 * After pe_relocator completes and pe_import resolves the IAT, the loader
 * calls pe_patch_apply() to rewrite IAT slots that point at known CRT
 * functions (memcpy/memset/strlen/...) so they invoke our SSE2/AVX2
 * optimized bodies instead of libc's sysv_abi stubs routed through the
 * ms_abi trampolines in pe_import.c.
 *
 * Two code paths:
 *   1. First launch of a given binary (keyed by sha256 image hash):
 *      scan the IAT, compute a patch plan, apply in-place, and persist
 *      the plan to ~/.cache/pe-loader/patches/<sha256>.ptc (zstd+varint).
 *   2. Subsequent launches: read the cache, apply without re-scanning.
 *
 * The trust gate may DENY patching for code-integrity-sensitive apps;
 * in that case pe_patch_apply is a no-op and no cache file is written.
 */

#ifndef PE_PATCH_H
#define PE_PATCH_H

#include <stdint.h>
#include <stddef.h>
#include "pe/pe_header.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Increment on any change to the on-disk wire format. */
#define PE_PATCH_CACHE_VERSION   1u
#define PE_PATCH_CACHE_MAGIC     0x31435450u /* "PTC1" (little-endian) */

/* Cache header flags */
#define PE_PATCH_FLAG_ZSTD       0x00000001u
#define PE_PATCH_FLAG_VARINT     0x00000002u

/* Maximum patches a single binary may carry.  UE5-scale targets see
 * 150-250 CRT references; we cap at 4096 for safety. */
#define PE_PATCH_MAX_ENTRIES     4096

/* In-memory patch plan.  One entry per patched IAT slot. */
typedef struct {
    uint64_t iat_rva;        /* RVA of the 8-byte IAT slot within the image */
    uint32_t replacement_idx;/* Index into PE_PATCH_COUNT table */
    uint32_t flags;          /* Reserved for future use (e.g. CPUID-spoof) */
} pe_patch_entry_t;

typedef struct {
    pe_patch_entry_t *entries;
    uint32_t          count;
    uint32_t          capacity;
} pe_patch_plan_t;

/* Public API -- called from main.c after pe_resolve_imports returns ok. */

/* Initialise the subsystem (creates cache dir, primes CPU-feature bits).
 * Safe to call repeatedly; no-op after first success. */
int pe_patch_init(void);

/* Apply patches to the given image.  image_sha256_hex is a 65-byte
 * NUL-terminated hex string of the PE file's SHA-256 (cache key).
 * Returns: >0 = number of patches applied, 0 = nothing to patch, -1 on error.
 * If the trust gate refuses patching, the function succeeds with 0. */
int pe_patch_apply(pe_image_t *image, const char *image_sha256_hex);

/* Shutdown -- flushes pending cache writes. */
void pe_patch_shutdown(void);

/* Trust hook: returns non-zero if patching is permitted for this binary.
 * Defined in pe_patch.c; trust_gate can stub/override via dlsym. */
int pe_patch_enabled(const char *image_sha256_hex);

/* ------------------------------------------------------------------
 * Cache subsystem (pe_patch_cache.c) -- internal but exported for
 * the AI daemon's /patches endpoint to introspect cache summaries.
 * ------------------------------------------------------------------ */

/* Save a patch plan for a binary.  Returns 0 on success, -1 on error.
 * Uses atomic tmp-file + rename to avoid torn writes. */
int pe_patch_cache_save(const char *image_sha256_hex,
                        const pe_patch_plan_t *plan);

/* Load a patch plan from cache.  Allocates plan->entries via malloc;
 * caller owns and must free.  Returns 0 on hit, -1 on miss/corruption. */
int pe_patch_cache_load(const char *image_sha256_hex,
                        pe_patch_plan_t *plan);

/* Free a plan loaded via pe_patch_cache_load. */
void pe_patch_plan_free(pe_patch_plan_t *plan);

/* SIGILL trampoline for CPUID spoofing (sigill_trampoline.c).
 * Installed only if opt-in config is set.  Idempotent. */
int pe_patch_sigill_install(void);
void pe_patch_sigill_uninstall(void);
/* Enable/disable CPUID spoofing per-process (per-app config). */
void pe_patch_sigill_set_enabled(int enabled);

#ifdef __cplusplus
}
#endif

#endif /* PE_PATCH_H */
