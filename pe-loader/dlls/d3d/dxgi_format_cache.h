/*
 * dxgi_format_cache.h -- lock-free per-thread DXGI_FORMAT -> VkFormat cache.
 *
 * Rationale
 * ---------
 * Every swap-chain Present, every SRV/RTV/UAV creation, every ResizeBuffers
 * call triggers a DXGI_FORMAT -> VkFormat conversion somewhere in the
 * chain (our stubs + DXVK + sometimes dxgi.so hand-offs). The conversion
 * itself is a large switch-case with ~100 entries; in hot paths this is
 * visible in perf traces as "dxgi_format_to_vk ~1% CPU".
 *
 * The cache is:
 *   - Per-thread via __thread storage (GCC TLS extension). No atomics at
 *     all in the hot path; the cache is thread-private.
 *   - Keyed by (dxgi_format, usage, colorspace). The triplet is because
 *     e.g. DXGI_FORMAT_R8G8B8A8_UNORM maps to VK_FORMAT_R8G8B8A8_UNORM for
 *     default usage but VK_FORMAT_R8G8B8A8_SRGB when used as a sampled
 *     image with an sRGB view (DXGI expresses this via colorspace, not
 *     the format enum).
 *   - Fixed 512-bucket open-addressed hash; on collision we just overwrite
 *     (LRU-like). Entry size 32 bytes = 16 KiB per thread in the worst case.
 *
 * Expected hit rate
 * -----------------
 * Games typically use 5-20 distinct (fmt, usage, cs) triplets per frame.
 * 512 buckets is 10x-100x over-provisioned -- miss-rate should be <<0.1%
 * once warmed. First-frame has 100% misses (that's fine; we're amortising
 * per-call overhead, not startup).
 *
 * API
 * ---
 *   dx_format_cache_init()
 *     Called once per thread before first lookup. Zero-init is OK; the
 *     init function is kept as a hook for future instrumentation.
 *   dx_format_cache_lookup(fmt, usage, cs, &out_vk_cs)
 *     Returns a VkFormat (uint32_t). Caller does NOT need to call
 *     _init first -- if the TLS block is zero, the first lookup just
 *     misses and the slow-path populates it. out_vk_cs is set to the
 *     VkColorSpaceKHR for the result (VK_COLOR_SPACE_SRGB_NONLINEAR_KHR
 *     by default).
 *   dx_format_cache_stats(&hits, &misses)
 *     Reads counters from CURRENT THREAD only. No cross-thread view.
 *
 * Thread-safety
 * -------------
 * All state is thread-local. No cross-thread sharing, no locks, no
 * atomics. Cache coherence is trivially the compiler's problem.
 */
#ifndef PE_DXGI_FORMAT_CACHE_H
#define PE_DXGI_FORMAT_CACHE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise the current thread's cache. Optional -- lookup() auto-inits
 * on first use. Returns 0 on success, -1 on allocation failure (only
 * relevant if future versions allocate; current impl is static storage). */
int dx_format_cache_init(void);

/* Look up VkFormat for the given DXGI triplet. Returns VK_FORMAT_UNDEFINED
 * (0) if the conversion is unknown. out_vk_color_space may be NULL; when
 * non-NULL, receives the VkColorSpaceKHR (0 for SRGB_NONLINEAR_KHR). */
uint32_t dx_format_cache_lookup(uint32_t dxgi_format,
                                 uint32_t usage,
                                 uint32_t colorspace,
                                 uint32_t *out_vk_color_space);

/* Per-thread counters. Reads from the CALLING thread's TLS only. */
void dx_format_cache_stats(uint64_t *out_hits, uint64_t *out_misses);

#ifdef __cplusplus
}
#endif

#endif /* PE_DXGI_FORMAT_CACHE_H */
