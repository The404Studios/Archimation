/* vk_present_shm.h -- shared-memory protocol between the Coherence Vulkan
 * present-mode layer (writer) and the Coherence measurement daemon (reader).
 *
 * The layer atomically writes present-mode state + per-frame counters into
 * /dev/shm/coherence_vk (64 bytes) using a seqlock pattern so readers don't
 * need a mutex.
 *
 * WRITER PROTOCOL (coherence_present_layer.c):
 *   1. bump sequence (odd) before mutating payload
 *   2. write payload fields
 *   3. bump sequence (even) after payload is stable
 *
 * READER PROTOCOL (coherence daemon measurement layer):
 *   do {
 *     s1 = atomic_load(sequence);
 *     if (s1 & 1) continue;            // writer in progress
 *     memcpy(&local, shm, sizeof(...));
 *     s2 = atomic_load(sequence);
 *   } while (s1 != s2);
 *
 * File is created mode 0644, size COH_VK_SHM_SIZE.  Magic 'COVK' (little-
 * endian 0x4B564F43) disambiguates from unrelated /dev/shm garbage.
 */

#ifndef COHERENCE_VK_PRESENT_SHM_H
#define COHERENCE_VK_PRESENT_SHM_H

#include <stdint.h>

#define COH_VK_SHM_PATH "/dev/shm/coherence_vk"
#define COH_VK_SHM_SIZE 64u
#define COH_VK_SHM_MAGIC 0x4B564F43u  /* 'COVK' little-endian */

/* Values match VkPresentModeKHR where possible; keep layer-local enum
 * so readers don't need <vulkan/vulkan.h> at compile time. */
#define COH_PRESENT_IMMEDIATE 0u    /* VK_PRESENT_MODE_IMMEDIATE_KHR */
#define COH_PRESENT_MAILBOX   1u    /* VK_PRESENT_MODE_MAILBOX_KHR */
#define COH_PRESENT_FIFO      2u    /* VK_PRESENT_MODE_FIFO_KHR */
#define COH_PRESENT_FIFO_RELX 3u    /* VK_PRESENT_MODE_FIFO_RELAXED_KHR */
#define COH_PRESENT_UNKNOWN   0xFFFFFFFFu

/* Policy values for shared-mem runtime override.  String equivalents are
 * set via COHERENCE_PRESENT_MODE env var. */
#define COH_POLICY_AUTO       0u
#define COH_POLICY_MAILBOX    1u
#define COH_POLICY_IMMEDIATE  2u
#define COH_POLICY_FIFO       3u

struct coh_vk_shared {
    uint32_t magic;                 /* COH_VK_SHM_MAGIC */
    uint32_t sequence;              /* seqlock; even = stable */
    uint32_t present_mode_requested;/* what policy asked for */
    uint32_t present_mode_actual;   /* what the driver actually accepted */
    uint32_t frame_count;           /* incremented per vkQueuePresentKHR */
    uint64_t last_present_ms;       /* CLOCK_MONOTONIC milliseconds */
    double   ft_mean_ms;            /* rolling 100ms mean frame-time */
    double   ft_var_ms2;            /* rolling 100ms variance (ms^2) */
    uint32_t fallback_count;        /* # times requested mode unavailable */
    uint8_t  _pad[16];
};

/* Compile-time assertion: struct fits the fixed mmap window. */
#if defined(__GNUC__) || defined(__clang__)
_Static_assert(sizeof(struct coh_vk_shared) <= COH_VK_SHM_SIZE,
               "coh_vk_shared must fit within COH_VK_SHM_SIZE");
#endif

#endif /* COHERENCE_VK_PRESENT_SHM_H */
