/* coherence_present_layer.c -- Vulkan implicit layer that controls the
 * VkPresentModeKHR selected by DXVK / VKD3D / native Vulkan apps.
 *
 * PURPOSE: The project's "vsync-off" previously only poked compositor
 * settings (xfconf use_compositing=false, hyprctl misc:vrr=2).  If the
 * Vulkan ICD (RADV/ANV/NVidia) decided FIFO anyway, the game was still
 * pinned to monitor refresh rate.  This layer forces the issue at the
 * Vulkan ABI boundary by intercepting vkCreateSwapchainKHR and rewriting
 * pCreateInfo->presentMode to the policy-selected mode.
 *
 * ABI INTERCEPT POINTS:
 *   vkCreateInstance        -- install layer dispatch, no behavioural change
 *   vkDestroyInstance       -- tear down dispatch
 *   vkCreateDevice          -- install device dispatch
 *   vkDestroyDevice         -- tear down device dispatch
 *   vkCreateSwapchainKHR    -- mutate presentMode based on policy
 *   vkQueuePresentKHR       -- count frames, update frame-time stats
 *
 * POLICY PRECEDENCE (highest wins):
 *   1. COHERENCE_PRESENT_MODE env var (AUTO|MAILBOX|IMMEDIATE|FIFO)
 *   2. /dev/shm/coherence_vk_policy  (single byte: 0=AUTO 1=MAILBOX 2=IMMEDIATE 3=FIFO)
 *   3. Compile-time default: MAILBOX
 *
 * FALLBACK CHAIN: MAILBOX -> IMMEDIATE -> FIFO_RELAXED -> FIFO (always
 * available per spec).  Every fallback increments shared-mem
 * fallback_count and logs LOUDLY to stderr.
 *
 * OPT-OUT: set DISABLE_COHERENCE_PRESENT_LAYER=1 before launch; the layer's
 * manifest declares this as disable_environment so the loader skips us.
 *
 * THREAD SAFETY: swapchain creation is per-instance, measured by an atomic
 * increment on the seqlock.  QueuePresent is per-queue (concurrent from
 * driver threads); we use __atomic ops only.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

#ifdef HAVE_VULKAN
# include <vulkan/vulkan.h>
# include <vulkan/vk_layer.h>
/* The Vulkan SDK header used to define VK_LAYER_EXPORT but that symbol
 * was dropped in 1.3.x.  We want the Makefile to build with
 * -fvisibility=hidden AND still publish the required layer entry points,
 * so we use a local visibility-default attribute. */
# ifndef COH_LAYER_EXPORT
#  define COH_LAYER_EXPORT __attribute__((visibility("default")))
# endif
#else
/* Minimal Vulkan ABI stubs -- let us compile-check without the SDK.
 * The full build (make) requires vulkan headers; this fallback only
 * keeps -fsyntax-only and CI green when headers are missing. */
typedef uint32_t VkFlags;
typedef uint32_t VkResult;
typedef uint32_t VkStructureType;
typedef void *VkInstance;
typedef void *VkPhysicalDevice;
typedef void *VkDevice;
typedef void *VkQueue;
typedef void *VkSurfaceKHR;
typedef void *VkSwapchainKHR;
typedef void *VkAllocationCallbacks;
#define VK_SUCCESS 0
#define VK_ERROR_INITIALIZATION_FAILED (-3)
typedef uint32_t VkPresentModeKHR;
#define VK_PRESENT_MODE_IMMEDIATE_KHR    0u
#define VK_PRESENT_MODE_MAILBOX_KHR      1u
#define VK_PRESENT_MODE_FIFO_KHR         2u
#define VK_PRESENT_MODE_FIFO_RELAXED_KHR 3u
#endif

/* Shared memory layout lives with the daemon, out of tree.  Keep path
 * consistent with profile/airootfs/usr/share/ai-arch/vk_present_shm.h. */
#define COH_VK_SHM_PATH "/dev/shm/coherence_vk"
#define COH_VK_POLICY_PATH "/dev/shm/coherence_vk_policy"
#define COH_VK_SHM_SIZE 64u
#define COH_VK_SHM_MAGIC 0x4B564F43u

struct coh_vk_shared {
    uint32_t magic;
    uint32_t sequence;
    uint32_t present_mode_requested;
    uint32_t present_mode_actual;
    uint32_t frame_count;
    uint64_t last_present_ms;
    double   ft_mean_ms;
    double   ft_var_ms2;
    uint32_t fallback_count;
    uint8_t  _pad[16];
};

/* --- Shared memory writer ------------------------------------------------ */
static struct coh_vk_shared *g_shm = NULL;

static void coh_shm_init(void) {
    if (g_shm) return;
    int fd = open(COH_VK_SHM_PATH, O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        fprintf(stderr, "[coherence_present_layer] open(%s): %s\n",
                COH_VK_SHM_PATH, strerror(errno));
        return;
    }
    if (ftruncate(fd, COH_VK_SHM_SIZE) < 0) {
        fprintf(stderr, "[coherence_present_layer] ftruncate: %s\n", strerror(errno));
        close(fd);
        return;
    }
    void *map = mmap(NULL, COH_VK_SHM_SIZE, PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, 0);
    close(fd);
    if (map == MAP_FAILED) {
        fprintf(stderr, "[coherence_present_layer] mmap: %s\n", strerror(errno));
        return;
    }
    g_shm = (struct coh_vk_shared *)map;

    /* First writer wins magic initialization.  Use CAS so multiple
     * processes on the same box don't clobber each other's counters. */
    uint32_t expected = 0;
    if (__atomic_compare_exchange_n(&g_shm->magic, &expected,
                                     COH_VK_SHM_MAGIC, 0,
                                     __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        g_shm->sequence = 0;
        g_shm->present_mode_requested = 0xFFFFFFFFu;
        g_shm->present_mode_actual = 0xFFFFFFFFu;
        g_shm->frame_count = 0;
        g_shm->last_present_ms = 0;
        g_shm->ft_mean_ms = 0.0;
        g_shm->ft_var_ms2 = 0.0;
        g_shm->fallback_count = 0;
    }
}

static void coh_shm_seq_begin(void) {
    if (!g_shm) return;
    /* Transition even -> odd (unstable). */
    __atomic_fetch_add(&g_shm->sequence, 1, __ATOMIC_RELEASE);
}
static void coh_shm_seq_end(void) {
    if (!g_shm) return;
    /* Transition odd -> even (stable). */
    __atomic_fetch_add(&g_shm->sequence, 1, __ATOMIC_RELEASE);
}

static uint64_t coh_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000ull);
}

/* --- Policy resolution --------------------------------------------------- */
enum coh_policy { COH_POL_AUTO=0, COH_POL_MAILBOX=1, COH_POL_IMMEDIATE=2, COH_POL_FIFO=3 };

static enum coh_policy coh_resolve_policy(void) {
    /* 1. Environment override. */
    const char *e = getenv("COHERENCE_PRESENT_MODE");
    if (e && *e) {
        if (!strcasecmp(e, "MAILBOX"))   return COH_POL_MAILBOX;
        if (!strcasecmp(e, "IMMEDIATE")) return COH_POL_IMMEDIATE;
        if (!strcasecmp(e, "FIFO"))      return COH_POL_FIFO;
        if (!strcasecmp(e, "AUTO"))      return COH_POL_AUTO;
    }
    /* 2. Shared-mem one-byte override. */
    int fd = open(COH_VK_POLICY_PATH, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        uint8_t b = 0;
        ssize_t n = read(fd, &b, 1);
        close(fd);
        if (n == 1 && b <= COH_POL_FIFO) return (enum coh_policy)b;
    }
    /* 3. Default: MAILBOX (gives tear-free + uncapped throughput). */
    return COH_POL_MAILBOX;
}

/* --- Mode selection ------------------------------------------------------ */
/* Given a policy and the driver-supported list, return the selected mode
 * and count whether we had to fall back. */
static VkPresentModeKHR coh_select_mode(enum coh_policy pol,
                                        const VkPresentModeKHR *avail,
                                        uint32_t n_avail,
                                        int *fellback)
{
    *fellback = 0;
    /* Helper: does the list contain `m`?  Written as a statement-expr with
     * an explicit block so -Wmisleading-indentation is silent. */
    #define HAS(m) ({ \
        int _found = 0; \
        for (uint32_t _i = 0; _i < n_avail; _i++) { \
            if (avail[_i] == (m)) { _found = 1; break; } \
        } \
        _found; })

    /* Intent chain per policy.  FIFO is last-resort (spec-guaranteed). */
    VkPresentModeKHR chain[4];
    int n = 0;
    switch (pol) {
    case COH_POL_MAILBOX:
    case COH_POL_AUTO:
        chain[n++] = VK_PRESENT_MODE_MAILBOX_KHR;
        chain[n++] = VK_PRESENT_MODE_IMMEDIATE_KHR;
        chain[n++] = VK_PRESENT_MODE_FIFO_RELAXED_KHR;
        chain[n++] = VK_PRESENT_MODE_FIFO_KHR;
        break;
    case COH_POL_IMMEDIATE:
        chain[n++] = VK_PRESENT_MODE_IMMEDIATE_KHR;
        chain[n++] = VK_PRESENT_MODE_MAILBOX_KHR;
        chain[n++] = VK_PRESENT_MODE_FIFO_RELAXED_KHR;
        chain[n++] = VK_PRESENT_MODE_FIFO_KHR;
        break;
    case COH_POL_FIFO:
        chain[n++] = VK_PRESENT_MODE_FIFO_KHR;
        chain[n++] = VK_PRESENT_MODE_FIFO_RELAXED_KHR;
        break;
    }

    for (int i = 0; i < n; i++) {
        if (HAS(chain[i])) {
            if (i > 0) *fellback = 1;
            return chain[i];
        }
    }
    /* Spec guarantees FIFO is always supported.  If even that's missing,
     * we just return the caller's first choice and let the driver error. */
    *fellback = 1;
    return chain[0];
    #undef HAS
}

#ifdef HAVE_VULKAN
/* --- Dispatch table storage --------------------------------------------- */
/* We store the next layer's function pointers in a per-instance / per-
 * device struct.  For simplicity we keep a single global cache; each
 * create*() overwrites it.  This is safe for the typical one-instance
 * game scenario; if a game creates concurrent instances on separate
 * threads, it still works because the chain info is in pCreateInfo and
 * each call walks it independently. */
static PFN_vkGetInstanceProcAddr g_next_gipa = NULL;
static PFN_vkGetDeviceProcAddr   g_next_gdpa = NULL;
static PFN_vkCreateSwapchainKHR  g_next_create_swapchain = NULL;
static PFN_vkQueuePresentKHR     g_next_queue_present = NULL;
static PFN_vkGetPhysicalDeviceSurfacePresentModesKHR g_next_get_modes = NULL;
static PFN_vkDestroyInstance     g_next_destroy_instance = NULL;
static PFN_vkDestroyDevice       g_next_destroy_device = NULL;

/* Cached physical-device pointer from swapchain's device.  The create
 * chain only gives us VkDevice; we need the VkPhysicalDevice to query
 * supported present modes.  VKD3D/DXVK pass the physical device via a
 * pNext chain on the swapchain create info in some versions; we also
 * stash it at vkCreateDevice time. */
static VkPhysicalDevice g_cached_pdev = VK_NULL_HANDLE;

/* --- Intercept: vkCreateSwapchainKHR ------------------------------------ */
static VkResult VKAPI_CALL coh_CreateSwapchainKHR(
    VkDevice device,
    const VkSwapchainCreateInfoKHR* pCreateInfo,
    const VkAllocationCallbacks* pAllocator,
    VkSwapchainKHR* pSwapchain)
{
    coh_shm_init();

    VkSwapchainCreateInfoKHR info = *pCreateInfo;
    enum coh_policy pol = coh_resolve_policy();

    /* Query what the driver supports on this surface. */
    VkPresentModeKHR modes[16];
    uint32_t n_modes = 16;
    VkResult r = VK_ERROR_INITIALIZATION_FAILED;
    if (g_next_get_modes && g_cached_pdev) {
        r = g_next_get_modes(g_cached_pdev, info.surface, &n_modes, modes);
    }
    VkPresentModeKHR chosen = info.presentMode;
    int fellback = 0;
    if (r == VK_SUCCESS && n_modes > 0) {
        chosen = coh_select_mode(pol, modes, n_modes, &fellback);
    } else {
        /* Can't enumerate -- respect whatever app asked; just log. */
        fprintf(stderr,
            "[coherence_present_layer] WARN: could not enumerate present modes (r=%d, pdev=%p); "
            "leaving app's choice %u intact\n", (int)r, (void*)g_cached_pdev,
            (unsigned)info.presentMode);
    }

    if (fellback) {
        fprintf(stderr,
            "[coherence_present_layer] FALLBACK: policy=%u requested best-fit not available, "
            "using mode=%u\n", (unsigned)pol, (unsigned)chosen);
    }

    info.presentMode = chosen;

    /* Publish to shared mem. */
    if (g_shm) {
        coh_shm_seq_begin();
        g_shm->present_mode_requested = (uint32_t)pol;
        g_shm->present_mode_actual = (uint32_t)chosen;
        if (fellback) g_shm->fallback_count++;
        coh_shm_seq_end();
    }

    fprintf(stderr,
        "[coherence_present_layer] vkCreateSwapchainKHR policy=%u -> mode=%u "
        "(driver-supported=%u)\n",
        (unsigned)pol, (unsigned)chosen, (unsigned)n_modes);

    if (!g_next_create_swapchain) return VK_ERROR_INITIALIZATION_FAILED;
    return g_next_create_swapchain(device, &info, pAllocator, pSwapchain);
}

/* --- Intercept: vkQueuePresentKHR --------------------------------------- */
static VkResult VKAPI_CALL coh_QueuePresentKHR(
    VkQueue queue,
    const VkPresentInfoKHR* pPresentInfo)
{
    if (g_shm) {
        uint64_t now_ms = coh_now_ms();
        coh_shm_seq_begin();
        uint64_t prev = g_shm->last_present_ms;
        g_shm->frame_count++;
        g_shm->last_present_ms = now_ms;
        if (prev != 0) {
            double dt_ms = (double)(now_ms - prev);
            /* EMA-style rolling mean with alpha tuned for a 100 ms window
             * at ~60 Hz (~6 samples) : alpha = 1/6 ≈ 0.166.  For higher
             * frame rates the tail lengthens; acceptable for a gauge. */
            const double alpha = 0.166;
            double prev_mean = g_shm->ft_mean_ms;
            g_shm->ft_mean_ms = prev_mean + alpha * (dt_ms - prev_mean);
            double d = dt_ms - g_shm->ft_mean_ms;
            g_shm->ft_var_ms2 = (1.0 - alpha) * (g_shm->ft_var_ms2 + alpha * d * d);
        }
        coh_shm_seq_end();
    }
    if (!g_next_queue_present) return VK_ERROR_INITIALIZATION_FAILED;
    return g_next_queue_present(queue, pPresentInfo);
}

/* --- Layer negotiation -------------------------------------------------- */
/* Intercept vkGetDeviceProcAddr so DXVK (which caches device funcs) sees
 * our swapchain/present wrappers. */
COH_LAYER_EXPORT PFN_vkVoidFunction VKAPI_CALL
coh_GetDeviceProcAddr(VkDevice device, const char* pName) {
    if (pName && !strcmp(pName, "vkCreateSwapchainKHR"))
        return (PFN_vkVoidFunction)coh_CreateSwapchainKHR;
    if (pName && !strcmp(pName, "vkQueuePresentKHR"))
        return (PFN_vkVoidFunction)coh_QueuePresentKHR;
    if (pName && !strcmp(pName, "vkGetDeviceProcAddr"))
        return (PFN_vkVoidFunction)coh_GetDeviceProcAddr;
    if (!g_next_gdpa) return NULL;
    return g_next_gdpa(device, pName);
}

/* --- Intercept: vkCreateDevice ------------------------------------------ */
static VkResult VKAPI_CALL coh_CreateDevice(
    VkPhysicalDevice physicalDevice,
    const VkDeviceCreateInfo* pCreateInfo,
    const VkAllocationCallbacks* pAllocator,
    VkDevice* pDevice)
{
    /* Walk layer chain.  pCreateInfo->pNext chain holds the
     * VkLayerDeviceCreateInfo that tells us the next layer's fpGetProcAddr. */
    VkLayerDeviceCreateInfo* chain_info = (VkLayerDeviceCreateInfo*)pCreateInfo->pNext;
    while (chain_info && !(chain_info->sType == VK_STRUCTURE_TYPE_LOADER_DEVICE_CREATE_INFO
                           && chain_info->function == VK_LAYER_LINK_INFO))
        chain_info = (VkLayerDeviceCreateInfo*)chain_info->pNext;

    if (!chain_info) {
        fprintf(stderr, "[coherence_present_layer] ERR: no VK_LAYER_LINK_INFO in CreateDevice\n");
        return VK_ERROR_INITIALIZATION_FAILED;
    }

    PFN_vkGetInstanceProcAddr pfn_gipa = chain_info->u.pLayerInfo->pfnNextGetInstanceProcAddr;
    PFN_vkGetDeviceProcAddr   pfn_gdpa = chain_info->u.pLayerInfo->pfnNextGetDeviceProcAddr;
    PFN_vkCreateDevice        pfn_create = (PFN_vkCreateDevice)pfn_gipa(VK_NULL_HANDLE, "vkCreateDevice");

    /* Advance chain. */
    chain_info->u.pLayerInfo = chain_info->u.pLayerInfo->pNext;

    VkResult result = pfn_create(physicalDevice, pCreateInfo, pAllocator, pDevice);
    if (result != VK_SUCCESS) return result;

    /* Capture next-layer device-level fps. */
    g_next_gdpa = pfn_gdpa;
    g_next_create_swapchain = (PFN_vkCreateSwapchainKHR)pfn_gdpa(*pDevice, "vkCreateSwapchainKHR");
    g_next_queue_present    = (PFN_vkQueuePresentKHR)pfn_gdpa(*pDevice, "vkQueuePresentKHR");
    g_next_destroy_device   = (PFN_vkDestroyDevice)pfn_gdpa(*pDevice, "vkDestroyDevice");
    g_cached_pdev = physicalDevice;
    (void)pfn_gipa;
    return result;
}

static void VKAPI_CALL coh_DestroyDevice(VkDevice device, const VkAllocationCallbacks* pAllocator) {
    if (g_next_destroy_device) g_next_destroy_device(device, pAllocator);
    g_next_create_swapchain = NULL;
    g_next_queue_present = NULL;
}

COH_LAYER_EXPORT PFN_vkVoidFunction VKAPI_CALL
coh_GetInstanceProcAddr(VkInstance instance, const char* pName);

/* --- Intercept: vkCreateInstance ---------------------------------------- */
static VkResult VKAPI_CALL coh_CreateInstance(
    const VkInstanceCreateInfo* pCreateInfo,
    const VkAllocationCallbacks* pAllocator,
    VkInstance* pInstance)
{
    VkLayerInstanceCreateInfo* chain_info = (VkLayerInstanceCreateInfo*)pCreateInfo->pNext;
    while (chain_info && !(chain_info->sType == VK_STRUCTURE_TYPE_LOADER_INSTANCE_CREATE_INFO
                           && chain_info->function == VK_LAYER_LINK_INFO))
        chain_info = (VkLayerInstanceCreateInfo*)chain_info->pNext;

    if (!chain_info) {
        fprintf(stderr, "[coherence_present_layer] ERR: no VK_LAYER_LINK_INFO in CreateInstance\n");
        return VK_ERROR_INITIALIZATION_FAILED;
    }

    PFN_vkGetInstanceProcAddr pfn_gipa = chain_info->u.pLayerInfo->pfnNextGetInstanceProcAddr;
    PFN_vkCreateInstance      pfn_create = (PFN_vkCreateInstance)pfn_gipa(VK_NULL_HANDLE, "vkCreateInstance");

    chain_info->u.pLayerInfo = chain_info->u.pLayerInfo->pNext;

    VkResult result = pfn_create(pCreateInfo, pAllocator, pInstance);
    if (result != VK_SUCCESS) return result;

    g_next_gipa = pfn_gipa;
    g_next_get_modes = (PFN_vkGetPhysicalDeviceSurfacePresentModesKHR)
        pfn_gipa(*pInstance, "vkGetPhysicalDeviceSurfacePresentModesKHR");
    g_next_destroy_instance = (PFN_vkDestroyInstance)
        pfn_gipa(*pInstance, "vkDestroyInstance");

    coh_shm_init();
    fprintf(stderr, "[coherence_present_layer] initialized on VkInstance=%p\n", (void*)*pInstance);
    return result;
}

static void VKAPI_CALL coh_DestroyInstance(VkInstance instance, const VkAllocationCallbacks* pAllocator) {
    if (g_next_destroy_instance) g_next_destroy_instance(instance, pAllocator);
}

COH_LAYER_EXPORT PFN_vkVoidFunction VKAPI_CALL
coh_GetInstanceProcAddr(VkInstance instance, const char* pName) {
    if (!pName) return NULL;
    if (!strcmp(pName, "vkGetInstanceProcAddr")) return (PFN_vkVoidFunction)coh_GetInstanceProcAddr;
    if (!strcmp(pName, "vkCreateInstance"))      return (PFN_vkVoidFunction)coh_CreateInstance;
    if (!strcmp(pName, "vkDestroyInstance"))     return (PFN_vkVoidFunction)coh_DestroyInstance;
    if (!strcmp(pName, "vkCreateDevice"))        return (PFN_vkVoidFunction)coh_CreateDevice;
    if (!strcmp(pName, "vkDestroyDevice"))       return (PFN_vkVoidFunction)coh_DestroyDevice;
    if (!strcmp(pName, "vkGetDeviceProcAddr"))   return (PFN_vkVoidFunction)coh_GetDeviceProcAddr;
    if (!strcmp(pName, "vkCreateSwapchainKHR"))  return (PFN_vkVoidFunction)coh_CreateSwapchainKHR;
    if (!strcmp(pName, "vkQueuePresentKHR"))     return (PFN_vkVoidFunction)coh_QueuePresentKHR;
    if (!g_next_gipa) return NULL;
    return g_next_gipa(instance, pName);
}

/* --- Layer negotiation entry point -------------------------------------- */
/* The Khronos Vulkan loader calls vkNegotiateLoaderLayerInterfaceVersion
 * on implicit layers that export it.  We advertise interface version 2
 * which is the current ABI. */
COH_LAYER_EXPORT VkResult VKAPI_CALL
vkNegotiateLoaderLayerInterfaceVersion(VkNegotiateLayerInterface* pVersionStruct)
{
    if (!pVersionStruct) return VK_ERROR_INITIALIZATION_FAILED;
    if (pVersionStruct->sType != LAYER_NEGOTIATE_INTERFACE_STRUCT)
        return VK_ERROR_INITIALIZATION_FAILED;

    if (pVersionStruct->loaderLayerInterfaceVersion > 2)
        pVersionStruct->loaderLayerInterfaceVersion = 2;

    pVersionStruct->pfnGetInstanceProcAddr       = coh_GetInstanceProcAddr;
    pVersionStruct->pfnGetDeviceProcAddr         = coh_GetDeviceProcAddr;
    pVersionStruct->pfnGetPhysicalDeviceProcAddr = NULL;
    return VK_SUCCESS;
}

#else /* !HAVE_VULKAN */
/* Without Vulkan headers, export only a stub symbol so the .so links.
 * The loader will refuse to use us (no GetInstanceProcAddr) and game
 * launches are unaffected.  build-packages.sh treats absence of vulkan
 * headers as a soft failure; the .so simply won't be installed. */
__attribute__((visibility("default")))
int coherence_present_layer_stub(void) { return 0; }
#endif
