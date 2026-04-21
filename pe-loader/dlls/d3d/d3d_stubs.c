/*
 * d3d_stubs.c - DirectX / Direct3D / DXGI minimal stubs
 *
 * Games and multimedia apps probe for GPU acceleration via Direct3D 9/11,
 * DXGI factory creation, and DirectDraw. We return clean "not available"
 * errors so callers can fall back to software rendering or skip GPU
 * features gracefully.
 *
 * XInput controller support used to live here; it was moved to its own
 * shared object (dlls/xinput/xinput_evdev.c -> libpe_xinput1_4.so, plus
 * libpe_xinput1_3.so / libpe_xinput9_1_0.so symlinks) in the S68 push
 * so the gamepad hot path doesn't force D3D rebuilds.
 *
 * For actual GPU acceleration under Linux, use DXVK / VKD3D-Proton
 * which translate D3D calls to Vulkan.
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>

#include "common/dll_common.h"

/* HRESULT codes */
#define S_OK            ((HRESULT)0x00000000)
#define E_NOTIMPL       ((HRESULT)0x80004001)
#define E_FAIL          ((HRESULT)0x80004005)
#define DXGI_ERROR_UNSUPPORTED ((HRESULT)0x887A0004)

/* -----------------------------------------------------------------------
 * DXVK / VKD3D-Proton Runtime Probing
 *
 * When DXVK or VKD3D-Proton .so files are installed, we forward D3D
 * calls to them for real GPU acceleration via Vulkan. No Wine needed.
 * ----------------------------------------------------------------------- */

/* g_dxvk_d3d9 and g_dxvk_d3d9_tried are defined in d3d9_device.c */
extern void *g_dxvk_d3d9;
/* Note: d3d9_device.c uses g_dxvk_tried (not g_dxvk_d3d9_tried) */
extern int   g_dxvk_tried;

/* From dxgi_factory.c: returns 1 if the detected GPU has Vulkan support.
 * Pre-GCN Radeon and GT218/Fermi-older NVIDIA lack Vulkan on Linux.
 * Using __attribute__((weak)) so link order doesn't matter. */
extern int dxgi_gpu_is_vulkan_capable(void) __attribute__((weak));

static void *g_dxvk_d3d11 = NULL;
/* Session 30: plain 'tried' flags were raced by concurrent D3D init from
 * the UI thread + Unity job system. Replace with pthread_once so each
 * backend is probed exactly once even under thundering-herd startup. */
static pthread_once_t g_dxvk_d3d11_once = PTHREAD_ONCE_INIT;

/* g_dxvk_dxgi and g_dxvk_dxgi_tried are defined in dxgi_factory.c */
extern void *g_dxvk_dxgi;
extern int   g_dxvk_dxgi_tried;

static void *g_vkd3d_d3d12 = NULL;
static pthread_once_t g_vkd3d_d3d12_once = PTHREAD_ONCE_INIT;

static void *try_dlopen_paths(const char *name, const char **paths, int npaths)
{
    void *h = dlopen(name, RTLD_NOW | RTLD_GLOBAL);
    if (h) return h;
    for (int i = 0; i < npaths; i++) {
        char buf[512];
        snprintf(buf, sizeof(buf), "%s/%s", paths[i], name);
        h = dlopen(buf, RTLD_NOW | RTLD_GLOBAL);
        if (h) return h;
    }
    return NULL;
}

static const char *g_dxvk_search_paths[] = {
    "/usr/lib/dxvk",
    "/usr/lib/x86_64-linux-gnu/dxvk",
    "/usr/lib64/dxvk",
    "/opt/dxvk/lib",
    "./dlls/dxvk",
    "~/.pe-compat/dxvk"
};
#define DXVK_NPATHS (sizeof(g_dxvk_search_paths)/sizeof(g_dxvk_search_paths[0]))

static const char *g_vkd3d_search_paths[] = {
    "/usr/lib/vkd3d-proton",
    "/usr/lib/x86_64-linux-gnu/vkd3d-proton",
    "/usr/lib64/vkd3d-proton",
    "/opt/vkd3d-proton/lib",
    "./dlls/vkd3d",
    "~/.pe-compat/vkd3d"
};
#define VKD3D_NPATHS (sizeof(g_vkd3d_search_paths)/sizeof(g_vkd3d_search_paths[0]))

static __attribute__((unused)) void *get_dxvk_d3d9(void)
{
    /* Deprecated helper — Direct3DCreate9 in d3d9_device.c is the real
     * load path (with its own pthread_once). We just return the shared
     * pointer here. The old racy "g_dxvk_tried" flag path was a subtle
     * data-race hazard if both modules' init raced; we avoid it by letting
     * d3d9_device.c own the load. */
    return g_dxvk_d3d9;
}

/* Cached symbol pointers — resolved once at probe time so every CreateDevice
 * call reduces to a single indirect CALL instead of dlsym(). dlsym involves
 * hashtable lookups inside libdl and is decidedly not free on hot paths
 * (D3D11CreateDevice can be called repeatedly during device-reset cycles). */
typedef HRESULT (__attribute__((ms_abi)) *d3d11_create_fn)(void*, UINT, HANDLE, UINT, void*, UINT, UINT, void**, void*, void**);
typedef HRESULT (__attribute__((ms_abi)) *d3d11_create_sc_fn)(void*, UINT, HANDLE, UINT, void*, UINT, UINT, void*, void**, void**, void*, void**);
static d3d11_create_fn    g_d3d11_create_fn    = NULL;
static d3d11_create_sc_fn g_d3d11_create_sc_fn = NULL;

static void dxvk_d3d11_probe_once(void)
{
    g_dxvk_d3d11 = try_dlopen_paths("d3d11.so", g_dxvk_search_paths, DXVK_NPATHS);
    if (g_dxvk_d3d11) {
        g_d3d11_create_fn    = (d3d11_create_fn)dlsym(g_dxvk_d3d11, "D3D11CreateDevice");
        g_d3d11_create_sc_fn = (d3d11_create_sc_fn)dlsym(g_dxvk_d3d11, "D3D11CreateDeviceAndSwapChain");
        fprintf(stderr, "[d3d] DXVK D3D11 found and loaded\n");
    }
}

static void *get_dxvk_d3d11(void)
{
    pthread_once(&g_dxvk_d3d11_once, dxvk_d3d11_probe_once);
    return g_dxvk_d3d11;
}

static pthread_once_t g_dxvk_dxgi_once = PTHREAD_ONCE_INIT;
static void dxvk_dxgi_probe_once(void)
{
    if (!g_dxvk_dxgi) {
        g_dxvk_dxgi_tried = 1;
        g_dxvk_dxgi = try_dlopen_paths("dxgi.so", g_dxvk_search_paths, DXVK_NPATHS);
        if (g_dxvk_dxgi)
            fprintf(stderr, "[d3d] DXVK DXGI found and loaded\n");
    }
}

static void *get_dxvk_dxgi(void)
{
    /* Shared with dxgi_factory.c's dxgi_try_dxvk(); pthread_once guarantees
     * at most one dlopen overall no matter which module triggers first. */
    pthread_once(&g_dxvk_dxgi_once, dxvk_dxgi_probe_once);
    return g_dxvk_dxgi;
}

/* Cache D3D12 hot-path function pointers at probe time — see d3d11 note. */
typedef HRESULT (__attribute__((ms_abi)) *d3d12_create_fn)(void*, int, const GUID*, void**);
typedef HRESULT (__attribute__((ms_abi)) *d3d12_debug_fn)(const GUID*, void**);
typedef HRESULT (__attribute__((ms_abi)) *d3d12_serialize_rs_fn)(void*, int, void**, void**);
typedef HRESULT (__attribute__((ms_abi)) *d3d12_serialize_vrs_fn)(void*, void**, void**);
typedef HRESULT (__attribute__((ms_abi)) *d3d12_create_rsd_fn)(const void*, SIZE_T, const GUID*, void**);
static d3d12_create_fn        g_d3d12_create_fn        = NULL;
static d3d12_debug_fn         g_d3d12_debug_fn         = NULL;
static d3d12_serialize_rs_fn  g_d3d12_serialize_rs_fn  = NULL;
static d3d12_serialize_vrs_fn g_d3d12_serialize_vrs_fn = NULL;
static d3d12_create_rsd_fn    g_d3d12_create_rsd_fn    = NULL;

static void vkd3d_d3d12_probe_once(void)
{
    g_vkd3d_d3d12 = try_dlopen_paths("libvkd3d-proton-d3d12.so",
                                       g_vkd3d_search_paths, VKD3D_NPATHS);
    if (!g_vkd3d_d3d12)
        g_vkd3d_d3d12 = try_dlopen_paths("d3d12.so",
                                          g_vkd3d_search_paths, VKD3D_NPATHS);
    if (g_vkd3d_d3d12) {
        g_d3d12_create_fn        = (d3d12_create_fn)dlsym(g_vkd3d_d3d12, "D3D12CreateDevice");
        g_d3d12_debug_fn         = (d3d12_debug_fn)dlsym(g_vkd3d_d3d12, "D3D12GetDebugInterface");
        g_d3d12_serialize_rs_fn  = (d3d12_serialize_rs_fn)dlsym(g_vkd3d_d3d12, "D3D12SerializeRootSignature");
        g_d3d12_serialize_vrs_fn = (d3d12_serialize_vrs_fn)dlsym(g_vkd3d_d3d12, "D3D12SerializeVersionedRootSignature");
        g_d3d12_create_rsd_fn    = (d3d12_create_rsd_fn)dlsym(g_vkd3d_d3d12, "D3D12CreateRootSignatureDeserializer");
        fprintf(stderr, "[d3d] VKD3D-Proton D3D12 found and loaded\n");
    }
}

static void *get_vkd3d_d3d12(void)
{
    pthread_once(&g_vkd3d_d3d12_once, vkd3d_d3d12_probe_once);
    return g_vkd3d_d3d12;
}

/* Direct3DCreate9/Ex moved to d3d9_device.c (has full DXVK probe + stub vtable fallback) */

/* -----------------------------------------------------------------------
 * Direct3D 11 - Forward to DXVK if available
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT HRESULT D3D11CreateDevice(
    void *adapter, UINT driverType, HANDLE software, UINT flags,
    void *featureLevels, UINT numFeatureLevels, UINT sdkVersion,
    void **device, void *featureLevel, void **deviceContext)
{
    /* Probe triggers dlsym caching; subsequent calls skip both. */
    if (get_dxvk_d3d11() && g_d3d11_create_fn) {
        return g_d3d11_create_fn(adapter, driverType, software, flags, featureLevels,
                                 numFeatureLevels, sdkVersion, device, featureLevel, deviceContext);
    }
    /* Pre-Vulkan HW: return E_NOTIMPL clean so the game can display "GPU not
     * supported". Previously this hit the generic "install dxvk" message even
     * though installing DXVK won't help on a GT218. */
    if (dxgi_gpu_is_vulkan_capable && !dxgi_gpu_is_vulkan_capable()) {
        fprintf(stderr, "[d3d] D3D11CreateDevice(): GPU lacks Vulkan support (pre-GCN/GT218)\n");
    } else {
        fprintf(stderr, "[d3d] D3D11CreateDevice(): no DXVK - install dxvk for GPU acceleration\n");
    }
    if (device) *device = NULL;
    if (deviceContext) *deviceContext = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3D11CreateDeviceAndSwapChain(
    void *adapter, UINT driverType, HANDLE software, UINT flags,
    void *featureLevels, UINT numFeatureLevels, UINT sdkVersion,
    void *swapChainDesc, void **swapChain, void **device,
    void *featureLevel, void **deviceContext)
{
    if (get_dxvk_d3d11() && g_d3d11_create_sc_fn) {
        return g_d3d11_create_sc_fn(adapter, driverType, software, flags, featureLevels,
                                     numFeatureLevels, sdkVersion, swapChainDesc, swapChain,
                                     device, featureLevel, deviceContext);
    }
    fprintf(stderr, "[d3d] D3D11CreateDeviceAndSwapChain(): no DXVK\n");
    if (swapChain) *swapChain = NULL;
    if (device) *device = NULL;
    if (deviceContext) *deviceContext = NULL;
    return E_NOTIMPL;
}

/* -----------------------------------------------------------------------
 * Direct3D 12 - Forward to VKD3D-Proton if available
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT HRESULT D3D12CreateDevice(
    void *pAdapter, int MinimumFeatureLevel, const GUID *riid, void **ppDevice)
{
    if (get_vkd3d_d3d12() && g_d3d12_create_fn)
        return g_d3d12_create_fn(pAdapter, MinimumFeatureLevel, riid, ppDevice);
    if (dxgi_gpu_is_vulkan_capable && !dxgi_gpu_is_vulkan_capable()) {
        fprintf(stderr, "[d3d] D3D12CreateDevice(): GPU lacks Vulkan support (pre-GCN/GT218)\n");
    } else {
        fprintf(stderr, "[d3d] D3D12CreateDevice(): no VKD3D-Proton - install vkd3d-proton for DX12\n");
    }
    if (ppDevice) *ppDevice = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3D12GetDebugInterface(const GUID *riid, void **ppvDebug)
{
    if (get_vkd3d_d3d12() && g_d3d12_debug_fn)
        return g_d3d12_debug_fn(riid, ppvDebug);
    if (ppvDebug) *ppvDebug = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3D12SerializeRootSignature(
    void *pRootSignature, int Version, void **ppBlob, void **ppErrorBlob)
{
    if (get_vkd3d_d3d12() && g_d3d12_serialize_rs_fn)
        return g_d3d12_serialize_rs_fn(pRootSignature, Version, ppBlob, ppErrorBlob);
    if (ppBlob) *ppBlob = NULL;
    if (ppErrorBlob) *ppErrorBlob = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3D12SerializeVersionedRootSignature(
    void *pRootSignature, void **ppBlob, void **ppErrorBlob)
{
    if (get_vkd3d_d3d12() && g_d3d12_serialize_vrs_fn)
        return g_d3d12_serialize_vrs_fn(pRootSignature, ppBlob, ppErrorBlob);
    if (ppBlob) *ppBlob = NULL;
    if (ppErrorBlob) *ppErrorBlob = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3D12CreateRootSignatureDeserializer(
    const void *pSrcData, SIZE_T SrcDataSizeInBytes, const GUID *riid, void **ppRootSignature)
{
    if (get_vkd3d_d3d12() && g_d3d12_create_rsd_fn)
        return g_d3d12_create_rsd_fn(pSrcData, SrcDataSizeInBytes, riid, ppRootSignature);
    if (ppRootSignature) *ppRootSignature = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3D12EnableExperimentalFeatures(
    UINT NumFeatures, const GUID *pIIDs, void *pConfigurationStructs,
    UINT *pConfigurationStructSizes)
{
    (void)NumFeatures; (void)pIIDs; (void)pConfigurationStructs;
    (void)pConfigurationStructSizes;
    return E_NOTIMPL;
}

/* CreateDXGIFactory/1/2 moved to dxgi_factory.c (has full DXVK probe + stub vtable fallback) */

static __attribute__((unused)) HRESULT dxgi_placeholder_unused(void) {
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT DXGIGetDebugInterface(void *riid, void **debug)
{
    void *dxvk = get_dxvk_dxgi();
    if (dxvk) {
        typedef HRESULT (__attribute__((ms_abi)) *fn_t)(void*, void**);
        fn_t fn = (fn_t)dlsym(dxvk, "DXGIGetDebugInterface");
        if (fn) return fn(riid, debug);
    }
    if (debug) *debug = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT DXGIGetDebugInterface1(UINT Flags, void *riid, void **debug)
{
    void *dxvk = get_dxvk_dxgi();
    if (dxvk) {
        typedef HRESULT (__attribute__((ms_abi)) *fn_t)(UINT, void*, void**);
        fn_t fn = (fn_t)dlsym(dxvk, "DXGIGetDebugInterface1");
        if (fn) return fn(Flags, riid, debug);
    }
    if (debug) *debug = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT DXGIDeclareAdapterRemovalSupport(void)
{
    return S_OK;
}

/* -----------------------------------------------------------------------
 * DirectDraw (legacy)
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT HRESULT DirectDrawCreate(void *guid, void **dd, void *unknown)
{
    (void)guid;
    (void)unknown;

    fprintf(stderr, "[d3d] DirectDrawCreate(): "
            "DirectDraw not available in PE compat layer. "
            "Use Vulkan/DXVK.\n");

    if (dd)
        *dd = NULL;

    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT DirectDrawCreateEx(
    void *guid,
    void **dd,
    void *iid,
    void *unknown)
{
    (void)guid;
    (void)iid;
    (void)unknown;

    fprintf(stderr, "[d3d] DirectDrawCreateEx(): "
            "DirectDraw not available in PE compat layer. "
            "Use Vulkan/DXVK.\n");

    if (dd)
        *dd = NULL;

    return E_NOTIMPL;
}

/* -----------------------------------------------------------------------
 * D3DX Utility (D3DX9 / D3DX10 / D3DX11)
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT HRESULT D3DXCreateTextureFromFileA(
    void *device,
    LPCSTR srcFile,
    void **texture)
{
    (void)device;

    fprintf(stderr, "[d3d] D3DXCreateTextureFromFileA('%s'): "
            "GPU acceleration not available in PE compat layer.\n",
            srcFile ? srcFile : "(null)");

    if (texture)
        *texture = NULL;

    return E_NOTIMPL;
}

/*
 * Intentionally no destructor: games keep D3D11/D3D12 device pointers with
 * vtables that live inside DXVK/VKD3D .so code. Closing the handles at
 * process exit would unmap the code before late Release() unwinds run,
 * which would crash. The OS reclaims everything at process exit.
 */
