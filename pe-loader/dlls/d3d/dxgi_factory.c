/*
 * dxgi_factory.c - DXGI Factory with HDR support
 *
 * Implements IDXGIFactory, IDXGIAdapter, IDXGIOutput, IDXGIOutput6.
 * Games call IDXGIOutput6::GetDesc1() to detect HDR capability.
 * When DXVK is available, everything forwards to DXVK which handles
 * real Vulkan HDR via VK_EXT_swapchain_colorspace + VK_EXT_hdr_metadata.
 * These stubs serve as fallback when DXVK is not loaded.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>

#include "common/dll_common.h"

#define LOG_PREFIX "[dxgi] "

/* Forward declarations for GPU auto-detection (defined later in file) */
typedef struct {
    UINT  vendor_id;
    UINT  device_id;
    SIZE_T vram_bytes;
    char  name[128];
    int   found;
} gpu_info_t;

static void detect_gpu(gpu_info_t *info);
static gpu_info_t g_gpu_cache;
static int g_gpu_detected = 0;

#define S_OK 0
#define E_NOINTERFACE        ((long)0x80004002)
#ifndef E_INVALIDARG
#define E_INVALIDARG         ((long)0x80070057)
#endif
#ifndef E_OUTOFMEMORY
#define E_OUTOFMEMORY        ((long)0x8007000E)
#endif
#define E_FAIL               ((long)0x80004005)
#define DXGI_ERROR_NOT_FOUND ((long)0x887A0002)

/* ---------- DXGI enums and structures ---------- */

typedef enum {
    DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709      = 0,   /* sRGB */
    DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709      = 1,   /* scRGB linear */
    DXGI_COLOR_SPACE_RGB_FULL_G2084_NONE_P2020   = 12,  /* HDR10 PQ */
    DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P2020     = 17,  /* BT.2020 SDR */
} DXGI_COLOR_SPACE_TYPE;

typedef enum {
    DXGI_FORMAT_UNKNOWN               = 0,
    DXGI_FORMAT_R8G8B8A8_UNORM        = 28,
    DXGI_FORMAT_R10G10B10A2_UNORM     = 24,  /* HDR10 surface format */
    DXGI_FORMAT_R16G16B16A16_FLOAT    = 10,  /* scRGB surface format */
    DXGI_FORMAT_B8G8R8A8_UNORM        = 87,
} DXGI_FORMAT;

typedef struct {
    WCHAR Description[128];
    UINT VendorId;
    UINT DeviceId;
    UINT SubSysId;
    UINT Revision;
    SIZE_T DedicatedVideoMemory;
    SIZE_T DedicatedSystemMemory;
    SIZE_T SharedSystemMemory;
    DWORD AdapterLuid_LowPart;
    LONG  AdapterLuid_HighPart;
} DXGI_ADAPTER_DESC;

typedef struct {
    WCHAR DeviceName[32];
    INT   DesktopLeft;
    INT   DesktopTop;
    INT   DesktopRight;
    INT   DesktopBottom;
    BOOL  AttachedToDesktop;
    UINT  Rotation;
    HANDLE Monitor;
} DXGI_OUTPUT_DESC;

/* IDXGIOutput6::GetDesc1 output — the HDR detection structure */
typedef struct {
    WCHAR DeviceName[32];
    INT   DesktopLeft;
    INT   DesktopTop;
    INT   DesktopRight;
    INT   DesktopBottom;
    BOOL  AttachedToDesktop;
    UINT  Rotation;
    HANDLE Monitor;
    /* HDR fields */
    UINT  BitsPerColor;
    DXGI_COLOR_SPACE_TYPE ColorSpace;
    float RedPrimary[2];
    float GreenPrimary[2];
    float BluePrimary[2];
    float WhitePoint[2];
    float MinLuminance;
    float MaxLuminance;
    float MaxFullFrameLuminance;
} DXGI_OUTPUT_DESC1;

typedef struct {
    UINT  Width;
    UINT  Height;
    UINT  RefreshRate_Numerator;
    UINT  RefreshRate_Denominator;
    DXGI_FORMAT Format;
    UINT  ScanlineOrdering;
    UINT  Scaling;
} DXGI_MODE_DESC;

/* ---------- HDR detection via environment ---------- */

/* Check if HDR is enabled by environment or gamescope */
static int hdr_is_enabled(void)
{
    const char *dxvk_hdr = getenv("DXVK_HDR");
    if (dxvk_hdr && dxvk_hdr[0] == '1') return 1;

    const char *proton_hdr = getenv("PROTON_ENABLE_HDR");
    if (proton_hdr && proton_hdr[0] == '1') return 1;

    /* gamescope sets this when running with --hdr-enabled */
    const char *gamescope = getenv("GAMESCOPE_HDR_ENABLED");
    if (gamescope && gamescope[0] == '1') return 1;

    /* Check if running under gamescope at all */
    const char *wayland = getenv("GAMESCOPE_WAYLAND_DISPLAY");
    if (wayland) return 1;

    return 0;
}

/* =================================================================
 * IDXGIOutput / IDXGIOutput6 — monitor output with HDR reporting
 * ================================================================= */

typedef struct IDXGIOutput IDXGIOutput;

typedef struct {
    /* IUnknown */
    __attribute__((ms_abi)) long (*QueryInterface)(IDXGIOutput *, const GUID *, void **);
    __attribute__((ms_abi)) ULONG (*AddRef)(IDXGIOutput *);
    __attribute__((ms_abi)) ULONG (*Release)(IDXGIOutput *);
    /* IDXGIObject */
    __attribute__((ms_abi)) long (*SetPrivateData)(IDXGIOutput *, const GUID *, UINT, const void *);
    __attribute__((ms_abi)) long (*SetPrivateDataInterface)(IDXGIOutput *, const GUID *, const void *);
    __attribute__((ms_abi)) long (*GetPrivateData)(IDXGIOutput *, const GUID *, UINT *, void *);
    __attribute__((ms_abi)) long (*GetParent)(IDXGIOutput *, const GUID *, void **);
    /* IDXGIOutput */
    __attribute__((ms_abi)) long (*GetDesc)(IDXGIOutput *, DXGI_OUTPUT_DESC *);
    __attribute__((ms_abi)) long (*GetDisplayModeList)(IDXGIOutput *, DXGI_FORMAT, UINT, UINT *, DXGI_MODE_DESC *);
    __attribute__((ms_abi)) long (*FindClosestMatchingMode)(IDXGIOutput *, const DXGI_MODE_DESC *, DXGI_MODE_DESC *, void *);
    __attribute__((ms_abi)) long (*WaitForVBlank)(IDXGIOutput *);
    __attribute__((ms_abi)) long (*TakeOwnership)(IDXGIOutput *, void *, BOOL);
    __attribute__((ms_abi)) void (*ReleaseOwnership)(IDXGIOutput *);
    /* IDXGIOutput1-5 gap fillers (we expose IDXGIOutput6 via QI) */
    __attribute__((ms_abi)) long (*GetDisplayModeList1)(IDXGIOutput *, DXGI_FORMAT, UINT, UINT *, void *);
    __attribute__((ms_abi)) long (*FindClosestMatchingMode1)(IDXGIOutput *, const void *, void *, void *);
    __attribute__((ms_abi)) long (*GetDisplaySurfaceData1)(IDXGIOutput *, void *);
    __attribute__((ms_abi)) long (*DuplicateOutput)(IDXGIOutput *, void *, void **);
    /* IDXGIOutput2 */
    __attribute__((ms_abi)) BOOL (*SupportsOverlays)(IDXGIOutput *);
    /* IDXGIOutput3 */
    __attribute__((ms_abi)) long (*CheckOverlaySupport)(IDXGIOutput *, DXGI_FORMAT, void *, UINT *);
    /* IDXGIOutput4 */
    __attribute__((ms_abi)) long (*CheckOverlayColorSpaceSupport)(IDXGIOutput *, DXGI_FORMAT, DXGI_COLOR_SPACE_TYPE, void *, UINT *);
    /* IDXGIOutput5 */
    __attribute__((ms_abi)) long (*DuplicateOutput1)(IDXGIOutput *, void *, UINT, UINT, const DXGI_FORMAT *, void **);
    /* IDXGIOutput6 */
    __attribute__((ms_abi)) long (*GetDesc1)(IDXGIOutput *, DXGI_OUTPUT_DESC1 *);
    __attribute__((ms_abi)) long (*CheckHardwareCompositionSupport)(IDXGIOutput *, UINT *);
} IDXGIOutputVtbl;

struct IDXGIOutput {
    const IDXGIOutputVtbl *lpVtbl;
    volatile ULONG refcount;
};

static const unsigned char IID_IUnknown_bytes[16] = {
    0x00,0x00,0x00,0x00, 0x00,0x00, 0x00,0x00,
    0xC0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46
};

static __attribute__((ms_abi)) long output_qi(IDXGIOutput *self, const GUID *iid, void **ppv)
{
    if (!ppv) return (long)0x80004003; /* E_POINTER */
    *ppv = NULL;
    if (!iid || memcmp(iid, IID_IUnknown_bytes, 16) == 0) {
        *ppv = self;
        __sync_add_and_fetch(&self->refcount, 1);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG output_addref(IDXGIOutput *self) { return __sync_add_and_fetch(&self->refcount, 1); }
static __attribute__((ms_abi)) ULONG output_release(IDXGIOutput *self)
{
    ULONG ref = __sync_sub_and_fetch(&self->refcount, 1);
    if (ref == 0) free(self);
    return ref;
}

static __attribute__((ms_abi)) long output_set_pd(IDXGIOutput *s, const GUID *g, UINT sz, const void *d)
{ (void)s; (void)g; (void)sz; (void)d; return S_OK; }
static __attribute__((ms_abi)) long output_set_pdi(IDXGIOutput *s, const GUID *g, const void *d)
{ (void)s; (void)g; (void)d; return S_OK; }
static __attribute__((ms_abi)) long output_get_pd(IDXGIOutput *s, const GUID *g, UINT *sz, void *d)
{ (void)s; (void)g; (void)sz; (void)d; return E_NOINTERFACE; }
static __attribute__((ms_abi)) long output_get_parent(IDXGIOutput *s, const GUID *g, void **pp)
{ (void)s; (void)g; (void)pp; return E_NOINTERFACE; }

static __attribute__((ms_abi)) long output_get_desc(IDXGIOutput *self, DXGI_OUTPUT_DESC *desc)
{
    (void)self;
    if (!desc) return E_FAIL;
    memset(desc, 0, sizeof(*desc));

    /* Default display name */
    const WCHAR name[] = { '\\','\\','.','\\','D','I','S','P','L','A','Y','1',0 };
    memcpy(desc->DeviceName, name, sizeof(name));
    desc->AttachedToDesktop = TRUE;
    /* 1920x1080 default desktop rect */
    desc->DesktopRight = 1920;
    desc->DesktopBottom = 1080;
    return S_OK;
}

static __attribute__((ms_abi)) long output_get_display_mode_list(IDXGIOutput *self, DXGI_FORMAT fmt,
    UINT flags, UINT *pNumModes, DXGI_MODE_DESC *pDesc)
{
    (void)self; (void)flags;
    if (!pNumModes) return E_FAIL;

    /* Report common modes */
    DXGI_MODE_DESC modes[] = {
        { 1920, 1080, 60, 1, fmt, 0, 0 },
        { 2560, 1440, 60, 1, fmt, 0, 0 },
        { 3840, 2160, 60, 1, fmt, 0, 0 },
        { 1280,  720, 60, 1, fmt, 0, 0 },
    };
    UINT count = sizeof(modes) / sizeof(modes[0]);

    if (!pDesc) {
        *pNumModes = count;
        return S_OK;
    }

    UINT to_copy = (*pNumModes < count) ? *pNumModes : count;
    memcpy(pDesc, modes, to_copy * sizeof(DXGI_MODE_DESC));
    *pNumModes = to_copy;
    return S_OK;
}

static __attribute__((ms_abi)) long output_find_closest(IDXGIOutput *self,
    const DXGI_MODE_DESC *pModeToMatch, DXGI_MODE_DESC *pClosest, void *pDevice)
{
    (void)self; (void)pDevice;
    if (!pModeToMatch || !pClosest) return E_FAIL;
    /* Return the requested mode as-is */
    *pClosest = *pModeToMatch;
    if (pClosest->RefreshRate_Numerator == 0) {
        pClosest->RefreshRate_Numerator = 60;
        pClosest->RefreshRate_Denominator = 1;
    }
    return S_OK;
}

static __attribute__((ms_abi)) long output_wait_vblank(IDXGIOutput *self)
{ (void)self; return S_OK; }
static __attribute__((ms_abi)) long output_take_ownership(IDXGIOutput *self, void *dev, BOOL excl)
{ (void)self; (void)dev; (void)excl; return S_OK; }
static __attribute__((ms_abi)) void output_release_ownership(IDXGIOutput *self)
{ (void)self; }

/* IDXGIOutput1 stubs */
static __attribute__((ms_abi)) long output_get_display_mode_list1(IDXGIOutput *s, DXGI_FORMAT f, UINT fl, UINT *n, void *d)
{ (void)s; (void)f; (void)fl; if (n) *n = 0; (void)d; return S_OK; }
static __attribute__((ms_abi)) long output_find_closest1(IDXGIOutput *s, const void *m, void *c, void *d)
{ (void)s; (void)m; (void)c; (void)d; return E_NOINTERFACE; }
static __attribute__((ms_abi)) long output_get_surface_data1(IDXGIOutput *s, void *d)
{ (void)s; (void)d; return E_NOINTERFACE; }
static __attribute__((ms_abi)) long output_dup_output(IDXGIOutput *s, void *d, void **o)
{ (void)s; (void)d; (void)o; return E_NOINTERFACE; }

/* IDXGIOutput2 */
static __attribute__((ms_abi)) BOOL output_supports_overlays(IDXGIOutput *s)
{ (void)s; return FALSE; }

/* IDXGIOutput3 */
static __attribute__((ms_abi)) long output_check_overlay(IDXGIOutput *s, DXGI_FORMAT f, void *d, UINT *fl)
{ (void)s; (void)f; (void)d; if (fl) *fl = 0; return S_OK; }

/* IDXGIOutput4 */
static __attribute__((ms_abi)) long output_check_overlay_cs(IDXGIOutput *s, DXGI_FORMAT f,
    DXGI_COLOR_SPACE_TYPE cs, void *d, UINT *fl)
{ (void)s; (void)f; (void)cs; (void)d; if (fl) *fl = 0; return S_OK; }

/* IDXGIOutput5 */
static __attribute__((ms_abi)) long output_dup_output1(IDXGIOutput *s, void *d, UINT u, UINT n,
    const DXGI_FORMAT *f, void **o)
{ (void)s; (void)d; (void)u; (void)n; (void)f; (void)o; return E_NOINTERFACE; }

/*
 * IDXGIOutput6::GetDesc1 — THE critical HDR detection function
 *
 * Games call this to check if the monitor supports HDR.
 * When DXVK_HDR=1 or running under gamescope --hdr-enabled,
 * we report HDR10 capability with BT.2020 primaries.
 */
static __attribute__((ms_abi)) long output_get_desc1(IDXGIOutput *self, DXGI_OUTPUT_DESC1 *desc)
{
    (void)self;
    if (!desc) return E_FAIL;
    memset(desc, 0, sizeof(*desc));

    /* Base output info */
    const WCHAR name[] = { '\\','\\','.','\\','D','I','S','P','L','A','Y','1',0 };
    memcpy(desc->DeviceName, name, sizeof(name));
    desc->AttachedToDesktop = TRUE;
    desc->DesktopRight = 1920;
    desc->DesktopBottom = 1080;

    if (hdr_is_enabled()) {
        /* Warn about NVIDIA+X11 HDR limitations (Vulkan HDR requires
         * VK_EXT_swapchain_colorspace which NVIDIA stable drivers lack on Linux).
         * We still report HDR to the game — DXVK will gracefully fall back to
         * SDR swapchain if the Vulkan extension isn't available. This avoids
         * breaking games that gate content behind GetDesc1 HDR checks. */
        if (!g_gpu_detected) { detect_gpu(&g_gpu_cache); g_gpu_detected = 1; }
        if (g_gpu_cache.vendor_id == 0x10DE && !getenv("GAMESCOPE_WAYLAND_DISPLAY"))
            fprintf(stderr, LOG_PREFIX "GetDesc1: NVIDIA+X11 detected — Vulkan HDR may not be available "
                    "(VK_EXT_swapchain_colorspace requires Wayland or gamescope). "
                    "DXVK will fall back to SDR swapchain.\n");
        fprintf(stderr, LOG_PREFIX "GetDesc1: reporting HDR10 capable output\n");

        desc->BitsPerColor = 10;
        desc->ColorSpace = DXGI_COLOR_SPACE_RGB_FULL_G2084_NONE_P2020;

        /* BT.2020 color primaries (wider gamut than sRGB) */
        desc->RedPrimary[0]   = 0.708f;   desc->RedPrimary[1]   = 0.292f;
        desc->GreenPrimary[0] = 0.170f;   desc->GreenPrimary[1] = 0.797f;
        desc->BluePrimary[0]  = 0.131f;   desc->BluePrimary[1]  = 0.046f;
        desc->WhitePoint[0]   = 0.3127f;  desc->WhitePoint[1]   = 0.3290f;  /* D65 */

        /* Luminance range (typical HDR display) */
        desc->MinLuminance          = 0.001f;   /* 0.001 nits (deep blacks) */
        desc->MaxLuminance          = 1000.0f;  /* 1000 nits peak */
        desc->MaxFullFrameLuminance = 600.0f;   /* 600 nits sustained */
    } else {
        fprintf(stderr, LOG_PREFIX "GetDesc1: SDR output (set DXVK_HDR=1 for HDR)\n");

        desc->BitsPerColor = 8;
        desc->ColorSpace = DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709;

        /* sRGB / BT.709 primaries */
        desc->RedPrimary[0]   = 0.640f;   desc->RedPrimary[1]   = 0.330f;
        desc->GreenPrimary[0] = 0.300f;   desc->GreenPrimary[1] = 0.600f;
        desc->BluePrimary[0]  = 0.150f;   desc->BluePrimary[1]  = 0.060f;
        desc->WhitePoint[0]   = 0.3127f;  desc->WhitePoint[1]   = 0.3290f;

        desc->MinLuminance          = 0.5f;
        desc->MaxLuminance          = 270.0f;
        desc->MaxFullFrameLuminance = 270.0f;
    }

    return S_OK;
}

static __attribute__((ms_abi)) long output_check_hw_composition(IDXGIOutput *self, UINT *pFlags)
{
    (void)self;
    if (pFlags) *pFlags = 0;
    return S_OK;
}

static const IDXGIOutputVtbl g_output_vtbl = {
    .QueryInterface         = output_qi,
    .AddRef                 = output_addref,
    .Release                = output_release,
    .SetPrivateData         = output_set_pd,
    .SetPrivateDataInterface = output_set_pdi,
    .GetPrivateData         = output_get_pd,
    .GetParent              = output_get_parent,
    .GetDesc                = output_get_desc,
    .GetDisplayModeList     = output_get_display_mode_list,
    .FindClosestMatchingMode = output_find_closest,
    .WaitForVBlank          = output_wait_vblank,
    .TakeOwnership          = output_take_ownership,
    .ReleaseOwnership       = output_release_ownership,
    .GetDisplayModeList1    = output_get_display_mode_list1,
    .FindClosestMatchingMode1 = output_find_closest1,
    .GetDisplaySurfaceData1 = output_get_surface_data1,
    .DuplicateOutput        = output_dup_output,
    .SupportsOverlays       = output_supports_overlays,
    .CheckOverlaySupport    = output_check_overlay,
    .CheckOverlayColorSpaceSupport = output_check_overlay_cs,
    .DuplicateOutput1       = output_dup_output1,
    .GetDesc1               = output_get_desc1,
    .CheckHardwareCompositionSupport = output_check_hw_composition,
};

static IDXGIOutput *create_output(void)
{
    IDXGIOutput *out = calloc(1, sizeof(IDXGIOutput));
    if (!out) return NULL;
    out->lpVtbl = &g_output_vtbl;
    out->refcount = 1;
    return out;
}

/* =================================================================
 * IDXGIAdapter — GPU adapter with output enumeration
 * ================================================================= */

typedef struct IDXGIAdapter IDXGIAdapter;

typedef struct {
    __attribute__((ms_abi)) long (*QueryInterface)(IDXGIAdapter *, const GUID *, void **);
    __attribute__((ms_abi)) ULONG (*AddRef)(IDXGIAdapter *);
    __attribute__((ms_abi)) ULONG (*Release)(IDXGIAdapter *);
    /* IDXGIObject */
    __attribute__((ms_abi)) long (*SetPrivateData)(IDXGIAdapter *, const GUID *, UINT, const void *);
    __attribute__((ms_abi)) long (*SetPrivateDataInterface)(IDXGIAdapter *, const GUID *, const void *);
    __attribute__((ms_abi)) long (*GetPrivateData)(IDXGIAdapter *, const GUID *, UINT *, void *);
    __attribute__((ms_abi)) long (*GetParent)(IDXGIAdapter *, const GUID *, void **);
    /* IDXGIAdapter */
    __attribute__((ms_abi)) long (*EnumOutputs)(IDXGIAdapter *, UINT, void **);
    __attribute__((ms_abi)) long (*GetDesc)(IDXGIAdapter *, DXGI_ADAPTER_DESC *);
    __attribute__((ms_abi)) long (*CheckInterfaceSupport)(IDXGIAdapter *, const GUID *, void *);
} IDXGIAdapterVtbl;

struct IDXGIAdapter {
    const IDXGIAdapterVtbl *lpVtbl;
    volatile ULONG refcount;
};

static __attribute__((ms_abi)) long adapter_qi(IDXGIAdapter *self, const GUID *iid, void **ppv)
{
    if (!ppv) return (long)0x80004003; /* E_POINTER */
    *ppv = NULL;
    if (!iid || memcmp(iid, IID_IUnknown_bytes, 16) == 0) {
        *ppv = self;
        __sync_add_and_fetch(&self->refcount, 1);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG adapter_addref(IDXGIAdapter *self) { return __sync_add_and_fetch(&self->refcount, 1); }
static __attribute__((ms_abi)) ULONG adapter_release(IDXGIAdapter *self)
{
    ULONG ref = __sync_sub_and_fetch(&self->refcount, 1);
    if (ref == 0) free(self);
    return ref;
}

static __attribute__((ms_abi)) long adapter_set_pd(IDXGIAdapter *s, const GUID *g, UINT sz, const void *d)
{ (void)s; (void)g; (void)sz; (void)d; return S_OK; }
static __attribute__((ms_abi)) long adapter_set_pdi(IDXGIAdapter *s, const GUID *g, const void *d)
{ (void)s; (void)g; (void)d; return S_OK; }
static __attribute__((ms_abi)) long adapter_get_pd(IDXGIAdapter *s, const GUID *g, UINT *sz, void *d)
{ (void)s; (void)g; (void)sz; (void)d; return E_NOINTERFACE; }
static __attribute__((ms_abi)) long adapter_get_parent(IDXGIAdapter *s, const GUID *g, void **pp)
{ (void)s; (void)g; (void)pp; return E_NOINTERFACE; }

static __attribute__((ms_abi)) long adapter_enum_outputs(IDXGIAdapter *self, UINT output_idx, void **ppOutput)
{
    (void)self;
    if (output_idx > 0) {
        if (ppOutput) *ppOutput = NULL;
        return DXGI_ERROR_NOT_FOUND;
    }

    /* Return our HDR-capable output for index 0 */
    IDXGIOutput *out = create_output();
    if (!out) return E_FAIL;
    if (ppOutput) *ppOutput = out;

    fprintf(stderr, LOG_PREFIX "EnumOutputs(0): returning HDR-aware output\n");
    return S_OK;
}

/*
 * Auto-detect GPU vendor/device from /sys/bus/pci/devices.
 * This ensures games and DXVK see the correct GPU identity,
 * which is critical for HDR codepaths and vendor-specific quirks.
 */
static void detect_gpu(gpu_info_t *info)
{
    memset(info, 0, sizeof(*info));

    DIR *dir = opendir("/sys/bus/pci/devices");
    if (!dir) goto fallback;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char path[512];
        FILE *f;

        /* Check PCI class — 0x030000 = VGA controller, 0x030200 = 3D controller */
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/class", ent->d_name);
        f = fopen(path, "r");
        if (!f) continue;
        unsigned long pci_class = 0;
        if (fscanf(f, "%lx", &pci_class) != 1) pci_class = 0;
        fclose(f);

        if ((pci_class >> 8) != 0x0300 && (pci_class >> 8) != 0x0302)
            continue;

        /* Read vendor */
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/vendor", ent->d_name);
        f = fopen(path, "r");
        if (!f) continue;
        unsigned int vid = 0;
        if (fscanf(f, "%x", &vid) != 1) vid = 0;
        fclose(f);

        /* Read device */
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/device", ent->d_name);
        f = fopen(path, "r");
        if (!f) continue;
        unsigned int did = 0;
        if (fscanf(f, "%x", &did) != 1) did = 0;
        fclose(f);

        /* Prefer discrete GPU (NVIDIA 0x10DE, AMD 0x1002) over integrated */
        if (info->found && vid != 0x10DE && vid != 0x1002)
            continue;

        info->vendor_id = vid;
        info->device_id = did;
        info->found = 1;

        /* Try to read VRAM size from resource (BAR 0 or 1) */
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/resource", ent->d_name);
        f = fopen(path, "r");
        if (f) {
            /* Each line: start end flags — VRAM is typically the largest BAR */
            unsigned long long start, end, flags;
            SIZE_T largest = 0;
            while (fscanf(f, "%llx %llx %llx", &start, &end, &flags) == 3) {
                if (end > start) {
                    SIZE_T sz = (SIZE_T)(end - start + 1);
                    if (sz > largest) largest = sz;
                }
            }
            fclose(f);
            if (largest > info->vram_bytes) info->vram_bytes = largest;
        }

        /* Set a human-readable GPU name based on vendor */
        if (vid == 0x10DE) {
            snprintf(info->name, sizeof(info->name), "NVIDIA GeForce (Device 0x%04X)", did);
            break; /* Prefer NVIDIA discrete, stop searching */
        } else if (vid == 0x1002) {
            snprintf(info->name, sizeof(info->name), "AMD Radeon (Device 0x%04X)", did);
            break; /* Prefer AMD discrete, stop searching */
        } else if (vid == 0x8086) {
            snprintf(info->name, sizeof(info->name), "Intel Graphics (Device 0x%04X)", did);
            /* Don't break — keep looking for discrete GPU */
        }
    }
    closedir(dir);

    if (info->found) {
        fprintf(stderr, LOG_PREFIX "Detected GPU: vendor=0x%04X device=0x%04X vram=%zuMB\n",
                info->vendor_id, info->device_id,
                (size_t)(info->vram_bytes / (1024 * 1024)));
        return;
    }

fallback:
    fprintf(stderr, LOG_PREFIX "GPU auto-detect failed, using generic adapter\n");
    info->vendor_id = 0x1002;
    info->device_id = 0x73BF;
    info->vram_bytes = (SIZE_T)4ULL * 1024 * 1024 * 1024;
    snprintf(info->name, sizeof(info->name), "Vulkan Compatible GPU (PE Loader)");
    info->found = 1;
}


static __attribute__((ms_abi)) long adapter_get_desc(IDXGIAdapter *self, DXGI_ADAPTER_DESC *desc)
{
    (void)self;
    if (!desc) return E_FAIL;
    memset(desc, 0, sizeof(*desc));

    /* Auto-detect GPU on first call, cache result */
    if (!g_gpu_detected) {
        detect_gpu(&g_gpu_cache);
        g_gpu_detected = 1;
    }

    /* Copy GPU name as WCHAR */
    for (int i = 0; i < 127 && g_gpu_cache.name[i]; i++)
        desc->Description[i] = (WCHAR)g_gpu_cache.name[i];

    desc->VendorId = g_gpu_cache.vendor_id;
    desc->DeviceId = g_gpu_cache.device_id;
    desc->DedicatedVideoMemory = g_gpu_cache.vram_bytes ? g_gpu_cache.vram_bytes
                                  : (SIZE_T)4ULL * 1024 * 1024 * 1024;
    desc->SharedSystemMemory = (SIZE_T)8ULL * 1024 * 1024 * 1024;
    desc->AdapterLuid_LowPart = 0x1001;
    return S_OK;
}

static __attribute__((ms_abi)) long adapter_check_iface(IDXGIAdapter *self, const GUID *iid, void *ver)
{
    (void)self; (void)iid; (void)ver;
    return S_OK;
}

static const IDXGIAdapterVtbl g_adapter_vtbl = {
    .QueryInterface         = adapter_qi,
    .AddRef                 = adapter_addref,
    .Release                = adapter_release,
    .SetPrivateData         = adapter_set_pd,
    .SetPrivateDataInterface = adapter_set_pdi,
    .GetPrivateData         = adapter_get_pd,
    .GetParent              = adapter_get_parent,
    .EnumOutputs            = adapter_enum_outputs,
    .GetDesc                = adapter_get_desc,
    .CheckInterfaceSupport  = adapter_check_iface,
};

static IDXGIAdapter *create_adapter(void)
{
    IDXGIAdapter *adapter = calloc(1, sizeof(IDXGIAdapter));
    if (!adapter) return NULL;
    adapter->lpVtbl = &g_adapter_vtbl;
    adapter->refcount = 1;
    return adapter;
}

/* =================================================================
 * IDXGIFactory — factory with adapter enumeration
 * ================================================================= */

typedef struct IDXGIFactory IDXGIFactory;

typedef struct {
    __attribute__((ms_abi)) long (*QueryInterface)(IDXGIFactory *, const GUID *, void **);
    __attribute__((ms_abi)) ULONG (*AddRef)(IDXGIFactory *);
    __attribute__((ms_abi)) ULONG (*Release)(IDXGIFactory *);
    /* IDXGIObject */
    __attribute__((ms_abi)) long (*SetPrivateData)(IDXGIFactory *, const GUID *, UINT, const void *);
    __attribute__((ms_abi)) long (*SetPrivateDataInterface)(IDXGIFactory *, const GUID *, const void *);
    __attribute__((ms_abi)) long (*GetPrivateData)(IDXGIFactory *, const GUID *, UINT *, void *);
    __attribute__((ms_abi)) long (*GetParent)(IDXGIFactory *, const GUID *, void **);
    /* IDXGIFactory */
    __attribute__((ms_abi)) long (*EnumAdapters)(IDXGIFactory *, UINT, void **);
    __attribute__((ms_abi)) long (*MakeWindowAssociation)(IDXGIFactory *, HANDLE, UINT);
    __attribute__((ms_abi)) long (*GetWindowAssociation)(IDXGIFactory *, HANDLE *);
    __attribute__((ms_abi)) long (*CreateSwapChain)(IDXGIFactory *, void *, void *, void **);
    __attribute__((ms_abi)) long (*CreateSoftwareAdapter)(IDXGIFactory *, HANDLE, void **);
} IDXGIFactoryVtbl;

struct IDXGIFactory {
    const IDXGIFactoryVtbl *lpVtbl;
    volatile ULONG refcount;
};

static __attribute__((ms_abi)) long factory_qi(IDXGIFactory *self, const GUID *iid, void **ppv)
{
    if (!ppv) return (long)0x80004003; /* E_POINTER */
    *ppv = NULL;
    if (!iid || memcmp(iid, IID_IUnknown_bytes, 16) == 0) {
        *ppv = self;
        __sync_add_and_fetch(&self->refcount, 1);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG factory_addref(IDXGIFactory *self) { return __sync_add_and_fetch(&self->refcount, 1); }
static __attribute__((ms_abi)) ULONG factory_release(IDXGIFactory *self)
{
    ULONG ref = __sync_sub_and_fetch(&self->refcount, 1);
    if (ref == 0) free(self);
    return ref;
}

static __attribute__((ms_abi)) long factory_set_pd(IDXGIFactory *s, const GUID *g, UINT sz, const void *d)
{ (void)s; (void)g; (void)sz; (void)d; return S_OK; }
static __attribute__((ms_abi)) long factory_set_pdi(IDXGIFactory *s, const GUID *g, const void *d)
{ (void)s; (void)g; (void)d; return S_OK; }
static __attribute__((ms_abi)) long factory_get_pd(IDXGIFactory *s, const GUID *g, UINT *sz, void *d)
{ (void)s; (void)g; (void)sz; (void)d; return E_NOINTERFACE; }
static __attribute__((ms_abi)) long factory_get_parent(IDXGIFactory *s, const GUID *g, void **pp)
{ (void)s; (void)g; (void)pp; return E_NOINTERFACE; }

static __attribute__((ms_abi)) long factory_enum_adapters(IDXGIFactory *self, UINT adapter_idx, void **ppAdapter)
{
    (void)self;
    if (adapter_idx > 0) {
        if (ppAdapter) *ppAdapter = NULL;
        return DXGI_ERROR_NOT_FOUND;
    }

    IDXGIAdapter *adapter = create_adapter();
    if (!adapter) return E_FAIL;
    if (ppAdapter) *ppAdapter = adapter;

    fprintf(stderr, LOG_PREFIX "EnumAdapters(0): returning Vulkan-compatible adapter\n");
    return S_OK;
}

static __attribute__((ms_abi)) long factory_mwa(IDXGIFactory *s, HANDLE w, UINT f)
{ (void)s; (void)w; (void)f; return S_OK; }
static __attribute__((ms_abi)) long factory_gwa(IDXGIFactory *s, HANDLE *w)
{ (void)s; if (w) *w = NULL; return S_OK; }

static __attribute__((ms_abi)) long factory_create_sc(IDXGIFactory *s, void *dev, void *desc, void **sc)
{
    (void)s; (void)dev; (void)desc;
    fprintf(stderr, LOG_PREFIX "CreateSwapChain: not available (stub — use DXVK for rendering)\n");
    if (sc) *sc = NULL;
    return (long)0x887A0001; /* DXGI_ERROR_INVALID_CALL */
}

static __attribute__((ms_abi)) long factory_create_sw(IDXGIFactory *s, HANDLE m, void **a)
{
    (void)s; (void)m; (void)a;
    return E_NOINTERFACE;
}

static const IDXGIFactoryVtbl g_factory_vtbl = {
    .QueryInterface         = factory_qi,
    .AddRef                 = factory_addref,
    .Release                = factory_release,
    .SetPrivateData         = factory_set_pd,
    .SetPrivateDataInterface = factory_set_pdi,
    .GetPrivateData         = factory_get_pd,
    .GetParent              = factory_get_parent,
    .EnumAdapters           = factory_enum_adapters,
    .MakeWindowAssociation  = factory_mwa,
    .GetWindowAssociation   = factory_gwa,
    .CreateSwapChain        = factory_create_sc,
    .CreateSoftwareAdapter  = factory_create_sw,
};

/* =================================================================
 * DXVK forwarding + factory creation
 * ================================================================= */

void *g_dxvk_dxgi = NULL;
int g_dxvk_dxgi_tried = 0;

static void dxgi_try_dxvk(void)
{
    if (g_dxvk_dxgi_tried) return;
    g_dxvk_dxgi_tried = 1;

    const char *paths[] = {
        "dxgi.so",
        "/usr/lib/dxvk/dxgi.so",
        "/usr/lib/x86_64-linux-gnu/dxvk/dxgi.so",
        "/usr/lib64/dxvk/dxgi.so",
        "/opt/dxvk/lib/dxgi.so",
        "./dlls/dxvk/dxgi.so",
        NULL
    };
    for (int i = 0; paths[i]; i++) {
        g_dxvk_dxgi = dlopen(paths[i], RTLD_NOW | RTLD_GLOBAL);
        if (g_dxvk_dxgi) {
            fprintf(stderr, LOG_PREFIX "DXVK DXGI loaded from %s\n", paths[i]);
            return;
        }
    }
    fprintf(stderr, LOG_PREFIX "DXVK not found - using stub DXGI (HDR via stubs)\n");
}

WINAPI_EXPORT long CreateDXGIFactory(const GUID *riid, void **ppFactory)
{
    dxgi_try_dxvk();

    if (g_dxvk_dxgi) {
        typedef long (__attribute__((ms_abi)) *create_fn)(const GUID *, void **);
        create_fn fn = (create_fn)dlsym(g_dxvk_dxgi, "CreateDXGIFactory");
        if (fn) {
            fprintf(stderr, LOG_PREFIX "Forwarding CreateDXGIFactory to DXVK\n");
            return fn(riid, ppFactory);
        }
    }

    fprintf(stderr, LOG_PREFIX "Using stub DXGI factory (with HDR output)\n");
    if (!ppFactory) return E_INVALIDARG;
    IDXGIFactory *factory = calloc(1, sizeof(IDXGIFactory));
    if (!factory) return E_OUTOFMEMORY;
    factory->lpVtbl = &g_factory_vtbl;
    factory->refcount = 1;
    *ppFactory = factory;
    return S_OK;
}

WINAPI_EXPORT long CreateDXGIFactory1(const GUID *riid, void **ppFactory)
{
    dxgi_try_dxvk();

    if (g_dxvk_dxgi) {
        typedef long (__attribute__((ms_abi)) *create_fn)(const GUID *, void **);
        create_fn fn = (create_fn)dlsym(g_dxvk_dxgi, "CreateDXGIFactory1");
        if (fn) {
            fprintf(stderr, LOG_PREFIX "Forwarding CreateDXGIFactory1 to DXVK\n");
            return fn(riid, ppFactory);
        }
    }

    return CreateDXGIFactory(riid, ppFactory);
}

WINAPI_EXPORT long CreateDXGIFactory2(UINT Flags, const GUID *riid, void **ppFactory)
{
    dxgi_try_dxvk();

    if (g_dxvk_dxgi) {
        typedef long (__attribute__((ms_abi)) *create_fn)(UINT, const GUID *, void **);
        create_fn fn = (create_fn)dlsym(g_dxvk_dxgi, "CreateDXGIFactory2");
        if (fn) {
            fprintf(stderr, LOG_PREFIX "Forwarding CreateDXGIFactory2 to DXVK\n");
            return fn(Flags, riid, ppFactory);
        }
    }

    (void)Flags;
    return CreateDXGIFactory(riid, ppFactory);
}

/*
 * dxgi_cleanup - Release the DXVK DXGI dlopen handle at process exit.
 */
__attribute__((destructor))
void dxgi_cleanup(void)
{
    if (g_dxvk_dxgi) {
        dlclose(g_dxvk_dxgi);
        g_dxvk_dxgi = NULL;
        g_dxvk_dxgi_tried = 0;
    }
}
