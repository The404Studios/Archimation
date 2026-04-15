/*
 * d3d9_device.c - Direct3D 9 minimal implementation
 *
 * COM vtables for IDirect3D9 and IDirect3DDevice9.
 * First tries to dlopen DXVK's d3d9.so, falls back to stubs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>

#include "common/dll_common.h"

#define LOG_PREFIX "[d3d9] "

/* Forward: dxgi_factory.c exposes Vulkan-capability detection. Used by the
 * software fallback path so we can return E_NOTIMPL cleanly on pre-Vulkan HW
 * (GT218, pre-GCN Radeon) instead of pretending support exists. */
extern int dxgi_gpu_is_vulkan_capable(void) __attribute__((weak));

/* COM IIDs - GUID is defined in windef.h */
typedef GUID IID;

/* HRESULT values */
#define D3D_OK          0
#define D3DERR_NOTAVAILABLE  ((long)0x8876086A)
#define E_NOTIMPL       ((long)0x80004001)
#define E_NOINTERFACE   ((long)0x80004002)
#define E_POINTER       ((long)0x80004003)
#define S_OK            0

/* Forward declarations */
typedef struct IDirect3D9 IDirect3D9;
typedef struct IDirect3DDevice9 IDirect3DDevice9;

/* ========== IDirect3D9 vtable ========== */

typedef struct {
    /* IUnknown */
    __attribute__((ms_abi)) long (*QueryInterface)(IDirect3D9 *, const IID *, void **);
    __attribute__((ms_abi)) ULONG (*AddRef)(IDirect3D9 *);
    __attribute__((ms_abi)) ULONG (*Release)(IDirect3D9 *);
    /* IDirect3D9 */
    __attribute__((ms_abi)) long (*RegisterSoftwareDevice)(IDirect3D9 *, void *);
    __attribute__((ms_abi)) UINT (*GetAdapterCount)(IDirect3D9 *);
    __attribute__((ms_abi)) long (*GetAdapterIdentifier)(IDirect3D9 *, UINT, DWORD, void *);
    __attribute__((ms_abi)) UINT (*GetAdapterModeCount)(IDirect3D9 *, UINT, DWORD);
    __attribute__((ms_abi)) long (*EnumAdapterModes)(IDirect3D9 *, UINT, DWORD, UINT, void *);
    __attribute__((ms_abi)) long (*GetAdapterDisplayMode)(IDirect3D9 *, UINT, void *);
    __attribute__((ms_abi)) long (*CheckDeviceType)(IDirect3D9 *, UINT, DWORD, DWORD, DWORD, BOOL);
    __attribute__((ms_abi)) long (*CheckDeviceFormat)(IDirect3D9 *, UINT, DWORD, DWORD, DWORD, DWORD, DWORD);
    __attribute__((ms_abi)) long (*CheckDeviceMultiSampleType)(IDirect3D9 *, UINT, DWORD, DWORD, BOOL, DWORD, DWORD *);
    __attribute__((ms_abi)) long (*CheckDepthStencilMatch)(IDirect3D9 *, UINT, DWORD, DWORD, DWORD, DWORD);
    __attribute__((ms_abi)) long (*CheckDeviceFormatConversion)(IDirect3D9 *, UINT, DWORD, DWORD, DWORD);
    __attribute__((ms_abi)) long (*GetDeviceCaps)(IDirect3D9 *, UINT, DWORD, void *);
    __attribute__((ms_abi)) HANDLE (*GetAdapterMonitor)(IDirect3D9 *, UINT);
    __attribute__((ms_abi)) long (*CreateDevice)(IDirect3D9 *, UINT, DWORD, HANDLE, DWORD, void *, IDirect3DDevice9 **);
} IDirect3D9Vtbl;

struct IDirect3D9 {
    const IDirect3D9Vtbl *lpVtbl;
    volatile ULONG refcount;
};

/* IDirect3D9 implementations */
static const unsigned char IID_IUnknown_bytes[16] = {
    0x00,0x00,0x00,0x00, 0x00,0x00, 0x00,0x00,
    0xC0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46
};

static __attribute__((ms_abi)) long d3d9_qi(IDirect3D9 *self, const IID *iid, void **ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (!iid || memcmp(iid, IID_IUnknown_bytes, 16) == 0) {
        *ppv = self;
        __sync_add_and_fetch(&self->refcount, 1);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG d3d9_addref(IDirect3D9 *self) { return __sync_add_and_fetch(&self->refcount, 1); }
static __attribute__((ms_abi)) ULONG d3d9_release(IDirect3D9 *self)
{
    ULONG ref = __sync_sub_and_fetch(&self->refcount, 1);
    if (ref == 0) free(self);
    return ref;
}

static __attribute__((ms_abi)) UINT d3d9_get_adapter_count(IDirect3D9 *self) { (void)self; return 1; }

static __attribute__((ms_abi)) long d3d9_get_adapter_identifier(IDirect3D9 *self, UINT adapter, DWORD flags, void *ident)
{
    (void)self; (void)adapter; (void)flags;
    if (ident) {
        memset(ident, 0, 536); /* sizeof(D3DADAPTER_IDENTIFIER9) */
        strncpy(ident, "PE-Compat Display Adapter", 259);
        strncpy((char *)ident + 260, "PE-Compat D3D9 Driver", 259);
    }
    return D3D_OK;
}

static __attribute__((ms_abi)) UINT d3d9_get_adapter_mode_count(IDirect3D9 *self, UINT a, DWORD f)
{
    (void)self; (void)a; (void)f;
    return 1;
}

static __attribute__((ms_abi)) long d3d9_enum_adapter_modes(IDirect3D9 *self, UINT a, DWORD f, UINT m, void *mode)
{
    (void)self; (void)a; (void)f; (void)m;
    if (mode) {
        memset(mode, 0, 16);
        *(UINT *)mode = 1920;
        *((UINT *)mode + 1) = 1080;
        *((UINT *)mode + 2) = 60;
        *((UINT *)mode + 3) = 22; /* D3DFMT_X8R8G8B8 */
    }
    return D3D_OK;
}

static __attribute__((ms_abi)) long d3d9_get_display_mode(IDirect3D9 *self, UINT a, void *mode)
{
    return d3d9_enum_adapter_modes(self, a, 0, 0, mode);
}

static __attribute__((ms_abi)) long d3d9_check_device_type(IDirect3D9 *s, UINT a, DWORD dt, DWORD bt, DWORD bb, BOOL w)
{
    (void)s; (void)a; (void)dt; (void)bt; (void)bb; (void)w;
    return D3D_OK;
}

static __attribute__((ms_abi)) long d3d9_check_device_format(IDirect3D9 *s, UINT a, DWORD dt, DWORD at, DWORD u, DWORD rt, DWORD cf)
{
    (void)s; (void)a; (void)dt; (void)at; (void)u; (void)rt; (void)cf;
    return D3D_OK;
}

static __attribute__((ms_abi)) long d3d9_check_ms(IDirect3D9 *s, UINT a, DWORD dt, DWORD sf, BOOL w, DWORD mt, DWORD *q)
{
    (void)s; (void)a; (void)dt; (void)sf; (void)w; (void)mt;
    if (q) *q = 0;
    return D3D_OK;
}

static __attribute__((ms_abi)) long d3d9_check_ds(IDirect3D9 *s, UINT a, DWORD dt, DWORD at, DWORD rt, DWORD ds)
{
    (void)s; (void)a; (void)dt; (void)at; (void)rt; (void)ds;
    return D3D_OK;
}

static __attribute__((ms_abi)) long d3d9_check_fc(IDirect3D9 *s, UINT a, DWORD dt, DWORD sf, DWORD tf)
{
    (void)s; (void)a; (void)dt; (void)sf; (void)tf;
    return D3D_OK;
}

static __attribute__((ms_abi)) long d3d9_get_device_caps(IDirect3D9 *s, UINT a, DWORD dt, void *caps)
{
    (void)s; (void)a; (void)dt;
    if (caps) memset(caps, 0, 304); /* sizeof(D3DCAPS9) */
    return D3D_OK;
}

static __attribute__((ms_abi)) HANDLE d3d9_get_adapter_monitor(IDirect3D9 *s, UINT a)
{
    (void)s; (void)a;
    return (HANDLE)(uintptr_t)0xA0001;
}

static __attribute__((ms_abi)) long d3d9_register_sw(IDirect3D9 *s, void *p) { (void)s; (void)p; return D3D_OK; }

/* Simple D3DDevice9 stub. On pre-Vulkan HW (GT218 / pre-GCN Radeon) we must
 * return a well-defined error so the app can display "GPU not supported"
 * instead of crashing deep inside a NULL-device callchain. Other paths
 * reach DXVK via the real Direct3DCreate9 fork below. */
static __attribute__((ms_abi)) long d3d9_create_device(IDirect3D9 *self, UINT adapter, DWORD devtype,
                                HANDLE focus, DWORD behavior, void *pp, IDirect3DDevice9 **ppdev)
{
    (void)self; (void)adapter; (void)devtype; (void)focus; (void)behavior; (void)pp;
    if (!ppdev) return E_POINTER;
    *ppdev = NULL;

    /* Dual-HW policy: pre-Vulkan HW gets explicit E_NOTIMPL (apps handle it
     * gracefully). Vulkan-capable HW without DXVK installed gets the legacy
     * D3DERR_NOTAVAILABLE so DX9-only apps suggest installing the runtime. */
    if (dxgi_gpu_is_vulkan_capable && !dxgi_gpu_is_vulkan_capable()) {
        fprintf(stderr, LOG_PREFIX "CreateDevice: pre-Vulkan GPU (GT218/pre-GCN), returning E_NOTIMPL\n");
        return E_NOTIMPL;
    }
    fprintf(stderr, LOG_PREFIX "CreateDevice: no GPU device available (DXVK not loaded)\n");
    return D3DERR_NOTAVAILABLE;
}

static const IDirect3D9Vtbl g_d3d9_vtbl = {
    .QueryInterface = d3d9_qi,
    .AddRef = d3d9_addref,
    .Release = d3d9_release,
    .RegisterSoftwareDevice = d3d9_register_sw,
    .GetAdapterCount = d3d9_get_adapter_count,
    .GetAdapterIdentifier = d3d9_get_adapter_identifier,
    .GetAdapterModeCount = d3d9_get_adapter_mode_count,
    .EnumAdapterModes = d3d9_enum_adapter_modes,
    .GetAdapterDisplayMode = d3d9_get_display_mode,
    .CheckDeviceType = d3d9_check_device_type,
    .CheckDeviceFormat = d3d9_check_device_format,
    .CheckDeviceMultiSampleType = d3d9_check_ms,
    .CheckDepthStencilMatch = d3d9_check_ds,
    .CheckDeviceFormatConversion = d3d9_check_fc,
    .GetDeviceCaps = d3d9_get_device_caps,
    .GetAdapterMonitor = d3d9_get_adapter_monitor,
    .CreateDevice = d3d9_create_device,
};

/* ========== Direct3DCreate9 ========== */

/* Shared with d3d_stubs.c (which uses g_dxvk_tried flag). Kept as a plain
 * int + pthread_once for consistency with Session 30's d3d11/d3d12 fix.
 * g_dxvk_tried is still exposed (extern in d3d_stubs.c) so the older get_dxvk_d3d9
 * helper observes the load; we guard the actual dlopen with a pthread_once to
 * avoid the startup thundering-herd race the plain flag had. */
void *g_dxvk_d3d9 = NULL;
int g_dxvk_tried = 0;
static pthread_once_t g_dxvk_d3d9_once = PTHREAD_ONCE_INIT;
/* Cached Direct3DCreate9 function pointer inside DXVK's d3d9.so: resolved
 * once so the per-call hot path becomes a single indirect CALL instead of
 * dlsym() (which scans hash tables). dlsym under glibc takes ~hundreds of
 * ns; on Present-heavy init patterns this saved real frame time. */
static IDirect3D9 *(__attribute__((ms_abi)) *g_dxvk_create9_fn)(UINT) = NULL;
/* Log-once guards to keep per-call stderr clean (some apps call Create9 per
 * screen-change). */
static int g_dxvk_logged = 0;
static int g_stub_logged = 0;

static void dxvk_d3d9_probe_once(void)
{
    g_dxvk_tried = 1;
    g_dxvk_d3d9 = dlopen("d3d9.so", RTLD_NOW);
    if (!g_dxvk_d3d9)
        g_dxvk_d3d9 = dlopen("/usr/lib/dxvk/d3d9.so", RTLD_NOW);
    if (g_dxvk_d3d9) {
        g_dxvk_create9_fn = (IDirect3D9 *(__attribute__((ms_abi)) *)(UINT))
            dlsym(g_dxvk_d3d9, "Direct3DCreate9");
    }
}

WINAPI_EXPORT IDirect3D9 *Direct3DCreate9(UINT SDKVersion)
{
    pthread_once(&g_dxvk_d3d9_once, dxvk_d3d9_probe_once);

    if (g_dxvk_create9_fn) {
        if (!__atomic_exchange_n(&g_dxvk_logged, 1, __ATOMIC_RELAXED))
            fprintf(stderr, LOG_PREFIX "Using DXVK d3d9\n");
        return g_dxvk_create9_fn(SDKVersion);
    }

    /* Fallback: our stub implementation */
    if (!__atomic_exchange_n(&g_stub_logged, 1, __ATOMIC_RELAXED))
        fprintf(stderr, LOG_PREFIX "Using stub D3D9 (DXVK not found)\n");
    IDirect3D9 *d3d = calloc(1, sizeof(IDirect3D9));
    if (!d3d) return NULL;
    d3d->lpVtbl = &g_d3d9_vtbl;
    d3d->refcount = 1;
    return d3d;
}

WINAPI_EXPORT long Direct3DCreate9Ex(UINT SDKVersion, void **ppD3D)
{
    if (!ppD3D) return E_NOTIMPL;
    *ppD3D = Direct3DCreate9(SDKVersion);
    return *ppD3D ? S_OK : E_NOTIMPL;
}

/*
 * d3d9_cleanup - Intentionally does NOT dlclose the DXVK handle.
 *
 * Games routinely hold IDirect3D9 pointers (with vtable entries pointing
 * into DXVK's d3d9.so) past our destructor. dlclose would unmap the code
 * pages and cause a crash during exit-time Release() calls. The OS reclaims
 * the memory at process exit anyway.
 */
