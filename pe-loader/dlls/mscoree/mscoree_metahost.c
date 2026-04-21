/*
 * mscoree_metahost.c - Real ICLRMetaHost / ICLRRuntimeInfo / ICLRRuntimeHost
 *                      vtables backed by Mono.
 *
 * S65 wired _CorExeMain to Mono but ICLRMetaHost::GetRuntime() still returned
 * E_FAIL, so PE binaries that explicitly host the CLR (Win32 .exe loading IL
 * assemblies in-process) could not.  This file fixes that.
 *
 * COM ABI:
 *   - Singleton metahost (one CLR per process, classic mscoree behaviour).
 *   - All vtable function pointers are __attribute__((ms_abi)) so PE callers
 *     hit them with the Win64 calling convention.
 *   - CLR ABI matches official mscoree.h ordering (must not be reordered).
 *
 * Mono mapping for ICLRRuntimeHost::ExecuteInDefaultAppDomain:
 *   1. mono_jit_init(domain_name)               (idempotent via root_domain)
 *   2. mono_domain_assembly_open(domain, path)
 *   3. mono_assembly_get_image(asm)
 *   4. split typeName "Namespace.Class" at the last dot
 *   5. mono_class_from_name(image, ns, klass)
 *   6. mono_class_get_method_from_name(klass, methodName, 1)
 *   7. mono_string_new(domain, argument)
 *   8. mono_runtime_invoke(method, NULL, &args, &exc)
 *   9. unbox the int32 return value
 *
 * Deferred (out of S66 scope, return E_NOTIMPL or sane defaults):
 *   - Real IEnumUnknown for EnumerateInstalledRuntimes / EnumerateLoadedRuntimes.
 *   - IHostControl / SetHostControl (host-controlled GC, threading).
 *   - ICLRControl / GetCLRControl (host policy hooks).
 *   - UnloadAppDomain / ExecuteInAppDomain (Mono can do this; not wired yet).
 *   - LoadLibrary / GetProcAddress on a loaded runtime image.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>

#include "common/dll_common.h"
#include "mscoree_internal.h"

/* --------------------------------------------------------------------------
 * GUID definitions (declared extern in mscoree_internal.h).
 * Numbers from official mscoree.h / Microsoft .NET 4.x SDK headers.
 * -------------------------------------------------------------------------- */

/* {9280188D-0E8E-4867-B30C-7FA83884E8DE} */
const GUID MSCOREE_CLSID_CLRMetaHost =
    { 0x9280188D, 0x0E8E, 0x4867,
      { 0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE } };

/* {D332DB9E-B9B3-4125-8207-A14884F53216} */
const GUID MSCOREE_IID_ICLRMetaHost =
    { 0xD332DB9E, 0xB9B3, 0x4125,
      { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } };

/* {BD39D1D2-BA2F-486A-89B0-B4B0CB466891} */
const GUID MSCOREE_IID_ICLRRuntimeInfo =
    { 0xBD39D1D2, 0xBA2F, 0x486A,
      { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } };

/* {90F1A06E-7712-4762-86B5-7A5EBA6BDB02} */
const GUID MSCOREE_CLSID_CLRRuntimeHost =
    { 0x90F1A06E, 0x7712, 0x4762,
      { 0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02 } };

/* {90F1A06C-7712-4762-86B5-7A5EBA6BDB02} */
const GUID MSCOREE_IID_ICLRRuntimeHost =
    { 0x90F1A06C, 0x7712, 0x4762,
      { 0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02 } };

/* {00000000-0000-0000-C000-000000000046} - IUnknown */
const GUID MSCOREE_IID_IUnknown =
    { 0x00000000, 0x0000, 0x0000,
      { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

/* --------------------------------------------------------------------------
 * Helpers: ASCII<->UTF16 and string-class splitting.
 * Mono speaks UTF-8; CLR speaks UTF-16LE.  Win32 wide chars are 2 bytes,
 * so we use uint16_t (== WCHAR == LPCWSTR element).  ASCII-only fast path
 * is sufficient for the namespace/class/method tokens we get from CLR
 * hosts in practice.
 * -------------------------------------------------------------------------- */

static char *wide_to_utf8_alloc(LPCWSTR ws)
{
    if (!ws) return NULL;
    size_t n = 0;
    while (ws[n]) ++n;
    /* worst case 4 bytes per code unit for non-BMP, but we only handle
     * BMP+ASCII via 1-3 bytes per unit.  4*n+1 is safe upper bound. */
    char *out = (char *)malloc(4 * n + 1);
    if (!out) return NULL;
    char *p = out;
    for (size_t i = 0; i < n; ++i) {
        uint16_t c = ws[i];
        if (c < 0x80) {
            *p++ = (char)c;
        } else if (c < 0x800) {
            *p++ = (char)(0xC0 | (c >> 6));
            *p++ = (char)(0x80 | (c & 0x3F));
        } else {
            /* surrogate pair handling deferred; treat as BMP code point */
            *p++ = (char)(0xE0 | (c >> 12));
            *p++ = (char)(0x80 | ((c >> 6) & 0x3F));
            *p++ = (char)(0x80 | (c & 0x3F));
        }
    }
    *p = '\0';
    return out;
}

/* Copy ASCII C string into a wide buffer with caller-provided cap.
 * Returns required count (incl. NUL).  Mirrors classic CLR "out" semantics:
 *  - if buffer is NULL or too small, write nothing, return required count.
 *  - if buffer fits, write+NUL terminate, return required count.
 */
static DWORD ascii_to_wide_buf(const char *ascii, LPWSTR buf, DWORD bufcap)
{
    size_t n = strlen(ascii);
    DWORD required = (DWORD)(n + 1);
    if (!buf || bufcap < required)
        return required;
    for (size_t i = 0; i < n; ++i)
        buf[i] = (WCHAR)(uint8_t)ascii[i];
    buf[n] = 0;
    return required;
}

/* Split "Foo.Bar.Baz" -> ns="Foo.Bar", cls="Baz".  No-dot case yields
 * ns="" and cls=full.  Caller frees both via free(). */
static int split_type_name(const char *full, char **out_ns, char **out_cls)
{
    *out_ns = NULL;
    *out_cls = NULL;
    if (!full) return -1;
    const char *dot = strrchr(full, '.');
    if (!dot) {
        *out_ns = strdup("");
        *out_cls = strdup(full);
    } else {
        size_t nslen = (size_t)(dot - full);
        *out_ns = (char *)malloc(nslen + 1);
        if (!*out_ns) return -1;
        memcpy(*out_ns, full, nslen);
        (*out_ns)[nslen] = '\0';
        *out_cls = strdup(dot + 1);
    }
    if (!*out_ns || !*out_cls) {
        free(*out_ns); free(*out_cls);
        *out_ns = NULL; *out_cls = NULL;
        return -1;
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * Forward declarations for the three vtable types.
 * -------------------------------------------------------------------------- */

typedef struct ICLRMetaHostVtbl       ICLRMetaHostVtbl;
typedef struct ICLRRuntimeInfoVtbl    ICLRRuntimeInfoVtbl;
typedef struct ICLRRuntimeHostVtbl    ICLRRuntimeHostVtbl;

typedef struct {
    const ICLRMetaHostVtbl *vtable;
    int ref_count;
} MonoMetaHost;

typedef struct {
    const ICLRRuntimeInfoVtbl *vtable;
    int ref_count;
    bool started;
    DWORD startup_flags;
} MonoRuntimeInfo;

typedef struct {
    const ICLRRuntimeHostVtbl *vtable;
    int ref_count;
    pthread_mutex_t lock;
    bool started;
    void *root_domain;        /* MonoDomain* from mono_jit_init */
} MonoRuntimeHost;

/* Vtable layouts -- ordering MUST match official mscoree.h.
 * Pointer types are intentionally `void *` for IHostControl / ICLRControl
 * etc. since we don't model those interfaces.  All entries are ms_abi. */

struct ICLRMetaHostVtbl {
    __attribute__((ms_abi)) HRESULT (*QueryInterface)(void *self, const GUID *riid, void **ppv);
    __attribute__((ms_abi)) ULONG   (*AddRef)(void *self);
    __attribute__((ms_abi)) ULONG   (*Release)(void *self);
    __attribute__((ms_abi)) HRESULT (*GetRuntime)(void *self, LPCWSTR pwzVersion, const GUID *riid, void **ppRuntime);
    __attribute__((ms_abi)) HRESULT (*GetVersionFromFile)(void *self, LPCWSTR pwzFilePath, LPWSTR pwzBuffer, DWORD *pcchBuffer);
    __attribute__((ms_abi)) HRESULT (*EnumerateInstalledRuntimes)(void *self, void **ppEnumerator);
    __attribute__((ms_abi)) HRESULT (*EnumerateLoadedRuntimes)(void *self, HANDLE hndProcess, void **ppEnumerator);
    __attribute__((ms_abi)) HRESULT (*RequestRuntimeLoadedNotification)(void *self, void *pCallbackFunction);
    __attribute__((ms_abi)) HRESULT (*QueryLegacyV2RuntimeBinding)(void *self, const GUID *riid, void **ppUnk);
    __attribute__((ms_abi)) HRESULT (*ExitProcess)(void *self, INT iExitCode);
};

struct ICLRRuntimeInfoVtbl {
    __attribute__((ms_abi)) HRESULT (*QueryInterface)(void *self, const GUID *riid, void **ppv);
    __attribute__((ms_abi)) ULONG   (*AddRef)(void *self);
    __attribute__((ms_abi)) ULONG   (*Release)(void *self);
    __attribute__((ms_abi)) HRESULT (*GetVersionString)(void *self, LPWSTR pwzBuffer, DWORD *pcchBuffer);
    __attribute__((ms_abi)) HRESULT (*GetRuntimeDirectory)(void *self, LPWSTR pwzBuffer, DWORD *pcchBuffer);
    __attribute__((ms_abi)) HRESULT (*IsLoaded)(void *self, HANDLE hndProcess, BOOL *pbLoaded);
    __attribute__((ms_abi)) HRESULT (*LoadErrorString)(void *self, UINT iResourceID, LPWSTR pwzBuffer, DWORD *pcchBuffer, LONG iLocaleID);
    __attribute__((ms_abi)) HRESULT (*LoadLibrary)(void *self, LPCWSTR pwzDllName, HMODULE *phndModule);
    __attribute__((ms_abi)) HRESULT (*GetProcAddress)(void *self, LPCSTR pszProcName, LPVOID *ppProc);
    __attribute__((ms_abi)) HRESULT (*GetInterface)(void *self, const GUID *rclsid, const GUID *riid, void **ppUnk);
    __attribute__((ms_abi)) HRESULT (*IsLoadable)(void *self, BOOL *pbLoadable);
    __attribute__((ms_abi)) HRESULT (*SetDefaultStartupFlags)(void *self, DWORD dwStartupFlags, LPCWSTR pwzHostConfigFile);
    __attribute__((ms_abi)) HRESULT (*GetDefaultStartupFlags)(void *self, DWORD *pdwStartupFlags, LPWSTR pwzHostConfigFile, DWORD *pcchHostConfigFile);
    __attribute__((ms_abi)) HRESULT (*BindAsLegacyV2Runtime)(void *self);
    __attribute__((ms_abi)) HRESULT (*IsStarted)(void *self, BOOL *pbStarted, DWORD *pdwStartupFlags);
};

struct ICLRRuntimeHostVtbl {
    __attribute__((ms_abi)) HRESULT (*QueryInterface)(void *self, const GUID *riid, void **ppv);
    __attribute__((ms_abi)) ULONG   (*AddRef)(void *self);
    __attribute__((ms_abi)) ULONG   (*Release)(void *self);
    __attribute__((ms_abi)) HRESULT (*Start)(void *self);
    __attribute__((ms_abi)) HRESULT (*Stop)(void *self);
    __attribute__((ms_abi)) HRESULT (*SetHostControl)(void *self, void *pHostControl);
    __attribute__((ms_abi)) HRESULT (*GetCLRControl)(void *self, void **pCLRControl);
    __attribute__((ms_abi)) HRESULT (*UnloadAppDomain)(void *self, DWORD dwAppDomainId, BOOL fWaitUntilDone);
    __attribute__((ms_abi)) HRESULT (*ExecuteInAppDomain)(void *self, DWORD dwAppDomainId, void *pCallback, void *cookie);
    __attribute__((ms_abi)) HRESULT (*GetCurrentAppDomainId)(void *self, DWORD *pdwAppDomainId);
    __attribute__((ms_abi)) HRESULT (*ExecuteApplication)(void *self, LPCWSTR pwzAppFullName, DWORD dwManifestPaths, LPCWSTR *ppwzManifestPaths, DWORD dwActivationData, LPCWSTR *ppwzActivationData, int *pReturnValue);
    __attribute__((ms_abi)) HRESULT (*ExecuteInDefaultAppDomain)(void *self, LPCWSTR pwzAssemblyPath, LPCWSTR pwzTypeName, LPCWSTR pwzMethodName, LPCWSTR pwzArgument, DWORD *pReturnValue);
};

/* --------------------------------------------------------------------------
 * Singletons.  The metahost is per-process, holds one runtime info, which
 * holds one runtime host.  Each AddRef'd handout returns the same pointer.
 * -------------------------------------------------------------------------- */

static MonoMetaHost     *g_metahost     = NULL;
static MonoRuntimeInfo  *g_runtime_info = NULL;
static MonoRuntimeHost  *g_runtime_host = NULL;
static pthread_mutex_t   g_singleton_lock = PTHREAD_MUTEX_INITIALIZER;

/* Forward decls for the static vtables (initialized at the bottom of file). */
static const ICLRMetaHostVtbl    g_metahost_vtbl;
static const ICLRRuntimeInfoVtbl g_runtime_info_vtbl;
static const ICLRRuntimeHostVtbl g_runtime_host_vtbl;

static MonoRuntimeHost *get_or_create_runtime_host(void)
{
    if (g_runtime_host) return g_runtime_host;
    MonoRuntimeHost *h = (MonoRuntimeHost *)calloc(1, sizeof(*h));
    if (!h) return NULL;
    h->vtable = &g_runtime_host_vtbl;
    h->ref_count = 1;
    pthread_mutex_init(&h->lock, NULL);
    g_runtime_host = h;
    return h;
}

static MonoRuntimeInfo *get_or_create_runtime_info(void)
{
    if (g_runtime_info) return g_runtime_info;
    MonoRuntimeInfo *r = (MonoRuntimeInfo *)calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->vtable = &g_runtime_info_vtbl;
    r->ref_count = 1;
    g_runtime_info = r;
    return r;
}

/* --------------------------------------------------------------------------
 * ICLRMetaHost methods.
 * -------------------------------------------------------------------------- */

static __attribute__((ms_abi)) HRESULT
MetaHost_QueryInterface(void *self, const GUID *riid, void **ppv)
{
    (void)self;
    if (!ppv || !riid) return E_POINTER;
    if (mscoree_guid_eq(riid, &MSCOREE_IID_ICLRMetaHost) ||
        mscoree_guid_eq(riid, &MSCOREE_IID_IUnknown)) {
        pthread_mutex_lock(&g_singleton_lock);
        __sync_add_and_fetch(&g_metahost->ref_count, 1);
        *ppv = g_metahost;
        pthread_mutex_unlock(&g_singleton_lock);
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG
MetaHost_AddRef(void *self)
{
    MonoMetaHost *m = (MonoMetaHost *)self;
    return (ULONG)__sync_add_and_fetch(&m->ref_count, 1);
}

static __attribute__((ms_abi)) ULONG
MetaHost_Release(void *self)
{
    MonoMetaHost *m = (MonoMetaHost *)self;
    int rc = __sync_sub_and_fetch(&m->ref_count, 1);
    /* Singleton: never actually free.  Mirrors official mscoree, which
     * keeps the metahost alive for process lifetime. */
    if (rc < 0) rc = 0;
    return (ULONG)rc;
}

/* GetRuntime: accept any "v4.*" string since Mono is API-compatible with
 * .NET Framework 4.x.  Hand back the singleton ICLRRuntimeInfo. */
static __attribute__((ms_abi)) HRESULT
MetaHost_GetRuntime(void *self, LPCWSTR pwzVersion, const GUID *riid, void **ppRuntime)
{
    (void)self;
    if (!ppRuntime || !riid) return E_POINTER;
    *ppRuntime = NULL;

    char *ver = wide_to_utf8_alloc(pwzVersion);
    fprintf(stderr, "[mscoree] ICLRMetaHost::GetRuntime(version=%s)\n",
            ver ? ver : "(null)");

    /* Accept "v4.*" or empty.  Reject other versions explicitly. */
    bool ok_version = (!ver || ver[0] == '\0' ||
                       (ver[0] == 'v' && ver[1] == '4' && ver[2] == '.'));
    free(ver);
    if (!ok_version) {
        fprintf(stderr, "[mscoree] GetRuntime: only v4.* runtimes supported\n");
        return CLR_E_SHIM_RUNTIMELOAD;
    }

    if (!mscoree_guid_eq(riid, &MSCOREE_IID_ICLRRuntimeInfo) &&
        !mscoree_guid_eq(riid, &MSCOREE_IID_IUnknown)) {
        return E_NOINTERFACE;
    }

    pthread_mutex_lock(&g_singleton_lock);
    MonoRuntimeInfo *info = get_or_create_runtime_info();
    if (info) {
        __sync_add_and_fetch(&info->ref_count, 1);
        *ppRuntime = info;
    }
    pthread_mutex_unlock(&g_singleton_lock);
    return info ? S_OK : E_FAIL;
}

static __attribute__((ms_abi)) HRESULT
MetaHost_GetVersionFromFile(void *self, LPCWSTR pwzFilePath,
                            LPWSTR pwzBuffer, DWORD *pcchBuffer)
{
    (void)self;
    (void)pwzFilePath;
    /* We always claim v4.0.30319 since that's the only runtime we host. */
    const char *ver = "v4.0.30319";
    DWORD req = (DWORD)strlen(ver) + 1;
    if (pcchBuffer) {
        DWORD cap = *pcchBuffer;
        *pcchBuffer = req;
        if (!pwzBuffer || cap < req) return E_INVALIDARG;
    } else if (!pwzBuffer) {
        return E_INVALIDARG;
    }
    if (pwzBuffer)
        ascii_to_wide_buf(ver, pwzBuffer, req);
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT
MetaHost_EnumerateInstalledRuntimes(void *self, void **ppEnumerator)
{
    (void)self;
    if (ppEnumerator) *ppEnumerator = NULL;
    /* Deferred: real IEnumUnknown wrapping the singleton ICLRRuntimeInfo. */
    return E_NOTIMPL;
}

static __attribute__((ms_abi)) HRESULT
MetaHost_EnumerateLoadedRuntimes(void *self, HANDLE hndProcess, void **ppEnumerator)
{
    (void)self;
    (void)hndProcess;
    if (ppEnumerator) *ppEnumerator = NULL;
    return E_NOTIMPL;
}

static __attribute__((ms_abi)) HRESULT
MetaHost_RequestRuntimeLoadedNotification(void *self, void *pCallbackFunction)
{
    (void)self;
    (void)pCallbackFunction;
    /* CLR returns S_OK and silently never invokes; our Mono load is synchronous
     * inside Start(), so the notification semantic is moot. */
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT
MetaHost_QueryLegacyV2RuntimeBinding(void *self, const GUID *riid, void **ppUnk)
{
    (void)self;
    (void)riid;
    if (ppUnk) *ppUnk = NULL;
    /* No legacy v2 binding -- Mono only ships one runtime. */
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) HRESULT
MetaHost_ExitProcess(void *self, INT iExitCode)
{
    (void)self;
    fprintf(stderr, "[mscoree] ICLRMetaHost::ExitProcess(%d)\n", iExitCode);
    _exit(iExitCode);
    /* unreachable */
    return S_OK;
}

static const ICLRMetaHostVtbl g_metahost_vtbl = {
    .QueryInterface                  = MetaHost_QueryInterface,
    .AddRef                          = MetaHost_AddRef,
    .Release                         = MetaHost_Release,
    .GetRuntime                      = MetaHost_GetRuntime,
    .GetVersionFromFile              = MetaHost_GetVersionFromFile,
    .EnumerateInstalledRuntimes      = MetaHost_EnumerateInstalledRuntimes,
    .EnumerateLoadedRuntimes         = MetaHost_EnumerateLoadedRuntimes,
    .RequestRuntimeLoadedNotification= MetaHost_RequestRuntimeLoadedNotification,
    .QueryLegacyV2RuntimeBinding     = MetaHost_QueryLegacyV2RuntimeBinding,
    .ExitProcess                     = MetaHost_ExitProcess,
};

/* --------------------------------------------------------------------------
 * ICLRRuntimeInfo methods.
 * -------------------------------------------------------------------------- */

static __attribute__((ms_abi)) HRESULT
RuntimeInfo_QueryInterface(void *self, const GUID *riid, void **ppv)
{
    if (!ppv || !riid) return E_POINTER;
    if (mscoree_guid_eq(riid, &MSCOREE_IID_ICLRRuntimeInfo) ||
        mscoree_guid_eq(riid, &MSCOREE_IID_IUnknown)) {
        MonoRuntimeInfo *r = (MonoRuntimeInfo *)self;
        __sync_add_and_fetch(&r->ref_count, 1);
        *ppv = r;
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG
RuntimeInfo_AddRef(void *self)
{
    MonoRuntimeInfo *r = (MonoRuntimeInfo *)self;
    return (ULONG)__sync_add_and_fetch(&r->ref_count, 1);
}

static __attribute__((ms_abi)) ULONG
RuntimeInfo_Release(void *self)
{
    MonoRuntimeInfo *r = (MonoRuntimeInfo *)self;
    int rc = __sync_sub_and_fetch(&r->ref_count, 1);
    if (rc < 0) rc = 0;
    return (ULONG)rc;
}

static __attribute__((ms_abi)) HRESULT
RuntimeInfo_GetVersionString(void *self, LPWSTR pwzBuffer, DWORD *pcchBuffer)
{
    (void)self;
    const char *ver = "v4.0.30319";
    DWORD req = (DWORD)strlen(ver) + 1;
    if (!pcchBuffer) return E_POINTER;
    DWORD cap = *pcchBuffer;
    *pcchBuffer = req;
    if (!pwzBuffer || cap < req) return E_INVALIDARG;
    ascii_to_wide_buf(ver, pwzBuffer, req);
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT
RuntimeInfo_GetRuntimeDirectory(void *self, LPWSTR pwzBuffer, DWORD *pcchBuffer)
{
    (void)self;
    /* Path Mono installs to on Arch.  Caller usually only checks success. */
    const char *dir = "/usr/lib/mono/4.5/";
    DWORD req = (DWORD)strlen(dir) + 1;
    if (!pcchBuffer) return E_POINTER;
    DWORD cap = *pcchBuffer;
    *pcchBuffer = req;
    if (!pwzBuffer || cap < req) return E_INVALIDARG;
    ascii_to_wide_buf(dir, pwzBuffer, req);
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT
RuntimeInfo_IsLoaded(void *self, HANDLE hndProcess, BOOL *pbLoaded)
{
    (void)self;
    (void)hndProcess;
    if (!pbLoaded) return E_POINTER;
    *pbLoaded = (g_runtime_host && g_runtime_host->started) ? TRUE : FALSE;
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT
RuntimeInfo_LoadErrorString(void *self, UINT iResourceID, LPWSTR pwzBuffer,
                            DWORD *pcchBuffer, LONG iLocaleID)
{
    (void)self;
    (void)iResourceID;
    (void)pwzBuffer;
    (void)pcchBuffer;
    (void)iLocaleID;
    return E_NOTIMPL;
}

static __attribute__((ms_abi)) HRESULT
RuntimeInfo_LoadLibrary(void *self, LPCWSTR pwzDllName, HMODULE *phndModule)
{
    (void)self;
    (void)pwzDllName;
    if (phndModule) *phndModule = NULL;
    /* Deferred: would need to dispatch to kernel32!LoadLibraryW on a
     * managed-image path. */
    return E_NOTIMPL;
}

static __attribute__((ms_abi)) HRESULT
RuntimeInfo_GetProcAddress(void *self, LPCSTR pszProcName, LPVOID *ppProc)
{
    (void)self;
    (void)pszProcName;
    if (ppProc) *ppProc = NULL;
    return E_NOTIMPL;
}

/* GetInterface: this is the bridge from ICLRRuntimeInfo to ICLRRuntimeHost.
 * The host normally calls
 *   info->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, &host)
 * to obtain the live runtime. */
static __attribute__((ms_abi)) HRESULT
RuntimeInfo_GetInterface(void *self, const GUID *rclsid, const GUID *riid, void **ppUnk)
{
    (void)self;
    if (!ppUnk || !rclsid || !riid) return E_POINTER;
    *ppUnk = NULL;

    if (!mscoree_guid_eq(rclsid, &MSCOREE_CLSID_CLRRuntimeHost)) {
        fprintf(stderr, "[mscoree] ICLRRuntimeInfo::GetInterface: unknown CLSID\n");
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    if (!mscoree_guid_eq(riid, &MSCOREE_IID_ICLRRuntimeHost) &&
        !mscoree_guid_eq(riid, &MSCOREE_IID_IUnknown)) {
        return E_NOINTERFACE;
    }

    pthread_mutex_lock(&g_singleton_lock);
    MonoRuntimeHost *h = get_or_create_runtime_host();
    if (h) {
        __sync_add_and_fetch(&h->ref_count, 1);
        *ppUnk = h;
    }
    pthread_mutex_unlock(&g_singleton_lock);
    return h ? S_OK : E_FAIL;
}

static __attribute__((ms_abi)) HRESULT
RuntimeInfo_IsLoadable(void *self, BOOL *pbLoadable)
{
    (void)self;
    if (!pbLoadable) return E_POINTER;
    /* Defer to mscoree_try_load_mono(): if Mono is loadable, we're loadable. */
    *pbLoadable = (mscoree_try_load_mono() == 0) ? TRUE : FALSE;
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT
RuntimeInfo_SetDefaultStartupFlags(void *self, DWORD dwStartupFlags,
                                   LPCWSTR pwzHostConfigFile)
{
    MonoRuntimeInfo *r = (MonoRuntimeInfo *)self;
    (void)pwzHostConfigFile;  /* Mono ignores app.config-style host config. */
    r->startup_flags = dwStartupFlags;
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT
RuntimeInfo_GetDefaultStartupFlags(void *self, DWORD *pdwStartupFlags,
                                   LPWSTR pwzHostConfigFile,
                                   DWORD *pcchHostConfigFile)
{
    MonoRuntimeInfo *r = (MonoRuntimeInfo *)self;
    if (pdwStartupFlags) *pdwStartupFlags = r->startup_flags;
    if (pcchHostConfigFile) {
        DWORD cap = *pcchHostConfigFile;
        *pcchHostConfigFile = 1;
        if (pwzHostConfigFile && cap >= 1) pwzHostConfigFile[0] = 0;
    } else if (pwzHostConfigFile) {
        pwzHostConfigFile[0] = 0;
    }
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT
RuntimeInfo_BindAsLegacyV2Runtime(void *self)
{
    (void)self;
    /* No legacy v2 in Mono; pretend we did. */
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT
RuntimeInfo_IsStarted(void *self, BOOL *pbStarted, DWORD *pdwStartupFlags)
{
    MonoRuntimeInfo *r = (MonoRuntimeInfo *)self;
    if (!pbStarted) return E_POINTER;
    *pbStarted = (g_runtime_host && g_runtime_host->started) ? TRUE : FALSE;
    if (pdwStartupFlags) *pdwStartupFlags = r->startup_flags;
    return S_OK;
}

static const ICLRRuntimeInfoVtbl g_runtime_info_vtbl = {
    .QueryInterface         = RuntimeInfo_QueryInterface,
    .AddRef                 = RuntimeInfo_AddRef,
    .Release                = RuntimeInfo_Release,
    .GetVersionString       = RuntimeInfo_GetVersionString,
    .GetRuntimeDirectory    = RuntimeInfo_GetRuntimeDirectory,
    .IsLoaded               = RuntimeInfo_IsLoaded,
    .LoadErrorString        = RuntimeInfo_LoadErrorString,
    .LoadLibrary            = RuntimeInfo_LoadLibrary,
    .GetProcAddress         = RuntimeInfo_GetProcAddress,
    .GetInterface           = RuntimeInfo_GetInterface,
    .IsLoadable             = RuntimeInfo_IsLoadable,
    .SetDefaultStartupFlags = RuntimeInfo_SetDefaultStartupFlags,
    .GetDefaultStartupFlags = RuntimeInfo_GetDefaultStartupFlags,
    .BindAsLegacyV2Runtime  = RuntimeInfo_BindAsLegacyV2Runtime,
    .IsStarted              = RuntimeInfo_IsStarted,
};

/* --------------------------------------------------------------------------
 * ICLRRuntimeHost methods - the real workhorse.
 * -------------------------------------------------------------------------- */

static __attribute__((ms_abi)) HRESULT
RuntimeHost_QueryInterface(void *self, const GUID *riid, void **ppv)
{
    if (!ppv || !riid) return E_POINTER;
    if (mscoree_guid_eq(riid, &MSCOREE_IID_ICLRRuntimeHost) ||
        mscoree_guid_eq(riid, &MSCOREE_IID_IUnknown)) {
        MonoRuntimeHost *h = (MonoRuntimeHost *)self;
        __sync_add_and_fetch(&h->ref_count, 1);
        *ppv = h;
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG
RuntimeHost_AddRef(void *self)
{
    MonoRuntimeHost *h = (MonoRuntimeHost *)self;
    return (ULONG)__sync_add_and_fetch(&h->ref_count, 1);
}

static __attribute__((ms_abi)) ULONG
RuntimeHost_Release(void *self)
{
    MonoRuntimeHost *h = (MonoRuntimeHost *)self;
    int rc = __sync_sub_and_fetch(&h->ref_count, 1);
    if (rc < 0) rc = 0;
    return (ULONG)rc;
}

/* Start: load Mono if needed, mono_jit_init() the root domain.  Idempotent. */
static __attribute__((ms_abi)) HRESULT
RuntimeHost_Start(void *self)
{
    MonoRuntimeHost *h = (MonoRuntimeHost *)self;
    HRESULT hr = S_OK;

    pthread_mutex_lock(&h->lock);
    if (h->started) {
        pthread_mutex_unlock(&h->lock);
        return S_OK;
    }

    if (mscoree_try_load_mono() != 0) {
        pthread_mutex_unlock(&h->lock);
        fprintf(stderr, "[mscoree] ICLRRuntimeHost::Start: Mono unavailable\n");
        return HOST_E_CLRNOTAVAILABLE;
    }
    if (!pfn_mono_jit_init) {
        pthread_mutex_unlock(&h->lock);
        return HOST_E_CLRNOTAVAILABLE;
    }

    /* Mono will reuse the existing root domain if mono_jit_init is called
     * twice in the same process; that's fine. */
    if (pfn_mono_get_root_domain) {
        h->root_domain = pfn_mono_get_root_domain();
    }
    if (!h->root_domain) {
        h->root_domain = pfn_mono_jit_init("clrhost");
    }
    if (!h->root_domain) {
        fprintf(stderr, "[mscoree] ICLRRuntimeHost::Start: mono_jit_init failed\n");
        hr = E_FAIL;
    } else {
        h->started = true;
        if (g_runtime_info) g_runtime_info->started = true;
        fprintf(stderr, "[mscoree] ICLRRuntimeHost::Start: Mono root domain ready\n");
    }
    pthread_mutex_unlock(&h->lock);
    return hr;
}

static __attribute__((ms_abi)) HRESULT
RuntimeHost_Stop(void *self)
{
    MonoRuntimeHost *h = (MonoRuntimeHost *)self;
    pthread_mutex_lock(&h->lock);
    /* mono_jit_cleanup() is destructive and one-shot: if the host calls
     * Start/Stop/Start we'd crash on the second Start.  Mark stopped but
     * keep the domain alive; this matches Mono's "single domain per
     * process" reality. */
    h->started = false;
    if (g_runtime_info) g_runtime_info->started = false;
    pthread_mutex_unlock(&h->lock);
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT
RuntimeHost_SetHostControl(void *self, void *pHostControl)
{
    (void)self;
    (void)pHostControl;
    /* Deferred: IHostControl drives custom GC/threading callbacks.
     * Mono doesn't expose those host hooks, so we accept and ignore. */
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT
RuntimeHost_GetCLRControl(void *self, void **pCLRControl)
{
    (void)self;
    if (pCLRControl) *pCLRControl = NULL;
    /* Deferred: ICLRControl. */
    return E_NOTIMPL;
}

static __attribute__((ms_abi)) HRESULT
RuntimeHost_UnloadAppDomain(void *self, DWORD dwAppDomainId, BOOL fWaitUntilDone)
{
    (void)self;
    (void)dwAppDomainId;
    (void)fWaitUntilDone;
    /* Deferred: Mono supports unloading via mono_domain_unload but we
     * only ever hand out the root domain (id=1). */
    return E_NOTIMPL;
}

static __attribute__((ms_abi)) HRESULT
RuntimeHost_ExecuteInAppDomain(void *self, DWORD dwAppDomainId, void *pCallback, void *cookie)
{
    (void)self;
    (void)dwAppDomainId;
    (void)pCallback;
    (void)cookie;
    /* Deferred: would need to JIT a thunk that calls back into native. */
    return E_NOTIMPL;
}

static __attribute__((ms_abi)) HRESULT
RuntimeHost_GetCurrentAppDomainId(void *self, DWORD *pdwAppDomainId)
{
    (void)self;
    if (!pdwAppDomainId) return E_POINTER;
    /* Mono's root domain is conventionally id 1. */
    *pdwAppDomainId = 1;
    return S_OK;
}

/* ExecuteApplication: invoke the assembly's entry point.  We synthesise an
 * argv from the activation data strings (best-effort) and reuse mono_jit_exec
 * the same way _CorExeMain does. */
static __attribute__((ms_abi)) HRESULT
RuntimeHost_ExecuteApplication(void *self, LPCWSTR pwzAppFullName,
                               DWORD dwManifestPaths, LPCWSTR *ppwzManifestPaths,
                               DWORD dwActivationData, LPCWSTR *ppwzActivationData,
                               int *pReturnValue)
{
    MonoRuntimeHost *h = (MonoRuntimeHost *)self;
    (void)dwManifestPaths;
    (void)ppwzManifestPaths;

    if (pReturnValue) *pReturnValue = -1;

    /* Auto-Start. */
    HRESULT hr = RuntimeHost_Start(h);
    if (hr != S_OK) return hr;

    if (!pfn_mono_domain_assembly_open || !pfn_mono_jit_exec)
        return HOST_E_CLRNOTAVAILABLE;

    char *path = wide_to_utf8_alloc(pwzAppFullName);
    if (!path) return E_FAIL;

    /* Build argv: argv[0] = path, then activation strings. */
    int argc = 1 + (int)dwActivationData;
    char **argv = (char **)calloc((size_t)argc + 1, sizeof(char *));
    if (!argv) { free(path); return E_FAIL; }
    argv[0] = path;
    for (DWORD i = 0; i < dwActivationData; ++i)
        argv[1 + i] = wide_to_utf8_alloc(ppwzActivationData
                                          ? ppwzActivationData[i]
                                          : NULL);

    void *assembly = pfn_mono_domain_assembly_open(h->root_domain, path);
    if (!assembly) {
        fprintf(stderr, "[mscoree] ExecuteApplication: assembly_open failed: %s\n", path);
        for (int i = 0; i < argc; ++i) free(argv[i]);
        free(argv);
        return E_FAIL;
    }

    int rc = pfn_mono_jit_exec(h->root_domain, assembly, argc, argv);
    if (pReturnValue) *pReturnValue = rc;

    /* free argv[0]==path is freed via the loop too */
    for (int i = 0; i < argc; ++i) free(argv[i]);
    free(argv);
    return S_OK;
}

/* ExecuteInDefaultAppDomain: invoke a static method on a managed type.
 * This is the canonical "host calls into IL" entry point. */
static __attribute__((ms_abi)) HRESULT
RuntimeHost_ExecuteInDefaultAppDomain(void *self,
                                      LPCWSTR pwzAssemblyPath,
                                      LPCWSTR pwzTypeName,
                                      LPCWSTR pwzMethodName,
                                      LPCWSTR pwzArgument,
                                      DWORD *pReturnValue)
{
    MonoRuntimeHost *h = (MonoRuntimeHost *)self;
    if (pReturnValue) *pReturnValue = (DWORD)-1;

    /* Auto-Start. */
    HRESULT hr = RuntimeHost_Start(h);
    if (hr != S_OK) return hr;

    /* All optional Mono symbols required for this path. */
    if (!pfn_mono_domain_assembly_open ||
        !pfn_mono_assembly_get_image ||
        !pfn_mono_class_from_name ||
        !pfn_mono_class_get_method_from_name ||
        !pfn_mono_string_new ||
        !pfn_mono_runtime_invoke) {
        fprintf(stderr, "[mscoree] ExecuteInDefaultAppDomain: missing Mono symbols\n");
        return HOST_E_CLRNOTAVAILABLE;
    }

    char *asm_path = wide_to_utf8_alloc(pwzAssemblyPath);
    char *full_type = wide_to_utf8_alloc(pwzTypeName);
    char *method = wide_to_utf8_alloc(pwzMethodName);
    char *arg_str = wide_to_utf8_alloc(pwzArgument);
    char *ns = NULL, *cls = NULL;

    if (!asm_path || !full_type || !method) {
        free(asm_path); free(full_type); free(method); free(arg_str);
        return E_INVALIDARG;
    }
    if (split_type_name(full_type, &ns, &cls) != 0) {
        free(asm_path); free(full_type); free(method); free(arg_str);
        return E_FAIL;
    }

    fprintf(stderr, "[mscoree] ExecuteInDefaultAppDomain: %s :: %s.%s::%s(\"%s\")\n",
            asm_path, ns, cls, method, arg_str ? arg_str : "");

    HRESULT result = E_FAIL;
    void *assembly = pfn_mono_domain_assembly_open(h->root_domain, asm_path);
    if (!assembly) {
        fprintf(stderr, "[mscoree] ExecuteInDefaultAppDomain: assembly_open failed\n");
        goto cleanup;
    }
    void *image = pfn_mono_assembly_get_image(assembly);
    if (!image) {
        fprintf(stderr, "[mscoree] ExecuteInDefaultAppDomain: assembly_get_image failed\n");
        goto cleanup;
    }
    void *klass = pfn_mono_class_from_name(image, ns, cls);
    if (!klass) {
        fprintf(stderr, "[mscoree] ExecuteInDefaultAppDomain: class %s.%s not found\n", ns, cls);
        goto cleanup;
    }
    /* CLR contract: the target signature is `int Method(string)` so
     * param_count = 1.  If your host wants overload resolution, switch
     * to mono_method_desc_search_in_class. */
    void *m = pfn_mono_class_get_method_from_name(klass, method, 1);
    if (!m) {
        fprintf(stderr, "[mscoree] ExecuteInDefaultAppDomain: method %s not found\n", method);
        goto cleanup;
    }
    void *arg_mono = pfn_mono_string_new(h->root_domain, arg_str ? arg_str : "");
    void *params[1] = { arg_mono };
    void *exc = NULL;
    void *ret = pfn_mono_runtime_invoke(m, NULL, params, &exc);
    if (exc) {
        fprintf(stderr, "[mscoree] ExecuteInDefaultAppDomain: managed exception thrown\n");
        result = E_FAIL;
        goto cleanup;
    }
    if (pReturnValue) {
        if (ret && pfn_mono_object_unbox) {
            int32_t *boxed = (int32_t *)pfn_mono_object_unbox(ret);
            *pReturnValue = boxed ? (DWORD)*boxed : 0;
        } else {
            *pReturnValue = 0;
        }
    }
    result = S_OK;

cleanup:
    free(asm_path);
    free(full_type);
    free(method);
    free(arg_str);
    free(ns);
    free(cls);
    return result;
}

static const ICLRRuntimeHostVtbl g_runtime_host_vtbl = {
    .QueryInterface              = RuntimeHost_QueryInterface,
    .AddRef                      = RuntimeHost_AddRef,
    .Release                     = RuntimeHost_Release,
    .Start                       = RuntimeHost_Start,
    .Stop                        = RuntimeHost_Stop,
    .SetHostControl              = RuntimeHost_SetHostControl,
    .GetCLRControl               = RuntimeHost_GetCLRControl,
    .UnloadAppDomain             = RuntimeHost_UnloadAppDomain,
    .ExecuteInAppDomain          = RuntimeHost_ExecuteInAppDomain,
    .GetCurrentAppDomainId       = RuntimeHost_GetCurrentAppDomainId,
    .ExecuteApplication          = RuntimeHost_ExecuteApplication,
    .ExecuteInDefaultAppDomain   = RuntimeHost_ExecuteInDefaultAppDomain,
};

/* --------------------------------------------------------------------------
 * Singleton accessor exposed via mscoree_internal.h.
 * -------------------------------------------------------------------------- */

HRESULT mscoree_get_metahost_singleton(const GUID *riid, void **ppInterface)
{
    if (!ppInterface || !riid) return E_POINTER;
    *ppInterface = NULL;

    if (!mscoree_guid_eq(riid, &MSCOREE_IID_ICLRMetaHost) &&
        !mscoree_guid_eq(riid, &MSCOREE_IID_IUnknown)) {
        return E_NOINTERFACE;
    }

    pthread_mutex_lock(&g_singleton_lock);
    if (!g_metahost) {
        g_metahost = (MonoMetaHost *)calloc(1, sizeof(*g_metahost));
        if (!g_metahost) {
            pthread_mutex_unlock(&g_singleton_lock);
            return E_FAIL;
        }
        g_metahost->vtable = &g_metahost_vtbl;
        g_metahost->ref_count = 0;
    }
    __sync_add_and_fetch(&g_metahost->ref_count, 1);
    *ppInterface = g_metahost;
    pthread_mutex_unlock(&g_singleton_lock);
    return S_OK;
}

/* --------------------------------------------------------------------------
 * Optional convenience export: GetCLRRuntimeHost().  Some legacy hosts call
 * this instead of CLRCreateInstance + GetRuntime + GetInterface.
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HRESULT GetCLRRuntimeHost(const GUID *riid, void **ppUnk)
{
    if (!ppUnk || !riid) return E_POINTER;
    *ppUnk = NULL;

    if (!mscoree_guid_eq(riid, &MSCOREE_IID_ICLRRuntimeHost) &&
        !mscoree_guid_eq(riid, &MSCOREE_IID_IUnknown)) {
        return E_NOINTERFACE;
    }

    /* Make sure Mono is in the door. */
    (void)mscoree_try_load_mono();

    pthread_mutex_lock(&g_singleton_lock);
    MonoRuntimeHost *h = get_or_create_runtime_host();
    if (h) {
        __sync_add_and_fetch(&h->ref_count, 1);
        *ppUnk = h;
    }
    pthread_mutex_unlock(&g_singleton_lock);
    return h ? S_OK : E_FAIL;
}
