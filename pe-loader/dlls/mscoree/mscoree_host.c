/*
 * mscoree_host.c - .NET CLR hosting stubs
 *
 * Provides minimal CLR hosting entry points for managed executables.
 * If Mono runtime (libmono-2.0.so or libmonosgen-2.0.so) is available,
 * we attempt to forward to it. Otherwise, we print a warning and return
 * E_FAIL to indicate the CLR is not available.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>

#include "common/dll_common.h"

/* HRESULT codes */
#define S_OK            ((HRESULT)0x00000000)
#define S_FALSE         ((HRESULT)0x00000001)
#define E_FAIL          ((HRESULT)0x80004005)
#define E_INVALIDARG    ((HRESULT)0x80070057)
#define E_NOTIMPL       ((HRESULT)0x80004001)
#define E_NOINTERFACE   ((HRESULT)0x80004002)
#define E_POINTER       ((HRESULT)0x80004003)
#define CLASS_E_CLASSNOTAVAILABLE ((HRESULT)0x80040111)

/* CLSID / IID for ICLRMetaHost and ICLRRuntimeInfo */
/* {9280188D-0E8E-4867-B30C-7FA83884E8DE} */
static const GUID CLSID_CLRMetaHost =
    { 0x9280188D, 0x0E8E, 0x4867, { 0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE } };

/* {D332DB9E-B9B3-4125-8207-A14884F53216} */
static const GUID IID_ICLRMetaHost =
    { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } };

/* CLR startup flags */
#define STARTUP_CONCURRENT_GC           0x1
#define STARTUP_LOADER_OPTIMIZATION_SINGLE_DOMAIN   0x1
#define STARTUP_LOADER_OPTIMIZATION_MULTI_DOMAIN    0x2

/* --------------------------------------------------------------------------
 * Mono runtime detection and loading
 * -------------------------------------------------------------------------- */

static void *g_mono_handle = NULL;
static int g_mono_init_attempted = 0;

/* Mono function pointers */
typedef void *(*mono_jit_init_fn)(const char *domain_name);
typedef int   (*mono_jit_exec_fn)(void *domain, void *assembly, int argc, char *argv[]);
typedef void *(*mono_domain_assembly_open_fn)(void *domain, const char *name);
typedef void  (*mono_jit_cleanup_fn)(void *domain);

static mono_jit_init_fn      pfn_mono_jit_init = NULL;
static mono_jit_exec_fn      pfn_mono_jit_exec = NULL;
static mono_domain_assembly_open_fn pfn_mono_domain_assembly_open = NULL;
static mono_jit_cleanup_fn   pfn_mono_jit_cleanup = NULL;

static pthread_mutex_t g_mono_init_lock = PTHREAD_MUTEX_INITIALIZER;

static int try_load_mono(void)
{
    pthread_mutex_lock(&g_mono_init_lock);
    if (g_mono_init_attempted) {
        int result = g_mono_handle ? 0 : -1;
        pthread_mutex_unlock(&g_mono_init_lock);
        return result;
    }

    g_mono_init_attempted = 1;

    /* Try different Mono library names */
    const char *libs[] = {
        "libmono-2.0.so",
        "libmono-2.0.so.1",
        "libmonosgen-2.0.so",
        "libmonosgen-2.0.so.1",
        "libcoreclr.so",    /* .NET Core / .NET 5+ */
        NULL
    };

    for (int i = 0; libs[i]; i++) {
        g_mono_handle = dlopen(libs[i], RTLD_LAZY | RTLD_GLOBAL);
        if (g_mono_handle) {
            fprintf(stderr, "[mscoree] Loaded Mono runtime: %s\n", libs[i]);

            pfn_mono_jit_init = (mono_jit_init_fn)dlsym(g_mono_handle, "mono_jit_init");
            pfn_mono_jit_exec = (mono_jit_exec_fn)dlsym(g_mono_handle, "mono_jit_exec");
            pfn_mono_domain_assembly_open = (mono_domain_assembly_open_fn)
                dlsym(g_mono_handle, "mono_domain_assembly_open");
            pfn_mono_jit_cleanup = (mono_jit_cleanup_fn)
                dlsym(g_mono_handle, "mono_jit_cleanup");

            if (pfn_mono_jit_init && pfn_mono_jit_exec) {
                pthread_mutex_unlock(&g_mono_init_lock);
                return 0;
            }

            fprintf(stderr, "[mscoree] WARNING: Mono library loaded but missing symbols\n");
            dlclose(g_mono_handle);
            g_mono_handle = NULL;
        }
    }

    fprintf(stderr, "[mscoree] WARNING: .NET CLR not available. "
            "Install Mono (mono-runtime) or .NET to run managed executables.\n");
    pthread_mutex_unlock(&g_mono_init_lock);
    return -1;
}

/* --------------------------------------------------------------------------
 * Stub ICLRMetaHost interface
 *
 * Many applications call CLRCreateInstance to get ICLRMetaHost.
 * We provide a minimal vtable that returns E_NOTIMPL for everything.
 * -------------------------------------------------------------------------- */

typedef struct {
    void *vtable;
    int ref_count;
} stub_meta_host_t;

static __attribute__((ms_abi)) HRESULT stub_QueryInterface(void *This, const GUID *riid, void **ppv)
{
    (void)This;
    (void)riid;
    if (ppv)
        *ppv = NULL;
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG stub_AddRef(void *This)
{
    stub_meta_host_t *host = (stub_meta_host_t *)This;
    return (ULONG)__sync_add_and_fetch(&host->ref_count, 1);
}

static __attribute__((ms_abi)) ULONG stub_Release(void *This)
{
    stub_meta_host_t *host = (stub_meta_host_t *)This;
    int rc = __sync_sub_and_fetch(&host->ref_count, 1);
    if (rc <= 0) {
        free(host->vtable);
        free(host);
    }
    return (ULONG)rc;
}

static __attribute__((ms_abi)) HRESULT stub_GetRuntime(void *This, LPCWSTR version, const GUID *riid, void **ppv)
{
    (void)This;
    (void)version;
    (void)riid;
    if (ppv)
        *ppv = NULL;
    fprintf(stderr, "[mscoree] ICLRMetaHost::GetRuntime() - stub, returning E_FAIL\n");
    return E_FAIL;
}

static __attribute__((ms_abi)) HRESULT stub_EnumerateRuntimes(void *This, void **ppEnum)
{
    (void)This;
    if (ppEnum)
        *ppEnum = NULL;
    return E_NOTIMPL;
}

/* Vtable layout for ICLRMetaHost (partial) */
typedef struct {
    __attribute__((ms_abi)) HRESULT (*QueryInterface)(void *, const GUID *, void **);
    __attribute__((ms_abi)) ULONG   (*AddRef)(void *);
    __attribute__((ms_abi)) ULONG   (*Release)(void *);
    __attribute__((ms_abi)) HRESULT (*GetRuntime)(void *, LPCWSTR, const GUID *, void **);
    __attribute__((ms_abi)) HRESULT (*GetVersionFromFile)(void *, LPCWSTR, LPWSTR, DWORD *);
    __attribute__((ms_abi)) HRESULT (*EnumerateInstalledRuntimes)(void *, void **);
    __attribute__((ms_abi)) HRESULT (*EnumerateLoadedRuntimes)(void *, HANDLE, void **);
    __attribute__((ms_abi)) HRESULT (*RequestRuntimeLoadedNotification)(void *, void *);
    __attribute__((ms_abi)) HRESULT (*QueryLegacyV2RuntimeBinding)(void *, const GUID *, void **);
    __attribute__((ms_abi)) HRESULT (*ExitProcess)(void *, INT);
} ICLRMetaHostVtbl;

static stub_meta_host_t *create_stub_meta_host(void)
{
    stub_meta_host_t *host = (stub_meta_host_t *)calloc(1, sizeof(stub_meta_host_t));
    if (!host)
        return NULL;

    ICLRMetaHostVtbl *vtbl = (ICLRMetaHostVtbl *)calloc(1, sizeof(ICLRMetaHostVtbl));
    if (!vtbl) {
        free(host);
        return NULL;
    }

    vtbl->QueryInterface = stub_QueryInterface;
    vtbl->AddRef = stub_AddRef;
    vtbl->Release = stub_Release;
    vtbl->GetRuntime = stub_GetRuntime;
    vtbl->EnumerateInstalledRuntimes = stub_EnumerateRuntimes;

    host->vtable = vtbl;
    host->ref_count = 1;
    return host;
}

/* --------------------------------------------------------------------------
 * CLRCreateInstance - main entry point for .NET 4.0+ hosting
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HRESULT CLRCreateInstance(
    const GUID *clsid, const GUID *riid, void **ppInterface)
{
    if (!ppInterface)
        return E_POINTER;

    *ppInterface = NULL;

    fprintf(stderr, "[mscoree] CLRCreateInstance(clsid={%08X-...}, riid={%08X-...})\n",
            clsid ? clsid->Data1 : 0, riid ? riid->Data1 : 0);

    /* Try to load Mono runtime */
    if (try_load_mono() == 0) {
        fprintf(stderr, "[mscoree] Mono runtime available, creating stub interface\n");
    }

    /* Check for ICLRMetaHost request */
    if (clsid && memcmp(clsid, &CLSID_CLRMetaHost, sizeof(GUID)) == 0 &&
        riid && memcmp(riid, &IID_ICLRMetaHost, sizeof(GUID)) == 0) {

        stub_meta_host_t *host = create_stub_meta_host();
        if (!host)
            return E_FAIL;

        *ppInterface = host;
        return S_OK;
    }

    return CLASS_E_CLASSNOTAVAILABLE;
}

/* --------------------------------------------------------------------------
 * CorBindToRuntimeEx - legacy CLR binding (pre-.NET 4.0)
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HRESULT CorBindToRuntimeEx(
    LPCWSTR pwszVersion,
    LPCWSTR pwszBuildFlavor,
    DWORD startupFlags,
    const GUID *rclsid,
    const GUID *riid,
    void **ppv)
{
    (void)pwszVersion;
    (void)pwszBuildFlavor;
    (void)startupFlags;
    (void)rclsid;
    (void)riid;

    fprintf(stderr, "[mscoree] CorBindToRuntimeEx() - legacy CLR binding\n");

    if (ppv)
        *ppv = NULL;

    if (try_load_mono() == 0) {
        fprintf(stderr, "[mscoree] Mono available but CorBindToRuntimeEx interface "
                "not fully implemented\n");
    }

    return E_FAIL;
}

/* --------------------------------------------------------------------------
 * _CorExeMain / _CorDllMain - entry points for managed assemblies
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT INT _CorExeMain(void)
{
    fprintf(stderr, "[mscoree] _CorExeMain() - managed executable entry point\n");

    if (try_load_mono() != 0) {
        fprintf(stderr, "[mscoree] ERROR: Cannot run managed executable without "
                ".NET runtime (Mono/CoreCLR)\n");
        return 1;
    }

    if (!pfn_mono_jit_init || !pfn_mono_jit_exec) {
        fprintf(stderr, "[mscoree] ERROR: Mono JIT functions not available\n");
        return 1;
    }

    /*
     * In a full implementation, we would:
     * 1. Read the PE header to find the CLR metadata
     * 2. Extract the managed entry point
     * 3. Initialize the Mono JIT domain
     * 4. Load the assembly and invoke the entry point
     *
     * For now, just report that we need the assembly path.
     */
    fprintf(stderr, "[mscoree] _CorExeMain: Mono JIT available but automatic "
            "managed entry not yet implemented. Use 'mono <assembly.exe>' directly.\n");
    return 1;
}

WINAPI_EXPORT BOOL _CorDllMain(HINSTANCE hInst, DWORD dwReason, LPVOID lpReserved)
{
    (void)hInst;
    (void)dwReason;
    (void)lpReserved;

    fprintf(stderr, "[mscoree] _CorDllMain(reason=%u) - managed DLL entry point\n",
            (unsigned)dwReason);

    return TRUE;
}

/* --------------------------------------------------------------------------
 * GetCORVersion / GetCORRequiredVersion - CLR version queries
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HRESULT GetCORVersion(
    LPWSTR szBuffer, DWORD cchBuffer, DWORD *dwLength)
{
    /* Return CLR 4.0 version string */
    const char *version = "v4.0.30319";
    size_t len = strlen(version);

    if (dwLength)
        *dwLength = (DWORD)(len + 1);

    if (!szBuffer || cchBuffer < len + 1)
        return E_INVALIDARG;

    for (size_t i = 0; i < len; i++)
        szBuffer[i] = (WCHAR)version[i];
    szBuffer[len] = 0;

    return S_OK;
}

WINAPI_EXPORT HRESULT GetCORRequiredVersion(
    LPWSTR szBuffer, DWORD cchBuffer, DWORD *dwLength)
{
    /* Same as GetCORVersion - return v4.0 */
    return GetCORVersion(szBuffer, cchBuffer, dwLength);
}

/* --------------------------------------------------------------------------
 * CoInitializeEE / CoUninitializeEE - EE (Execution Engine) stubs
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HRESULT CoInitializeEE(DWORD fFlags)
{
    (void)fFlags;

    fprintf(stderr, "[mscoree] CoInitializeEE(flags=0x%x) - stub\n", (unsigned)fFlags);

    if (try_load_mono() != 0)
        return E_FAIL;

    return S_OK;
}

WINAPI_EXPORT void CoUninitializeEE(BOOL fFlags)
{
    (void)fFlags;

    fprintf(stderr, "[mscoree] CoUninitializeEE() - stub\n");
}

/* --------------------------------------------------------------------------
 * CorExitProcess - clean shutdown of the CLR
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT void CorExitProcess(INT exitCode)
{
    fprintf(stderr, "[mscoree] CorExitProcess(%d)\n", exitCode);

    if (g_mono_handle && pfn_mono_jit_cleanup) {
        /* Clean up Mono if it was initialized */
        /* pfn_mono_jit_cleanup(domain) - we don't track the domain here */
    }

    _exit(exitCode);
}

/* --------------------------------------------------------------------------
 * GetCORSystemDirectory - path to the CLR installation
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HRESULT GetCORSystemDirectory(
    LPWSTR szBuffer, DWORD cchBuffer, DWORD *dwLength)
{
    const char *dir = "/usr/lib/pe-compat/clr";
    size_t len = strlen(dir);

    if (dwLength)
        *dwLength = (DWORD)(len + 1);

    if (!szBuffer || cchBuffer < len + 1)
        return E_INVALIDARG;

    for (size_t i = 0; i < len; i++)
        szBuffer[i] = (WCHAR)dir[i];
    szBuffer[len] = 0;

    return S_OK;
}
