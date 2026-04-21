/*
 * dllmain.c - DllGetClassObject entry point for the WMI provider DLL
 *
 * Real Windows ships wbemprox.dll (HKCR\CLSID\{4590f811-1d3a-11d0-891f-
 * 00aa004b2e24}\InprocServer32 -> %SystemRoot%\System32\wbem\wbemprox.dll).
 * Our HKCR-fallback in ole32_classregistry.c will LoadLibraryA() the
 * wbem stub and call DllGetClassObject().  This file is the export
 * surface that satisfies that probe.
 *
 * Constructor priority 110 fires AFTER advapi32's registry init (which
 * uses constructor 100 in our default-population path) so we can write
 * the InprocServer32 entry without racing the hive setup.
 */

#include "wbem_internal.h"

/* Forward decls for the locator-side singletons. */
extern WbemClassFactory *wbem_classfactory_get_singleton(void);

/* ------------------------------------------------------------------ */
/* DllGetClassObject -- the canonical COM entry point                  */
/* ------------------------------------------------------------------ */
WINAPI_EXPORT HRESULT DllGetClassObject(const CLSID *rclsid, const IID *riid, void **ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (!rclsid || !riid) return E_POINTER;

    /* Only one CLSID lives in this DLL (CLSID_WbemLocator).  Anything
     * else and we tell the caller to look elsewhere. */
    if (!wbem_guid_eq(rclsid, &CLSID_WbemLocator))
        return CLASS_E_CLASSNOTAVAILABLE;

    /* Caller wants either IUnknown or IClassFactory off our factory. */
    if (!wbem_guid_eq(riid, &IID_IUnknown_wbem) &&
        !wbem_guid_eq(riid, &IID_IClassFactory_wbem))
        return E_NOINTERFACE;

    WbemClassFactory *cf = wbem_classfactory_get_singleton();
    cf->vtbl->AddRef(cf);
    *ppv = cf;
    return S_OK;
}

/* ------------------------------------------------------------------ */
/* DllCanUnloadNow -- always say no.  Our singletons live forever and  */
/* the loader never unloads stub DLLs in practice.                     */
/* ------------------------------------------------------------------ */
WINAPI_EXPORT HRESULT DllCanUnloadNow(void)
{
    return S_FALSE;
}

/* ------------------------------------------------------------------ */
/* DllRegisterServer / DllUnregisterServer -- regsvr32 hooks.  We can  */
/* run them at install time from objectd or scripts/post-install.sh,   */
/* OR a constructor (below) registers the same data lazily on first    */
/* dlopen so PE apps that bypass install-time tooling still work.      */
/* ------------------------------------------------------------------ */

/* Registry types & roots (mirror of registry_defaults.c). */
#define HKCR_VAL ((HKEY)(uintptr_t)0x80000000)
#define REG_SZ_T 1

/* registry.o (linked into advapi32.so) is reachable through dlsym at
 * runtime via the advapi32 module.  But we can't link advapi32.so here
 * (circular: advapi32 -> ole32 -> wbem -> advapi32).  Instead we resolve
 * the symbol lazily through dlsym(RTLD_DEFAULT, ...) which finds it via
 * advapi32.so once the loader has dlopen'd it. */
#include <dlfcn.h>

typedef LONG (*registry_set_default_fn)(HKEY root, const char *subkey,
                                        const char *name, DWORD type,
                                        const void *data, DWORD size);

static void wbem_register_classes(void)
{
    registry_set_default_fn rsd = (registry_set_default_fn)
        dlsym(RTLD_DEFAULT, "registry_set_default");
    if (!rsd) {
        /* advapi32 not loaded yet; nothing we can do but log.  The HKCR
         * fallback in ole32 will still find us if a later install pass
         * writes the entry, but that's the operator's problem now. */
        fprintf(stderr, "[wbem] registry_set_default not resolvable; "
                        "skipping HKCR self-registration\n");
        return;
    }

    /* HKCR\CLSID\{4590F811-1D3A-11D0-891F-00AA004B2E24}\InprocServer32
     *   (default) = "wbem.dll"
     * The PE-loader DLL search order will resolve "wbem.dll" via the
     * libpe_wbem.so stub. */
    const char *clsid_subkey =
        "CLSID\\{4590F811-1D3A-11D0-891F-00AA004B2E24}\\InprocServer32";
    const char *dll_path     = "wbem.dll";
    rsd(HKCR_VAL, clsid_subkey, NULL, REG_SZ_T,
        dll_path, (DWORD)(strlen(dll_path) + 1));

    const char *ts = "Both";
    rsd(HKCR_VAL, clsid_subkey, "ThreadingModel", REG_SZ_T,
        ts, (DWORD)(strlen(ts) + 1));

    /* Friendly ProgID -> CLSID mapping that some clients walk. */
    const char *progid_subkey = "WbemScripting.SWbemLocator\\CLSID";
    const char *clsid_str = "{4590F811-1D3A-11D0-891F-00AA004B2E24}";
    rsd(HKCR_VAL, progid_subkey, NULL, REG_SZ_T,
        clsid_str, (DWORD)(strlen(clsid_str) + 1));

    fprintf(stderr, "[wbem] HKCR\\CLSID\\{4590F811-...} registered -> wbem.dll\n");
}

WINAPI_EXPORT HRESULT DllRegisterServer(void)
{
    wbem_register_classes();
    return S_OK;
}

WINAPI_EXPORT HRESULT DllUnregisterServer(void)
{
    /* No-op: HKCR entries are written once and persist via the registry
     * hive on disk.  CoCreateInstance callers that need them gone can
     * RegDeleteKey directly. */
    return S_OK;
}

/* ------------------------------------------------------------------ */
/* Constructor -- lazy HKCR registration on first dlopen                */
/* ------------------------------------------------------------------ */
__attribute__((constructor(150)))
static void wbem_dll_init(void)
{
    fprintf(stderr, "[wbem] libpe_wbem.so loaded; registering "
                    "CLSID_WbemLocator -> wbem.dll\n");
    wbem_register_classes();
}
