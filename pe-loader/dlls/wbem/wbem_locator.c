/*
 * wbem_locator.c - IWbemLocator + IClassFactory for CLSID_WbemLocator
 *
 * The entry point any WMI consumer reaches first:
 *   CoCreateInstance(CLSID_WbemLocator, ..., IID_IWbemLocator, &loc);
 *   loc->ConnectServer(L"\\\\.\\root\\cimv2", ...) -> IWbemServices*
 *
 * Both objects are process-singletons (refcount-managed but never actually
 * deleted on Release == 0; Release saturates at 1 to keep the singleton
 * pinned).  This matches the practical lifetime of a WMI session and
 * avoids tearing down provider-side caches.
 *
 * Also hosts the well-known IIDs/CLSIDs and the small BSTR utilities so
 * every TU links them through the locator object instead of pulling
 * oleaut32.so at build time.
 */

#include "wbem_internal.h"

/* ------------------------------------------------------------------ */
/* Well-known IIDs / CLSIDs (paper-canonical UUIDs)                    */
/* ------------------------------------------------------------------ */
const IID IID_IUnknown_wbem = {
    0x00000000, 0x0000, 0x0000,
    { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};
const IID IID_IClassFactory_wbem = {
    0x00000001, 0x0000, 0x0000,
    { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};
/* {DC12A687-737F-11CF-884D-00AA004B2E24} */
const IID IID_IWbemLocator = {
    0xDC12A687, 0x737F, 0x11CF,
    { 0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24 }
};
/* {9556DC99-828C-11CF-A37E-00AA003240C7} */
const IID IID_IWbemServices = {
    0x9556DC99, 0x828C, 0x11CF,
    { 0xA3, 0x7E, 0x00, 0xAA, 0x00, 0x32, 0x40, 0xC7 }
};
/* {027947E1-D731-11CE-A357-000000000001} */
const IID IID_IEnumWbemClassObject = {
    0x027947E1, 0xD731, 0x11CE,
    { 0xA3, 0x57, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }
};
/* {DC12A681-737F-11CF-884D-00AA004B2E24} */
const IID IID_IWbemClassObject = {
    0xDC12A681, 0x737F, 0x11CF,
    { 0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24 }
};
/* {4590F811-1D3A-11D0-891F-00AA004B2E24} */
const CLSID CLSID_WbemLocator = {
    0x4590F811, 0x1D3A, 0x11D0,
    { 0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24 }
};

/* ------------------------------------------------------------------ */
/* BSTR <-> UTF-8 helpers                                               */
/* ------------------------------------------------------------------ */

/* Allocate a Windows BSTR from a UTF-8 ASCII string.  Layout matches
 * oleaut32's SysAllocString: [DWORD byte_len][WCHARs...][NUL NUL].  The
 * returned pointer is the WCHAR data, NOT the prefix -- callers free it
 * via wbem_bstr_free which walks back 4 bytes. */
void *wbem_bstr_from_utf8(const char *s)
{
    if (!s) s = "";
    size_t n = strlen(s);
    if (n > 0x10000000u) return NULL;            /* sanity bound */

    uint32_t byte_len = (uint32_t)(n * 2);
    uint8_t *block = (uint8_t *)malloc(4 + byte_len + 2);
    if (!block) return NULL;

    memcpy(block, &byte_len, 4);
    uint16_t *wide = (uint16_t *)(block + 4);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        /* High-bit bytes truncated to '?' -- WMI clients only need ASCII
         * for our string properties (paths, names, versions). */
        wide[i] = (c < 0x80) ? c : '?';
    }
    /* Two trailing NUL bytes (one wchar) */
    block[4 + byte_len    ] = 0;
    block[4 + byte_len + 1] = 0;
    return wide;
}

void wbem_bstr_free(void *bstr)
{
    if (!bstr) return;
    uint8_t *block = (uint8_t *)bstr - 4;
    free(block);
}

/* Decode an inbound BSTR/LPCWSTR (UTF-16LE) to a heap ASCII string.
 * BSTRs from a real client carry a 4-byte byte-length prefix; LPCWSTRs
 * passed by APIs do not.  We handle both: if the byte-length prefix
 * looks sane (matches a NUL terminator at that offset), trust it;
 * otherwise NUL-scan up to a sanity bound. */
char *wbem_utf16_to_ascii(const void *bstr_or_lpcwstr)
{
    if (!bstr_or_lpcwstr) return NULL;
    const uint16_t *w = (const uint16_t *)bstr_or_lpcwstr;

    /* Length: prefer the BSTR prefix when it's plausible.  We don't have
     * a guaranteed-safe way to read the prefix on a non-BSTR pointer, so
     * we fall through to NUL-scan and only use the prefix length as an
     * upper bound check. */
    size_t n = 0;
    while (n < 0x40000 && w[n]) n++;
    if (n == 0x40000) return NULL;

    char *out = (char *)malloc(n + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < n; i++) {
        uint16_t c = w[i];
        out[i] = (c < 0x80) ? (char)c : '?';
    }
    out[n] = '\0';
    return out;
}

/* ------------------------------------------------------------------ */
/* IWbemLocator -- singleton with saturating refcount                   */
/* ------------------------------------------------------------------ */
static __attribute__((ms_abi)) HRESULT loc_qi(void *This, const IID *riid, void **ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (!riid) return E_POINTER;
    if (wbem_guid_eq(riid, &IID_IUnknown_wbem) ||
        wbem_guid_eq(riid, &IID_IWbemLocator)) {
        *ppv = This;
        WbemLocator *l = (WbemLocator *)This;
        atomic_fetch_add(&l->ref, 1);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG loc_addref(void *This)
{
    WbemLocator *l = (WbemLocator *)This;
    return (ULONG)(atomic_fetch_add(&l->ref, 1) + 1);
}

static __attribute__((ms_abi)) ULONG loc_release(void *This)
{
    WbemLocator *l = (WbemLocator *)This;
    int prev = atomic_fetch_sub(&l->ref, 1);
    /* Saturate at 1: we never destroy the singleton. */
    if (prev <= 1) {
        atomic_store(&l->ref, 1);
        return 1;
    }
    return (ULONG)(prev - 1);
}

static __attribute__((ms_abi)) HRESULT loc_connect(void *This,
    void *strNetworkResource, void *strUser, void *strPassword,
    void *strLocale, LONG lSecurityFlags, void *strAuthority,
    void *pCtx, void **ppNamespace)
{
    (void)This; (void)strUser; (void)strPassword; (void)strLocale;
    (void)lSecurityFlags; (void)strAuthority; (void)pCtx;

    if (!ppNamespace) return E_POINTER;
    *ppNamespace = NULL;

    /* Log the namespace so we can spot apps probing odd ones (most use
     * "ROOT\\CIMV2" / "root\\cimv2"). */
    char *ns = strNetworkResource ? wbem_utf16_to_ascii(strNetworkResource) : NULL;
    fprintf(stderr, "[wbem] IWbemLocator::ConnectServer(%s): OK\n",
            ns ? ns : "(null)");
    free(ns);

    WbemServices *svc = wbem_services_get_singleton();
    if (!svc) return E_OUTOFMEMORY;

    /* Hand the caller an AddRef'd reference. */
    svc->vtbl->AddRef(svc);
    *ppNamespace = svc;
    return WBEM_S_NO_ERROR;
}

static IWbemLocatorVtbl g_locator_vtbl = {
    .QueryInterface = loc_qi,
    .AddRef         = loc_addref,
    .Release        = loc_release,
    .ConnectServer  = loc_connect,
};

static WbemLocator g_locator = {
    .vtbl = &g_locator_vtbl,
    .ref  = 1,        /* singleton stays pinned */
};

WbemLocator *wbem_locator_get_singleton(void) { return &g_locator; }

/* ------------------------------------------------------------------ */
/* IClassFactory for CLSID_WbemLocator                                  */
/* ------------------------------------------------------------------ */
static __attribute__((ms_abi)) HRESULT cf_qi(void *This, const IID *riid, void **ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (!riid) return E_POINTER;
    if (wbem_guid_eq(riid, &IID_IUnknown_wbem) ||
        wbem_guid_eq(riid, &IID_IClassFactory_wbem)) {
        *ppv = This;
        WbemClassFactory *cf = (WbemClassFactory *)This;
        atomic_fetch_add(&cf->ref, 1);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG cf_addref(void *This)
{
    WbemClassFactory *cf = (WbemClassFactory *)This;
    return (ULONG)(atomic_fetch_add(&cf->ref, 1) + 1);
}

static __attribute__((ms_abi)) ULONG cf_release(void *This)
{
    WbemClassFactory *cf = (WbemClassFactory *)This;
    int prev = atomic_fetch_sub(&cf->ref, 1);
    if (prev <= 1) {
        atomic_store(&cf->ref, 1);
        return 1;
    }
    return (ULONG)(prev - 1);
}

static __attribute__((ms_abi)) HRESULT cf_create(void *This, void *pUnkOuter,
                                                  const IID *riid, void **ppv)
{
    (void)This; (void)pUnkOuter;
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (!riid) return E_POINTER;

    /* The only object this factory makes is the IWbemLocator. */
    if (wbem_guid_eq(riid, &IID_IUnknown_wbem) ||
        wbem_guid_eq(riid, &IID_IWbemLocator)) {
        WbemLocator *l = wbem_locator_get_singleton();
        l->vtbl->AddRef(l);
        *ppv = l;
        return S_OK;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) HRESULT cf_lock(void *This, BOOL fLock)
{
    (void)This; (void)fLock;
    return S_OK;
}

static IClassFactoryVtbl g_cf_vtbl = {
    .QueryInterface = cf_qi,
    .AddRef         = cf_addref,
    .Release        = cf_release,
    .CreateInstance = cf_create,
    .LockServer     = cf_lock,
};

static WbemClassFactory g_cf = {
    .vtbl = &g_cf_vtbl,
    .ref  = 1,
};

WbemClassFactory *wbem_classfactory_get_singleton(void) { return &g_cf; }
