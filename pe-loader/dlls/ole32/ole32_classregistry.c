/*
 * ole32_classregistry.c - COM class registry and factory system
 *
 * Implements a real class registry that supports CoRegisterClassObject /
 * CoRevokeClassObject and allows CoCreateInstance to instantiate objects
 * through registered IClassFactory interfaces.  Also provides GUID string
 * parsing/formatting, the COM task allocator, and random GUID generation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif

#include "common/dll_common.h"

/* ------------------------------------------------------------------ */
/* HRESULT constants                                                   */
/* ------------------------------------------------------------------ */
#define S_OK                        ((HRESULT)0x00000000)
#define S_FALSE                     ((HRESULT)0x00000001)
#define E_NOTIMPL                   ((HRESULT)0x80004001)
#define E_NOINTERFACE               ((HRESULT)0x80004002)
#define E_POINTER                   ((HRESULT)0x80004003)
#define E_FAIL                      ((HRESULT)0x80004005)
#define E_OUTOFMEMORY               ((HRESULT)0x8007000E)
#define E_INVALIDARG                ((HRESULT)0x80070057)
#define CLASS_E_CLASSNOTAVAILABLE   ((HRESULT)0x80040111)
#define REGDB_E_CLASSNOTREG         ((HRESULT)0x80040154)
#define RPC_E_CHANGED_MODE          ((HRESULT)0x80010106)
#define CO_E_NOTINITIALIZED         ((HRESULT)0x800401F0)

/* COINIT flags */
#define COINIT_MULTITHREADED        0x0
#define COINIT_APARTMENTTHREADED    0x2
#define COINIT_DISABLE_OLE1DDE      0x4
#define COINIT_SPEED_OVER_MEMORY    0x8

/* CLSCTX flags */
#define CLSCTX_INPROC_SERVER        0x1
#define CLSCTX_INPROC_HANDLER       0x2
#define CLSCTX_LOCAL_SERVER         0x4
#define CLSCTX_REMOTE_SERVER        0x10

/* REGCLS flags */
#define REGCLS_SINGLEUSE            0
#define REGCLS_MULTIPLEUSE          1
#define REGCLS_MULTI_SEPARATE       2
#define REGCLS_SUSPENDED            4

/* ------------------------------------------------------------------ */
/* COM type definitions                                                */
/* ------------------------------------------------------------------ */
typedef GUID CLSID;
typedef GUID IID;
typedef GUID *REFCLSID;
typedef GUID *REFIID;

/*
 * IClassFactory vtable -- the minimal COM interface every class factory
 * must implement.  We store a void* to the factory object and call
 * through this vtable when CoCreateInstance is invoked.
 */
typedef struct IClassFactoryVtbl {
    __attribute__((ms_abi)) HRESULT (*QueryInterface)(void *This, const IID *riid, void **ppvObject);
    __attribute__((ms_abi)) ULONG   (*AddRef)(void *This);
    __attribute__((ms_abi)) ULONG   (*Release)(void *This);
    __attribute__((ms_abi)) HRESULT (*CreateInstance)(void *This, void *pUnkOuter, const IID *riid, void **ppvObject);
    __attribute__((ms_abi)) HRESULT (*LockServer)(void *This, BOOL fLock);
} IClassFactoryVtbl;

/* Well-known IIDs */
static const IID IID_IUnknown = {
    0x00000000, 0x0000, 0x0000,
    { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

static const IID IID_IClassFactory = {
    0x00000001, 0x0000, 0x0000,
    { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

/* ------------------------------------------------------------------ */
/* Per-thread COM initialisation state                                 */
/* ------------------------------------------------------------------ */
static __thread int  com_init_count = 0;
static __thread DWORD com_init_flags = 0;

/* ------------------------------------------------------------------ */
/* Class registry -- thread-safe table of registered class factories    */
/* ------------------------------------------------------------------ */
#define MAX_CLASS_REGISTRATIONS 256

typedef struct {
    int      in_use;
    CLSID    clsid;
    void    *factory;           /* IClassFactory* */
    DWORD    cls_context;
    DWORD    regcls_flags;
    DWORD    cookie;            /* registration cookie for CoRevokeClassObject */
} class_registration_t;

static class_registration_t g_class_registry[MAX_CLASS_REGISTRATIONS];
static DWORD                g_next_cookie = 1;
static pthread_mutex_t      g_registry_lock = PTHREAD_MUTEX_INITIALIZER;

/* ------------------------------------------------------------------ */
/* GUID helpers (internal)                                             */
/* ------------------------------------------------------------------ */
static int guid_equal(const GUID *a, const GUID *b)
{
    return memcmp(a, b, sizeof(GUID)) == 0;
}

/* Parse a hex digit; returns -1 on invalid input. */
static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse `count` hex characters from `*p` into `out`, advance `*p`. */
static int parse_hex(const char **p, unsigned long long *out, int count)
{
    unsigned long long val = 0;
    for (int i = 0; i < count; i++) {
        int d = hex_digit(**p);
        if (d < 0) return -1;
        val = (val << 4) | (unsigned long long)d;
        (*p)++;
    }
    *out = val;
    return 0;
}

/* Parse a GUID string of the form {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
 * or XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX (braces optional).
 * Works with both narrow and wide strings (caller converts). */
static int parse_guid_string(const char *str, GUID *guid)
{
    if (!str || !guid)
        return -1;

    const char *p = str;

    /* Skip optional leading brace */
    int has_brace = 0;
    if (*p == '{') {
        has_brace = 1;
        p++;
    }

    unsigned long long val;

    /* Data1: 8 hex digits */
    if (parse_hex(&p, &val, 8) < 0) return -1;
    guid->Data1 = (DWORD)val;

    if (*p != '-') return -1;
    p++;

    /* Data2: 4 hex digits */
    if (parse_hex(&p, &val, 4) < 0) return -1;
    guid->Data2 = (WORD)val;

    if (*p != '-') return -1;
    p++;

    /* Data3: 4 hex digits */
    if (parse_hex(&p, &val, 4) < 0) return -1;
    guid->Data3 = (WORD)val;

    if (*p != '-') return -1;
    p++;

    /* Data4[0..1]: 4 hex digits (2 bytes) */
    if (parse_hex(&p, &val, 2) < 0) return -1;
    guid->Data4[0] = (BYTE)val;
    if (parse_hex(&p, &val, 2) < 0) return -1;
    guid->Data4[1] = (BYTE)val;

    if (*p != '-') return -1;
    p++;

    /* Data4[2..7]: 12 hex digits (6 bytes) */
    for (int i = 2; i < 8; i++) {
        if (parse_hex(&p, &val, 2) < 0) return -1;
        guid->Data4[i] = (BYTE)val;
    }

    /* Skip optional trailing brace */
    if (has_brace) {
        if (*p != '}') return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* CoInitialize / CoInitializeEx / CoUninitialize                      */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT HRESULT CoInitialize(LPVOID pvReserved)
{
    (void)pvReserved;

    if (com_init_count > 0) {
        /* Detect apartment mode mismatch: CoInitialize implies STA */
        if (!(com_init_flags & COINIT_APARTMENTTHREADED)) {
            return RPC_E_CHANGED_MODE;
        }
        com_init_count++;
        return S_FALSE;
    }

    com_init_count = 1;
    com_init_flags = COINIT_APARTMENTTHREADED;
    return S_OK;
}

WINAPI_EXPORT HRESULT CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit)
{
    (void)pvReserved;

    if (com_init_count > 0) {
        /* Detect apartment mode mismatch */
        if ((dwCoInit & COINIT_APARTMENTTHREADED) !=
            (com_init_flags & COINIT_APARTMENTTHREADED)) {
            return RPC_E_CHANGED_MODE;
        }
        com_init_count++;
        return S_FALSE;
    }

    com_init_count = 1;
    com_init_flags = dwCoInit;
    return S_OK;
}

WINAPI_EXPORT void CoUninitialize(void)
{
    if (com_init_count > 0)
        com_init_count--;
}

/* ------------------------------------------------------------------ */
/* Class registry operations                                           */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT HRESULT CoRegisterClassObject(
    const CLSID *rclsid,
    void        *pUnk,          /* IUnknown* (must support IClassFactory) */
    DWORD        dwClsContext,
    DWORD        flags,
    LPDWORD      lpdwRegister)
{
    if (!rclsid || !pUnk)
        return E_INVALIDARG;

    pthread_mutex_lock(&g_registry_lock);

    /* Find a free slot */
    int slot = -1;
    for (int i = 0; i < MAX_CLASS_REGISTRATIONS; i++) {
        if (!g_class_registry[i].in_use) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        pthread_mutex_unlock(&g_registry_lock);
        fprintf(stderr, "[ole32] CoRegisterClassObject: registry full\n");
        return E_OUTOFMEMORY;
    }

    class_registration_t *reg = &g_class_registry[slot];
    reg->in_use       = 1;
    memcpy(&reg->clsid, rclsid, sizeof(CLSID));
    reg->factory       = pUnk;
    reg->cls_context   = dwClsContext;
    reg->regcls_flags  = flags;
    reg->cookie        = g_next_cookie++;

    if (lpdwRegister)
        *lpdwRegister = reg->cookie;

    pthread_mutex_unlock(&g_registry_lock);
    return S_OK;
}

WINAPI_EXPORT HRESULT CoRevokeClassObject(DWORD dwRegister)
{
    pthread_mutex_lock(&g_registry_lock);

    for (int i = 0; i < MAX_CLASS_REGISTRATIONS; i++) {
        if (g_class_registry[i].in_use &&
            g_class_registry[i].cookie == dwRegister) {
            g_class_registry[i].in_use = 0;
            memset(&g_class_registry[i], 0, sizeof(class_registration_t));
            pthread_mutex_unlock(&g_registry_lock);
            return S_OK;
        }
    }

    pthread_mutex_unlock(&g_registry_lock);
    return E_INVALIDARG;
}

/* Look up a registered class factory by CLSID.  Returns the factory
 * pointer or NULL.  Caller must hold g_registry_lock or accept a race. */
static void *find_class_factory(const CLSID *clsid)
{
    for (int i = 0; i < MAX_CLASS_REGISTRATIONS; i++) {
        if (g_class_registry[i].in_use &&
            guid_equal(&g_class_registry[i].clsid, clsid)) {
            return g_class_registry[i].factory;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* CoGetClassObject                                                    */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT HRESULT CoGetClassObject(
    const CLSID *rclsid,
    DWORD        dwClsContext,
    void        *pvReserved,
    const IID   *riid,
    void       **ppv)
{
    (void)dwClsContext;
    (void)pvReserved;

    if (!rclsid || !riid || !ppv)
        return E_POINTER;

    *ppv = NULL;

    pthread_mutex_lock(&g_registry_lock);
    void *factory = find_class_factory(rclsid);
    /* AddRef while holding the lock so CoRevokeClassObject on another
     * thread cannot drop the last reference and destroy the factory
     * between lookup and AddRef. */
    if (factory &&
        (guid_equal(riid, &IID_IClassFactory) || guid_equal(riid, &IID_IUnknown))) {
        IClassFactoryVtbl **vtbl_ptr = (IClassFactoryVtbl **)factory;
        if (*vtbl_ptr && (*vtbl_ptr)->AddRef)
            (*vtbl_ptr)->AddRef(factory);
        pthread_mutex_unlock(&g_registry_lock);
        *ppv = factory;
        return S_OK;
    }
    pthread_mutex_unlock(&g_registry_lock);

    if (!factory) {
        fprintf(stderr, "[ole32] CoGetClassObject: CLSID {%08X-...} not registered\n",
                rclsid->Data1);
        return REGDB_E_CLASSNOTREG;
    }

    return E_NOINTERFACE;
}

/* ------------------------------------------------------------------ */
/* CoCreateInstance                                                     */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT HRESULT CoCreateInstance(
    const CLSID *rclsid,
    void        *pUnkOuter,
    DWORD        dwClsContext,
    const IID   *riid,
    void       **ppv)
{
    if (!rclsid || !riid || !ppv)
        return E_POINTER;

    *ppv = NULL;

    /* Look up the class factory */
    void *factory = NULL;
    HRESULT hr;

    hr = CoGetClassObject(rclsid, dwClsContext, NULL, &IID_IClassFactory, &factory);
    if (hr != S_OK || !factory)
        return (hr == S_OK) ? REGDB_E_CLASSNOTREG : hr;

    /* Call IClassFactory::CreateInstance */
    IClassFactoryVtbl **vtbl_ptr = (IClassFactoryVtbl **)factory;
    if (!*vtbl_ptr || !(*vtbl_ptr)->CreateInstance) {
        /* Release the factory reference we just acquired */
        if (*vtbl_ptr && (*vtbl_ptr)->Release)
            (*vtbl_ptr)->Release(factory);
        return E_NOINTERFACE;
    }

    hr = (*vtbl_ptr)->CreateInstance(factory, pUnkOuter, riid, ppv);

    /* Release the factory */
    if (*vtbl_ptr && (*vtbl_ptr)->Release)
        (*vtbl_ptr)->Release(factory);

    return hr;
}

/* ------------------------------------------------------------------ */
/* GUID / CLSID string conversion                                     */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT HRESULT CLSIDFromString(LPCWSTR lpsz, CLSID *pclsid)
{
    if (!pclsid)
        return E_POINTER;

    memset(pclsid, 0, sizeof(CLSID));

    if (!lpsz)
        return E_INVALIDARG;

    /* Convert wide string to narrow for parsing */
    char narrow[64];
    int i;
    for (i = 0; i < 63 && lpsz[i] != 0; i++)
        narrow[i] = (char)(lpsz[i] & 0x7F);
    narrow[i] = '\0';

    if (parse_guid_string(narrow, pclsid) < 0) {
        memset(pclsid, 0, sizeof(CLSID));
        return E_INVALIDARG;
    }

    return S_OK;
}

WINAPI_EXPORT HRESULT StringFromCLSID(const CLSID *rclsid, LPWSTR *lplpsz)
{
    if (!rclsid || !lplpsz)
        return E_POINTER;

    /* Allocate 39 wide chars: {8-4-4-4-12}\0 = 38 + 1 */
    WCHAR *buf = (WCHAR *)malloc(39 * sizeof(WCHAR));
    if (!buf)
        return E_OUTOFMEMORY;

    char narrow[39];
    snprintf(narrow, sizeof(narrow),
             "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
             rclsid->Data1, rclsid->Data2, rclsid->Data3,
             rclsid->Data4[0], rclsid->Data4[1],
             rclsid->Data4[2], rclsid->Data4[3],
             rclsid->Data4[4], rclsid->Data4[5],
             rclsid->Data4[6], rclsid->Data4[7]);

    for (int i = 0; i < 39; i++)
        buf[i] = (WCHAR)narrow[i];

    *lplpsz = buf;
    return S_OK;
}

WINAPI_EXPORT int StringFromGUID2(const GUID *rguid, LPWSTR lpsz, int cchMax)
{
    if (!rguid || !lpsz || cchMax < 39)
        return 0;

    char narrow[39];
    snprintf(narrow, sizeof(narrow),
             "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
             rguid->Data1, rguid->Data2, rguid->Data3,
             rguid->Data4[0], rguid->Data4[1],
             rguid->Data4[2], rguid->Data4[3],
             rguid->Data4[4], rguid->Data4[5],
             rguid->Data4[6], rguid->Data4[7]);

    for (int i = 0; i < 39; i++)
        lpsz[i] = (WCHAR)narrow[i];

    return 39;  /* number of characters written, including NUL */
}

WINAPI_EXPORT HRESULT CLSIDFromProgID(LPCWSTR lpszProgID, CLSID *lpclsid)
{
    (void)lpszProgID;

    if (!lpclsid)
        return E_POINTER;

    /* We have no ProgID registry -- always fail */
    memset(lpclsid, 0, sizeof(CLSID));
    return REGDB_E_CLASSNOTREG;
}

/* ------------------------------------------------------------------ */
/* COM task memory allocator                                           */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT LPVOID CoTaskMemAlloc(SIZE_T cb)
{
    if (cb == 0)
        return NULL;
    return malloc(cb);
}

WINAPI_EXPORT LPVOID CoTaskMemRealloc(LPVOID pv, SIZE_T cb)
{
    if (cb == 0) {
        free(pv);
        return NULL;
    }
    return realloc(pv, cb);
}

WINAPI_EXPORT void CoTaskMemFree(LPVOID pv)
{
    free(pv);
}

/* ------------------------------------------------------------------ */
/* OLE initialisation (superset of COM)                                */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT HRESULT OleInitialize(LPVOID pvReserved)
{
    return CoInitializeEx(pvReserved, COINIT_APARTMENTTHREADED);
}

WINAPI_EXPORT void OleUninitialize(void)
{
    CoUninitialize();
}

/* ------------------------------------------------------------------ */
/* PropVariantClear                                                    */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT HRESULT PropVariantClear(void *pvar)
{
    if (pvar)
        memset(pvar, 0, 24); /* PROPVARIANT is ~24 bytes */
    return S_OK;
}

/* ------------------------------------------------------------------ */
/* Marshalling stubs                                                   */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT HRESULT CoMarshalInterface(
    void       *pStm,
    const IID  *riid,
    void       *pUnk,
    DWORD       dwDestContext,
    void       *pvDestContext,
    DWORD       mshlflags)
{
    (void)pStm;
    (void)riid;
    (void)pUnk;
    (void)dwDestContext;
    (void)pvDestContext;
    (void)mshlflags;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT CoUnmarshalInterface(
    void       *pStm,
    const IID  *riid,
    void      **ppv)
{
    (void)pStm;
    (void)riid;
    if (ppv) *ppv = NULL;
    return E_NOTIMPL;
}

/* ------------------------------------------------------------------ */
/* CoCreateGuid -- generate a random version-4 GUID                    */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT HRESULT CoCreateGuid(GUID *pguid)
{
    if (!pguid)
        return E_POINTER;

    int filled = 0;
    /* Session 30: CoCreateGuid was opening /dev/urandom on every call with
     * fopen, adding two syscalls per GUID. Games/installers generate a lot
     * of GUIDs at startup (one per registered class). Use getrandom(2) first
     * for a single syscall, falling back to /dev/urandom. We don't link against
     * bcrypt here to avoid a cross-DLL ms_abi/sysv_abi calling-convention
     * mismatch — a direct syscall / read() stays in sysv_abi. */
#if defined(__linux__)
    {
# ifndef SYS_getrandom
#  define SYS_getrandom 318
# endif
        ssize_t got = 0;
        while ((size_t)got < 16) {
            long r = syscall(SYS_getrandom, (uint8_t *)pguid + got, 16 - got, 0);
            if (r > 0) { got += r; continue; }
            if (r < 0 && errno == EINTR) continue;
            break;
        }
        if (got == 16) filled = 1;
    }
#endif
    if (!filled) {
        FILE *f = fopen("/dev/urandom", "rb");
        if (f) {
            if (fread(pguid, 1, 16, f) == 16) filled = 1;
            fclose(f);
        }
    }
    if (!filled) {
        /* Last-resort weak PRNG — never in normal operation. */
        srand((unsigned int)((uintptr_t)pguid ^ (uintptr_t)&filled));
        for (int i = 0; i < 16; i++)
            ((BYTE *)pguid)[i] = (BYTE)(rand() & 0xFF);
    }

    /* Set version to 4 (random) in Data3: top nibble = 0100b */
    pguid->Data3 = (pguid->Data3 & 0x0FFF) | 0x4000;

    /* Set variant to RFC 4122: top bits of Data4[0] = 10b */
    pguid->Data4[0] = (pguid->Data4[0] & 0x3F) | 0x80;

    return S_OK;
}

/* ------------------------------------------------------------------ */
/* IsEqualGUID                                                         */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT int IsEqualGUID(const GUID *g1, const GUID *g2)
{
    if (!g1 || !g2)
        return 0;
    return memcmp(g1, g2, sizeof(GUID)) == 0;
}
