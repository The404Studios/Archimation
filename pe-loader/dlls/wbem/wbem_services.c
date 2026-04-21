/*
 * wbem_services.c - IWbemServices, the namespace workhorse
 *
 * The only methods we implement with real semantics are ExecQuery and
 * GetObject (path lookup).  Every Get*Async / Put* / Delete* / ExecMethod
 * returns WBEM_E_NOT_SUPPORTED -- our consumers (read-only WMI clients
 * like wmic, PowerShell Get-WmiObject, anti-cheat probes, installer
 * pre-flight scripts) never invoke them.
 *
 * ExecQuery dispatches by FROM-class to one of the wbem_provider_* entry
 * points in wbem_providers.c.  Unrecognised classes return
 * WBEM_E_INVALID_CLASS.
 */

#include "wbem_internal.h"

/* ------------------------------------------------------------------ */
/* IWbemServices vtable -- saturating-ref singleton                    */
/* ------------------------------------------------------------------ */
static __attribute__((ms_abi)) HRESULT svc_qi(void *This, const IID *riid, void **ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (!riid) return E_POINTER;
    if (wbem_guid_eq(riid, &IID_IUnknown_wbem) ||
        wbem_guid_eq(riid, &IID_IWbemServices)) {
        WbemServices *s = (WbemServices *)This;
        atomic_fetch_add(&s->ref, 1);
        *ppv = This;
        return S_OK;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG svc_addref(void *This)
{
    WbemServices *s = (WbemServices *)This;
    return (ULONG)(atomic_fetch_add(&s->ref, 1) + 1);
}

static __attribute__((ms_abi)) ULONG svc_release(void *This)
{
    WbemServices *s = (WbemServices *)This;
    int prev = atomic_fetch_sub(&s->ref, 1);
    if (prev <= 1) {
        atomic_store(&s->ref, 1);
        return 1;
    }
    return (ULONG)(prev - 1);
}

/* Per-arity "no" stubs.  GCC enforces strict pointer-type matches on the
 * vtable initializer, so we cover every concrete signature shape that
 * appears among the methods we don't implement.
 *
 * Naming convention: svc_ns_<sync|async>_<This+arg-count>. */
static __attribute__((ms_abi)) HRESULT svc_ns_sync_5(void *a, void *b, LONG c, void *d, void **e)
{ (void)a; (void)b; (void)c; (void)d; if (e) *e = NULL; return WBEM_E_NOT_SUPPORTED; }

static __attribute__((ms_abi)) HRESULT svc_ns_sync_6(void *a, void *b, void *c, LONG d, void *e, void **f)
{ (void)a; (void)b; (void)c; (void)d; (void)e; if (f) *f = NULL; return WBEM_E_NOT_SUPPORTED; }

/* PutInstance / DeleteInstance share this shape (4 + Out**call) */
static __attribute__((ms_abi)) HRESULT svc_ns_async_5(void *a, void *b, LONG c, void *d, void *e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; return WBEM_E_NOT_SUPPORTED; }

/* ExecQueryAsync / ExecNotificationQueryAsync: This + lang + query + flags + ctx + sink */
static __attribute__((ms_abi)) HRESULT svc_ns_async_q6(void *a, void *b, void *c, LONG d, void *e, void *f)
{ (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; return WBEM_E_NOT_SUPPORTED; }

/* ExecMethod: This + path + method + flags + ctx + in + **out + **call */
static __attribute__((ms_abi)) HRESULT svc_ns_method(void *a, void *b, void *c, LONG d, void *e,
                                                      void *f, void **g, void **h)
{
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
    if (g) *g = NULL;
    if (h) *h = NULL;
    return WBEM_E_NOT_SUPPORTED;
}

/* ExecMethodAsync: This + path + method + flags + ctx + in + sink (7 total) */
static __attribute__((ms_abi)) HRESULT svc_ns_method_async(void *a, void *b, void *c, LONG d,
                                                            void *e, void *f, void *g)
{ (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g; return WBEM_E_NOT_SUPPORTED; }

static __attribute__((ms_abi)) HRESULT svc_open_namespace(void *This, void *str, LONG f,
                                                           void *ctx, void **ns, void **call)
{
    (void)This; (void)str; (void)f; (void)ctx;
    if (call) *call = NULL;
    /* Re-use the same singleton for every namespace path -- callers that
     * want a different one (e.g. ROOT\\WMI vs ROOT\\CIMV2) still get a
     * usable IWbemServices, just one whose providers only know Win32_*. */
    if (!ns) return E_POINTER;
    WbemServices *s = wbem_services_get_singleton();
    s->vtbl->AddRef(s);
    *ns = s;
    return WBEM_S_NO_ERROR;
}

static __attribute__((ms_abi)) HRESULT svc_cancel(void *This, void *sink)
{ (void)This; (void)sink; return WBEM_S_NO_ERROR; }

static __attribute__((ms_abi)) HRESULT svc_qos(void *This, LONG f, void **sink)
{ (void)This; (void)f; if (sink) *sink = NULL; return WBEM_E_NOT_SUPPORTED; }

/* ------------------------------------------------------------------ */
/* GetObject -- path-style instance lookup.  We emulate it by treating */
/* the "path" as a class name and returning a freshly minted (empty)   */
/* template instance, the same way Windows WMI does for class objects. */
/* ------------------------------------------------------------------ */
static __attribute__((ms_abi)) HRESULT svc_get_object(void *This, void *path, LONG f,
                                                      void *ctx, void **obj, void **call)
{
    (void)This; (void)f; (void)ctx;
    if (call) *call = NULL;
    if (!obj) return E_POINTER;
    *obj = NULL;
    if (!path) return WBEM_E_INVALID_PARAMETER;

    char *p = wbem_utf16_to_ascii(path);
    if (!p) return E_OUTOFMEMORY;

    /* "Win32_Foo" or "Win32_Foo.Key='val'" -> take leading class token. */
    char cls[WBEM_QUERY_MAX_CLASS];
    int i = 0;
    while (p[i] && p[i] != '.' && p[i] != '=' && i < (int)sizeof(cls) - 1) {
        cls[i] = p[i]; i++;
    }
    cls[i] = '\0';
    free(p);

    /* Empty template; provider populator can be invoked by the caller via
     * GetNames + Get on a per-property basis. */
    WbemClassObject *o = wbem_classobject_new(cls);
    if (!o) return E_OUTOFMEMORY;
    *obj = o;
    return WBEM_S_NO_ERROR;
}

/* ------------------------------------------------------------------ */
/* ExecQuery -- the workhorse                                           */
/* ------------------------------------------------------------------ */
static __attribute__((ms_abi)) HRESULT svc_exec_query(void *This, void *lang, void *query,
                                                       LONG flags, void *ctx, void **ppEnum)
{
    (void)This; (void)flags; (void)ctx;
    if (!ppEnum) return E_POINTER;
    *ppEnum = NULL;
    if (!lang || !query) return WBEM_E_INVALID_PARAMETER;

    /* QueryLanguage MUST be "WQL" (case-insensitive in practice). */
    char *lang_a = wbem_utf16_to_ascii(lang);
    if (!lang_a) return E_OUTOFMEMORY;
    int wql = wbem_streqi(lang_a, "WQL");
    free(lang_a);
    if (!wql) return WBEM_E_INVALID_QUERY_TYPE;

    wbem_query_t q;
    wbem_parse_query((const uint16_t *)query, &q);
    if (!q.ok) {
        char *qa = wbem_utf16_to_ascii(query);
        fprintf(stderr, "[wbem] ExecQuery: WQL parse failed: %s\n",
                qa ? qa : "(null)");
        free(qa);
        return WBEM_E_INVALID_QUERY;
    }

    /* Log -- noisy but invaluable when an app asks for an unknown class. */
    fprintf(stderr, "[wbem] ExecQuery: SELECT * FROM %s%s%s\n",
            q.from_class,
            q.where_op != WBEM_OP_NONE ? " WHERE " : "",
            q.where_op != WBEM_OP_NONE ? q.where_key : "");

    WbemEnum *e = NULL;

    /* Class dispatch -- case-insensitive on class name, real Windows is
     * case-insensitive here too. */
    if (wbem_streqi(q.from_class, "Win32_OperatingSystem")) {
        e = wbem_provider_os(&q);
    } else if (wbem_streqi(q.from_class, "Win32_Processor")) {
        e = wbem_provider_processor(&q);
    } else if (wbem_streqi(q.from_class, "Win32_Process")) {
        e = wbem_provider_process(&q);
    } else if (wbem_streqi(q.from_class, "Win32_Service")) {
        e = wbem_provider_service(&q);
    } else if (wbem_streqi(q.from_class, "Win32_LogicalDisk")) {
        e = wbem_provider_disk(&q);
    } else if (wbem_streqi(q.from_class, "Win32_NetworkAdapter") ||
               wbem_streqi(q.from_class, "Win32_NetworkAdapterConfiguration")) {
        e = wbem_provider_netadapter(&q);
    } else if (wbem_streqi(q.from_class, "Win32_BIOS")) {
        e = wbem_provider_bios(&q);
    } else if (wbem_streqi(q.from_class, "Win32_ComputerSystem") ||
               wbem_streqi(q.from_class, "Win32_ComputerSystemProduct")) {
        e = wbem_provider_computersystem(&q);
    } else {
        fprintf(stderr, "[wbem] ExecQuery: unknown class %s\n", q.from_class);
        return WBEM_E_INVALID_CLASS;
    }

    if (!e) return WBEM_E_FAILED;
    *ppEnum = e;
    return WBEM_S_NO_ERROR;
}

/* CreateInstanceEnum: "give me everything in this class" -- equivalent to
 * SELECT * FROM <class> with no filter.  We synthesise a query and re-use
 * the same dispatcher. */
static __attribute__((ms_abi)) HRESULT svc_create_inst_enum(void *This, void *cls, LONG f,
                                                             void *ctx, void **ppEnum)
{
    (void)This; (void)f; (void)ctx;
    if (!ppEnum) return E_POINTER;
    *ppEnum = NULL;
    if (!cls) return WBEM_E_INVALID_PARAMETER;

    char *cls_a = wbem_utf16_to_ascii(cls);
    if (!cls_a) return E_OUTOFMEMORY;

    wbem_query_t q;
    memset(&q, 0, sizeof(q));
    q.ok = 1;
    q.select_star = 1;
    snprintf(q.from_class, sizeof(q.from_class), "%s", cls_a);
    q.where_op = WBEM_OP_NONE;
    free(cls_a);

    /* Reuse ExecQuery dispatch logic by manually picking the provider --
     * cleaner than building up a UTF-16 query string just to re-parse it. */
    WbemEnum *e = NULL;
    if      (wbem_streqi(q.from_class, "Win32_OperatingSystem"))  e = wbem_provider_os(&q);
    else if (wbem_streqi(q.from_class, "Win32_Processor"))        e = wbem_provider_processor(&q);
    else if (wbem_streqi(q.from_class, "Win32_Process"))          e = wbem_provider_process(&q);
    else if (wbem_streqi(q.from_class, "Win32_Service"))          e = wbem_provider_service(&q);
    else if (wbem_streqi(q.from_class, "Win32_LogicalDisk"))      e = wbem_provider_disk(&q);
    else if (wbem_streqi(q.from_class, "Win32_NetworkAdapter") ||
             wbem_streqi(q.from_class, "Win32_NetworkAdapterConfiguration"))
                                                                  e = wbem_provider_netadapter(&q);
    else if (wbem_streqi(q.from_class, "Win32_BIOS"))             e = wbem_provider_bios(&q);
    else if (wbem_streqi(q.from_class, "Win32_ComputerSystem") ||
             wbem_streqi(q.from_class, "Win32_ComputerSystemProduct"))
                                                                  e = wbem_provider_computersystem(&q);
    else                                                          return WBEM_E_INVALID_CLASS;

    if (!e) return WBEM_E_FAILED;
    *ppEnum = e;
    return WBEM_S_NO_ERROR;
}

/* ------------------------------------------------------------------ */
/* Vtable assembly                                                      */
/* ------------------------------------------------------------------ */
static IWbemServicesVtbl g_svc_vtbl = {
    .QueryInterface             = svc_qi,
    .AddRef                     = svc_addref,
    .Release                    = svc_release,
    .OpenNamespace              = svc_open_namespace,
    .CancelAsyncCall            = svc_cancel,
    .QueryObjectSink            = svc_qos,
    .GetObject                  = svc_get_object,
    .GetObjectAsync             = svc_ns_async_5,
    .PutClass                   = svc_ns_sync_5,
    .PutClassAsync              = svc_ns_async_5,
    .DeleteClass                = svc_ns_sync_5,
    .DeleteClassAsync           = svc_ns_async_5,
    .CreateClassEnum            = svc_ns_sync_5,
    .CreateClassEnumAsync       = svc_ns_async_5,
    .PutInstance                = svc_ns_sync_5,
    .PutInstanceAsync           = svc_ns_async_5,
    .DeleteInstance             = svc_ns_sync_5,
    .DeleteInstanceAsync        = svc_ns_async_5,
    .CreateInstanceEnum         = svc_create_inst_enum,
    .CreateInstanceEnumAsync    = svc_ns_async_5,
    .ExecQuery                  = svc_exec_query,
    .ExecQueryAsync             = svc_ns_async_q6,
    .ExecNotificationQuery      = svc_ns_sync_6,
    .ExecNotificationQueryAsync = svc_ns_async_q6,
    .ExecMethod                 = svc_ns_method,
    .ExecMethodAsync            = svc_ns_method_async,
};

static WbemServices g_services = {
    .vtbl = &g_svc_vtbl,
    .ref  = 1,
};

WbemServices *wbem_services_get_singleton(void) { return &g_services; }
