/*
 * wbem_classobject.c - IWbemClassObject (a row in a WMI result set)
 *
 * Backed by an ordered append-only property store.  Get(L"PropName", ...)
 * does a linear scan -- with the property counts we ship (10-30 per row),
 * a hash table would be slower than the cache-resident scan.
 *
 * The variant we hand back has VT_BSTR strings allocated from our own
 * BSTR helper (oleaut32-compatible layout).  Callers that VariantClear()
 * the result will free the BSTR through SysFreeString -- which walks
 * back 4 bytes and free()s the prefix block, exactly what wbem_bstr_free
 * does.
 */

#include "wbem_internal.h"

/* Forward decls for the vtable so we can take their address inside this TU. */
static __attribute__((ms_abi)) HRESULT obj_qi(void *This, const IID *riid, void **ppv);
static __attribute__((ms_abi)) ULONG   obj_addref(void *This);
static __attribute__((ms_abi)) ULONG   obj_release(void *This);
static __attribute__((ms_abi)) HRESULT obj_get(void *This, void *name, LONG f,
                                                WBEM_VARIANT *v, LONG *type, LONG *flavor);
static __attribute__((ms_abi)) HRESULT obj_get_names(void *This, void *qual, LONG f,
                                                      WBEM_VARIANT *v, void **names);
static __attribute__((ms_abi)) HRESULT obj_begin_enum(void *This, LONG f);
static __attribute__((ms_abi)) HRESULT obj_next(void *This, LONG f, void **name,
                                                 WBEM_VARIANT *v, LONG *type, LONG *flavor);
static __attribute__((ms_abi)) HRESULT obj_end_enum(void *This);
static __attribute__((ms_abi)) HRESULT obj_clone(void *This, void **out);
static __attribute__((ms_abi)) HRESULT obj_inherits(void *This, void *anc);

/* Catch-all NOT_SUPPORTED stubs.  Per-arity to satisfy GCC's typed
 * function-pointer assignments under -Wall. */
static __attribute__((ms_abi)) HRESULT obj_ns1(void *a)
{ (void)a; return WBEM_E_NOT_SUPPORTED; }
static __attribute__((ms_abi)) HRESULT obj_ns2(void *a, void *b)
{ (void)a; (void)b; return WBEM_E_NOT_SUPPORTED; }
static __attribute__((ms_abi)) HRESULT obj_ns_put(void *a, void *b, LONG c, WBEM_VARIANT *d, LONG e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; return WBEM_E_NOT_SUPPORTED; }
static __attribute__((ms_abi)) HRESULT obj_ns_pq(void *a, void *b, void **c)
{ (void)a; (void)b; if (c) *c = NULL; return WBEM_E_NOT_SUPPORTED; }
static __attribute__((ms_abi)) HRESULT obj_ns_text(void *a, LONG b, void **c)
{ (void)a; (void)b; if (c) *c = NULL; return WBEM_E_NOT_SUPPORTED; }
static __attribute__((ms_abi)) HRESULT obj_ns_spawn(void *a, LONG b, void **c)
{ (void)a; (void)b; if (c) *c = NULL; return WBEM_E_NOT_SUPPORTED; }
static __attribute__((ms_abi)) HRESULT obj_ns_qs(void *a, void **b)
{ (void)a; if (b) *b = NULL; return WBEM_E_NOT_SUPPORTED; }
static __attribute__((ms_abi)) HRESULT obj_ns_cmp(void *a, LONG b, void *c)
{ (void)a; (void)b; (void)c; return WBEM_E_NOT_SUPPORTED; }
static __attribute__((ms_abi)) HRESULT obj_ns_method(void *a, void *b, LONG c, void **d, void **e)
{ (void)a; (void)b; (void)c; if (d) *d = NULL; if (e) *e = NULL; return WBEM_E_NOT_SUPPORTED; }
static __attribute__((ms_abi)) HRESULT obj_ns_method_put(void *a, void *b, LONG c, void *d, void *e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; return WBEM_E_NOT_SUPPORTED; }
static __attribute__((ms_abi)) HRESULT obj_ns_method_next(void *a, LONG b, void **c, void **d, void **e)
{ (void)a; (void)b; if (c) *c = NULL; if (d) *d = NULL; if (e) *e = NULL; return WBEM_E_NOT_SUPPORTED; }
static __attribute__((ms_abi)) HRESULT obj_ns_method_begin(void *a, LONG b)
{ (void)a; (void)b; return WBEM_E_NOT_SUPPORTED; }

static IWbemClassObjectVtbl g_obj_vtbl = {
    .QueryInterface          = obj_qi,
    .AddRef                  = obj_addref,
    .Release                 = obj_release,
    .GetQualifierSet         = obj_ns_qs,
    .Get                     = obj_get,
    .Put                     = obj_ns_put,
    .Delete                  = obj_ns2,
    .GetNames                = obj_get_names,
    .BeginEnumeration        = obj_begin_enum,
    .Next                    = obj_next,
    .EndEnumeration          = obj_end_enum,
    .GetPropertyQualifierSet = obj_ns_pq,
    .Clone                   = obj_clone,
    .GetObjectText           = obj_ns_text,
    .SpawnDerivedClass       = obj_ns_spawn,
    .SpawnInstance           = obj_ns_spawn,
    .CompareTo               = obj_ns_cmp,
    .GetPropertyOrigin       = obj_ns_pq,
    .InheritsFrom            = obj_inherits,
    .GetMethod               = obj_ns_method,
    .PutMethod               = obj_ns_method_put,
    .DeleteMethod            = obj_ns2,
    .BeginMethodEnumeration  = obj_ns_method_begin,
    .NextMethod              = obj_ns_method_next,
    .EndMethodEnumeration    = obj_ns1,
    .GetMethodQualifierSet   = obj_ns_pq,
    .GetMethodOrigin         = obj_ns_pq,
};

/* ------------------------------------------------------------------ */
/* Constructor / destructor                                             */
/* ------------------------------------------------------------------ */
WbemClassObject *wbem_classobject_new(const char *class_name)
{
    WbemClassObject *o = (WbemClassObject *)calloc(1, sizeof(*o));
    if (!o) return NULL;
    o->vtbl      = &g_obj_vtbl;
    atomic_store(&o->ref, 1);
    o->class_name = strdup(class_name ? class_name : "");
    if (!o->class_name) { free(o); return NULL; }
    o->cap_props = 16;
    o->props = (WbemProp *)calloc((size_t)o->cap_props, sizeof(WbemProp));
    if (!o->props) { free(o->class_name); free(o); return NULL; }
    o->n_props   = 0;
    o->enum_idx  = -1;
    return o;
}

static void prop_clear(WbemProp *p)
{
    if (!p) return;
    free(p->name);
    if (p->v.vt == VT_BSTR && p->v.bstrVal) {
        wbem_bstr_free(p->v.bstrVal);
    }
    memset(p, 0, sizeof(*p));
}

static void wbem_classobject_destroy(WbemClassObject *o)
{
    if (!o) return;
    for (int i = 0; i < o->n_props; i++) prop_clear(&o->props[i]);
    free(o->props);
    free(o->class_name);
    free(o);
}

/* ------------------------------------------------------------------ */
/* IUnknown                                                              */
/* ------------------------------------------------------------------ */
static __attribute__((ms_abi)) HRESULT obj_qi(void *This, const IID *riid, void **ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (!riid) return E_POINTER;
    if (wbem_guid_eq(riid, &IID_IUnknown_wbem) ||
        wbem_guid_eq(riid, &IID_IWbemClassObject)) {
        WbemClassObject *o = (WbemClassObject *)This;
        atomic_fetch_add(&o->ref, 1);
        *ppv = This;
        return S_OK;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG obj_addref(void *This)
{
    WbemClassObject *o = (WbemClassObject *)This;
    return (ULONG)(atomic_fetch_add(&o->ref, 1) + 1);
}

static __attribute__((ms_abi)) ULONG obj_release(void *This)
{
    WbemClassObject *o = (WbemClassObject *)This;
    int prev = atomic_fetch_sub(&o->ref, 1);
    if (prev == 1) {
        wbem_classobject_destroy(o);
        return 0;
    }
    return (ULONG)(prev - 1);
}

/* ------------------------------------------------------------------ */
/* Property helpers (called by providers to stuff rows)                */
/* ------------------------------------------------------------------ */

/* Grow the backing array; returns 1 on success, 0 on OOM. */
static int props_reserve_one(WbemClassObject *o)
{
    if (o->n_props < o->cap_props) return 1;
    int new_cap = o->cap_props * 2;
    WbemProp *np = (WbemProp *)realloc(o->props, (size_t)new_cap * sizeof(WbemProp));
    if (!np) return 0;
    memset(np + o->cap_props, 0, (size_t)(new_cap - o->cap_props) * sizeof(WbemProp));
    o->props = np;
    o->cap_props = new_cap;
    return 1;
}

int wbem_row_set_str(WbemClassObject *o, const char *name, const char *utf8)
{
    if (!o || !name) return 0;
    if (!props_reserve_one(o)) return 0;
    WbemProp *p = &o->props[o->n_props];
    p->name = strdup(name);
    if (!p->name) return 0;
    p->v.vt = VT_BSTR;
    p->v.bstrVal = wbem_bstr_from_utf8(utf8 ? utf8 : "");
    if (!p->v.bstrVal) { free(p->name); p->name = NULL; return 0; }
    p->cim_type = CIM_STRING;
    o->n_props++;
    return 1;
}

int wbem_row_set_i4(WbemClassObject *o, const char *name, int32_t v)
{
    if (!o || !name || !props_reserve_one(o)) return 0;
    WbemProp *p = &o->props[o->n_props];
    p->name = strdup(name);
    if (!p->name) return 0;
    p->v.vt = VT_I4;
    p->v.lVal = v;
    p->cim_type = CIM_SINT32;
    o->n_props++;
    return 1;
}

int wbem_row_set_u4(WbemClassObject *o, const char *name, uint32_t v)
{
    if (!o || !name || !props_reserve_one(o)) return 0;
    WbemProp *p = &o->props[o->n_props];
    p->name = strdup(name);
    if (!p->name) return 0;
    /* Stored as VT_I4 because oleaut32 VARIANT_T's union doesn't carry a
     * dedicated VT_UI4 slot in that field name; the bit pattern is
     * preserved and CIM_UINT32 is communicated via pType. */
    p->v.vt = VT_I4;
    p->v.ulVal = v;
    p->cim_type = CIM_UINT32;
    o->n_props++;
    return 1;
}

int wbem_row_set_u8(WbemClassObject *o, const char *name, uint64_t v)
{
    if (!o || !name || !props_reserve_one(o)) return 0;
    WbemProp *p = &o->props[o->n_props];
    p->name = strdup(name);
    if (!p->name) return 0;
    p->v.vt = VT_UI8;
    p->v.ullVal = v;
    p->cim_type = CIM_UINT64;
    o->n_props++;
    return 1;
}

int wbem_row_set_bool(WbemClassObject *o, const char *name, BOOL v)
{
    if (!o || !name || !props_reserve_one(o)) return 0;
    WbemProp *p = &o->props[o->n_props];
    p->name = strdup(name);
    if (!p->name) return 0;
    p->v.vt = VT_BOOL;
    p->v.boolVal = v ? -1 : 0;          /* VARIANT_TRUE = -1 */
    p->cim_type = CIM_BOOLEAN;
    o->n_props++;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Get() -- linear scan, case-insensitive name match                   */
/* ------------------------------------------------------------------ */

/* Variant copy: caller-owned VARIANT receives a deep clone of src.
 * BSTR strings are reallocated so the caller owns them. */
static HRESULT variant_copy_out(WBEM_VARIANT *dst, const WBEM_VARIANT *src)
{
    memset(dst, 0, sizeof(*dst));
    dst->vt = src->vt;
    if (src->vt == VT_BSTR) {
        if (!src->bstrVal) { dst->bstrVal = NULL; return S_OK; }
        /* Re-encode the source BSTR (UTF-16LE) back into a fresh BSTR so
         * the caller's free path is independent of ours.  We have an
         * ASCII-only ingest pipeline so the round-trip is lossless. */
        const uint16_t *w = (const uint16_t *)src->bstrVal;
        size_t n = 0;
        while (n < 0x10000 && w[n]) n++;
        char *tmp = (char *)malloc(n + 1);
        if (!tmp) return E_OUTOFMEMORY;
        for (size_t i = 0; i < n; i++) tmp[i] = (w[i] < 0x80) ? (char)w[i] : '?';
        tmp[n] = '\0';
        dst->bstrVal = wbem_bstr_from_utf8(tmp);
        free(tmp);
        if (!dst->bstrVal) return E_OUTOFMEMORY;
        return S_OK;
    }
    /* Numeric & bool variants: byte-copy the union. */
    dst->ullVal = src->ullVal;
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT obj_get(void *This, void *name, LONG f,
                                                WBEM_VARIANT *v, LONG *type, LONG *flavor)
{
    (void)f;
    if (!This || !name) return E_POINTER;
    WbemClassObject *o = (WbemClassObject *)This;
    if (flavor) *flavor = 0;

    char *na = wbem_utf16_to_ascii(name);
    if (!na) return E_OUTOFMEMORY;

    /* "__CLASS" pseudo-property -- common for callers wanting to know the
     * concrete subclass of a returned object. */
    if (wbem_streqi(na, "__CLASS")) {
        free(na);
        if (v) {
            memset(v, 0, sizeof(*v));
            v->vt = VT_BSTR;
            v->bstrVal = wbem_bstr_from_utf8(o->class_name);
            if (!v->bstrVal) return E_OUTOFMEMORY;
        }
        if (type) *type = CIM_STRING;
        return WBEM_S_NO_ERROR;
    }

    for (int i = 0; i < o->n_props; i++) {
        if (wbem_streqi(o->props[i].name, na)) {
            free(na);
            if (v) {
                HRESULT hr = variant_copy_out(v, &o->props[i].v);
                if (hr != S_OK) return hr;
            }
            if (type) *type = o->props[i].cim_type;
            return WBEM_S_NO_ERROR;
        }
    }
    free(na);
    if (v) { memset(v, 0, sizeof(*v)); v->vt = VT_NULL; }
    if (type) *type = CIM_EMPTY;
    return WBEM_E_NOT_FOUND;
}

/* GetNames: we do not synthesise a SafeArray here -- callers that walk
 * properties almost universally use BeginEnumeration/Next, so returning
 * NOT_SUPPORTED is fine.  Real consumers that want a names array can
 * call SpawnInstance + iterate, but we don't ship that path. */
static __attribute__((ms_abi)) HRESULT obj_get_names(void *This, void *qual, LONG f,
                                                      WBEM_VARIANT *v, void **names)
{
    (void)This; (void)qual; (void)f; (void)v;
    if (names) *names = NULL;
    return WBEM_E_NOT_SUPPORTED;
}

static __attribute__((ms_abi)) HRESULT obj_begin_enum(void *This, LONG f)
{
    (void)f;
    WbemClassObject *o = (WbemClassObject *)This;
    o->enum_idx = 0;
    return WBEM_S_NO_ERROR;
}

static __attribute__((ms_abi)) HRESULT obj_next(void *This, LONG f, void **name,
                                                 WBEM_VARIANT *v, LONG *type, LONG *flavor)
{
    (void)f;
    WbemClassObject *o = (WbemClassObject *)This;
    if (o->enum_idx < 0) return WBEM_E_INVALID_PARAMETER;
    if (o->enum_idx >= o->n_props) return WBEM_S_NO_MORE_DATA;

    WbemProp *p = &o->props[o->enum_idx++];
    if (name) *name = wbem_bstr_from_utf8(p->name);
    if (v) variant_copy_out(v, &p->v);
    if (type) *type = p->cim_type;
    if (flavor) *flavor = 0;
    return WBEM_S_NO_ERROR;
}

static __attribute__((ms_abi)) HRESULT obj_end_enum(void *This)
{
    WbemClassObject *o = (WbemClassObject *)This;
    o->enum_idx = -1;
    return WBEM_S_NO_ERROR;
}

static __attribute__((ms_abi)) HRESULT obj_clone(void *This, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    WbemClassObject *src = (WbemClassObject *)This;
    WbemClassObject *dst = wbem_classobject_new(src->class_name);
    if (!dst) return E_OUTOFMEMORY;
    /* Property-by-property re-insert via the typed setters so BSTRs are
     * freshly allocated.  Slow but cold path. */
    for (int i = 0; i < src->n_props; i++) {
        WbemProp *p = &src->props[i];
        if (p->v.vt == VT_BSTR) {
            char *a = wbem_utf16_to_ascii(p->v.bstrVal);
            wbem_row_set_str(dst, p->name, a ? a : "");
            free(a);
        } else if (p->v.vt == VT_I4) {
            if (p->cim_type == CIM_UINT32) wbem_row_set_u4(dst, p->name, p->v.ulVal);
            else                            wbem_row_set_i4(dst, p->name, p->v.lVal);
        } else if (p->v.vt == VT_UI8) {
            wbem_row_set_u8(dst, p->name, p->v.ullVal);
        } else if (p->v.vt == VT_BOOL) {
            wbem_row_set_bool(dst, p->name, p->v.boolVal != 0);
        }
    }
    *out = dst;
    return WBEM_S_NO_ERROR;
}

static __attribute__((ms_abi)) HRESULT obj_inherits(void *This, void *anc)
{
    /* Return S_OK iff anc names "CIM_ManagedSystemElement" or our class.
     * Most consumers don't call this; treat unknown ancestors as S_FALSE. */
    if (!anc) return E_POINTER;
    WbemClassObject *o = (WbemClassObject *)This;
    char *a = wbem_utf16_to_ascii(anc);
    if (!a) return E_OUTOFMEMORY;
    int hit = wbem_streqi(a, o->class_name) ||
              wbem_streqi(a, "CIM_ManagedSystemElement");
    free(a);
    return hit ? S_OK : S_FALSE;
}

/* ------------------------------------------------------------------ */
/* WHERE-clause filter -- shared by all providers                       */
/* ------------------------------------------------------------------ */
int wbem_row_matches_where(const WbemClassObject *o, const wbem_query_t *q)
{
    if (!q || q->where_op == WBEM_OP_NONE) return 1;

    for (int i = 0; i < o->n_props; i++) {
        if (!wbem_streqi(o->props[i].name, q->where_key)) continue;

        const WbemProp *p = &o->props[i];
        if (q->where_op == WBEM_OP_EQ_STR) {
            if (p->v.vt != VT_BSTR || !p->v.bstrVal) return 0;
            char *a = wbem_utf16_to_ascii(p->v.bstrVal);
            int eq = a && wbem_streqi(a, q->where_str);
            free(a);
            return eq;
        }
        if (q->where_op == WBEM_OP_EQ_INT) {
            if (p->v.vt == VT_I4)
                return p->cim_type == CIM_UINT32
                       ? (int64_t)p->v.ulVal == q->where_int
                       : (int64_t)p->v.lVal  == q->where_int;
            if (p->v.vt == VT_UI8)
                return (int64_t)p->v.ullVal == q->where_int;
            return 0;
        }
    }
    /* Key not present on this row -- treat as no match. */
    return 0;
}
