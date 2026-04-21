/*
 * wbem_enum.c - IEnumWbemClassObject (iterates ExecQuery results)
 *
 * Owns an array of WbemClassObject*, each at +1 refcount.  Next() AddRefs
 * each object it hands out; the caller is responsible for Release()ing
 * them.  Reset rewinds the cursor; Skip advances it without producing.
 */

#include "wbem_internal.h"

/* Forward decl for vtable address. */
static __attribute__((ms_abi)) HRESULT en_qi(void *This, const IID *riid, void **ppv);
static __attribute__((ms_abi)) ULONG   en_addref(void *This);
static __attribute__((ms_abi)) ULONG   en_release(void *This);
static __attribute__((ms_abi)) HRESULT en_reset(void *This);
static __attribute__((ms_abi)) HRESULT en_next(void *This, LONG timeout, ULONG count,
                                                void **objs, ULONG *returned);
static __attribute__((ms_abi)) HRESULT en_next_async(void *This, ULONG count, void *sink);
static __attribute__((ms_abi)) HRESULT en_clone(void *This, void **out);
static __attribute__((ms_abi)) HRESULT en_skip(void *This, LONG timeout, ULONG count);

static IEnumWbemClassObjectVtbl g_enum_vtbl = {
    .QueryInterface = en_qi,
    .AddRef         = en_addref,
    .Release        = en_release,
    .Reset          = en_reset,
    .Next           = en_next,
    .NextAsync      = en_next_async,
    .Clone          = en_clone,
    .Skip           = en_skip,
};

WbemEnum *wbem_enum_new(WbemClassObject **rows, int n_rows)
{
    WbemEnum *e = (WbemEnum *)calloc(1, sizeof(*e));
    if (!e) {
        /* If allocation fails, the rows array is the caller's problem to
         * release.  We only take ownership when we successfully wrap. */
        return NULL;
    }
    e->vtbl   = &g_enum_vtbl;
    atomic_store(&e->ref, 1);
    e->rows   = rows;
    e->n_rows = n_rows;
    e->cur    = 0;
    return e;
}

static void wbem_enum_destroy(WbemEnum *e)
{
    if (!e) return;
    if (e->rows) {
        for (int i = 0; i < e->n_rows; i++) {
            if (e->rows[i]) e->rows[i]->vtbl->Release(e->rows[i]);
        }
        free(e->rows);
    }
    free(e);
}

/* ------------------------------------------------------------------ */
static __attribute__((ms_abi)) HRESULT en_qi(void *This, const IID *riid, void **ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (!riid) return E_POINTER;
    if (wbem_guid_eq(riid, &IID_IUnknown_wbem) ||
        wbem_guid_eq(riid, &IID_IEnumWbemClassObject)) {
        WbemEnum *e = (WbemEnum *)This;
        atomic_fetch_add(&e->ref, 1);
        *ppv = This;
        return S_OK;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG en_addref(void *This)
{
    WbemEnum *e = (WbemEnum *)This;
    return (ULONG)(atomic_fetch_add(&e->ref, 1) + 1);
}

static __attribute__((ms_abi)) ULONG en_release(void *This)
{
    WbemEnum *e = (WbemEnum *)This;
    int prev = atomic_fetch_sub(&e->ref, 1);
    if (prev == 1) {
        wbem_enum_destroy(e);
        return 0;
    }
    return (ULONG)(prev - 1);
}

static __attribute__((ms_abi)) HRESULT en_reset(void *This)
{
    WbemEnum *e = (WbemEnum *)This;
    e->cur = 0;
    return WBEM_S_NO_ERROR;
}

static __attribute__((ms_abi)) HRESULT en_next(void *This, LONG timeout, ULONG count,
                                                void **objs, ULONG *returned)
{
    (void)timeout;
    if (returned) *returned = 0;
    if (!objs || count == 0) return E_POINTER;

    WbemEnum *e = (WbemEnum *)This;
    ULONG produced = 0;
    while (produced < count && e->cur < e->n_rows) {
        WbemClassObject *o = e->rows[e->cur++];
        if (!o) continue;
        o->vtbl->AddRef(o);
        objs[produced++] = o;
    }
    if (returned) *returned = produced;
    if (produced == 0) return WBEM_S_NO_MORE_DATA;
    if (produced < count) return WBEM_S_FALSE;          /* partial */
    return WBEM_S_NO_ERROR;
}

static __attribute__((ms_abi)) HRESULT en_next_async(void *This, ULONG count, void *sink)
{
    (void)This; (void)count; (void)sink;
    return WBEM_E_NOT_SUPPORTED;
}

static __attribute__((ms_abi)) HRESULT en_clone(void *This, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    WbemEnum *e = (WbemEnum *)This;
    /* Build a new enum that shares the row pointers with each AddRef'd. */
    WbemClassObject **rows = (WbemClassObject **)calloc((size_t)(e->n_rows ? e->n_rows : 1),
                                                         sizeof(WbemClassObject *));
    if (!rows) return E_OUTOFMEMORY;
    for (int i = 0; i < e->n_rows; i++) {
        rows[i] = e->rows[i];
        if (rows[i]) rows[i]->vtbl->AddRef(rows[i]);
    }
    WbemEnum *clone = wbem_enum_new(rows, e->n_rows);
    if (!clone) {
        for (int i = 0; i < e->n_rows; i++)
            if (rows[i]) rows[i]->vtbl->Release(rows[i]);
        free(rows);
        return E_OUTOFMEMORY;
    }
    clone->cur = e->cur;
    *out = clone;
    return WBEM_S_NO_ERROR;
}

static __attribute__((ms_abi)) HRESULT en_skip(void *This, LONG timeout, ULONG count)
{
    (void)timeout;
    WbemEnum *e = (WbemEnum *)This;
    if ((ULONG)(e->n_rows - e->cur) < count) {
        e->cur = e->n_rows;
        return WBEM_S_NO_MORE_DATA;
    }
    e->cur += (int)count;
    return WBEM_S_NO_ERROR;
}
