/*
 * wbem_internal.h - Shared types for the wbemprox.dll stub
 *
 * Internal-only header.  All ms_abi vtable signatures, the property store,
 * the parsed-query struct, and provider entry points live here so the
 * locator/services/classobject/enum/query/providers TUs share one source
 * of truth and don't drift on COM call shapes.
 *
 * Real Windows wbemprox/fastprox are massive; this file describes only the
 * subset we expose: IWbemLocator, IWbemServices, IEnumWbemClassObject,
 * IWbemClassObject -- enough to satisfy the SELECT * FROM Win32_X [WHERE ...]
 * shape used by every common admin tool (wmic, PowerShell Get-WmiObject,
 * .NET ManagementObjectSearcher, anti-cheat probes, installer pre-flight).
 */

#ifndef WBEM_INTERNAL_H
#define WBEM_INTERNAL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>

#include "common/dll_common.h"

/* ------------------------------------------------------------------ */
/* HRESULT codes (subset of WBEM_E_* and friends)                      */
/* ------------------------------------------------------------------ */
#define S_OK                          ((HRESULT)0x00000000)
#define S_FALSE                       ((HRESULT)0x00000001)
#define E_NOTIMPL                     ((HRESULT)0x80004001)
#define E_NOINTERFACE                 ((HRESULT)0x80004002)
#define E_POINTER                     ((HRESULT)0x80004003)
#define E_FAIL                        ((HRESULT)0x80004005)
#define E_OUTOFMEMORY                 ((HRESULT)0x8007000E)
#define E_INVALIDARG                  ((HRESULT)0x80070057)
#define CLASS_E_CLASSNOTAVAILABLE     ((HRESULT)0x80040111)

#define WBEM_S_NO_ERROR               ((HRESULT)0x00000000)
#define WBEM_S_FALSE                  ((HRESULT)0x00000001)
#define WBEM_S_NO_MORE_DATA           ((HRESULT)0x00040002)
#define WBEM_E_FAILED                 ((HRESULT)0x80041001)
#define WBEM_E_NOT_FOUND              ((HRESULT)0x80041002)
#define WBEM_E_INVALID_PARAMETER      ((HRESULT)0x80041008)
#define WBEM_E_INVALID_CLASS          ((HRESULT)0x80041010)
#define WBEM_E_INVALID_QUERY          ((HRESULT)0x80041017)
#define WBEM_E_INVALID_QUERY_TYPE     ((HRESULT)0x80041018)
#define WBEM_E_NOT_SUPPORTED          ((HRESULT)0x8004100C)

/* WBEM_INFINITE for timeout args */
#define WBEM_INFINITE                 0xFFFFFFFFu

/* VARIANT type tags we emit (must match oleaut32_variant.c). */
#define VT_EMPTY    0
#define VT_NULL     1
#define VT_I4       3
#define VT_BSTR     8
#define VT_BOOL     11
#define VT_UI8      21

/* VARIANT layout MUST be byte-compatible with oleaut32's VARIANT_T so a
 * caller that VariantClear()s our output won't corrupt memory.  16 bytes:
 * vt(2) + 3xuint16 reserved + 8-byte payload union. */
typedef struct {
    uint16_t vt;
    uint16_t wReserved1;
    uint16_t wReserved2;
    uint16_t wReserved3;
    union {
        int32_t  lVal;
        uint32_t ulVal;
        int64_t  llVal;
        uint64_t ullVal;
        void    *bstrVal;
        void    *punkVal;
        int16_t  boolVal;
        void    *byref;
    };
} WBEM_VARIANT;

/* CIM types (subset).  Returned by IWbemClassObject::Get() in pType. */
#define CIM_ILLEGAL    0xFFF
#define CIM_EMPTY      0
#define CIM_SINT8      16
#define CIM_UINT8      17
#define CIM_SINT16     2
#define CIM_UINT16     18
#define CIM_SINT32     3
#define CIM_UINT32     19
#define CIM_SINT64     20
#define CIM_UINT64     21
#define CIM_REAL32     4
#define CIM_REAL64     5
#define CIM_BOOLEAN    11
#define CIM_STRING     8
#define CIM_DATETIME   101
#define CIM_REFERENCE  102

/* ------------------------------------------------------------------ */
/* COM core typedefs (locally redeclared so we don't pull ole32 hdrs)  */
/* ------------------------------------------------------------------ */
typedef GUID IID;
typedef GUID CLSID;
typedef GUID *REFIID;
typedef GUID *REFCLSID;

/* IUnknown vtable -- common QI/AddRef/Release prologue every COM iface
 * starts with.  Each concrete vtable below extends this layout in slot
 * order, so we place these three slots first in every vtable struct. */
#define COM_IUNKNOWN_SLOTS \
    __attribute__((ms_abi)) HRESULT (*QueryInterface)(void *This, const IID *riid, void **ppv); \
    __attribute__((ms_abi)) ULONG   (*AddRef)(void *This); \
    __attribute__((ms_abi)) ULONG   (*Release)(void *This)

/* ------------------------------------------------------------------ */
/* IClassFactory (5 slots)                                             */
/* ------------------------------------------------------------------ */
typedef struct IClassFactoryVtbl {
    COM_IUNKNOWN_SLOTS;
    __attribute__((ms_abi)) HRESULT (*CreateInstance)(void *This, void *pUnkOuter,
                                                      const IID *riid, void **ppv);
    __attribute__((ms_abi)) HRESULT (*LockServer)(void *This, BOOL fLock);
} IClassFactoryVtbl;

typedef struct {
    IClassFactoryVtbl *vtbl;
    atomic_int         ref;
} WbemClassFactory;

/* ------------------------------------------------------------------ */
/* IWbemLocator (4 + 3 = 7 slots)                                      */
/* slot 3: ConnectServer                                               */
/* ------------------------------------------------------------------ */
typedef struct IWbemLocatorVtbl {
    COM_IUNKNOWN_SLOTS;
    __attribute__((ms_abi)) HRESULT (*ConnectServer)(void *This,
        void *strNetworkResource, void *strUser, void *strPassword,
        void *strLocale, LONG lSecurityFlags, void *strAuthority,
        void *pCtx, void **ppNamespace);
} IWbemLocatorVtbl;

typedef struct {
    IWbemLocatorVtbl *vtbl;
    atomic_int        ref;
} WbemLocator;

/* ------------------------------------------------------------------ */
/* IWbemServices (3 + 23 = 26 slots; we plug only what we need and    */
/* return WBEM_E_NOT_SUPPORTED for the rest)                          */
/* ------------------------------------------------------------------ */
typedef struct IWbemServicesVtbl {
    COM_IUNKNOWN_SLOTS;
    /*  3 */ __attribute__((ms_abi)) HRESULT (*OpenNamespace)(void *This, void *str, LONG f, void *ctx, void **ns, void **call);
    /*  4 */ __attribute__((ms_abi)) HRESULT (*CancelAsyncCall)(void *This, void *sink);
    /*  5 */ __attribute__((ms_abi)) HRESULT (*QueryObjectSink)(void *This, LONG f, void **sink);
    /*  6 */ __attribute__((ms_abi)) HRESULT (*GetObject)(void *This, void *path, LONG f, void *ctx, void **obj, void **call);
    /*  7 */ __attribute__((ms_abi)) HRESULT (*GetObjectAsync)(void *This, void *path, LONG f, void *ctx, void *sink);
    /*  8 */ __attribute__((ms_abi)) HRESULT (*PutClass)(void *This, void *obj, LONG f, void *ctx, void **call);
    /*  9 */ __attribute__((ms_abi)) HRESULT (*PutClassAsync)(void *This, void *obj, LONG f, void *ctx, void *sink);
    /* 10 */ __attribute__((ms_abi)) HRESULT (*DeleteClass)(void *This, void *cls, LONG f, void *ctx, void **call);
    /* 11 */ __attribute__((ms_abi)) HRESULT (*DeleteClassAsync)(void *This, void *cls, LONG f, void *ctx, void *sink);
    /* 12 */ __attribute__((ms_abi)) HRESULT (*CreateClassEnum)(void *This, void *super, LONG f, void *ctx, void **e);
    /* 13 */ __attribute__((ms_abi)) HRESULT (*CreateClassEnumAsync)(void *This, void *super, LONG f, void *ctx, void *sink);
    /* 14 */ __attribute__((ms_abi)) HRESULT (*PutInstance)(void *This, void *inst, LONG f, void *ctx, void **call);
    /* 15 */ __attribute__((ms_abi)) HRESULT (*PutInstanceAsync)(void *This, void *inst, LONG f, void *ctx, void *sink);
    /* 16 */ __attribute__((ms_abi)) HRESULT (*DeleteInstance)(void *This, void *path, LONG f, void *ctx, void **call);
    /* 17 */ __attribute__((ms_abi)) HRESULT (*DeleteInstanceAsync)(void *This, void *path, LONG f, void *ctx, void *sink);
    /* 18 */ __attribute__((ms_abi)) HRESULT (*CreateInstanceEnum)(void *This, void *cls, LONG f, void *ctx, void **e);
    /* 19 */ __attribute__((ms_abi)) HRESULT (*CreateInstanceEnumAsync)(void *This, void *cls, LONG f, void *ctx, void *sink);
    /* 20 */ __attribute__((ms_abi)) HRESULT (*ExecQuery)(void *This, void *lang, void *query, LONG f, void *ctx, void **e);
    /* 21 */ __attribute__((ms_abi)) HRESULT (*ExecQueryAsync)(void *This, void *lang, void *query, LONG f, void *ctx, void *sink);
    /* 22 */ __attribute__((ms_abi)) HRESULT (*ExecNotificationQuery)(void *This, void *lang, void *query, LONG f, void *ctx, void **e);
    /* 23 */ __attribute__((ms_abi)) HRESULT (*ExecNotificationQueryAsync)(void *This, void *lang, void *query, LONG f, void *ctx, void *sink);
    /* 24 */ __attribute__((ms_abi)) HRESULT (*ExecMethod)(void *This, void *path, void *method, LONG f, void *ctx, void *in, void **out, void **call);
    /* 25 */ __attribute__((ms_abi)) HRESULT (*ExecMethodAsync)(void *This, void *path, void *method, LONG f, void *ctx, void *in, void *sink);
} IWbemServicesVtbl;

typedef struct {
    IWbemServicesVtbl *vtbl;
    atomic_int         ref;
} WbemServices;

/* ------------------------------------------------------------------ */
/* IWbemClassObject (3 + 24 slots; we plug Get/GetNames/BeginEnum/Next/EndEnum) */
/* ------------------------------------------------------------------ */
typedef struct IWbemClassObjectVtbl {
    COM_IUNKNOWN_SLOTS;
    /*  3 */ __attribute__((ms_abi)) HRESULT (*GetQualifierSet)(void *This, void **q);
    /*  4 */ __attribute__((ms_abi)) HRESULT (*Get)(void *This, void *name, LONG f, WBEM_VARIANT *v, LONG *type, LONG *flavor);
    /*  5 */ __attribute__((ms_abi)) HRESULT (*Put)(void *This, void *name, LONG f, WBEM_VARIANT *v, LONG type);
    /*  6 */ __attribute__((ms_abi)) HRESULT (*Delete)(void *This, void *name);
    /*  7 */ __attribute__((ms_abi)) HRESULT (*GetNames)(void *This, void *qual, LONG f, WBEM_VARIANT *v, void **names);
    /*  8 */ __attribute__((ms_abi)) HRESULT (*BeginEnumeration)(void *This, LONG f);
    /*  9 */ __attribute__((ms_abi)) HRESULT (*Next)(void *This, LONG f, void **name, WBEM_VARIANT *v, LONG *type, LONG *flavor);
    /* 10 */ __attribute__((ms_abi)) HRESULT (*EndEnumeration)(void *This);
    /* 11 */ __attribute__((ms_abi)) HRESULT (*GetPropertyQualifierSet)(void *This, void *name, void **q);
    /* 12 */ __attribute__((ms_abi)) HRESULT (*Clone)(void *This, void **out);
    /* 13 */ __attribute__((ms_abi)) HRESULT (*GetObjectText)(void *This, LONG f, void **text);
    /* 14 */ __attribute__((ms_abi)) HRESULT (*SpawnDerivedClass)(void *This, LONG f, void **out);
    /* 15 */ __attribute__((ms_abi)) HRESULT (*SpawnInstance)(void *This, LONG f, void **out);
    /* 16 */ __attribute__((ms_abi)) HRESULT (*CompareTo)(void *This, LONG f, void *other);
    /* 17 */ __attribute__((ms_abi)) HRESULT (*GetPropertyOrigin)(void *This, void *name, void **origin);
    /* 18 */ __attribute__((ms_abi)) HRESULT (*InheritsFrom)(void *This, void *anc);
    /* 19 */ __attribute__((ms_abi)) HRESULT (*GetMethod)(void *This, void *name, LONG f, void **in, void **out);
    /* 20 */ __attribute__((ms_abi)) HRESULT (*PutMethod)(void *This, void *name, LONG f, void *in, void *out);
    /* 21 */ __attribute__((ms_abi)) HRESULT (*DeleteMethod)(void *This, void *name);
    /* 22 */ __attribute__((ms_abi)) HRESULT (*BeginMethodEnumeration)(void *This, LONG f);
    /* 23 */ __attribute__((ms_abi)) HRESULT (*NextMethod)(void *This, LONG f, void **name, void **in, void **out);
    /* 24 */ __attribute__((ms_abi)) HRESULT (*EndMethodEnumeration)(void *This);
    /* 25 */ __attribute__((ms_abi)) HRESULT (*GetMethodQualifierSet)(void *This, void *name, void **q);
    /* 26 */ __attribute__((ms_abi)) HRESULT (*GetMethodOrigin)(void *This, void *name, void **origin);
} IWbemClassObjectVtbl;

/* Property store: ordered list of (name, variant, cim_type) triples. */
typedef struct {
    char         *name;        /* heap, ASCII, owned */
    WBEM_VARIANT  v;           /* BSTR strings inside are heap-owned */
    LONG          cim_type;    /* CIM_* */
} WbemProp;

typedef struct {
    IWbemClassObjectVtbl *vtbl;
    atomic_int            ref;
    char                 *class_name;     /* heap, ASCII, owned */
    WbemProp             *props;
    int                   n_props;
    int                   cap_props;
    int                   enum_idx;       /* BeginEnumeration cursor */
} WbemClassObject;

/* ------------------------------------------------------------------ */
/* IEnumWbemClassObject (3 + 5 slots)                                  */
/* ------------------------------------------------------------------ */
typedef struct IEnumWbemClassObjectVtbl {
    COM_IUNKNOWN_SLOTS;
    /*  3 */ __attribute__((ms_abi)) HRESULT (*Reset)(void *This);
    /*  4 */ __attribute__((ms_abi)) HRESULT (*Next)(void *This, LONG timeout, ULONG count, void **objs, ULONG *returned);
    /*  5 */ __attribute__((ms_abi)) HRESULT (*NextAsync)(void *This, ULONG count, void *sink);
    /*  6 */ __attribute__((ms_abi)) HRESULT (*Clone)(void *This, void **out);
    /*  7 */ __attribute__((ms_abi)) HRESULT (*Skip)(void *This, LONG timeout, ULONG count);
} IEnumWbemClassObjectVtbl;

typedef struct {
    IEnumWbemClassObjectVtbl *vtbl;
    atomic_int                ref;
    WbemClassObject         **rows;       /* owns N AddRef'd rows */
    int                       n_rows;
    int                       cur;        /* Next cursor */
} WbemEnum;

/* ------------------------------------------------------------------ */
/* WQL parser output                                                    */
/* ------------------------------------------------------------------ */
#define WBEM_QUERY_MAX_CLASS  64
#define WBEM_QUERY_MAX_KEY    64
#define WBEM_QUERY_MAX_VAL    256

typedef enum {
    WBEM_OP_NONE = 0,
    WBEM_OP_EQ_STR,    /* WHERE Foo = 'bar' */
    WBEM_OP_EQ_INT,    /* WHERE Pid = 42 */
} wbem_op_t;

typedef struct {
    int        ok;                            /* 0 = parse failed */
    int        select_star;                   /* 1 if SELECT * */
    char       from_class[WBEM_QUERY_MAX_CLASS];
    wbem_op_t  where_op;
    char       where_key[WBEM_QUERY_MAX_KEY];
    char       where_str[WBEM_QUERY_MAX_VAL];
    int64_t    where_int;
} wbem_query_t;

/* Parse "SELECT * FROM Win32_X [WHERE Y = 'Z' | Y = 123]".  Token-only,
 * case-insensitive on keywords, single-quoted string literals supported,
 * unsigned/positive signed integer literals supported.  Anything else
 * sets q->ok = 0. */
void wbem_parse_query(const uint16_t *wql_utf16, wbem_query_t *q);

/* ------------------------------------------------------------------ */
/* Internal API exposed across TUs                                      */
/* ------------------------------------------------------------------ */

/* Build IWbemServices singleton (refcounted; caller AddRefs). */
WbemServices *wbem_services_get_singleton(void);

/* Allocate an empty IWbemClassObject for a given class name.
 * Refcount starts at 1 (caller owns). */
WbemClassObject *wbem_classobject_new(const char *class_name);

/* Helpers for providers to populate a row.  Strings are duplicated; the
 * row owns the heap copies.  Returns 0 on OOM, 1 on success. */
int wbem_row_set_str(WbemClassObject *o, const char *name, const char *utf8);
int wbem_row_set_i4 (WbemClassObject *o, const char *name, int32_t v);
int wbem_row_set_u4 (WbemClassObject *o, const char *name, uint32_t v);
int wbem_row_set_u8 (WbemClassObject *o, const char *name, uint64_t v);
int wbem_row_set_bool(WbemClassObject *o, const char *name, BOOL v);

/* Build IEnumWbemClassObject taking ownership of rows array (rows[i] are
 * already AddRef'd at +1 each).  free() takes the outer array.  */
WbemEnum *wbem_enum_new(WbemClassObject **rows, int n_rows);

/* Provider entry points -- each builds a fresh enum honouring q->where_*.
 * Returns NULL on hard failure (caller maps to WBEM_E_FAILED). */
WbemEnum *wbem_provider_os         (const wbem_query_t *q);
WbemEnum *wbem_provider_processor  (const wbem_query_t *q);
WbemEnum *wbem_provider_process    (const wbem_query_t *q);
WbemEnum *wbem_provider_service    (const wbem_query_t *q);
WbemEnum *wbem_provider_disk       (const wbem_query_t *q);
WbemEnum *wbem_provider_netadapter (const wbem_query_t *q);
WbemEnum *wbem_provider_bios       (const wbem_query_t *q);
WbemEnum *wbem_provider_computersystem(const wbem_query_t *q);

/* Allocate a BSTR from a UTF-8 string.  Returned buffer is a Windows BSTR
 * (4-byte length prefix preceding the pointer).  Free with SysFreeString
 * (or the inline equivalent in wbem_classobject.c). */
void *wbem_bstr_from_utf8(const char *s);

/* Free a BSTR allocated by wbem_bstr_from_utf8.  Safe on NULL. */
void  wbem_bstr_free(void *bstr);

/* Apply the WHERE clause filter to a candidate property value.  Returns
 * 1 if the row matches (or no WHERE), 0 if it should be filtered out. */
int wbem_row_matches_where(const WbemClassObject *o, const wbem_query_t *q);

/* Well-known IIDs / CLSIDs */
extern const IID  IID_IUnknown_wbem;
extern const IID  IID_IClassFactory_wbem;
extern const IID  IID_IWbemLocator;
extern const IID  IID_IWbemServices;
extern const IID  IID_IEnumWbemClassObject;
extern const IID  IID_IWbemClassObject;
extern const CLSID CLSID_WbemLocator;

/* GUID equality (avoid pulling string.h into every TU). */
static inline int wbem_guid_eq(const GUID *a, const GUID *b)
{
    return memcmp(a, b, sizeof(GUID)) == 0;
}

/* UTF-16LE BSTR -> ASCII heap string.  Returns NULL on OOM/empty.
 * The "BSTR" here is the bare WCHAR pointer Win32 hands out; we walk the
 * 4-byte length prefix when possible, otherwise NUL-scan. */
char *wbem_utf16_to_ascii(const void *bstr_or_lpcwstr);

/* ASCII case-insensitive compare (avoid strcasecmp portability churn). */
static inline int wbem_streqi(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? (char)(*a + 32) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (char)(*b + 32) : *b;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

#endif /* WBEM_INTERNAL_H */
