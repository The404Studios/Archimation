/*
 * oleaut32_variant.c - OLE Automation (oleaut32.dll) stubs
 *
 * BSTR, VARIANT, SafeArray, TypeLib, ErrorInfo, and IDispatch helpers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wchar.h>

#include "common/dll_common.h"

/* ========== BSTR Functions ========== */

/*
 * BSTR layout: [4-byte length][WCHAR data...][NUL]
 * SysAllocString returns pointer to WCHAR data, NOT the length prefix.
 */

WINAPI_EXPORT void *SysAllocString(const void *psz)
{
    if (!psz) return NULL;
    const uint16_t *src = (const uint16_t *)psz;
    size_t len = 0;
    while (src[len]) len++;

    uint32_t byte_len = (uint32_t)(len * sizeof(uint16_t));
    uint8_t *block = malloc(4 + byte_len + 2);
    if (!block) return NULL;

    memcpy(block, &byte_len, 4);
    memcpy(block + 4, src, byte_len);
    /* NUL terminator */
    block[4 + byte_len] = 0;
    block[4 + byte_len + 1] = 0;

    return block + 4;
}

WINAPI_EXPORT void *SysAllocStringLen(const void *strIn, uint32_t ui)
{
    if (ui > (UINT32_MAX - 6) / sizeof(uint16_t)) return NULL;
    uint32_t byte_len = ui * sizeof(uint16_t);
    uint8_t *block = malloc(4 + byte_len + 2);
    if (!block) return NULL;

    memcpy(block, &byte_len, 4);
    if (strIn)
        memcpy(block + 4, strIn, byte_len);
    else
        memset(block + 4, 0, byte_len);
    block[4 + byte_len] = 0;
    block[4 + byte_len + 1] = 0;

    return block + 4;
}

WINAPI_EXPORT void *SysAllocStringByteLen(const char *psz, uint32_t len)
{
    uint8_t *block = malloc(4 + len + 2);
    if (!block) return NULL;

    memcpy(block, &len, 4);
    if (psz)
        memcpy(block + 4, psz, len);
    else
        memset(block + 4, 0, len);
    block[4 + len] = 0;
    block[4 + len + 1] = 0;

    return block + 4;
}

WINAPI_EXPORT void SysFreeString(void *bstrString)
{
    if (!bstrString) return;
    uint8_t *block = (uint8_t *)bstrString - 4;
    free(block);
}

WINAPI_EXPORT uint32_t SysStringLen(const void *pbstr)
{
    if (!pbstr) return 0;
    uint32_t byte_len;
    memcpy(&byte_len, (const uint8_t *)pbstr - 4, 4);
    return byte_len / sizeof(uint16_t);
}

WINAPI_EXPORT uint32_t SysStringByteLen(const void *bstr)
{
    if (!bstr) return 0;
    uint32_t byte_len;
    memcpy(&byte_len, (const uint8_t *)bstr - 4, 4);
    return byte_len;
}

WINAPI_EXPORT int SysReAllocString(void **pbstr, const void *psz)
{
    if (!pbstr) return 0;
    void *new_bstr = SysAllocString(psz);
    SysFreeString(*pbstr);
    *pbstr = new_bstr;
    return new_bstr ? 1 : 0;
}

WINAPI_EXPORT int SysReAllocStringLen(void **pbstr, const void *psz, uint32_t len)
{
    if (!pbstr) return 0;
    void *new_bstr = SysAllocStringLen(psz, len);
    SysFreeString(*pbstr);
    *pbstr = new_bstr;
    return new_bstr ? 1 : 0;
}

/* ========== VARIANT Functions ========== */

/* VARIANT is 16 bytes: vt(2) + wReserved1-3(6) + union(8) */
#define VT_EMPTY   0
#define VT_NULL    1
#define VT_I2      2
#define VT_I4      3
#define VT_R4      4
#define VT_R8      5
#define VT_BSTR    8
#define VT_DISPATCH 9
#define VT_UNKNOWN  13
#define VT_I1      16
#define VT_UI1     17
#define VT_UI2     18
#define VT_UI4     19
#define VT_I8      20
#define VT_UI8     21
#define VT_VARIANT 12
#define VT_ARRAY   0x2000
#define VT_BYREF   0x4000

/* SafeArray fFeatures flags (we store vt hint in high bits to avoid
 * clobbering standard Windows feature bits). */
#define FADF_AUTO       0x0001
#define FADF_STATIC     0x0002
#define FADF_EMBEDDED   0x0004
#define FADF_FIXEDSIZE  0x0010
#define FADF_BSTR       0x0100
#define FADF_UNKNOWN    0x0200
#define FADF_DISPATCH   0x0400
#define FADF_VARIANT    0x0800

/* Forward declarations used before their definitions. */
typedef struct _SAFEARRAY SAFEARRAY;
WINAPI_EXPORT HRESULT SafeArrayDestroy(SAFEARRAY *psa);

typedef struct {
    uint16_t vt;
    uint16_t wReserved1;
    uint16_t wReserved2;
    uint16_t wReserved3;
    union {
        int32_t lVal;
        uint32_t ulVal;
        float fltVal;
        double dblVal;
        void *bstrVal;
        void *punkVal;
        void *pdispVal;
        int64_t llVal;
        uint64_t ullVal;
        void *byref;
        SAFEARRAY *parray;
    };
} VARIANT_T;

WINAPI_EXPORT void VariantInit(void *pvarg)
{
    if (pvarg) memset(pvarg, 0, sizeof(VARIANT_T));
}

WINAPI_EXPORT HRESULT VariantClear(void *pvarg)
{
    if (!pvarg) return 0x80070057; /* E_INVALIDARG */
    VARIANT_T *v = (VARIANT_T *)pvarg;

    /* VT_BYREF: we don't own the referent -- just zero the variant. */
    if (v->vt & VT_BYREF) {
        memset(pvarg, 0, sizeof(VARIANT_T));
        return 0;
    }

    /* VT_ARRAY: destroy the SafeArray (which will per-element clean BSTR/VARIANT). */
    if (v->vt & VT_ARRAY) {
        if (v->parray) SafeArrayDestroy(v->parray);
    } else if (v->vt == VT_BSTR) {
        if (v->bstrVal) SysFreeString(v->bstrVal);
    } else if ((v->vt == VT_UNKNOWN || v->vt == VT_DISPATCH) && v->punkVal) {
        /* Release COM object - call Release through vtable */
        typedef uint32_t (__attribute__((ms_abi)) *ReleaseFn)(void *);
        void **vtbl = *(void ***)v->punkVal;
        if (vtbl && vtbl[2])
            ((ReleaseFn)vtbl[2])(v->punkVal);
    }
    memset(pvarg, 0, sizeof(VARIANT_T));
    return 0;
}

WINAPI_EXPORT HRESULT VariantCopy(void *pvargDest, const void *pvargSrc)
{
    if (!pvargDest || !pvargSrc) return 0x80070057;

    /* Self-copy: VariantClear would destroy source before we read it */
    if (pvargDest == pvargSrc) return 0;

    VariantClear(pvargDest);
    memcpy(pvargDest, pvargSrc, sizeof(VARIANT_T));
    const VARIANT_T *src = (const VARIANT_T *)pvargSrc;
    VARIANT_T *dst = (VARIANT_T *)pvargDest;

    /* VT_BYREF: we copy the reference as-is (neither side owns the referent). */
    if (src->vt & VT_BYREF) return 0;

    /* VT_ARRAY: we cannot easily deep-copy without a full SafeArrayCopy
     * implementation. To prevent double-free, null out dst->parray and
     * surface E_NOTIMPL. Caller gets an empty variant rather than a
     * variant sharing a SafeArray with the source. */
    if (src->vt & VT_ARRAY) {
        memset(dst, 0, sizeof(VARIANT_T));
        return 0x80004001; /* E_NOTIMPL */
    }

    if (src->vt == VT_BSTR && src->bstrVal) {
        dst->bstrVal = SysAllocStringLen(src->bstrVal, SysStringLen(src->bstrVal));
        if (!dst->bstrVal) {
            memset(dst, 0, sizeof(VARIANT_T));
            return 0x8007000E; /* E_OUTOFMEMORY */
        }
    } else if ((src->vt == VT_UNKNOWN || src->vt == VT_DISPATCH) && src->punkVal) {
        typedef uint32_t (__attribute__((ms_abi)) *AddRefFn)(void *);
        void **vtbl = *(void ***)src->punkVal;
        if (vtbl && vtbl[1])
            ((AddRefFn)vtbl[1])(src->punkVal); /* AddRef on SOURCE, not dest */
    }
    return 0;
}

WINAPI_EXPORT HRESULT VariantCopyInd(void *pvarDest, const void *pvargSrc)
{
    return VariantCopy(pvarDest, pvargSrc);
}

WINAPI_EXPORT HRESULT VariantChangeType(void *pvargDest, const void *pvarSrc,
                                          uint16_t wFlags, uint16_t vt)
{
    (void)wFlags;
    if (!pvargDest || !pvarSrc) return 0x80070057;
    const VARIANT_T *src = (const VARIANT_T *)pvarSrc;

    /* Simple same-type copy */
    if (src->vt == vt) return VariantCopy(pvargDest, pvarSrc);

    /* Snapshot source primitives in case dest aliases source.
     * VariantClear(dst) could free a shared BSTR if dst == src. */
    VARIANT_T snapshot = *src;

    VariantClear(pvargDest);
    VARIANT_T *dst = (VARIANT_T *)pvargDest;

    /* Coerce snapshot -> double (intermediate for numeric <-> string). */
    double as_double = 0.0;
    int64_t as_i64 = 0;
    int have_num = 0;
    switch (snapshot.vt) {
    case VT_I2:   as_i64 = (int16_t)(snapshot.lVal & 0xFFFF); as_double = (double)as_i64; have_num = 1; break;
    case VT_I4:   as_i64 = snapshot.lVal; as_double = (double)as_i64; have_num = 1; break;
    case VT_I8:   as_i64 = snapshot.llVal; as_double = (double)as_i64; have_num = 1; break;
    case VT_UI1:  as_i64 = (uint8_t)snapshot.ulVal; as_double = (double)as_i64; have_num = 1; break;
    case VT_UI2:  as_i64 = (uint16_t)snapshot.ulVal; as_double = (double)as_i64; have_num = 1; break;
    case VT_UI4:  as_i64 = (uint32_t)snapshot.ulVal; as_double = (double)as_i64; have_num = 1; break;
    case VT_R4:   as_double = (double)snapshot.fltVal; as_i64 = (int64_t)as_double; have_num = 1; break;
    case VT_R8:   as_double = snapshot.dblVal; as_i64 = (int64_t)as_double; have_num = 1; break;
    case VT_EMPTY:
    case VT_NULL: as_i64 = 0; as_double = 0.0; have_num = 1; break;
    case VT_BSTR: {
        if (snapshot.bstrVal) {
            uint32_t wlen = SysStringLen(snapshot.bstrVal);
            if (wlen < 128) {
                char narrow[130];
                const uint16_t *w = (const uint16_t *)snapshot.bstrVal;
                uint32_t i;
                for (i = 0; i < wlen; i++)
                    narrow[i] = (w[i] < 128) ? (char)w[i] : '?';
                narrow[i] = '\0';
                char *end = NULL;
                as_double = strtod(narrow, &end);
                as_i64 = (int64_t)as_double;
                have_num = (end && end != narrow);
            }
        }
        break;
    }
    default: break;
    }

    if (vt == VT_EMPTY || vt == VT_NULL) {
        dst->vt = vt;
        return 0;
    }

    if (vt == VT_I2 && have_num) { dst->vt = VT_I2; dst->lVal = (int16_t)as_i64; return 0; }
    if (vt == VT_I4 && have_num) { dst->vt = VT_I4; dst->lVal = (int32_t)as_i64; return 0; }
    if (vt == VT_I8 && have_num) { dst->vt = VT_I8; dst->llVal = as_i64; return 0; }
    if (vt == VT_UI1 && have_num) { dst->vt = VT_UI1; dst->ulVal = (uint8_t)as_i64; return 0; }
    if (vt == VT_UI2 && have_num) { dst->vt = VT_UI2; dst->ulVal = (uint16_t)as_i64; return 0; }
    if (vt == VT_UI4 && have_num) { dst->vt = VT_UI4; dst->ulVal = (uint32_t)as_i64; return 0; }
    if (vt == VT_R4 && have_num) { dst->vt = VT_R4; dst->fltVal = (float)as_double; return 0; }
    if (vt == VT_R8 && have_num) { dst->vt = VT_R8; dst->dblVal = as_double; return 0; }

    if (vt == VT_BSTR && have_num) {
        char narrow[64];
        if (snapshot.vt == VT_R4 || snapshot.vt == VT_R8) {
            snprintf(narrow, sizeof(narrow), "%g", as_double);
        } else {
            snprintf(narrow, sizeof(narrow), "%lld", (long long)as_i64);
        }
        size_t len = strlen(narrow);
        uint16_t wbuf[64];
        for (size_t i = 0; i <= len && i < 64; i++) wbuf[i] = (uint16_t)narrow[i];
        void *bstr = SysAllocStringLen(wbuf, (uint32_t)len);
        if (!bstr) { memset(dst, 0, sizeof(VARIANT_T)); return 0x8007000E; }
        dst->vt = VT_BSTR;
        dst->bstrVal = bstr;
        return 0;
    }

    /* Unsupported conversion: leave dst cleared so subsequent
     * VariantClear by caller sees a well-defined empty variant
     * rather than vt=target with no payload. */
    memset(dst, 0, sizeof(VARIANT_T));
    return 0x80020005; /* DISP_E_TYPEMISMATCH */
}

WINAPI_EXPORT HRESULT VariantChangeTypeEx(void *pvargDest, const void *pvarSrc,
                                            uint32_t lcid, uint16_t wFlags, uint16_t vt)
{
    (void)lcid;
    return VariantChangeType(pvargDest, pvarSrc, wFlags, vt);
}

/* ========== SafeArray Functions ========== */

struct _SAFEARRAY {
    uint16_t cDims;
    uint16_t fFeatures;
    uint32_t cbElements;
    uint32_t cLocks;
    void *pvData;
    /* Non-standard: store vt hint so SafeArrayGetVartype / Destroy work
     * without rebuilding it from fFeatures for every vt. */
    uint16_t vt_hint;
    uint16_t _pad;
    struct { uint32_t cElements; int32_t lLbound; } rgsabound[1];
};

WINAPI_EXPORT SAFEARRAY *SafeArrayCreate(uint16_t vt, uint32_t cDims, const void *rgsabound)
{
    if (cDims == 0 || cDims > 64) return NULL;
    typedef struct { uint32_t cElements; int32_t lLbound; } BOUND;
    const BOUND *bounds = (const BOUND *)rgsabound;

    size_t total = 1;
    for (uint32_t i = 0; i < cDims; i++) {
        if (bounds[i].cElements == 0) { total = 0; break; }
        if (total > SIZE_MAX / bounds[i].cElements) return NULL; /* overflow */
        total *= bounds[i].cElements;
    }

    uint32_t elem_size;
    uint16_t fFeatures = 0;
    switch (vt) {
    case VT_I1:
    case VT_UI1:       elem_size = 1; break;
    case VT_I2:
    case VT_UI2:       elem_size = 2; break;
    case VT_I4:
    case VT_UI4:
    case VT_R4:        elem_size = 4; break;
    case VT_I8:
    case VT_UI8:
    case VT_R8:        elem_size = 8; break;
    case VT_BSTR:      elem_size = sizeof(void *); fFeatures = FADF_BSTR; break;
    case VT_UNKNOWN:   elem_size = sizeof(void *); fFeatures = FADF_UNKNOWN; break;
    case VT_DISPATCH:  elem_size = sizeof(void *); fFeatures = FADF_DISPATCH; break;
    case VT_VARIANT:   elem_size = sizeof(VARIANT_T); fFeatures = FADF_VARIANT; break;
    default:           elem_size = sizeof(void *); break;
    }

    size_t hdr_size = sizeof(struct _SAFEARRAY) + (cDims > 1 ? (cDims - 1) * 8 : 0);
    SAFEARRAY *sa = calloc(1, hdr_size);
    if (!sa) return NULL;

    sa->cDims = cDims;
    sa->cbElements = elem_size;
    sa->fFeatures = fFeatures;
    sa->vt_hint = vt;
    /* Explicit overflow check before allocation (total * elem_size). */
    if (total > 0 && elem_size > 0 && total > SIZE_MAX / elem_size) {
        free(sa);
        return NULL;
    }
    sa->pvData = (total > 0) ? calloc(total, elem_size) : NULL;
    if (total > 0 && !sa->pvData) { free(sa); return NULL; }

    for (uint32_t i = 0; i < cDims; i++) {
        sa->rgsabound[i].cElements = bounds[i].cElements;
        sa->rgsabound[i].lLbound = bounds[i].lLbound;
    }
    return sa;
}

WINAPI_EXPORT HRESULT SafeArrayDestroy(SAFEARRAY *psa)
{
    if (!psa) return 0;
    if (psa->cLocks > 0) return 0x8002000D; /* DISP_E_ARRAYISLOCKED */

    /* Element cleanup for BSTR / VARIANT / IUnknown arrays. */
    if (psa->pvData) {
        size_t total = 1;
        int overflow = 0;
        for (uint32_t i = 0; i < psa->cDims; i++) {
            uint32_t c = psa->rgsabound[i].cElements;
            if (c == 0) { total = 0; break; }
            if (total > SIZE_MAX / c) { overflow = 1; break; }
            total *= c;
        }
        if (!overflow) {
            if (psa->fFeatures & FADF_BSTR) {
                void **bstrs = (void **)psa->pvData;
                for (size_t i = 0; i < total; i++) {
                    if (bstrs[i]) SysFreeString(bstrs[i]);
                }
            } else if (psa->fFeatures & FADF_VARIANT) {
                VARIANT_T *vs = (VARIANT_T *)psa->pvData;
                for (size_t i = 0; i < total; i++) {
                    VariantClear(&vs[i]);
                }
            } else if (psa->fFeatures & (FADF_UNKNOWN | FADF_DISPATCH)) {
                void **objs = (void **)psa->pvData;
                typedef uint32_t (__attribute__((ms_abi)) *ReleaseFn)(void *);
                for (size_t i = 0; i < total; i++) {
                    if (objs[i]) {
                        void **vtbl = *(void ***)objs[i];
                        if (vtbl && vtbl[2]) ((ReleaseFn)vtbl[2])(objs[i]);
                    }
                }
            }
        }
    }

    free(psa->pvData);
    free(psa);
    return 0;
}

WINAPI_EXPORT HRESULT SafeArrayDestroyData(SAFEARRAY *psa)
{
    if (!psa) return 0x80070057;
    if (psa->cLocks > 0) return 0x8002000D;
    if (!psa->pvData) return 0;

    size_t total = 1;
    for (uint32_t i = 0; i < psa->cDims; i++) {
        uint32_t c = psa->rgsabound[i].cElements;
        if (c == 0) { total = 0; break; }
        if (total > SIZE_MAX / c) return 0x8007000E;
        total *= c;
    }
    if (psa->fFeatures & FADF_BSTR) {
        void **bstrs = (void **)psa->pvData;
        for (size_t i = 0; i < total; i++) if (bstrs[i]) { SysFreeString(bstrs[i]); bstrs[i] = NULL; }
    } else if (psa->fFeatures & FADF_VARIANT) {
        VARIANT_T *vs = (VARIANT_T *)psa->pvData;
        for (size_t i = 0; i < total; i++) VariantClear(&vs[i]);
    }
    memset(psa->pvData, 0, total * psa->cbElements);
    return 0;
}

WINAPI_EXPORT uint32_t SafeArrayGetDim(SAFEARRAY *psa)
{
    return psa ? psa->cDims : 0;
}

WINAPI_EXPORT HRESULT SafeArrayGetLBound(SAFEARRAY *psa, uint32_t nDim, int32_t *plLbound)
{
    if (!psa || !plLbound || nDim < 1 || nDim > psa->cDims) return 0x80070057;
    *plLbound = psa->rgsabound[nDim - 1].lLbound;
    return 0;
}

WINAPI_EXPORT HRESULT SafeArrayGetUBound(SAFEARRAY *psa, uint32_t nDim, int32_t *plUbound)
{
    if (!psa || !plUbound || nDim < 1 || nDim > psa->cDims) return 0x80070057;
    *plUbound = psa->rgsabound[nDim - 1].lLbound + (int32_t)psa->rgsabound[nDim - 1].cElements - 1;
    return 0;
}

WINAPI_EXPORT HRESULT SafeArrayAccessData(SAFEARRAY *psa, void **ppvData)
{
    if (!psa || !ppvData) return 0x80070057;
    psa->cLocks++;
    *ppvData = psa->pvData;
    return 0;
}

WINAPI_EXPORT HRESULT SafeArrayUnaccessData(SAFEARRAY *psa)
{
    if (!psa) return 0x80070057;
    if (psa->cLocks > 0) psa->cLocks--;
    return 0;
}

WINAPI_EXPORT HRESULT SafeArrayGetElement(SAFEARRAY *psa, const int32_t *rgIndices, void *pv)
{
    if (!psa || !rgIndices || !pv || !psa->pvData) return 0x80070057;
    int64_t linear = 0;
    int64_t stride = 1;
    for (int d = psa->cDims - 1; d >= 0; d--) {
        int32_t idx = rgIndices[d] - psa->rgsabound[d].lLbound;
        if (idx < 0 || (uint32_t)idx >= psa->rgsabound[d].cElements)
            return 0x8002000B; /* DISP_E_BADINDEX */
        linear += (int64_t)idx * stride;
        stride *= (int64_t)psa->rgsabound[d].cElements;
    }
    uint8_t *slot = (uint8_t *)psa->pvData + (size_t)linear * psa->cbElements;
    if (psa->fFeatures & FADF_BSTR) {
        /* Return a newly-allocated BSTR copy so caller owns it. */
        void *stored = *(void **)slot;
        if (!stored) { *(void **)pv = NULL; return 0; }
        void *copy = SysAllocStringLen(stored, SysStringLen(stored));
        if (!copy) return 0x8007000E;
        *(void **)pv = copy;
        return 0;
    }
    if (psa->fFeatures & FADF_VARIANT) {
        return VariantCopy(pv, slot);
    }
    if (psa->fFeatures & (FADF_UNKNOWN | FADF_DISPATCH)) {
        void *obj = *(void **)slot;
        *(void **)pv = obj;
        if (obj) {
            typedef uint32_t (__attribute__((ms_abi)) *AddRefFn)(void *);
            void **vtbl = *(void ***)obj;
            if (vtbl && vtbl[1]) ((AddRefFn)vtbl[1])(obj);
        }
        return 0;
    }
    memcpy(pv, slot, psa->cbElements);
    return 0;
}

WINAPI_EXPORT HRESULT SafeArrayPutElement(SAFEARRAY *psa, const int32_t *rgIndices, void *pv)
{
    if (!psa || !rgIndices || !psa->pvData) return 0x80070057;
    int64_t linear = 0;
    int64_t stride = 1;
    for (int d = psa->cDims - 1; d >= 0; d--) {
        int32_t idx = rgIndices[d] - psa->rgsabound[d].lLbound;
        if (idx < 0 || (uint32_t)idx >= psa->rgsabound[d].cElements)
            return 0x8002000B; /* DISP_E_BADINDEX */
        linear += (int64_t)idx * stride;
        stride *= (int64_t)psa->rgsabound[d].cElements;
    }
    uint8_t *slot = (uint8_t *)psa->pvData + (size_t)linear * psa->cbElements;
    if (psa->fFeatures & FADF_BSTR) {
        /* Free any existing stored BSTR, then deep-copy incoming. */
        void **dst = (void **)slot;
        if (*dst) SysFreeString(*dst);
        if (pv) {
            *dst = SysAllocStringLen(pv, SysStringLen(pv));
            if (!*dst) return 0x8007000E;
        } else {
            *dst = NULL;
        }
        return 0;
    }
    if (psa->fFeatures & FADF_VARIANT) {
        if (!pv) return 0x80070057;
        VariantClear(slot);
        return VariantCopy(slot, pv);
    }
    if (psa->fFeatures & (FADF_UNKNOWN | FADF_DISPATCH)) {
        void **dst = (void **)slot;
        void *incoming = pv ? *(void **)pv : NULL;
        typedef uint32_t (__attribute__((ms_abi)) *AddRefFn)(void *);
        typedef uint32_t (__attribute__((ms_abi)) *ReleaseFn)(void *);
        if (incoming) {
            void **vtbl = *(void ***)incoming;
            if (vtbl && vtbl[1]) ((AddRefFn)vtbl[1])(incoming);
        }
        if (*dst) {
            void **vtbl = *(void ***)(*dst);
            if (vtbl && vtbl[2]) ((ReleaseFn)vtbl[2])(*dst);
        }
        *dst = incoming;
        return 0;
    }
    if (!pv) return 0x80070057;
    memcpy(slot, pv, psa->cbElements);
    return 0;
}

WINAPI_EXPORT HRESULT SafeArrayGetVartype(SAFEARRAY *psa, uint16_t *pvt)
{
    if (!psa || !pvt) return 0x80070057;
    *pvt = psa->vt_hint;
    return 0;
}

WINAPI_EXPORT HRESULT SafeArrayLock(SAFEARRAY *psa)
{
    if (!psa) return 0x80070057;
    psa->cLocks++;
    return 0;
}

WINAPI_EXPORT HRESULT SafeArrayUnlock(SAFEARRAY *psa)
{
    if (!psa) return 0x80070057;
    if (psa->cLocks > 0) psa->cLocks--;
    return 0;
}

WINAPI_EXPORT uint32_t SafeArrayGetElemsize(SAFEARRAY *psa)
{
    return psa ? psa->cbElements : 0;
}

WINAPI_EXPORT SAFEARRAY *SafeArrayCreateVector(uint16_t vt, int32_t lLbound, uint32_t cElements)
{
    struct { uint32_t cElements; int32_t lLbound; } bound;
    bound.cElements = cElements;
    bound.lLbound = lLbound;
    return SafeArrayCreate(vt, 1, &bound);
}

/* ========== Error Info Functions ========== */

WINAPI_EXPORT HRESULT GetErrorInfo(uint32_t dwReserved, void **pperrinfo)
{
    (void)dwReserved;
    if (pperrinfo) *pperrinfo = NULL;
    return 1; /* S_FALSE - no error info */
}

WINAPI_EXPORT HRESULT SetErrorInfo(uint32_t dwReserved, void *perrinfo)
{
    (void)dwReserved; (void)perrinfo;
    return 0;
}

WINAPI_EXPORT HRESULT CreateErrorInfo(void **pperrinfo)
{
    if (pperrinfo) *pperrinfo = NULL;
    return 0x80004001; /* E_NOTIMPL */
}

/* ========== TypeLib Functions ========== */

WINAPI_EXPORT HRESULT LoadTypeLib(const void *szFile, void **pptlib)
{
    (void)szFile;
    fprintf(stderr, "[oleaut32] LoadTypeLib: stub\n");
    if (pptlib) *pptlib = NULL;
    return 0x80029C4A; /* TYPE_E_CANTLOADLIBRARY */
}

WINAPI_EXPORT HRESULT LoadTypeLibEx(const void *szFile, uint32_t regkind, void **pptlib)
{
    (void)regkind;
    return LoadTypeLib(szFile, pptlib);
}

WINAPI_EXPORT HRESULT RegisterTypeLib(void *ptlib, const void *szFullPath, const void *szHelpDir)
{
    (void)ptlib; (void)szFullPath; (void)szHelpDir;
    return 0;
}

WINAPI_EXPORT HRESULT UnRegisterTypeLib(const void *libID, uint16_t wVerMajor,
                                         uint16_t wVerMinor, uint32_t lcid, uint32_t syskind)
{
    (void)libID; (void)wVerMajor; (void)wVerMinor; (void)lcid; (void)syskind;
    return 0;
}

WINAPI_EXPORT HRESULT CreateTypeLib2(uint32_t syskind, const void *szFile, void **ppctlib)
{
    (void)syskind; (void)szFile;
    if (ppctlib) *ppctlib = NULL;
    return 0x80004001;
}

/* ========== Dispatch Helpers ========== */

WINAPI_EXPORT HRESULT DispGetParam(void *pdispparams, uint32_t position,
                                     uint16_t vtTarg, void *pvarResult, uint32_t *puArgErr)
{
    (void)pdispparams; (void)position; (void)vtTarg;
    (void)pvarResult; (void)puArgErr;
    return 0x80020004; /* DISP_E_PARAMNOTFOUND */
}

WINAPI_EXPORT HRESULT DispInvoke(void *_this, void *ptinfo, int32_t dispidMember,
                                   uint16_t wFlags, void *pparams,
                                   void *pvarResult, void *pexcepinfo, uint32_t *puArgErr)
{
    (void)_this; (void)ptinfo; (void)dispidMember; (void)wFlags;
    (void)pparams; (void)pvarResult; (void)pexcepinfo; (void)puArgErr;
    return 0x80020003; /* DISP_E_MEMBERNOTFOUND */
}

/* ========== Misc OLE Automation ========== */

WINAPI_EXPORT int32_t DosDateTimeToVariantTime(uint16_t wDosDate, uint16_t wDosTime, double *pvtime)
{
    (void)wDosDate; (void)wDosTime;
    if (pvtime) *pvtime = 0.0;
    return 1;
}

WINAPI_EXPORT int32_t VariantTimeToDosDateTime(double vtime, uint16_t *pwDosDate, uint16_t *pwDosTime)
{
    (void)vtime;
    if (pwDosDate) *pwDosDate = 0;
    if (pwDosTime) *pwDosTime = 0;
    return 1;
}

WINAPI_EXPORT int32_t SystemTimeToVariantTime(void *lpSystemTime, double *pvtime)
{
    (void)lpSystemTime;
    if (pvtime) *pvtime = 0.0;
    return 1;
}

WINAPI_EXPORT int32_t VariantTimeToSystemTime(double vtime, void *lpSystemTime)
{
    (void)vtime;
    if (lpSystemTime) memset(lpSystemTime, 0, 16);
    return 1;
}

WINAPI_EXPORT HRESULT VarBstrFromI4(int32_t lIn, uint32_t lcid, uint32_t dwFlags, void **pbstrOut)
{
    (void)lcid; (void)dwFlags;
    if (!pbstrOut) return 0x80070057;
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", lIn);
    /* Convert to BSTR (UTF-16) */
    size_t len = strlen(buf);
    uint16_t *wbuf = malloc((len + 1) * 2);
    if (!wbuf) return 0x8007000E;
    for (size_t i = 0; i <= len; i++) wbuf[i] = (uint16_t)buf[i];
    *pbstrOut = SysAllocStringLen(wbuf, (uint32_t)len);
    free(wbuf);
    return 0;
}

WINAPI_EXPORT uint32_t OaBuildVersion(void)
{
    return 0x000A0000; /* OLE Automation version 10.0 */
}
