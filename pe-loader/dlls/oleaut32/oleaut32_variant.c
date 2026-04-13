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
#define VT_I4      3
#define VT_BSTR    8
#define VT_DISPATCH 9
#define VT_UNKNOWN  13
#define VT_BYREF   0x4000

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
    if (v->vt == VT_BSTR)
        SysFreeString(v->bstrVal);
    else if ((v->vt == VT_UNKNOWN || v->vt == VT_DISPATCH) && v->punkVal) {
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
    if (src->vt == VT_BSTR && src->bstrVal) {
        dst->bstrVal = SysAllocStringLen(src->bstrVal, SysStringLen(src->bstrVal));
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

    VariantClear(pvargDest);
    VARIANT_T *dst = (VARIANT_T *)pvargDest;
    dst->vt = vt;

    /* Basic conversions */
    if (vt == VT_EMPTY || vt == VT_NULL) return 0;
    if (vt == VT_I4) {
        if (src->vt == VT_I4) dst->lVal = src->lVal;
        else dst->lVal = 0;
        return 0;
    }

    return 0x80020005; /* DISP_E_TYPEMISMATCH */
}

WINAPI_EXPORT HRESULT VariantChangeTypeEx(void *pvargDest, const void *pvarSrc,
                                            uint32_t lcid, uint16_t wFlags, uint16_t vt)
{
    (void)lcid;
    return VariantChangeType(pvargDest, pvarSrc, wFlags, vt);
}

/* ========== SafeArray Functions ========== */

typedef struct {
    uint16_t cDims;
    uint16_t fFeatures;
    uint32_t cbElements;
    uint32_t cLocks;
    void *pvData;
    struct { uint32_t cElements; int32_t lLbound; } rgsabound[1];
} SAFEARRAY;

WINAPI_EXPORT SAFEARRAY *SafeArrayCreate(uint16_t vt, uint32_t cDims, const void *rgsabound)
{
    if (cDims == 0) return NULL;
    typedef struct { uint32_t cElements; int32_t lLbound; } BOUND;
    const BOUND *bounds = (const BOUND *)rgsabound;

    size_t total = 1;
    for (uint32_t i = 0; i < cDims; i++) {
        if (bounds[i].cElements > 0 && total > SIZE_MAX / bounds[i].cElements) {
            return NULL; /* overflow */
        }
        total *= bounds[i].cElements;
    }

    uint32_t elem_size;
    switch (vt) {
    case 2: elem_size = 2; break; /* VT_I2 */
    case 3: elem_size = 4; break; /* VT_I4 */
    case 5: elem_size = 8; break; /* VT_R8 */
    case 8: elem_size = sizeof(void *); break; /* VT_BSTR */
    case 12: elem_size = 16; break; /* VT_VARIANT */
    default: elem_size = 4; break;
    }

    size_t hdr_size = sizeof(SAFEARRAY) + (cDims > 1 ? (cDims - 1) * 8 : 0);
    SAFEARRAY *sa = calloc(1, hdr_size);
    if (!sa) return NULL;

    sa->cDims = cDims;
    sa->cbElements = elem_size;
    if (elem_size > 0 && total > SIZE_MAX / elem_size) {
        free(sa);
        return NULL;
    }
    sa->pvData = calloc(total, elem_size);
    if (!sa->pvData) { free(sa); return NULL; }

    for (uint32_t i = 0; i < cDims; i++) {
        sa->rgsabound[i].cElements = bounds[i].cElements;
        sa->rgsabound[i].lLbound = bounds[i].lLbound;
    }
    return sa;
}

WINAPI_EXPORT HRESULT SafeArrayDestroy(SAFEARRAY *psa)
{
    if (!psa) return 0;
    free(psa->pvData);
    free(psa);
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
    if (!psa || !rgIndices || !pv) return 0x80070057;
    int32_t linear = 0;
    int32_t stride = 1;
    for (int d = psa->cDims - 1; d >= 0; d--) {
        int32_t idx = rgIndices[d] - psa->rgsabound[d].lLbound;
        if (idx < 0 || (uint32_t)idx >= psa->rgsabound[d].cElements)
            return 0x8002000B; /* DISP_E_BADINDEX */
        linear += idx * stride;
        stride *= psa->rgsabound[d].cElements;
    }
    memcpy(pv, (uint8_t *)psa->pvData + linear * psa->cbElements, psa->cbElements);
    return 0;
}

WINAPI_EXPORT HRESULT SafeArrayPutElement(SAFEARRAY *psa, const int32_t *rgIndices, void *pv)
{
    if (!psa || !rgIndices || !pv) return 0x80070057;
    int32_t linear = 0;
    int32_t stride = 1;
    for (int d = psa->cDims - 1; d >= 0; d--) {
        int32_t idx = rgIndices[d] - psa->rgsabound[d].lLbound;
        if (idx < 0 || (uint32_t)idx >= psa->rgsabound[d].cElements)
            return 0x8002000B; /* DISP_E_BADINDEX */
        linear += idx * stride;
        stride *= psa->rgsabound[d].cElements;
    }
    memcpy((uint8_t *)psa->pvData + linear * psa->cbElements, pv, psa->cbElements);
    return 0;
}

WINAPI_EXPORT HRESULT SafeArrayGetVartype(SAFEARRAY *psa, uint16_t *pvt)
{
    (void)psa;
    if (pvt) *pvt = 0;
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
