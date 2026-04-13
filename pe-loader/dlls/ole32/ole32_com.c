/*
 * ole32_com.c - Additional COM stubs
 *
 * Core COM functions (CoInitialize, CoCreateInstance, CoTaskMem*, etc.)
 * are in ole32_classregistry.c. This file contains supplemental functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/dll_common.h"

/* HRESULT codes */
#ifndef S_OK
#define S_OK                    ((HRESULT)0x00000000)
#endif
#ifndef E_NOTIMPL
#define E_NOTIMPL               ((HRESULT)0x80004001)
#endif
#ifndef REGDB_E_CLASSNOTREG
#define REGDB_E_CLASSNOTREG     ((HRESULT)0x80040154)
#endif

/* CoCreateInstanceEx */
WINAPI_EXPORT HRESULT CoCreateInstanceEx(
    const GUID *rclsid,
    void *pUnkOuter,
    DWORD dwClsCtx,
    void *pServerInfo,
    DWORD dwCount,
    void *pResults)
{
    (void)rclsid; (void)pUnkOuter; (void)dwClsCtx;
    (void)pServerInfo; (void)dwCount; (void)pResults;
    return REGDB_E_CLASSNOTREG;
}

WINAPI_EXPORT HRESULT CoWaitForMultipleHandles(DWORD dwFlags, DWORD dwTimeout,
                                                 ULONG cHandles, void *pHandles,
                                                 LPDWORD lpdwindex)
{
    (void)dwFlags; (void)dwTimeout; (void)cHandles; (void)pHandles;
    if (lpdwindex) *lpdwindex = 0;
    return S_OK;
}

WINAPI_EXPORT void CoFreeUnusedLibraries(void)
{
    /* No-op */
}

WINAPI_EXPORT HRESULT CoGetMalloc(DWORD dwMemContext, void **ppMalloc)
{
    (void)dwMemContext;
    if (ppMalloc) *ppMalloc = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT CoRegisterMessageFilter(void *lpMessageFilter, void **lplpMessageFilter)
{
    (void)lpMessageFilter;
    if (lplpMessageFilter) *lplpMessageFilter = NULL;
    return S_OK;
}
