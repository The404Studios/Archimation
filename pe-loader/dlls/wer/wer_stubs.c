/*
 * wer_stubs.c - Windows Error Reporting (wer.dll / faultrep.dll) stubs
 *
 * UE5 registers crash handlers early during startup via these APIs.
 * All functions return S_OK to prevent load failures.
 */

#include <stdio.h>
#include <string.h>

#include "common/dll_common.h"

#define S_OK ((HRESULT)0x00000000)
#define WER_LOG "[wer] "

WINAPI_EXPORT HRESULT WerRegisterRuntimeExceptionModule(
    const uint16_t *pwszOutOfProcessCallbackDll, void *pContext)
{
    (void)pwszOutOfProcessCallbackDll; (void)pContext;
    fprintf(stderr, WER_LOG "WerRegisterRuntimeExceptionModule: stub\n");
    return S_OK;
}

WINAPI_EXPORT HRESULT WerUnregisterRuntimeExceptionModule(
    const uint16_t *pwszOutOfProcessCallbackDll, void *pContext)
{
    (void)pwszOutOfProcessCallbackDll; (void)pContext;
    return S_OK;
}

WINAPI_EXPORT HRESULT WerRegisterMemoryBlock(void *pvAddress, DWORD dwSize)
{
    (void)pvAddress; (void)dwSize;
    return S_OK;
}

WINAPI_EXPORT HRESULT WerUnregisterMemoryBlock(void *pvAddress)
{
    (void)pvAddress;
    return S_OK;
}

WINAPI_EXPORT HRESULT WerRegisterFile(
    const uint16_t *pwzFile, DWORD regFileType, DWORD dwFlags)
{
    (void)pwzFile; (void)regFileType; (void)dwFlags;
    return S_OK;
}

WINAPI_EXPORT HRESULT WerUnregisterFile(const uint16_t *pwzFile)
{
    (void)pwzFile;
    return S_OK;
}

WINAPI_EXPORT HRESULT WerRegisterExcludedMemoryBlock(void *address, DWORD size)
{
    (void)address; (void)size;
    return S_OK;
}

WINAPI_EXPORT HRESULT WerUnregisterExcludedMemoryBlock(void *address)
{
    (void)address;
    return S_OK;
}

WINAPI_EXPORT HRESULT WerSetFlags(DWORD dwFlags)
{
    (void)dwFlags;
    return S_OK;
}

WINAPI_EXPORT HRESULT WerGetFlags(void *hProcess, DWORD *pdwFlags)
{
    (void)hProcess;
    if (pdwFlags) *pdwFlags = 0;
    return S_OK;
}

WINAPI_EXPORT HRESULT WerRegisterAppLocalDump(const uint16_t *localAppDataRelativePath)
{
    (void)localAppDataRelativePath;
    return S_OK;
}

WINAPI_EXPORT HRESULT WerUnregisterAppLocalDump(void)
{
    return S_OK;
}

/* faultrep.dll functions */
WINAPI_EXPORT BOOL ReportFault(void *pep, DWORD dwOpt)
{
    (void)pep; (void)dwOpt;
    fprintf(stderr, WER_LOG "ReportFault: stub (not reporting)\n");
    return TRUE;
}

WINAPI_EXPORT HRESULT AddERExcludedApplicationA(const char *szApplication)
{
    (void)szApplication;
    return S_OK;
}
