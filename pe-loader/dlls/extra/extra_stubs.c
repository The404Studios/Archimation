/*
 * extra_stubs.c - Catch-all stubs for rarely-used DLLs
 *
 * Covers: wevtapi.dll, powrprof.dll, cabinet.dll, wintrust.dll,
 *         ntmarta.dll, wldp.dll, profapi.dll, normaliz.dll, avrt.dll
 *
 * These are linked into libpe_kernel32.so to handle misc imports.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/dll_common.h"

/* ========== wevtapi.dll - Event Tracing ========== */
/*
 * EventRegister, EventUnregister, EventWrite, EventWriteTransfer,
 * EventEnabled: canonical home is advapi32.dll (advapi32_security.c).
 * Removed duplicates from extra_stubs.
 *
 * Kept: EventWriteString, EventActivityIdControl, EventProviderEnabled
 * (not present in advapi32_security.c).
 */

WINAPI_EXPORT uint32_t EventWriteString(uint64_t RegHandle, uint8_t Level,
                                         uint64_t Keyword, const void *String)
{
    (void)RegHandle; (void)Level; (void)Keyword; (void)String;
    return 0;
}

WINAPI_EXPORT uint32_t EventActivityIdControl(uint32_t ControlCode, void *ActivityId)
{
    (void)ControlCode;
    if (ActivityId) memset(ActivityId, 0, 16);
    return 0;
}

WINAPI_EXPORT BOOL EventProviderEnabled(uint64_t RegHandle, uint8_t Level, uint64_t Keyword)
{
    (void)RegHandle; (void)Level; (void)Keyword;
    return FALSE;
}

/* ========== powrprof.dll - Power Management ========== */

WINAPI_EXPORT uint32_t CallNtPowerInformation(uint32_t InformationLevel,
                                               void *InputBuffer, uint32_t InputBufferLength,
                                               void *OutputBuffer, uint32_t OutputBufferLength)
{
    (void)InformationLevel; (void)InputBuffer; (void)InputBufferLength;
    if (OutputBuffer && OutputBufferLength > 0)
        memset(OutputBuffer, 0, OutputBufferLength);
    return 0; /* STATUS_SUCCESS */
}

WINAPI_EXPORT uint32_t PowerGetActiveScheme(void *UserRootPowerKey, void **ActivePolicyGuid)
{
    (void)UserRootPowerKey;
    if (ActivePolicyGuid) {
        /* Return a fake "balanced" power scheme GUID */
        void *guid = calloc(1, 16);
        if (guid) {
            /* {381b4222-f694-41f0-9685-ff5bb260df2e} */
            uint8_t *g = (uint8_t *)guid;
            g[0] = 0x22; g[1] = 0x42; g[2] = 0x1b; g[3] = 0x38;
            *ActivePolicyGuid = guid;
        }
    }
    return 0;
}

WINAPI_EXPORT uint32_t PowerReadDCValue(void *RootKey, const void *SchemeGuid,
                                         const void *SubGroupOfPowerSettingsGuid,
                                         const void *PowerSettingGuid,
                                         uint32_t *Type, void *Buffer, uint32_t *BufferSize)
{
    (void)RootKey; (void)SchemeGuid; (void)SubGroupOfPowerSettingsGuid;
    (void)PowerSettingGuid; (void)Type; (void)Buffer; (void)BufferSize;
    return 2; /* ERROR_FILE_NOT_FOUND */
}

WINAPI_EXPORT uint32_t PowerReadACValue(void *RootKey, const void *SchemeGuid,
                                         const void *SubGroupOfPowerSettingsGuid,
                                         const void *PowerSettingGuid,
                                         uint32_t *Type, void *Buffer, uint32_t *BufferSize)
{
    (void)RootKey; (void)SchemeGuid; (void)SubGroupOfPowerSettingsGuid;
    (void)PowerSettingGuid; (void)Type; (void)Buffer; (void)BufferSize;
    return 2;
}

WINAPI_EXPORT BOOL GetSystemPowerStatus(void *lpSystemPowerStatus)
{
    if (lpSystemPowerStatus) {
        /* SYSTEM_POWER_STATUS: ACLineStatus=1 (online), 100% battery */
        memset(lpSystemPowerStatus, 0, 12);
        uint8_t *s = (uint8_t *)lpSystemPowerStatus;
        s[0] = 1;   /* ACLineStatus = online */
        s[1] = 0;   /* BatteryFlag = no battery */
        s[2] = 100; /* BatteryLifePercent */
    }
    return TRUE;
}

/* ========== cabinet.dll - Cabinet/FDI Archive Functions ========== */

WINAPI_EXPORT void *FDICreate(void *pfnalloc, void *pfnfree, void *pfnopen,
                               void *pfnread, void *pfnwrite, void *pfnclose,
                               void *pfnseek, int cpuType, void *perf)
{
    (void)pfnalloc; (void)pfnfree; (void)pfnopen; (void)pfnread;
    (void)pfnwrite; (void)pfnclose; (void)pfnseek; (void)cpuType; (void)perf;
    fprintf(stderr, "[cabinet] FDICreate: stub\n");
    return NULL;
}

WINAPI_EXPORT BOOL FDICopy(void *hfdi, const char *pszCabinet, const char *pszCabPath,
                            int flags, void *pfnfdin, void *pfnfdid, void *pvUser)
{
    (void)hfdi; (void)pszCabinet; (void)pszCabPath; (void)flags;
    (void)pfnfdin; (void)pfnfdid; (void)pvUser;
    return FALSE;
}

WINAPI_EXPORT BOOL FDIDestroy(void *hfdi)
{
    (void)hfdi;
    return TRUE;
}

WINAPI_EXPORT BOOL FDIIsCabinet(void *hfdi, int hf, void *pfdici)
{
    (void)hfdi; (void)hf; (void)pfdici;
    return FALSE;
}

/* ========== wintrust.dll - Code Signing Verification ========== */

WINAPI_EXPORT long WinVerifyTrust(void *hwnd, void *pgActionID, void *pWVTData)
{
    (void)hwnd; (void)pgActionID; (void)pWVTData;
    return 0; /* TRUST_E_NOSIGNATURE = 0x800B0100, but return 0 = trusted */
}

WINAPI_EXPORT BOOL CryptCATAdminAcquireContext(void **phCatAdmin,
                                                const void *pgSubsystem, uint32_t dwFlags)
{
    (void)pgSubsystem; (void)dwFlags;
    if (phCatAdmin) *phCatAdmin = (void *)0xCAFE0001;
    return TRUE;
}

WINAPI_EXPORT BOOL CryptCATAdminReleaseContext(void *hCatAdmin, uint32_t dwFlags)
{
    (void)hCatAdmin; (void)dwFlags;
    return TRUE;
}

WINAPI_EXPORT void *CryptCATAdminEnumCatalogFromHash(void *hCatAdmin,
                                                      const void *pbHash, uint32_t cbHash,
                                                      uint32_t dwFlags, void **phPrevCatInfo)
{
    (void)hCatAdmin; (void)pbHash; (void)cbHash; (void)dwFlags; (void)phPrevCatInfo;
    return NULL; /* No catalog found */
}

WINAPI_EXPORT BOOL CryptCATAdminReleaseCatalogContext(void *hCatAdmin,
                                                       void *hCatInfo, uint32_t dwFlags)
{
    (void)hCatAdmin; (void)hCatInfo; (void)dwFlags;
    return TRUE;
}

WINAPI_EXPORT BOOL CryptCATAdminCalcHashFromFileHandle(void *hFile, uint32_t *pcbHash,
                                                        void *pbHash, uint32_t dwFlags)
{
    (void)hFile; (void)dwFlags;
    if (pcbHash && !pbHash) { *pcbHash = 20; return TRUE; } /* SHA1 size */
    if (pcbHash && pbHash) { memset(pbHash, 0, *pcbHash); return TRUE; }
    return FALSE;
}

/* ========== ntmarta.dll - NT MARTA (Security) ========== */

WINAPI_EXPORT uint32_t AccRewriteGetNamedRights(const void *pObjectName, uint32_t ObjectType,
                                                  uint32_t SecurityInfo, void *ppsidOwner,
                                                  void *ppsidGroup, void *ppDacl,
                                                  void *ppSacl, void *ppSecurityDescriptor)
{
    (void)pObjectName; (void)ObjectType; (void)SecurityInfo;
    (void)ppsidOwner; (void)ppsidGroup; (void)ppDacl; (void)ppSacl;
    (void)ppSecurityDescriptor;
    return 5; /* ERROR_ACCESS_DENIED */
}

/* ========== wldp.dll - Windows Lockdown Policy ========== */

WINAPI_EXPORT HRESULT WldpQueryDynamicCodeTrust(void *fileHandle, void *baseImage, uint32_t imageSize)
{
    (void)fileHandle; (void)baseImage; (void)imageSize;
    return 0; /* S_OK - code is trusted */
}

WINAPI_EXPORT HRESULT WldpIsClassInApprovedList(const void *classID, void *hostInfo,
                                                  BOOL *isApproved, uint32_t optionalFlags)
{
    (void)classID; (void)hostInfo; (void)optionalFlags;
    if (isApproved) *isApproved = TRUE;
    return 0;
}

/* ========== profapi.dll - User Profile API ========== */

/* Already mostly in userenv; these are redirects */

/* ========== normaliz.dll - Unicode Normalization ========== */

WINAPI_EXPORT int IdnToAscii(uint32_t dwFlags, const void *lpUnicodeCharStr,
                              int cchUnicodeChar, void *lpASCIICharStr, int cchASCIIChar)
{
    (void)dwFlags;
    /* Passthrough: just copy if it's ASCII */
    if (lpUnicodeCharStr && lpASCIICharStr && cchUnicodeChar > 0) {
        int len = cchUnicodeChar < cchASCIIChar ? cchUnicodeChar : cchASCIIChar;
        memcpy(lpASCIICharStr, lpUnicodeCharStr, len * 2);
        return len;
    }
    return 0;
}

WINAPI_EXPORT int IdnToUnicode(uint32_t dwFlags, const void *lpASCIICharStr,
                                int cchASCIIChar, void *lpUnicodeCharStr, int cchUnicodeChar)
{
    (void)dwFlags;
    if (lpASCIICharStr && lpUnicodeCharStr && cchASCIIChar > 0) {
        int len = cchASCIIChar < cchUnicodeChar ? cchASCIIChar : cchUnicodeChar;
        memcpy(lpUnicodeCharStr, lpASCIICharStr, len * 2);
        return len;
    }
    return 0;
}

WINAPI_EXPORT BOOL IsNormalizedString(uint32_t NormForm, const void *lpString, int cwLength)
{
    (void)NormForm; (void)lpString; (void)cwLength;
    return TRUE; /* Assume normalized */
}

WINAPI_EXPORT int NormalizeString(uint32_t NormForm, const void *lpSrcString, int cwSrcLength,
                                   void *lpDstString, int cwDstLength)
{
    (void)NormForm;
    if (!lpSrcString) return 0;
    int src_len;
    if (cwSrcLength > 0) {
        src_len = cwSrcLength;
    } else {
        /* Calculate uint16_t string length */
        const uint16_t *p = (const uint16_t *)lpSrcString;
        src_len = 0;
        while (p[src_len]) src_len++;
        src_len++; /* include null */
    }
    if (!lpDstString || cwDstLength == 0) return src_len;
    int copy = src_len < cwDstLength ? src_len : cwDstLength;
    memcpy(lpDstString, lpSrcString, copy * sizeof(uint16_t));
    return copy;
}

/* ========== avrt.dll - Multimedia Scheduling ========== */

WINAPI_EXPORT void *AvSetMmThreadCharacteristicsA(const char *TaskName, uint32_t *TaskIndex)
{
    (void)TaskName;
    if (TaskIndex) *TaskIndex = 1;
    return (void *)0xAE570001;
}

WINAPI_EXPORT void *AvSetMmThreadCharacteristicsW(const void *TaskName, uint32_t *TaskIndex)
{
    (void)TaskName;
    if (TaskIndex) *TaskIndex = 1;
    return (void *)0xAE570001;
}

WINAPI_EXPORT BOOL AvRevertMmThreadCharacteristics(void *AvrtHandle)
{
    (void)AvrtHandle;
    return TRUE;
}

WINAPI_EXPORT BOOL AvSetMmThreadPriority(void *AvrtHandle, uint32_t Priority)
{
    (void)AvrtHandle; (void)Priority;
    return TRUE;
}

WINAPI_EXPORT BOOL AvSetMmMaxThreadCharacteristicsA(const char *FirstTask,
                                                     const char *SecondTask,
                                                     uint32_t *TaskIndex)
{
    (void)FirstTask; (void)SecondTask;
    if (TaskIndex) *TaskIndex = 1;
    return TRUE;
}

WINAPI_EXPORT BOOL AvSetMmMaxThreadCharacteristicsW(const void *FirstTask,
                                                     const void *SecondTask,
                                                     uint32_t *TaskIndex)
{
    (void)FirstTask; (void)SecondTask;
    if (TaskIndex) *TaskIndex = 1;
    return TRUE;
}

/* ========== mfplat.dll - Media Foundation Platform ========== */

WINAPI_EXPORT HRESULT MFStartup(uint32_t Version, uint32_t dwFlags)
{
    (void)Version; (void)dwFlags;
    fprintf(stderr, "[mfplat] MFStartup: stub\n");
    return 0;
}

WINAPI_EXPORT HRESULT MFShutdown(void)
{
    return 0;
}

WINAPI_EXPORT HRESULT MFCreateMediaType(void **ppMFType)
{
    if (ppMFType) *ppMFType = NULL;
    return 0x80004001; /* E_NOTIMPL */
}

WINAPI_EXPORT HRESULT MFCreateAttributes(void **ppMFAttributes, uint32_t cInitialSize)
{
    (void)cInitialSize;
    if (ppMFAttributes) *ppMFAttributes = NULL;
    return 0x80004001;
}

WINAPI_EXPORT HRESULT MFCreateMemoryBuffer(uint32_t cbMaxLength, void **ppBuffer)
{
    (void)cbMaxLength;
    if (ppBuffer) *ppBuffer = NULL;
    return 0x80004001;
}

WINAPI_EXPORT HRESULT MFCreateSample(void **ppIMFSample)
{
    if (ppIMFSample) *ppIMFSample = NULL;
    return 0x80004001;
}
