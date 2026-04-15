/*
 * secur32_sspi.c - Security Support Provider Interface (secur32.dll / sspicli.dll)
 *
 * Provides SSPI functions: AcquireCredentialsHandle, InitializeSecurityContext,
 * GetUserNameEx, etc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "common/dll_common.h"

/* Security status codes */
#define SEC_E_OK                    0x00000000
#define SEC_I_CONTINUE_NEEDED       0x00090312
#define SEC_E_INSUFFICIENT_MEMORY   0x80090300
#define SEC_E_INVALID_HANDLE        0x80090301
#define SEC_E_UNSUPPORTED_FUNCTION  0x80090302
#define SEC_E_INTERNAL_ERROR        0x80090304
#define SEC_E_SECPKG_NOT_FOUND      0x80090305
#define SEC_E_NOT_OWNER             0x80090306
#define SEC_E_NO_CREDENTIALS        0x8009030E

/* NameFormat for GetUserNameEx */
#define NameUnknown          0
#define NameFullyQualifiedDN 1
#define NameSamCompatible    2
#define NameDisplay          3
#define NameUniqueId         6
#define NameCanonical        7
#define NameUserPrincipal    8
#define NameServicePrincipal 10

/* Security package info */
typedef struct {
    uint32_t fCapabilities;
    uint16_t wVersion;
    uint16_t wRPCID;
    uint32_t cbMaxToken;
    void *Name;
    void *Comment;
} SecPkgInfoA;

/* ========== Security Package Enumeration ========== */

static char ntlm_name[] = "NTLM";
static char ntlm_comment[] = "NTLM Security Package (stub)";
static char negotiate_name[] = "Negotiate";
static char negotiate_comment[] = "Microsoft Package Negotiator (stub)";

static SecPkgInfoA g_packages[] = {
    { 0x00083FB3, 1, 10, 12288, ntlm_name, ntlm_comment },
    { 0x000F3FF3, 1, 9, 12288, negotiate_name, negotiate_comment },
};

WINAPI_EXPORT int32_t EnumerateSecurityPackagesA(uint32_t *pcPackages, void **ppPackageInfo)
{
    if (!pcPackages || !ppPackageInfo) return SEC_E_INVALID_HANDLE;
    *pcPackages = 2;
    *ppPackageInfo = g_packages;
    return SEC_E_OK;
}

WINAPI_EXPORT int32_t EnumerateSecurityPackagesW(uint32_t *pcPackages, void **ppPackageInfo)
{
    /* For simplicity, return the ANSI version */
    return EnumerateSecurityPackagesA(pcPackages, ppPackageInfo);
}

WINAPI_EXPORT int32_t QuerySecurityPackageInfoA(const char *pszPackageName, void **ppPackageInfo)
{
    if (!pszPackageName || !ppPackageInfo) return SEC_E_SECPKG_NOT_FOUND;
    for (int i = 0; i < 2; i++) {
        if (strcasecmp(pszPackageName, (char *)g_packages[i].Name) == 0) {
            *ppPackageInfo = &g_packages[i];
            return SEC_E_OK;
        }
    }
    return SEC_E_SECPKG_NOT_FOUND;
}

WINAPI_EXPORT int32_t QuerySecurityPackageInfoW(const void *pszPackageName, void **ppPackageInfo)
{
    (void)pszPackageName;
    if (ppPackageInfo) *ppPackageInfo = &g_packages[0]; /* Default to NTLM */
    return SEC_E_OK;
}

WINAPI_EXPORT int32_t FreeContextBuffer(void *pvContextBuffer)
{
    (void)pvContextBuffer;
    /* Don't free static data */
    return SEC_E_OK;
}

/* ========== Credential Management ========== */

WINAPI_EXPORT int32_t AcquireCredentialsHandleA(
    const char *pszPrincipal, const char *pszPackage, uint32_t fCredentialUse,
    void *pvLogonId, void *pAuthData, void *pGetKeyFn, void *pvGetKeyArgument,
    void *phCredential, void *ptsExpiry)
{
    (void)pszPrincipal; (void)pszPackage; (void)fCredentialUse;
    (void)pvLogonId; (void)pAuthData; (void)pGetKeyFn; (void)pvGetKeyArgument;
    (void)ptsExpiry;
    /* Fill credential handle with dummy value */
    if (phCredential) memset(phCredential, 0x42, 16);
    return SEC_E_OK;
}

WINAPI_EXPORT int32_t AcquireCredentialsHandleW(
    const void *pszPrincipal, const void *pszPackage, uint32_t fCredentialUse,
    void *pvLogonId, void *pAuthData, void *pGetKeyFn, void *pvGetKeyArgument,
    void *phCredential, void *ptsExpiry)
{
    (void)pszPrincipal; (void)pszPackage; (void)fCredentialUse;
    (void)pvLogonId; (void)pAuthData; (void)pGetKeyFn; (void)pvGetKeyArgument;
    (void)ptsExpiry;
    if (phCredential) memset(phCredential, 0x42, 16);
    return SEC_E_OK;
}

WINAPI_EXPORT int32_t FreeCredentialsHandle(void *phCredential)
{
    (void)phCredential;
    return SEC_E_OK;
}

/* ========== Security Context ========== */

WINAPI_EXPORT int32_t InitializeSecurityContextA(
    void *phCredential, void *phContext, const char *pszTargetName,
    uint32_t fContextReq, uint32_t Reserved1, uint32_t TargetDataRep,
    void *pInput, uint32_t Reserved2, void *phNewContext,
    void *pOutput, uint32_t *pfContextAttr, void *ptsExpiry)
{
    (void)phCredential; (void)phContext; (void)pszTargetName;
    (void)fContextReq; (void)Reserved1; (void)TargetDataRep;
    (void)pInput; (void)Reserved2; (void)pOutput;
    (void)pfContextAttr; (void)ptsExpiry;
    if (phNewContext) memset(phNewContext, 0x43, 16);
    return SEC_E_OK;
}

WINAPI_EXPORT int32_t InitializeSecurityContextW(
    void *phCredential, void *phContext, const void *pszTargetName,
    uint32_t fContextReq, uint32_t Reserved1, uint32_t TargetDataRep,
    void *pInput, uint32_t Reserved2, void *phNewContext,
    void *pOutput, uint32_t *pfContextAttr, void *ptsExpiry)
{
    (void)phCredential; (void)phContext; (void)pszTargetName;
    (void)fContextReq; (void)Reserved1; (void)TargetDataRep;
    (void)pInput; (void)Reserved2; (void)pOutput;
    (void)pfContextAttr; (void)ptsExpiry;
    if (phNewContext) memset(phNewContext, 0x43, 16);
    return SEC_E_OK;
}

WINAPI_EXPORT int32_t AcceptSecurityContext(
    void *phCredential, void *phContext, void *pInput,
    uint32_t fContextReq, uint32_t TargetDataRep,
    void *phNewContext, void *pOutput, uint32_t *pfContextAttr, void *ptsExpiry)
{
    (void)phCredential; (void)phContext; (void)pInput;
    (void)fContextReq; (void)TargetDataRep;
    (void)phNewContext; (void)pOutput; (void)pfContextAttr; (void)ptsExpiry;
    return SEC_E_OK;
}

WINAPI_EXPORT int32_t DeleteSecurityContext(void *phContext)
{
    (void)phContext;
    return SEC_E_OK;
}

WINAPI_EXPORT int32_t CompleteAuthToken(void *phContext, void *pToken)
{
    (void)phContext; (void)pToken;
    return SEC_E_OK;
}

WINAPI_EXPORT int32_t QueryContextAttributesA(void *phContext, uint32_t ulAttribute, void *pBuffer)
{
    (void)phContext; (void)ulAttribute; (void)pBuffer;
    return SEC_E_UNSUPPORTED_FUNCTION;
}

WINAPI_EXPORT int32_t QueryContextAttributesW(void *phContext, uint32_t ulAttribute, void *pBuffer)
{
    (void)phContext; (void)ulAttribute; (void)pBuffer;
    return SEC_E_UNSUPPORTED_FUNCTION;
}

WINAPI_EXPORT int32_t ImpersonateSecurityContext(void *phContext)
{
    (void)phContext;
    return SEC_E_OK;
}

WINAPI_EXPORT int32_t RevertSecurityContext(void *phContext)
{
    (void)phContext;
    return SEC_E_OK;
}

WINAPI_EXPORT int32_t DecryptMessage(void *phContext, void *pMessage,
                                       uint32_t MessageSeqNo, uint32_t *pfQOP)
{
    (void)phContext; (void)pMessage; (void)MessageSeqNo; (void)pfQOP;
    return SEC_E_UNSUPPORTED_FUNCTION;
}

WINAPI_EXPORT int32_t EncryptMessage(void *phContext, uint32_t fQOP,
                                       void *pMessage, uint32_t MessageSeqNo)
{
    (void)phContext; (void)fQOP; (void)pMessage; (void)MessageSeqNo;
    return SEC_E_UNSUPPORTED_FUNCTION;
}

WINAPI_EXPORT int32_t MakeSignature(void *phContext, uint32_t fQOP,
                                      void *pMessage, uint32_t MessageSeqNo)
{
    (void)phContext; (void)fQOP; (void)pMessage; (void)MessageSeqNo;
    return SEC_E_UNSUPPORTED_FUNCTION;
}

WINAPI_EXPORT int32_t VerifySignature(void *phContext, void *pMessage,
                                        uint32_t MessageSeqNo, uint32_t *pfQOP)
{
    (void)phContext; (void)pMessage; (void)MessageSeqNo; (void)pfQOP;
    return SEC_E_UNSUPPORTED_FUNCTION;
}

/* ========== Security Interface Table ========== */

/*
 * SecurityFunctionTableA layout (Win32 SDK):
 *   DWORD                      dwVersion;
 *   ENUMERATE_SECURITY_PACKAGES_FN_A EnumerateSecurityPackagesA;
 *   QUERY_CREDENTIALS_ATTRIBUTES_FN_A QueryCredentialsAttributesA;
 *   ACQUIRE_CREDENTIALS_HANDLE_FN_A  AcquireCredentialsHandleA;
 *   FREE_CREDENTIALS_HANDLE_FN       FreeCredentialsHandle;
 *   ... (remaining slots NULL is acceptable)
 */
typedef struct {
    uint32_t dwVersion;
    void *EnumerateSecurityPackages;
    void *QueryCredentialsAttributes;
    void *AcquireCredentialsHandle;
    void *FreeCredentialsHandle;
    void *Reserved2;
    void *InitializeSecurityContext;
    void *AcceptSecurityContext;
    void *CompleteAuthToken;
    void *DeleteSecurityContext;
    void *ApplyControlToken;
    void *QueryContextAttributes;
    void *ImpersonateSecurityContext;
    void *RevertSecurityContext;
    void *MakeSignature;
    void *VerifySignature;
    void *FreeContextBuffer;
    void *QuerySecurityPackageInfo;
    void *Reserved3;
    void *Reserved4;
    void *EncryptMessage;
    void *DecryptMessage;
    void *SetContextAttributes;
    void *SetCredentialsAttributes;
} SecurityFunctionTableA_t;

static SecurityFunctionTableA_t g_sspi_table_a = {
    .dwVersion = 1,
    .EnumerateSecurityPackages = EnumerateSecurityPackagesA,
    .QueryCredentialsAttributes = NULL,
    .AcquireCredentialsHandle = AcquireCredentialsHandleA,
    .FreeCredentialsHandle = FreeCredentialsHandle,
    .Reserved2 = NULL,
    .InitializeSecurityContext = InitializeSecurityContextA,
    .AcceptSecurityContext = AcceptSecurityContext,
    .CompleteAuthToken = CompleteAuthToken,
    .DeleteSecurityContext = DeleteSecurityContext,
    .ApplyControlToken = NULL,
    .QueryContextAttributes = QueryContextAttributesA,
    .ImpersonateSecurityContext = ImpersonateSecurityContext,
    .RevertSecurityContext = RevertSecurityContext,
    .MakeSignature = MakeSignature,
    .VerifySignature = VerifySignature,
    .FreeContextBuffer = FreeContextBuffer,
    .QuerySecurityPackageInfo = QuerySecurityPackageInfoA,
    .Reserved3 = NULL,
    .Reserved4 = NULL,
    .EncryptMessage = EncryptMessage,
    .DecryptMessage = DecryptMessage,
    .SetContextAttributes = NULL,
    .SetCredentialsAttributes = NULL,
};

static SecurityFunctionTableA_t g_sspi_table_w = {
    .dwVersion = 1,
    .EnumerateSecurityPackages = EnumerateSecurityPackagesW,
    .QueryCredentialsAttributes = NULL,
    .AcquireCredentialsHandle = AcquireCredentialsHandleW,
    .FreeCredentialsHandle = FreeCredentialsHandle,
    .Reserved2 = NULL,
    .InitializeSecurityContext = InitializeSecurityContextW,
    .AcceptSecurityContext = AcceptSecurityContext,
    .CompleteAuthToken = CompleteAuthToken,
    .DeleteSecurityContext = DeleteSecurityContext,
    .ApplyControlToken = NULL,
    .QueryContextAttributes = QueryContextAttributesW,
    .ImpersonateSecurityContext = ImpersonateSecurityContext,
    .RevertSecurityContext = RevertSecurityContext,
    .MakeSignature = MakeSignature,
    .VerifySignature = VerifySignature,
    .FreeContextBuffer = FreeContextBuffer,
    .QuerySecurityPackageInfo = QuerySecurityPackageInfoW,
    .Reserved3 = NULL,
    .Reserved4 = NULL,
    .EncryptMessage = EncryptMessage,
    .DecryptMessage = DecryptMessage,
    .SetContextAttributes = NULL,
    .SetCredentialsAttributes = NULL,
};

WINAPI_EXPORT void *InitSecurityInterfaceA(void)
{
    return &g_sspi_table_a;
}

WINAPI_EXPORT void *InitSecurityInterfaceW(void)
{
    return &g_sspi_table_w;
}

/* ========== User Name ========== */

WINAPI_EXPORT BOOL GetUserNameExA(uint32_t NameFormat, char *lpNameBuffer, uint32_t *nSize)
{
    if (!nSize) return FALSE;

    struct passwd *pw = getpwuid(getuid());
    const char *username = pw ? pw->pw_name : "user";
    char buf[512];

    switch (NameFormat) {
    case NameSamCompatible:
        snprintf(buf, sizeof(buf), "LINUX\\%s", username);
        break;
    case NameDisplay:
    case NameFullyQualifiedDN:
        snprintf(buf, sizeof(buf), "%s", pw ? pw->pw_gecos : username);
        break;
    case NameUserPrincipal:
        snprintf(buf, sizeof(buf), "%s@localhost", username);
        break;
    default:
        snprintf(buf, sizeof(buf), "%s", username);
        break;
    }

    uint32_t len = (uint32_t)strlen(buf) + 1;
    if (!lpNameBuffer || *nSize < len) {
        *nSize = len;
        return FALSE;
    }
    strncpy(lpNameBuffer, buf, *nSize);
    lpNameBuffer[*nSize - 1] = '\0';
    *nSize = len - 1;
    return TRUE;
}

WINAPI_EXPORT BOOL GetUserNameExW(uint32_t NameFormat, uint16_t *lpNameBuffer, uint32_t *nSize)
{
    char buf[512];
    uint32_t buf_size = sizeof(buf);
    if (!GetUserNameExA(NameFormat, buf, &buf_size)) {
        if (nSize) *nSize = buf_size;
        return FALSE;
    }
    uint32_t len = (uint32_t)strlen(buf) + 1;
    if (!lpNameBuffer || !nSize || *nSize < len) {
        if (nSize) *nSize = len;
        return FALSE;
    }
    for (uint32_t i = 0; i < len; i++)
        lpNameBuffer[i] = (uint16_t)(uint8_t)buf[i];
    *nSize = len - 1;
    return TRUE;
}

/* ========== LSA Functions ========== */

WINAPI_EXPORT int32_t LsaConnectUntrusted(void **LsaHandle)
{
    if (LsaHandle) *LsaHandle = (void *)0xA0000001;
    return 0; /* STATUS_SUCCESS */
}

WINAPI_EXPORT int32_t LsaLookupAuthenticationPackage(void *LsaHandle,
                                                       void *PackageName,
                                                       uint32_t *AuthenticationPackage)
{
    (void)LsaHandle; (void)PackageName;
    if (AuthenticationPackage) *AuthenticationPackage = 0;
    return 0;
}

WINAPI_EXPORT int32_t LsaFreeReturnBuffer(void *Buffer)
{
    /* We never return heap-allocated buffers from the LSA stubs above
     * (LsaLookupAuthenticationPackage, LsaConnectUntrusted, etc. only
     * write scalar out-params or NULL). free() on a caller-provided
     * stack/static pointer would crash, so this must be a no-op.
     * If we ever start returning malloc'd LSA buffers, this needs to
     * check a magic-tagged header before freeing. */
    (void)Buffer;
    return 0;
}

WINAPI_EXPORT int32_t LsaDeregisterLogonProcess(void *LsaHandle)
{
    (void)LsaHandle;
    return 0;
}

WINAPI_EXPORT int32_t LsaRegisterLogonProcess(void *LogonProcessName,
                                                 void **LsaHandle,
                                                 void *SecurityMode)
{
    (void)LogonProcessName; (void)SecurityMode;
    if (LsaHandle) *LsaHandle = (void *)0xA0000002;
    return 0;
}

/* ========== SspiPrepareForCredRead/Write ========== */

WINAPI_EXPORT int32_t SspiPrepareForCredRead(void *AuthIdentity, const void *pszTargetName,
                                               uint32_t *pCredmanCredentialType, void **ppszCredmanTargetName)
{
    (void)AuthIdentity; (void)pszTargetName;
    if (pCredmanCredentialType) *pCredmanCredentialType = 1;
    if (ppszCredmanTargetName) *ppszCredmanTargetName = NULL;
    return SEC_E_OK;
}

WINAPI_EXPORT int32_t SspiPrepareForCredWrite(void *AuthIdentity, const void *pszTargetName,
                                                uint32_t *pCredmanCredentialType,
                                                void **ppszCredmanTargetName,
                                                void **ppCredmanUserName,
                                                void **ppCredmanCredentialBlob,
                                                uint32_t *pCredmanCredentialBlobSize)
{
    (void)AuthIdentity; (void)pszTargetName;
    if (pCredmanCredentialType) *pCredmanCredentialType = 1;
    if (ppszCredmanTargetName) *ppszCredmanTargetName = NULL;
    if (ppCredmanUserName) *ppCredmanUserName = NULL;
    if (ppCredmanCredentialBlob) *ppCredmanCredentialBlob = NULL;
    if (pCredmanCredentialBlobSize) *pCredmanCredentialBlobSize = 0;
    return SEC_E_OK;
}

WINAPI_EXPORT void SspiFreeAuthIdentity(void *AuthIdentity)
{
    free(AuthIdentity);
}
