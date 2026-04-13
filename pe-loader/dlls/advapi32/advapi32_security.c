/*
 * advapi32_security.c - Windows Security API stubs
 *
 * Token functions, SID functions, security descriptors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "common/dll_common.h"

/* Simplified SID structure */
typedef struct {
    BYTE Revision;
    BYTE SubAuthorityCount;
    BYTE IdentifierAuthority[6];
    DWORD SubAuthority[8];
} SID;

/* SID_IDENTIFIER_AUTHORITY */
typedef struct {
    BYTE Value[6];
} SID_IDENTIFIER_AUTHORITY;

typedef void *PSID;

/* Well-known SIDs */
static SID g_admin_sid = {
    1, 2, {0,0,0,0,0,5}, {32, 544, 0,0,0,0,0,0}
};
static SID g_user_sid = {
    1, 1, {0,0,0,0,0,5}, {1000, 0,0,0,0,0,0,0}
};
static SID g_everyone_sid = {
    1, 1, {0,0,0,0,0,1}, {0, 0,0,0,0,0,0,0}
};

/* TOKEN_INFORMATION_CLASS values */
#define TokenUser               1
#define TokenGroups             2
#define TokenPrivileges         3
#define TokenType               8
#define TokenElevationType      18
#define TokenElevation          20
#define TokenIntegrityLevel     25

/* ---------- Token Functions ---------- */

WINAPI_EXPORT BOOL OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess,
                                     HANDLE *TokenHandle)
{
    (void)ProcessHandle; (void)DesiredAccess;
    if (!TokenHandle) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    /* Return a pseudo-handle */
    *TokenHandle = handle_alloc(HANDLE_TYPE_FILE, -1, NULL);
    return TRUE;
}

WINAPI_EXPORT BOOL OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess,
                                    BOOL OpenAsSelf, HANDLE *TokenHandle)
{
    (void)ThreadHandle; (void)DesiredAccess; (void)OpenAsSelf;
    if (!TokenHandle) return FALSE;
    *TokenHandle = handle_alloc(HANDLE_TYPE_FILE, -1, NULL);
    return TRUE;
}

WINAPI_EXPORT BOOL GetTokenInformation(HANDLE TokenHandle, int TokenInformationClass,
                                        LPVOID TokenInformation, DWORD TokenInformationLength,
                                        DWORD *ReturnLength)
{
    (void)TokenHandle;

    switch (TokenInformationClass) {
    case TokenUser: {
        /* TOKEN_USER: SID and attributes */
        DWORD needed = sizeof(void *) + sizeof(DWORD) + sizeof(SID);
        if (ReturnLength) *ReturnLength = needed;
        if (TokenInformationLength < needed) {
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
        if (TokenInformation) {
            memset(TokenInformation, 0, needed);
            unsigned char *p = (unsigned char *)TokenInformation;
            /* TOKEN_USER.User.Sid points to SID at end of struct */
            SID *sid_ptr = (SID *)(p + sizeof(void *) + sizeof(DWORD));
            memcpy(sid_ptr, &g_user_sid, sizeof(SID));
            *(void **)p = sid_ptr;
        }
        return TRUE;
    }
    case TokenElevationType: {
        DWORD needed = sizeof(DWORD);
        if (ReturnLength) *ReturnLength = needed;
        if (TokenInformationLength < needed) {
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
        if (TokenInformation)
            *(DWORD *)TokenInformation = 2; /* TokenElevationTypeFull - we're root */
        return TRUE;
    }
    case TokenElevation: {
        DWORD needed = sizeof(DWORD);
        if (ReturnLength) *ReturnLength = needed;
        if (TokenInformationLength < needed) {
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
        if (TokenInformation)
            *(DWORD *)TokenInformation = (getuid() == 0) ? 1 : 0;
        return TRUE;
    }
    case TokenIntegrityLevel: {
        DWORD needed = sizeof(void *) + sizeof(DWORD) + sizeof(SID);
        if (ReturnLength) *ReturnLength = needed;
        if (TokenInformationLength < needed) {
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
        if (TokenInformation) {
            memset(TokenInformation, 0, needed);
            unsigned char *p = (unsigned char *)TokenInformation;
            SID *il_sid = (SID *)(p + sizeof(void *) + sizeof(DWORD));
            il_sid->Revision = 1;
            il_sid->SubAuthorityCount = 1;
            il_sid->IdentifierAuthority[5] = 16; /* SECURITY_MANDATORY_LABEL_AUTHORITY */
            il_sid->SubAuthority[0] = 0x3000; /* SECURITY_MANDATORY_HIGH_RID */
            *(void **)p = il_sid;
        }
        return TRUE;
    }
    default:
        if (ReturnLength) *ReturnLength = 0;
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
}

WINAPI_EXPORT BOOL AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges,
                                          void *NewState, DWORD BufferLength,
                                          void *PreviousState, DWORD *ReturnLength)
{
    (void)TokenHandle; (void)DisableAllPrivileges; (void)NewState;
    (void)BufferLength; (void)PreviousState; (void)ReturnLength;
    /* Pretend success - we have all privileges on Linux */
    return TRUE;
}

WINAPI_EXPORT BOOL LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, void *lpLuid)
{
    (void)lpSystemName;
    if (!lpName || !lpLuid) return FALSE;
    /* Return a fake LUID */
    memset(lpLuid, 0, sizeof(DWORD) * 2);
    *(DWORD *)lpLuid = 1;
    return TRUE;
}

WINAPI_EXPORT BOOL LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, void *lpLuid)
{
    (void)lpSystemName; (void)lpName;
    if (!lpLuid) return FALSE;
    memset(lpLuid, 0, sizeof(DWORD) * 2);
    *(DWORD *)lpLuid = 1;
    return TRUE;
}

/* ---------- SID Functions ---------- */

WINAPI_EXPORT BOOL AllocateAndInitializeSid(
    SID_IDENTIFIER_AUTHORITY *pIdentifierAuthority,
    BYTE nSubAuthorityCount,
    DWORD sa0, DWORD sa1, DWORD sa2, DWORD sa3,
    DWORD sa4, DWORD sa5, DWORD sa6, DWORD sa7,
    PSID *pSid)
{
    SID *sid = (SID *)calloc(1, sizeof(SID));
    if (!sid) return FALSE;
    sid->Revision = 1;
    sid->SubAuthorityCount = nSubAuthorityCount > 8 ? 8 : nSubAuthorityCount;
    if (pIdentifierAuthority)
        memcpy(sid->IdentifierAuthority, pIdentifierAuthority->Value, 6);
    DWORD subs[] = {sa0, sa1, sa2, sa3, sa4, sa5, sa6, sa7};
    for (int i = 0; i < sid->SubAuthorityCount; i++)
        sid->SubAuthority[i] = subs[i];
    *pSid = sid;
    return TRUE;
}

WINAPI_EXPORT void *FreeSid(PSID pSid)
{
    free(pSid);
    return NULL;
}

WINAPI_EXPORT BOOL CheckTokenMembership(HANDLE TokenHandle, PSID SidToCheck, BOOL *IsMember)
{
    (void)TokenHandle; (void)SidToCheck;
    if (IsMember) *IsMember = TRUE; /* Pretend user is member */
    return TRUE;
}

WINAPI_EXPORT BOOL IsValidSid(void *pSid)
{
    if (!pSid) return FALSE;
    SID *sid = (SID *)pSid;
    return sid->Revision == 1 && sid->SubAuthorityCount <= 8;
}

WINAPI_EXPORT DWORD GetLengthSid(void *pSid)
{
    if (!pSid) return 0;
    SID *sid = (SID *)pSid;
    return 8 + sid->SubAuthorityCount * 4;
}

WINAPI_EXPORT BOOL EqualSid(void *pSid1, void *pSid2)
{
    if (!pSid1 || !pSid2) return FALSE;
    DWORD len1 = GetLengthSid(pSid1);
    DWORD len2 = GetLengthSid(pSid2);
    if (len1 != len2) return FALSE;
    return memcmp(pSid1, pSid2, len1) == 0;
}

WINAPI_EXPORT BOOL CopySid(DWORD nDestinationSidLength, void *pDestinationSid, void *pSourceSid)
{
    if (!pDestinationSid || !pSourceSid) return FALSE;
    DWORD len = GetLengthSid(pSourceSid);
    if (nDestinationSidLength < len) return FALSE;
    memcpy(pDestinationSid, pSourceSid, len);
    return TRUE;
}

WINAPI_EXPORT BOOL ConvertSidToStringSidA(void *Sid, LPSTR *StringSid)
{
    if (!Sid || !StringSid) return FALSE;
    SID *sid = (SID *)Sid;

    char buf[256];
    uint64_t auth = 0;
    for (int i = 0; i < 6; i++)
        auth = (auth << 8) | sid->IdentifierAuthority[i];

    int pos = snprintf(buf, sizeof(buf), "S-%u-%lu", sid->Revision, (unsigned long)auth);
    for (int i = 0; i < sid->SubAuthorityCount; i++)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "-%u", sid->SubAuthority[i]);

    *StringSid = strdup(buf);
    return *StringSid != NULL;
}

WINAPI_EXPORT BOOL ConvertSidToStringSidW(void *Sid, LPWSTR *StringSid)
{
    char *narrow = NULL;
    if (!ConvertSidToStringSidA(Sid, &narrow)) return FALSE;

    size_t len = strlen(narrow);
    WCHAR *wide = calloc(len + 1, sizeof(WCHAR));
    if (!wide) { free(narrow); return FALSE; }
    for (size_t i = 0; i <= len; i++)
        wide[i] = (WCHAR)(unsigned char)narrow[i];

    free(narrow);
    *StringSid = wide;
    return TRUE;
}

WINAPI_EXPORT BOOL LookupAccountSidA(LPCSTR lpSystemName, void *Sid,
                                      LPSTR Name, DWORD *cchName,
                                      LPSTR ReferencedDomainName, DWORD *cchReferencedDomainName,
                                      int *peUse)
{
    (void)lpSystemName; (void)Sid;
    const char *user = "user";
    const char *domain = "ARCHLINUX";

    struct passwd *pw = getpwuid(getuid());
    if (pw) user = pw->pw_name;

    if (Name && cchName && *cchName > strlen(user)) {
        strncpy(Name, user, *cchName - 1);
        Name[*cchName - 1] = '\0';
    }
    if (cchName) *cchName = (DWORD)strlen(user);

    if (ReferencedDomainName && cchReferencedDomainName && *cchReferencedDomainName > strlen(domain)) {
        strncpy(ReferencedDomainName, domain, *cchReferencedDomainName - 1);
        ReferencedDomainName[*cchReferencedDomainName - 1] = '\0';
    }
    if (cchReferencedDomainName) *cchReferencedDomainName = (DWORD)strlen(domain);

    if (peUse) *peUse = 1; /* SidTypeUser */
    return TRUE;
}

/* ---------- GetUserName ---------- */

WINAPI_EXPORT BOOL GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer)
{
    if (!lpBuffer || !pcbBuffer) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    const char *user = "user";
    struct passwd *pw = getpwuid(getuid());
    if (pw) user = pw->pw_name;

    DWORD len = (DWORD)strlen(user) + 1;
    if (*pcbBuffer < len) {
        *pcbBuffer = len;
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    strncpy(lpBuffer, user, *pcbBuffer - 1);
    lpBuffer[*pcbBuffer - 1] = '\0';
    *pcbBuffer = len;
    return TRUE;
}

WINAPI_EXPORT BOOL GetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer)
{
    char narrow[256];
    DWORD size = sizeof(narrow);
    if (!GetUserNameA(narrow, &size)) return FALSE;

    DWORD len = (DWORD)strlen(narrow) + 1;
    if (!lpBuffer || !pcbBuffer || *pcbBuffer < len) {
        if (pcbBuffer) *pcbBuffer = len;
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    for (DWORD i = 0; i < len; i++)
        lpBuffer[i] = (WCHAR)(unsigned char)narrow[i];
    *pcbBuffer = len;
    return TRUE;
}

/* ---------- Security Descriptor Functions ---------- */

/* SECURITY_DESCRIPTOR is 20 bytes (relative) or 40 bytes (absolute, x64) */
typedef struct {
    BYTE Revision;
    BYTE Sbz1;
    WORD Control;
    void *Owner;
    void *Group;
    void *Sacl;
    void *Dacl;
} SECURITY_DESCRIPTOR;

WINAPI_EXPORT BOOL InitializeSecurityDescriptor(void *pSecurityDescriptor, DWORD dwRevision)
{
    if (!pSecurityDescriptor) return FALSE;
    SECURITY_DESCRIPTOR *sd = (SECURITY_DESCRIPTOR *)pSecurityDescriptor;
    memset(sd, 0, sizeof(SECURITY_DESCRIPTOR));
    sd->Revision = (BYTE)dwRevision;
    return TRUE;
}

WINAPI_EXPORT BOOL SetSecurityDescriptorDacl(void *pSecurityDescriptor,
                                              BOOL bDaclPresent, void *pDacl,
                                              BOOL bDaclDefaulted)
{
    if (!pSecurityDescriptor) return FALSE;
    SECURITY_DESCRIPTOR *sd = (SECURITY_DESCRIPTOR *)pSecurityDescriptor;
    if (bDaclPresent)
        sd->Control |= 0x0004; /* SE_DACL_PRESENT */
    if (bDaclDefaulted)
        sd->Control |= 0x0008; /* SE_DACL_DEFAULTED */
    sd->Dacl = pDacl;
    return TRUE;
}

WINAPI_EXPORT BOOL SetSecurityDescriptorOwner(void *pSecurityDescriptor,
                                               void *pOwner, BOOL bOwnerDefaulted)
{
    if (!pSecurityDescriptor) return FALSE;
    SECURITY_DESCRIPTOR *sd = (SECURITY_DESCRIPTOR *)pSecurityDescriptor;
    sd->Owner = pOwner;
    if (bOwnerDefaulted)
        sd->Control |= 0x0001; /* SE_OWNER_DEFAULTED */
    return TRUE;
}

WINAPI_EXPORT BOOL SetSecurityDescriptorGroup(void *pSecurityDescriptor,
                                               void *pGroup, BOOL bGroupDefaulted)
{
    if (!pSecurityDescriptor) return FALSE;
    SECURITY_DESCRIPTOR *sd = (SECURITY_DESCRIPTOR *)pSecurityDescriptor;
    sd->Group = pGroup;
    if (bGroupDefaulted)
        sd->Control |= 0x0002; /* SE_GROUP_DEFAULTED */
    return TRUE;
}

/* ---------- ACL Functions ---------- */

WINAPI_EXPORT BOOL InitializeAcl(void *pAcl, DWORD nAclLength, DWORD dwAclRevision)
{
    if (!pAcl || nAclLength < 8) return FALSE;
    memset(pAcl, 0, nAclLength);
    /* ACL header: Revision(1), Sbz1(1), AclSize(2), AceCount(2), Sbz2(2) */
    unsigned char *acl = (unsigned char *)pAcl;
    acl[0] = (BYTE)dwAclRevision;
    *(WORD *)(acl + 2) = (WORD)nAclLength;
    return TRUE;
}

/* ---------- ImpersonateLoggedOnUser / RevertToSelf ---------- */

WINAPI_EXPORT BOOL ImpersonateLoggedOnUser(HANDLE hToken)
{
    (void)hToken;
    return TRUE; /* Stub */
}

WINAPI_EXPORT BOOL RevertToSelf(void)
{
    return TRUE;
}

WINAPI_EXPORT BOOL DuplicateToken(HANDLE ExistingTokenHandle, int ImpersonationLevel,
                                   HANDLE *DuplicateTokenHandle)
{
    (void)ExistingTokenHandle; (void)ImpersonationLevel;
    if (DuplicateTokenHandle)
        *DuplicateTokenHandle = handle_alloc(HANDLE_TYPE_FILE, -1, NULL);
    return TRUE;
}

WINAPI_EXPORT BOOL DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess,
                                     void *lpTokenAttributes, int ImpersonationLevel,
                                     int tokenType, HANDLE *phNewToken)
{
    (void)hExistingToken; (void)dwDesiredAccess;
    (void)lpTokenAttributes; (void)ImpersonationLevel; (void)tokenType;
    if (phNewToken)
        *phNewToken = handle_alloc(HANDLE_TYPE_FILE, -1, NULL);
    return TRUE;
}

/* ---------- AllocateLocallyUniqueId ---------- */

static uint64_t g_next_luid = 1000;

WINAPI_EXPORT BOOL AllocateLocallyUniqueId(void *Luid)
{
    if (!Luid) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* LUID is a 64-bit value: LowPart (DWORD) + HighPart (LONG) */
    uint64_t val = __sync_fetch_and_add(&g_next_luid, 1);
    DWORD *parts = (DWORD *)Luid;
    parts[0] = (DWORD)(val & 0xFFFFFFFF);
    parts[1] = (DWORD)(val >> 32);
    return TRUE;
}

/* ---------- ETW (Event Tracing for Windows) stubs ---------- */
/* Many apps import these from advapi32.dll for telemetry/diagnostics. */

WINAPI_EXPORT ULONG EventRegister(
    const void *ProviderId, void *EnableCallback, void *CallbackContext,
    ULONGLONG *RegHandle)
{
    (void)ProviderId; (void)EnableCallback; (void)CallbackContext;
    if (RegHandle) *RegHandle = 0x1234;
    return 0; /* ERROR_SUCCESS */
}

WINAPI_EXPORT ULONG EventUnregister(ULONGLONG RegHandle)
{
    (void)RegHandle;
    return 0;
}

WINAPI_EXPORT ULONG EventSetInformation(
    ULONGLONG RegHandle, int InformationClass,
    void *EventInformation, ULONG InformationLength)
{
    (void)RegHandle; (void)InformationClass;
    (void)EventInformation; (void)InformationLength;
    return 0;
}

WINAPI_EXPORT ULONG EventWrite(ULONGLONG RegHandle, const void *EventDescriptor,
                                ULONG UserDataCount, void *UserData)
{
    (void)RegHandle; (void)EventDescriptor; (void)UserDataCount; (void)UserData;
    return 0;
}

WINAPI_EXPORT ULONG EventWriteTransfer(ULONGLONG RegHandle, const void *EventDescriptor,
                                        const void *ActivityId, const void *RelatedActivityId,
                                        ULONG UserDataCount, void *UserData)
{
    (void)RegHandle; (void)EventDescriptor; (void)ActivityId;
    (void)RelatedActivityId; (void)UserDataCount; (void)UserData;
    return 0;
}

WINAPI_EXPORT BOOL EventEnabled(ULONGLONG RegHandle, const void *EventDescriptor)
{
    (void)RegHandle; (void)EventDescriptor;
    return FALSE; /* Tracing disabled */
}

/* ---------- CreateWellKnownSid ---------- */

WINAPI_EXPORT BOOL CreateWellKnownSid(int WellKnownSidType, void *DomainSid,
                                       void *pSid, DWORD *cbSid)
{
    (void)DomainSid;
    DWORD needed = sizeof(SID);
    if (!pSid || !cbSid || *cbSid < needed) {
        if (cbSid) *cbSid = needed;
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    SID *sid = (SID *)pSid;
    switch (WellKnownSidType) {
    case 0: /* WinNullSid */
        *sid = (SID){1, 1, {0,0,0,0,0,0}, {0}};
        break;
    case 1: /* WinWorldSid (Everyone) */
        memcpy(sid, &g_everyone_sid, sizeof(SID));
        break;
    case 26: /* WinBuiltinAdministratorsSid */
        memcpy(sid, &g_admin_sid, sizeof(SID));
        break;
    default:
        memcpy(sid, &g_user_sid, sizeof(SID));
        break;
    }
    *cbSid = needed;
    return TRUE;
}
