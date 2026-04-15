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
#include <pthread.h>

#include "common/dll_common.h"

/* Cached username (NSS lookups via getpwuid are expensive when called per
 * security API invocation -- some apps call LookupAccountSid thousands of
 * times). Populated on first use, immutable thereafter for the process
 * lifetime. */
static char g_cached_username[64] = {0};
static pthread_once_t g_username_once = PTHREAD_ONCE_INIT;

static void init_cached_username(void)
{
    const char *user = "user";
    struct passwd *pw = getpwuid(getuid());
    if (pw && pw->pw_name && pw->pw_name[0])
        user = pw->pw_name;
    strncpy(g_cached_username, user, sizeof(g_cached_username) - 1);
    g_cached_username[sizeof(g_cached_username) - 1] = '\0';
}

static const char *cached_username(void)
{
    pthread_once(&g_username_once, init_cached_username);
    return g_cached_username;
}

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
    HANDLE h = handle_alloc(HANDLE_TYPE_FILE, -1, NULL);
    if (!h || h == (HANDLE)-1) {
        *TokenHandle = NULL;
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    *TokenHandle = h;
    return TRUE;
}

WINAPI_EXPORT BOOL OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess,
                                    BOOL OpenAsSelf, HANDLE *TokenHandle)
{
    (void)ThreadHandle; (void)DesiredAccess; (void)OpenAsSelf;
    if (!TokenHandle) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    HANDLE h = handle_alloc(HANDLE_TYPE_FILE, -1, NULL);
    if (!h || h == (HANDLE)-1) {
        *TokenHandle = NULL;
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    *TokenHandle = h;
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

/* Well-known privilege name -> LUID table. Real Windows uses LUIDs 2..35.
 * Callers roundtrip via LookupPrivilegeValue then AdjustTokenPrivileges, and
 * later use the same LUID to compare against what they stored -- so each
 * distinct name must map to a distinct LUID, and the same name must always
 * map to the same LUID. */
static DWORD luid_for_privilege_name(const char *name)
{
    static const struct { const char *name; DWORD luid; } privs[] = {
        {"SeCreateTokenPrivilege", 2},
        {"SeAssignPrimaryTokenPrivilege", 3},
        {"SeLockMemoryPrivilege", 4},
        {"SeIncreaseQuotaPrivilege", 5},
        {"SeMachineAccountPrivilege", 6},
        {"SeTcbPrivilege", 7},
        {"SeSecurityPrivilege", 8},
        {"SeTakeOwnershipPrivilege", 9},
        {"SeLoadDriverPrivilege", 10},
        {"SeSystemProfilePrivilege", 11},
        {"SeSystemtimePrivilege", 12},
        {"SeProfileSingleProcessPrivilege", 13},
        {"SeIncreaseBasePriorityPrivilege", 14},
        {"SeCreatePagefilePrivilege", 15},
        {"SeCreatePermanentPrivilege", 16},
        {"SeBackupPrivilege", 17},
        {"SeRestorePrivilege", 18},
        {"SeShutdownPrivilege", 19},
        {"SeDebugPrivilege", 20},
        {"SeAuditPrivilege", 21},
        {"SeSystemEnvironmentPrivilege", 22},
        {"SeChangeNotifyPrivilege", 23},
        {"SeRemoteShutdownPrivilege", 24},
        {"SeUndockPrivilege", 25},
        {"SeSyncAgentPrivilege", 26},
        {"SeEnableDelegationPrivilege", 27},
        {"SeManageVolumePrivilege", 28},
        {"SeImpersonatePrivilege", 29},
        {"SeCreateGlobalPrivilege", 30},
        {"SeTrustedCredManAccessPrivilege", 31},
        {"SeRelabelPrivilege", 32},
        {"SeIncreaseWorkingSetPrivilege", 33},
        {"SeTimeZonePrivilege", 34},
        {"SeCreateSymbolicLinkPrivilege", 35},
    };
    for (size_t i = 0; i < sizeof(privs)/sizeof(privs[0]); i++) {
        if (strcmp(privs[i].name, name) == 0)
            return privs[i].luid;
    }
    /* Unknown name -- return a stable hash-derived LUID so repeated lookups
     * match, but none collide with the well-known set. */
    DWORD h = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        h ^= *p;
        h *= 16777619u;
    }
    if (h < 100) h += 100; /* keep out of well-known range */
    return h;
}

WINAPI_EXPORT BOOL LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, void *lpLuid)
{
    (void)lpSystemName;
    if (!lpName || !lpLuid) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    DWORD *parts = (DWORD *)lpLuid;
    parts[0] = luid_for_privilege_name(lpName);
    parts[1] = 0;
    return TRUE;
}

WINAPI_EXPORT BOOL LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, void *lpLuid)
{
    (void)lpSystemName;
    if (!lpName || !lpLuid) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    /* Narrow the name for the lookup table (privilege names are ASCII). */
    char narrow[128];
    size_t i;
    for (i = 0; lpName[i] && i < sizeof(narrow) - 1; i++)
        narrow[i] = (char)(lpName[i] & 0xFF);
    narrow[i] = '\0';
    DWORD *parts = (DWORD *)lpLuid;
    parts[0] = luid_for_privilege_name(narrow);
    parts[1] = 0;
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
    if (!pSid) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    SID *sid = (SID *)calloc(1, sizeof(SID));
    if (!sid) { *pSid = NULL; return FALSE; }
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

    int pos = snprintf(buf, sizeof(buf), "S-%u-%llu",
                       (unsigned int)sid->Revision, (unsigned long long)auth);
    if (pos < 0) pos = 0;
    if ((size_t)pos >= sizeof(buf)) pos = (int)sizeof(buf) - 1;
    for (int i = 0; i < sid->SubAuthorityCount; i++) {
        if ((size_t)pos + 1 >= sizeof(buf)) break;
        int w = snprintf(buf + pos, sizeof(buf) - pos, "-%u",
                         (unsigned int)sid->SubAuthority[i]);
        if (w < 0) break;
        if ((size_t)(pos + w) >= sizeof(buf)) { pos = (int)sizeof(buf) - 1; break; }
        pos += w;
    }

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
    (void)lpSystemName;
    if (!Sid) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Map well-known SIDs to their canonical names. Previously this ignored
     * the input SID entirely and always returned the current user -- code
     * that probes the Admin/Everyone SIDs would mis-identify them. */
    const char *user = cached_username();
    const char *name;
    const char *domain;
    int use;
    SID *sid_in = (SID *)Sid;

    if (sid_in->Revision == 1 &&
        sid_in->IdentifierAuthority[5] == 1 &&
        sid_in->SubAuthorityCount == 1 &&
        sid_in->SubAuthority[0] == 0) {
        name = "Everyone";
        domain = "";
        use = 5; /* SidTypeWellKnownGroup */
    } else if (sid_in->Revision == 1 &&
               sid_in->IdentifierAuthority[5] == 5 &&
               sid_in->SubAuthorityCount == 2 &&
               sid_in->SubAuthority[0] == 32 &&
               sid_in->SubAuthority[1] == 544) {
        name = "Administrators";
        domain = "BUILTIN";
        use = 4; /* SidTypeAlias */
    } else if (sid_in->Revision == 1 &&
               sid_in->IdentifierAuthority[5] == 16) {
        name = "Mandatory Label";
        domain = "";
        use = 10; /* SidTypeLabel */
    } else {
        name = user;
        domain = "ARCHLINUX";
        use = 1; /* SidTypeUser */
    }

    DWORD name_len = (DWORD)strlen(name);
    DWORD domain_len = (DWORD)strlen(domain);

    /* Windows-documented buffer-too-small semantic: set *cchName to required
     * size INCLUDING terminator, set last error, return FALSE. */
    BOOL name_fits = (Name && cchName && *cchName > name_len);
    BOOL domain_fits = (ReferencedDomainName && cchReferencedDomainName &&
                        *cchReferencedDomainName > domain_len);

    if ((cchName && !name_fits) || (cchReferencedDomainName && !domain_fits)) {
        if (cchName) *cchName = name_len + 1;
        if (cchReferencedDomainName) *cchReferencedDomainName = domain_len + 1;
        if (peUse) *peUse = use;
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    if (name_fits) {
        memcpy(Name, name, name_len);
        Name[name_len] = '\0';
    }
    if (cchName) *cchName = name_len;

    if (domain_fits) {
        memcpy(ReferencedDomainName, domain, domain_len);
        ReferencedDomainName[domain_len] = '\0';
    }
    if (cchReferencedDomainName) *cchReferencedDomainName = domain_len;

    if (peUse) *peUse = use;
    return TRUE;
}

/* ---------- GetUserName ---------- */

WINAPI_EXPORT BOOL GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer)
{
    if (!lpBuffer || !pcbBuffer) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    const char *user = cached_username();

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
    if (!cbSid) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Build the SID in a temp, then report its actual length. Prior code
     * always reported sizeof(SID)==40, confusing callers that call
     * GetLengthSid() on the returned SID and get a smaller value. */
    SID tmp;
    memset(&tmp, 0, sizeof(tmp));
    switch (WellKnownSidType) {
    case 0: /* WinNullSid: S-1-0-0 */
        tmp.Revision = 1;
        tmp.SubAuthorityCount = 1;
        tmp.IdentifierAuthority[5] = 0;
        tmp.SubAuthority[0] = 0;
        break;
    case 1: /* WinWorldSid (Everyone): S-1-1-0 */
        tmp = g_everyone_sid;
        break;
    case 26: /* WinBuiltinAdministratorsSid: S-1-5-32-544 */
        tmp = g_admin_sid;
        break;
    case 27: /* WinBuiltinUsersSid: S-1-5-32-545 */
        tmp.Revision = 1;
        tmp.SubAuthorityCount = 2;
        tmp.IdentifierAuthority[5] = 5;
        tmp.SubAuthority[0] = 32;
        tmp.SubAuthority[1] = 545;
        break;
    default:
        tmp = g_user_sid;
        break;
    }

    DWORD needed = 8 + tmp.SubAuthorityCount * 4;
    if (!pSid || *cbSid < needed) {
        *cbSid = needed;
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    memcpy(pSid, &tmp, needed);
    *cbSid = needed;
    return TRUE;
}
