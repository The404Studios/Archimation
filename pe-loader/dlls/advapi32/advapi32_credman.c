/*
 * advapi32_credman.c - Windows Credential Manager API stubs
 *
 * Implements Cred* functions (CredRead/CredWrite/CredDelete/CredEnumerate/
 * CredFree). Modern .NET apps and many installers call these to access
 * saved credentials. Without stubs, imports fail at load time.
 *
 * Strategy: return "not found" consistently. Reads/enumerations fail with
 * ERROR_NOT_FOUND; writes silently succeed (drop on floor). Apps fall back
 * to prompting the user or skipping the cached-credential path.
 *
 * We never return an allocated CREDENTIAL* from read/enumerate, so CredFree
 * is effectively a no-op (the caller should never have anything of ours to
 * free). Making it free() unconditionally would be wrong if the caller ever
 * passes a stack/static pointer defensively.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/dll_common.h"

/* Error codes (mirror Winerror.h values). */
#ifndef ERROR_INVALID_PARAMETER
#define ERROR_INVALID_PARAMETER   87
#endif
#ifndef ERROR_NOT_FOUND
#define ERROR_NOT_FOUND           1168
#endif
#ifndef ERROR_NOT_SUPPORTED
#define ERROR_NOT_SUPPORTED       50
#endif
#ifndef ERROR_CANCELLED
#define ERROR_CANCELLED           1223
#endif
#ifndef ERROR_INSUFFICIENT_BUFFER
#define ERROR_INSUFFICIENT_BUFFER 122
#endif

/* CRED_TYPE_* values. Valid range 1..7 (CRED_TYPE_MAXIMUM). */
#define CRED_TYPE_GENERIC                  1
#define CRED_TYPE_DOMAIN_PASSWORD          2
#define CRED_TYPE_DOMAIN_CERTIFICATE       3
#define CRED_TYPE_DOMAIN_VISIBLE_PASSWORD  4
#define CRED_TYPE_GENERIC_CERTIFICATE      5
#define CRED_TYPE_DOMAIN_EXTENDED          6
#define CRED_TYPE_MAXIMUM                  7

typedef struct _FILETIME_CREDMAN {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME_CREDMAN;

/* Windows x64 layout, ~88 bytes. */
typedef struct _CREDENTIAL_ATTRIBUTEA {
    LPSTR  Keyword;
    DWORD  Flags;
    DWORD  ValueSize;
    LPBYTE Value;
} CREDENTIAL_ATTRIBUTEA, *PCREDENTIAL_ATTRIBUTEA;

typedef struct _CREDENTIAL_ATTRIBUTEW {
    LPWSTR Keyword;
    DWORD  Flags;
    DWORD  ValueSize;
    LPBYTE Value;
} CREDENTIAL_ATTRIBUTEW, *PCREDENTIAL_ATTRIBUTEW;

typedef struct _CREDENTIALA {
    DWORD                  Flags;
    DWORD                  Type;
    LPSTR                  TargetName;
    LPSTR                  Comment;
    FILETIME_CREDMAN       LastWritten;
    DWORD                  CredentialBlobSize;
    LPBYTE                 CredentialBlob;
    DWORD                  Persist;
    DWORD                  AttributeCount;
    PCREDENTIAL_ATTRIBUTEA Attributes;
    LPSTR                  TargetAlias;
    LPSTR                  UserName;
} CREDENTIALA, *PCREDENTIALA;

typedef struct _CREDENTIALW {
    DWORD                  Flags;
    DWORD                  Type;
    LPWSTR                 TargetName;
    LPWSTR                 Comment;
    FILETIME_CREDMAN       LastWritten;
    DWORD                  CredentialBlobSize;
    LPBYTE                 CredentialBlob;
    DWORD                  Persist;
    DWORD                  AttributeCount;
    PCREDENTIAL_ATTRIBUTEW Attributes;
    LPWSTR                 TargetAlias;
    LPWSTR                 UserName;
} CREDENTIALW, *PCREDENTIALW;

/* Validate the Type field -- Windows rejects unknown values with
 * ERROR_INVALID_PARAMETER. Zero is also invalid. */
static int cred_type_valid(DWORD type)
{
    return type >= CRED_TYPE_GENERIC && type <= CRED_TYPE_MAXIMUM;
}

/* ---------- CredRead ---------- */

WINAPI_EXPORT BOOL CredReadA(LPCSTR TargetName, DWORD Type, DWORD Flags,
                             PCREDENTIALA *Credential)
{
    (void)Flags;
    if (!TargetName || !Credential) {
        set_last_error(ERROR_INVALID_PARAMETER);
        if (Credential) *Credential = NULL;
        return FALSE;
    }
    if (!cred_type_valid(Type)) {
        *Credential = NULL;
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *Credential = NULL;
    set_last_error(ERROR_NOT_FOUND);
    return FALSE;
}

WINAPI_EXPORT BOOL CredReadW(LPCWSTR TargetName, DWORD Type, DWORD Flags,
                             PCREDENTIALW *Credential)
{
    (void)Flags;
    if (!TargetName || !Credential) {
        set_last_error(ERROR_INVALID_PARAMETER);
        if (Credential) *Credential = NULL;
        return FALSE;
    }
    if (!cred_type_valid(Type)) {
        *Credential = NULL;
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *Credential = NULL;
    set_last_error(ERROR_NOT_FOUND);
    return FALSE;
}

/* ---------- CredWrite (silently drop) ---------- */

WINAPI_EXPORT BOOL CredWriteA(PCREDENTIALA Credential, DWORD Flags)
{
    (void)Flags;
    if (!Credential) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!cred_type_valid(Credential->Type)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!Credential->TargetName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    /* Silently drop. Apps don't care if the write "succeeded" --
     * they'll read it back later and get NOT_FOUND, at which point they
     * fall back to their prompt path. */
    return TRUE;
}

WINAPI_EXPORT BOOL CredWriteW(PCREDENTIALW Credential, DWORD Flags)
{
    (void)Flags;
    if (!Credential) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!cred_type_valid(Credential->Type)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!Credential->TargetName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return TRUE;
}

/* ---------- CredDelete ---------- */

WINAPI_EXPORT BOOL CredDeleteA(LPCSTR TargetName, DWORD Type, DWORD Flags)
{
    (void)Flags;
    if (!TargetName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!cred_type_valid(Type)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    set_last_error(ERROR_NOT_FOUND);
    return FALSE;
}

WINAPI_EXPORT BOOL CredDeleteW(LPCWSTR TargetName, DWORD Type, DWORD Flags)
{
    (void)Flags;
    if (!TargetName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!cred_type_valid(Type)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    set_last_error(ERROR_NOT_FOUND);
    return FALSE;
}

/* ---------- CredEnumerate ---------- */

WINAPI_EXPORT BOOL CredEnumerateA(LPCSTR Filter, DWORD Flags, DWORD *Count,
                                  PCREDENTIALA **Credential)
{
    (void)Filter; (void)Flags;
    if (!Count || !Credential) {
        set_last_error(ERROR_INVALID_PARAMETER);
        if (Count) *Count = 0;
        if (Credential) *Credential = NULL;
        return FALSE;
    }
    *Count = 0;
    *Credential = NULL;
    set_last_error(ERROR_NOT_FOUND);
    return FALSE;
}

WINAPI_EXPORT BOOL CredEnumerateW(LPCWSTR Filter, DWORD Flags, DWORD *Count,
                                  PCREDENTIALW **Credential)
{
    (void)Filter; (void)Flags;
    if (!Count || !Credential) {
        set_last_error(ERROR_INVALID_PARAMETER);
        if (Count) *Count = 0;
        if (Credential) *Credential = NULL;
        return FALSE;
    }
    *Count = 0;
    *Credential = NULL;
    set_last_error(ERROR_NOT_FOUND);
    return FALSE;
}

/* ---------- CredFree ---------- */

/* No-op: our CredRead/CredEnumerate never return non-NULL pointers, so
 * CredFree should never see one of our allocations. Calling free() on an
 * arbitrary pointer would corrupt the heap if Windows callers ever passed
 * a stack/static address defensively. */
WINAPI_EXPORT void CredFree(PVOID Buffer)
{
    (void)Buffer;
}

/* ---------- Optional marshalling stubs ---------- */

WINAPI_EXPORT BOOL CredIsMarshaledCredentialA(LPCSTR MarshaledCredential)
{
    (void)MarshaledCredential;
    return FALSE;
}

WINAPI_EXPORT BOOL CredIsMarshaledCredentialW(LPCWSTR MarshaledCredential)
{
    (void)MarshaledCredential;
    return FALSE;
}

WINAPI_EXPORT BOOL CredMarshalCredentialA(int CredType, PVOID Credential,
                                          LPSTR *MarshaledCredential)
{
    (void)CredType; (void)Credential;
    if (MarshaledCredential) *MarshaledCredential = NULL;
    set_last_error(ERROR_NOT_SUPPORTED);
    return FALSE;
}

WINAPI_EXPORT BOOL CredMarshalCredentialW(int CredType, PVOID Credential,
                                          LPWSTR *MarshaledCredential)
{
    (void)CredType; (void)Credential;
    if (MarshaledCredential) *MarshaledCredential = NULL;
    set_last_error(ERROR_NOT_SUPPORTED);
    return FALSE;
}

WINAPI_EXPORT BOOL CredUnmarshalCredentialA(LPCSTR MarshaledCredential,
                                            int *CredType, PVOID *Credential)
{
    (void)MarshaledCredential;
    if (CredType) *CredType = 0;
    if (Credential) *Credential = NULL;
    set_last_error(ERROR_NOT_SUPPORTED);
    return FALSE;
}

WINAPI_EXPORT BOOL CredUnmarshalCredentialW(LPCWSTR MarshaledCredential,
                                            int *CredType, PVOID *Credential)
{
    (void)MarshaledCredential;
    if (CredType) *CredType = 0;
    if (Credential) *Credential = NULL;
    set_last_error(ERROR_NOT_SUPPORTED);
    return FALSE;
}

/* ---------- CredGetSessionTypes ---------- */

WINAPI_EXPORT BOOL CredGetSessionTypes(DWORD MaximumPersistCount,
                                       LPDWORD MaximumPersist)
{
    /* Out buffer: one DWORD per CRED_TYPE slot. Zero the slots the caller
     * asked for so apps that dereference without checking don't read
     * garbage. CRED_PERSIST_NONE == 0, so an array of zeros is a valid
     * "nothing persists" answer -- but we still fail the call. */
    if (MaximumPersist && MaximumPersistCount) {
        for (DWORD i = 0; i < MaximumPersistCount; i++) MaximumPersist[i] = 0;
    }
    set_last_error(ERROR_NOT_SUPPORTED);
    return FALSE;
}

/* ---------- CredGetTargetInfo ---------- */

/* Opaque forward decls -- callers only need to store the pointer. */
typedef struct _CREDENTIAL_TARGET_INFORMATIONA CREDENTIAL_TARGET_INFORMATIONA;
typedef struct _CREDENTIAL_TARGET_INFORMATIONW CREDENTIAL_TARGET_INFORMATIONW;

WINAPI_EXPORT BOOL CredGetTargetInfoA(LPCSTR TargetName, DWORD Flags,
                                      CREDENTIAL_TARGET_INFORMATIONA **TargetInfo)
{
    (void)Flags;
    if (!TargetName || !TargetInfo) {
        set_last_error(ERROR_INVALID_PARAMETER);
        if (TargetInfo) *TargetInfo = NULL;
        return FALSE;
    }
    *TargetInfo = NULL;
    set_last_error(ERROR_NOT_FOUND);
    return FALSE;
}

WINAPI_EXPORT BOOL CredGetTargetInfoW(LPCWSTR TargetName, DWORD Flags,
                                      CREDENTIAL_TARGET_INFORMATIONW **TargetInfo)
{
    (void)Flags;
    if (!TargetName || !TargetInfo) {
        set_last_error(ERROR_INVALID_PARAMETER);
        if (TargetInfo) *TargetInfo = NULL;
        return FALSE;
    }
    *TargetInfo = NULL;
    set_last_error(ERROR_NOT_FOUND);
    return FALSE;
}

/* ---------- CredRename ---------- */

WINAPI_EXPORT BOOL CredRenameA(LPCSTR OldTargetName, LPCSTR NewTargetName,
                               DWORD Type, DWORD Flags)
{
    (void)Flags;
    if (!OldTargetName || !NewTargetName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!cred_type_valid(Type)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    set_last_error(ERROR_NOT_FOUND);
    return FALSE;
}

WINAPI_EXPORT BOOL CredRenameW(LPCWSTR OldTargetName, LPCWSTR NewTargetName,
                               DWORD Type, DWORD Flags)
{
    (void)Flags;
    if (!OldTargetName || !NewTargetName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!cred_type_valid(Type)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    set_last_error(ERROR_NOT_FOUND);
    return FALSE;
}

/* ---------- CredWriteDomainCredentials ---------- */

WINAPI_EXPORT BOOL CredWriteDomainCredentialsA(PVOID TargetInfo,
                                               PCREDENTIALA Credential,
                                               DWORD Flags)
{
    (void)Flags;
    if (!TargetInfo || !Credential) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!cred_type_valid(Credential->Type) || !Credential->TargetName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL CredWriteDomainCredentialsW(PVOID TargetInfo,
                                               PCREDENTIALW Credential,
                                               DWORD Flags)
{
    (void)Flags;
    if (!TargetInfo || !Credential) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!cred_type_valid(Credential->Type) || !Credential->TargetName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return TRUE;
}

/* ---------- CredReadDomainCredentials ---------- */

WINAPI_EXPORT BOOL CredReadDomainCredentialsA(PVOID TargetInfo, DWORD Flags,
                                              DWORD *Count,
                                              PCREDENTIALA **Credential)
{
    (void)TargetInfo; (void)Flags;
    if (!Count || !Credential) {
        set_last_error(ERROR_INVALID_PARAMETER);
        if (Count) *Count = 0;
        if (Credential) *Credential = NULL;
        return FALSE;
    }
    *Count = 0;
    *Credential = NULL;
    set_last_error(ERROR_NOT_FOUND);
    return FALSE;
}

WINAPI_EXPORT BOOL CredReadDomainCredentialsW(PVOID TargetInfo, DWORD Flags,
                                              DWORD *Count,
                                              PCREDENTIALW **Credential)
{
    (void)TargetInfo; (void)Flags;
    if (!Count || !Credential) {
        set_last_error(ERROR_INVALID_PARAMETER);
        if (Count) *Count = 0;
        if (Credential) *Credential = NULL;
        return FALSE;
    }
    *Count = 0;
    *Credential = NULL;
    set_last_error(ERROR_NOT_FOUND);
    return FALSE;
}

/* ---------- CredPackAuthenticationBuffer / CredUnPack ---------- */

/* Real Windows packs a cred-marshalled UserName + password into the
 * output buffer. We fail with ERROR_NOT_SUPPORTED rather than return a
 * fake buffer -- callers that need the real behavior will bail early;
 * callers that fall back to prompting the user will take that path. */

WINAPI_EXPORT BOOL CredPackAuthenticationBufferA(DWORD Flags, LPSTR UserName,
                                                 LPSTR Password,
                                                 LPBYTE PackedCredentials,
                                                 DWORD *PackedCredentialsSize)
{
    (void)Flags; (void)UserName; (void)Password; (void)PackedCredentials;
    if (PackedCredentialsSize) *PackedCredentialsSize = 0;
    set_last_error(ERROR_NOT_SUPPORTED);
    return FALSE;
}

WINAPI_EXPORT BOOL CredPackAuthenticationBufferW(DWORD Flags, LPWSTR UserName,
                                                 LPWSTR Password,
                                                 LPBYTE PackedCredentials,
                                                 DWORD *PackedCredentialsSize)
{
    (void)Flags; (void)UserName; (void)Password; (void)PackedCredentials;
    if (PackedCredentialsSize) *PackedCredentialsSize = 0;
    set_last_error(ERROR_NOT_SUPPORTED);
    return FALSE;
}

WINAPI_EXPORT BOOL CredUnPackAuthenticationBufferA(DWORD Flags,
                                                   PVOID AuthBuffer,
                                                   DWORD AuthBufferSize,
                                                   LPSTR UserName,
                                                   DWORD *MaxUserName,
                                                   LPSTR DomainName,
                                                   DWORD *MaxDomainName,
                                                   LPSTR Password,
                                                   DWORD *MaxPassword)
{
    (void)Flags; (void)AuthBuffer; (void)AuthBufferSize;
    (void)UserName; (void)DomainName; (void)Password;
    if (MaxUserName)   *MaxUserName   = 0;
    if (MaxDomainName) *MaxDomainName = 0;
    if (MaxPassword)   *MaxPassword   = 0;
    set_last_error(ERROR_NOT_SUPPORTED);
    return FALSE;
}

WINAPI_EXPORT BOOL CredUnPackAuthenticationBufferW(DWORD Flags,
                                                   PVOID AuthBuffer,
                                                   DWORD AuthBufferSize,
                                                   LPWSTR UserName,
                                                   DWORD *MaxUserName,
                                                   LPWSTR DomainName,
                                                   DWORD *MaxDomainName,
                                                   LPWSTR Password,
                                                   DWORD *MaxPassword)
{
    (void)Flags; (void)AuthBuffer; (void)AuthBufferSize;
    (void)UserName; (void)DomainName; (void)Password;
    if (MaxUserName)   *MaxUserName   = 0;
    if (MaxDomainName) *MaxDomainName = 0;
    if (MaxPassword)   *MaxPassword   = 0;
    set_last_error(ERROR_NOT_SUPPORTED);
    return FALSE;
}

/* ---------- CredUI* (usually in credui.dll but some apps link them
 * through advapi32). Return ERROR_CANCELLED so graceful-fallback paths
 * treat this as "user declined" rather than as a fatal error.) ---------- */

WINAPI_EXPORT DWORD CredUIPromptForCredentialsA(PVOID UiInfo, LPCSTR TargetName,
                                                PVOID Reserved, DWORD AuthError,
                                                LPSTR UserName, DWORD UserNameMax,
                                                LPSTR Password, DWORD PasswordMax,
                                                BOOL *Save, DWORD Flags)
{
    (void)UiInfo; (void)TargetName; (void)Reserved; (void)AuthError;
    (void)UserName; (void)UserNameMax; (void)Password; (void)PasswordMax;
    (void)Flags;
    if (Save) *Save = FALSE;
    return ERROR_CANCELLED;
}

WINAPI_EXPORT DWORD CredUIPromptForCredentialsW(PVOID UiInfo, LPCWSTR TargetName,
                                                PVOID Reserved, DWORD AuthError,
                                                LPWSTR UserName, DWORD UserNameMax,
                                                LPWSTR Password, DWORD PasswordMax,
                                                BOOL *Save, DWORD Flags)
{
    (void)UiInfo; (void)TargetName; (void)Reserved; (void)AuthError;
    (void)UserName; (void)UserNameMax; (void)Password; (void)PasswordMax;
    (void)Flags;
    if (Save) *Save = FALSE;
    return ERROR_CANCELLED;
}

WINAPI_EXPORT DWORD CredUIPromptForWindowsCredentialsA(PVOID UiInfo,
                                                       DWORD AuthError,
                                                       ULONG *AuthPackage,
                                                       LPCVOID InAuthBuffer,
                                                       ULONG InAuthBufferSize,
                                                       LPVOID *OutAuthBuffer,
                                                       ULONG *OutAuthBufferSize,
                                                       BOOL *Save, DWORD Flags)
{
    (void)UiInfo; (void)AuthError; (void)InAuthBuffer; (void)InAuthBufferSize;
    (void)Flags;
    if (AuthPackage)       *AuthPackage       = 0;
    if (OutAuthBuffer)     *OutAuthBuffer     = NULL;
    if (OutAuthBufferSize) *OutAuthBufferSize = 0;
    if (Save)              *Save              = FALSE;
    return ERROR_CANCELLED;
}

WINAPI_EXPORT DWORD CredUIPromptForWindowsCredentialsW(PVOID UiInfo,
                                                       DWORD AuthError,
                                                       ULONG *AuthPackage,
                                                       LPCVOID InAuthBuffer,
                                                       ULONG InAuthBufferSize,
                                                       LPVOID *OutAuthBuffer,
                                                       ULONG *OutAuthBufferSize,
                                                       BOOL *Save, DWORD Flags)
{
    (void)UiInfo; (void)AuthError; (void)InAuthBuffer; (void)InAuthBufferSize;
    (void)Flags;
    if (AuthPackage)       *AuthPackage       = 0;
    if (OutAuthBuffer)     *OutAuthBuffer     = NULL;
    if (OutAuthBufferSize) *OutAuthBufferSize = 0;
    if (Save)              *Save              = FALSE;
    return ERROR_CANCELLED;
}

WINAPI_EXPORT DWORD CredUICmdLinePromptForCredentialsA(LPCSTR TargetName,
                                                       PVOID Reserved,
                                                       DWORD AuthError,
                                                       LPSTR UserName,
                                                       ULONG UserNameMax,
                                                       LPSTR Password,
                                                       ULONG PasswordMax,
                                                       LPBOOL Save, DWORD Flags)
{
    (void)TargetName; (void)Reserved; (void)AuthError;
    (void)UserName; (void)UserNameMax; (void)Password; (void)PasswordMax;
    (void)Flags;
    if (Save) *Save = FALSE;
    return ERROR_CANCELLED;
}

WINAPI_EXPORT DWORD CredUICmdLinePromptForCredentialsW(LPCWSTR TargetName,
                                                       PVOID Reserved,
                                                       DWORD AuthError,
                                                       LPWSTR UserName,
                                                       ULONG UserNameMax,
                                                       LPWSTR Password,
                                                       ULONG PasswordMax,
                                                       LPBOOL Save, DWORD Flags)
{
    (void)TargetName; (void)Reserved; (void)AuthError;
    (void)UserName; (void)UserNameMax; (void)Password; (void)PasswordMax;
    (void)Flags;
    if (Save) *Save = FALSE;
    return ERROR_CANCELLED;
}

WINAPI_EXPORT DWORD CredUIConfirmCredentialsA(LPCSTR TargetName, BOOL Confirm)
{
    (void)TargetName; (void)Confirm;
    return ERROR_CANCELLED;
}

WINAPI_EXPORT DWORD CredUIConfirmCredentialsW(LPCWSTR TargetName, BOOL Confirm)
{
    (void)TargetName; (void)Confirm;
    return ERROR_CANCELLED;
}

WINAPI_EXPORT DWORD CredUIStoreSSOCredA(LPCSTR Realm, LPCSTR UserName,
                                        LPCSTR Password, BOOL Persist)
{
    (void)Realm; (void)UserName; (void)Password; (void)Persist;
    return ERROR_NOT_SUPPORTED;
}

WINAPI_EXPORT DWORD CredUIStoreSSOCredW(LPCWSTR Realm, LPCWSTR UserName,
                                        LPCWSTR Password, BOOL Persist)
{
    (void)Realm; (void)UserName; (void)Password; (void)Persist;
    return ERROR_NOT_SUPPORTED;
}

WINAPI_EXPORT DWORD CredUIReadSSOCredA(LPCSTR Realm, LPSTR *UserName)
{
    (void)Realm;
    if (UserName) *UserName = NULL;
    return ERROR_NOT_FOUND;
}

WINAPI_EXPORT DWORD CredUIReadSSOCredW(LPCWSTR Realm, LPWSTR *UserName)
{
    (void)Realm;
    if (UserName) *UserName = NULL;
    return ERROR_NOT_FOUND;
}

WINAPI_EXPORT DWORD CredUIParseUserNameA(LPCSTR UserName, LPSTR User,
                                         ULONG UserMax, LPSTR Domain,
                                         ULONG DomainMax)
{
    (void)UserMax; (void)DomainMax;
    if (!UserName || !User || !Domain) return ERROR_INVALID_PARAMETER;
    /* Minimal parse: put whole string into User, empty Domain.
     * Some installers assert on success here; giving them back the
     * original username is the least-surprising answer. */
    if (UserMax > 0) {
        ULONG i = 0;
        while (UserName[i] && i < UserMax - 1) { User[i] = UserName[i]; i++; }
        User[i] = '\0';
    }
    if (DomainMax > 0) Domain[0] = '\0';
    return 0; /* NO_ERROR */
}

WINAPI_EXPORT DWORD CredUIParseUserNameW(LPCWSTR UserName, LPWSTR User,
                                         ULONG UserMax, LPWSTR Domain,
                                         ULONG DomainMax)
{
    if (!UserName || !User || !Domain) return ERROR_INVALID_PARAMETER;
    const uint16_t *src = (const uint16_t *)UserName;
    uint16_t *dst_user = (uint16_t *)User;
    uint16_t *dst_dom  = (uint16_t *)Domain;
    if (UserMax > 0) {
        ULONG i = 0;
        while (src[i] && i < UserMax - 1) { dst_user[i] = src[i]; i++; }
        dst_user[i] = 0;
    }
    if (DomainMax > 0) dst_dom[0] = 0;
    return 0;
}
