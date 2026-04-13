/*
 * crypt32_cert.c - crypt32.dll stubs (Certificate and crypto store)
 *
 * CertOpenStore, CertCloseStore, CertFindCertificateInStore,
 * CertGetCertificateChain, CertFreeCertificateChain,
 * CertFreeCertificateContext, CertGetNameStringA,
 * CryptAcquireContextA, CryptReleaseContext, CryptGenRandom,
 * CryptStringToBinaryA, CryptBinaryToStringA, PFXImportCertStore.
 *
 * Anti-cheat and many applications check certificates and use
 * cryptographic services.  We provide minimal stubs that report
 * "no certificates found" and supply /dev/urandom-backed randomness.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "common/dll_common.h"

/*
 * Fake handle value for certificate stores and crypto providers.
 * We use a recognizable sentinel that is not NULL and not
 * INVALID_HANDLE_VALUE.
 */
#define FAKE_CERT_STORE     ((HANDLE)(uintptr_t)0xCE570001)

/* ------------------------------------------------------------------ */
/*  Certificate store operations                                       */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT HANDLE CertOpenStore(
    LPCSTR      lpszStoreProvider,
    DWORD       dwEncodingType,
    HANDLE      hCryptProv,
    DWORD       dwFlags,
    const void *pvPara)
{
    (void)lpszStoreProvider;
    (void)dwEncodingType;
    (void)hCryptProv;
    (void)dwFlags;
    (void)pvPara;

    fprintf(stderr, "[crypt32] CertOpenStore(...)\n");

    /* Return a fake, non-NULL handle so callers proceed normally */
    return FAKE_CERT_STORE;
}

WINAPI_EXPORT BOOL CertCloseStore(HANDLE hCertStore, DWORD dwFlags)
{
    (void)hCertStore;
    (void)dwFlags;

    fprintf(stderr, "[crypt32] CertCloseStore(...)\n");

    return TRUE;
}

WINAPI_EXPORT void *CertFindCertificateInStore(
    HANDLE      hCertStore,
    DWORD       dwCertEncodingType,
    DWORD       dwFindFlags,
    DWORD       dwFindType,
    const void *pvFindPara,
    void       *pPrevCertContext)
{
    (void)hCertStore;
    (void)dwCertEncodingType;
    (void)dwFindFlags;
    (void)dwFindType;
    (void)pvFindPara;
    (void)pPrevCertContext;

    fprintf(stderr, "[crypt32] CertFindCertificateInStore(...)\n");

    /* No certificates in our store */
    return NULL;
}

WINAPI_EXPORT BOOL CertGetCertificateChain(
    HANDLE      hChainEngine,
    void       *pCertContext,
    void       *pTime,
    HANDLE      hAdditionalStore,
    void       *pChainPara,
    DWORD       dwFlags,
    void       *pvReserved,
    void      **ppChainContext)
{
    (void)hChainEngine;
    (void)pCertContext;
    (void)pTime;
    (void)hAdditionalStore;
    (void)pChainPara;
    (void)dwFlags;
    (void)pvReserved;

    fprintf(stderr, "[crypt32] CertGetCertificateChain(...)\n");

    if (ppChainContext)
        *ppChainContext = NULL;

    return FALSE;
}

WINAPI_EXPORT void CertFreeCertificateChain(void *pChainContext)
{
    (void)pChainContext;

    fprintf(stderr, "[crypt32] CertFreeCertificateChain(...)\n");
}

WINAPI_EXPORT BOOL CertFreeCertificateContext(void *pCertContext)
{
    (void)pCertContext;

    fprintf(stderr, "[crypt32] CertFreeCertificateContext(...)\n");

    return TRUE;
}

WINAPI_EXPORT DWORD CertGetNameStringA(
    void   *pCertContext,
    DWORD   dwType,
    DWORD   dwFlags,
    void   *pvTypePara,
    LPSTR   pszNameString,
    DWORD   cchNameString)
{
    (void)pCertContext;
    (void)dwType;
    (void)dwFlags;
    (void)pvTypePara;

    fprintf(stderr, "[crypt32] CertGetNameStringA(...)\n");

    /* Write an empty string if the caller provided a buffer */
    if (pszNameString && cchNameString > 0)
        pszNameString[0] = '\0';

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Cryptographic provider operations - forwarded to canonical advapi32 */
/*                                                                      */
/*  Many executables import these from crypt32.dll even though the      */
/*  canonical implementations live in advapi32.dll (advapi32_crypto.c). */
/*  We forward at runtime via dlsym.                                    */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT BOOL WINAPI CryptAcquireContextA(HANDLE *phProv, LPCSTR szContainer,
                                                LPCSTR szProvider, DWORD dwProvType,
                                                DWORD dwFlags)
{
    typedef BOOL (WINAPI *fn_t)(HANDLE*, LPCSTR, LPCSTR, DWORD, DWORD);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        void *h = dlopen("libpe_advapi32.so", RTLD_LAZY);
        if (h) real_fn = (fn_t)dlsym(h, "CryptAcquireContextA");
    }
    if (real_fn) return real_fn(phProv, szContainer, szProvider, dwProvType, dwFlags);
    if (phProv) *phProv = (HANDLE)(uintptr_t)0xCEF00001;
    return TRUE;
}

WINAPI_EXPORT BOOL WINAPI CryptReleaseContext(HANDLE hProv, DWORD dwFlags)
{
    typedef BOOL (WINAPI *fn_t)(HANDLE, DWORD);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        void *h = dlopen("libpe_advapi32.so", RTLD_LAZY);
        if (h) real_fn = (fn_t)dlsym(h, "CryptReleaseContext");
    }
    return real_fn ? real_fn(hProv, dwFlags) : TRUE;
}

WINAPI_EXPORT BOOL WINAPI CryptGenRandom(HANDLE hProv, DWORD dwLen, BYTE *pbBuffer)
{
    typedef BOOL (WINAPI *fn_t)(HANDLE, DWORD, BYTE*);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        void *h = dlopen("libpe_advapi32.so", RTLD_LAZY);
        if (h) real_fn = (fn_t)dlsym(h, "CryptGenRandom");
    }
    return real_fn ? real_fn(hProv, dwLen, pbBuffer) : FALSE;
}

/* ------------------------------------------------------------------ */
/*  String / binary encoding stubs                                     */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT BOOL CryptStringToBinaryA(
    LPCSTR  pszString,
    DWORD   cchString,
    DWORD   dwFlags,
    BYTE   *pbBinary,
    DWORD  *pcbBinary,
    DWORD  *pdwSkip,
    DWORD  *pdwFlags)
{
    (void)pszString;
    (void)cchString;
    (void)dwFlags;
    (void)pbBinary;
    (void)pcbBinary;
    (void)pdwSkip;
    (void)pdwFlags;

    fprintf(stderr, "[crypt32] CryptStringToBinaryA(...)\n");

    return FALSE;
}

WINAPI_EXPORT BOOL CryptBinaryToStringA(
    const BYTE *pbBinary,
    DWORD       cbBinary,
    DWORD       dwFlags,
    LPSTR       pszString,
    DWORD      *pcchString)
{
    (void)pbBinary;
    (void)cbBinary;
    (void)dwFlags;
    (void)pszString;
    (void)pcchString;

    fprintf(stderr, "[crypt32] CryptBinaryToStringA(...)\n");

    return FALSE;
}

/* ------------------------------------------------------------------ */
/*  DPAPI - Data Protection API                                        */
/*                                                                      */
/*  CryptProtectData / CryptUnprotectData are used by game launchers,  */
/*  credential managers, and many apps for local secret storage.        */
/*  We implement a transparent pass-through: "encrypted" data is just  */
/*  the plaintext prefixed with a small header.  This lets callers      */
/*  round-trip successfully without real crypto (acceptable for a       */
/*  PE compat layer where there is no Windows DPAPI key store).        */
/* ------------------------------------------------------------------ */

/* DATA_BLOB structure (wincrypt.h) */
typedef struct _CRYPTOAPI_BLOB {
    DWORD cbData;
    BYTE *pbData;
} DATA_BLOB;

/* CRYPTPROTECT_PROMPTSTRUCT - we ignore it */
typedef void CRYPTPROTECT_PROMPTSTRUCT;

#define DPAPI_MAGIC_V1  0x50414450  /* 'PDAP' */

typedef struct {
    uint32_t magic;
    uint32_t plain_len;
} dpapi_header_t;

WINAPI_EXPORT BOOL CryptProtectData(
    DATA_BLOB                    *pDataIn,
    LPCWSTR                       szDataDescr,
    DATA_BLOB                    *pOptionalEntropy,
    void                         *pvReserved,
    CRYPTPROTECT_PROMPTSTRUCT    *pPromptStruct,
    DWORD                         dwFlags,
    DATA_BLOB                    *pDataOut)
{
    (void)szDataDescr; (void)pOptionalEntropy; (void)pvReserved;
    (void)pPromptStruct; (void)dwFlags;

    if (!pDataIn || !pDataOut) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    fprintf(stderr, "[crypt32] CryptProtectData(%u bytes)\n", pDataIn->cbData);

    /* Output = header + plaintext */
    size_t out_len = sizeof(dpapi_header_t) + pDataIn->cbData;
    BYTE *out = (BYTE *)malloc(out_len);
    if (!out) {
        set_last_error(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    dpapi_header_t *hdr = (dpapi_header_t *)out;
    hdr->magic = DPAPI_MAGIC_V1;
    hdr->plain_len = pDataIn->cbData;
    if (pDataIn->cbData > 0)
        memcpy(out + sizeof(dpapi_header_t), pDataIn->pbData, pDataIn->cbData);

    pDataOut->cbData = (DWORD)out_len;
    pDataOut->pbData = out;
    return TRUE;
}

WINAPI_EXPORT BOOL CryptUnprotectData(
    DATA_BLOB                    *pDataIn,
    LPWSTR                       *ppszDataDescr,
    DATA_BLOB                    *pOptionalEntropy,
    void                         *pvReserved,
    CRYPTPROTECT_PROMPTSTRUCT    *pPromptStruct,
    DWORD                         dwFlags,
    DATA_BLOB                    *pDataOut)
{
    (void)pOptionalEntropy; (void)pvReserved;
    (void)pPromptStruct; (void)dwFlags;

    if (!pDataIn || !pDataOut) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    fprintf(stderr, "[crypt32] CryptUnprotectData(%u bytes)\n", pDataIn->cbData);

    if (ppszDataDescr)
        *ppszDataDescr = NULL;

    /* Verify our header */
    if (pDataIn->cbData < sizeof(dpapi_header_t)) {
        set_last_error(ERROR_INVALID_DATA);
        return FALSE;
    }

    dpapi_header_t *hdr = (dpapi_header_t *)pDataIn->pbData;
    if (hdr->magic != DPAPI_MAGIC_V1 ||
        hdr->plain_len > pDataIn->cbData - sizeof(dpapi_header_t)) {
        set_last_error(ERROR_INVALID_DATA);
        return FALSE;
    }

    BYTE *out = (BYTE *)malloc(hdr->plain_len > 0 ? hdr->plain_len : 1);
    if (!out) {
        set_last_error(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    if (hdr->plain_len > 0)
        memcpy(out, pDataIn->pbData + sizeof(dpapi_header_t), hdr->plain_len);

    pDataOut->cbData = hdr->plain_len;
    pDataOut->pbData = out;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  PFX import                                                         */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT HANDLE PFXImportCertStore(
    void    *pPFX,
    LPCWSTR  szPassword,
    DWORD    dwFlags)
{
    (void)pPFX;
    (void)szPassword;
    (void)dwFlags;

    fprintf(stderr, "[crypt32] PFXImportCertStore(...)\n");

    return NULL;
}
