/*
 * advapi32_crypto.c - Windows CryptoAPI stubs
 *
 * CryptAcquireContext, CryptGenRandom -> /dev/urandom
 * CryptCreateHash, CryptHashData, etc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "common/dll_common.h"

/* Provider types */
#define PROV_RSA_FULL       1
#define PROV_RSA_AES        24

/* Hash algorithms */
#define CALG_MD5        0x8003
#define CALG_SHA1       0x8004
#define CALG_SHA_256    0x800c
#define CALG_SHA_384    0x800d
#define CALG_SHA_512    0x800e

/* Hash context */
typedef struct {
    DWORD algorithm;
    unsigned char data[4096]; /* Accumulated data */
    size_t data_len;
    unsigned char hash[64];  /* Computed hash */
    DWORD hash_len;
    int finalized;
} hash_context_t;

static HANDLE g_crypt_prov = NULL;

WINAPI_EXPORT BOOL CryptAcquireContextA(HANDLE *phProv, LPCSTR szContainer,
                                         LPCSTR szProvider, DWORD dwProvType,
                                         DWORD dwFlags)
{
    (void)szContainer; (void)szProvider; (void)dwProvType; (void)dwFlags;
    if (!phProv) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!g_crypt_prov)
        g_crypt_prov = (HANDLE)(uintptr_t)0xCBEEF001;
    *phProv = g_crypt_prov;
    return TRUE;
}

WINAPI_EXPORT BOOL CryptAcquireContextW(HANDLE *phProv, LPCWSTR szContainer,
                                         LPCWSTR szProvider, DWORD dwProvType,
                                         DWORD dwFlags)
{
    (void)szContainer; (void)szProvider;
    return CryptAcquireContextA(phProv, NULL, NULL, dwProvType, dwFlags);
}

WINAPI_EXPORT BOOL CryptReleaseContext(HANDLE hProv, DWORD dwFlags)
{
    (void)hProv; (void)dwFlags;
    return TRUE;
}

WINAPI_EXPORT BOOL CryptGenRandom(HANDLE hProv, DWORD dwLen, BYTE *pbBuffer)
{
    (void)hProv;
    if (!pbBuffer) return FALSE;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        /* Fallback: use rand() */
        for (DWORD i = 0; i < dwLen; i++)
            pbBuffer[i] = (BYTE)(rand() & 0xFF);
        return TRUE;
    }

    size_t total = 0;
    while (total < dwLen) {
        ssize_t rd = read(fd, pbBuffer + total, dwLen - total);
        if (rd <= 0) break;
        total += rd;
    }
    close(fd);
    return total == dwLen;
}

/* ---------- Hash Functions ---------- */

WINAPI_EXPORT BOOL CryptCreateHash(HANDLE hProv, DWORD Algid, HANDLE hKey,
                                    DWORD dwFlags, HANDLE *phHash)
{
    (void)hProv; (void)hKey; (void)dwFlags;
    if (!phHash) return FALSE;

    hash_context_t *ctx = calloc(1, sizeof(hash_context_t));
    if (!ctx) return FALSE;
    ctx->algorithm = Algid;
    ctx->data_len = 0;
    ctx->finalized = 0;

    switch (Algid) {
    case CALG_MD5:     ctx->hash_len = 16; break;
    case CALG_SHA1:    ctx->hash_len = 20; break;
    case CALG_SHA_256: ctx->hash_len = 32; break;
    case CALG_SHA_384: ctx->hash_len = 48; break;
    case CALG_SHA_512: ctx->hash_len = 64; break;
    default:           ctx->hash_len = 20; break;
    }

    *phHash = handle_alloc(HANDLE_TYPE_FILE, -1, ctx);
    return TRUE;
}

WINAPI_EXPORT BOOL CryptHashData(HANDLE hHash, const BYTE *pbData,
                                  DWORD dwDataLen, DWORD dwFlags)
{
    (void)dwFlags;
    handle_entry_t *entry = handle_lookup(hHash);
    if (!entry || !entry->data) return FALSE;

    hash_context_t *ctx = (hash_context_t *)entry->data;
    if (ctx->finalized) return FALSE;

    if (ctx->data_len + dwDataLen > sizeof(ctx->data)) {
        fprintf(stderr, "[advapi32] CryptHashData: data exceeds 4096-byte buffer\n");
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    memcpy(ctx->data + ctx->data_len, pbData, dwDataLen);
    ctx->data_len += dwDataLen;
    return TRUE;
}

WINAPI_EXPORT BOOL CryptGetHashParam(HANDLE hHash, DWORD dwParam,
                                      BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags)
{
    (void)dwFlags;
    handle_entry_t *entry = handle_lookup(hHash);
    if (!entry || !entry->data) return FALSE;

    hash_context_t *ctx = (hash_context_t *)entry->data;

    if (dwParam == 2) { /* HP_HASHVAL */
        if (!ctx->finalized) {
            /* Simple hash: XOR-fold data to hash_len bytes */
            memset(ctx->hash, 0, ctx->hash_len);
            for (size_t i = 0; i < ctx->data_len; i++)
                ctx->hash[i % ctx->hash_len] ^= ctx->data[i];
            ctx->finalized = 1;
        }
        if (pbData && pdwDataLen && *pdwDataLen >= ctx->hash_len) {
            memcpy(pbData, ctx->hash, ctx->hash_len);
            *pdwDataLen = ctx->hash_len;
        } else if (pdwDataLen) {
            *pdwDataLen = ctx->hash_len;
        }
        return TRUE;
    }

    if (dwParam == 4) { /* HP_HASHSIZE */
        if (pdwDataLen) *pdwDataLen = sizeof(DWORD);
        if (pbData) *(DWORD *)pbData = ctx->hash_len;
        return TRUE;
    }

    return FALSE;
}

WINAPI_EXPORT BOOL CryptDestroyHash(HANDLE hHash)
{
    handle_entry_t *entry = handle_lookup(hHash);
    if (entry && entry->data) {
        free(entry->data);
        entry->data = NULL;
    }
    handle_close(hHash);
    return TRUE;
}

/* BCrypt functions removed -- they belong in bcrypt.dll (libpe_bcrypt.so),
 * not advapi32.dll. See dlls/bcrypt/bcrypt_crypto.c for the implementation. */
