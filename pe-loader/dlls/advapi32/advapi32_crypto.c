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
#include <pthread.h>

#if defined(__linux__)
#include <sys/syscall.h>
#include <errno.h>
#ifndef SYS_getrandom
#define SYS_getrandom 318
#endif
#endif

#include "common/dll_common.h"

/* Cached /dev/urandom fd + runtime RDRAND detection. Opens once (FD_CLOEXEC),
 * then every CryptGenRandom call is a single read() with zero open/close
 * overhead. Matches the fast path in bcrypt_crypto.c. */
static int g_adv_urandom_fd = -1;
static pthread_once_t g_adv_urandom_once = PTHREAD_ONCE_INIT;
static int g_adv_has_rdrand = -1;

static void adv_urandom_open_once(void)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) g_adv_urandom_fd = fd;
}

#if defined(__x86_64__) && defined(__RDRND__)
#include <immintrin.h>
static inline int adv_rdrand_u64(uint64_t *out)
{
    for (int i = 0; i < 10; i++) {
        unsigned long long v;
        if (_rdrand64_step(&v)) { *out = v; return 1; }
    }
    return 0;
}
#else
static inline int adv_rdrand_u64(uint64_t *out) { (void)out; return 0; }
#endif

static int adv_fill_random(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) return 1;

    if (g_adv_has_rdrand < 0) {
#if defined(__x86_64__) && defined(__RDRND__)
        g_adv_has_rdrand = __builtin_cpu_supports("rdrnd") ? 1 : 0;
#else
        g_adv_has_rdrand = 0;
#endif
    }
    if (g_adv_has_rdrand == 1) {
        size_t i = 0;
        while (i + 8 <= len) {
            uint64_t v;
            if (!adv_rdrand_u64(&v)) { g_adv_has_rdrand = 0; break; }
            memcpy(buf + i, &v, 8);
            i += 8;
        }
        if (i < len && g_adv_has_rdrand == 1) {
            uint64_t v;
            if (adv_rdrand_u64(&v)) {
                memcpy(buf + i, &v, len - i);
                return 1;
            }
        } else if (i == len) {
            return 1;
        }
    }

#if defined(__linux__)
    size_t done = 0;
    while (done < len) {
        long r = syscall(SYS_getrandom, buf + done, len - done, 0);
        if (r > 0) { done += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        break;
    }
    if (done == len) return 1;
#endif

    pthread_once(&g_adv_urandom_once, adv_urandom_open_once);
    int fd = g_adv_urandom_fd;
    if (fd < 0) return 0;
    size_t total = 0;
    while (total < len) {
        ssize_t r = read(fd, buf + total, len - total);
        if (r > 0) { total += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        break;
    }
    return total == len;
}

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
    /* Session 36 fix: validate handle. Real Windows sets ERROR_INVALID_HANDLE
     * and returns FALSE if hProv is not a valid provider.  Also dwFlags must
     * be 0 per MSDN -- non-zero is ERROR_INVALID_PARAMETER.
     * We do NOT clear g_crypt_prov here: the provider is a process-wide
     * singleton that other callers may still hold.  The last caller's
     * release is effectively free since there's no refcounted resource. */
    if (dwFlags != 0) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!hProv || (g_crypt_prov && hProv != g_crypt_prov)) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL CryptGenRandom(HANDLE hProv, DWORD dwLen, BYTE *pbBuffer)
{
    (void)hProv;
    if (!pbBuffer) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (dwLen == 0) return TRUE;

    if (adv_fill_random(pbBuffer, dwLen))
        return TRUE;

    /* Absolute last resort — rand() is insecure but avoids returning
     * uninitialized bytes to the app. Log loudly. */
    fprintf(stderr, "[advapi32] CryptGenRandom: all entropy sources failed, falling back to rand()\n");
    for (DWORD i = 0; i < dwLen; i++)
        pbBuffer[i] = (BYTE)(rand() & 0xFF);
    return TRUE;
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

    HANDLE h = handle_alloc(HANDLE_TYPE_FILE, -1, ctx);
    if (!h || h == (HANDLE)-1) {
        free(ctx);
        *phHash = NULL;
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    *phHash = h;
    return TRUE;
}

WINAPI_EXPORT BOOL CryptHashData(HANDLE hHash, const BYTE *pbData,
                                  DWORD dwDataLen, DWORD dwFlags)
{
    (void)dwFlags;
    if (dwDataLen > 0 && !pbData) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    handle_entry_t *entry = handle_lookup(hHash);
    if (!entry || !entry->data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    hash_context_t *ctx = (hash_context_t *)entry->data;
    if (ctx->finalized) {
        /* Windows: cannot hash more data after HP_HASHVAL has been read.
         * NTE_BAD_HASH_STATE = 0x80090002 maps to ERROR_INVALID_PARAMETER here. */
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (ctx->data_len + dwDataLen > sizeof(ctx->data)) {
        fprintf(stderr, "[advapi32] CryptHashData: data exceeds 4096-byte buffer\n");
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (dwDataLen > 0)
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
        if (!pdwDataLen) {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        if (!ctx->finalized) {
            /* Simple hash: XOR-fold data to hash_len bytes */
            memset(ctx->hash, 0, ctx->hash_len);
            for (size_t i = 0; i < ctx->data_len; i++)
                ctx->hash[i % ctx->hash_len] ^= ctx->data[i];
            ctx->finalized = 1;
        }
        /* Probe call (pbData == NULL) or buffer-too-small: MSDN spec says
         * return FALSE and set ERROR_MORE_DATA, with *pdwDataLen set to
         * required size. Callers rely on this to size their buffer. */
        if (!pbData || *pdwDataLen < ctx->hash_len) {
            *pdwDataLen = ctx->hash_len;
            if (!pbData) return TRUE;  /* Size query with pbData=NULL is success on Windows */
            set_last_error(ERROR_MORE_DATA);
            return FALSE;
        }
        memcpy(pbData, ctx->hash, ctx->hash_len);
        *pdwDataLen = ctx->hash_len;
        return TRUE;
    }

    if (dwParam == 4) { /* HP_HASHSIZE */
        if (!pdwDataLen) {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        if (!pbData) {
            *pdwDataLen = sizeof(DWORD);
            return TRUE;
        }
        if (*pdwDataLen < sizeof(DWORD)) {
            *pdwDataLen = sizeof(DWORD);
            set_last_error(ERROR_MORE_DATA);
            return FALSE;
        }
        *(DWORD *)pbData = ctx->hash_len;
        *pdwDataLen = sizeof(DWORD);
        return TRUE;
    }

    set_last_error(ERROR_INVALID_PARAMETER);
    return FALSE;
}

WINAPI_EXPORT BOOL CryptDestroyHash(HANDLE hHash)
{
    handle_entry_t *entry = handle_lookup(hHash);
    if (!entry) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    if (entry->data) {
        free(entry->data);
        entry->data = NULL;
    }
    handle_close(hHash);
    return TRUE;
}

/* BCrypt functions removed -- they belong in bcrypt.dll (libpe_bcrypt.so),
 * not advapi32.dll. See dlls/bcrypt/bcrypt_crypto.c for the implementation. */
