/*
 * bcrypt_crypto.c - BCrypt (bcrypt.dll) cryptographic stubs
 *
 * Provides BCryptOpenAlgorithmProvider, BCryptGenRandom (backed by /dev/urandom),
 * and hash/encrypt stubs.
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
#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#endif
#endif

#include "common/dll_common.h"

/*
 * Fast RNG path:
 *  1. __builtin_cpu_supports("rdrnd") at runtime → use RDRAND (new HW: AES-NI + RDRAND)
 *  2. Linux getrandom(2) syscall (kernel 3.17+), avoids fd open/close
 *  3. Cached /dev/urandom fd fallback (FD_CLOEXEC, opened once, never closed)
 *
 * Old HW (Pentium 4, no RDRAND) goes path #2/#3. New HW (Ivy Bridge+) path #1
 * eliminates a syscall entirely for small random requests.
 */
static int g_urandom_fd = -1;
static pthread_once_t g_urandom_once = PTHREAD_ONCE_INIT;
static int g_has_rdrand = -1;   /* -1 = unprobed; 0 = no; 1 = yes */

static void urandom_open_once(void)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) g_urandom_fd = fd;
}

#if defined(__x86_64__) && defined(__RDRND__)
/* Compiled-in RDRAND intrinsic; only used after runtime CPU check. */
#include <immintrin.h>
static inline int rdrand_u64(uint64_t *out)
{
    for (int i = 0; i < 10; i++) {
        unsigned long long v;
        if (_rdrand64_step(&v)) { *out = v; return 1; }
    }
    return 0;
}
#else
static inline int rdrand_u64(uint64_t *out) { (void)out; return 0; }
#endif

static int fill_random(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) return 1;

    /* Runtime CPU probe (dual-HW rule: always scalar fallback for old HW).
     * Only honour RDRAND when BOTH the CPU advertises it AND we were
     * compiled with -mrdrnd so the intrinsic is available; otherwise stay
     * on getrandom/urandom. */
    if (g_has_rdrand < 0) {
#if defined(__x86_64__) && defined(__RDRND__)
        g_has_rdrand = __builtin_cpu_supports("rdrnd") ? 1 : 0;
#else
        g_has_rdrand = 0;
#endif
    }
    if (g_has_rdrand == 1) {
        size_t i = 0;
        while (i + 8 <= len) {
            uint64_t v;
            if (!rdrand_u64(&v)) { g_has_rdrand = 0; break; }
            memcpy(buf + i, &v, 8);
            i += 8;
        }
        if (i < len && g_has_rdrand == 1) {
            uint64_t v;
            if (rdrand_u64(&v)) {
                memcpy(buf + i, &v, len - i);
                return 1;
            }
        } else if (i == len) {
            return 1;
        }
        /* fall through on RDRAND failure */
    }

#if defined(__linux__)
    /* getrandom(2): zero-fd, single syscall */
    size_t done = 0;
    while (done < len) {
        long r = syscall(SYS_getrandom, buf + done, len - done, 0);
        if (r > 0) { done += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        break; /* ENOSYS on kernel <3.17 — fall through */
    }
    if (done == len) return 1;
#endif

    /* Cached /dev/urandom fd path */
    pthread_once(&g_urandom_once, urandom_open_once);
    int fd = g_urandom_fd;
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

/* NTSTATUS codes (supplement those in winnt.h) */
#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED     ((NTSTATUS)0xC00000BB)
#endif
#ifndef STATUS_NO_MEMORY
#define STATUS_NO_MEMORY         ((NTSTATUS)0xC0000017)
#endif
#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND         ((NTSTATUS)0xC0000225)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL  ((NTSTATUS)0xC0000023)
#endif

/* Algorithm IDs (wide strings - use simple matching) */
#define ALG_SHA1     1
#define ALG_SHA256   2
#define ALG_SHA384   3
#define ALG_SHA512   4
#define ALG_MD5      5
#define ALG_AES      10
#define ALG_RSA      20
#define ALG_RNG      30

typedef struct {
    uint32_t magic;       /* 'BCAL' */
    uint32_t alg_id;
    uint32_t hash_length;
    uint32_t block_length;
} bcrypt_alg_t;

typedef struct {
    uint32_t magic;       /* 'BCHA' */
    bcrypt_alg_t *alg;
    uint8_t *hash_data;
    size_t hash_data_len;
} bcrypt_hash_t;

#define BCRYPT_ALG_MAGIC  0x4C414342  /* 'BCAL' */
#define BCRYPT_HASH_MAGIC 0x41484342  /* 'BCHA' */

/* Simple wide string comparison (UTF-16LE vs ASCII) */
static int wcmp(const uint16_t *ws, const char *s)
{
    while (*s) {
        if (*ws != (uint16_t)*s) return 1;
        ws++; s++;
    }
    return *ws != 0;
}

static uint32_t identify_alg(const void *pszAlgId)
{
    if (!pszAlgId) return 0;
    const uint16_t *w = (const uint16_t *)pszAlgId;
    if (wcmp(w, "SHA1") == 0)   return ALG_SHA1;
    if (wcmp(w, "SHA256") == 0) return ALG_SHA256;
    if (wcmp(w, "SHA384") == 0) return ALG_SHA384;
    if (wcmp(w, "SHA512") == 0) return ALG_SHA512;
    if (wcmp(w, "MD5") == 0)    return ALG_MD5;
    if (wcmp(w, "AES") == 0)    return ALG_AES;
    if (wcmp(w, "RSA") == 0)    return ALG_RSA;
    if (wcmp(w, "RNG") == 0)    return ALG_RNG;
    /* Accept unknown algorithms */
    return 99;
}

static uint32_t get_hash_length(uint32_t alg)
{
    switch (alg) {
    case ALG_MD5:    return 16;
    case ALG_SHA1:   return 20;
    case ALG_SHA256: return 32;
    case ALG_SHA384: return 48;
    case ALG_SHA512: return 64;
    default:         return 32;
    }
}

WINAPI_EXPORT int32_t BCryptOpenAlgorithmProvider(void **phAlgorithm,
                                                    const void *pszAlgId,
                                                    const void *pszImplementation,
                                                    uint32_t dwFlags)
{
    (void)pszImplementation; (void)dwFlags;
    if (!phAlgorithm) return STATUS_INVALID_PARAMETER;

    uint32_t alg = identify_alg(pszAlgId);
    bcrypt_alg_t *a = calloc(1, sizeof(bcrypt_alg_t));
    if (!a) return STATUS_NO_MEMORY;

    a->magic = BCRYPT_ALG_MAGIC;
    a->alg_id = alg;
    a->hash_length = get_hash_length(alg);
    a->block_length = 64;

    *phAlgorithm = a;
    return STATUS_SUCCESS;
}

WINAPI_EXPORT int32_t BCryptCloseAlgorithmProvider(void *hAlgorithm, uint32_t dwFlags)
{
    (void)dwFlags;
    if (!hAlgorithm) return STATUS_INVALID_HANDLE;
    bcrypt_alg_t *a = (bcrypt_alg_t *)hAlgorithm;
    if (a->magic != BCRYPT_ALG_MAGIC) return STATUS_INVALID_HANDLE;
    a->magic = 0;
    free(a);
    return STATUS_SUCCESS;
}

WINAPI_EXPORT int32_t BCryptGenRandom(void *hAlgorithm, uint8_t *pbBuffer,
                                       uint32_t cbBuffer, uint32_t dwFlags)
{
    (void)hAlgorithm; (void)dwFlags;
    if (!pbBuffer || cbBuffer == 0) return STATUS_INVALID_PARAMETER;

    if (!fill_random(pbBuffer, cbBuffer)) {
        fprintf(stderr, "[bcrypt] CRITICAL: entropy source unavailable\n");
        return STATUS_NOT_SUPPORTED;
    }
    return STATUS_SUCCESS;
}

WINAPI_EXPORT int32_t BCryptCreateHash(void *hAlgorithm, void **phHash,
                                         uint8_t *pbHashObject, uint32_t cbHashObject,
                                         const uint8_t *pbSecret, uint32_t cbSecret,
                                         uint32_t dwFlags)
{
    (void)pbHashObject; (void)cbHashObject; (void)pbSecret; (void)cbSecret; (void)dwFlags;
    if (!hAlgorithm || !phHash) return STATUS_INVALID_PARAMETER;

    bcrypt_alg_t *a = (bcrypt_alg_t *)hAlgorithm;
    if (a->magic != BCRYPT_ALG_MAGIC) return STATUS_INVALID_HANDLE;
    bcrypt_hash_t *h = calloc(1, sizeof(bcrypt_hash_t));
    if (!h) return STATUS_NO_MEMORY;

    h->magic = BCRYPT_HASH_MAGIC;
    h->alg = a;
    h->hash_data = NULL;
    h->hash_data_len = 0;

    *phHash = h;
    return STATUS_SUCCESS;
}

WINAPI_EXPORT int32_t BCryptHashData(void *hHash, const uint8_t *pbInput,
                                      uint32_t cbInput, uint32_t dwFlags)
{
    (void)dwFlags;
    if (!hHash) return STATUS_INVALID_HANDLE;
    bcrypt_hash_t *h = (bcrypt_hash_t *)hHash;
    if (h->magic != BCRYPT_HASH_MAGIC) return STATUS_INVALID_HANDLE;

    /* Accumulate data (simplified - real impl would use actual hash algo) */
    if (cbInput == 0) return STATUS_SUCCESS;
    if (!pbInput) return STATUS_INVALID_PARAMETER;
    uint8_t *new_data = realloc(h->hash_data, h->hash_data_len + cbInput);
    if (!new_data) return STATUS_NO_MEMORY;
    memcpy(new_data + h->hash_data_len, pbInput, cbInput);
    h->hash_data = new_data;
    h->hash_data_len += cbInput;
    return STATUS_SUCCESS;
}

WINAPI_EXPORT int32_t BCryptFinishHash(void *hHash, uint8_t *pbOutput,
                                        uint32_t cbOutput, uint32_t dwFlags)
{
    (void)dwFlags;
    if (!hHash || !pbOutput) return STATUS_INVALID_PARAMETER;
    bcrypt_hash_t *h = (bcrypt_hash_t *)hHash;
    if (h->magic != BCRYPT_HASH_MAGIC) return STATUS_INVALID_HANDLE;

    /*
     * Simplified: XOR-fold accumulated data into output.
     * Real impl would use SHA/MD5 from OpenSSL/libgcrypt.
     */
    if (cbOutput == 0) return STATUS_INVALID_PARAMETER;
    memset(pbOutput, 0, cbOutput);
    for (size_t i = 0; i < h->hash_data_len; i++)
        pbOutput[i % cbOutput] ^= h->hash_data[i];

    return STATUS_SUCCESS;
}

WINAPI_EXPORT int32_t BCryptDestroyHash(void *hHash)
{
    if (!hHash) return STATUS_INVALID_HANDLE;
    bcrypt_hash_t *h = (bcrypt_hash_t *)hHash;
    if (h->magic != BCRYPT_HASH_MAGIC) return STATUS_INVALID_HANDLE;
    h->magic = 0;
    free(h->hash_data);
    free(h);
    return STATUS_SUCCESS;
}

WINAPI_EXPORT int32_t BCryptDuplicateHash(void *hHash, void **phNewHash,
                                            uint8_t *pbHashObject, uint32_t cbHashObject,
                                            uint32_t dwFlags)
{
    (void)pbHashObject; (void)cbHashObject; (void)dwFlags;
    if (!hHash || !phNewHash) return STATUS_INVALID_PARAMETER;
    bcrypt_hash_t *src = (bcrypt_hash_t *)hHash;
    if (src->magic != BCRYPT_HASH_MAGIC) return STATUS_INVALID_HANDLE;
    bcrypt_hash_t *dst = calloc(1, sizeof(bcrypt_hash_t));
    if (!dst) return STATUS_NO_MEMORY;
    dst->magic = BCRYPT_HASH_MAGIC;
    dst->alg = src->alg;
    if (src->hash_data_len > 0) {
        dst->hash_data = malloc(src->hash_data_len);
        if (!dst->hash_data) { free(dst); return STATUS_NO_MEMORY; }
        memcpy(dst->hash_data, src->hash_data, src->hash_data_len);
        dst->hash_data_len = src->hash_data_len;
    }
    *phNewHash = dst;
    return STATUS_SUCCESS;
}

WINAPI_EXPORT int32_t BCryptGetProperty(void *hObject, const void *pszProperty,
                                          uint8_t *pbOutput, uint32_t cbOutput,
                                          uint32_t *pcbResult, uint32_t dwFlags)
{
    (void)dwFlags;
    if (!hObject || !pszProperty) return STATUS_INVALID_PARAMETER;

    /* Check if it's an algorithm handle */
    bcrypt_alg_t *a = (bcrypt_alg_t *)hObject;
    if (a->magic == BCRYPT_ALG_MAGIC) {
        const uint16_t *prop = (const uint16_t *)pszProperty;
        /* "HashDigestLength" */
        if (wcmp(prop, "HashDigestLength") == 0) {
            if (pcbResult) *pcbResult = 4;
            if (pbOutput && cbOutput >= 4)
                memcpy(pbOutput, &a->hash_length, 4);
            return STATUS_SUCCESS;
        }
        /* "ObjectLength" - hash object size */
        if (wcmp(prop, "ObjectLength") == 0) {
            uint32_t obj_len = 512;
            if (pcbResult) *pcbResult = 4;
            if (pbOutput && cbOutput >= 4)
                memcpy(pbOutput, &obj_len, 4);
            return STATUS_SUCCESS;
        }
    }

    if (pcbResult) *pcbResult = 0;
    return STATUS_NOT_FOUND;
}

WINAPI_EXPORT int32_t BCryptSetProperty(void *hObject, const void *pszProperty,
                                          const uint8_t *pbInput, uint32_t cbInput,
                                          uint32_t dwFlags)
{
    (void)hObject; (void)pszProperty; (void)pbInput; (void)cbInput; (void)dwFlags;
    return STATUS_SUCCESS;
}

WINAPI_EXPORT int32_t BCryptEncrypt(void *hKey, const uint8_t *pbInput, uint32_t cbInput,
                                      void *pPaddingInfo, uint8_t *pbIV, uint32_t cbIV,
                                      uint8_t *pbOutput, uint32_t cbOutput,
                                      uint32_t *pcbResult, uint32_t dwFlags)
{
    (void)hKey; (void)pbInput; (void)cbInput; (void)pPaddingInfo;
    (void)pbIV; (void)cbIV; (void)pbOutput; (void)cbOutput; (void)dwFlags;
    if (pcbResult) *pcbResult = 0;
    return STATUS_NOT_SUPPORTED;
}

WINAPI_EXPORT int32_t BCryptDecrypt(void *hKey, const uint8_t *pbInput, uint32_t cbInput,
                                      void *pPaddingInfo, uint8_t *pbIV, uint32_t cbIV,
                                      uint8_t *pbOutput, uint32_t cbOutput,
                                      uint32_t *pcbResult, uint32_t dwFlags)
{
    (void)hKey; (void)pbInput; (void)cbInput; (void)pPaddingInfo;
    (void)pbIV; (void)cbIV; (void)pbOutput; (void)cbOutput; (void)dwFlags;
    if (pcbResult) *pcbResult = 0;
    return STATUS_NOT_SUPPORTED;
}

WINAPI_EXPORT int32_t BCryptGenerateSymmetricKey(void *hAlgorithm, void **phKey,
                                                   uint8_t *pbKeyObject, uint32_t cbKeyObject,
                                                   const uint8_t *pbSecret, uint32_t cbSecret,
                                                   uint32_t dwFlags)
{
    (void)hAlgorithm; (void)pbKeyObject; (void)cbKeyObject;
    (void)pbSecret; (void)cbSecret; (void)dwFlags;
    if (phKey) *phKey = (void *)(uintptr_t)0xBC010001;
    return STATUS_SUCCESS;
}

WINAPI_EXPORT int32_t BCryptDestroyKey(void *hKey)
{
    (void)hKey;
    return STATUS_SUCCESS;
}

WINAPI_EXPORT int32_t BCryptHash(void *hAlgorithm, uint8_t *pbSecret, uint32_t cbSecret,
                                   uint8_t *pbInput, uint32_t cbInput,
                                   uint8_t *pbOutput, uint32_t cbOutput)
{
    /* One-shot hash */
    void *hHash = NULL;
    int32_t status = BCryptCreateHash(hAlgorithm, &hHash, NULL, 0, pbSecret, cbSecret, 0);
    if (status != STATUS_SUCCESS) return status;
    status = BCryptHashData(hHash, pbInput, cbInput, 0);
    if (status == STATUS_SUCCESS)
        status = BCryptFinishHash(hHash, pbOutput, cbOutput, 0);
    BCryptDestroyHash(hHash);
    return status;
}

WINAPI_EXPORT int32_t BCryptGetFipsAlgorithmMode(uint8_t *pfEnabled)
{
    if (pfEnabled) *pfEnabled = 0; /* FIPS not enabled */
    return STATUS_SUCCESS;
}
