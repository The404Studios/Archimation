/*
 * pe_patch_cache.c - Compressed on-disk patch plan cache
 *
 * Location: ~/.cache/pe-loader/patches/<sha256>.ptc
 *
 * Wire format (all little-endian):
 *
 *   Header (16 bytes, NEVER compressed):
 *     u32  magic         = 'P','T','C','1' (0x31435450 LE)
 *     u32  version       = PE_PATCH_CACHE_VERSION
 *     u32  flags         = PE_PATCH_FLAG_ZSTD | PE_PATCH_FLAG_VARINT | ...
 *     u32  entry_count   = number of patches in the plan
 *
 *   Body (zstd-compressed when flags&ZSTD):
 *     If flags&VARINT:
 *       For each entry: varint(iat_rva_delta) varint(replacement_idx)
 *                       varint(entry_flags)
 *       iat_rva_delta is the difference from the previous entry's RVA
 *       (first entry uses 0 as the predecessor).  Deltas are small and
 *       non-negative when entries are sorted by RVA, which we enforce
 *       on save.
 *     Else (raw):
 *       For each entry: u64 iat_rva, u32 replacement_idx, u32 flags
 *                       (16 bytes total)
 *
 * Atomic save: write to <sha256>.ptc.tmp and rename().  A partial tmp
 * file is never observable as a valid cache entry because the final
 * rename is atomic on all supported filesystems.
 *
 * Corruption policy: any parse error -> return -1.  pe_patch.c treats
 * that as a cache miss and regenerates the plan.  We never crash or
 * assert on a bad cache file.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>

#include <zstd.h>

#include "pe_patch.h"
#include "pe/pe_patch_abi.h"

#define LOG_PREFIX "[pe_patch_cache] "

/* Absolute maximum raw body size we will accept from disk.  Guards
 * against bogus entry_count values in the header.  PE_PATCH_MAX_ENTRIES
 * * 16 bytes (the raw, non-varint path) is the theoretical worst case. */
#define MAX_RAW_BODY (PE_PATCH_MAX_ENTRIES * 16u)

/* Hard cap on the compressed body size we will mmap/read.  1 MiB is
 * wildly more than any real plan will produce. */
#define MAX_COMP_BODY (1u << 20)

/* Cache directory is computed once; a trailing slash is not included. */
static char g_cache_dir[512] = {0};
static int  g_cache_dir_ok   = 0;

/* --- path helpers --- */

static int ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
        return S_ISDIR(st.st_mode) ? 0 : -1;
    if (mkdir(path, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static int init_cache_dir(void)
{
    if (g_cache_dir_ok) return 0;

    const char *home = getenv("HOME");
    if (!home || !*home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw && pw->pw_dir) home = pw->pw_dir;
    }
    if (!home || !*home) return -1;

    char tmp[512];
    /* Build .../.cache */
    int n = snprintf(tmp, sizeof(tmp), "%s/.cache", home);
    if (n <= 0 || (size_t)n >= sizeof(tmp)) return -1;
    if (ensure_dir(tmp) < 0) return -1;

    n = snprintf(tmp, sizeof(tmp), "%s/.cache/pe-loader", home);
    if (n <= 0 || (size_t)n >= sizeof(tmp)) return -1;
    if (ensure_dir(tmp) < 0) return -1;

    n = snprintf(tmp, sizeof(tmp), "%s/.cache/pe-loader/patches", home);
    if (n <= 0 || (size_t)n >= sizeof(tmp)) return -1;
    if (ensure_dir(tmp) < 0) return -1;

    memcpy(g_cache_dir, tmp, (size_t)n + 1);
    g_cache_dir_ok = 1;
    return 0;
}

static int cache_path(const char *sha256_hex, char *out, size_t outlen)
{
    if (init_cache_dir() < 0) return -1;
    if (!sha256_hex) return -1;
    /* SHA-256 hex is 64 chars; don't blindly trust caller length. */
    size_t n = strnlen(sha256_hex, 128);
    if (n < 16 || n > 128) return -1;
    int r = snprintf(out, outlen, "%s/%.*s.ptc",
                     g_cache_dir, (int)n, sha256_hex);
    if (r <= 0 || (size_t)r >= outlen) return -1;
    return 0;
}

/* --- little-endian helpers --- */

static inline void put_u32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline uint32_t get_u32_le(const uint8_t *p)
{
    return ((uint32_t)p[0])       | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void put_u64_le(uint8_t *p, uint64_t v)
{
    put_u32_le(p,     (uint32_t)(v));
    put_u32_le(p + 4, (uint32_t)(v >> 32));
}

static inline uint64_t get_u64_le(const uint8_t *p)
{
    uint64_t lo = (uint64_t)get_u32_le(p);
    uint64_t hi = (uint64_t)get_u32_le(p + 4);
    return lo | (hi << 32);
}

/* --- varint (little-endian base-128) ---
 *
 * Encodes unsigned 64-bit values using 7 bits/byte with a
 * continuation flag in the MSB.  Numbers that fit in 7 bits take
 * one byte; this is what we expect for typical deltas between
 * adjacent CRT IAT slots (usually 8-16 bytes).
 */

static size_t varint_encode(uint64_t v, uint8_t *out)
{
    size_t n = 0;
    while (v >= 0x80u) {
        out[n++] = (uint8_t)((v & 0x7Fu) | 0x80u);
        v >>= 7;
    }
    out[n++] = (uint8_t)(v & 0x7Fu);
    return n;
}

/* Returns bytes consumed on success, 0 on malformed/oversize input. */
static size_t varint_decode(const uint8_t *in, size_t in_len, uint64_t *out)
{
    uint64_t v = 0;
    unsigned shift = 0;
    size_t n = 0;
    while (n < in_len) {
        uint8_t b = in[n++];
        v |= ((uint64_t)(b & 0x7Fu)) << shift;
        if ((b & 0x80u) == 0) { *out = v; return n; }
        shift += 7;
        if (shift > 63) return 0;
    }
    return 0; /* truncated */
}

/* --- plan sorting -- ensures varint deltas are monotonic --- */

static int cmp_entries(const void *a, const void *b)
{
    const pe_patch_entry_t *ea = (const pe_patch_entry_t *)a;
    const pe_patch_entry_t *eb = (const pe_patch_entry_t *)b;
    if (ea->iat_rva < eb->iat_rva) return -1;
    if (ea->iat_rva > eb->iat_rva) return 1;
    return 0;
}

/* --- public API --- */

void pe_patch_plan_free(pe_patch_plan_t *plan)
{
    if (!plan) return;
    free(plan->entries);
    plan->entries  = NULL;
    plan->count    = 0;
    plan->capacity = 0;
}

int pe_patch_cache_save(const char *sha256_hex, const pe_patch_plan_t *plan)
{
    if (!sha256_hex || !plan || plan->count == 0)
        return -1;
    if (plan->count > PE_PATCH_MAX_ENTRIES)
        return -1;

    /* Sort a private copy so the on-disk deltas are non-negative. */
    pe_patch_entry_t *sorted = (pe_patch_entry_t *)malloc(
        sizeof(pe_patch_entry_t) * plan->count);
    if (!sorted) return -1;
    memcpy(sorted, plan->entries, sizeof(pe_patch_entry_t) * plan->count);
    qsort(sorted, plan->count, sizeof(pe_patch_entry_t), cmp_entries);

    /* Varint-encode the body. */
    /* Worst case: 10 bytes per varint, 3 varints per entry = 30 bytes. */
    size_t raw_cap = (size_t)plan->count * 30u;
    uint8_t *raw = (uint8_t *)malloc(raw_cap);
    if (!raw) { free(sorted); return -1; }

    size_t raw_len = 0;
    uint64_t prev_rva = 0;
    for (uint32_t i = 0; i < plan->count; i++) {
        uint64_t delta = sorted[i].iat_rva - prev_rva;
        raw_len += varint_encode(delta, raw + raw_len);
        raw_len += varint_encode((uint64_t)sorted[i].replacement_idx,
                                 raw + raw_len);
        raw_len += varint_encode((uint64_t)sorted[i].flags,
                                 raw + raw_len);
        prev_rva = sorted[i].iat_rva;
    }

    /* zstd compress. */
    size_t comp_cap = ZSTD_compressBound(raw_len);
    uint8_t *comp = (uint8_t *)malloc(comp_cap);
    if (!comp) { free(raw); free(sorted); return -1; }

    size_t comp_len = ZSTD_compress(comp, comp_cap, raw, raw_len, 3);
    if (ZSTD_isError(comp_len)) {
        free(comp); free(raw); free(sorted);
        return -1;
    }

    /* Build the full file image: 16-byte header + zstd body. */
    size_t file_len = 16 + comp_len;
    uint8_t *file_buf = (uint8_t *)malloc(file_len);
    if (!file_buf) { free(comp); free(raw); free(sorted); return -1; }

    put_u32_le(file_buf + 0,  PE_PATCH_CACHE_MAGIC);
    put_u32_le(file_buf + 4,  PE_PATCH_CACHE_VERSION);
    put_u32_le(file_buf + 8,  PE_PATCH_FLAG_ZSTD | PE_PATCH_FLAG_VARINT);
    put_u32_le(file_buf + 12, plan->count);
    memcpy(file_buf + 16, comp, comp_len);

    /* Atomic write: tmp + rename. */
    char path[768];
    char tmp_path[768 + 8];
    if (cache_path(sha256_hex, path, sizeof(path)) < 0) {
        free(file_buf); free(comp); free(raw); free(sorted);
        return -1;
    }
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    if (n <= 0 || (size_t)n >= sizeof(tmp_path)) {
        free(file_buf); free(comp); free(raw); free(sorted);
        return -1;
    }

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        free(file_buf); free(comp); free(raw); free(sorted);
        return -1;
    }

    ssize_t w_total = 0;
    while ((size_t)w_total < file_len) {
        ssize_t w = write(fd, file_buf + w_total, file_len - (size_t)w_total);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd); unlink(tmp_path);
            free(file_buf); free(comp); free(raw); free(sorted);
            return -1;
        }
        w_total += w;
    }
    if (fsync(fd) < 0) { /* non-fatal: kernel buffers are fine for cache */ }
    close(fd);

    if (rename(tmp_path, path) < 0) {
        unlink(tmp_path);
        free(file_buf); free(comp); free(raw); free(sorted);
        return -1;
    }

    free(file_buf); free(comp); free(raw); free(sorted);
    return 0;
}

int pe_patch_cache_load(const char *sha256_hex, pe_patch_plan_t *plan)
{
    if (!sha256_hex || !plan) return -1;
    plan->entries  = NULL;
    plan->count    = 0;
    plan->capacity = 0;

    char path[768];
    if (cache_path(sha256_hex, path, sizeof(path)) < 0) return -1;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) ||
        st.st_size < 16 || (size_t)st.st_size > 16 + MAX_COMP_BODY) {
        close(fd);
        return -1;
    }

    uint8_t header[16];
    ssize_t r = read(fd, header, sizeof(header));
    if (r != (ssize_t)sizeof(header)) { close(fd); return -1; }

    uint32_t magic = get_u32_le(header + 0);
    uint32_t ver   = get_u32_le(header + 4);
    uint32_t flags = get_u32_le(header + 8);
    uint32_t count = get_u32_le(header + 12);

    if (magic != PE_PATCH_CACHE_MAGIC ||
        ver   != PE_PATCH_CACHE_VERSION ||
        count == 0 || count > PE_PATCH_MAX_ENTRIES) {
        close(fd);
        return -1;
    }

    size_t body_len = (size_t)st.st_size - 16;
    uint8_t *body = (uint8_t *)malloc(body_len);
    if (!body) { close(fd); return -1; }

    /* Drain the body in a loop (read() may short-return on large files). */
    size_t got = 0;
    while (got < body_len) {
        ssize_t rr = read(fd, body + got, body_len - got);
        if (rr <= 0) {
            if (rr < 0 && errno == EINTR) continue;
            free(body); close(fd); return -1;
        }
        got += (size_t)rr;
    }
    close(fd);

    /* Decompress if ZSTD flag set. */
    uint8_t *raw = body;
    size_t raw_len = body_len;
    uint8_t *raw_alloc = NULL;

    if (flags & PE_PATCH_FLAG_ZSTD) {
        /* ZSTD_getFrameContentSize may return unknown; fall back to a
         * generous bound and retry with grow. */
        unsigned long long guess = ZSTD_getFrameContentSize(body, body_len);
        size_t dcap;
        if (guess == ZSTD_CONTENTSIZE_ERROR || guess == ZSTD_CONTENTSIZE_UNKNOWN ||
            guess > MAX_RAW_BODY) {
            dcap = MAX_RAW_BODY;
        } else {
            dcap = (size_t)guess;
            if (dcap == 0 || dcap > MAX_RAW_BODY) dcap = MAX_RAW_BODY;
        }
        raw_alloc = (uint8_t *)malloc(dcap);
        if (!raw_alloc) { free(body); return -1; }
        size_t dlen = ZSTD_decompress(raw_alloc, dcap, body, body_len);
        if (ZSTD_isError(dlen)) {
            free(raw_alloc); free(body); return -1;
        }
        raw = raw_alloc;
        raw_len = dlen;
    }

    /* Parse body. */
    pe_patch_entry_t *entries = (pe_patch_entry_t *)calloc(
        count, sizeof(pe_patch_entry_t));
    if (!entries) {
        if (raw_alloc) free(raw_alloc);
        free(body);
        return -1;
    }

    if (flags & PE_PATCH_FLAG_VARINT) {
        size_t pos = 0;
        uint64_t prev_rva = 0;
        for (uint32_t i = 0; i < count; i++) {
            uint64_t delta, idx, ef;
            size_t used;
            used = varint_decode(raw + pos, raw_len - pos, &delta);
            if (!used) { free(entries); goto fail; }
            pos += used;
            used = varint_decode(raw + pos, raw_len - pos, &idx);
            if (!used) { free(entries); goto fail; }
            pos += used;
            used = varint_decode(raw + pos, raw_len - pos, &ef);
            if (!used) { free(entries); goto fail; }
            pos += used;

            if (idx >= PE_PATCH_COUNT) { free(entries); goto fail; }
            prev_rva += delta;
            entries[i].iat_rva         = prev_rva;
            entries[i].replacement_idx = (uint32_t)idx;
            entries[i].flags           = (uint32_t)ef;
        }
    } else {
        /* Raw 16-bytes-per-entry path. */
        if (raw_len < (size_t)count * 16) { free(entries); goto fail; }
        for (uint32_t i = 0; i < count; i++) {
            const uint8_t *p = raw + (size_t)i * 16;
            entries[i].iat_rva         = get_u64_le(p);
            uint32_t idx               = get_u32_le(p + 8);
            entries[i].replacement_idx = idx;
            entries[i].flags           = get_u32_le(p + 12);
            if (idx >= PE_PATCH_COUNT) { free(entries); goto fail; }
        }
    }

    if (raw_alloc) free(raw_alloc);
    free(body);

    plan->entries  = entries;
    plan->count    = count;
    plan->capacity = count;
    return 0;

fail:
    if (raw_alloc) free(raw_alloc);
    free(body);
    return -1;
}
