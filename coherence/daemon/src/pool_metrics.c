/*
 * pool_metrics.c — coherence daemon aggregator for bounded absent pools.
 *
 * Purpose: read two pool stats sources and coalesce them into a single
 * JSON blob at /var/run/coherence/pools.json, rewritten every ~1s.
 *
 * Sources:
 *   1. /sys/kernel/trust/subject_pool     (kernel pool; see trust_subject_pool.c)
 *   2. /var/run/coherence/pe_patch_pool.stats  (PE loader per-process write)
 *
 * Output schema (newline-terminated, torn-write-safe via atomic rename):
 *   {
 *     "trust_subject": { "population": ..., "max": 64, "points": ...,
 *                        "max_points": 256, "hits": ..., "misses": ...,
 *                        "hit_rate": 0.80, "evictions": ... },
 *     "pe_patch":      { ... same shape ... }
 *   }
 *
 * Implementation:
 *   - One pthread, woken every 1000 ms; non-blocking file reads.
 *   - A GCC constructor auto-starts the thread at daemon load so no
 *     edits to main.c / control_loop.c are required.
 *   - No mallocs in the hot loop: scratch buffers are static.
 *   - -Werror clean.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Paths are documented in the header comment; keep as compile-time strings
 * so tampering/env redirection is off-by-default. */
#define POOLS_OUT_PATH         "/var/run/coherence/pools.json"
#define TRUST_POOL_SYSFS_PATH  "/sys/kernel/trust/subject_pool"
#define PE_PATCH_STATS_PATH    "/var/run/coherence/pe_patch_pool.stats"

#define POOL_METRICS_PERIOD_MS 1000u

/* Upper bound on any source payload we parse.  Both producers emit a
 * single short JSON blob well under 1 KB; 4 KB gives overhead. */
#define POOL_METRICS_BUF_SZ    4096u

/* --- state (internal; no API surface for now) --- */
static pthread_t         g_thread;
static atomic_int        g_run = 0;
static atomic_int        g_started = 0;

typedef struct {
    uint32_t population;
    uint32_t max_population;
    uint32_t points;
    uint32_t max_points;
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    uint64_t avg_age_on_hit_ns;
    int      present;   /* 0 = source unavailable; all fields cleared */
} pool_snapshot_t;

/* --- helpers --- */

static int read_file_small(const char *path, char *buf, size_t sz)
{
    if (sz == 0) return -1;
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sz - 1);
    close(fd);
    if (n <= 0) { buf[0] = 0; return -1; }
    buf[n] = 0;
    return 0;
}

/* Tiny ad-hoc numeric scanner -- pulls a decimal integer after the key
 * literal.  NOT a general JSON parser -- intentionally.  Producer shape
 * is controlled by us.  Returns 0 on success. */
static int scan_u64_after(const char *buf, const char *key, uint64_t *out)
{
    const char *p = strstr(buf, key);
    if (!p) return -1;
    p += strlen(key);
    /* Skip quotes, colon, spaces. */
    while (*p == '\"' || *p == ':' || *p == ' ' || *p == '\t') p++;
    if (*p < '0' || *p > '9') return -1;
    uint64_t v = 0;
    while (*p >= '0' && *p <= '9') {
        v = v * 10u + (uint64_t)(*p - '0');
        p++;
    }
    *out = v;
    return 0;
}

static int scan_u32_after(const char *buf, const char *key, uint32_t *out)
{
    uint64_t v;
    if (scan_u64_after(buf, key, &v) != 0) return -1;
    if (v > 0xFFFFFFFFu) v = 0xFFFFFFFFu;
    *out = (uint32_t)v;
    return 0;
}

static void snapshot_clear(pool_snapshot_t *s)
{
    memset(s, 0, sizeof(*s));
}

static int parse_snapshot(const char *buf, pool_snapshot_t *out)
{
    snapshot_clear(out);
    /* All fields optional -- missing ones stay zero.  We call it "present"
     * if AT LEAST ONE of the canonical fields parsed; otherwise the file
     * is junk and we report population=0. */
    int hits = 0;
    if (scan_u32_after(buf, "\"population\"", &out->population) == 0) hits++;
    if (scan_u32_after(buf, "\"max\"",        &out->max_population) == 0) hits++;
    if (scan_u32_after(buf, "\"points\"",     &out->points) == 0) hits++;
    if (scan_u32_after(buf, "\"max_points\"", &out->max_points) == 0) hits++;
    if (scan_u64_after(buf, "\"hits\"",       &out->hits) == 0) hits++;
    if (scan_u64_after(buf, "\"misses\"",     &out->misses) == 0) hits++;
    if (scan_u64_after(buf, "\"evictions\"",  &out->evictions) == 0) hits++;
    if (scan_u64_after(buf, "\"avg_age_on_hit_ns\"",
                       &out->avg_age_on_hit_ns) == 0) hits++;
    out->present = (hits > 0) ? 1 : 0;
    return out->present ? 0 : -1;
}

static double snapshot_hit_rate(const pool_snapshot_t *s)
{
    uint64_t total = s->hits + s->misses;
    if (total == 0) return 0.0;
    return (double)s->hits / (double)total;
}

static void render_snapshot_json(char **p, const char *field,
                                 const pool_snapshot_t *s)
{
    int n = sprintf(*p,
        "\"%s\":{"
        "\"population\":%u,\"max\":%u,"
        "\"points\":%u,\"max_points\":%u,"
        "\"hits\":%llu,\"misses\":%llu,"
        "\"hit_rate\":%.4f,\"evictions\":%llu,"
        "\"avg_age_on_hit_ns\":%llu,\"present\":%d}",
        field,
        s->population, s->max_population,
        s->points, s->max_points,
        (unsigned long long)s->hits, (unsigned long long)s->misses,
        snapshot_hit_rate(s),
        (unsigned long long)s->evictions,
        (unsigned long long)s->avg_age_on_hit_ns,
        s->present);
    if (n > 0) *p += n;
}

static void pool_metrics_write_once(void)
{
    static char buf[POOL_METRICS_BUF_SZ];
    pool_snapshot_t trust_s;  snapshot_clear(&trust_s);
    pool_snapshot_t pe_s;     snapshot_clear(&pe_s);

    if (read_file_small(TRUST_POOL_SYSFS_PATH, buf, sizeof(buf)) == 0)
        parse_snapshot(buf, &trust_s);
    if (read_file_small(PE_PATCH_STATS_PATH, buf, sizeof(buf)) == 0)
        parse_snapshot(buf, &pe_s);

    char out[POOL_METRICS_BUF_SZ];
    char *p = out;
    int prefix = sprintf(p, "{");
    if (prefix > 0) p += prefix;
    render_snapshot_json(&p, "trust_subject", &trust_s);
    int comma = sprintf(p, ",");
    if (comma > 0) p += comma;
    render_snapshot_json(&p, "pe_patch", &pe_s);
    int suffix = sprintf(p, "}\n");
    if (suffix > 0) p += suffix;

    /* Atomic write via tmp + rename. */
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", POOLS_OUT_PATH, (int)getpid());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    size_t to_write = (size_t)(p - out);
    while (to_write > 0) {
        ssize_t w = write(fd, out + ((size_t)(p - out) - to_write), to_write);
        if (w < 0) { if (errno == EINTR) continue; break; }
        if (w == 0) break;
        to_write -= (size_t)w;
    }
    close(fd);
    if (rename(tmp, POOLS_OUT_PATH) != 0)
        (void)unlink(tmp);
}

static void *pool_metrics_thread(void *arg)
{
    (void)arg;
    /* Best-effort directory create (harmless if exists/fails). */
    (void)mkdir("/var/run/coherence", 0755);
    while (atomic_load(&g_run)) {
        pool_metrics_write_once();
        struct timespec req = {
            .tv_sec  = POOL_METRICS_PERIOD_MS / 1000,
            .tv_nsec = (long)(POOL_METRICS_PERIOD_MS % 1000) * 1000000L,
        };
        struct timespec rem;
        while (nanosleep(&req, &rem) == -1 && errno == EINTR) {
            if (!atomic_load(&g_run)) break;
            req = rem;
        }
    }
    return NULL;
}

/* Public API (no header yet — callers use the constructor path). */
void pool_metrics_start_thread(void);
void pool_metrics_stop(void);

void pool_metrics_start_thread(void)
{
    int expected = 0;
    if (!atomic_compare_exchange_strong(&g_started, &expected, 1))
        return;
    atomic_store(&g_run, 1);
    if (pthread_create(&g_thread, NULL, pool_metrics_thread, NULL) != 0) {
        atomic_store(&g_run, 0);
        atomic_store(&g_started, 0);
    }
}

void pool_metrics_stop(void)
{
    if (!atomic_load(&g_started)) return;
    atomic_store(&g_run, 0);
    pthread_join(g_thread, NULL);
    atomic_store(&g_started, 0);
}

/* Auto-start at daemon load -- no main.c edits required. */
__attribute__((constructor))
static void pool_metrics_autostart(void)
{
    pool_metrics_start_thread();
}

__attribute__((destructor))
static void pool_metrics_autoshutdown(void)
{
    pool_metrics_stop();
}
