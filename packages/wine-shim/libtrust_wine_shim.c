/*
 * libtrust_wine_shim.c - LD_PRELOAD trust gate for the Wine PE32 handoff.
 *
 * Session 74, Agent 1.  Paired with pe-loader/loader/main.c's PE32 handoff
 * branch, which execve()s /usr/bin/wine with:
 *
 *   LD_PRELOAD=/usr/lib/libtrust_wine_shim.so
 *   TRUST_SHIM_PID=<pid of the original loader caller>
 *
 * The shim intercepts open(), openat(), and execve() via dlsym(RTLD_NEXT)
 * and funnels each call through /dev/trust TRUST_IOC_CHECK_CAP before
 * invoking the real glibc entrypoint.  On deny, we set errno = EACCES
 * and return -1 (open/openat) or -1 (execve) without ever entering the
 * underlying syscall.
 *
 * Design notes:
 *   - The first call lazy-opens /dev/trust.  If /dev/trust is missing
 *     (trust.ko not loaded), we flip a "fail-open" flag and stop calling
 *     the kernel for the remainder of the process lifetime.  This lets
 *     Wine keep working on hosts that don't ship trust.ko while still
 *     gating the happy path where the module IS loaded.
 *   - We deliberately do NOT hook every syscall Wine uses.  Hooking
 *     open/openat catches file reads/writes and execve catches child
 *     process creation -- the two capability classes that actually
 *     matter for an untrusted .exe.  fstat/stat/read/write ride on an
 *     already-checked fd, so re-gating them would just burn CPU.
 *   - Thread-safety: all mutable state is stored in a single volatile
 *     flag-word plus atomic compare-and-exchange on the first open.
 *     We never take a global lock; a lost race just does an extra
 *     /dev/trust open+close, which is harmless.
 *   - AICONTROL_WINE_SHIM_DISABLE=1 fully bypasses the gate (pass-through
 *     to real glibc) for debugging.  AICONTROL_WINE_SHIM_VERBOSE=1 emits
 *     one stderr line per denied call.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdatomic.h>

/* Minimal redefinition of the subset of trust_ioctl.h we need.  We
 * intentionally avoid pulling the full trust/include/ headers so the
 * shim stays ABI-stable and rebuild-free across trust kernel updates
 * that don't change these four symbols. */
#define TRUST_IOC_MAGIC 'T'

#ifndef _IOWR
#include <sys/ioctl.h>
#endif

/* TRUST_CAP_FILE_READ (bit 0), TRUST_CAP_FILE_WRITE (bit 1),
 * TRUST_CAP_PROCESS_CREATE (bit 4).  Kept in sync with
 * trust/include/trust_types.h. */
#define SHIM_CAP_FILE_READ      (1U << 0)
#define SHIM_CAP_FILE_WRITE     (1U << 1)
#define SHIM_CAP_PROCESS_CREATE (1U << 4)

typedef struct {
    uint32_t subject_id;
    uint32_t capability;
    int32_t  result;      /* Out: 1=has cap, 0=no */
    uint32_t _padding;
} shim_check_cap_t;

#define SHIM_TRUST_IOC_CHECK_CAP _IOWR(TRUST_IOC_MAGIC, 1, shim_check_cap_t)

/* --- Global shim state ---------------------------------------------- */

static int          g_trust_fd      = -1;          /* /dev/trust */
static atomic_int   g_init_done     = 0;           /* 0=unstarted, 1=in progress, 2=done */
static int          g_disabled      = 0;           /* AICONTROL_WINE_SHIM_DISABLE */
static int          g_verbose       = 0;           /* AICONTROL_WINE_SHIM_VERBOSE */
static int          g_fail_open     = 0;           /* set if /dev/trust unreachable */
static uint32_t     g_subject_id    = 0;           /* from TRUST_SHIM_PID */

/* --- Real-function pointers (resolved lazily) ----------------------- */

typedef int  (*real_open_t)(const char *pathname, int flags, ...);
typedef int  (*real_openat_t)(int dirfd, const char *pathname, int flags, ...);
typedef int  (*real_execve_t)(const char *path, char *const argv[], char *const envp[]);

static real_open_t     real_open     = NULL;
static real_openat_t   real_openat   = NULL;
static real_execve_t   real_execve   = NULL;

/* --- One-shot initialiser ------------------------------------------- */

static void shim_init_once(void)
{
    int expected = 0;
    if (!atomic_compare_exchange_strong(&g_init_done, &expected, 1)) {
        /* Another thread beat us; spin until it finishes.  Init is
         * bounded (no syscalls-of-unbounded-length), so a tight loop
         * is fine. */
        while (atomic_load(&g_init_done) != 2)
            ; /* spin */
        return;
    }

    const char *disabled = getenv("AICONTROL_WINE_SHIM_DISABLE");
    const char *verbose  = getenv("AICONTROL_WINE_SHIM_VERBOSE");
    const char *pid_s    = getenv("TRUST_SHIM_PID");

    g_disabled = (disabled && *disabled && *disabled != '0') ? 1 : 0;
    g_verbose  = (verbose  && *verbose  && *verbose  != '0') ? 1 : 0;

    if (pid_s && *pid_s) {
        long v = strtol(pid_s, NULL, 10);
        if (v > 0 && v < INT32_MAX) g_subject_id = (uint32_t)v;
    }
    if (g_subject_id == 0) {
        /* Fall back to our own pid.  Trust kernel will either match an
         * existing subject or fail-open (see below). */
        g_subject_id = (uint32_t)getpid();
    }

    /* Resolve real libc symbols.  If any of these fail we degrade to
     * full fail-open; a Wine process without any of these three libc
     * symbols is not a real Wine process. */
    real_open   = (real_open_t)   dlsym(RTLD_NEXT, "open");
    real_openat = (real_openat_t) dlsym(RTLD_NEXT, "openat");
    real_execve = (real_execve_t) dlsym(RTLD_NEXT, "execve");

    if (!real_open || !real_openat || !real_execve) {
        g_fail_open = 1;
        if (g_verbose) {
            fprintf(stderr, "[trust_wine_shim] dlsym RTLD_NEXT failed; "
                    "passing through\n");
        }
    } else if (!g_disabled) {
        /* Open /dev/trust on the real_open pointer so we skip our own hook. */
        g_trust_fd = real_open("/dev/trust", O_RDWR | O_CLOEXEC);
        if (g_trust_fd < 0) {
            g_fail_open = 1;
            if (g_verbose) {
                fprintf(stderr, "[trust_wine_shim] /dev/trust unavailable "
                        "(%s); fail-open\n", strerror(errno));
            }
        } else if (g_verbose) {
            fprintf(stderr, "[trust_wine_shim] armed: subject=%u fd=%d\n",
                    g_subject_id, g_trust_fd);
        }
    }

    atomic_store(&g_init_done, 2);
}

/* --- Capability check ----------------------------------------------- *
 * Returns 1 = allowed, 0 = denied.  Fail-open on ioctl error so a
 * misbehaving kernel module never bricks Wine. */
static int shim_check_cap(uint32_t cap)
{
    shim_init_once();
    if (g_disabled || g_fail_open || g_trust_fd < 0)
        return 1;

    shim_check_cap_t req;
    memset(&req, 0, sizeof(req));
    req.subject_id = g_subject_id;
    req.capability = cap;

    if (ioctl(g_trust_fd, SHIM_TRUST_IOC_CHECK_CAP, &req) < 0) {
        /* ENOENT means "unknown subject" -- we emit a single verbose
         * breadcrumb and fail-open for that pid for the rest of the
         * process lifetime. */
        if (g_verbose) {
            fprintf(stderr, "[trust_wine_shim] ioctl failed (%s); "
                    "fail-open for remainder\n", strerror(errno));
        }
        g_fail_open = 1;
        return 1;
    }
    return req.result == 1 ? 1 : 0;
}

static void shim_log_deny(const char *what, const char *path, uint32_t cap)
{
    if (!g_verbose) return;
    fprintf(stderr, "[trust_wine_shim] DENY %s(%s) cap=0x%x subject=%u\n",
            what, path ? path : "(null)", cap, g_subject_id);
}

/* --- Hooked entrypoints --------------------------------------------- */

int open(const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    shim_init_once();
    if (!real_open) {
        /* Extremely degenerate case; preserve EACCES behaviour rather
         * than segfault. */
        errno = EACCES;
        return -1;
    }

    uint32_t cap = (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC))
                   ? SHIM_CAP_FILE_WRITE : SHIM_CAP_FILE_READ;

    if (!shim_check_cap(cap)) {
        shim_log_deny("open", pathname, cap);
        errno = EACCES;
        return -1;
    }

    return real_open(pathname, flags, mode);
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    shim_init_once();
    if (!real_openat) {
        errno = EACCES;
        return -1;
    }

    uint32_t cap = (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC))
                   ? SHIM_CAP_FILE_WRITE : SHIM_CAP_FILE_READ;

    if (!shim_check_cap(cap)) {
        shim_log_deny("openat", pathname, cap);
        errno = EACCES;
        return -1;
    }

    return real_openat(dirfd, pathname, flags, mode);
}

int execve(const char *path, char *const argv[], char *const envp[])
{
    shim_init_once();
    if (!real_execve) {
        errno = EACCES;
        return -1;
    }

    if (!shim_check_cap(SHIM_CAP_PROCESS_CREATE)) {
        shim_log_deny("execve", path, SHIM_CAP_PROCESS_CREATE);
        errno = EACCES;
        return -1;
    }

    return real_execve(path, argv, envp);
}
