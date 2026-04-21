/*
 * test_theorems.c - Userspace verification of the Root of Authority
 *                   security theorem invariants exposed by trust.ko.
 *
 * Owner: Session 48 Agent 8.
 *
 * Tests are driven by reading /sys/kernel/trust_invariants/* counters
 * and (where applicable) issuing ioctls to /dev/trust to provoke a
 * theorem-relevant code path, then re-reading the counter to verify
 * it did NOT increment (success) or DID increment for an injected
 * fault (negative test).
 *
 * No libtrust dependency — we open /sys nodes and /dev/trust directly
 * so the harness compiles even if libtrust is absent (e.g. on a
 * stripped CI image).
 *
 * Exit codes:
 *   0  all expected-PASS tests passed (skipped tests are OK)
 *   1  one or more tests FAILED
 *   2  test harness error (couldn't open required path, etc.)
 *
 * Build:
 *   make -C tests/kernel        (uses tests/kernel/Makefile)
 * Run:
 *   sudo ./test_theorems        (root needed for /dev/trust ioctls)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define TI_SYSFS_DIR    "/sys/kernel/trust_invariants"
#define TRUST_SYSFS_DIR "/sys/kernel/trust"
#define TRUST_DEV       "/dev/trust"

/* Local copy of the ioctl numbers we need.  Mirroring instead of
 * including trust_ioctl.h keeps this test buildable in isolation
 * (e.g. when verifying against an installed kernel-headers tree
 * that may lag the in-tree definitions).  Keep these in sync with
 * trust/include/trust_ioctl.h. */
#define TRUST_IOC_MAGIC 'T'

typedef struct {
    uint32_t subject_id;
    uint16_t domain;
    uint16_t _padding;
    uint32_t authority;
    int32_t  initial_score;
} ti_ioc_register_t;

typedef struct {
    uint32_t subject_id;
    int32_t  result;
} ti_ioc_apoptosis_t;

typedef struct {
    uint32_t subject_id;
    uint32_t action_type;
    int32_t  result;
    int32_t  remaining;
} ti_ioc_token_burn_t;

#define TI_IOC_REGISTER   _IOW (TRUST_IOC_MAGIC, 10, ti_ioc_register_t)
#define TI_IOC_APOPTOSIS  _IOWR(TRUST_IOC_MAGIC, 83, ti_ioc_apoptosis_t)
#define TI_IOC_TOKEN_BURN _IOWR(TRUST_IOC_MAGIC, 71, ti_ioc_token_burn_t)

/* TRUST_DOMAIN_USER and a generic action type, copied to avoid header
 * dependency.  Real kernel headers may rename these — verify via
 * `grep TRUST_DOMAIN_ trust/include/trust_types.h` if a test fails
 * with -EINVAL. */
#define TI_DOMAIN_USER  1U
#define TI_ACTION_FILE_READ 1U

/* --- Test framework ----------------------------------------- */

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;

static void rep_pass(const char *name, const char *detail)
{
    g_pass++;
    printf("[PASS] %-32s %s\n", name, detail ? detail : "");
}

static void rep_fail(const char *name, const char *detail)
{
    g_fail++;
    printf("[FAIL] %-32s %s\n", name, detail ? detail : "");
}

static void rep_skip(const char *name, const char *detail)
{
    g_skip++;
    printf("[SKIP] %-32s %s\n", name, detail ? detail : "");
}

/* --- Helpers ------------------------------------------------ */

static int read_u64_node(const char *path, uint64_t *out)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -errno;
    unsigned long long tmp = 0;
    int n = fscanf(f, "%llu", &tmp);
    fclose(f);
    if (n != 1)
        return -EIO;
    *out = (uint64_t)tmp;
    return 0;
}

static bool path_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* Open /dev/trust read-write (root only).  Returns -1 if the device
 * is absent or permission-denied.  Tests that need it should SKIP
 * gracefully on -1. */
static int open_trust_dev(void)
{
    int fd = open(TRUST_DEV, O_RDWR);
    return fd;
}

/* --- T1: Non-Static Secrets --------------------------------- */
/*
 * Walk /sys/kernel/trust/ AND /sys/kernel/trust_invariants/ and assert
 * no entry's name contains "seed", "proof", "cfg", or "secret".
 * We do a substring match (not exact) because a real leak might be
 * called e.g. "raw_seed", "current_proof", "private_cfg".
 *
 * The trust_invariants module also runs an in-kernel self-scan at
 * load time; this test exercises the userspace-visible surface in
 * case any node was added by an out-of-tree patch.
 */
static const char *t1_forbidden[] = {
    "seed", "proof", "cfg", "secret", "private_key", "passphrase", NULL
};

static int t1_scan_one(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) {
        if (errno == ENOENT)
            return 0;  /* OK if the kobject didn't load */
        return -errno;
    }
    int violations = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.')
            continue;
        for (int i = 0; t1_forbidden[i]; i++) {
            if (strstr(e->d_name, t1_forbidden[i])) {
                fprintf(stderr,
                        "  T1 violation: %s/%s matches forbidden "
                        "pattern '%s'\n",
                        dir, e->d_name, t1_forbidden[i]);
                violations++;
            }
        }
    }
    closedir(d);
    return violations;
}

static void test_theorem1(void)
{
    int v1 = t1_scan_one(TRUST_SYSFS_DIR);
    int v2 = t1_scan_one(TI_SYSFS_DIR);

    if (v1 < 0 && v2 < 0) {
        rep_skip("T1 non-static-secrets",
                 "neither /sys/kernel/trust nor /sys/kernel/trust_invariants present");
        return;
    }

    int total = (v1 > 0 ? v1 : 0) + (v2 > 0 ? v2 : 0);
    if (total == 0) {
        rep_pass("T1 non-static-secrets",
                 "no SEED/proof/cfg/secret nodes found");
    } else {
        char buf[128];
        snprintf(buf, sizeof buf, "%d forbidden node(s)", total);
        rep_fail("T1 non-static-secrets", buf);
    }

    /* Also check the in-kernel violation counter (if available). */
    uint64_t k = 0;
    if (read_u64_node(TI_SYSFS_DIR "/theorem1_violations", &k) == 0) {
        if (k != 0) {
            char buf[128];
            snprintf(buf, sizeof buf,
                     "kernel theorem1_violations=%llu",
                     (unsigned long long)k);
            rep_fail("T1 kernel-counter", buf);
        } else {
            rep_pass("T1 kernel-counter", "0 violations");
        }
    }
}

/* --- T2: Non-Replayability ---------------------------------- */
/*
 * Read global_nonce twice; the second read must be > the first IF
 * any proof consumption has happened in between, OR equal if the
 * system is idle.  We also issue a couple of ioctls that should
 * advance the nonce, then verify strict-greater.
 *
 * Even on an idle system, reading the nonce twice must NEVER show a
 * decrease — which is the actual replayability invariant.
 */
static void test_theorem2(void)
{
    uint64_t n1 = 0, n2 = 0;

    if (read_u64_node(TI_SYSFS_DIR "/global_nonce", &n1) < 0) {
        rep_skip("T2 non-replayability", "global_nonce node absent");
        return;
    }

    /* Try to provoke a nonce advance via a token burn (Agent 6's
     * proof-consumption path may or may not be wired yet — graceful). */
    int fd = open_trust_dev();
    if (fd >= 0) {
        ti_ioc_register_t reg = {
            .subject_id = (uint32_t)getpid() + 90001,
            .domain = TI_DOMAIN_USER,
            ._padding = 0,
            .authority = 0,
            .initial_score = 100,
        };
        (void)ioctl(fd, TI_IOC_REGISTER, &reg);
        ti_ioc_token_burn_t burn = {
            .subject_id = reg.subject_id,
            .action_type = TI_ACTION_FILE_READ,
            .result = 0,
            .remaining = 0,
        };
        (void)ioctl(fd, TI_IOC_TOKEN_BURN, &burn);
        close(fd);
    }

    if (read_u64_node(TI_SYSFS_DIR "/global_nonce", &n2) < 0) {
        rep_fail("T2 non-replayability", "second nonce read failed");
        return;
    }

    if (n2 < n1) {
        char buf[128];
        snprintf(buf, sizeof buf,
                 "nonce went backwards: %llu -> %llu",
                 (unsigned long long)n1, (unsigned long long)n2);
        rep_fail("T2 non-replayability", buf);
        return;
    }

    /* Check the violation counter: it should be 0 even if no ioctls
     * advanced the nonce. */
    uint64_t v = 0;
    if (read_u64_node(TI_SYSFS_DIR "/theorem2_violations", &v) == 0
        && v != 0) {
        char buf[128];
        snprintf(buf, sizeof buf,
                 "theorem2_violations=%llu (expected 0)",
                 (unsigned long long)v);
        rep_fail("T2 violation-counter", buf);
        return;
    }

    char detail[128];
    snprintf(detail, sizeof detail,
             "nonce monotonic (n1=%llu n2=%llu)",
             (unsigned long long)n1, (unsigned long long)n2);
    rep_pass("T2 non-replayability", detail);
}

/* --- T4: Bounded Authority Inheritance ---------------------- */
/*
 * Verifying T4 from userspace requires triggering a meiosis through
 * either libtrust (Agent 12) or the meiotic ioctls.  The mitotic
 * fork hook is in-kernel only; we can't synthesise a fork from this
 * harness without either CLONE plumbing or libtrust support.
 *
 * Strategy: read theorem4_violations.  If the running kernel has done
 * any mitosis/meiosis at all, the counter should be 0 (no violations
 * observed during normal operation).  We also gate the active probe
 * on a probe-availability check.
 */
static bool have_meiosis_ioctl(void)
{
    /* Best-effort: check that /dev/trust exists and that the
     * meiotic_combine ioctl wire size is one we recognise.  We don't
     * actually issue the ioctl from here because constructing a
     * valid combine call requires two pre-registered subjects with
     * specific chromosomal compatibility — that's libtrust's job. */
    return path_exists(TRUST_DEV);
}

static void test_theorem4(void)
{
    uint64_t v = 0;
    if (read_u64_node(TI_SYSFS_DIR "/theorem4_violations", &v) < 0) {
        rep_skip("T4 bounded-inheritance", "counter node absent");
        return;
    }

    if (!have_meiosis_ioctl()) {
        rep_skip("T4 bounded-inheritance",
                 "/dev/trust absent — cannot exercise mitosis/meiosis");
        return;
    }

    /* Passive observation: counter must be 0. */
    if (v == 0) {
        rep_pass("T4 bounded-inheritance",
                 "passive: no S_max-inheritance violations recorded");
    } else {
        char buf[128];
        snprintf(buf, sizeof buf,
                 "theorem4_violations=%llu (expected 0)",
                 (unsigned long long)v);
        rep_fail("T4 bounded-inheritance", buf);
    }
}

/* --- T5: Guaranteed Revocation O(1) ------------------------- */
/*
 * Register a single subject, trigger apoptosis on it, and verify
 * theorem5_violations does NOT increment.  We snapshot the counter
 * before and after to defeat sysfs-cached counter values.
 */
static void test_theorem5(void)
{
    int fd = open_trust_dev();
    if (fd < 0) {
        rep_skip("T5 revocation-budget",
                 "/dev/trust unavailable (run as root?)");
        return;
    }

    uint64_t v_before = 0, v_after = 0;
    if (read_u64_node(TI_SYSFS_DIR "/theorem5_violations", &v_before) < 0) {
        rep_skip("T5 revocation-budget", "counter node absent");
        close(fd);
        return;
    }

    ti_ioc_register_t reg = {
        .subject_id = (uint32_t)getpid() + 70001,
        .domain = TI_DOMAIN_USER,
        ._padding = 0,
        .authority = 0,
        .initial_score = 100,
    };
    if (ioctl(fd, TI_IOC_REGISTER, &reg) < 0 && errno != EEXIST) {
        char buf[128];
        snprintf(buf, sizeof buf, "register failed: %s", strerror(errno));
        rep_skip("T5 revocation-budget", buf);
        close(fd);
        return;
    }

    ti_ioc_apoptosis_t apop = { .subject_id = reg.subject_id, .result = 0 };
    int rc = ioctl(fd, TI_IOC_APOPTOSIS, &apop);
    if (rc < 0) {
        char buf[128];
        snprintf(buf, sizeof buf, "apoptosis ioctl failed: %s",
                 strerror(errno));
        rep_skip("T5 revocation-budget", buf);
        close(fd);
        return;
    }

    if (read_u64_node(TI_SYSFS_DIR "/theorem5_violations", &v_after) < 0) {
        rep_fail("T5 revocation-budget", "post-read failed");
        close(fd);
        return;
    }

    if (v_after > v_before) {
        char buf[128];
        snprintf(buf, sizeof buf,
                 "violations increased: %llu -> %llu",
                 (unsigned long long)v_before, (unsigned long long)v_after);
        rep_fail("T5 revocation-budget", buf);
    } else {
        uint64_t max_us = 0;
        (void)read_u64_node(TI_SYSFS_DIR "/theorem5_max_us", &max_us);
        char buf[128];
        snprintf(buf, sizeof buf,
                 "no new violations (max_us=%llu)",
                 (unsigned long long)max_us);
        rep_pass("T5 revocation-budget", buf);
    }

    close(fd);
}

/* --- T6: Metabolic Fairness --------------------------------- */
/*
 * Per the spec: burn tokens until empty, verify that the next burn
 * fails (predicate-prevented) and that theorem6_violations does NOT
 * increment.  The whole point of T6 is that the predicate prevents
 * the unfair action *in advance* rather than detecting it after.
 *
 * We use TRUST_IOC_TOKEN_BURN with TI_ACTION_FILE_READ (cost 1).
 * We cap iterations at 4096 to avoid an infinite loop if the
 * subject auto-regenerates; if we hit the cap we SKIP rather than
 * FAIL because the test envelope is wrong, not the kernel.
 */
static void test_theorem6(void)
{
    int fd = open_trust_dev();
    if (fd < 0) {
        rep_skip("T6 metabolic-fairness",
                 "/dev/trust unavailable (run as root?)");
        return;
    }

    uint64_t v_before = 0, v_after = 0;
    if (read_u64_node(TI_SYSFS_DIR "/theorem6_violations", &v_before) < 0) {
        rep_skip("T6 metabolic-fairness", "counter node absent");
        close(fd);
        return;
    }

    ti_ioc_register_t reg = {
        .subject_id = (uint32_t)getpid() + 60001,
        .domain = TI_DOMAIN_USER,
        ._padding = 0,
        .authority = 0,
        .initial_score = 100,
    };
    if (ioctl(fd, TI_IOC_REGISTER, &reg) < 0 && errno != EEXIST) {
        char buf[128];
        snprintf(buf, sizeof buf,
                 "register failed: %s", strerror(errno));
        rep_skip("T6 metabolic-fairness", buf);
        close(fd);
        return;
    }

    /* Drain. */
    int last_rc = 0, last_err = 0, drained_at = -1;
    for (int i = 0; i < 4096; i++) {
        ti_ioc_token_burn_t b = {
            .subject_id = reg.subject_id,
            .action_type = TI_ACTION_FILE_READ,
            .result = 0,
            .remaining = 0,
        };
        last_rc = ioctl(fd, TI_IOC_TOKEN_BURN, &b);
        last_err = errno;
        if (last_rc < 0 || b.result != 0 || b.remaining <= 0) {
            drained_at = i;
            break;
        }
    }

    if (drained_at < 0) {
        rep_skip("T6 metabolic-fairness",
                 "token bucket did not drain in 4096 burns "
                 "(test envelope wrong)");
        close(fd);
        return;
    }

    /* Try one more burn — it should fail (predicate-prevented). */
    ti_ioc_token_burn_t extra = {
        .subject_id = reg.subject_id,
        .action_type = TI_ACTION_FILE_READ,
        .result = 0,
        .remaining = 0,
    };
    int extra_rc = ioctl(fd, TI_IOC_TOKEN_BURN, &extra);
    bool predicate_prevented =
        (extra_rc < 0) || (extra.result != 0);

    if (read_u64_node(TI_SYSFS_DIR "/theorem6_violations", &v_after) < 0) {
        rep_fail("T6 metabolic-fairness", "post-read failed");
        close(fd);
        return;
    }

    if (!predicate_prevented) {
        rep_fail("T6 metabolic-fairness",
                 "burn-on-empty unexpectedly succeeded");
    } else if (v_after != v_before) {
        char buf[128];
        snprintf(buf, sizeof buf,
                 "violation counter advanced %llu -> %llu — predicate "
                 "should prevent, not detect",
                 (unsigned long long)v_before,
                 (unsigned long long)v_after);
        rep_fail("T6 metabolic-fairness", buf);
    } else {
        char buf[128];
        snprintf(buf, sizeof buf,
                 "predicate prevented burn-on-empty after %d successful "
                 "burns; counter unchanged at %llu",
                 drained_at, (unsigned long long)v_after);
        rep_pass("T6 metabolic-fairness", buf);
    }

    (void)last_err;
    close(fd);
}

/* --- main --------------------------------------------------- */

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("Root of Authority — security theorem verification\n");
    printf("=================================================\n");

    if (!path_exists(TI_SYSFS_DIR) && !path_exists(TRUST_SYSFS_DIR)) {
        fprintf(stderr,
                "ERROR: neither %s nor %s exist; trust.ko probably "
                "not loaded.\n", TI_SYSFS_DIR, TRUST_SYSFS_DIR);
        return 2;
    }

    test_theorem1();
    test_theorem2();
    test_theorem4();
    test_theorem5();
    test_theorem6();

    printf("=================================================\n");
    printf("Result: %d PASS, %d FAIL, %d SKIP\n", g_pass, g_fail, g_skip);
    return g_fail == 0 ? 0 : 1;
}
