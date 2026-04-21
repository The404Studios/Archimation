/*
 * trust_attest.c - TPM2-anchored boot attestation for trust.ko
 *
 * Strategy:
 *   1. Parse trust.attest= from kernel cmdline for explicit override.
 *   2. Acquire a TPM chip reference via tpm_default_chip()
 *      (or tpm_chip_find_get(NULL) on kernels where the former is
 *      unavailable).  NULL → no TPM → SOFTWARE mode.
 *   3. Verify the chip advertises TPM 2.0 (TPM_CHIP_FLAG_TPM2).  TPM
 *      1.2 cannot carry SHA-256 PCR banks → SOFTWARE mode.
 *   4. Read /etc/archimation/expected-pcr-11 (32-byte hex, 64 ASCII
 *      chars + optional newline).  Missing / short / unreadable →
 *      SOFTWARE mode (degraded, never a silent HARDWARE claim).
 *   5. tpm_pcr_read(chip, 11, &digest) for the SHA-256 bank.
 *   6. memcmp against expected.  Equal → HARDWARE.  Unequal → FAILED.
 *
 * Graceful-degradation rationale: old hardware (pre-2013 boards, some
 * server SKUs with TPM disabled in firmware, virt setups without a
 * swtpm) MUST still boot — otherwise we've traded authority for
 * bricking the user.  Instead we make SOFTWARE mode loud: pr_warn at
 * boot, a sysfs attribute, and (in other files) a subject-record
 * annotation so userspace can downgrade its trust claims accordingly.
 *
 * References:
 *   - include/linux/tpm.h — tpm_chip, tpm_pcr_read, tpm_default_chip
 *   - Documentation/security/tpm/tpm_tis.rst
 *   - systemd TPM2_PCR_MEASUREMENTS (PCR 11 semantics)
 *   - docs/research/s72_gamma_tpm2_attest.md (full design)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/err.h>

/*
 * include/linux/tpm.h landed tpm_default_chip() in ~5.2 and
 * tpm_chip_find_get() has been stable since 4.x.  We use the more
 * modern API when available and fall back gracefully.  The forward
 * declaration approach avoids pulling the full struct tpm_chip into
 * this file (it's opaque to module consumers anyway).
 */
#include <linux/tpm.h>

#include "trust_attest.h"

#define PCR_INDEX_UKI           11
#define EXPECTED_PCR_PATH       "/etc/archimation/expected-pcr-11"
#define PCR11_SHA256_LEN        32
#define PCR11_HEX_LEN           (PCR11_SHA256_LEN * 2)
#define CMDLINE_MAX_TOKEN_LEN   32

/* Module-global state, set once by trust_attest_init, read by queries. */
static trust_attest_mode_t g_attest_mode = TRUST_ATTEST_SOFTWARE;
static struct tpm_chip *g_attest_chip;
static u8 g_attest_expected[PCR11_SHA256_LEN];
static u8 g_attest_measured[PCR11_SHA256_LEN];
static bool g_attest_have_expected;
static bool g_attest_have_measured;

/* sysfs object rooted at /sys/kernel/trust_attest/ — separate from the
 * main /sys/kernel/trust/ tree so we can publish attestation state
 * even when the main module bails (HARDWARE-required deployments will
 * want to see WHY they were refused). */
static struct kobject *g_attest_kobj;

static const char *
mode_name(trust_attest_mode_t m)
{
    switch (m) {
    case TRUST_ATTEST_HARDWARE: return "hardware";
    case TRUST_ATTEST_SOFTWARE: return "software";
    case TRUST_ATTEST_FAILED:   return "failed";
    default:                    return "unknown";
    }
}

const char *trust_attest_mode_name(trust_attest_mode_t m)
{
    return mode_name(m);
}

trust_attest_mode_t trust_attest_mode(void)
{
    return g_attest_mode;
}

bool trust_attest_hardware(void)
{
    return g_attest_mode == TRUST_ATTEST_HARDWARE;
}

/* --- kernel-cmdline override parsing ---
 *
 * We accept:
 *   trust.attest=hardware  (force HARDWARE; fail if TPM absent)
 *   trust.attest=software  (skip TPM, go straight to SOFTWARE)
 *   trust.attest=skip      (alias for software — recovery UX)
 *   (absent)               (auto-detect)
 *
 * Returns:
 *   0 = auto
 *   1 = force hardware
 *   2 = force software
 * -1 = malformed (treated as auto by caller)
 */
enum {
    CMDLINE_AUTO          = 0,
    CMDLINE_FORCE_HW      = 1,
    CMDLINE_FORCE_SW      = 2,
};

static int parse_cmdline_override(void)
{
    const char *p, *val;
    char tok[CMDLINE_MAX_TOKEN_LEN + 1];
    size_t i;

    /* saved_command_line is the full boot cmdline string, populated
     * early during kernel init.  It is a global extern char *. */
    extern const char *saved_command_line;

    if (!saved_command_line)
        return CMDLINE_AUTO;

    p = strstr(saved_command_line, "trust.attest=");
    if (!p)
        return CMDLINE_AUTO;

    val = p + strlen("trust.attest=");
    for (i = 0; i < CMDLINE_MAX_TOKEN_LEN; i++) {
        char c = val[i];
        if (c == '\0' || c == ' ' || c == '\t' || c == '\n')
            break;
        tok[i] = c;
    }
    tok[i] = '\0';

    if (!strcmp(tok, "hardware"))
        return CMDLINE_FORCE_HW;
    if (!strcmp(tok, "software") || !strcmp(tok, "skip"))
        return CMDLINE_FORCE_SW;

    pr_warn("trust_attest: unrecognised trust.attest= value '%s' — treating as auto\n",
            tok);
    return CMDLINE_AUTO;
}

/* --- hex parsing helpers --- */

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex32(const char *buf, size_t len, u8 out[PCR11_SHA256_LEN])
{
    size_t i;
    size_t hex_chars = 0;
    char tight[PCR11_HEX_LEN];

    /* Accept the file with trailing newline / whitespace; pack the
     * hex chars into `tight` first so we can bail on truncation. */
    for (i = 0; i < len && hex_chars < PCR11_HEX_LEN; i++) {
        char c = buf[i];
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t')
            continue;
        tight[hex_chars++] = c;
    }

    if (hex_chars != PCR11_HEX_LEN)
        return -EINVAL;

    for (i = 0; i < PCR11_SHA256_LEN; i++) {
        int hi = hex_nibble(tight[2*i]);
        int lo = hex_nibble(tight[2*i + 1]);
        if (hi < 0 || lo < 0)
            return -EINVAL;
        out[i] = (u8)((hi << 4) | lo);
    }
    return 0;
}

/* --- expected-value file reader ---
 *
 * kernel_read_file_from_path handles the open+read+size-check path
 * and is available across the 6.x line.  Cap the allowed size to a
 * generous bound so a hostile file cannot exhaust memory.
 */
static int read_expected_pcr(u8 out[PCR11_SHA256_LEN])
{
    void *buf = NULL;
    size_t buf_size = 0;
    loff_t file_size = 0;
    int ret;

    ret = kernel_read_file_from_path(EXPECTED_PCR_PATH,
                                     0,
                                     &buf,
                                     128 /* max: 64 hex + some ws */,
                                     &file_size,
                                     READING_POLICY);
    if (ret < 0) {
        /* Caller will map this to SOFTWARE — leave verbose diagnostics
         * to trust_attest_init rather than spamming from here. */
        return ret;
    }
    buf_size = (size_t)ret;
    ret = parse_hex32((const char *)buf, buf_size, out);
    kvfree(buf);
    return ret;
}

/* --- sysfs surface ---
 *
 * /sys/kernel/trust_attest/mode         — "hardware", "software", "failed"
 * /sys/kernel/trust_attest/expected_pcr — 64 hex chars + '\n', or "unknown"
 * /sys/kernel/trust_attest/measured_pcr — 64 hex chars + '\n', or "unknown"
 *
 * All three are read-only.  Publishing `measured_pcr` even in FAILED
 * mode is intentional: it gives an admin the data to decide whether
 * the drift is expected (config change) or hostile (tamper).
 */

static ssize_t mode_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    (void)k; (void)a;
    return sysfs_emit(buf, "%s\n", mode_name(g_attest_mode));
}

static ssize_t expected_pcr_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    (void)k; (void)a;
    if (!g_attest_have_expected)
        return sysfs_emit(buf, "unknown\n");
    return sysfs_emit(buf, "%*phN\n", PCR11_SHA256_LEN, g_attest_expected);
}

static ssize_t measured_pcr_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    (void)k; (void)a;
    if (!g_attest_have_measured)
        return sysfs_emit(buf, "unknown\n");
    return sysfs_emit(buf, "%*phN\n", PCR11_SHA256_LEN, g_attest_measured);
}

static struct kobj_attribute attr_mode        = __ATTR_RO(mode);
static struct kobj_attribute attr_expected    = __ATTR(expected_pcr, 0444, expected_pcr_show, NULL);
static struct kobj_attribute attr_measured    = __ATTR(measured_pcr, 0444, measured_pcr_show, NULL);

static struct attribute *attest_attrs[] = {
    &attr_mode.attr,
    &attr_expected.attr,
    &attr_measured.attr,
    NULL,
};

static const struct attribute_group attest_group = {
    .attrs = attest_attrs,
};

static void attest_sysfs_register(void)
{
    int ret;

    g_attest_kobj = kobject_create_and_add("trust_attest", kernel_kobj);
    if (!g_attest_kobj) {
        pr_warn("trust_attest: kobject_create_and_add failed — sysfs unavailable\n");
        return;
    }
    ret = sysfs_create_group(g_attest_kobj, &attest_group);
    if (ret) {
        pr_warn("trust_attest: sysfs_create_group failed (%d)\n", ret);
        kobject_put(g_attest_kobj);
        g_attest_kobj = NULL;
    }
}

static void attest_sysfs_unregister(void)
{
    if (g_attest_kobj) {
        sysfs_remove_group(g_attest_kobj, &attest_group);
        kobject_put(g_attest_kobj);
        g_attest_kobj = NULL;
    }
}

/* --- TPM chip acquisition ---
 *
 * tpm_default_chip() returns the default chip, NULL if none.  On
 * older kernels without tpm_default_chip, tpm_chip_find_get(NULL)
 * is the stable alternative.  We use the #ifdef below to stay
 * forward + backward compatible.
 */
static struct tpm_chip *acquire_tpm_chip(void)
{
#ifdef CONFIG_TCG_TPM2_HMAC
    /* Modern path (kernel ≥5.2): tpm_default_chip is the canonical API. */
    return tpm_default_chip();
#else
    return tpm_chip_find_get(NULL);
#endif
}

/* --- main entry point --- */

int trust_attest_init(void)
{
    int override, rc;
    struct tpm_digest digest;

    memset(&digest, 0, sizeof(digest));
    attest_sysfs_register();

    override = parse_cmdline_override();

    if (override == CMDLINE_FORCE_SW) {
        g_attest_mode = TRUST_ATTEST_SOFTWARE;
        pr_warn("trust_attest: trust.attest=software on cmdline — "
                "TPM skipped, authority claims are ADVISORY\n");
        return 0;
    }

    /* AUTO or FORCE_HW — try to acquire a TPM chip. */
    g_attest_chip = acquire_tpm_chip();
    if (!g_attest_chip) {
        if (override == CMDLINE_FORCE_HW) {
            pr_err("trust_attest: trust.attest=hardware but no TPM chip available\n");
            pr_crit("trust_attest: refusing init.  Remove trust.attest=hardware "
                    "from cmdline OR install a TPM 2.0 device.\n");
            g_attest_mode = TRUST_ATTEST_FAILED;
            return -ENODEV;
        }
        g_attest_mode = TRUST_ATTEST_SOFTWARE;
        pr_warn("trust_attest: no TPM chip detected — software-only mode, "
                "authority claims are ADVISORY\n");
        return 0;
    }

    /* Confirm TPM 2.0.  TPM_CHIP_FLAG_TPM2 is a stable bit across 6.x. */
    if (!(g_attest_chip->flags & TPM_CHIP_FLAG_TPM2)) {
        if (override == CMDLINE_FORCE_HW) {
            pr_err("trust_attest: trust.attest=hardware but chip is TPM 1.2 (SHA-1 only)\n");
            pr_crit("trust_attest: refusing init.  TPM 1.2 cannot anchor "
                    "SHA-256 PCR 11.  Upgrade firmware or drop the override.\n");
            put_device(&g_attest_chip->dev);
            g_attest_chip = NULL;
            g_attest_mode = TRUST_ATTEST_FAILED;
            return -ENOTSUPP;
        }
        put_device(&g_attest_chip->dev);
        g_attest_chip = NULL;
        g_attest_mode = TRUST_ATTEST_SOFTWARE;
        pr_warn("trust_attest: chip is TPM 1.2 (SHA-1) — software-only mode, "
                "authority claims are ADVISORY\n");
        return 0;
    }

    /* Load expected PCR from bootc-provisioned file. */
    rc = read_expected_pcr(g_attest_expected);
    if (rc) {
        if (override == CMDLINE_FORCE_HW) {
            pr_err("trust_attest: trust.attest=hardware but %s unreadable (%d)\n",
                   EXPECTED_PCR_PATH, rc);
            pr_crit("trust_attest: refusing init.  bootc image build must "
                    "stage the expected PCR value at %s.\n",
                    EXPECTED_PCR_PATH);
            put_device(&g_attest_chip->dev);
            g_attest_chip = NULL;
            g_attest_mode = TRUST_ATTEST_FAILED;
            return rc;
        }
        put_device(&g_attest_chip->dev);
        g_attest_chip = NULL;
        g_attest_mode = TRUST_ATTEST_SOFTWARE;
        pr_warn("trust_attest: %s unreadable (%d) — software-only mode, "
                "authority claims are ADVISORY\n",
                EXPECTED_PCR_PATH, rc);
        return 0;
    }
    g_attest_have_expected = true;

    /* Read PCR 11 (SHA-256 bank). */
    digest.alg_id = TPM_ALG_SHA256;
    rc = tpm_pcr_read(g_attest_chip, PCR_INDEX_UKI, &digest);
    if (rc) {
        pr_err("trust_attest: tpm_pcr_read(PCR 11) failed (%d)\n", rc);
        put_device(&g_attest_chip->dev);
        g_attest_chip = NULL;
        g_attest_mode = TRUST_ATTEST_FAILED;
        pr_crit("trust_attest: refusing init — cannot read measurement.  "
                "Boot with trust.attest=skip to force software mode.\n");
        return rc;
    }
    memcpy(g_attest_measured, digest.digest, PCR11_SHA256_LEN);
    g_attest_have_measured = true;

    /* Compare. */
    if (memcmp(g_attest_expected, g_attest_measured, PCR11_SHA256_LEN) != 0) {
        g_attest_mode = TRUST_ATTEST_FAILED;
        pr_err("trust_attest: PCR 11 MISMATCH\n");
        pr_err("trust_attest:   expected %*phN\n",
               PCR11_SHA256_LEN, g_attest_expected);
        pr_err("trust_attest:   measured %*phN\n",
               PCR11_SHA256_LEN, g_attest_measured);
        pr_crit("trust_attest: userspace has been tampered OR config has "
                "drifted.  /dev/trust will NOT be created.\n");
        pr_crit("trust_attest: to force software-only mode, reboot with "
                "trust.attest=skip on kernel cmdline.\n");
        /* Keep chip reference around so sysfs read paths remain valid
         * until trust_attest_cleanup. */
        return -EACCES;
    }

    g_attest_mode = TRUST_ATTEST_HARDWARE;
    pr_info("trust_attest: TPM2 attestation PASSED — authority enabled\n");
    pr_info("trust_attest: PCR 11 = %*phN\n",
            PCR11_SHA256_LEN, g_attest_measured);
    return 0;
}

void trust_attest_cleanup(void)
{
    if (g_attest_chip) {
        put_device(&g_attest_chip->dev);
        g_attest_chip = NULL;
    }
    attest_sysfs_unregister();
}
