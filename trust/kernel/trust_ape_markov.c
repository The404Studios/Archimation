/*
 * trust_ape_markov.c - Statistical validator for the APE reconfigurable
 *                      hash output distribution (paper Theorem 3).
 *
 * Spec: "Root of Authority" (Roberts/Eli/Leelee, Zenodo 18710335),
 *       §APE Theorem 3 — Reconfiguration Unpredictability:
 *
 *   Pr[adversary predicts cfg(n+1)] <= 1/|Config| + negl(lambda)
 *
 * The proof chain feeds a transformed buffer into SHA-256 / SHA-3-256 /
 * BLAKE2b-256.  If the chain is well-mixed, the OUTPUT byte distribution
 * over many independent random inputs should be statistically
 * indistinguishable from uniform on { 0..255 }.
 *
 * We can't formally prove uniformity in C, but at module-load time we
 * can run a lightweight point-test:
 *
 *   1. Generate N=10000 fresh 32-byte random inputs (get_random_bytes).
 *   2. Feed each through the same primitive the APE chain uses on the
 *      success path: SHA-256 over (random_seed || random_input).
 *      We CANNOT call apply_reconfigurable_hash() directly from this
 *      translation unit (it is `static` to trust_ape.c, which is locked
 *      to Agent 1 of S48).  Using SHA-256 directly is a strict
 *      LOWER-BOUND on the chain's mixing — if SHA-256 alone fails
 *      uniformity at our threshold, the composite chain certainly does.
 *      A passing SHA-256 test does NOT prove the composite is uniform,
 *      but it gates against catastrophic regressions in the underlying
 *      primitive (e.g. crypto API returning a stub) and gives operators
 *      a printable confidence signal at boot.
 *   3. Bucket all N*32 = 320000 output bytes into a 256-bin histogram.
 *   4. Compute the chi-square statistic in pure integer math:
 *
 *        chi_sq = sum_i (obs[i] - exp)^2 / exp
 *
 *      where exp = (N * 32) / 256 = 1250 expected observations per bin.
 *      For 255 d.o.f., the p<0.001 critical value is ~330; we use a
 *      slightly tighter threshold of 300 (a healthy SHA-256 typically
 *      lands around 200-260) and emit a WARN-level pr_info on miss.
 *   5. Module load NEVER fails on a chi-square miss — the test is
 *      diagnostic, not gating.
 *
 * Invocation: this function is NOT invoked automatically.  Per the
 * Session 58 charter, trust_ape.c (Agent 1's domain) is locked, so
 * Session 59 must wire trust_ape_markov_validator() into the tail of
 * trust_ape_init().  Until then, the symbol is dead code that adds
 * ~1.5 KB to trust.ko and ~1 KB of stack/heap when called.
 *
 * Memory: one kmalloc(256 * sizeof(u32)) = 1024 bytes; freed on every
 * exit path.  No persistent allocations.
 *
 * Safety: runs in process context only (caller is module_init), uses
 * kmalloc(GFP_KERNEL), may sleep inside crypto_alloc_shash().  Do NOT
 * call from softirq, NMI, or with spinlocks held.
 */

#include <linux/types.h>
#include <linux/random.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/err.h>
#include <crypto/hash.h>

#include "trust_ape.h"

#define APE_MARKOV_SAMPLE_N      10000U  /* iteration count */
#define APE_MARKOV_INPUT_LEN        32U  /* bytes per random input */
#define APE_MARKOV_OUTPUT_LEN       32U  /* SHA-256 digest size */
#define APE_MARKOV_BUCKETS         256U  /* per-byte distribution bins */
#define APE_MARKOV_CHISQ_THRESH    300U  /* 255 d.o.f., ~p<0.005 */
#define APE_MARKOV_SEED_LEN         32U  /* per-run nonce mixed into hash */

/*
 * Helper: hash one (seed || input) pair into out[32] using SHA-256.
 * Returns 0 on success, negative crypto errno on failure.
 */
static int ape_markov_hash_once(struct crypto_shash *tfm,
                                const u8 *seed, u32 seed_len,
                                const u8 *in,   u32 in_len,
                                u8 *out)
{
    SHASH_DESC_ON_STACK(desc, tfm);
    int ret;

    desc->tfm = tfm;

    ret = crypto_shash_init(desc);
    if (ret)
        return ret;
    ret = crypto_shash_update(desc, seed, seed_len);
    if (ret)
        return ret;
    ret = crypto_shash_update(desc, in, in_len);
    if (ret)
        return ret;
    return crypto_shash_final(desc, out);
}

/*
 * trust_ape_markov_validator — public entry point.
 *
 * Runs APE_MARKOV_SAMPLE_N iterations of (random seed || random input)
 * -> SHA-256 -> per-byte histogram, then computes a chi-square statistic
 * against the uniform expectation.  Logs the verdict to dmesg.
 *
 * Never returns failure.  Never aborts module load.  Idempotent — safe
 * to call repeatedly (e.g. from a future ktest harness).
 */
void trust_ape_markov_validator(void)
{
    struct crypto_shash *tfm;
    u32  *buckets;
    u8    seed[APE_MARKOV_SEED_LEN];
    u8    input[APE_MARKOV_INPUT_LEN];
    u8    digest[APE_MARKOV_OUTPUT_LEN];
    u64   chi_sq_num;     /* numerator running sum (u64 to avoid overflow) */
    u32   expected;
    u32   chi_sq;
    u32   i, j;
    int   ret;
    u32   completed = 0;
    bool  pass;

    /*
     * Bucket allocation.  256 * 4 bytes = 1024 bytes — small, but worth
     * the kmalloc rather than stack-burning a kernel thread.
     */
    buckets = kmalloc(APE_MARKOV_BUCKETS * sizeof(u32), GFP_KERNEL);
    if (!buckets) {
        pr_warn("trust_ape_markov: kmalloc(%u) failed; skipping validator\n",
                (unsigned int)(APE_MARKOV_BUCKETS * sizeof(u32)));
        return;
    }
    memset(buckets, 0, APE_MARKOV_BUCKETS * sizeof(u32));

    /* Allocate the SHA-256 transform once and reuse. */
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        pr_warn("trust_ape_markov: crypto_alloc_shash(sha256) failed (%ld); "
                "skipping validator\n", PTR_ERR(tfm));
        kfree(buckets);
        return;
    }

    /*
     * Per-run seed — distinguishes this validator's hashes from any
     * collision with the live proof chain in dmesg dumps and ensures
     * each module load samples a fresh point in the input space.
     */
    get_random_bytes(seed, sizeof(seed));

    for (i = 0; i < APE_MARKOV_SAMPLE_N; i++) {
        get_random_bytes(input, sizeof(input));

        ret = ape_markov_hash_once(tfm,
                                   seed, sizeof(seed),
                                   input, sizeof(input),
                                   digest);
        if (ret) {
            /*
             * A mid-loop crypto failure is not a security event but
             * does invalidate the statistic.  Log and bail without
             * computing chi-square (would skew toward "skewed").
             */
            pr_warn("trust_ape_markov: crypto_shash failed at iter %u (err %d); "
                    "aborting validator\n", i, ret);
            goto out;
        }

        /* Bucket every byte of the digest. */
        for (j = 0; j < APE_MARKOV_OUTPUT_LEN; j++)
            buckets[digest[j]]++;

        completed++;
    }

    /*
     * Chi-square in pure integer math.
     *   expected = (N * output_len) / 256
     *   chi_sq   = sum_i (obs[i] - exp)^2 / exp
     *
     * With N=10000, output_len=32: expected = 1250 per bin, total
     * observations = 320000.  Per-bin (obs-exp)^2 fits in u32 even at
     * worst case (obs=320000 -> diff^2 ~ 1e11) only if widened to u64;
     * we accumulate in u64 throughout to be safe.
     */
    expected = (APE_MARKOV_SAMPLE_N * APE_MARKOV_OUTPUT_LEN) / APE_MARKOV_BUCKETS;
    if (expected == 0) {
        /* Defensive — only possible if someone shrinks N below 8. */
        pr_warn("trust_ape_markov: expected==0 (N too small); skipping\n");
        goto out;
    }

    chi_sq_num = 0;
    for (i = 0; i < APE_MARKOV_BUCKETS; i++) {
        s64 diff = (s64)buckets[i] - (s64)expected;
        u64 sq   = (u64)(diff * diff);     /* diff^2 always non-negative */
        chi_sq_num += sq / expected;       /* per-bin contribution */
    }

    /*
     * chi_sq_num fits in u32 for any reasonable distribution.  Clamp
     * defensively so the format specifier doesn't truncate silently.
     */
    chi_sq = (chi_sq_num > (u64)U32_MAX) ? U32_MAX : (u32)chi_sq_num;
    pass   = (chi_sq < APE_MARKOV_CHISQ_THRESH);

    pr_info("trust_ape_markov: chi-square %u (threshold %u) -- "
            "output distribution %s "
            "[N=%u iters, %u bytes each, %u bins, %u expected/bin]\n",
            chi_sq, APE_MARKOV_CHISQ_THRESH,
            pass ? "uniform (PASS)" : "skewed (WARN)",
            completed,
            (unsigned int)APE_MARKOV_OUTPUT_LEN,
            (unsigned int)APE_MARKOV_BUCKETS,
            expected);

out:
    crypto_free_shash(tfm);
    kfree(buckets);
}
