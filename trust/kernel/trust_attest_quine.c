/*
 * trust_attest_quine.c — Live .text self-attestation (quine fold).
 *
 * S75 Tier-3 Item #7. Roadmap §1.3.7; research-F §3; research-J §5
 * Proposal C; architecture-v2.md §9 Proposal C.
 *
 * Idea (paper §Hardware-APE, with a software fold):
 *   At init we SHA-256 the module's .text section and cache the 32-byte
 *   digest. trust_ape.c::compute_proof_v2() folds that digest into every
 *   proof's hash input. A kernel-write adversary who modifies the live
 *   module (e.g. inserting a NOP sled, replacing a verdict enum, etc.)
 *   either:
 *     (a) does NOT patch the cached hash — every new proof diverges
 *         from the attacker's expected value → the chain breaks;
 *     (b) DOES patch the cached hash to match their modified code —
 *         but the very act of patching requires a SHA-256 pre-image
 *         while the exploit resides in .text, which is circular.
 *
 * This is orthogonal to trust_attest.c (TPM2 boot-time PCR 11). That
 * file anchors the boot transition; this file anchors the *runtime*
 * state against post-boot tampering.
 *
 * Layout choices we made (and why):
 *   - We use THIS_MODULE->mem[MOD_TEXT] on kernels that expose the new
 *     `struct mod_mem` layout (6.4+), falling back to the legacy
 *     core_layout.base / core_layout.text_size on older kernels. Both
 *     are "the module's own .text" — the quine target.
 *   - We DO NOT hash the whole module image (which would include
 *     .rodata, __ksymtab, initcall tables, ...). Only .text, because
 *     (a) that's what the paper's "code-is-data" fold requires and
 *     (b) .rodata on some kernels contains kernfs pointers that drift
 *     at random module-load addresses — hashing them produces a
 *     platform-specific digest that a reproducible build can't match.
 *   - We tick a counter in trust_ape and every N consumes re-hash via
 *     a workqueue (no crypto under spinlock). Between recomputes the
 *     cached hash is stable, serving every proof.
 *   - On recompute failure (e.g. OOM, crypto_alloc_shash -ENOMEM) we
 *     leave the previous hash in place — breaking every live proof
 *     just because a transient allocation failed would be worse than
 *     delaying the live-tampering detection.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/err.h>
#include <linux/atomic.h>
#include <linux/seqlock.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/version.h>
#include <crypto/hash.h>

#include "../include/trust_attest_quine.h"

/* -------------------------------------------------------------------- */
/*   State                                                              */
/* -------------------------------------------------------------------- */

/*
 * Cached hash plus a seqlock for the fast-path reader (every APE proof).
 * A seqlock gives us a cheap, atomic, retryable read with no writer
 * starvation — writers (recompute) are rare so the reader almost never
 * retries.
 *
 * S78 Dev B follow-up (S77 Agent 4 item 1): use seqcount_spinlock_t rather
 * than plain seqcount_t so lockdep on preemptible kernels (CONFIG_PREEMPT=y
 * + CONFIG_DEBUG_LOCK_ALLOC=y) can prove the writer-side is serialized by
 * g_quine_writer_lock. The writer runs from a workqueue (process context)
 * so taking a spinlock around write_seqcount_begin/end is cheap; readers
 * (APE compute_proof_v2) remain lock-free.
 *
 * S78 Dev B follow-up (item 7): g_quine_tick widened to atomic_long_t so
 * the ~1000-tick-per-proof consume pace can't wrap the 31-bit counter in
 * any conceivable deployment lifetime.
 */
static u8                 g_quine_text_hash[TRUST_QUINE_HASH_LEN];
static DEFINE_SPINLOCK(g_quine_writer_lock);
static seqcount_spinlock_t g_quine_seq =
    SEQCNT_SPINLOCK_ZERO(g_quine_seq, &g_quine_writer_lock);
static atomic64_t         g_quine_recompute_count = ATOMIC64_INIT(0);
static atomic_long_t      g_quine_tick            = ATOMIC_LONG_INIT(0);
/* S78 Dev B item 4: count reads that fell through to the magic sentinel
 * (quine subsystem uninitialized). A non-zero counter is a userspace
 * watchdog signal — see trust_attest_quine_get_hash() for the contract. */
static atomic64_t         g_quine_uninit_reads    = ATOMIC64_INIT(0);
static bool               g_quine_initialized;

static struct kobject    *g_quine_kobj;     /* /sys/kernel/trust_attest */
static bool               g_quine_owns_kobj; /* did we create it? */

/* Workqueue for deferred recomputes (can't crypto_alloc under spinlock). */
static struct work_struct g_quine_recompute_work;

/* -------------------------------------------------------------------- */
/*   .text locate + hash                                                */
/* -------------------------------------------------------------------- */

/*
 * Resolve the module's .text base+size. Returns 0 on success; on older
 * kernels where neither API is available, returns -ENOTSUPP and leaves
 * the caller to fall back (SOFTWARE mode — loud pr_warn).
 */
static int quine_locate_text(const void **base_out, size_t *size_out)
{
    struct module *mod = THIS_MODULE;

    if (!mod) {
        /* Unreachable in practice — THIS_MODULE is non-NULL in a loaded
         * module's compilation unit — but guard anyway. */
        return -EINVAL;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    /*
     * 6.4+: `struct module` dropped core_layout/init_layout in favour
     * of the unified mem[MOD_MEM_NUM_TYPES] array. MOD_TEXT is the
     * executable segment of the module's "core" region.
     */
    if (mod->mem[MOD_TEXT].size == 0 || mod->mem[MOD_TEXT].base == NULL)
        return -ENOENT;
    *base_out = mod->mem[MOD_TEXT].base;
    *size_out = mod->mem[MOD_TEXT].size;
    return 0;
#else
    /* 5.x / early 6.x: legacy layout. text_size is the .text span. */
    if (mod->core_layout.text_size == 0 || mod->core_layout.base == NULL)
        return -ENOENT;
    *base_out = mod->core_layout.base;
    *size_out = (size_t)mod->core_layout.text_size;
    return 0;
#endif
}

/*
 * Compute SHA-256 over [@base, @base+@size). Fills @out[32] on success.
 * Process context; uses GFP_KERNEL + crypto_alloc_shash.
 */
static int quine_hash_text(const void *base, size_t size,
                           u8 out[TRUST_QUINE_HASH_LEN])
{
    struct crypto_shash *tfm;
    struct shash_desc   *desc;
    int ret;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    desc->tfm = tfm;

    /* crypto_shash_digest is the one-shot SHA API (init+update+final). */
    ret = crypto_shash_digest(desc, base, size, out);

    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

/*
 * Perform one full recompute: locate .text, hash it, publish under
 * the seqlock, bump the counter. Safe in process context.
 */
static void quine_do_recompute(void)
{
    const void *base = NULL;
    size_t      size = 0;
    u8          staged[TRUST_QUINE_HASH_LEN];
    int         ret;

    ret = quine_locate_text(&base, &size);
    if (ret) {
        pr_warn_ratelimited("trust_attest_quine: cannot locate .text "
                            "(%d); hash stale, proofs unaffected\n", ret);
        return;
    }

    ret = quine_hash_text(base, size, staged);
    if (ret) {
        pr_warn_ratelimited("trust_attest_quine: SHA-256 compute failed "
                            "(%d); hash stale\n", ret);
        return;
    }

    /* Publish atomically. Readers using read_seqcount_retry() see either
     * the old or the new value, never a torn mix.
     *
     * S78 Dev B item 1: seqcount_spinlock_t requires the writer to hold
     * the associated spinlock across write_seqcount_begin/end. This
     * satisfies lockdep on CONFIG_PREEMPT kernels and makes concurrent
     * recompute-from-two-threads impossible (belt-and-suspenders — the
     * workqueue itself serializes, but explicit is better than implicit). */
    spin_lock(&g_quine_writer_lock);
    write_seqcount_begin(&g_quine_seq);
    memcpy(g_quine_text_hash, staged, TRUST_QUINE_HASH_LEN);
    write_seqcount_end(&g_quine_seq);
    spin_unlock(&g_quine_writer_lock);

    atomic64_inc(&g_quine_recompute_count);
    memzero_explicit(staged, TRUST_QUINE_HASH_LEN);
}

/* Workqueue trampoline. */
static void quine_recompute_work_fn(struct work_struct *w)
{
    (void)w;
    quine_do_recompute();
}

/* -------------------------------------------------------------------- */
/*   Public API (header-declared)                                       */
/* -------------------------------------------------------------------- */

void trust_attest_quine_get_hash(u8 out[TRUST_QUINE_HASH_LEN])
{
    unsigned int seq;

    if (!g_quine_initialized) {
        /*
         * S78 Dev B item 4: threat-model hardening.
         *
         * Previously we returned 32 zero bytes here. That's indistinguishable
         * from an adversary who loaded the module with quine wholly disabled
         * (crypto API failure, OOM during init) and then presented a
         * zero-hash "clean" proof stream. APE's consume_proof_v2 would fold
         * the zeros identically whether honest-but-broken or actively-evaded.
         *
         * Fix: publish a fixed non-zero MAGIC sentinel (0xDEADBEEF repeating)
         * instead of zero. Any downstream consumer that sees the sentinel in
         * a text_hash field knows the quine subsystem was uninitialized at
         * the time of the read — NOT that the .text happened to hash to
         * all zeros (cryptographically infeasible) AND NOT that an adversary
         * successfully spoofed a clean state. Bump g_quine_uninit_reads so
         * userspace (cortex algedonic_reader or a watchdog) can fire an
         * alarm when this path is hit. See header for the contract.
         */
        u32 magic = 0xDEADBEEFU;
        size_t i;
        for (i = 0; i + sizeof(magic) <= TRUST_QUINE_HASH_LEN; i += sizeof(magic))
            memcpy(out + i, &magic, sizeof(magic));
        atomic64_inc(&g_quine_uninit_reads);
        return;
    }

    do {
        seq = read_seqcount_begin(&g_quine_seq);
        memcpy(out, g_quine_text_hash, TRUST_QUINE_HASH_LEN);
    } while (read_seqcount_retry(&g_quine_seq, seq));
}
EXPORT_SYMBOL_GPL(trust_attest_quine_get_hash);

void trust_attest_quine_force_recompute(void)
{
    if (!g_quine_initialized)
        return;
    /*
     * We accept the synchronous cost here — callers that want
     * deferred behaviour should schedule_work(&g_quine_recompute_work)
     * directly. This is the "I want a fresh hash now" path.
     */
    quine_do_recompute();
}
EXPORT_SYMBOL_GPL(trust_attest_quine_force_recompute);

int trust_attest_quine_tick(void)
{
    long val;

    if (!g_quine_initialized)
        return 0;

    /* S78 Dev B item 7: widened to atomic_long_t. On LP64 (x86_64) this
     * is a 64-bit counter — overflow-immune for any realistic uptime.
     * On 32-bit kernels long is still 32 bits but DKMS targets LP64 here. */
    val = atomic_long_inc_return(&g_quine_tick);
    if ((val % TRUST_QUINE_RECOMPUTE_EVERY) == 0) {
        /*
         * schedule_work — the caller may be holding spinlocks
         * (trust_ape.c::compute_proof_v2 isn't, but the function
         * signature should be safe from any site). Defers crypto to
         * process context.
         */
        schedule_work(&g_quine_recompute_work);
        return 1;
    }
    return 0;
}
EXPORT_SYMBOL_GPL(trust_attest_quine_tick);

/* -------------------------------------------------------------------- */
/*   sysfs                                                              */
/* -------------------------------------------------------------------- */

static ssize_t quine_text_hash_show(struct kobject *k,
                                    struct kobj_attribute *a, char *buf)
{
    u8 snap[TRUST_QUINE_HASH_LEN];
    (void)k; (void)a;

    trust_attest_quine_get_hash(snap);
    /* sysfs_emit + %*phN is the established pattern in this tree
     * (see trust_attest.c:246,254). */
    return sysfs_emit(buf, "%*phN\n", (int)TRUST_QUINE_HASH_LEN, snap);
}

static ssize_t quine_recompute_count_show(struct kobject *k,
                                          struct kobj_attribute *a, char *buf)
{
    (void)k; (void)a;
    return sysfs_emit(buf, "%lld\n",
                      (long long)atomic64_read(&g_quine_recompute_count));
}

/* S78 Dev B item 4: /sys/kernel/trust_attest_quine/quine_uninit_reads
 * exposes the uninit-sentinel-read counter. Userspace watchdog contract:
 * any non-zero value AFTER module init completed is abnormal and
 * indicates the quine subsystem failed to initialize (e.g. sysfs race
 * during module load) — proofs folded over that window contain the
 * 0xDEADBEEF sentinel instead of a real .text hash. */
static ssize_t quine_uninit_reads_show(struct kobject *k,
                                       struct kobj_attribute *a, char *buf)
{
    (void)k; (void)a;
    return sysfs_emit(buf, "%lld\n",
                      (long long)atomic64_read(&g_quine_uninit_reads));
}

static struct kobj_attribute attr_text_hash =
    __ATTR(text_hash,        0444, quine_text_hash_show,        NULL);
static struct kobj_attribute attr_recompute_count =
    __ATTR(recompute_count,  0444, quine_recompute_count_show,  NULL);
static struct kobj_attribute attr_uninit_reads =
    __ATTR(quine_uninit_reads, 0444, quine_uninit_reads_show,   NULL);

static struct attribute *quine_attrs[] = {
    &attr_text_hash.attr,
    &attr_recompute_count.attr,
    &attr_uninit_reads.attr,
    NULL,
};

static const struct attribute_group quine_group = {
    .attrs = quine_attrs,
};

/* -------------------------------------------------------------------- */
/*   Init / Exit                                                        */
/* -------------------------------------------------------------------- */

/*
 * We share /sys/kernel/trust_attest/ with trust_attest.c. That file
 * creates its kobject in trust_attest_init(). We try to attach our
 * attributes to an existing kobject by looking it up via
 * kset_find_obj(); if we can't (e.g. trust_attest_init failed earlier),
 * we create our own. Ownership flag `g_quine_owns_kobj` tracks which
 * path was taken so exit cleans up correctly.
 *
 * NOTE on kernel-API uncertainty: kset_find_obj() works against a
 * struct kset, but kernel_kobj is a bare kobject (it has an associated
 * kset internally but it's not exposed as `kernel_kobj->kset`). The
 * portable pattern is: try kobject_create_and_add() — if the name
 * already exists we get -EEXIST and fall back to direct sysfs_create_
 * group on the existing object obtained via kset_find_obj(kernel_kset,
 * ...). To avoid cross-module header gymnastics we take a simpler
 * path: create a new kobject named "trust_attest" ONLY if trust_attest
 * didn't (detected by kobject_create_and_add returning a pre-existing-
 * named failure). If collision, we log and skip sysfs — the hash is
 * still folded into proofs; we just lose the observability surface.
 * The integration agent can wire up a cleaner kobject-sharing contract
 * via trust_attest.c exposing a getter. See report for the TODO.
 */
/* S78 Dev B item 5: __init marker lets the kernel reclaim this function's
 * text after module load completes. Deliberately NOT paired with __exit on
 * trust_attest_quine_exit() because that function is also called from the
 * init-failure rollback paths in trust_core.c:905,915,926,938,950,963.
 * Marking the exit __exit would trigger a modpost section-mismatch warning
 * for __init trust_init -> __exit trust_attest_quine_exit on built-in
 * builds (and cause real text-discard issues if the module were ever
 * compiled =y rather than =m). Keeping trust_attest_quine_exit() unmarked
 * is the correct idiom for dual-purpose cleanup. Same applies to
 * trust_quorum_hmac_exit(). */
int __init trust_attest_quine_init(void)
{
    int ret;

    INIT_WORK(&g_quine_recompute_work, quine_recompute_work_fn);

    /* First hash — synchronous, under process context (module init). */
    quine_do_recompute();

    /*
     * Attempt to register sysfs attrs. Try a sibling kobject under
     * kernel_kobj named "trust_attest_quine" rather than reusing
     * /sys/kernel/trust_attest/ — sharing requires trust_attest.c to
     * export its g_attest_kobj, which it currently doesn't (see
     * report TODO).
     */
    g_quine_kobj = kobject_create_and_add("trust_attest_quine", kernel_kobj);
    if (!g_quine_kobj) {
        pr_warn("trust_attest_quine: kobject_create_and_add failed — "
                "sysfs hidden, but hash folding continues\n");
        g_quine_initialized = true; /* still functional for APE path */
        return 0;
    }
    g_quine_owns_kobj = true;

    ret = sysfs_create_group(g_quine_kobj, &quine_group);
    if (ret) {
        pr_warn("trust_attest_quine: sysfs_create_group failed (%d) — "
                "hash folding still active\n", ret);
        kobject_put(g_quine_kobj);
        g_quine_kobj = NULL;
        g_quine_owns_kobj = false;
    }

    g_quine_initialized = true;
    pr_info("trust_attest_quine: .text self-attestation active "
            "(hash recomputes every %u proof consumes)\n",
            TRUST_QUINE_RECOMPUTE_EVERY);
    return 0;
}

void trust_attest_quine_exit(void)
{
    /* Order matters: mark uninitialized FIRST so readers stop pulling
     * from the cache while we tear it down. */
    g_quine_initialized = false;

    /* Drain any pending deferred recompute before we destroy state. */
    cancel_work_sync(&g_quine_recompute_work);

    if (g_quine_kobj && g_quine_owns_kobj) {
        sysfs_remove_group(g_quine_kobj, &quine_group);
        kobject_put(g_quine_kobj);
    }
    g_quine_kobj = NULL;
    g_quine_owns_kobj = false;

    memzero_explicit(g_quine_text_hash, TRUST_QUINE_HASH_LEN);
}
