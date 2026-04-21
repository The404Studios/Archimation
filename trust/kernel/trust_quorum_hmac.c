/*
 * trust_quorum_hmac.c — HMAC-SHA256 over quorum verdict payloads.
 *
 * S75 Tier-3 Item #7 pair (roadmap §1.3.7). Research-G §6 calls for an
 * L1 crypto uplift so the 23-way vote can be recognised by downstream
 * consumers even when the carrying channel is untrusted (e.g. a future
 * cross-process quorum broadcast). This file supplies the HMAC primitive;
 * the call-site in trust_quorum.c is intentionally NOT wired here to
 * avoid colliding with Agent G's verdict-enum rename work.
 *
 * Kernel HMAC-SHA256: crypto_alloc_shash("hmac(sha256)", 0, 0) returns
 * a shash tfm that prepends the MAC construction over SHA-256. The key
 * is set via crypto_shash_setkey(tfm, key, keylen).
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <crypto/hash.h>

#include "../include/trust_quorum_hmac.h"

#define TRUST_QUORUM_HMAC_KEY_LEN 32U  /* 256-bit key */

static u8          g_hmac_key[TRUST_QUORUM_HMAC_KEY_LEN];
static bool        g_hmac_initialized;
static DEFINE_MUTEX(g_hmac_key_lock);

int trust_quorum_hmac_init(void)
{
    mutex_lock(&g_hmac_key_lock);
    if (g_hmac_initialized) {
        mutex_unlock(&g_hmac_key_lock);
        return 0;
    }

    /*
     * get_random_bytes() is callable from any context and draws from
     * the kernel CSPRNG. Used elsewhere in this tree — trust_ape.c:654
     * seeds fresh SEED material the same way.
     */
    get_random_bytes(g_hmac_key, TRUST_QUORUM_HMAC_KEY_LEN);
    g_hmac_initialized = true;
    mutex_unlock(&g_hmac_key_lock);

    pr_info("trust_quorum_hmac: module key initialised (%u bytes)\n",
            TRUST_QUORUM_HMAC_KEY_LEN);
    return 0;
}

void trust_quorum_hmac_exit(void)
{
    mutex_lock(&g_hmac_key_lock);
    memzero_explicit(g_hmac_key, TRUST_QUORUM_HMAC_KEY_LEN);
    g_hmac_initialized = false;
    mutex_unlock(&g_hmac_key_lock);
}

int trust_quorum_hmac_compute(const void *payload, size_t len,
                              u8 out[TRUST_QUORUM_HMAC_LEN])
{
    struct crypto_shash *tfm;
    struct shash_desc   *desc;
    u8                   keycopy[TRUST_QUORUM_HMAC_KEY_LEN];
    int                  ret;

    if (!g_hmac_initialized)
        return -ENODEV;
    if (!payload && len)
        return -EINVAL;
    if (!out)
        return -EINVAL;

    /*
     * Snapshot the key under the mutex so a concurrent rotate (future)
     * doesn't tear our setkey call. Copy is the minimum cost — setkey
     * itself copies into the tfm anyway.
     */
    mutex_lock(&g_hmac_key_lock);
    memcpy(keycopy, g_hmac_key, TRUST_QUORUM_HMAC_KEY_LEN);
    mutex_unlock(&g_hmac_key_lock);

    tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(tfm)) {
        memzero_explicit(keycopy, TRUST_QUORUM_HMAC_KEY_LEN);
        return PTR_ERR(tfm);
    }

    ret = crypto_shash_setkey(tfm, keycopy, TRUST_QUORUM_HMAC_KEY_LEN);
    memzero_explicit(keycopy, TRUST_QUORUM_HMAC_KEY_LEN);
    if (ret)
        goto out_free_tfm;

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        ret = -ENOMEM;
        goto out_free_tfm;
    }
    desc->tfm = tfm;

    ret = crypto_shash_digest(desc, payload, len, out);

    kfree(desc);
out_free_tfm:
    crypto_free_shash(tfm);
    return ret;
}
