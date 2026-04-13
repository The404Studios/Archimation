/*
 * trust_ape.c - Authority Proof Engine (software emulation)
 *
 * Implements the self-consuming proof chain from the Root of Authority paper.
 * This is a software emulation of the Ring -2 hardware APE described in the
 * paper. In hardware, the SEED register is physically write-once and the
 * PROOF register is atomic read-and-zero. We emulate these semantics using
 * spinlocks and explicit state flags.
 *
 * Proof chain formula:
 *   Pn+1 = Hcfg(n)(Pn || Rn || SEED || NONCEn || TSn || Sn)
 *
 * Where:
 *   Pn      = Current proof (consumed/destroyed on use)
 *   Rn      = Request being authorized
 *   SEED    = Write-once entity identity seed
 *   NONCEn  = Monotonic counter (never repeats)
 *   TSn     = Timestamp
 *   Sn      = Behavioral state snapshot (chromosome checksum)
 *   Hcfg(n) = Hash function whose config is derived from consumed proof
 *
 * Key security properties (from paper's theorems):
 *   Theorem 1 (Non-Static Secrets): P changes with every action
 *   Theorem 2 (Non-Replayability): Monotonic nonce prevents replay
 *   Theorem 3 (Reconfiguration Unpredictability): Hash config derived from
 *             consumed proof is unpredictable without knowing the proof
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/random.h>
#include <crypto/hash.h>
#include <crypto/sha2.h>
#include "trust_internal.h"

/* Global APE state */
trust_ape_t g_trust_ape;

/* Supported hash algorithm names (indexed by TRUST_HASH_CFG_*) */
static const char *hash_algo_names[TRUST_HASH_CFG_COUNT] = {
    "sha256",       /* TRUST_HASH_CFG_SHA256 */
    "blake2b-256",  /* TRUST_HASH_CFG_BLAKE2B */
    "sha3-256",     /* TRUST_HASH_CFG_SHA3 */
};

/*
 * Derive the hash configuration for the next proof from the current proof.
 * This implements "Reconfiguration Unpredictability" — the hash algo used
 * for Pn+1 is determined by bytes of Pn, which is consumed and destroyed.
 */
static u32 derive_hash_cfg(const u8 *proof)
{
    /* Use first 4 bytes of proof as selector */
    u32 selector = proof[0] | (proof[1] << 8) |
                   (proof[2] << 16) | (proof[3] << 24);
    return selector % TRUST_HASH_CFG_COUNT;
}

/*
 * Compute a proof using the specified hash configuration.
 * Input: Pn || Rn || SEED || NONCEn || TSn || Sn
 * Output: Pn+1 (32 bytes)
 */
static int compute_proof(u32 hash_cfg, const u8 *data, u32 data_len,
                          u8 *out)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    const char *algo;
    int ret;

    if (hash_cfg >= TRUST_HASH_CFG_COUNT)
        hash_cfg = TRUST_HASH_CFG_SHA256;

    algo = hash_algo_names[hash_cfg];
    tfm = crypto_alloc_shash(algo, 0, 0);
    if (IS_ERR(tfm)) {
        /* Fallback to SHA-256 if requested algo not available */
        tfm = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(tfm))
            return PTR_ERR(tfm);
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;
    ret = crypto_shash_digest(desc, data, data_len, out);

    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

/* Find an APE entry by subject_id */
static trust_ape_entry_t *ape_find(u32 subject_id)
{
    int i;
    for (i = 0; i < g_trust_ape.count; i++) {
        if (g_trust_ape.entries[i].subject_id == subject_id)
            return &g_trust_ape.entries[i];
    }
    return NULL;
}

/*
 * Initialize the APE subsystem.
 */
void trust_ape_init(void)
{
    memset(&g_trust_ape, 0, sizeof(g_trust_ape));
    spin_lock_init(&g_trust_ape.lock);
    pr_info("trust_ape: Authority Proof Engine initialized (software emulation)\n");
}

/*
 * Create a new proof chain entity for a subject.
 *
 * The seed is written once and can never be read back — this emulates
 * the hardware write-once/read-never SEED register of the APE.
 *
 * The initial proof P0 is generated from the seed and a random nonce.
 */
int trust_ape_create_entity(u32 subject_id, const u8 *seed, u32 seed_len)
{
    trust_ape_entry_t *entry;
    u8 init_data[TRUST_SEED_SIZE + 8 + 8]; /* seed + nonce + timestamp */
    u8 local_seed[TRUST_SEED_SIZE];
    u8 initial_proof[TRUST_PROOF_SIZE];
    u64 ts, nonce;
    int ret;

    /*
     * Pre-compute the proof BEFORE acquiring the spinlock.
     * compute_proof() calls crypto_alloc_shash() and kmalloc(GFP_KERNEL),
     * both of which can sleep — illegal under a spinlock.
     */

    /* Prepare seed locally */
    memset(local_seed, 0, TRUST_SEED_SIZE);
    if (seed && seed_len > 0) {
        u32 copy_len = seed_len < TRUST_SEED_SIZE ? seed_len : TRUST_SEED_SIZE;
        memcpy(local_seed, seed, copy_len);
    } else {
        /* Generate random seed if none provided */
        get_random_bytes(local_seed, TRUST_SEED_SIZE);
    }

    /* Initialize monotonic nonce */
    get_random_bytes(&nonce, sizeof(nonce));

    /* Generate initial proof P0 = H(SEED || NONCE || TS) */
    ts = trust_get_timestamp();
    memcpy(init_data, local_seed, TRUST_SEED_SIZE);
    memcpy(init_data + TRUST_SEED_SIZE, &nonce, 8);
    memcpy(init_data + TRUST_SEED_SIZE + 8, &ts, 8);

    ret = compute_proof(TRUST_HASH_CFG_SHA256, init_data,
                        sizeof(init_data), initial_proof);
    if (ret)
        return ret;

    /* Now acquire the spinlock to insert the entry */
    spin_lock(&g_trust_ape.lock);

    /* Check for duplicate */
    entry = ape_find(subject_id);
    if (entry) {
        spin_unlock(&g_trust_ape.lock);
        memzero_explicit(initial_proof, TRUST_PROOF_SIZE);
        return -EEXIST;
    }

    /* Allocate slot */
    if (g_trust_ape.count >= TRUST_APE_MAX_ENTITIES) {
        /*
         * Pool exhaustion: no created_at field available for LRU eviction.
         * TODO: Add created_at to trust_ape_entry_t and implement LRU
         * eviction here instead of failing. For now, last_proof_ts in the
         * proof state could serve as a proxy, but evicting actively-used
         * entries is dangerous — better to let callers clean up stale
         * entities explicitly via trust_ape_destroy_entity().
         */
        spin_unlock(&g_trust_ape.lock);
        memzero_explicit(initial_proof, TRUST_PROOF_SIZE);
        pr_warn("trust_ape: proof pool exhausted (%d/%d entities), "
                "cannot create entity for subject %u\n",
                g_trust_ape.count, TRUST_APE_MAX_ENTITIES, subject_id);
        return -ENOSPC;
    }

    entry = &g_trust_ape.entries[g_trust_ape.count];
    memset(entry, 0, sizeof(*entry));
    entry->subject_id = subject_id;
    spin_lock_init(&entry->lock);

    /* Write seed (write-once — will never be exposed to userspace) */
    memcpy(entry->state.seed, local_seed, TRUST_SEED_SIZE);
    entry->state.seed_set = 1;

    /* Set nonce */
    entry->state.nonce = nonce;

    /* Copy the pre-computed proof into the entry */
    memcpy(entry->state.proof, initial_proof, TRUST_PROOF_SIZE);
    entry->state.proof_valid = 1;
    entry->state.chain_broken = 0;
    entry->state.chain_length = 0;
    entry->state.hash_cfg = derive_hash_cfg(entry->state.proof);
    entry->state.last_proof_ts = ts;

    g_trust_ape.count++;
    spin_unlock(&g_trust_ape.lock);

    /* Securely zero temporary proof material */
    memzero_explicit(initial_proof, TRUST_PROOF_SIZE);
    memzero_explicit(local_seed, TRUST_SEED_SIZE);

    pr_info("trust_ape: created proof chain for subject %u (chain_length=0)\n",
            subject_id);
    return 0;
}

/*
 * Destroy a proof chain entity. The entire proof state is zeroed,
 * making the proof chain irrecoverable.
 */
int trust_ape_destroy_entity(u32 subject_id)
{
    trust_ape_entry_t *entry;
    int idx;

    spin_lock(&g_trust_ape.lock);
    entry = ape_find(subject_id);
    if (!entry) {
        spin_unlock(&g_trust_ape.lock);
        return -ENOENT;
    }

    /* Securely zero all proof material */
    memzero_explicit(&entry->state, sizeof(entry->state));

    /* Compact array */
    idx = entry - g_trust_ape.entries;
    if (idx < g_trust_ape.count - 1) {
        memmove(&g_trust_ape.entries[idx],
                &g_trust_ape.entries[idx + 1],
                sizeof(trust_ape_entry_t) * (g_trust_ape.count - idx - 1));
    }
    g_trust_ape.count--;
    spin_unlock(&g_trust_ape.lock);

    pr_info("trust_ape: destroyed proof chain for subject %u\n", subject_id);
    return 0;
}

/*
 * Consume the current proof and generate the next one.
 *
 * This is the core APE operation — it implements the self-consuming proof:
 *   1. Atomically read current proof Pn (and zero the register)
 *   2. Derive hash config from Pn
 *   3. Increment monotonic nonce
 *   4. Compute Pn+1 = Hcfg(n)(Pn || Rn || SEED || NONCEn || TSn)
 *   5. Store Pn+1 as the new proof
 *
 * Returns 0 on success, -EINVAL if chain is broken, -ENOENT if not found.
 * proof_out receives a copy of the OLD proof Pn (for the caller to verify).
 */
int trust_ape_consume_proof(u32 subject_id, const u8 *request, u32 req_len,
                             u8 *proof_out)
{
    trust_ape_entry_t *entry;
    u8 consumed_proof[TRUST_PROOF_SIZE];
    u8 seed_copy[TRUST_SEED_SIZE];
    u8 new_proof[TRUST_PROOF_SIZE];
    u8 hash_input[TRUST_PROOF_SIZE + 256 + TRUST_SEED_SIZE + 8 + 8];
    u32 input_len;
    u32 hash_cfg;
    u64 nonce_copy;
    u64 ts;
    int ret;

    spin_lock(&g_trust_ape.lock);
    entry = ape_find(subject_id);
    if (!entry) {
        spin_unlock(&g_trust_ape.lock);
        return -ENOENT;
    }

    spin_lock(&entry->lock);
    spin_unlock(&g_trust_ape.lock);

    /* Check proof chain integrity */
    if (entry->state.chain_broken || !entry->state.proof_valid) {
        spin_unlock(&entry->lock);
        return -EINVAL;
    }

    /* === ATOMIC READ-AND-ZERO of proof register === */
    /* Step 1: Copy current proof Pn */
    memcpy(consumed_proof, entry->state.proof, TRUST_PROOF_SIZE);
    /* Step 2: Zero the proof register (consumed) */
    memzero_explicit(entry->state.proof, TRUST_PROOF_SIZE);
    entry->state.proof_valid = 0;

    /* Copy seed and increment nonce under lock — needed for hash input */
    memcpy(seed_copy, entry->state.seed, TRUST_SEED_SIZE);
    entry->state.nonce++;
    nonce_copy = entry->state.nonce;

    /* Release spinlock BEFORE crypto operations (which can sleep) */
    spin_unlock(&entry->lock);

    /* Return old proof to caller if requested */
    if (proof_out)
        memcpy(proof_out, consumed_proof, TRUST_PROOF_SIZE);

    /* Derive hash config from consumed proof (Theorem 3) */
    hash_cfg = derive_hash_cfg(consumed_proof);

    /* Build hash input: Pn || Rn || SEED || NONCEn || TSn */
    input_len = 0;
    memcpy(hash_input + input_len, consumed_proof, TRUST_PROOF_SIZE);
    input_len += TRUST_PROOF_SIZE;

    if (request && req_len > 0) {
        u32 copy_len = req_len < 256 ? req_len : 256;
        memcpy(hash_input + input_len, request, copy_len);
        input_len += copy_len;
    }

    memcpy(hash_input + input_len, seed_copy, TRUST_SEED_SIZE);
    input_len += TRUST_SEED_SIZE;

    memcpy(hash_input + input_len, &nonce_copy, 8);
    input_len += 8;

    ts = trust_get_timestamp();
    memcpy(hash_input + input_len, &ts, 8);
    input_len += 8;

    /* Compute Pn+1 = Hcfg(n)(input) — outside any lock (can sleep) */
    ret = compute_proof(hash_cfg, hash_input, input_len, new_proof);

    /* Securely zero temporary buffers */
    memzero_explicit(consumed_proof, TRUST_PROOF_SIZE);
    memzero_explicit(seed_copy, TRUST_SEED_SIZE);
    memzero_explicit(hash_input, sizeof(hash_input));

    /* Re-acquire locks to write results back */
    spin_lock(&g_trust_ape.lock);
    entry = ape_find(subject_id);
    if (!entry) {
        /* Entity was destroyed while we were computing — nothing to update */
        spin_unlock(&g_trust_ape.lock);
        memzero_explicit(new_proof, TRUST_PROOF_SIZE);
        return -ENOENT;
    }

    spin_lock(&entry->lock);
    spin_unlock(&g_trust_ape.lock);

    if (ret) {
        /* Hash computation failed — proof chain is broken */
        entry->state.chain_broken = 1;
        spin_unlock(&entry->lock);
        memzero_explicit(new_proof, TRUST_PROOF_SIZE);
        pr_err("trust_ape: proof chain BROKEN for subject %u (hash failed)\n",
               subject_id);
        return ret;
    }

    /* Store new proof and update state */
    memcpy(entry->state.proof, new_proof, TRUST_PROOF_SIZE);
    entry->state.proof_valid = 1;
    entry->state.chain_length++;
    entry->state.hash_cfg = derive_hash_cfg(entry->state.proof);
    entry->state.last_proof_ts = ts;

    spin_unlock(&entry->lock);
    memzero_explicit(new_proof, TRUST_PROOF_SIZE);
    return 0;
}

/*
 * Verify that a subject's proof chain is intact.
 * Returns 0 if valid, -EINVAL if broken, -ENOENT if not found.
 */
int trust_ape_verify_chain(u32 subject_id)
{
    trust_ape_entry_t *entry;
    int ret;

    spin_lock(&g_trust_ape.lock);
    entry = ape_find(subject_id);
    if (!entry) {
        spin_unlock(&g_trust_ape.lock);
        return -ENOENT;
    }

    spin_lock(&entry->lock);
    spin_unlock(&g_trust_ape.lock);

    if (entry->state.chain_broken)
        ret = -EINVAL;
    else if (!entry->state.proof_valid)
        ret = -EINVAL;
    else if (!entry->state.seed_set)
        ret = -EINVAL;
    else
        ret = 0;

    spin_unlock(&entry->lock);
    return ret;
}

/*
 * Get the current monotonic nonce for a subject.
 */
int trust_ape_get_nonce(u32 subject_id, u64 *nonce_out)
{
    trust_ape_entry_t *entry;
    u64 nonce;

    spin_lock(&g_trust_ape.lock);
    entry = ape_find(subject_id);
    if (!entry) {
        spin_unlock(&g_trust_ape.lock);
        return -ENOENT;
    }

    /* Copy while holding lock — entry may be invalidated after unlock */
    nonce = entry->state.nonce;
    spin_unlock(&g_trust_ape.lock);

    *nonce_out = nonce;
    return 0;
}

/*
 * Get the proof chain length for a subject.
 */
int trust_ape_get_chain_length(u32 subject_id, u32 *length_out)
{
    trust_ape_entry_t *entry;
    u32 length;

    spin_lock(&g_trust_ape.lock);
    entry = ape_find(subject_id);
    if (!entry) {
        spin_unlock(&g_trust_ape.lock);
        return -ENOENT;
    }

    /* Copy while holding lock — entry may be invalidated after unlock */
    length = entry->state.chain_length;
    spin_unlock(&g_trust_ape.lock);

    *length_out = length;
    return 0;
}
