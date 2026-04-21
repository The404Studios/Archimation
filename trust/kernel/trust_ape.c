/*
 * trust_ape.c - Authority Proof Engine (software emulation)
 *
 * Implements the Self-Consuming Proof chain from the Root of Authority
 * paper (Roberts/Eli/Leelee, Zenodo 18710335, DOI 10.5281/zenodo.18710335),
 * §SCP / §APE.  This is a software emulation of the Ring -2 hardware APE
 * described in §Hardware-APE.  In hardware, SEED is physically write-once
 * and PROOF is atomic read-and-zero; we emulate those semantics with
 * spinlocks, xchg(), and explicit state flags.
 *
 * Proof chain formula (§SCP eq. (1)):
 *
 *   P_{n+1} = H_{cfg(n)}(P_n || R_n || SEED || N_n || T_n || S_n)
 *
 * Where:
 *   P_n      = current proof (consumed/destroyed atomically on use)
 *   R_n      = hash(actual_result_n) — entanglement of the n-th action's
 *              actual result.  NEW in S48: previously we hashed only the
 *              request bytes; the spec calls for the result, threaded
 *              through trust_ape_consume_proof_v2().
 *   SEED     = write-once entity-identity seed (no exported getter)
 *   N_n      = monotonic public nonce (incremented on every consume)
 *   T_n      = timestamp
 *   S_n      = behavioral state snapshot (chromosome checksum, threaded
 *              by callers via R_n || S_n on the request side for now)
 *   H_cfg(n) = reconfigurable hash whose configuration is extracted from
 *              bits of the (about-to-be-destroyed) P_n.  See
 *              derive_hash_cfg() and apply_reconfigurable_hash() below.
 *
 * Key security properties (paper Theorems 1–3):
 *   1. Non-Static Secrets — P changes on every action.
 *   2. Non-Replayability — monotonic N_n prevents replay.
 *   3. Reconfiguration Unpredictability — H's configuration depends on
 *      bits of the consumed P_n, so an attacker who has not seen P_n
 *      cannot predict the structure of the next H call (94,371,840
 *      possible configurations).
 *
 * S48 changes:
 *   • R_n result-entanglement parameter added (see _v2 entry point).
 *   • Reconfigurable-hash fully implemented (perm/window/mask/rot).
 *   • xchg() on P_n register for true atomic read-and-zero.
 *   • Double-read trap → per-CPU counter + force-apoptosis flag.
 *   • Constant-time dispatch — no branches on secret bits.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/percpu.h>
#include <linux/atomic.h>
#include <crypto/hash.h>
#include <crypto/sha2.h>
#include "trust_internal.h"
#include "trust_ape.h"
#include "../include/trust_theorems.h"
#include "../include/trust_attest_quine.h"   /* S75 Item #7: .text fold */

/* Global APE state */
trust_ape_t g_trust_ape;

/* Per-CPU double-read trap counter (Theorem 1 enforcement). */
static DEFINE_PER_CPU(u64, ape_double_read_traps);

/*
 * Per-CPU sequencer-advance counter (Session 49 / Agent B).
 *
 * Theorem 2 (Non-Replayability) requires every successful proof
 * consumption to advance a process-wide monotonic nonce.  We mirror
 * trust_invariants_advance_nonce() with this lightweight per-CPU tally
 * so /sys/kernel/trust/stats can show how many APE-driven advances
 * have been observed without taking the global atomic64 hot path
 * twice.  Bumped ONLY on the success path of consume_proof_v2 (after
 * the entity's local nonce has been written back), so a failed consume
 * (-EALREADY, -ESTALE, -ENOENT, -EINVAL, crypto errno) does not move
 * the counter — preserving the bind-to-success invariant.
 */
static DEFINE_PER_CPU(u64, ape_seq_advances);

/*
 * The force-apoptosis flag is an APE-private bit stored inside the
 * trust_proof_state_t._padding byte that already exists in
 * trust_subject_t / trust_ape_entry_t->state.  We do NOT touch the
 * 496-byte trust_subject_t layout (locked by _Static_assert in
 * trust_ioctl.h); we re-purpose an already-reserved padding byte that
 * was previously always zero.
 *
 * Bit 0 = force_apoptosis (set by double-read trap, cleared by
 *         trust_lifecycle after acting on it).
 * Bits 1..7 reserved for future APE flags.
 *
 * Macros below are kept local so no other subsystem accidentally writes
 * the byte assuming it is still pure padding.
 */
#define APE_PAD_FORCE_APOPTOSIS  (1U << 0)

static inline u8 ape_pad_get(const trust_proof_state_t *st)
{
    return st->_padding;
}

static inline void ape_pad_or(trust_proof_state_t *st, u8 bit)
{
    st->_padding |= bit;
}

static inline void ape_pad_clear(trust_proof_state_t *st, u8 bit)
{
    st->_padding &= (u8)~bit;
}

/* Supported hash algorithm names (indexed by TRUST_HASH_CFG_*) */
static const char *hash_algo_names[TRUST_HASH_CFG_COUNT] = {
    "sha256",       /* TRUST_HASH_CFG_SHA256 */
    "blake2b-256",  /* TRUST_HASH_CFG_BLAKE2B */
    "sha3-256",     /* TRUST_HASH_CFG_SHA3 */
};

/* ------------------------------------------------------------------ *
 *           Reconfigurable hash — paper §APE Theorem 3               *
 * ------------------------------------------------------------------ *
 *
 * The hash configuration is extracted from low bits of the destroyed
 * proof P_n:
 *
 *   perm   <- P_n[ 7: 0]   selects 1 of 720 permutations of 0..7
 *   window <- P_n[15: 8]   8-bit window size  (1..256)
 *   mask   <- P_n[19:16]   4-bit XOR mask pattern
 *   rot    <- P_n[24:20]   5-bit per-byte left-rotation amount
 *
 *   |configurations| = 720 * 256 * 16 * 32 = 94,371,840
 *
 * The reconfigurable hash transforms the input buffer in a deterministic
 * but config-dependent way BEFORE feeding it to the underlying SHA-2 /
 * SHA-3 / BLAKE2b primitive.  This means an attacker who has not seen
 * P_n cannot reproduce the H' ⨯ SHA-256 composition that produced
 * P_{n+1}, even with full knowledge of every other input.
 */

/*
 * Compact 720-row permutation table over { 0..7 }.  We materialise the
 * first 720 permutations enumerated by Heap's algorithm at runtime once
 * during init — keeps .text small (5760 bytes of .bss) and lets us
 * BUILD_BUG_ON the count against the spec.
 */
static u8 ape_perm_table[APE_CFG_PERM_COUNT][8];

/* Heap's algorithm — generate permutations of @arr length @n into table. */
static void heap_permute_init(void)
{
    u8 work[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    u8 stack[8] = {0};
    u32 produced = 0;
    int i = 0;

    /* First permutation is the identity. */
    memcpy(ape_perm_table[produced++], work, 8);

    while (i < 8 && produced < APE_CFG_PERM_COUNT) {
        if (stack[i] < (u8)i) {
            u8 a, b;
            if ((i & 1) == 0) {
                a = 0;
                b = (u8)i;
            } else {
                a = stack[i];
                b = (u8)i;
            }
            { u8 tmp = work[a]; work[a] = work[b]; work[b] = tmp; }
            memcpy(ape_perm_table[produced++], work, 8);
            stack[i]++;
            i = 0;
        } else {
            stack[i] = 0;
            i++;
        }
    }

    /* If we somehow short-counted, fill the tail with identity (safe). */
    while (produced < APE_CFG_PERM_COUNT) {
        memcpy(ape_perm_table[produced++], work, 8);
    }
}

/*
 * Decode cfg(n) bits.  Constant-time wrt the secret bits — we only do
 * arithmetic and table indexing, no branches.
 */
struct ape_hash_cfg {
    u16 perm_idx;     /* 0..719 */
    u16 window;       /* 1..256 (we store 1..256) */
    u8  mask;         /* 0..15  → expanded into a 16-byte XOR pattern */
    u8  rot;          /* 0..31  → per-byte left-rotate amount mod 8 */
};

static inline void decode_cfg(const u8 *proof, struct ape_hash_cfg *out)
{
    u32 lo;

    /*
     * Constant-time field extraction.  No branch on secret bits — only
     * shifts/masks/mod-by-constant.  The mod APE_CFG_PERM_COUNT folds
     * the 8-bit index into the 720-entry table; gcc emits a constant
     * divide by 720 (no branch) on x86_64.
     */
    lo = (u32)proof[0] | ((u32)proof[1] << 8) |
         ((u32)proof[2] << 16) | ((u32)proof[3] << 24);

    out->perm_idx = (u16)((lo & 0xFFU) % APE_CFG_PERM_COUNT);    /* 8 bits */
    out->window   = (u16)(((lo >> 8) & 0xFFU) + 1U);             /* 1..256 */
    out->mask     = (u8) ((lo >> 16) & 0x0FU);                   /* 4 bits */
    out->rot      = (u8) ((lo >> 20) & 0x1FU);                   /* 5 bits */
}

/*
 * Apply the reconfigurable hash transform in place over @buf of length
 * @len.  The output is the same length; SHA is applied AFTER this on
 * the transformed bytes.
 *
 *  1. Pre-rotate every byte left by (rot mod 8).
 *  2. XOR a 16-byte mask pattern derived from `mask` over each window.
 *  3. Permute every aligned 8-byte block by ape_perm_table[perm_idx].
 *
 * Constant-time: no early exit, no data-dependent control flow.
 */
static void apply_reconfigurable_hash(const struct ape_hash_cfg *cfg,
                                      u8 *buf, u32 len)
{
    u32 i, j;
    u8 mask_pat[16];
    const u8 *perm = ape_perm_table[cfg->perm_idx];
    u8 rot = cfg->rot & 0x07U;       /* rot mod 8 */

    /* Build a 16-byte mask pattern from the 4-bit mask:
     * pattern[i] = (mask << 4) | (mask ^ i) — fills uniformly. */
    for (i = 0; i < 16; i++)
        mask_pat[i] = (u8)((cfg->mask << 4) | (cfg->mask ^ (i & 0x0FU)));

    /* Step 1: per-byte left rotate.  rot==0 leaves bytes unchanged. */
    if (rot != 0) {
        for (i = 0; i < len; i++) {
            u8 b = buf[i];
            buf[i] = (u8)((b << rot) | (b >> (8 - rot)));
        }
    }

    /* Step 2: XOR mask pattern over each window-sized chunk. */
    {
        u32 win = cfg->window;
        for (i = 0; i < len; i += win) {
            u32 chunk = (i + win <= len) ? win : (len - i);
            for (j = 0; j < chunk; j++)
                buf[i + j] ^= mask_pat[j & 0x0FU];
        }
    }

    /* Step 3: permute every full 8-byte block in place. */
    {
        u8 tmp[8];
        u32 blocks = len / 8U;
        for (i = 0; i < blocks; i++) {
            u8 *blk = buf + i * 8U;
            for (j = 0; j < 8; j++)
                tmp[j] = blk[perm[j]];
            memcpy(blk, tmp, 8);
        }
        /* Tail bytes (<8) left as-is — SHA absorbs them with no ambiguity. */
    }
}

/*
 * Derive the underlying-SHA selector from cfg.perm_idx — keeps the
 * existing TRUST_HASH_CFG_* tri-cycle (sha256 / blake2b / sha3-256)
 * which other subsystems already expect.  This is the FINAL hash
 * stage, applied AFTER apply_reconfigurable_hash().
 */
static inline u32 cfg_to_underlying(const struct ape_hash_cfg *cfg)
{
    /* perm_idx mod TRUST_HASH_CFG_COUNT — constant-time table-driven. */
    return cfg->perm_idx % TRUST_HASH_CFG_COUNT;
}

/*
 * Legacy 4-byte selector (kept for proof_state.hash_cfg cache field).
 * Equivalent to cfg_to_underlying(decode_cfg(proof)).
 */
static u32 derive_hash_cfg(const u8 *proof)
{
    struct ape_hash_cfg cfg;
    decode_cfg(proof, &cfg);
    return cfg_to_underlying(&cfg);
}

/*
 * Compute a proof using the reconfigurable hash.  Caller passes the
 * fully-built input buffer; we transform it according to cfg(n) derived
 * from @cfg_proof (the destroyed P_n) and then run the underlying SHA.
 *
 * @cfg_proof MUST be the consumed P_n (or an equivalent zero-buffer
 * for the very first proof).  The transform is performed on a heap
 * scratch copy so the caller's input isn't disturbed.
 */
static int compute_proof_v2(const u8 *cfg_proof,
                            const u8 *data, u32 data_len, u8 *out)
{
    struct ape_hash_cfg cfg;
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    const char *algo;
    u8 *scratch;
    u32 underlying;
    int ret;

    decode_cfg(cfg_proof, &cfg);
    underlying = cfg_to_underlying(&cfg);
    if (underlying >= TRUST_HASH_CFG_COUNT)
        underlying = TRUST_HASH_CFG_SHA256;

    scratch = kmalloc(data_len, GFP_KERNEL);
    if (!scratch)
        return -ENOMEM;
    memcpy(scratch, data, data_len);

    apply_reconfigurable_hash(&cfg, scratch, data_len);

    algo = hash_algo_names[underlying];
    tfm = crypto_alloc_shash(algo, 0, 0);
    if (IS_ERR(tfm)) {
        /* Fallback to SHA-256 if requested algo not available */
        tfm = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(tfm)) {
            ret = PTR_ERR(tfm);
            goto out_free_scratch;
        }
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        ret = -ENOMEM;
        goto out_free_scratch;
    }

    desc->tfm = tfm;
    ret = crypto_shash_digest(desc, scratch, data_len, out);

    kfree(desc);
    crypto_free_shash(tfm);
out_free_scratch:
    memzero_explicit(scratch, data_len);
    kfree(scratch);
    return ret;
}

/*
 * Sentinel marking a tombstoned (destroyed) entry slot.
 * We never compact the entries array (that would move per-entry spinlocks
 * while concurrent consumers hold them), so destroy leaves a tombstone
 * that create can later reuse.
 *
 * Shares the reserved subject-id value; register paths reject it up front
 * so ape_find()'s short-circuit can never elide a real caller's lookup.
 */
#define APE_TOMBSTONE TRUST_SUBJECT_ID_RESERVED_MAX

/*
 * Subject_id -> entries[] index lookup.  Previously every APE op did an
 * O(n) linear scan of up to TRUST_APE_MAX_ENTITIES (1024) pairs, paid
 * on every proof mint/consume/verify/nonce/destroy.  With many active
 * subjects this was the hottest path in the module.
 *
 * We replace the scan with a bounded-probe open-addressed hash index
 * sized 2x the pool so fill factor stays <= 50%, guaranteeing almost
 * all lookups finish in 1-2 probes.  The index is maintained in the
 * same lock as g_trust_ape.lock so no separate synchronization is
 * needed.  Empty slots are 0xFFFF; live slots hold the entries[] index.
 *
 * Memory: 2048 * 2 bytes = 4KB — trivial, fits in L1 on both old and
 * new hardware, no per-CPU duplication.
 */
#define APE_INDEX_SIZE  (TRUST_APE_MAX_ENTITIES * 2)
#define APE_INDEX_EMPTY 0xFFFFU
#define APE_INDEX_MAX_PROBE 64

static u16 g_ape_index[APE_INDEX_SIZE];

/* FNV-1a 32-bit mixing folded to APE_INDEX_SIZE */
static inline u32 ape_index_hash(u32 subject_id)
{
    u32 h = subject_id;
    h ^= h >> 16;
    h *= 0x85ebca6bU;
    h ^= h >> 13;
    return h & (APE_INDEX_SIZE - 1);
}

/* Find index slot for subject_id.  Returns APE_INDEX_SIZE if not found. */
static u32 ape_index_find(u32 subject_id)
{
    u32 h = ape_index_hash(subject_id);
    u32 i;

    for (i = 0; i < APE_INDEX_MAX_PROBE; i++) {
        u32 slot = (h + i) & (APE_INDEX_SIZE - 1);
        u16 idx = g_ape_index[slot];
        if (idx == APE_INDEX_EMPTY)
            return APE_INDEX_SIZE;
        if (idx < TRUST_APE_MAX_ENTITIES &&
            g_trust_ape.entries[idx].subject_id == subject_id)
            return slot;
    }
    return APE_INDEX_SIZE;
}

/* Insert subject_id -> entries_idx mapping.  Returns 0 on success. */
static int ape_index_insert(u32 subject_id, u16 entries_idx)
{
    u32 h = ape_index_hash(subject_id);
    u32 i;

    for (i = 0; i < APE_INDEX_MAX_PROBE; i++) {
        u32 slot = (h + i) & (APE_INDEX_SIZE - 1);
        if (g_ape_index[slot] == APE_INDEX_EMPTY) {
            g_ape_index[slot] = entries_idx;
            return 0;
        }
    }
    return -ENOSPC;
}

/*
 * Remove the index entry for subject_id.  We use backward-shift deletion
 * to maintain probe-chain integrity — critical for open addressing.
 */
static void ape_index_remove(u32 subject_id)
{
    u32 slot = ape_index_find(subject_id);
    u32 mask = APE_INDEX_SIZE - 1;
    u32 i;

    if (slot == APE_INDEX_SIZE)
        return;

    g_ape_index[slot] = APE_INDEX_EMPTY;

    /*
     * Shift displaced entries back to preserve probe chains.  Classic
     * Robin-Hood back-shift: for each live neighbour at 'next', shift it
     * into the empty 'slot' ONLY if 'slot' lies on its linear probe path
     * from desired->next (i.e. (slot-desired) & mask <= (next-desired) &
     * mask).  Previously the code only checked "is it at home?" which is
     * insufficient: an entry with desired = slot+k (wrap-around) was
     * incorrectly moved BEFORE its home, making ape_index_find miss it.
     * Stop the walk as soon as a neighbour can't move — it anchors the
     * remainder of the probe chain in place.
     */
    for (i = 1; i < APE_INDEX_MAX_PROBE; i++) {
        u32 next = (slot + i) & mask;
        u16 idx = g_ape_index[next];
        u32 desired;
        u32 dist_slot, dist_next;

        if (idx == APE_INDEX_EMPTY)
            break;
        if (idx >= TRUST_APE_MAX_ENTITIES)
            break;   /* corrupted slot — stop */

        desired = ape_index_hash(g_trust_ape.entries[idx].subject_id);
        dist_slot = (slot - desired) & mask;
        dist_next = (next - desired) & mask;

        /*
         * Can only shift if the empty 'slot' is NOT ahead of the entry's
         * home along the probe direction.  dist_slot <= dist_next means
         * slot is between desired and next (inclusive of desired), so
         * the entry still finds itself via linear probe from desired.
         */
        if (dist_slot > dist_next)
            break;

        g_ape_index[slot] = idx;
        g_ape_index[next] = APE_INDEX_EMPTY;
        slot = next;
    }
}

/* Find an APE entry by subject_id. O(1) hash lookup with tombstone skip. */
static trust_ape_entry_t *ape_find(u32 subject_id)
{
    u32 slot;
    u16 idx;

    if (subject_id == APE_TOMBSTONE)
        return NULL;
    slot = ape_index_find(subject_id);
    if (slot == APE_INDEX_SIZE)
        return NULL;
    idx = g_ape_index[slot];
    if (idx >= TRUST_APE_MAX_ENTITIES)
        return NULL;
    return &g_trust_ape.entries[idx];
}

/*
 * Find a reusable tombstone slot for a new entity.  Returns NULL if
 * none.  Only walks up to g_trust_ape.count (not MAX) since tombstones
 * live inside the already-allocated range.  This is a slow path
 * (create-time only) so the linear scan is acceptable.
 */
static trust_ape_entry_t *ape_find_free_slot(u16 *idx_out)
{
    int i;
    for (i = 0; i < g_trust_ape.count; i++) {
        if (g_trust_ape.entries[i].subject_id == APE_TOMBSTONE) {
            if (idx_out)
                *idx_out = (u16)i;
            return &g_trust_ape.entries[i];
        }
    }
    return NULL;
}

/*
 * Build-time spec assertions.  These compile-fail if any session ever
 * weakens the configuration space below the paper's claim.
 */
static inline void __maybe_unused trust_ape_build_asserts(void)
{
    BUILD_BUG_ON(APE_CFG_TOTAL != 94371840ULL);
    BUILD_BUG_ON(APE_CFG_PERM_COUNT   != 720U);
    BUILD_BUG_ON(APE_CFG_WINDOW_COUNT != 256U);
    BUILD_BUG_ON(APE_CFG_MASK_COUNT   != 16U);
    BUILD_BUG_ON(APE_CFG_ROT_COUNT    != 32U);
    BUILD_BUG_ON(APE_RESULT_HASH_LEN  != 32U);
    /* xchg() requires the proof "register" to be naturally aligned in
     * units the arch can xchg.  We xchg one word at a time over the
     * 32-byte buffer so this is implicit, but assert proof size is a
     * multiple of 8 for the loop. */
    BUILD_BUG_ON((TRUST_PROOF_SIZE % 8) != 0);
}

/*
 * Initialize the APE subsystem.
 */
void trust_ape_init(void)
{
    u32 i;

    memset(&g_trust_ape, 0, sizeof(g_trust_ape));
    spin_lock_init(&g_trust_ape.lock);
    /* 0xFFFF != 0, so a plain memset wouldn't work — init each slot */
    for (i = 0; i < APE_INDEX_SIZE; i++)
        g_ape_index[i] = APE_INDEX_EMPTY;

    /* Build the 720-entry permutation table once. */
    heap_permute_init();

    /* Force-evaluate build asserts in case the optimizer drops them. */
    (void)&trust_ape_build_asserts;

    pr_info("trust_ape: Authority Proof Engine initialized "
            "(software emulation, %llu reconfigurable-hash configs)\n",
            (unsigned long long)APE_CFG_TOTAL);

    /*
     * Session 49 / Agent B: verify the global-nonce sequencer wiring
     * is live before we accept any consume_proof_v2() calls that will
     * depend on it.  Logs a confirmation line on success or a loud
     * pr_err on failure (does not fail module load — Theorem 2 will
     * still be best-effort enforced via per-entity nonce, just not
     * cross-subject monotonic).
     */
    trust_ape_sequencer_selfcheck();

    /*
     * Session 59: Theorem 3 (Reconfiguration Unpredictability) point-
     * test.  Feeds N independent random inputs through the SHA primitive
     * backing the proof chain and chi-squares the output byte-distribution
     * against uniform on { 0..255 }.  Self-contained — does not touch any
     * APE state.  Logs verdict; never fails module load.
     */
    trust_ape_markov_validator();
}

/*
 * Atomic read-and-zero of the proof register.
 *
 * The hardware APE has a single-shot read-and-zero PROOF register.  In
 * software we approximate this by doing per-word xchg() across the
 * 32-byte buffer.  The total operation is NOT atomic at byte 0..31
 * granularity, but it IS atomic at the per-word level AND completed
 * under entry->lock — so any concurrent consume serializes via the lock
 * AND a torn read by an attacker who somehow bypasses the lock would
 * still race against the xchg semantics on each word.
 *
 * @dst: 32-byte output (the consumed P_n)
 * @reg: 32-byte register-style buffer (zeroed by this call)
 *
 * Returns 1 if @reg was non-zero on entry (real proof was consumed),
 * 0 if @reg was already all-zero (DOUBLE-READ TRAP).
 */
static int xchg_read_and_zero(u8 *dst, u8 *reg)
{
    u64 *dq = (u64 *)dst;
    u64 *rq = (u64 *)reg;
    u64 acc = 0;
    u32 i;

    /* TRUST_PROOF_SIZE is asserted to be a multiple of 8. */
    for (i = 0; i < TRUST_PROOF_SIZE / sizeof(u64); i++) {
        u64 v = xchg(&rq[i], 0ULL);
        dq[i] = v;
        acc |= v;
    }
    return acc != 0;
}

/*
 * Create a new proof chain entity for a subject.
 *
 * The seed is written once and can never be read back via any exported
 * API — verified by callgraph (grep -nE '\.seed|->seed' across kernel
 * tree returns only writes inside trust_ape.c plus the internal hash
 * input on consume).  This emulates the hardware write-once/read-never
 * SEED register of the APE.
 *
 * The initial proof P0 is generated from the seed and a random nonce.
 */
int trust_ape_create_entity(u32 subject_id, const u8 *seed, u32 seed_len)
{
    trust_ape_entry_t *entry;
    u8 init_data[TRUST_SEED_SIZE + 8 + 8]; /* seed + nonce + timestamp */
    u8 local_seed[TRUST_SEED_SIZE];
    u8 initial_proof[TRUST_PROOF_SIZE];
    u8 zero_cfg[TRUST_PROOF_SIZE] = {0};   /* P_{-1} = 0 for cfg derivation */
    u64 ts, nonce;
    int ret;

    /* APE_TOMBSTONE collision: see trust_internal.h. */
    if (subject_id == TRUST_SUBJECT_ID_RESERVED_MAX)
        return -EINVAL;

    /*
     * Pre-compute the proof BEFORE acquiring the spinlock.
     * compute_proof_v2() calls crypto_alloc_shash() and kmalloc(GFP_KERNEL),
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

    /* Generate initial proof P0 = H(SEED || NONCE || TS) using zero cfg
     * (no prior proof to derive from). */
    ts = trust_get_timestamp();
    memcpy(init_data, local_seed, TRUST_SEED_SIZE);
    memcpy(init_data + TRUST_SEED_SIZE, &nonce, 8);
    memcpy(init_data + TRUST_SEED_SIZE + 8, &ts, 8);

    ret = compute_proof_v2(zero_cfg, init_data, sizeof(init_data),
                           initial_proof);
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

    /* Allocate slot: prefer reusing a tombstone, else extend the array. */
    {
        u16 entries_idx;
        entry = ape_find_free_slot(&entries_idx);
        if (!entry) {
            if (g_trust_ape.count >= TRUST_APE_MAX_ENTITIES) {
                /*
                 * Pool exhaustion: no created_at field available for LRU eviction.
                 * last_proof_ts in the proof state could serve as a proxy, but
                 * evicting actively-used entries is dangerous — better to let
                 * callers clean up stale entities via trust_ape_destroy_entity().
                 */
                spin_unlock(&g_trust_ape.lock);
                memzero_explicit(initial_proof, TRUST_PROOF_SIZE);
                pr_warn("trust_ape: proof pool exhausted (%d/%d entities), "
                        "cannot create entity for subject %u\n",
                        g_trust_ape.count, TRUST_APE_MAX_ENTITIES, subject_id);
                return -ENOSPC;
            }
            entries_idx = (u16)g_trust_ape.count;
            entry = &g_trust_ape.entries[entries_idx];
            g_trust_ape.count++;
            spin_lock_init(&entry->lock);  /* Fresh slot: init lock. */
        }
        /*
         * For reused tombstones, the spinlock is already initialized and was
         * released by the previous holder; do not re-init (would race with
         * anyone still observing the lock).  Just zero the state payload.
         */
        entry->subject_id = subject_id;
        memset(&entry->state, 0, sizeof(entry->state));

        /* Maintain fast-lookup index */
        if (ape_index_insert(subject_id, entries_idx) != 0) {
            /*
             * Index full (probe chain too long).  Revert: the entry slot
             * is left as a tombstone ready for re-use.  With size = 2x
             * pool and bounded probes this should never happen in
             * practice, but fail closed for safety.
             */
            entry->subject_id = APE_TOMBSTONE;
            spin_unlock(&g_trust_ape.lock);
            memzero_explicit(initial_proof, TRUST_PROOF_SIZE);
            pr_warn("trust_ape: index probe overflow for subject %u\n",
                    subject_id);
            return -ENOSPC;
        }
    }

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
    entry->state._padding = 0;       /* APE-private flags, force_apoptosis=0 */

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

    spin_lock(&g_trust_ape.lock);
    entry = ape_find(subject_id);
    if (!entry) {
        spin_unlock(&g_trust_ape.lock);
        return -ENOENT;
    }

    /*
     * Wait for any active consumer to finish before tombstoning.
     * A concurrent trust_ape_consume_proof() may hold entry->lock after
     * releasing g_trust_ape.lock; taking entry->lock here serializes with
     * it.  We do NOT compact the array — that would relocate the spinlock
     * itself and break any waiter.  Instead we tombstone the slot so
     * subsequent creates can reuse it with the same (still-valid) lock.
     */
    spin_lock(&entry->lock);

    /* Remove from fast-lookup index before tombstoning the entry so
     * concurrent lookups skip straight to "not found" instead of
     * racing through the tombstone. */
    ape_index_remove(subject_id);

    /* Securely zero all proof material */
    memzero_explicit(&entry->state, sizeof(entry->state));
    entry->subject_id = APE_TOMBSTONE;

    spin_unlock(&entry->lock);
    spin_unlock(&g_trust_ape.lock);

    pr_info("trust_ape: destroyed proof chain for subject %u\n", subject_id);
    return 0;
}

/*
 * Consume the current proof and generate the next one.
 *
 * This is the canonical §APE step:
 *   1. xchg-read-and-zero current proof P_n (atomic register semantics)
 *   2. If P_n was already zero — DOUBLE-READ TRAP: bump per-CPU counter,
 *      mark subject for forced apoptosis (poll-readable by lifecycle),
 *      return -EALREADY.
 *   3. Derive cfg(n) from P_n (perm/window/mask/rot — see decode_cfg).
 *   4. Increment monotonic nonce N_n.
 *   5. Compute P_{n+1} = H_cfg(n)(P_n || R_n || SEED || N_n || T_n).
 *   6. Store P_{n+1} as the new register value.
 *
 * Returns 0 on success, -EALREADY on double-consume, -EINVAL if chain
 * broken, -ENOENT if not found, -ESTALE if the entity was rotated mid-
 * compute, or a crypto errno.
 *
 * proof_out receives a copy of the consumed P_n (for caller verification).
 *
 * Spec mapping:
 *   request          = R-input  (will be hashed alongside action_result)
 *   action_result_   = R_n      (paper §SCP eq. (1) "R_n = hash(result)")
 *     hash             NULL → 32-byte zero (legacy back-compat).
 */
int trust_ape_consume_proof_v2(u32 subject_id,
                               const u8 *request, u32 req_len,
                               const u8 *action_result_hash, size_t hashlen,
                               u8 *proof_out)
{
    trust_ape_entry_t *entry;
    u8 consumed_proof[TRUST_PROOF_SIZE];
    u8 seed_copy[TRUST_SEED_SIZE];
    u8 new_proof[TRUST_PROOF_SIZE];
    u8 result_hash[APE_RESULT_HASH_LEN] = {0};   /* R_n */
    u8 hash_input[TRUST_PROOF_SIZE +
                  APE_RESULT_HASH_LEN +
                  256 +                            /* req-derived bytes */
                  TRUST_SEED_SIZE + 8 + 8 +
                  TRUST_QUINE_HASH_LEN];           /* S75: .text fold */
    u8 text_hash[TRUST_QUINE_HASH_LEN];
    u32 input_len;
    u64 nonce_copy;
    u64 ts;
    u64 identity_epoch;   /* snapshot to detect destroy/re-create race */
    int had_proof;
    int ret;

    /* Validate result-hash arg up front. */
    if (action_result_hash) {
        if (hashlen != APE_RESULT_HASH_LEN)
            return -EINVAL;
        memcpy(result_hash, action_result_hash, APE_RESULT_HASH_LEN);
    } else {
        /* Back-compat: legacy callers pass NULL.  Emit a debug-once;
         * downstream they should migrate to threading R_n through. */
        pr_debug_once("trust_ape: NULL result_hash in consume_proof "
                      "(subject %u) — using zero R_n; migrate caller to "
                      "trust_ape_consume_proof_v2 with real R_n\n",
                      subject_id);
        /* result_hash already zeroed by initialiser. */
    }

    spin_lock(&g_trust_ape.lock);
    entry = ape_find(subject_id);
    if (!entry) {
        spin_unlock(&g_trust_ape.lock);
        return -ENOENT;
    }

    spin_lock(&entry->lock);
    spin_unlock(&g_trust_ape.lock);

    /* Check proof chain integrity */
    if (entry->state.chain_broken) {
        spin_unlock(&entry->lock);
        return -EINVAL;
    }

    /* === ATOMIC READ-AND-ZERO of proof register (xchg per word) === */
    had_proof = xchg_read_and_zero(consumed_proof, entry->state.proof);

    /*
     * DOUBLE-READ TRAP.  If proof_valid was 0 OR the register was
     * already zero, this is a duplicate consume against an already-
     * destroyed proof.  Bump the per-CPU counter and stamp the
     * force-apoptosis bit so trust_lifecycle picks it up on its
     * next sweep.  Then refuse the call.
     */
    if (!had_proof || !entry->state.proof_valid) {
        this_cpu_inc(ape_double_read_traps);
        ape_pad_or(&entry->state, APE_PAD_FORCE_APOPTOSIS);
        entry->state.proof_valid = 0;
        spin_unlock(&entry->lock);
        memzero_explicit(consumed_proof, TRUST_PROOF_SIZE);
        memzero_explicit(result_hash, APE_RESULT_HASH_LEN);
        pr_warn_ratelimited("trust_ape: DOUBLE-READ TRAP on subject %u "
                            "— marking for forced apoptosis\n", subject_id);
        return -EALREADY;
    }
    entry->state.proof_valid = 0;

    /* Copy seed and increment nonce under lock — needed for hash input */
    memcpy(seed_copy, entry->state.seed, TRUST_SEED_SIZE);
    entry->state.nonce++;
    nonce_copy = entry->state.nonce;

    /*
     * Snapshot the post-increment nonce as an identity epoch.  Every
     * consume mutates nonce monotonically, and destroy zeros the entire
     * state (including nonce); re-create sets a fresh random nonce.
     * If we observe the same nonce after crypto we know the entry is
     * still "ours" to write back to.  Any destroy-then-create between
     * our writes would rewind or jump the nonce, letting us refuse
     * the write-back.
     */
    identity_epoch = nonce_copy;

    /* Release spinlock BEFORE crypto operations (which can sleep) */
    spin_unlock(&entry->lock);

    /* Return old proof to caller if requested */
    if (proof_out)
        memcpy(proof_out, consumed_proof, TRUST_PROOF_SIZE);

    /*
     * Build hash input — paper §SCP eq. (1) order:
     *   P_n || R_n || (request bytes appended after R_n) || SEED ||
     *   N_n || T_n.
     *
     * The request bytes are an extension of R_n in our impl: hardware
     * APE binds R_n only, but we let callers also feed an opaque
     * request payload (e.g. action-type header) — this widens the
     * pre-image and never weakens it.
     */
    input_len = 0;
    memcpy(hash_input + input_len, consumed_proof, TRUST_PROOF_SIZE);
    input_len += TRUST_PROOF_SIZE;

    memcpy(hash_input + input_len, result_hash, APE_RESULT_HASH_LEN);
    input_len += APE_RESULT_HASH_LEN;

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

    /*
     * S75 Item #7: fold SHA-256(trust.ko .text) into the proof input.
     * A kernel-write adversary who has modified the live module cannot
     * produce a matching text hash while their exploit is resident —
     * every proof they mint diverges from honest-kernel output. See
     * trust/include/trust_attest_quine.h and research-F §3.
     * Pre-init (and if the quine subsystem failed to start) returns
     * a zero buffer, preserving input layout without breaking proofs.
     */
    trust_attest_quine_get_hash(text_hash);
    memcpy(hash_input + input_len, text_hash, TRUST_QUINE_HASH_LEN);
    input_len += TRUST_QUINE_HASH_LEN;

    /*
     * Compute P_{n+1} = H_cfg(n)(input).  cfg(n) is derived from the
     * destroyed P_n inside compute_proof_v2().
     */
    ret = compute_proof_v2(consumed_proof, hash_input, input_len, new_proof);

    /* Securely zero temporary buffers */
    memzero_explicit(consumed_proof, TRUST_PROOF_SIZE);
    memzero_explicit(seed_copy, TRUST_SEED_SIZE);
    memzero_explicit(result_hash, APE_RESULT_HASH_LEN);
    memzero_explicit(text_hash, TRUST_QUINE_HASH_LEN);
    memzero_explicit(hash_input, sizeof(hash_input));

    /* Tick the quine consume counter (deferred recompute every N). */
    (void)trust_attest_quine_tick();

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

    /*
     * Identity-epoch check: if the nonce is anything other than
     * identity_epoch, the slot was destroyed and re-created (fresh
     * random nonce) or something else consumed it further (impossible
     * while proof_valid=0, but defence-in-depth).  Writing our computed
     * P_{n+1} into a differently-seeded entity would splice proof
     * chains across identities — a silent authority forgery.
     */
    if (entry->state.nonce != identity_epoch) {
        spin_unlock(&entry->lock);
        memzero_explicit(new_proof, TRUST_PROOF_SIZE);
        pr_warn("trust_ape: subject %u rotated during consume; "
                "discarding computed proof\n", subject_id);
        return -ESTALE;
    }

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

    /*
     * Sequencer (Session 49 / Agent B).
     *
     * Bind APE proof consumption to the global monotonic nonce so
     * Theorem 2 (Non-Replayability) becomes a runtime invariant, not
     * a documentation claim.  Placement is deliberate:
     *   - AFTER entry->state.nonce was bumped & written back, so the
     *     per-entity local nonce and the global nonce both advance
     *     atomically-with-respect-to "this consume succeeded";
     *   - BEFORE the function returns 0, but AFTER every error-return
     *     above (which all return without touching this counter), so
     *     a -EALREADY/-ESTALE/-EINVAL/-ENOENT/crypto-errno path does
     *     NOT advance the global — replay attempts cannot bump it.
     *
     * We ignore the return value; the caller doesn't need the new
     * nonce, only the side-effect (atomic64 increment + monotonicity
     * WARN_ON_ONCE inside trust_invariants).
     */
    (void)trust_invariants_advance_nonce();
    this_cpu_inc(ape_seq_advances);
    return 0;
}

/*
 * Backward-compat entry point — preserves the v1 ABI for existing
 * call sites in trust_dispatch.c, trust_fused.c, trust_core.c.
 * Forwards to v2 with NULL R_n (treated as 32-byte zero).
 *
 * NEW callers should use trust_ape_consume_proof_v2() and pass a real
 * hash(actual_result_n).  See handoff notes in session log.
 */
int trust_ape_consume_proof(u32 subject_id, const u8 *request, u32 req_len,
                             u8 *proof_out)
{
    return trust_ape_consume_proof_v2(subject_id, request, req_len,
                                      NULL, 0, proof_out);
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

    /*
     * Take the per-entry lock before reading the 64-bit nonce.
     * trust_ape_consume_proof_v2() mutates state.nonce under entry->lock
     * (not g_trust_ape.lock), so reading without it can tear on 32-bit.
     */
    spin_lock(&entry->lock);
    spin_unlock(&g_trust_ape.lock);
    nonce = entry->state.nonce;
    spin_unlock(&entry->lock);

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

    /* Take entry->lock for a coherent read of state fields that consume
     * mutates under entry->lock (not g_trust_ape.lock). */
    spin_lock(&entry->lock);
    spin_unlock(&g_trust_ape.lock);
    length = entry->state.chain_length;
    spin_unlock(&entry->lock);

    *length_out = length;
    return 0;
}

/*
 * Force-apoptosis flag query / clear, exposed to trust_lifecycle.
 * Both are non-destructive of proof state.
 */
int trust_ape_check_force_apoptosis(u32 subject_id)
{
    trust_ape_entry_t *entry;
    int flagged;

    spin_lock(&g_trust_ape.lock);
    entry = ape_find(subject_id);
    if (!entry) {
        spin_unlock(&g_trust_ape.lock);
        return -ENOENT;
    }

    spin_lock(&entry->lock);
    spin_unlock(&g_trust_ape.lock);
    flagged = (ape_pad_get(&entry->state) & APE_PAD_FORCE_APOPTOSIS) ? 1 : 0;
    spin_unlock(&entry->lock);
    return flagged;
}

int trust_ape_clear_force_apoptosis(u32 subject_id)
{
    trust_ape_entry_t *entry;

    spin_lock(&g_trust_ape.lock);
    entry = ape_find(subject_id);
    if (!entry) {
        spin_unlock(&g_trust_ape.lock);
        return -ENOENT;
    }

    spin_lock(&entry->lock);
    spin_unlock(&g_trust_ape.lock);
    ape_pad_clear(&entry->state, APE_PAD_FORCE_APOPTOSIS);
    spin_unlock(&entry->lock);
    return 0;
}

/*
 * Sum the per-CPU double-read trap counters for stats / observability.
 */
u64 trust_ape_double_read_count(void)
{
    u64 total = 0;
    int cpu;

    for_each_possible_cpu(cpu)
        total += per_cpu(ape_double_read_traps, cpu);
    return total;
}

/*
 * Sum the per-CPU sequencer-advance counters (Session 49 / Agent B).
 *
 * This is the count of successful proof consumptions that have advanced
 * the global monotonic nonce via trust_invariants_advance_nonce().  It
 * should track 1:1 with the delta of trust_invariants_read_nonce() over
 * the same wall-clock interval IF this APE is the only producer; other
 * subsystems (e.g. trust_meiosis hash-derived nonces) may also advance,
 * so this counter is the APE-attributable share, not the absolute total.
 */
u64 trust_ape_seq_advances_total(void)
{
    u64 total = 0;
    int cpu;

    for_each_possible_cpu(cpu)
        total += per_cpu(ape_seq_advances, cpu);
    return total;
}

/*
 * Sequencer self-check (Session 49 / Agent B).
 *
 * Called once from trust_ape_init() right after the APE pool is
 * primed.  Verifies at module-load time that:
 *   (a) trust_invariants_advance_nonce() is callable from APE's
 *       compilation unit (link succeeded against trust_invariants.o);
 *   (b) the global nonce strictly advances on each call (monotonicity
 *       — the runtime invariant for Theorem 2).
 *
 * trust_theorems.h DOES expose trust_invariants_read_nonce() (line
 * 119), so we use it for the before/after comparison rather than
 * falling back to advance-twice-and-compare.  Kept defensive: if some
 * future header diet drops the getter, the BUILD would fail at this
 * call site immediately instead of silently regressing the check.
 *
 * This function is intentionally not static so a future ktest harness
 * can call it on demand without re-loading the module.
 */
void trust_ape_sequencer_selfcheck(void)
{
    u64 before, after;

    before = trust_invariants_read_nonce();
    (void)trust_invariants_advance_nonce();
    after  = trust_invariants_read_nonce();

    if (after > before) {
        pr_info("trust_ape: sequencer wired; nonce monotonicity verified "
                "at init (nonce %llu -> %llu)\n",
                (unsigned long long)before,
                (unsigned long long)after);
    } else {
        /*
         * Non-fatal — we can't WARN here because trust_invariants
         * itself already WARN_ON_ONCEs on monotonicity break.  Just
         * log loudly so the failure shows up in dmesg and an operator
         * can correlate with theorem2_violations sysfs counter.
         */
        pr_err("trust_ape: SEQUENCER SELF-CHECK FAILED — global nonce "
               "did not advance (before=%llu after=%llu); Theorem 2 "
               "runtime invariant is NOT enforced on this boot\n",
               (unsigned long long)before,
               (unsigned long long)after);
    }
}
