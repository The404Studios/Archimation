/*
 * trust_attest_quine.h — Live self-attestation (module .text quine).
 *
 * S75 Tier-3 Item #7 (roadmap §1.3.7). Per research-F §3 and research-J
 * §5 Proposal C: every APE proof folds in SHA-256(trust.ko .text). A
 * kernel-write adversary who has tampered with the module cannot produce
 * a matching hash while their exploit is still resident; every proof they
 * mint diverges from every proof an honest kernel mints. "Live
 * reflexivity" — the module attests to itself.
 *
 * Strict separation from trust_attest.c (TPM2 boot attestation): that
 * module anchors the boot chain via PCR 11; THIS module anchors the
 * runtime .text against live tampering. Both coexist; neither replaces
 * the other.
 *
 * sysfs surface (read-only):
 *   /sys/kernel/trust_attest/text_hash         — 64 hex chars + '\n'
 *   /sys/kernel/trust_attest/recompute_count   — u64 decimal
 *
 * (We nest under the SAME /sys/kernel/trust_attest/ kobject that
 *  trust_attest.c creates. Call ordering documented at the init site.)
 */

#ifndef _TRUST_ATTEST_QUINE_H
#define _TRUST_ATTEST_QUINE_H

#ifdef __KERNEL__
#include <linux/types.h>

/*
 * Hash over the module's .text section. 32 bytes == SHA-256 digest size.
 */
#define TRUST_QUINE_HASH_LEN 32U

/*
 * Recompute the quine hash every N successful proof consumptions.
 * Default 1000 chosen as a balance: low enough to catch late-injection
 * tampering within a few seconds of proof activity, high enough that
 * the hash is amortized across a busy APE workload (SHA-256 over a
 * few hundred KB of .text is O(tens of usec) on modern x86).
 *
 * Bumpable at module load (future): currently compile-time.
 */
#define TRUST_QUINE_RECOMPUTE_EVERY 1000U

/*
 * Module init. Computes the first hash over the live .text range and
 * registers sysfs attributes. Returns 0 on success, negative errno on
 * sysfs/crypto failure. MUST be called AFTER trust_attest_init() so the
 * parent kobject (/sys/kernel/trust_attest/) already exists — we only
 * add attributes to it, we do not create it ourselves.
 */
int trust_attest_quine_init(void);

/*
 * Module exit. Removes sysfs attributes. Idempotent.
 */
void trust_attest_quine_exit(void);

/*
 * Fill @out with the cached 32-byte .text hash.
 *
 * Called from trust_ape.c::compute_proof_v2 (surgical edit). If the
 * quine subsystem is not initialized (module bail-out path), returns
 * a 32-byte zero buffer so the proof input layout stays fixed width
 * and pre-init APE calls during module load don't fault on NULL.
 *
 * Fast path: a single memcpy under a seqlock read. Not a hot spinlock.
 */
void trust_attest_quine_get_hash(u8 out[TRUST_QUINE_HASH_LEN]);

/*
 * Force an immediate re-hash of the module .text. Safe to call from
 * process context (uses GFP_KERNEL + crypto_alloc_shash internally).
 * Intended for:
 *   - trust_ape.c: every TRUST_QUINE_RECOMPUTE_EVERY proof consumes.
 *   - future ktest harness: deliberate trigger.
 *
 * No return value; failures are logged (pr_err) and leave the cached
 * hash unchanged rather than zeroing it (clearing on failure would
 * break every in-flight proof).
 */
void trust_attest_quine_force_recompute(void);

/*
 * Internal helper exposed for the APE hot path: tick the consume
 * counter and trigger a deferred recompute if the threshold was just
 * crossed. Returns 1 if a recompute was queued this call, 0 otherwise.
 * Kept header-visible so trust_ape.c can call it without extra Kbuild
 * wiring beyond the new .o.
 */
int trust_attest_quine_tick(void);

#endif /* __KERNEL__ */
#endif /* _TRUST_ATTEST_QUINE_H */
