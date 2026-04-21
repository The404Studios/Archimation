/*
 * trust_quorum_hmac.h — HMAC-SHA256 uplift for quorum verdict payloads.
 *
 * S75 Tier-3 Item #7 pair. Roadmap §1.3.7 pairs quine self-attestation
 * with quorum L1 HMAC uplift per research-G §6. Together: cryptographic
 * (HMAC) + behavioral (23-way vote) integrity on every verdict.
 *
 * Call-site (for Agent G's awareness, not wired here):
 *   trust/kernel/trust_quorum.c::trust_quorum_vote() at line 120 — the
 *   point where the verdict enum is returned and the counter bumped.
 *   Compute an HMAC over (subject_id | field_id | verdict | agree) and
 *   stash/emit it for downstream consumers. See report.
 *
 * The key is derived from an in-kernel module-lifetime random nonce;
 * it's never written to sysfs. Rotation is out-of-scope for this header
 * (if quorum needs rotation, expose a separate rekey RPC).
 */

#ifndef _TRUST_QUORUM_HMAC_H
#define _TRUST_QUORUM_HMAC_H

#ifdef __KERNEL__
#include <linux/types.h>

#define TRUST_QUORUM_HMAC_LEN 32U  /* HMAC-SHA256 */

/*
 * Initialise the HMAC key pool. Generates a random 32-byte module key
 * via get_random_bytes(). Idempotent; subsequent calls no-op.
 * Call from trust_quorum_init() or trust_main.c (integration agent).
 * Returns 0 on success, -ENOMEM on allocation failure.
 */
int trust_quorum_hmac_init(void);

/*
 * Zero the module key. Call from trust_quorum_exit() / trust_main exit.
 */
void trust_quorum_hmac_exit(void);

/*
 * Compute HMAC-SHA256 over @payload (@len bytes) using the module key.
 *
 * @out: must point at TRUST_QUORUM_HMAC_LEN bytes of writable buffer.
 *
 * Returns 0 on success, negative errno on failure. Process context only
 * (uses crypto_alloc_shash + kmalloc; may sleep).
 */
int trust_quorum_hmac_compute(const void *payload, size_t len,
                              u8 out[TRUST_QUORUM_HMAC_LEN]);

#endif /* __KERNEL__ */
#endif /* _TRUST_QUORUM_HMAC_H */
