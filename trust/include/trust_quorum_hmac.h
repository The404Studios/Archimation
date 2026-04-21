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
 *
 * Lifetime (S78 Dev B item 2 — header contract):
 * -----------------------------------------------
 *   - The HMAC key is generated ONCE per module load via get_random_bytes()
 *     at trust_quorum_hmac_init() time. It is NOT per-boot (the module may
 *     be reloaded many times per boot during DKMS install/upgrade cycles)
 *     and it is NOT per-process (all subjects share the single module key).
 *
 *   - Any of the following events generates a fresh key and invalidates
 *     every HMAC tag minted under the previous key:
 *       (a) rmmod trust && modprobe trust
 *       (b) DKMS rebuild + reload during kernel upgrade
 *       (c) Module load failure + retry (partial init aborts the first key)
 *       (d) trust.ko panic-recovery reload (if enabled)
 *
 *   - Archived verdict tags from a prior module load CANNOT be verified
 *     after reload. Userspace consumers (cortex archivists, audit daemons)
 *     MUST treat the sysfs counter /sys/kernel/trust/quorum/hmac_computed
 *     as a generation marker: a reset-to-zero means the key rotated and
 *     any cached (payload, HMAC) pair the consumer holds is now
 *     unverifiable even against an identical payload.
 *
 *   - DO NOT cache HMACs across q_hmac_computed counter resets. Userspace
 *     that wants cross-reload verification must either (i) re-compute the
 *     tag by replaying the verdict under the new key, or (ii) persist the
 *     full payload and accept that verification is module-load-scoped.
 *
 *   - Rationale: get_random_bytes() output is not exported; persisting the
 *     key would require a keyring or TPM-sealed blob, which is a separate
 *     design question. A per-load ephemeral key is sufficient for the
 *     current threat model (in-kernel integrity witness; not a cross-
 *     reboot audit log).
 */

#ifndef _TRUST_QUORUM_HMAC_H
#define _TRUST_QUORUM_HMAC_H

#ifdef __KERNEL__
#include <linux/init.h>
#include <linux/types.h>

#define TRUST_QUORUM_HMAC_LEN 32U  /* HMAC-SHA256 */

/*
 * Initialise the HMAC key pool. Generates a random 32-byte module key
 * via get_random_bytes(). Idempotent; subsequent calls no-op.
 * Call from trust_quorum_init() or trust_main.c (integration agent).
 * Returns 0 on success, -ENOMEM on allocation failure.
 *
 * S78 Dev B item 5: __init so the kernel reclaims this function's text
 * post-boot.
 */
int __init trust_quorum_hmac_init(void);

/*
 * Zero the module key. Call from trust_quorum_exit() / trust_main exit.
 * Deliberately NOT marked __exit — may be called from init-failure
 * rollback paths; see trust_attest_quine.h for the full rationale.
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
