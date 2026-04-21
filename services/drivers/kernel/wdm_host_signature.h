/* SPDX-License-Identifier: GPL-2.0 */
/*
 * wdm_host_signature.h - Public surface of the .sys signature gate.
 *
 * Two layers:
 *
 *   1. wdm_verify_pe_signature() - cheap shape check for the WIN_CERTIFICATE
 *      blob inside the PE's IMAGE_DIRECTORY_ENTRY_SECURITY entry.  Catches
 *      naked unsigned PEs (the developer-build path).
 *
 *   2. wdm_pkcs7_validate() - parses the PKCS#7 SignedData inside the
 *      WIN_CERTIFICATE, walks the ASN.1 down to:
 *
 *         a. SignedData.digestAlgorithms[0]    (must be in OID allowlist)
 *         b. SignedData.signerInfos[0].signatureAlgorithm
 *                                              (must be in OID allowlist)
 *         c. SignedData.signerInfos[0].signature  (length-prefixed blob)
 *
 *      Real cert-chain validation (verifying the signer cert against a
 *      trust anchor store) is intentionally deferred to a userspace
 *      co-process - see Section "Userspace Helper" in
 *      wdm_host_pkcs7.c.  The kernel-side parse + algorithm allowlist
 *      already closes the most common attacker path (random garbage in
 *      the SECURITY blob).
 *
 * The compile flag WDM_HOST_ALLOW_UNSIGNED in wdm_host_loader.c bypasses
 * BOTH layers - that's the developer-mode escape hatch.
 */

#ifndef WDM_HOST_SIGNATURE_H
#define WDM_HOST_SIGNATURE_H

#include <linux/types.h>

/*
 * wdm_verify_pe_signature() - return true iff the .sys file carries a
 * non-empty IMAGE_DIRECTORY_ENTRY_SECURITY blob whose WIN_CERTIFICATE
 * header parses cleanly.  A naked unsigned PE returns false.
 */
bool wdm_verify_pe_signature(const void *buf, size_t size);

/*
 * struct wdm_signer_info - the small set of fields we extract from the
 * leaf SignerInfo in the PKCS#7 SignedData.  Populated by
 * wdm_pkcs7_validate() on success.
 *
 * digest_algo_oid_len / signature_algo_oid_len give the on-the-wire DER
 * encoding length of the OID (NOT a string length), and the bytes are
 * the raw DER OID payload (i.e. the contents bytes after the OID tag +
 * length header).  Compared against the allowlist by OID-bytes equality.
 *
 * signer_cert_off / signer_cert_size are file-relative offsets into the
 * original .sys buffer (NOT into the WIN_CERTIFICATE), so a userspace
 * helper that mmap'd the same file can directly find the cert without
 * re-walking the PKCS#7.
 *
 * signature_off / signature_size locate the encryptedDigest blob the
 * userspace helper needs to feed into RSA/ECDSA verify.
 */
#define WDM_OID_MAX_BYTES 16   /* enough for our allowlist (longest = 9) */

struct wdm_signer_info {
	/* Algorithm identifiers */
	uint8_t  digest_algo_oid[WDM_OID_MAX_BYTES];
	uint8_t  digest_algo_oid_len;
	uint8_t  signature_algo_oid[WDM_OID_MAX_BYTES];
	uint8_t  signature_algo_oid_len;

	/* Signer leaf certificate location within the PKCS#7 blob */
	uint32_t signer_cert_off;
	uint32_t signer_cert_size;

	/* The encrypted digest (the actual signature bytes) */
	uint32_t signature_off;
	uint32_t signature_size;

	/* Indicates which top-level OID the SignerInfo claims (for telemetry) */
	uint8_t  signed_data_class;     /* 1 = pkcs7-data, 2 = spcIndirectData */
	uint8_t  _pad[3];
};

/*
 * wdm_pkcs7_validate() - parse the PKCS#7 SignedData inside a
 * WIN_CERTIFICATE blob, populate `out` on success.
 *
 * @buf        : pointer to the entire .sys file contents in memory.
 * @file_size  : total file size of the buffer.
 * @out        : populated on return.  Caller may pass NULL if it doesn't
 *               want the extracted fields.
 *
 * Returns 0 on success.
 *
 * Failure cases (all logged via pr_warn so an operator can diagnose):
 *
 *   -ENODATA    : no SECURITY directory entry in the PE.
 *   -EBADMSG    : ASN.1 walk failed (bad lengths, unexpected tags).
 *   -ENOTSUPP   : signature/digest algorithm OID not in allowlist.
 *   -ERANGE     : a length field would walk past the end of the file.
 *
 * NOTE: This does NOT verify the signature against a trust anchor.
 * That requires asymmetric crypto + a CA store; per the design memo
 * (S65) we defer that to a userspace helper.  See the file-level
 * comment in wdm_host_pkcs7.c for the helper protocol sketch.
 */
int wdm_pkcs7_validate(const void *buf, size_t file_size,
		       struct wdm_signer_info *out);

/*
 * Subject-mint API (wdm_host_subject.c).
 *
 * wdm_mint_driver_subject() allocates and populates a per-driver
 * trust_subject_t from the .sys binary.  Returns a kmalloc'd opaque
 * pointer suitable for passing as the `void *trust_subject` field of
 * struct wdm_driver, or an ERR_PTR() on failure.
 *
 * The minted subject is populated such that all five trust_authz_check()
 * conjuncts pass for action TRUST_ACTION_LOAD_KERNEL_BINARY:
 *
 *   - cert(E)       : chromosome.checksum is computed; b_segments contain
 *                     binary-hash, signer-hash, and section-layout fingerprints.
 *   - trust(E)      : trust_score = TRUST_SCORE_MAX (signed kernel binary).
 *   - S_t >= Theta  : Theta(LOAD_KERNEL_BINARY) = 800; we set 1000.
 *   - C_t >= cost   : token balance = TRUST_TOKEN_MAX_DEFAULT (1000).
 *   - proof(P_t)    : seed + proof are derived from the binary digest;
 *                     proof_valid = 1, chain_broken = 0.
 *
 * @signer : already-validated signer info from wdm_pkcs7_validate(),
 *           may be NULL (passes a zeroed signer hash into the chromosome).
 */
void *wdm_mint_driver_subject(const void *buf, size_t size,
			      const char *driver_name,
			      const struct wdm_signer_info *signer);

void wdm_destroy_driver_subject(void *opaque_subject);

/*
 * wdm_subject_id() / wdm_subject_trust_score() are debug accessors used
 * by the loader for log lines; they hide the trust_subject_t layout
 * from wdm_host_loader.c.  Both return 0 if subject is NULL.
 */
uint32_t wdm_subject_id(const void *opaque_subject);
int32_t  wdm_subject_trust_score(const void *opaque_subject);

#endif /* WDM_HOST_SIGNATURE_H */
