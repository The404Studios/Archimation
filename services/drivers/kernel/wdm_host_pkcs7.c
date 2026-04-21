// SPDX-License-Identifier: GPL-2.0
/*
 * wdm_host_pkcs7.c - PKCS#7 SignedData parser + algorithm-allowlist gate
 *
 * ---------------------------------------------------------------------------
 * Position in the trust chain
 * ---------------------------------------------------------------------------
 *
 * wdm_verify_pe_signature() in wdm_host_signature.c confirms that the PE's
 * IMAGE_DIRECTORY_ENTRY_SECURITY slot holds a WIN_CERTIFICATE blob whose
 * revision / type / length are sane.  That alone only proves "the PE has
 * some bytes where a cert should live" - it does not prove those bytes
 * actually parse as a PKCS#7 SignedData, nor that the signer committed to a
 * sane digest / signature algorithm.  A tool that emits a random 4 KB of
 * high-entropy garbage in the SECURITY slot would still pass the shape
 * check.
 *
 * This file adds the next layer: we walk the PKCS#7 ASN.1 tree, extract
 * the SignerInfo's digestAlgorithm and signatureAlgorithm OIDs, and reject
 * anything outside our allowlist.  We also locate the leaf certificate and
 * the encryptedDigest blob so a future userspace helper can validate the
 * chain without re-walking the PKCS#7.
 *
 * Full cert-chain validation (verifying the leaf against a CA store) needs
 * asymmetric crypto + a CA trust anchor, which is heavier than we want in
 * the load path and orthogonal to what the kernel side enforces.  The plan
 * (sketched in the "Userspace Helper" section near the end of this file)
 * is a netlink generic family that this module posts to, and that a
 * userspace systemd unit answers.  The MVP is parse+allowlist only; chain
 * validation is a follow-up.
 *
 * ---------------------------------------------------------------------------
 * ASN.1 walk style
 * ---------------------------------------------------------------------------
 *
 * We implement a hand-written DER walker rather than pulling in the
 * kernel's asn1_decoder / pkcs7 infrastructure.  Rationale:
 *
 *   - asn1_decoder needs generated .asn1 tables and adds ~2 KB per parse.
 *   - The PKCS#7 / Authenticode shape is stable and well-specified
 *     (RFC 2315 + MS-AUTHENTICODE); we only need six traversal steps.
 *   - Keeping the walker local means this file has no cross-module
 *     dependency on the kernel's PKCS#7 keyring (which pulls in keyrings
 *     infrastructure that's heavier than we want for a .sys gate).
 *
 * DER basics (RFC 6025 + X.690):
 *   tag (1 byte) || length || contents
 *   length short form  : 0..127   => tag byte already encodes length.
 *                                    Wait, no - we mean the length byte < 0x80.
 *   length long form   : first byte 0x80 | N, N = number of subsequent
 *                        bytes that encode the big-endian length.
 *                        N = 0 is indefinite-length (DER forbids it, we
 *                        reject).
 *   Tags we care about:
 *     0x06 OBJECT IDENTIFIER (primitive)
 *     0x30 SEQUENCE (constructed)
 *     0x31 SET (constructed)
 *     0xa0 context[0] explicit (constructed)    - used by ContentInfo content
 *     0x04 OCTET STRING
 *     0x02 INTEGER
 *
 * ---------------------------------------------------------------------------
 * Algorithm allowlist
 * ---------------------------------------------------------------------------
 *
 * Any signer using an algorithm outside the allowlist is rejected at load.
 * The allowlist is intentionally conservative: we only keep the algorithms
 * MS Authenticode and modern code-signing CAs actually produce today.
 *
 *   sha256                         :  2.16.840.1.101.3.4.2.1
 *   sha384                         :  2.16.840.1.101.3.4.2.2
 *   sha512                         :  2.16.840.1.101.3.4.2.3
 *   rsaEncryption                  :  1.2.840.113549.1.1.1
 *   sha256WithRSAEncryption        :  1.2.840.113549.1.1.11
 *   sha384WithRSAEncryption        :  1.2.840.113549.1.1.12
 *   sha512WithRSAEncryption        :  1.2.840.113549.1.1.13
 *   ecdsa-with-SHA256              :  1.2.840.10045.4.3.2
 *   ecdsa-with-SHA384              :  1.2.840.10045.4.3.3
 *
 * We explicitly EXCLUDE md5 (1.2.840.113549.2.5), sha1
 * (1.3.14.3.2.26), md5WithRSA, sha1WithRSA - these are broken and we do
 * not want to accept a .sys signed with them even with "valid" chain.
 *
 * ---------------------------------------------------------------------------
 * Userspace helper protocol (planned, not in this file)
 * ---------------------------------------------------------------------------
 *
 * Kernel sends (signer_cert_off, signer_cert_size, request_id) on a
 *   generic netlink socket family "wdm_host_validator" attr
 *   WDM_VA_SIGNER_CERT + WDM_VA_REQUEST_ID.
 * Userspace replies (request_id, result_code, reason_string) where
 *   result_code = 0 (accept), 1 (unknown issuer), 2 (revoked), 3 (expired),
 *   4 (not-trusted-for-code-signing).
 * Kernel defaults to timeout = 5s.  On timeout, policy knob
 *   /sys/module/wdm_host/parameters/chain_timeout_action decides between
 *   "fail-closed" (default: reject) and "fail-open" (accept with warn).
 *
 * That layer is tracked as a follow-up; the parse+allowlist in this file
 * is already enough to close the "random bytes in SECURITY slot" attack.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/errno.h>

#include "wdm_host_internal.h"
#include "wdm_host_signature.h"

/* ============================================================================
 * Helper: the WIN_CERTIFICATE header (redefined here to keep the file
 * self-contained - the definitions here MUST match wdm_host_signature.c).
 * ============================================================================ */

#define WDM_PE_DOS_MAGIC      0x5A4D
#define WDM_PE_SIGNATURE      0x00004550U
#define WDM_PE_OPT_MAGIC_32   0x010B
#define WDM_PE_OPT_MAGIC_64   0x020B
#define WDM_DIR_SECURITY      4

struct wdm_win_certificate_hdr {
	uint32_t dwLength;
	uint16_t wRevision;
	uint16_t wCertificateType;
} __packed;

/* ============================================================================
 * DER walker
 * ============================================================================ */

/*
 * Parse a DER tag+length header.  On success fills *out_tag with the tag
 * byte, *out_len with the content length, and advances *cursor past the
 * tag+length header.  Returns 0 on success, negative errno on failure.
 *
 * We reject indefinite-length (0x80 with no following count) because DER
 * forbids it.  We also reject length encodings > 4 bytes (which would
 * give a >= 4 GB DER value - impossible in our 64 MB file-size cap).
 */
static int der_read_tl(const uint8_t *buf, size_t buf_len,
		       size_t *cursor, uint8_t *out_tag, size_t *out_len)
{
	size_t p = *cursor;
	uint8_t tag;
	uint8_t first_len;

	if (p + 2 > buf_len)
		return -EBADMSG;
	tag = buf[p++];
	first_len = buf[p++];

	if (first_len < 0x80) {
		*out_len = first_len;
	} else {
		uint8_t n = first_len & 0x7f;
		size_t len_val = 0;
		uint8_t i;

		if (n == 0) {
			/* indefinite length - DER forbids this */
			return -EBADMSG;
		}
		if (n > 4) {
			/* sanity cap - refuses anything the file itself can't hold */
			return -ERANGE;
		}
		if (p + n > buf_len)
			return -EBADMSG;
		for (i = 0; i < n; i++) {
			len_val = (len_val << 8) | buf[p++];
		}
		*out_len = len_val;
	}

	if (*out_len > buf_len || p + *out_len > buf_len)
		return -ERANGE;

	*out_tag = tag;
	*cursor = p;
	return 0;
}

/*
 * Match a DER OID payload against an expected pattern.
 *
 * The "expected" bytes are the content bytes of the OID (i.e. what follows
 * the 0x06 tag and length) so the allowlist table can be declared compactly.
 * Returns 1 on match, 0 otherwise.
 */
static int der_oid_equals(const uint8_t *oid, size_t oid_len,
			  const uint8_t *expect, size_t expect_len)
{
	if (oid_len != expect_len)
		return 0;
	return memcmp(oid, expect, oid_len) == 0;
}

/* ============================================================================
 * OID allowlist (payload bytes only, no tag/length prefix)
 * ============================================================================ */

/* Digest OIDs */
static const uint8_t WDM_OID_SHA256[] = {
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
};
static const uint8_t WDM_OID_SHA384[] = {
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
};
static const uint8_t WDM_OID_SHA512[] = {
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
};

/* Signature OIDs */
static const uint8_t WDM_OID_RSA_ENC[] = {
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
};
static const uint8_t WDM_OID_SHA256_RSA[] = {
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b
};
static const uint8_t WDM_OID_SHA384_RSA[] = {
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c
};
static const uint8_t WDM_OID_SHA512_RSA[] = {
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d
};
static const uint8_t WDM_OID_ECDSA_SHA256[] = {
	0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
};
static const uint8_t WDM_OID_ECDSA_SHA384[] = {
	0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03
};

/* PKCS#7 SignedData OID: 1.2.840.113549.1.7.2 */
static const uint8_t WDM_OID_PKCS7_SIGNED_DATA[] = {
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02
};

struct wdm_oid_entry {
	const uint8_t *bytes;
	size_t len;
	const char *name;
};

/* Digest algorithm allowlist (what goes in SignerInfo.digestAlgorithm) */
static const struct wdm_oid_entry WDM_DIGEST_ALLOWLIST[] = {
	{ WDM_OID_SHA256, sizeof(WDM_OID_SHA256), "sha256" },
	{ WDM_OID_SHA384, sizeof(WDM_OID_SHA384), "sha384" },
	{ WDM_OID_SHA512, sizeof(WDM_OID_SHA512), "sha512" },
};

/* Signature algorithm allowlist (SignerInfo.digestEncryptionAlgorithm) */
static const struct wdm_oid_entry WDM_SIG_ALLOWLIST[] = {
	{ WDM_OID_RSA_ENC,      sizeof(WDM_OID_RSA_ENC),      "rsaEncryption"   },
	{ WDM_OID_SHA256_RSA,   sizeof(WDM_OID_SHA256_RSA),   "sha256WithRSA"   },
	{ WDM_OID_SHA384_RSA,   sizeof(WDM_OID_SHA384_RSA),   "sha384WithRSA"   },
	{ WDM_OID_SHA512_RSA,   sizeof(WDM_OID_SHA512_RSA),   "sha512WithRSA"   },
	{ WDM_OID_ECDSA_SHA256, sizeof(WDM_OID_ECDSA_SHA256), "ecdsa-sha256"    },
	{ WDM_OID_ECDSA_SHA384, sizeof(WDM_OID_ECDSA_SHA384), "ecdsa-sha384"    },
};

static const char *wdm_lookup_oid(const uint8_t *oid, size_t len,
				   const struct wdm_oid_entry *table,
				   size_t table_len)
{
	size_t i;

	for (i = 0; i < table_len; i++) {
		if (der_oid_equals(oid, len, table[i].bytes, table[i].len))
			return table[i].name;
	}
	return NULL;
}

/* ============================================================================
 * Locate the WIN_CERTIFICATE blob (duplicates the shape-parser in
 * wdm_host_signature.c but returns pointers instead of a bool, which lets
 * us re-use the file offsets).  On success sets *pkcs7_off and
 * *pkcs7_len to the OFFSET OF THE FIRST BYTE AFTER the WIN_CERTIFICATE
 * header (i.e. where the PKCS#7 blob begins) and its length.
 * ============================================================================ */
static int wdm_locate_pkcs7(const void *buf, size_t size,
			    size_t *pkcs7_off, size_t *pkcs7_len)
{
	const uint8_t *p = buf;
	uint32_t pe_off;
	uint16_t opt_magic;
	uint32_t num_dirs;
	uint32_t sec_off, sec_size;
	uint32_t dir_offset_in_opt;
	size_t dirs_off;
	const struct wdm_win_certificate_hdr *cert;

	if (!buf || size < 0x40)
		return -ENODATA;

	if (le16_to_cpu(*(const uint16_t *)p) != WDM_PE_DOS_MAGIC)
		return -ENODATA;

	pe_off = le32_to_cpu(*(const uint32_t *)(p + 0x3C));
	if (pe_off >= size || pe_off + 4 + 20 > size)
		return -ENODATA;
	if (le32_to_cpu(*(const uint32_t *)(p + pe_off)) != WDM_PE_SIGNATURE)
		return -ENODATA;

	if (pe_off + 24 + 2 > size)
		return -ENODATA;
	opt_magic = le16_to_cpu(*(const uint16_t *)(p + pe_off + 24));
	if (opt_magic == WDM_PE_OPT_MAGIC_32)
		dir_offset_in_opt = 92;
	else if (opt_magic == WDM_PE_OPT_MAGIC_64)
		dir_offset_in_opt = 108;
	else
		return -ENODATA;

	if (pe_off + 24 + dir_offset_in_opt + 4 > size)
		return -ENODATA;
	num_dirs = le32_to_cpu(*(const uint32_t *)
			       (p + pe_off + 24 + dir_offset_in_opt));
	if (num_dirs <= WDM_DIR_SECURITY)
		return -ENODATA;

	dirs_off = pe_off + 24 + dir_offset_in_opt + 4
		 + (size_t)WDM_DIR_SECURITY * 8U;
	if (dirs_off + 8 > size)
		return -ENODATA;
	sec_off  = le32_to_cpu(*(const uint32_t *)(p + dirs_off + 0));
	sec_size = le32_to_cpu(*(const uint32_t *)(p + dirs_off + 4));

	if (sec_off == 0 || sec_size == 0)
		return -ENODATA;
	if (sec_size < sizeof(struct wdm_win_certificate_hdr) + 1)
		return -ENODATA;
	if ((uint64_t)sec_off + sec_size > (uint64_t)size)
		return -ENODATA;

	cert = (const struct wdm_win_certificate_hdr *)(p + sec_off);
	if (le32_to_cpu(cert->dwLength) > sec_size)
		return -ENODATA;
	if (le32_to_cpu(cert->dwLength) <
	    sizeof(struct wdm_win_certificate_hdr) + 1)
		return -ENODATA;

	/* The PKCS#7 blob sits immediately after the WIN_CERTIFICATE header. */
	*pkcs7_off = sec_off + sizeof(struct wdm_win_certificate_hdr);
	*pkcs7_len = le32_to_cpu(cert->dwLength)
		   - sizeof(struct wdm_win_certificate_hdr);
	return 0;
}

/* ============================================================================
 * PKCS#7 SignedData walk
 *
 * Simplified expected shape (RFC 2315 + MS-AUTHENTICODE):
 *
 *   ContentInfo ::= SEQUENCE {
 *     contentType        OID                    -- = 1.2.840.113549.1.7.2
 *     content        [0] EXPLICIT SignedData
 *   }
 *   SignedData ::= SEQUENCE {
 *     version            INTEGER
 *     digestAlgorithms   SET OF DigestAlgorithmIdentifier
 *     contentInfo        SEQUENCE { ... }     -- spcIndirectDataContent
 *     certificates   [0] IMPLICIT SET OF Certificate    -- optional
 *     crls           [1] IMPLICIT SET OF Cert RevList  -- optional
 *     signerInfos        SET OF SignerInfo
 *   }
 *   SignerInfo ::= SEQUENCE {
 *     version            INTEGER
 *     issuerAndSerial    SEQUENCE
 *     digestAlgorithm    AlgorithmIdentifier
 *     authAttrs      [0] IMPLICIT SET OF Attribute    -- optional
 *     sigAlgorithm       AlgorithmIdentifier
 *     signature          OCTET STRING
 *     unauthAttrs    [1] IMPLICIT SET OF Attribute    -- optional
 *   }
 *
 * We don't need a full parser: we just walk the SEQUENCEs, match OIDs,
 * and record file offsets.  Any unexpected tag aborts with -EBADMSG.
 * ============================================================================ */

int wdm_pkcs7_validate(const void *buf, size_t file_size,
		       struct wdm_signer_info *out)
{
	size_t pkcs7_off = 0, pkcs7_len = 0;
	const uint8_t *p;
	size_t cursor;
	size_t end;
	uint8_t tag;
	size_t len;
	int rc;
	size_t signed_data_start, signed_data_end;
	size_t outer_content_start, outer_content_end;
	size_t signer_infos_start, signer_infos_end;
	size_t signer_info_start, signer_info_end;
	struct wdm_signer_info tmp;
	const char *digest_name, *sig_name;
	size_t oid_start;
	size_t algo_id_end;

	memset(&tmp, 0, sizeof(tmp));

	rc = wdm_locate_pkcs7(buf, file_size, &pkcs7_off, &pkcs7_len);
	if (rc) {
		pr_warn("wdm_host: pkcs7: no SECURITY blob (%d)\n", rc);
		return rc;
	}

	p = (const uint8_t *)buf;
	cursor = pkcs7_off;
	end = pkcs7_off + pkcs7_len;

	/* Outer ContentInfo SEQUENCE */
	rc = der_read_tl(p, end, &cursor, &tag, &len);
	if (rc || tag != 0x30) {
		pr_warn("wdm_host: pkcs7: outer not SEQUENCE (tag=0x%02x rc=%d)\n",
			tag, rc);
		return rc ? rc : -EBADMSG;
	}
	outer_content_start = cursor;
	outer_content_end = cursor + len;
	if (outer_content_end > end) {
		pr_warn("wdm_host: pkcs7: outer SEQUENCE overruns PKCS#7 blob\n");
		return -ERANGE;
	}

	/* contentType OID - must equal pkcs7-signedData */
	rc = der_read_tl(p, outer_content_end, &cursor, &tag, &len);
	if (rc || tag != 0x06) {
		pr_warn("wdm_host: pkcs7: missing contentType OID\n");
		return rc ? rc : -EBADMSG;
	}
	if (!der_oid_equals(p + cursor, len, WDM_OID_PKCS7_SIGNED_DATA,
			    sizeof(WDM_OID_PKCS7_SIGNED_DATA))) {
		pr_warn("wdm_host: pkcs7: outer OID is not pkcs7-signedData\n");
		return -EBADMSG;
	}
	cursor += len;

	/* content [0] EXPLICIT ... */
	rc = der_read_tl(p, outer_content_end, &cursor, &tag, &len);
	if (rc || tag != 0xa0) {
		pr_warn("wdm_host: pkcs7: missing [0] EXPLICIT wrapper\n");
		return rc ? rc : -EBADMSG;
	}
	/* Inside [0] is the SignedData SEQUENCE */
	rc = der_read_tl(p, cursor + len, &cursor, &tag, &len);
	if (rc || tag != 0x30) {
		pr_warn("wdm_host: pkcs7: SignedData not SEQUENCE\n");
		return rc ? rc : -EBADMSG;
	}
	signed_data_start = cursor;
	signed_data_end = cursor + len;

	/* SignedData.version INTEGER - skip */
	rc = der_read_tl(p, signed_data_end, &cursor, &tag, &len);
	if (rc || tag != 0x02) {
		pr_warn("wdm_host: pkcs7: missing SignedData.version\n");
		return rc ? rc : -EBADMSG;
	}
	cursor += len;

	/* digestAlgorithms SET - skip.  We'll re-extract the actual digest OID
	 * from SignerInfo.digestAlgorithm below since that's the one that
	 * authoritatively describes the signature. */
	rc = der_read_tl(p, signed_data_end, &cursor, &tag, &len);
	if (rc || tag != 0x31) {
		pr_warn("wdm_host: pkcs7: missing digestAlgorithms SET\n");
		return rc ? rc : -EBADMSG;
	}
	cursor += len;

	/* encapContentInfo SEQUENCE - skip */
	rc = der_read_tl(p, signed_data_end, &cursor, &tag, &len);
	if (rc || tag != 0x30) {
		pr_warn("wdm_host: pkcs7: missing encapContentInfo SEQUENCE\n");
		return rc ? rc : -EBADMSG;
	}
	cursor += len;

	/* Optional certificates [0] IMPLICIT SET OF Certificate - record its
	 * offset and length as "signer_cert" if present (we take the first
	 * certificate in the SET as the leaf).  The correct thing would be
	 * to cross-walk issuerAndSerial from SignerInfo and pick the cert
	 * that matches, but for the MVP "leaf = first cert" is accurate for
	 * Microsoft-signed drivers (signer first, then intermediates). */
	if (cursor < signed_data_end) {
		size_t peek_cursor = cursor;
		rc = der_read_tl(p, signed_data_end, &peek_cursor, &tag, &len);
		if (!rc && tag == 0xa0) {
			size_t certs_start = peek_cursor;
			size_t certs_end = peek_cursor + len;
			uint8_t sub_tag;
			size_t sub_len;
			size_t first_cert_cursor = certs_start;
			/* Each Certificate is a SEQUENCE */
			if (der_read_tl(p, certs_end, &first_cert_cursor,
					&sub_tag, &sub_len) == 0 &&
			    sub_tag == 0x30 &&
			    first_cert_cursor + sub_len <= certs_end) {
				/* signer_cert_off points at the SEQUENCE tag so
				 * userspace can feed the whole DER cert into an
				 * X.509 parser. */
				tmp.signer_cert_off =
					(uint32_t)(first_cert_cursor - 2 -
						   (sub_len < 0x80 ? 0 : 1));
				/* Re-derive the "full with tag+length" region
				 * by moving back to certs_start where the
				 * SEQUENCE tag sits. */
				tmp.signer_cert_off = (uint32_t)certs_start;
				tmp.signer_cert_size = (uint32_t)(certs_end -
								  certs_start);
			}
			cursor = certs_end;
		}
	}

	/* Optional CRLs [1] IMPLICIT - skip */
	if (cursor < signed_data_end) {
		size_t peek_cursor = cursor;
		rc = der_read_tl(p, signed_data_end, &peek_cursor, &tag, &len);
		if (!rc && tag == 0xa1) {
			cursor = peek_cursor + len;
		}
	}

	/* signerInfos SET */
	rc = der_read_tl(p, signed_data_end, &cursor, &tag, &len);
	if (rc || tag != 0x31) {
		pr_warn("wdm_host: pkcs7: missing signerInfos SET\n");
		return rc ? rc : -EBADMSG;
	}
	signer_infos_start = cursor;
	signer_infos_end = cursor + len;
	if (len == 0) {
		pr_warn("wdm_host: pkcs7: empty signerInfos\n");
		return -EBADMSG;
	}

	/* First SignerInfo (we only authorize against the first one; PE files
	 * carry a single SignerInfo in ~every real-world case). */
	rc = der_read_tl(p, signer_infos_end, &cursor, &tag, &len);
	if (rc || tag != 0x30) {
		pr_warn("wdm_host: pkcs7: SignerInfo not SEQUENCE\n");
		return rc ? rc : -EBADMSG;
	}
	signer_info_start = cursor;
	signer_info_end = cursor + len;

	/* version INTEGER */
	rc = der_read_tl(p, signer_info_end, &cursor, &tag, &len);
	if (rc || tag != 0x02) {
		pr_warn("wdm_host: pkcs7: SignerInfo.version missing\n");
		return rc ? rc : -EBADMSG;
	}
	cursor += len;

	/* issuerAndSerialNumber SEQUENCE - skip */
	rc = der_read_tl(p, signer_info_end, &cursor, &tag, &len);
	if (rc || tag != 0x30) {
		pr_warn("wdm_host: pkcs7: SignerInfo.issuerAndSerial missing\n");
		return rc ? rc : -EBADMSG;
	}
	cursor += len;

	/* digestAlgorithm AlgorithmIdentifier ::= SEQUENCE {OID [params]} */
	rc = der_read_tl(p, signer_info_end, &cursor, &tag, &len);
	if (rc || tag != 0x30) {
		pr_warn("wdm_host: pkcs7: SignerInfo.digestAlgorithm missing\n");
		return rc ? rc : -EBADMSG;
	}
	algo_id_end = cursor + len;
	oid_start = cursor;
	rc = der_read_tl(p, algo_id_end, &cursor, &tag, &len);
	if (rc || tag != 0x06) {
		pr_warn("wdm_host: pkcs7: digestAlgorithm OID missing\n");
		return rc ? rc : -EBADMSG;
	}
	if (len > WDM_OID_MAX_BYTES) {
		pr_warn("wdm_host: pkcs7: digestAlgorithm OID too large (%zu)\n",
			len);
		return -ENOTSUPP;
	}
	memcpy(tmp.digest_algo_oid, p + cursor, len);
	tmp.digest_algo_oid_len = (uint8_t)len;
	(void)oid_start;   /* silence unused - we keep for debug symmetry */
	cursor = algo_id_end;

	/* Optional authenticatedAttributes [0] IMPLICIT SET - skip */
	if (cursor < signer_info_end) {
		size_t peek_cursor = cursor;
		rc = der_read_tl(p, signer_info_end, &peek_cursor, &tag, &len);
		if (!rc && tag == 0xa0) {
			cursor = peek_cursor + len;
		}
	}

	/* digestEncryptionAlgorithm AlgorithmIdentifier */
	rc = der_read_tl(p, signer_info_end, &cursor, &tag, &len);
	if (rc || tag != 0x30) {
		pr_warn("wdm_host: pkcs7: SignerInfo.sigAlgorithm missing\n");
		return rc ? rc : -EBADMSG;
	}
	algo_id_end = cursor + len;
	rc = der_read_tl(p, algo_id_end, &cursor, &tag, &len);
	if (rc || tag != 0x06) {
		pr_warn("wdm_host: pkcs7: sigAlgorithm OID missing\n");
		return rc ? rc : -EBADMSG;
	}
	if (len > WDM_OID_MAX_BYTES) {
		pr_warn("wdm_host: pkcs7: sigAlgorithm OID too large (%zu)\n",
			len);
		return -ENOTSUPP;
	}
	memcpy(tmp.signature_algo_oid, p + cursor, len);
	tmp.signature_algo_oid_len = (uint8_t)len;
	cursor = algo_id_end;

	/* encryptedDigest OCTET STRING */
	rc = der_read_tl(p, signer_info_end, &cursor, &tag, &len);
	if (rc || tag != 0x04) {
		pr_warn("wdm_host: pkcs7: encryptedDigest missing\n");
		return rc ? rc : -EBADMSG;
	}
	tmp.signature_off = (uint32_t)cursor;
	tmp.signature_size = (uint32_t)len;
	/* cursor += len;   // we don't need to walk further */

	/* ---- Algorithm allowlist ---- */
	digest_name = wdm_lookup_oid(tmp.digest_algo_oid,
				     tmp.digest_algo_oid_len,
				     WDM_DIGEST_ALLOWLIST,
				     ARRAY_SIZE(WDM_DIGEST_ALLOWLIST));
	sig_name = wdm_lookup_oid(tmp.signature_algo_oid,
				  tmp.signature_algo_oid_len,
				  WDM_SIG_ALLOWLIST,
				  ARRAY_SIZE(WDM_SIG_ALLOWLIST));

	if (!digest_name) {
		pr_warn("wdm_host: pkcs7: digestAlgorithm OID not in allowlist "
			"(len=%u) - rejecting\n", tmp.digest_algo_oid_len);
		return -ENOTSUPP;
	}
	if (!sig_name) {
		pr_warn("wdm_host: pkcs7: sigAlgorithm OID not in allowlist "
			"(len=%u) - rejecting\n", tmp.signature_algo_oid_len);
		return -ENOTSUPP;
	}

	pr_info("wdm_host: pkcs7: accepted SignerInfo digest=%s sig=%s "
		"signer_cert@+%u (%u B) signature@+%u (%u B)\n",
		digest_name, sig_name,
		tmp.signer_cert_off, tmp.signer_cert_size,
		tmp.signature_off, tmp.signature_size);

	(void)signed_data_start; (void)signer_info_start;
	(void)outer_content_start;   /* offsets computed for symmetry / debug */

	if (out)
		*out = tmp;
	return 0;
}
EXPORT_SYMBOL_GPL(wdm_pkcs7_validate);
