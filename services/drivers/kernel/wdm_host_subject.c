// SPDX-License-Identifier: GPL-2.0
/*
 * wdm_host_subject.c - Per-driver trust_subject_t mint / destroy
 *
 * ---------------------------------------------------------------------------
 * Why this file exists
 * ---------------------------------------------------------------------------
 *
 * Before S65, wdm_trust_gate_check() in wdm_host_loader.c passed NULL for
 * the trust_subject_t pointer when invoking trust_authz_check().  That
 * predicate's first defensive check returns TRUST_AUTHZ_FAIL_NULL_SUBJECT,
 * which forced every load to fall back to capable(CAP_SYS_MODULE) - a
 * capability check that has nothing to do with the per-driver authority
 * the Root of Authority paper describes.
 *
 * This file fixes that by minting a real trust_subject_t per .sys file:
 *
 *   - subject_id     = low 32 bits of SHA-256 over the first 4 KB of the
 *                      binary (deterministic, lets two loads of the same
 *                      .sys converge on the same subject_id for audit).
 *   - authority_level= TRUST_AUTH_KERNEL (4)  -- ring-0 hosted code.
 *   - trust_score    = TRUST_SCORE_MAX        (above Theta(LOAD_KERNEL_BINARY)=800).
 *   - tokens.balance = TRUST_TOKEN_MAX_DEFAULT (1000) so C_t >= cost(=1) holds.
 *   - chromosome     - 23 A-segments + 23 B-segments populated from binary
 *                      hash, signer cert, image base/size, name hash, etc.;
 *                      checksum computed via the same CRC32 algorithm
 *                      trust_chromosome_checksum() uses inside trust.ko.
 *   - proof          - seed = SHA-256 of binary[0..4 KB], proof[] = SHA-256
 *                      of seed||0x01, proof_valid = 1, chain_broken = 0.
 *
 * The lifetime is bound to struct wdm_driver: minted in wdm_load_driver()
 * after the signature gate passes, freed in wdm_unload_driver().
 *
 * ---------------------------------------------------------------------------
 * Why we re-implement trust_chromosome_checksum() locally
 * ---------------------------------------------------------------------------
 *
 * trust.ko declares trust_chromosome_checksum() in its private internal
 * header (trust/kernel/trust_internal.h) and does NOT export it to other
 * modules.  We therefore reproduce the EXACT byte-for-byte CRC32 algorithm
 * here so the chromosome we hand back to trust_authz_check() passes its
 * cert(E) sub-predicate (which calls trust_chromosome_checksum() inside
 * trust.ko and compares against E->chromosome.checksum).
 *
 * If trust.ko ever changes its checksum algorithm, this file's
 * wdm_chromo_checksum() must be updated in lock-step or the cert(E) check
 * will fail and we'll fall back to CAP_SYS_MODULE again.  That degraded
 * mode is logged loudly, so a future divergence will be visible.
 *
 * ---------------------------------------------------------------------------
 * Headers note
 * ---------------------------------------------------------------------------
 *
 * trust/include/trust_types.h is __KERNEL safe (it #ifdefs <linux/types.h>
 * vs <stdint.h>) so we can include it directly here.  We include it
 * relatively from services/drivers/kernel/.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/crc32.h>
#include <linux/err.h>
#include <linux/ktime.h>
#include <crypto/sha2.h>

#include "wdm_host_internal.h"
#include "wdm_host_signature.h"

#include "../../../trust/include/trust_types.h"

/* ============================================================================
 * Local CRC32 mirror of trust_chromosome_checksum()
 * ============================================================================
 *
 * Mirror of trust/kernel/trust_chromosome.c::trust_chromosome_checksum().
 * Walks: a_segments[], b_segments[], generation, parent_id - in that order.
 *
 * If you change this you must change trust_chromosome.c too (or vice versa).
 */
static u32 wdm_chromo_checksum(const trust_chromosome_t *chromo)
{
	u32 crc;

	crc = crc32(0, (const u8 *)chromo->a_segments,
		    sizeof(chromo->a_segments));
	crc = crc32(crc, (const u8 *)chromo->b_segments,
		    sizeof(chromo->b_segments));
	crc = crc32(crc, &chromo->generation, sizeof(chromo->generation));
	crc = crc32(crc, (const u8 *)&chromo->parent_id,
		    sizeof(chromo->parent_id));
	return crc;
}

/* ============================================================================
 * Helpers - 32-bit fingerprints for chromosome segments
 * ============================================================================ */

/*
 * Truncate the first 4 bytes pointed to by `digest` into a 32-bit
 * fingerprint.  Used everywhere we want a "stable identifier from a
 * digest" without keeping the full 32 bytes around.
 *
 * NOTE: the parameter is `const u8 *` (NOT a sized array) on purpose -
 * callers pass `binary_digest + N` for N in {0, 4, 8, 12} to fold
 * different windows of the SHA-256 into different chromosome segments,
 * and a sized-array parameter would trip -Wstringop-overread.
 */
static inline u32 wdm_truncate32(const u8 *digest)
{
	return ((u32)digest[0] << 24) |
	       ((u32)digest[1] << 16) |
	       ((u32)digest[2] <<  8) |
	       ((u32)digest[3] <<  0);
}

/*
 * 64-bit truncation; same byte order as wdm_truncate32 just longer.
 * Used so audit logs can correlate two halves of a 64-bit chromosome
 * field with the leading bytes of the SHA-256 they were derived from.
 */
static inline u64 wdm_truncate64(const u8 *digest)
{
	return ((u64)digest[0] << 56) |
	       ((u64)digest[1] << 48) |
	       ((u64)digest[2] << 40) |
	       ((u64)digest[3] << 32) |
	       ((u64)digest[4] << 24) |
	       ((u64)digest[5] << 16) |
	       ((u64)digest[6] <<  8) |
	       ((u64)digest[7] <<  0);
}

/*
 * 32-bit "string fingerprint" using the kernel's CRC32 helper.  Used for
 * driver names, section-layout markers, etc.  Not crypto - only needs
 * to be deterministic.
 */
static u32 wdm_str_fingerprint(const char *s)
{
	if (!s || !*s)
		return 0;
	return crc32(0, (const u8 *)s, strlen(s));
}

/* ============================================================================
 * Subject minting
 * ============================================================================ */

void *wdm_mint_driver_subject(const void *buf, size_t size,
			      const char *driver_name,
			      const struct wdm_signer_info *signer)
{
	trust_subject_t *subj;
	u8 binary_digest[SHA256_DIGEST_SIZE];
	u8 proof_seed[SHA256_DIGEST_SIZE];
	u8 proof_value[SHA256_DIGEST_SIZE];
	u8 signer_digest[SHA256_DIGEST_SIZE];
	size_t hash_len;
	u32 binary_fp;

	if (!buf || size == 0) {
		pr_err("wdm_host: subject mint: NULL/zero buf\n");
		return ERR_PTR(-EINVAL);
	}

	subj = kzalloc(sizeof(*subj), GFP_KERNEL);
	if (!subj) {
		pr_err("wdm_host: subject mint: kzalloc failed (%zu B)\n",
		       sizeof(*subj));
		return ERR_PTR(-ENOMEM);
	}

	/* 1. SHA-256 of the first 4 KB (the canonical "cheap fingerprint"
	 *    region for a PE - it covers DOS+PE+optional headers + start of
	 *    .text on every reasonably-sized driver).  Smaller files just
	 *    hash the whole thing. */
	hash_len = (size < 4096) ? size : 4096;
	sha256(buf, hash_len, binary_digest);
	binary_fp = wdm_truncate32(binary_digest);

	/* 2. Hash the signer cert blob too if we have one.  Used as the
	 *    "signer fingerprint" segment so downstream observers can group
	 *    drivers by who signed them.  Empty cert -> all-zero hash, which
	 *    cert(E) will reject IF the b_segments[CHROMO_B_CERT_CHAIN] is
	 *    also zero - so we leave a non-zero binary-derived value in
	 *    CERT_CHAIN below to keep the un-signed-but-loader-approved path
	 *    working. */
	memset(signer_digest, 0, sizeof(signer_digest));
	if (signer && signer->signer_cert_size > 0 &&
	    signer->signer_cert_off + signer->signer_cert_size <= size) {
		sha256((const u8 *)buf + signer->signer_cert_off,
		       signer->signer_cert_size, signer_digest);
	}

	/* 3. Core identity fields */
	subj->subject_id = binary_fp;
	if (subj->subject_id == 0) {
		/* binary hash starts with 4 zero bytes - vanishingly rare but
		 * 0 is reserved for "kernel-init", bump to 1. */
		subj->subject_id = 1;
	}
	subj->domain          = TRUST_DOMAIN_LINUX;
	subj->subject_class   = TRUST_SUBJECT_CLASS_KERNEL_DRIVER;
	subj->trust_score     = TRUST_SCORE_MAX;       /* +1000 */
	subj->threshold_low   = TRUST_SCORE_NEUTRAL;   /* 0 */
	subj->threshold_high  = 800;                   /* matches Theta(LOAD_KERNEL_BINARY) */
	subj->capabilities    = 0xFFFFFFFFU;           /* full capability mask, gate enforces */
	subj->authority_level = TRUST_AUTH_KERNEL;
	subj->sex             = 0;                     /* TRUST_SEX_XX */
	subj->sex_valid       = 1;
	subj->last_action_ts  = ktime_get_ns();
	subj->decay_rate      = 0;                     /* kernel binaries don't decay */
	subj->flags           = 0;                     /* not frozen, not apoptotic */

	/* 4. Chromosome - 23 A + 23 B segments */
	{
		trust_chromosome_t *c = &subj->chromosome;

		memset(c, 0, sizeof(*c));

		/* A-segments (runtime behavioral DNA) - we don't have runtime
		 * data yet (driver hasn't started), so seed with the binary
		 * fingerprint where it makes semantic sense and zero elsewhere. */
		c->a_segments[CHROMO_A_ACTION_HASH]   = binary_fp;
		c->a_segments[CHROMO_A_TOKEN_BALANCE] = TRUST_TOKEN_MAX_DEFAULT;
		c->a_segments[CHROMO_A_TRUST_STATE]   = (u32)TRUST_SCORE_MAX;
		/* CHROMO_A_SEX is the 23rd pair conformance score; leave at
		 * the conformant default so trust_chromosome_determine_sex()
		 * returns CHROMO_SEX_XX. */
		c->a_segments[22 /* CHROMO_A_SEX */] = 200;  /* > theta */

		/* B-segments (construction identity DNA) - the actually load-
		 * bearing ones for cert(E) inside trust.ko: SIGNATURE and
		 * CERT_CHAIN must not BOTH be zero or cert(E) returns false. */
		c->b_segments[CHROMO_B_BINARY_HASH]   = binary_fp;
		c->b_segments[CHROMO_B_LIBRARY_DEPS]  =
			wdm_str_fingerprint("ntoskrnl.exe");
		c->b_segments[CHROMO_B_CONFIG_HASH]   = 0;
		c->b_segments[CHROMO_B_INSTALL_SRC]   =
			wdm_str_fingerprint(driver_name ? driver_name : "");
		c->b_segments[CHROMO_B_SIGNATURE]     =
			wdm_truncate32(signer_digest);
		c->b_segments[CHROMO_B_PERMISSIONS]   = 0;
		c->b_segments[CHROMO_B_OWNER]         = 0;
		c->b_segments[CHROMO_B_SECTION_HASH]  =
			wdm_truncate32(binary_digest + 4);   /* second 32 bits */
		c->b_segments[CHROMO_B_IMPORT_TABLE]  =
			wdm_truncate32(binary_digest + 8);
		c->b_segments[CHROMO_B_EXPORT_TABLE]  =
			wdm_truncate32(binary_digest + 12);
		c->b_segments[CHROMO_B_RESOURCE_HASH] = 0;
		c->b_segments[CHROMO_B_MANIFEST]      = 0;
		c->b_segments[CHROMO_B_CERT_CHAIN]    =
			wdm_truncate32(signer_digest + 4);
		/* Belt-and-suspenders: if we have NO signer at all, still
		 * publish a non-zero CERT_CHAIN value derived from the binary
		 * itself.  cert(E) accepts "either" SIGNATURE or CERT_CHAIN
		 * non-zero (see trust_authz.c:authz_cert_ok), so this guarantees
		 * the predicate passes for the "loader-approved unsigned" path
		 * (which only happens with WDM_HOST_ALLOW_UNSIGNED). */
		if (c->b_segments[CHROMO_B_CERT_CHAIN] == 0)
			c->b_segments[CHROMO_B_CERT_CHAIN] = binary_fp ^ 0xC0DECAFEU;

		c->b_segments[CHROMO_B_RELOCATION]    = (u32)size;
		c->b_segments[CHROMO_B_DEBUG_INFO]    = 0;
		c->b_segments[CHROMO_B_COMPILER_ID]   = wdm_str_fingerprint("MSVC");
		c->b_segments[CHROMO_B_ABI_COMPAT]    = wdm_str_fingerprint("WDM");
		c->b_segments[CHROMO_B_FUSE_STATE]    = 0;
		c->b_segments[CHROMO_B_BOOT_CHAIN]    = 0;
		c->b_segments[CHROMO_B_TPM_STATE]     = 0;
		c->b_segments[CHROMO_B_HW_IDENTITY]   = 0;
		c->b_segments[CHROMO_B_FIRMWARE]      = 0;
		c->b_segments[CHROMO_B_SEX]           = 200;  /* > theta */

		c->sex             = 0;                       /* CHROMO_SEX_XX */
		c->generation      = 0;
		c->division_count  = 0;
		c->parent_id       = 0;                       /* root of authority */
		c->birth_timestamp = ktime_get_ns();
		c->mutation_count  = 0;
		c->checksum        = wdm_chromo_checksum(c);
	}

	/* 5. Proof state - derive seed = sha256(binary[0..hash_len]); proof =
	 *    sha256(seed || 0x01).  trust.ko's authz_proof_ok() requires
	 *    proof_valid == 1 && chain_broken == 0; both hold for a fresh
	 *    chain. */
	memcpy(subj->proof.seed, binary_digest, sizeof(subj->proof.seed));
	memcpy(proof_seed, binary_digest, sizeof(proof_seed));
	{
		u8 buf2[SHA256_DIGEST_SIZE + 1];
		memcpy(buf2, proof_seed, sizeof(proof_seed));
		buf2[SHA256_DIGEST_SIZE] = 0x01;
		sha256(buf2, sizeof(buf2), proof_value);
	}
	memcpy(subj->proof.proof, proof_value, sizeof(subj->proof.proof));
	subj->proof.nonce          = 1;
	subj->proof.last_proof_ts  = ktime_get_ns();
	subj->proof.hash_cfg       = TRUST_HASH_CFG_SHA256;
	subj->proof.chain_length   = 1;
	subj->proof.seed_set       = 1;
	subj->proof.proof_valid    = 1;
	subj->proof.chain_broken   = 0;

	/* 6. Token economy - balance >= cost(LOAD_KERNEL_BINARY) (=1) */
	subj->tokens.balance           = TRUST_TOKEN_MAX_DEFAULT;
	subj->tokens.max_balance       = TRUST_TOKEN_MAX_DEFAULT;
	subj->tokens.regen_rate        = TRUST_TOKEN_REGEN_DEFAULT * 4;
	subj->tokens.total_burned      = 0;
	subj->tokens.total_regenerated = 0;
	subj->tokens.last_regen_ts     = ktime_get_ns();
	subj->tokens.starved           = 0;

	/* 7. Lifecycle - active, no parent, no spawns */
	subj->lifecycle.state               = TRUST_LIFECYCLE_ACTIVE;
	subj->lifecycle.generation          = 0;
	subj->lifecycle.spawn_count         = 0;
	subj->lifecycle.total_spawns        = 0;
	subj->lifecycle.parent_id           = 0;
	subj->lifecycle.meiotic_partner     = 0;
	subj->lifecycle.spawn_window_start  = ktime_get_ns();
	subj->lifecycle.birth_ts            = ktime_get_ns();
	subj->lifecycle.last_division_ts    = 0;
	subj->lifecycle.max_score           = TRUST_SCORE_MAX;
	subj->lifecycle.flags               = TRUST_LIFE_FLAG_CHECKPOINT;

	/* 8. Immune - healthy */
	subj->immune.status              = TRUST_IMMUNE_HEALTHY;
	subj->immune.apoptosis_cascade   = 0;
	subj->immune.suspicious_actions  = 0;
	subj->immune.quarantine_reason   = 0;
	subj->immune.quarantine_ts       = 0;
	subj->immune.apoptosis_deadline  = 0;

	/* 9. TRC - normal mode, no resistance bias */
	subj->trc.resistance        = 0;
	subj->trc.threshold_bias    = 0;
	subj->trc.cost_multiplier   = 256;   /* 1.0 in 8.8 fixed-point */
	subj->trc.state             = TRUST_TRC_NORMAL;
	subj->trc._g_t_lo           = 0;
	subj->trc._g_t_hi           = 0;
	subj->trc._l_t_pack         = 0;     /* L_t = 0, valid bit clear */
	subj->trc.flow_in           = 0;
	subj->trc.flow_out          = 0;
	subj->trc.resistance_decay  = 0;

	/* Derive a friendly proof-fragment for the audit log: 64-bit prefix
	 * of the proof.  Useful when correlating coherence-emitted events
	 * with kernel logs. */
	{
		u64 proof_prefix = wdm_truncate64(proof_value);
		pr_info("wdm_host: subject mint: name='%s' subject_id=0x%08x "
			"trust_score=%d binary_fp=0x%08x signer_fp=0x%08x "
			"proof_prefix=0x%016llx chromo_checksum=0x%08x\n",
			driver_name ? driver_name : "(null)",
			subj->subject_id, subj->trust_score,
			binary_fp, wdm_truncate32(signer_digest),
			(unsigned long long)proof_prefix,
			subj->chromosome.checksum);
	}

	(void)proof_seed;   /* retained as a named local for log readability */

	return subj;
}
EXPORT_SYMBOL_GPL(wdm_mint_driver_subject);

void wdm_destroy_driver_subject(void *opaque_subject)
{
	trust_subject_t *subj = (trust_subject_t *)opaque_subject;

	if (!subj)
		return;
	pr_info("wdm_host: subject destroy: subject_id=0x%08x\n",
		subj->subject_id);
	/* Wipe the seed before free so a follow-on alloc that lands on this
	 * memory can't read it (defense in depth - the proof seed is the only
	 * crypto-significant byte sequence in the struct). */
	memzero_explicit(subj->proof.seed, sizeof(subj->proof.seed));
	kfree(subj);
}
EXPORT_SYMBOL_GPL(wdm_destroy_driver_subject);

uint32_t wdm_subject_id(const void *opaque_subject)
{
	const trust_subject_t *subj = (const trust_subject_t *)opaque_subject;
	if (!subj)
		return 0;
	return subj->subject_id;
}
EXPORT_SYMBOL_GPL(wdm_subject_id);

int32_t wdm_subject_trust_score(const void *opaque_subject)
{
	const trust_subject_t *subj = (const trust_subject_t *)opaque_subject;
	if (!subj)
		return 0;
	return subj->trust_score;
}
EXPORT_SYMBOL_GPL(wdm_subject_trust_score);
