// SPDX-License-Identifier: GPL-2.0
/*
 * wdm_host_signature.c - Authenticode presence check for hosted .sys files
 *
 * Per the S64 audit, wdm_host_loader.c happily ring-0 maps any .sys we
 * point it at - that's a CVE waiting to happen. Until we can wire the
 * full PKCS#7 / WinTrust chain into the kernel (which needs userspace
 * help via the keyrings subsystem), we enforce the cheap baseline:
 *
 *   1. The PE optional header MUST contain a non-empty SECURITY
 *      data directory entry (PE_DIR_SECURITY = index 4).
 *   2. The first WIN_CERTIFICATE blob at that file offset MUST have
 *      a sane wLength, wRevision, and wCertificateType.
 *
 * That's enough to reject a bare unsigned developer build that someone
 * dropped into /lib/modules - the operator must compile the module with
 * -DWDM_HOST_ALLOW_UNSIGNED to opt out of this check. We DO NOT verify
 * the cert chain itself: doing so requires a userspace co-process and
 * a trust anchor store, which are tracked separately.
 *
 * Public API:
 *   wdm_verify_pe_signature(buf, size) -> bool
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>

#include "wdm_host_internal.h"
#include "wdm_host_signature.h"

/* Re-define the minimal PE structures we need. We don't pull these from
 * wdm_host_loader.c because that file keeps them file-local on purpose
 * (avoids ABI drift if those structs grow new fields). */

#define WDM_PE_DOS_MAGIC      0x5A4D
#define WDM_PE_SIGNATURE      0x00004550U
#define WDM_PE_OPT_MAGIC_32   0x010B
#define WDM_PE_OPT_MAGIC_64   0x020B

/* Index of the IMAGE_DIRECTORY_ENTRY_SECURITY data directory entry. The
 * SECURITY entry is unique among data directories: VirtualAddress is a
 * raw FILE OFFSET, NOT an RVA (because the cert blob lives outside any
 * mapped section). */
#define WDM_DIR_SECURITY 4

/* WIN_CERTIFICATE header per the PE/COFF spec. */
struct wdm_win_certificate {
	uint32_t dwLength;          /* total length including this header */
	uint16_t wRevision;         /* WIN_CERT_REVISION_2_0 = 0x0200    */
	uint16_t wCertificateType;  /* WIN_CERT_TYPE_PKCS_SIGNED_DATA = 2 */
	/* uint8_t bCertificate[];                                     */
} __packed;

#define WDM_WIN_CERT_REVISION_1_0       0x0100
#define WDM_WIN_CERT_REVISION_2_0       0x0200
#define WDM_WIN_CERT_TYPE_X509          0x0001
#define WDM_WIN_CERT_TYPE_PKCS_SIGNED   0x0002
#define WDM_WIN_CERT_TYPE_RESERVED      0x0003
#define WDM_WIN_CERT_TYPE_TS_SIGNED     0x0004

/* Smallest WIN_CERTIFICATE we accept - header + one DER byte. */
#define WDM_MIN_CERT_BYTES (sizeof(struct wdm_win_certificate) + 1)

bool wdm_verify_pe_signature(const void *buf, size_t size)
{
	const u8 *p = buf;
	uint32_t pe_off;
	uint16_t opt_magic;
	uint32_t num_dirs;
	uint32_t sec_off, sec_size;
	const struct wdm_win_certificate *cert;
	const uint32_t *pe_sig;
	const uint16_t *dos_magic;
	const uint8_t *opt_hdr;
	size_t dirs_off;
	uint32_t dir_offset_in_opt;

	if (!buf || size < 0x40) {
		pr_err("wdm_host: signature check: file too small (%zu)\n",
		       size);
		return false;
	}

	/* MZ */
	dos_magic = (const uint16_t *)p;
	if (le16_to_cpu(*dos_magic) != WDM_PE_DOS_MAGIC) {
		pr_err("wdm_host: signature check: not a PE (no MZ)\n");
		return false;
	}

	/* e_lfanew at offset 0x3C - 4 bytes signed */
	pe_off = le32_to_cpu(*(const uint32_t *)(p + 0x3C));
	if (pe_off >= size || pe_off + 4 + 20 > size) {
		pr_err("wdm_host: signature check: bad PE offset %u\n", pe_off);
		return false;
	}

	pe_sig = (const uint32_t *)(p + pe_off);
	if (le32_to_cpu(*pe_sig) != WDM_PE_SIGNATURE) {
		pr_err("wdm_host: signature check: missing PE\\0\\0\n");
		return false;
	}

	/* Optional header magic at pe_off + 4 (COFF) + 20 (sizeof COFF)
	 *  = pe_off + 24. */
	if (pe_off + 24 + 2 > size) {
		pr_err("wdm_host: signature check: opt-header truncated\n");
		return false;
	}
	opt_hdr = p + pe_off + 24;
	opt_magic = le16_to_cpu(*(const uint16_t *)opt_hdr);

	/* NumberOfRvaAndSizes lives at:
	 *   PE32  : opt_hdr + 92
	 *   PE32+ : opt_hdr + 108
	 * Data directories follow immediately after that uint32. */
	if (opt_magic == WDM_PE_OPT_MAGIC_32) {
		dir_offset_in_opt = 92;
	} else if (opt_magic == WDM_PE_OPT_MAGIC_64) {
		dir_offset_in_opt = 108;
	} else {
		pr_err("wdm_host: signature check: unknown opt-magic 0x%04x\n",
		       opt_magic);
		return false;
	}

	if (pe_off + 24 + dir_offset_in_opt + 4 > size) {
		pr_err("wdm_host: signature check: NumberOfRvaAndSizes "
		       "truncated\n");
		return false;
	}
	num_dirs = le32_to_cpu(*(const uint32_t *)
			       (opt_hdr + dir_offset_in_opt));
	if (num_dirs <= WDM_DIR_SECURITY) {
		pr_err("wdm_host: signature check: only %u data directories "
		       "(need >= %u for SECURITY)\n",
		       num_dirs, WDM_DIR_SECURITY + 1);
		return false;
	}

	dirs_off = pe_off + 24 + dir_offset_in_opt + 4
		   + (size_t)WDM_DIR_SECURITY * 8U;
	if (dirs_off + 8 > size) {
		pr_err("wdm_host: signature check: SECURITY directory "
		       "truncated\n");
		return false;
	}
	sec_off  = le32_to_cpu(*(const uint32_t *)(p + dirs_off + 0));
	sec_size = le32_to_cpu(*(const uint32_t *)(p + dirs_off + 4));

	if (sec_off == 0 || sec_size == 0) {
		pr_err("wdm_host: signature check: PE has no SECURITY blob "
		       "(sec_off=%u sec_size=%u) - refusing unsigned .sys\n",
		       sec_off, sec_size);
		return false;
	}

	if (sec_size < WDM_MIN_CERT_BYTES) {
		pr_err("wdm_host: signature check: SECURITY size %u "
		       "below WIN_CERTIFICATE header\n", sec_size);
		return false;
	}
	if ((u64)sec_off + sec_size > (u64)size) {
		pr_err("wdm_host: signature check: SECURITY blob extends "
		       "beyond file (off=%u size=%u file=%zu)\n",
		       sec_off, sec_size, size);
		return false;
	}

	cert = (const struct wdm_win_certificate *)(p + sec_off);
	if (le32_to_cpu(cert->dwLength) > sec_size ||
	    le32_to_cpu(cert->dwLength) < WDM_MIN_CERT_BYTES) {
		pr_err("wdm_host: signature check: WIN_CERTIFICATE.dwLength "
		       "(%u) inconsistent with directory size (%u)\n",
		       le32_to_cpu(cert->dwLength), sec_size);
		return false;
	}
	if (le16_to_cpu(cert->wRevision) != WDM_WIN_CERT_REVISION_1_0 &&
	    le16_to_cpu(cert->wRevision) != WDM_WIN_CERT_REVISION_2_0) {
		pr_err("wdm_host: signature check: bad WIN_CERTIFICATE "
		       "revision 0x%04x\n", le16_to_cpu(cert->wRevision));
		return false;
	}
	if (le16_to_cpu(cert->wCertificateType) != WDM_WIN_CERT_TYPE_X509 &&
	    le16_to_cpu(cert->wCertificateType) != WDM_WIN_CERT_TYPE_PKCS_SIGNED &&
	    le16_to_cpu(cert->wCertificateType) != WDM_WIN_CERT_TYPE_TS_SIGNED) {
		pr_err("wdm_host: signature check: unknown wCertificateType "
		       "0x%04x\n", le16_to_cpu(cert->wCertificateType));
		return false;
	}

	pr_info("wdm_host: signature check: WIN_CERTIFICATE present "
		"(revision=0x%04x type=0x%04x size=%u) - shape OK; chain "
		"verification deferred to userspace co-process\n",
		le16_to_cpu(cert->wRevision),
		le16_to_cpu(cert->wCertificateType),
		le32_to_cpu(cert->dwLength));
	return true;
}
EXPORT_SYMBOL_GPL(wdm_verify_pe_signature);
