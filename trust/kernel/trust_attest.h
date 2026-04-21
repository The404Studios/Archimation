/*
 * trust_attest.h - TPM2 Boot Attestation for the Root of Authority
 *
 * trust.ko must REFUSE TO INITIALIZE if the userspace it is about to
 * verify has itself been tampered.  At boot, trust_attest_init() reads
 * PCR 11 from the TPM2 chip (where systemd-stub measures the Unified
 * Kernel Image — see systemd TPM2_PCR_MEASUREMENTS doc) and compares
 * it against an expected value written at bootc image build time to
 *   /etc/archwindows/expected-pcr-11
 *
 * The module exposes three terminal modes:
 *
 *   HARDWARE — TPM 2.0 present, PCR 11 matched: /dev/trust created,
 *              full authority semantics active.  dmesg at pr_info.
 *
 *   SOFTWARE — TPM absent, TPM 1.2, or file missing: /dev/trust still
 *              created but every subject record is annotated with
 *              TRUST_MODE_SOFTWARE — authority claims are advisory
 *              rather than cryptographically grounded.  dmesg at
 *              pr_warn (VISIBLE — never silent).
 *
 *   FAILED   — TPM 2.0 present and PCR 11 mismatch: /dev/trust NOT
 *              created, trust_init returns -EACCES, the module bails.
 *              dmesg at pr_err + pr_crit with user-visible override
 *              guidance ("Boot with trust.attest=skip to force
 *              software mode").
 *
 * Kernel cmdline override:  trust.attest=hardware|software|skip
 *   hardware — hard-fail on anything other than a matching PCR 11
 *   software — skip TPM entirely, go straight to SOFTWARE mode
 *   skip     — alias of software, for clarity during recovery
 *   (unset)  — auto-detect
 *
 * Design rationale + failure-mode UX: docs/research/s72_gamma_tpm2_attest.md
 */

#ifndef TRUST_ATTEST_H
#define TRUST_ATTEST_H

#include <linux/types.h>

typedef enum {
    TRUST_ATTEST_HARDWARE = 0,   /* TPM 2.0 + PCR match: full authority */
    TRUST_ATTEST_SOFTWARE = 1,   /* No TPM / old TPM / degraded: advisory */
    TRUST_ATTEST_FAILED   = 2,   /* TPM 2.0 + PCR mismatch: refuse init */
} trust_attest_mode_t;

/*
 * Called EARLY in trust_init (before TLB/APE/lifecycle setup).
 * Returns 0 on HARDWARE or SOFTWARE (init continues).
 * Returns non-zero (typically -EACCES) on FAILED — caller must abort.
 */
int trust_attest_init(void);

/*
 * Teardown counterpart — release any TPM chip reference acquired in
 * trust_attest_init.  Called from trust_exit.  Idempotent.
 */
void trust_attest_cleanup(void);

/* Query the cached mode decided at init time. */
trust_attest_mode_t trust_attest_mode(void);

/* Convenience: true iff current mode is HARDWARE. */
bool trust_attest_hardware(void);

/* Human-readable mode name for dmesg / sysfs. */
const char *trust_attest_mode_name(trust_attest_mode_t m);

/*
 * Subject-record annotation flag.  Other trust.ko files (e.g.
 * trust_core.c at registration time) may OR this into a subject's
 * trust flags when mode != HARDWARE so userspace can tell that a
 * proof was issued under software-only attestation.
 *
 * Uses bit 31 to stay out of the way of existing TRUST_FLAG_* values
 * in trust_types.h (which currently consume bits 0..7).
 */
#define TRUST_MODE_SOFTWARE  (1U << 31)

#endif /* TRUST_ATTEST_H */
