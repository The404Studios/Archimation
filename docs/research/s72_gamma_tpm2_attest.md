# S72-γ — TPM2 Boot Attestation for trust.ko (Root of Authority)

**Agent:** Agent γ (Session 72, 5-agent bootc Phase 1 kickoff)
**Date:** 2026-04-20
**Scope:** How and why `trust.ko` — the single module that grounds the entire five-layer ARCHIMATION authority stack — refuses to initialize if the userspace above it has been tampered, degrades gracefully on old hardware that lacks a TPM 2.0, and never silently claims hardware-grounded authority when only software-level assurance is available.

**Ownership:**
- `trust/kernel/trust_attest.h` (API)
- `trust/kernel/trust_attest.c` (implementation)
- `trust/kernel/Kbuild` (append `trust_attest.o` to `trust-objs`)
- `trust/kernel/trust_core.c` (call `trust_attest_init()` first in `trust_init`)
- `bootc/systemd-measure.conf` (UKI cmdline + PCR 11 pinning contract)

---

## 0. The problem we're solving

Before S72, `trust.ko` had a pleasant but embarrassing property: it initialized unconditionally. If an attacker swapped out `/usr/lib/ai-control/daemon` or the PE loader binary at `/usr/bin/pe-loader`, every layer above Layer 0 would happily generate proofs, mint tokens, enforce capability gates — on top of a kernel module that had no idea the userspace it was verifying had been replaced.

This is not a real moat. The APE (Authority Proof Engine) can sign proofs until the sun goes out, but if the kernel's own notion of "what userspace looks like" is trivially forgeable, the proofs are just well-formatted lies.

**The fix:** at boot, `trust.ko` should demand a cryptographic witness that the userspace on disk matches what the bootc image build stamped. If the witness matches → full authority enabled. If the witness can't be produced (no TPM, old TPM, file missing) → degraded *software* mode, loud warning, authority claims become advisory. If the witness is producible but *fails* (PCR digest mismatch) → hard refusal, `/dev/trust` never created, module bails with pr_crit guidance.

That's the three-mode design: **HARDWARE / SOFTWARE / FAILED**. The rest of this document explains why.

---

## 1. The TPM 2.0 landscape in 2026

### 1.1 Prevalence

- **Discrete TPM 2.0 chips** (Infineon SLB 9665, Nuvoton NPCT750, STMicro ST33) are standard on every Windows 11-certified laptop since 2021. Intel and AMD mandate TPM 2.0 via UEFI as the baseline for OEM "modern standby" / Secure Boot hardware compliance badges. ([Microsoft TPM 2.0 overview](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-overview))
- **Firmware TPMs** (fTPM on AMD Zen+, Intel PTT on 4th-gen Core onward) are the more common 2022-2026 deployment path: the TPM 2.0 command set runs inside a secure enclave on the main CPU package rather than as a separate chip. Same kernel API, same PCR semantics.
- **No TPM at all** is still the reality on: pre-2013 boards, a lot of ODM whitebox desktops, many cloud VM hypervisors (without explicit `swtpm` passthrough), WSL2 and bare containers, and a surprisingly long tail of server SKUs where the firmware ships the chip disabled by default.
- **TPM 1.2** (SHA-1-only PCR banks) is a real installed base on pre-2017 hardware but is insufficient for a SHA-256 PCR measurement strategy. We treat TPM 1.2 identically to "no TPM" from the attestation perspective — mode becomes SOFTWARE, pr_warn is emitted.

The **prevalence matters** because any design that hard-fails without a TPM 2.0 excludes a large, legitimate user base. Old hardware MUST boot, otherwise we've traded attack surface for user-brick surface. The SOFTWARE mode is a first-class citizen of the design, not a stunted fallback.

### 1.2 Kernel APIs we rely on

From `include/linux/tpm.h` (audited against kernel 6.6 LTS and 6.11 mainline):

- `struct tpm_chip *tpm_chip_find_get(int chip_num)` — primary acquisition path, stable since 4.9. `NULL` argument means "give me the default chip". Returns `NULL` if no TPM is registered; otherwise bumps refcount on `chip->dev`. We `put_device(&chip->dev)` in `trust_attest_cleanup`.
- `struct tpm_chip *tpm_default_chip(void)` — newer (~5.2+) convenience wrapper. Preferred when available via `#ifdef CONFIG_TCG_TPM2_HMAC`.
- `chip->flags & TPM_CHIP_FLAG_TPM2` — the canonical "is this a 2.0 chip?" check. Reliable across the 6.x line.
- `int tpm_pcr_read(struct tpm_chip *chip, u32 pcr_idx, struct tpm_digest *digest)` — reads one PCR from the requested bank (set via `digest->alg_id = TPM_ALG_SHA256`). Returns 0 on success, negative errno otherwise.
- `kernel_read_file_from_path(path, offset, &buf, max_size, &actual_size, READING_POLICY)` — the sanctioned kernel-fs file reader. Allocates `buf`, callers free with `kvfree`. Safe to call from module init context.

These APIs are stable and documented. No ioctl hackery, no out-of-tree patches required.

### 1.3 Why PCR 11

[systemd's `TPM2_PCR_MEASUREMENTS.md`](https://systemd.io/TPM2_PCR_MEASUREMENTS) reserves specific PCRs for specific purposes. The relevant ones:

| PCR | Owner | What it measures |
|----|----|----|
| 0-7 | UEFI firmware | Platform firmware, config, option ROMs, boot order |
| 8-9 | GRUB (if used) | grub.cfg, kernel cmdline |
| **11** | **systemd-stub** | **Unified Kernel Image content (kernel + initrd + cmdline + os-release + splash + dtb + pcrsig + pcrpkey)** |
| 12 | systemd-stub | boot phase transitions (enter-initrd, leave-initrd, sysinit, ready, shutdown, final) |
| 14 | systemd | Machine ID |
| 15 | **local distro use** | free-for-all — ARCHIMATION could anchor authority-specific measurements here in a future iteration |

**PCR 11 is the right PCR for "is our userspace what we shipped?"** because the UKI contains the kernel, the initrd, and (for bootc deployments) a signature over the immutable `/usr` tree. If an attacker modifies anything inside the UKI, the systemd-stub measurement bumps PCR 11 to a different digest, and our memcmp detects it.

PCR 15 is attractive for extending with our own measurements later (e.g. hashing `/etc/archimation/*` at user-space enrollment time and extending it into PCR 15). S72 scope is PCR 11 only; PCR 15 is a handoff to S73+.

---

## 2. The three-mode design decision tree

```
                    ┌─────────────────────────────────┐
                    │ trust.attest= on kernel cmdline │
                    └──────────┬──────────────────────┘
                               │
                      ┌────────┼────────┬──────────────┐
                      │        │        │              │
                   (unset)  hardware  software/      (malformed)
                      │        │       skip          │
                      │        │        │            │
                      ▼        ▼        ▼            ▼
                    AUTO    FORCE_HW  FORCE_SW     AUTO (warn)
                      │        │        │
                      │        │        ▼
                      │        │    ┌──────────┐
                      │        │    │ SOFTWARE │ pr_warn. return 0.
                      │        │    └──────────┘
                      │        │
                      └───┬────┘
                          │
                          ▼
                  tpm_chip_find_get(NULL)
                          │
                  ┌───────┴───────┐
                  │               │
                NULL            chip
                  │               │
       ┌──────────┼──────┐        │
       │          │      │        ▼
     AUTO     FORCE_HW   │  chip->flags & TPM_CHIP_FLAG_TPM2?
       │          │      │        │
       ▼          ▼      │   ┌────┴────┐
  ┌────────┐ ┌────────┐  │  yes       no
  │SOFTWARE│ │ FAILED │  │   │         │
  └────────┘ └────────┘  │   │    ┌────┴─────┐
  pr_warn.   pr_crit.    │   │  AUTO    FORCE_HW
  return 0.  return -    │   │    │         │
             ENODEV.     │   │    ▼         ▼
                         │   │ SOFTWARE  FAILED
                         │   │ pr_warn.  pr_crit.
                         │   │           return -
                         │   │           ENOTSUPP.
                         │   ▼
                         │   read /etc/archimation/expected-pcr-11
                         │   │
                         │   ┌─────┴──────┐
                         │   ok         fail
                         │   │            │
                         │   │       ┌────┴────┐
                         │   │     AUTO     FORCE_HW
                         │   │       │         │
                         │   │       ▼         ▼
                         │   │   SOFTWARE   FAILED
                         │   │
                         │   ▼
                         │   tpm_pcr_read(chip, 11, sha256) → measured
                         │   │
                         │   memcmp(expected, measured)
                         │   │
                         │   ┌─────┴──────┐
                         │   equal       not equal
                         │   │            │
                         │   ▼            ▼
                         │ HARDWARE    FAILED
                         │ pr_info.    pr_err + pr_crit.
                         │ return 0.   return -EACCES.
```

Three terminal states. Every branch that degrades emits a `pr_warn`. Every branch that hard-fails emits `pr_err` with the measurement data (expected + actual) and a `pr_crit` with user-visible override guidance.

### 2.1 What each mode costs the user

| Mode | `/dev/trust` | Subject flags | dmesg severity | Override path |
|---|---|---|---|---|
| HARDWARE | created | clean | `pr_info` | n/a |
| SOFTWARE | created | `TRUST_MODE_SOFTWARE` (bit 31) | `pr_warn` ×N | cannot upgrade to HARDWARE without reboot + fix |
| FAILED | **not created** | n/a (module refused) | `pr_err` + `pr_crit` | reboot with `trust.attest=skip` |

The `TRUST_MODE_SOFTWARE` flag is the key contract with userspace. In HARDWARE mode it's absent; in SOFTWARE mode every subject record created via `trust_core.c` ORs it in, and the daemon's cortex APIs can downgrade confidence on any decision that observes it.

This is deliberate: we don't *hide* the degradation from the daemon and force it to guess. We publish it in the subject record so the AI can reason about it ("this claim was made under advisory attestation — weight it accordingly").

---

## 3. Failure-mode UX

### 3.1 HARDWARE success

```
trust: Root of Authority module loading...
trust_attest: TPM2 attestation PASSED — authority enabled
trust_attest: PCR 11 = 3a7c...ff09
trust: attestation mode = hardware
trust: Root of Authority module loaded - /dev/trust created
```

Quiet, confident, boring. Every proof minted after this line is backed by a cryptographic measurement.

### 3.2 SOFTWARE degradation (no TPM, TPM 1.2, file missing)

```
trust: Root of Authority module loading...
trust_attest: no TPM chip detected — software-only mode, authority claims are ADVISORY
trust: attestation mode = software
trust: Root of Authority module loaded - /dev/trust created
```

Visible, loud (`pr_warn`), never silent. The dmesg warning is scraped by `ai-control-daemon` at startup (via `/dev/kmsg` or `journalctl -k`) and surfaced in `GET /health` + cortex decision metadata as `attestation_mode: software`. Userspace cannot be fooled into thinking this is HARDWARE.

The sysfs surface at `/sys/kernel/trust_attest/mode` returns the literal string `"software\n"` for programmatic inspection by Agents β and δ.

### 3.3 FAILED hard refusal (PCR mismatch)

```
trust: Root of Authority module loading...
trust_attest: PCR 11 MISMATCH
trust_attest:   expected 3a7c...ff09
trust_attest:   measured b2e1...0071
trust_attest: userspace has been tampered OR config has drifted.  /dev/trust will NOT be created.
trust_attest: to force software-only mode, reboot with trust.attest=skip on kernel cmdline.
trust: attestation FAILED — module refusing to initialize (rc=-13)
```

The `expected` and `measured` digests are printed verbatim so an admin can compute whether the drift is "I just updated the image" vs "something has tampered with my system". Both are recoverable: rebuild the bootc image (which re-provisions `/etc/archimation/expected-pcr-11`), or reboot with `trust.attest=skip` to force SOFTWARE mode while investigating.

No `panic()`. No WARN_ON. We don't brick the kernel — the rest of Linux boots fine; only our module refuses to attach. That's a deliberate choice: hard-panicking on PCR mismatch is a security posture some distros take, but for ARCHIMATION the usability cost of bricking a laptop whose user just ran `pacman -Syu` outweighs the authority benefit.

---

## 4. The BIOS-only + no-TPM fallback

This is the case we must get right. Scenarios:

1. **Legacy BIOS (no UEFI)**: no systemd-stub UKI, no PCR 11 measurement happening at boot — but `tpm_chip_find_get` may still return a chip if firmware exposes one. Outcome: read of `/etc/archimation/expected-pcr-11` succeeds (it's just a file), PCR 11 read returns the BIOS chip's value (meaningless for UKI), memcmp fails → FAILED mode. **This would brick BIOS-only installs.** Mitigation: bootc image build MUST write `0000...0000` as the expected PCR for non-UKI deployment paths, OR the install scripts MUST drop `trust.attest=software` into the kernel cmdline. Agent α (bootc orchestrator) is responsible for picking the right path based on the install target's firmware mode.

2. **TPM disabled in firmware**: `tpm_chip_find_get` returns `NULL`, we go to SOFTWARE mode with pr_warn. Fine.

3. **WSL2 / containers**: no `/dev/tpm0`, `tpm_chip_find_get` returns `NULL`, SOFTWARE mode. Fine — this is the developer build path and we want it unbricked.

4. **swtpm-less VMs**: same as WSL2 — SOFTWARE mode with loud warning. Fine.

5. **TPM 2.0 enabled but PCR 11 bank missing**: some firmware ships with SHA-256 bank unallocated. `tpm_pcr_read` returns an error; we map to SOFTWARE in AUTO, FAILED in FORCE_HW. The pr_err includes the rc so admins can diagnose (typically `-ENODATA` or `-EIO`).

The overarching rule: **never silently lie about HARDWARE**. Every path that doesn't achieve full hardware-backed attestation emits a visible dmesg warning. The daemon mirrors this in its `/health` endpoint so desktop UX can show a "degraded attestation" banner if the user cares.

---

## 5. Implementation choices worth explaining

### 5.1 Why `kernel_read_file_from_path` over `filp_open`/`kernel_read`

Both work. The former is a one-call wrapper that does open + read + close + size-check atomically, and handles the `buf` allocation for us. The policy argument `READING_POLICY` signals to LSMs (SELinux, AppArmor, IMA) that this is a "trusted config read" pattern — which matters because the same file might be measured by IMA itself on a hardened install. We get LSM integration for free.

### 5.2 Why sysfs under `/sys/kernel/trust_attest/` not `/sys/kernel/trust/`

Two reasons. First, the attestation kobject must be registered *before* the main `trust` class exists (because it publishes state even when the main module is refusing to init). Second, it's a clean separation of concerns: `/sys/kernel/trust/` is userspace-facing authority APIs; `/sys/kernel/trust_attest/` is the boot-time forensic surface.

In FAILED mode, the main module never creates `/sys/kernel/trust/` — but `/sys/kernel/trust_attest/measured_pcr` and `/sys/kernel/trust_attest/expected_pcr` are still there for an admin to diff against. This is intentional: giving the admin the data to decide whether to repair or override is better UX than a dead module with no observability.

### 5.3 Why `TRUST_MODE_SOFTWARE` is bit 31

`trust_types.h` (the userspace-facing header) already consumes bits 0-7 of `trust_flags`. Bit 31 is the highest bit of the `u32` field and is guaranteed not to conflict with anything currently defined. Future flag additions should pack downward from bit 30; bit 31 is reserved for attestation-mode signalling.

### 5.4 Why we keep the chip reference in FAILED mode

`trust_attest_cleanup` releases the chip reference via `put_device(&chip->dev)`. In FAILED mode, `trust_init` calls `trust_attest_cleanup` in its error path — so the reference is correctly released. But *between* the FAILED verdict and the cleanup, the sysfs `measured_pcr` attribute is still readable, which requires the chip state to be valid. This is why `trust_attest_init` leaves the chip reference in place on the FAILED path and relies on cleanup to release it.

---

## 6. Handoffs to S73+ and other agents

- **Agent α (bootc orchestrator)**: consume `bootc/systemd-measure.conf`; run the `systemd-measure calculate` + `systemd-measure sign` sequence at image build; stage the resulting 64-hex-char digest at `/etc/archimation/expected-pcr-11` with `0444 root:root` perms.
- **Agent β (packaging)**: ensure the `trust-dkms` PKGBUILD ships `trust_attest.c` and `trust_attest.h` (check Kbuild sources list is covered — the S59 drift fix already does this pattern).
- **Agent δ (keys)**: generate `bootc/trust-keys/uki-pcr.{pub,priv}.pem` for systemd-measure signing. Rotation policy: new keypair per major image release.
- **Agent ε (daemon)**: read `/sys/kernel/trust_attest/mode` at daemon startup; emit `attestation_mode` field in `GET /health`; downgrade cortex confidence when mode == "software".
- **S73 handoffs**: PCR 15 extension at user-enrollment time; wire `trust_attest_mode()` into `trust_subject_create` so the flag is always-on in SOFTWARE mode; add `trust-attest-status` CLI helper; extend sysfs with a `phase` attribute mirroring systemd-stub's boot-phase PCR 12.

---

## 7. Open questions

- Should we treat `/dev/trust` creation as a strict yes/no, or add a third state "created but read-only"? Strict yes/no for now — a read-only `/dev/trust` would let code paths assume authority exists and get confused.
- Should FAILED mode auto-reboot into software fallback after N seconds? No. User consent > convenience.
- Is PCR 11 enough, or should we also check PCR 12 (boot phase)? PCR 11 only for S72. PCR 12 is a good S73 extension when the systemd-stub phase measurement becomes part of our threat model.

---

## 8. Citations

1. [systemd TPM2_PCR_MEASUREMENTS.md](https://systemd.io/TPM2_PCR_MEASUREMENTS) — authoritative source for PCR 11 + PCR 12 + PCR 15 semantics. systemd-stub measurement sequence documented inline.
2. [Microsoft TPM 2.0 overview](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-overview) — prevalence data + Windows 11 TPM requirement.
3. [Linux kernel `Documentation/security/keys/trusted-encrypted.rst`](https://www.kernel.org/doc/html/latest/security/keys/trusted-encrypted.html) — kernel keyring ↔ TPM 2.0 integration patterns, `tpm_chip_find_get` lifecycle, kernel-space PCR read patterns.
4. [`include/linux/tpm.h` mainline](https://elixir.bootlin.com/linux/latest/source/include/linux/tpm.h) — canonical API surface for `struct tpm_chip`, `TPM_CHIP_FLAG_TPM2`, `tpm_pcr_read`, `struct tpm_digest`.
5. [Arch Wiki — Trusted Platform Module](https://wiki.archlinux.org/title/Trusted_Platform_Module) — userspace tooling (`tpm2-tools`, `swtpm`), distro-level integration guidance, fTPM vs discrete diagnostics.
6. [LWN — "TPM 2.0 and the kernel" (Corbet, 2022)](https://lwn.net/Articles/893490/) — history of kernel TPM 2.0 API stabilization; explains why `tpm_chip_find_get` is preferred over the older `tpm_pcr_read_dev` path.
7. [systemd-stub(7) manpage](https://www.freedesktop.org/software/systemd/man/systemd-stub.html) — what the UKI measures, how, and into which PCR. Confirms PCR 11 scope = all UKI sections.
8. [systemd-measure(1) manpage](https://www.freedesktop.org/software/systemd/man/systemd-measure.html) — invocation, `--phase=enter-initrd`, `--pcr-public-key` signing flow, JSON output schema for the `calculate` subcommand.
9. [Red Hat "Enabling measured boot with TPM 2.0" (2024)](https://www.redhat.com/en/blog/enabling-measured-boot-tpm-2) — end-to-end measured-boot deployment recipe for RHEL; our model cribs from the ostree parts.
10. [kernel.org `kernel_read_file_from_path` API docs](https://www.kernel.org/doc/html/latest/filesystems/api-summary.html#c.kernel_read_file_from_path) — the supported in-kernel file reader used by `read_expected_pcr`.
11. [fwupd's TPM 2.0 measurement walker](https://github.com/fwupd/fwupd/blob/main/libfwupdplugin/fu-efi-common.c) — reference implementation for walking PCR 11 measurement log in userspace; informs the shape of our future S73 event-log surface.
12. [Intel "Platform Trust Technology (PTT) overview"](https://www.intel.com/content/www/us/en/support/articles/000008927/technologies.html) — prevalence + enumeration path for firmware TPM; explains why `tpm_chip_find_get(NULL)` returns the PTT chip on modern Intel laptops even without a discrete module.

---

## 9. Summary

`trust.ko` now has a boot-time gate. In HARDWARE mode it behaves as before, with a cryptographic guarantee that the userspace on disk matches what the bootc image build stamped. In SOFTWARE mode it still works but loudly and visibly degrades every subject record with a flag userspace can read. In FAILED mode it refuses to attach, prints both measured and expected PCR digests, and tells the admin how to override to software — no panic, no brick, no silent downgrade.

The old-hardware graceful path is designed-in, not bolted-on: TPM absence, TPM 1.2, firmware-disabled TPM, and missing expected-PCR files all route to SOFTWARE mode with a `pr_warn`. The daemon mirrors the mode in `/health` so desktop UX can surface it honestly.

The single file of trust between build time and run time is `/etc/archimation/expected-pcr-11`. Agent α's bootc orchestrator stages it; `trust_attest.c` consumes it; systemd-measure produces it. Everything else is mechanism.
