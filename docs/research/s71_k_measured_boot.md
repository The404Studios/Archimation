# S71-K — Secure Boot, Measured Boot, TPM 2.0, and Module Signing for ARCHIMATION

**Agent:** Research Agent K (S71 12-agent push)
**Date:** 2026-04-20
**Scope:** The trust kernel module (`trust.ko`) is the "Root of Authority" for the ARCHIMATION stack — but the kernel itself currently boots from an **unsigned GRUB 2 build** and runs an **unsigned `trust.ko` loaded on first boot via DKMS**. Everything above Layer 0 trusts the kernel; nothing proves the kernel is what we shipped. This report surveys 2024-2026 UEFI Secure Boot, measured boot, TPM 2.0 attestation, and Linux module signing, and sketches the 2-session path that makes our authority root genuinely trustworthy.

---

## 0. Ground truth: what ARCHIMATION ships today

Absolute paths audited from the tree:

- `C:\Users\wilde\Downloads\arch-linux-with-full-ai-control\profile\grub\grub.cfg` — **unsigned GRUB 2**, boots `vmlinuz-linux` with no image hash check.
- `C:\Users\wilde\Downloads\arch-linux-with-full-ai-control\profile\efiboot\loader\loader.conf` — stock `systemd-boot` config installed by archiso for the ISO fallback path; no signed entries.
- `C:\Users\wilde\Downloads\arch-linux-with-full-ai-control\packages\trust-dkms\PKGBUILD` — ships 22 `.c` + 9 private `.h` + 4 public `.h` + `Kbuild` + `dkms.conf` with `AUTOINSTALL="yes"`. Module is **built on first boot from source, unsigned**. Auto-load config at `/etc/modules-load.d/trust.conf` uses `-trust` (the `-` prefix means "don't fail boot if not built yet").
- `C:\Users\wilde\Downloads\arch-linux-with-full-ai-control\packages\trust-dkms\trust-dkms.install` — `post_install()` runs `dkms build` + `dkms install` + `depmod -a`. No `sign-file` invocation, no MOK key discovery.
- `grep -rn 'CONFIG_MODULE_SIG\|sign-file\|mokutil\|sbctl\|tpm2' profile/` → **zero matches**. No secure-boot tooling staged into the airootfs.
- `C:\Users\wilde\Downloads\arch-linux-with-full-ai-control\services\drivers\kernel\wdm_host_pkcs7.c` — we already parse Authenticode PKCS#7 on PE `.sys` binaries inside the wdm_host kernel module, but this is for the **Windows driver gate**, not for our own module signatures. Good news: it proves we're not afraid of ASN.1.

**So:** the APE (Authority Proof Engine) can sign proofs all day in software, but if an attacker replaces `trust.ko` on disk, the entire chain of authority above it is built on a lie. **Secure boot + measured boot + module signing is the one piece of the design that's currently "unsigned GRUB trusts you it's Tuesday."**

---

## 1. The secure boot chain in 2026

```
UEFI firmware
    PK (Platform Key, one)
    KEK (Key Exchange Keys, multiple; Microsoft's is pre-provisioned)
    db  (allowlist: signed boot binaries)
    dbx (denylist: revoked hashes, SBAT generation numbers)
        │
        └─ verifies ──▶ shim.efi  (Microsoft-signed, Red Hat/Debian/SUSE maintained)
                            │
                            └─ MokList (Machine Owner Keys) ──▶ verifies ──▶
                                    │
                                    └─▶ systemd-boot.efi  (or GRUB.efi)
                                            │
                                            └─▶ UKI.efi  (systemd-stub + kernel + initrd + cmdline)
                                                    │
                                                    └─▶ kernel  (verifies signed modules
                                                                  via CONFIG_MODULE_SIG
                                                                  + built-in keyring
                                                                  + MOK keyring)
```

### 1.1 What changed 2024-2026

- **SBAT (Secure Boot Advanced Targeting)** — shim **≥15.3** refuses to launch EFI binaries without an `.sbat` section. shim **≥15.8** is required for new Microsoft UEFI CA submissions. Revocation now ships as generation-number bumps in the dbx instead of per-hash blacklist entries — this is the fix for the GRUB BootHole-style situation where per-binary revocation exhausted NVRAM space. ([shim SBAT.md](https://github.com/rhboot/shim/blob/main/SBAT.md))
- **Windows UEFI CA 2023** — new 2024+ hardware ships with a different root than the 2011 CA that all current Linux shim builds chain to. CVE-2023-24932 was the mitigation trigger; Microsoft issued a July 2024 update that can reapply the 2023 cert to `db`. Any Linux distro that wants to Just Work on 2025+ laptops out-of-box needs to be re-signed against the 2023 CA or accept mokutil-enrollment UX on first boot. ([Microsoft CVE-2023-24932](https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d))
- **Lockdown LSM** — `SECURITY_LOCKDOWN_LSM` + `kernel_lockdown=integrity` on kernels ≥5.4 refuses to load unsigned modules when Secure Boot is on. On 6.x this is effectively the enforcement hammer: if SB is enrolled, module signing is not optional. ([kernel_lockdown(7)](https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html))
- **SHA-1 module signing removed** — patches posted Nov 2025 drop SHA-1 from the module signing path (default has been SHA-512 for several kernels). Any tooling still emitting SHA-1-signed modules will break on future 6.x kernels. ([Phoronix](https://www.phoronix.com/news/Linux-Patch-Drop-SHA1-Mod-Sign))
- **sbctl 0.18 (Oct 2025)** — the Arch-friendly user tool for SB key management. Now ships with a pacman hook that auto-signs on every kernel/systemd/bootloader pacman upgrade. Supports Yubikey-hosted private keys (`--keytype`). **Does not yet seal keys to TPM PCR policies** — that's the one thing upstream considers done by `systemd-measure` instead. ([sbctl GitHub](https://github.com/Foxboron/sbctl), [sbctl(8)](https://man.archlinux.org/man/sbctl.8))

---

## 2. TPM 2.0 attestation patterns

### 2.1 PCR layout that systemd uses in 2025-2026

From [systemd TPM2_PCR_MEASUREMENTS](https://systemd.io/TPM2_PCR_MEASUREMENTS/):

| PCR  | Name                     | What it contains                                                   | Who writes it       |
|------|--------------------------|--------------------------------------------------------------------|---------------------|
| 0-4  | firmware / option-ROMs   | UEFI firmware code + settings + UEFI driver code                   | Firmware            |
| 5    | boot-loader-config       | `loader/loader.conf` content                                       | systemd-boot        |
| 7    | **Secure Boot state**    | PK/KEK/db/dbx + MOK state + which cert signed the loaded image     | Firmware            |
| 8-9  | bootloader               | GRUB or systemd-boot measured code/config (GRUB uses 8/9 directly) | Bootloader          |
| 10   | **IMA**                  | `Integrity Measurement Architecture` running hash of loaded files  | Kernel              |
| 11   | **kernel-boot (UKI)**    | Every PE section of the UKI + boot-phase markers                   | systemd-stub        |
| 12   | kernel-config            | Kernel cmdline, devicetree, initrd, microcode addons, credentials  | systemd-stub        |
| 13   | sysexts                  | System extension initrd archives                                   | systemd-stub        |
| 14   | MOK state                | shim-measured MOK + KEK + db as alternative to PCR 7               | shim                |
| 15   | system-identity          | `/etc/machine-id`, root-fs UUID, LUKS volume keys                  | systemd-stub + init |

**The PCR we care about for ARCHIMATION is PCR 11**, because that's where the UKI containing `vmlinuz-linux` + `initramfs-linux.img` + our kernel cmdline lands. If we ship our daemon + cortex as an addon initrd (sysext), we get a second anchor at PCR 13.

There is no standardized "user-space daemon PCR." The PLAN comment "PCR 11 is our potential target for the ARCHIMATION stack (daemon hash)" is correct only if we fold the daemon into the UKI via a sysext addon — extending PCR 13 — or a credential addon. We should **not** invent a custom `tpm2_pcr_extend` of our own on top of PCRs 16-23; that's discouraged because the 16-23 range is "debug/resettable" and gets cleared under various conditions.

### 2.2 Attestation flow

```
Verifier (remote AI cortex, or local health-daemon)
    │
    │  1. Ask TPM for a Quote signed by AK (Attestation Key)
    │     over PCRs 0,4,7,8,9,10,11,12,14
    │
    │  2. Receive Quote + IMA measurement-list + UKI signature
    │     (our pre-signed /usr/lib/systemd/pcrlock.d/*.pcrlock files)
    │
    │  3. Verify:
    │     a. AK certificate chains to manufacturer EK endorsement cert
    │     b. Quote signature valid under AK
    │     c. PCR 7 matches "Secure Boot on + our db"
    │     d. PCR 11 matches one of our signed UKI hashes
    │     e. IMA log re-hashes to PCR 10 value
    │     f. All measured files appear in our allowlist
    │
    └───── pass → issue session token; fail → contain + alert
```

For ARCHIMATION, step 3e-f is the interesting one: our cortex/decision engine can make trust decisions based on "did PCR 10 ever include an unknown binary" and emit an SCM/trust event. This is the bridge from hardware measurement to the software trust model.

---

## 3. TPM 2.0 hardware landscape in 2026

| Class              | Name                  | Trust caveat                                                                                       |
|--------------------|-----------------------|----------------------------------------------------------------------------------------------------|
| Discrete           | Infineon SLB9670, STMicro ST33      | Best isolation, separate die, tamper-resistant. Desktop add-in ($5-20).                |
| Integrated (CPU)   | AMD fTPM              | Firmware TPM on Ryzen. The 2021-22 "Ryzen stutter" bug was fTPM-related SPI-flash transactions pausing the system. Fixed in AGESA 1207+, but some affected boards still see sporadic hangs; AMD guidance is "BIOS update, else add a dTPM header, else disable." ([AMD PA-410](https://www.amd.com/en/resources/support-articles/faqs/PA-410.html)) |
| Integrated (CPU)   | Intel PTT             | Platform Trust Technology, baked into ME/CSME. No fTPM-class stutter, but shares ME fate.           |
| Virtualized        | swtpm + QEMU          | Our QEMU smoke-test path can and should include a software TPM so CI tests PCR measurement.        |

**Old-hardware constraint:** pre-~2013 desktops may have TPM 1.2 (SHA-1 only) or no TPM. TPM 1.2 is useless for PCR 11-style SHA-256 measurements — its PCR bank is SHA-1 and has been known-broken for years. Our fallback story has to be "software-only measured boot (no TPM quote, but we still IMA-hash and kernel-lockdown)" — we can't pretend to attest without a TPM.

**New-hardware opportunity:** Windows 11 launched Oct 2021 with TPM 2.0 as a **mandatory requirement**. Every consumer laptop sold 2022+ ships TPM 2.0 (typically fTPM on AMD, PTT on Intel). Our install story for the mainstream case is clean: `systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7+11+12` and the user never sees a LUKS password again after the initial install. ([Arch Wiki TPM](https://wiki.archlinux.org/title/Trusted_Platform_Module))

---

## 4. Module signing strategy for trust-dkms

### 4.1 The DKMS pain point

DKMS modules rebuild every kernel bump. Stock DKMS on Arch does NOT sign. The well-trodden pattern from Fedora's `akmods` and Ubuntu's `shim-signed`:

1. Generate a **MOK key pair** on first install (`openssl req -newkey rsa:4096 ...`).
2. Configure `/etc/dkms/framework.conf` with:
   ```
   mok_signing_key="/var/lib/dkms/mok.key"
   mok_certificate="/var/lib/dkms/mok.pub"
   sign_tool="/etc/dkms/sign_helper.sh"
   ```
3. `sign_helper.sh` calls `/usr/src/linux-$(uname -r)/scripts/sign-file sha512 <key> <cert> <module.ko>`.
4. User runs `mokutil --import /var/lib/dkms/mok.pub`, sets one-time password, reboots; shim's MokManager prompts for password, enrolls MOK into firmware NVRAM, reboots again.
5. Kernel trusts anything signed by that cert from now on across DKMS rebuilds.

This is the **pattern every distro that cares about Secure Boot has converged on**. NVIDIA/VirtualBox/r8125 all do this. The Arch-specific wrinkle is that `mokutil` and `shim-signed` live in the AUR; we'd pull them into `packages.x86_64`.

### 4.2 Two philosophies — which do we ship?

| Strategy                       | Pros                                                                 | Cons                                                                                     |
|--------------------------------|----------------------------------------------------------------------|------------------------------------------------------------------------------------------|
| **Per-install key (MOK)**      | Each user owns their key; no distro-global blast radius if key leaks | Requires user to do mokutil enrollment reboot; some users won't get past "blue screen"   |
| **Pre-signed with project key**| Zero-touch boot; `trust.ko` is signed at package-build time against a key we own and enroll into the ISO's `db` | We become a key-management org; key compromise = emergency SBAT bump; opposite of "user owns authority" |
| **Hybrid (recommended)**       | Ship with per-install MOK flow **by default**, but provide `ai-install-to-disk --enroll-project-key` for lab/fleet deployments | Two codepaths to test                                                                     |

Given the project's ethos ("AI under user control, trust rooted in the local subject"), **per-install MOK is the right default**. The installer generates a key unique to the machine, enrolls it into shim's MokList, DKMS signs each rebuild. No distro-level key to leak.

### 4.3 Concrete `trust-dkms.install` changes (design sketch)

```bash
post_install() {
    _gen_autoconf

    # NEW: lazily create per-install MOK if missing
    if [ ! -f /var/lib/dkms/mok.key ]; then
        mkdir -p /var/lib/dkms
        openssl req -new -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
            -outform DER -keyout /var/lib/dkms/mok.key \
            -out /var/lib/dkms/mok.pub \
            -subj "/CN=ARCHIMATION trust-dkms MOK/"
        chmod 600 /var/lib/dkms/mok.key
        echo ">>> Generated MOK at /var/lib/dkms/mok.pub"
        echo ">>> Enroll with: mokutil --import /var/lib/dkms/mok.pub"
    fi

    # existing dkms add / build / install
    dkms add "${_mod}/${_ver}" --no-depmod 2>/dev/null || true
    dkms build "${_mod}/${_ver}" --no-depmod && \
        dkms install "${_mod}/${_ver}" --no-depmod
    depmod -a
}
```

Pair this with a single-line `/etc/dkms/framework.conf.d/trust.conf`:
```
mok_signing_key="/var/lib/dkms/mok.key"
mok_certificate="/var/lib/dkms/mok.pub"
```

DKMS will then sign on every rebuild automatically (uses `scripts/sign-file` from the kernel headers). This is ~30 LOC across two files.

---

## 5. UKI adoption for ARCHIMATION — the recommended direction

### 5.1 Why UKI

The current `grub.cfg` has **10 menu entries**, each manually constructing kernel cmdline + referencing separate `vmlinuz-linux` and `initramfs-linux.img`. To Secure-Boot sign all this properly we would need to:

- Sign `grubx64.efi` (every GRUB module we load is also subject to SBAT).
- Sign `vmlinuz-linux` (linux-signed from AUR, or self-built signed kernel).
- Leave `initramfs-linux.img` **unsigned** (intrinsic limitation of split boot — initramfs is generated locally).
- Trust that cmdline in `grub.cfg` on the ESP hasn't been tampered with (it hasn't been measured!).

UKI solves this by packaging kernel + initramfs + stub + cmdline into **one PE binary** that is signed atomically and measured as one PCR-11 hash. systemd-stub performs the kernel/initramfs handoff inside the signed blob. No part of the boot chain escapes measurement.

### 5.2 Concrete UKI build path on Arch

```bash
# /etc/mkinitcpio.d/archimation.preset
PRESETS=('default')
default_uki="/efi/EFI/Linux/archimation-$(uname -r).efi"
default_options="--splash /usr/share/systemd/bootctl/splash-arch.bmp"

# kernel-install then calls ukify with:
ukify build \
    --linux=/boot/vmlinuz-linux \
    --initrd=/boot/amd-ucode.img \
    --initrd=/boot/intel-ucode.img \
    --initrd=/boot/initramfs-linux.img \
    --cmdline='@/etc/kernel/cmdline' \
    --output=$default_uki \
    --signtool=sbsign \
    --secureboot-private-key=/var/lib/sbctl/keys/db/db.key \
    --secureboot-certificate=/var/lib/sbctl/keys/db/db.pem
```

systemd-boot then auto-discovers `/efi/EFI/Linux/*.efi` (the [Boot Loader Spec Type #2](https://uapi-group.org/specifications/specs/boot_loader_specification/) convention). No `loader.conf` entries needed. ([Arch Wiki UKI](https://wiki.archlinux.org/title/Unified_kernel_image))

### 5.3 The pacman-hook chain

```
pacman -S linux
    │
    ├─▶ mkinitcpio hook generates /boot/initramfs-linux.img
    │
    ├─▶ kernel-install hook runs ukify → /efi/EFI/Linux/archimation-*.efi
    │
    └─▶ sbctl hook runs `sbctl sign -s /efi/EFI/Linux/archimation-*.efi`
```

sbctl's pacman hook (`80-secureboot.hook`) is already shipped upstream; it auto-signs any file in its database. We'd add UKI paths to the db at install time. ([sbctl GitHub](https://github.com/Foxboron/sbctl))

---

## 6. Sealed LUKS2 — the aspirational endpoint

```
systemd-cryptenroll --tpm2-device=auto \
                    --tpm2-pcrs=7+11+12 \
                    --tpm2-public-key=/etc/archimation/pcrlock.pub \
                    --tpm2-signature=/etc/archimation/pcrlock.sig \
                    /dev/nvme0n1p3
```

- **PCR 7**: Secure Boot state (firmware db + signer cert).
- **PCR 11**: UKI hash — changes every kernel update, but...
- **`--tpm2-public-key`** binds the unlock to a signed policy: any PCR 11 value for which a valid signature under that public key exists is accepted. `systemd-measure sign` pre-calculates the next kernel's PCR 11 and emits `/run/systemd/tpm2-pcr-signature.json` during image build.

**Result:** disk unlocks automatically on boot IF AND ONLY IF the firmware matches AND the booted UKI is one we signed. User sees no password prompt. Attacker who swaps `trust.ko` changes PCR 11 → no valid signature → TPM refuses to unseal → disk stays encrypted. ([0pointer brave-new-trusted-boot-world](https://0pointer.net/blog/brave-new-trusted-boot-world.html))

This is the single biggest UX wins we can ship. It also makes the "trust root" authentic: `trust.ko` only runs if the UEFI chain has already proven the whole boot path matches what we shipped.

**Caveats:**

- PCR fragility: any firmware/GRUB/UKI change not pre-signed → disk is locked; user must fall back to LUKS recovery password. Don't enroll TPM as the ONLY unlock method; always keep a passphrase slot.
- `sbctl`'s TPM-shielded keys are stored in TSS2 format which `systemd-measure` doesn't yet read ([systemd#34981](https://github.com/systemd/systemd/issues/34981)); for now keep the PCR-sign key separate from the SB signing key. This is a one-file tweak once resolved.
- Attackers with physical access can perform a [cold-boot or TPM bus-sniff attack](https://oddlama.org/blog/bypassing-disk-encryption-with-tpm2-unlock/) against auto-unlock; this is a **convenience feature, not a rock-solid threat defense** for mobile devices. Document this honestly.

---

## 7. Old-hardware fallback

For the ~10-15% of users on hardware that doesn't support TPM 2.0 (pre-2013 desktops, some industrial boxes, custom BIOS on servers with TPM disabled), the graceful-degradation path is:

1. **No PCR sealing** — LUKS stays on passphrase.
2. **Still enable CONFIG_MODULE_SIG_FORCE** — module signing works without TPM, just without the attestation.
3. **Still enable Secure Boot if possible** — shim + MOK still works on TPM-less UEFI; the signatures are checked by firmware alone.
4. **IMA still useful** — IMA extends PCR 10 only if a TPM exists; without one, IMA can still maintain the appraisal log in kernel memory and refuse files that don't hash-match a policy, just without the attestation chain.
5. **trust.ko still works** — it's a kernel module, not a hardware driver. It cares about signed loading (for which SB + MOK suffice), not about a TPM being present.

Honest message to user: **"Without TPM 2.0 the authority root is firmware-strength, not hardware-strength. That's fine for 95% of threats."**

---

## 8. Recommended 2-session plan

### Session A — module signing + secure-boot tooling (lower risk, independent wins)

1. Add `sbctl`, `mokutil`, `shim-signed` (AUR built in CI), `tpm2-tools` to `profile/packages.x86_64`.
2. Update `packages/trust-dkms/trust-dkms.install` to:
   - Generate `/var/lib/dkms/mok.{key,pub}` on first install (4-line openssl invocation).
   - Drop `/etc/dkms/framework.conf.d/trust.conf` that points DKMS at the MOK key.
   - On post-install, `echo ">>> trust.ko signed with local MOK. Enroll with: mokutil --import /var/lib/dkms/mok.pub"`.
3. Add a `/usr/bin/archimation-secureboot-setup` helper (60 LOC bash) that wraps: `sbctl create-keys → sbctl enroll-keys --microsoft → mokutil --import dkms/mok.pub` and gives one-screen instructions.
4. Add a build-time `verify_modules_signable()` in `scripts/build-packages.sh` asserting the shipped kernel has `CONFIG_MODULE_SIG=y` (same style as S67's `verify_trust_dkms_manifest()`).
5. Scripts-only; no ISO rebake required.

**Exit criteria:** on a real-hardware test box, `mokutil --list-enrolled` shows our MOK; `mokutil --sb-state` shows SecureBoot enabled; `modinfo trust | grep signer` shows our cert; `dmesg | grep trust` shows module loaded without `module verification failed`.

### Session B — UKI + systemd-boot migration (larger scope, higher leverage)

1. Switch `profile/packages.x86_64` from `grub` to `systemd-boot-efi` + `systemd-ukify`.
2. Replace `profile/grub/grub.cfg` with:
   - `profile/airootfs/etc/kernel/cmdline` (single source of truth for cmdline).
   - `profile/airootfs/etc/mkinitcpio.d/archimation.preset` (UKI preset).
   - `profile/airootfs/etc/kernel/install.conf` with `layout=uki`.
3. archiso hooks emit the UKI directly into `archisobasedir/EFI/Linux/`.
4. Add `profile/airootfs/etc/archimation/pcrlock.d/` with pre-signed PCR 11 policies for the shipped UKI.
5. Installer (`ai-install-to-disk`) at end of install:
   - Runs `sbctl setup --auto-enroll` (if user opted in to SB).
   - Runs `systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7+11 /dev/<root>` (if user opted in to TPM auto-unlock + keeping passphrase slot).
6. QEMU smoke test extended with `-tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 -chardev socket,id=chrtpm,path=/tmp/mytpm/swtpm-sock` + `swtpm` in test harness.

**Exit criteria:** QEMU boot from UKI, `systemd-analyze security` reports PCR 11 measured, `systemd-cryptenroll --tpm2-device=list` shows the swtpm, LUKS volume unlocks without passphrase when PCR state matches; reboot with tampered UKI (flip a byte) → fails to unseal.

---

## 9. Lessons carried forward from S66/S67

- **PKGBUILD manifest drift** (the `verify_trust_dkms_manifest()` pattern from S67) applies identically here: if we add a new file to `/etc/dkms/framework.conf.d/`, we need a build-time check it's shipped. Secure-boot adds `/var/lib/sbctl/`, `/var/lib/dkms/mok.{key,pub}`, `/efi/EFI/Linux/`, and `/etc/kernel/cmdline` as new "authority-bearing" paths — each should have a conformance test.
- **Honest failure beats lying success** (S65 SCM lesson): if the user's hardware can't TPM-attest, the installer should **say so and continue without sealing**, not pretend to seal and have the UX fail weirdly later.
- **Test-corpus approach** (S65/S67): we'd want a small corpus of "boot scenarios" (SB on+TPM on, SB on+TPM off, SB off+TPM on, SB off+TPM off) tested in CI via QEMU+OVMF+swtpm. This is the measured-boot equivalent of the S65 PE corpus.

---

## 10. Summary (400 words)

The ARCHIMATION trust model has a strong software crypto core (APE, trust kernel module, dictionary-routed Markov validators) but currently boots from an unsigned GRUB 2 and loads an unsigned `trust.ko` via DKMS on first boot. Every authority claim above Layer 0 therefore rests on a kernel that nothing proved was the one we shipped. The 2024-2026 Linux stack has crystallized a clean way to fix this: UEFI Secure Boot with sbctl-managed per-install keys enrolled via Microsoft's shim, a Unified Kernel Image (systemd-stub + kernel + initrd + signed cmdline) replacing the GRUB boot path, TPM 2.0 PCR 11 measuring the UKI and PCR 7 pinning the SB state, and `systemd-cryptenroll --tpm2-device=auto` sealing the LUKS key to a signed PCR policy so disk auto-unlocks on any UKI we signed but nothing else. sbctl 0.18 ships with an Arch pacman hook that re-signs on every linux/systemd/systemd-boot update; systemd-measure signs expected PCR 11 values at image build; Lockdown LSM + CONFIG_MODULE_SIG_FORCE makes unsigned module loading a compile error rather than a policy choice.

For `trust.ko` the DKMS-signing pattern is solved: generate a per-install MOK key in `post_install`, wire `/etc/dkms/framework.conf.d/trust.conf` at `mok_signing_key` + `mok_certificate`, and DKMS will invoke `scripts/sign-file` on every rebuild. User runs `mokutil --import` once, reboots through shim's MokManager, and every future kernel update is silently re-signed. akmods/Fedora and Ubuntu's `shim-signed` both use this identical pattern.

Old hardware without TPM 2.0 degrades gracefully to firmware-strength SB + signed modules without attestation; trust.ko still runs, the Authority Proof Engine still issues software proofs, but the "root" is now the user's MOK rather than the TPM EK cert. New hardware (Windows-11-mandated TPM 2.0, ubiquitous on 2022+ consumer laptops) unlocks the full stack including password-free boot on a trusted configuration, cold-boot/bus-sniff caveats documented.

Recommendation: a **2-session sprint**. Session A (low risk) adds sbctl + MOK + DKMS module signing and ships without an ISO rebake. Session B (larger scope) migrates archiso from GRUB to systemd-boot + UKI + ukify, adds swtpm to QEMU smoke tests, and wires `systemd-cryptenroll` into `ai-install-to-disk` so the installed system auto-unlocks on trusted boot. Together they move ARCHIMATION's trust root from "the kernel trusts us it's Tuesday" to "the hardware quoted PCRs chain back to a cert we can verify."

---

## Sources

- [sbctl — GitHub (Foxboron)](https://github.com/Foxboron/sbctl) — v0.18 Oct 2025, pacman hook, TPM-shielded keys, not-yet PCR sealing.
- [sbctl(8) — Arch man pages](https://man.archlinux.org/man/sbctl.8) — full command reference.
- [Unified kernel image — Arch Wiki](https://wiki.archlinux.org/title/Unified_kernel_image) — UKI assembly with ukify + kernel-install.
- [kernel-install — Arch Wiki](https://wiki.archlinux.org/title/Kernel-install) — `install.conf` `layout=uki`.
- [systemd-boot — Arch Wiki](https://wiki.archlinux.org/title/Systemd-boot) — `/efi/EFI/Linux/*.efi` auto-discovery.
- [Trusted Platform Module — Arch Wiki](https://wiki.archlinux.org/title/Trusted_Platform_Module) — tpm2-tools, PCR reading, TSS2 keys.
- [systemd-cryptenroll — Arch Wiki](https://wiki.archlinux.org/title/Systemd-cryptenroll) — `--tpm2-device=auto --tpm2-pcrs=7`.
- [Signed kernel modules — Arch Wiki](https://wiki.archlinux.org/title/Signed_kernel_modules) — MOK enrollment flow.
- [UEFI/Secure Boot — Arch Wiki](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot) — shim/PreLoader/MokList.
- [systemd TPM2 PCR Measurements](https://systemd.io/TPM2_PCR_MEASUREMENTS/) — PCR 5/11/12/13/15 definitions.
- [systemd-measure(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd-measure.html) — pre-calculate + sign PCR 11 values.
- [systemd-stub(7)](https://www.freedesktop.org/software/systemd/man/latest/systemd-stub.html) — UKI PE sections and boot-phase markers.
- [Brave New Trusted Boot World — Lennart Poettering blog](https://0pointer.net/blog/brave-new-trusted-boot-world.html) — Oct 2022 design document for the UKI+PCR11+TPM2 vision.
- [Unlocking LUKS2 with TPM2/FIDO2/PKCS#11 on systemd 248](https://0pointer.net/blog/unlocking-luks2-volumes-with-tpm2-fido2-pkcs11-security-hardware-on-systemd-248.html) — `systemd-cryptenroll` origin.
- [systemd#34981 — TPM-shielded sbctl keys for PCR signing](https://github.com/systemd/systemd/issues/34981) — TSS2 read in systemd-measure not yet merged.
- [UKI + Secure Boot with sbctl on Arch — edu4rdshl.dev](https://edu4rdshl.dev/posts/uki-secure-boot-on-archlinux-systemd-boot-walkthrough/) — end-to-end walkthrough.
- [archinstall-luks2-lvm2-secureboot-tpm2 — GitHub](https://github.com/joelmathewthomas/archinstall-luks2-lvm2-secureboot-tpm2) — working Arch install template.
- [Bypassing disk encryption with TPM2 unlock — oddlama](https://oddlama.org/blog/bypassing-disk-encryption-with-tpm2-unlock/) — cold-boot / bus-sniff caveats.
- [shim SBAT.md — rhboot/shim](https://github.com/rhboot/shim/blob/main/SBAT.md) — generation-number revocation.
- [Microsoft KB CVE-2023-24932](https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d) — 2024 UEFI CA refresh.
- [Microsoft UEFI Signing Requirements (updated)](https://techcommunity.microsoft.com/blog/hardware-dev-center/updated-microsoft-uefi-signing-requirements/1062916) — Windows UEFI CA 2023.
- [UEFI/SecureBoot/DKMS — Ubuntu Wiki](https://wiki.ubuntu.com/UEFI/SecureBoot/DKMS) — reference DKMS + MOK pattern.
- [SecureBoot — Debian Wiki](https://wiki.debian.org/SecureBoot) — shim chain + MOK workflow.
- [Automatic DKMS module signing — gist lijikun](https://gist.github.com/lijikun/22be09ec9b178e745758a29c7a147cc9) — `/etc/dkms/framework.conf` `sign_tool`.
- [akmods + Fedora Secure Boot guides (2024-2025)](https://packetrealm.io/posts/fedora-nvidia-akmods-secure-boot/) — RPM Fusion MOK pattern.
- [AMD Ryzen fTPM stutter — AMD PA-410](https://www.amd.com/en/resources/support-articles/faqs/PA-410.html) — AGESA 1207+ fix, dTPM fallback.
- [Linux patch drops SHA-1 module signing — Phoronix (Nov 2025)](https://www.phoronix.com/news/Linux-Patch-Drop-SHA1-Mod-Sign) — upcoming 6.x kernels.
- [kernel_lockdown(7) man page](https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html) — integrity/confidentiality levels.
- [Kernel module signing facility — kernel.org](https://docs.kernel.org/admin-guide/module-signing.html) — `scripts/sign-file` reference.
- [Red Hat IMA/EVM — RHEL 10 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/managing_monitoring_and_updating_the_kernel/enhancing-security-with-the-kernel-integrity-subsystem) — IMA measurement into PCR 10.
- [IMA Event Log docs](https://ima-doc.readthedocs.io/en/latest/event-log-format.html) — measurement-list format.
- [TPM-Based Continuous Remote Attestation for 5G VNFs on Kubernetes — arXiv 2510.03219 (2025)](https://arxiv.org/html/2510.03219v1) — attestation protocol example.
- [Incus-OS #792 — Authorized Policies to mitigate PCR fragility](https://github.com/lxc/incus-os/issues/792) — signed-policy pattern on sealed keys.
