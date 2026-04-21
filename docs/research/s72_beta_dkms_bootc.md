# S72-β — DKMS to bootc transition, module signing, and key management for ARCHIMATION

**Agent:** Research Agent β (Session 72 Phase 1 foundation push)
**Date:** 2026-04-20
**Scope:** How do we take the `trust-dkms` first-boot-build model and turn it into a bootc / OCI-native signed-module pipeline without abandoning the archiso path? What key management shape fits an open-source distro whose moat is a kernel module? What do Universal Blue, Silverblue, and RHEL already ship that we can crib from? This doc is the companion to `bootc/build-trust-module.sh`, `bootc/trust-keys/README.md`, and the `packages/trust-dkms/trust-dkms.install` rewrite that all landed together in S72.
**Relation to S71-K:** S71-K surveyed the full Secure Boot / measured boot / TPM landscape. This doc is narrower: the **kernel-module** side of that chain specifically, at the bootc boundary.

---

## 0. The S71 → S72 problem handoff

S71-K flagged that `trust-dkms` ships unsigned sources and builds on first boot. That was a fine archiso behaviour — the ISO path is inherently non-reproducible anyway, and "install kernel headers then compile" is the Arch/DKMS convention. But S72 Phase 1 is introducing bootc as a second shipment vector, and bootc has three hard constraints that DKMS fundamentally violates:

1. **Immutable `/usr` at runtime.** A running bootc system's `/usr` is a read-only composefs overlay; there is no writable place to land a newly-built `trust.ko` for `modprobe` to find on the next boot. The DKMS install path writes to `/usr/lib/modules/<kver>/extra/trust.ko`, which **doesn't exist as a writable path** on a deployed bootc image.
2. **Pinned kernel at image build time.** `bootc upgrade` replaces the entire image atomically. The kernel version inside an image is frozen; kernel headers on the target may never match. DKMS's "rebuild on every kernel change" premise assumes a mutable system.
3. **Signed chain-of-trust.** bootc images are expected to be signed (cosign, Sigstore, etc.) end-to-end, and the bootc community expects anything in `/usr/lib/modules/*/extra` to be signed by a key whose cert is in the image. An unsigned module under `lockdown=integrity` (the setting `linux-hardened` flips by default — see [kernel_lockdown(7)](https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html)) just **won't load**.

ARCHIMATION's moat is `trust.ko`. Shipping it unsigned to a bootc deployment is equivalent to shipping no moat at all.

---

## 1. How the adjacent world handles this

### 1.1 RHEL + CentOS Stream (the grown-ups)

RHEL ships every kernel module signed with Red Hat's internal CA that is pre-provisioned in the `db` signature store of shim via `shim-x64` and `kernel-secureboot-keys`. For out-of-tree modules (third-party storage adapters, GPU drivers), RHEL's docs ([Chapter 3, RHEL 8 Managing Kernel](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/managing_monitoring_and_updating_the_kernel/signing-a-kernel-and-modules-for-secure-boot_managing-monitoring-and-updating-the-kernel)) prescribe the MOK flow exactly:

```
# 1. generate local keypair
openssl req -new -x509 -newkey rsa:4096 -nodes ...
# 2. enroll the public cert via mokutil
mokutil --import /path/to/public_key.der
# 3. reboot → MokManager screen → enroll → reboot
# 4. sign the module
/usr/src/kernels/$(uname -r)/scripts/sign-file sha256 priv.pem pub.der ./third_party.ko
```

This is the canonical flow every downstream distro copies. It **works**, but the reboot-into-MokManager dance is a notorious UX failure mode for home users.

### 1.2 Fedora akmods + Universal Blue (the immutable cousins)

Fedora's `akmods` ([RPM Fusion Packaging/KernelModules/Akmods](https://rpmfusion.org/Packaging/KernelModules/Akmods)) is the "automated kmod" build system. For every out-of-tree module packaged by RPM Fusion (nvidia, v4l2loopback, zfs, vboxhost), akmods ships:

- `kmod-<name>-<kver>-<ver>.rpm` — the pre-built + signed binary module for a specific kernel version.
- `akmod-<name>-<ver>.rpm` — the fallback "compile locally" path for kernels akmods hasn't pre-built yet.

Universal Blue's fork ([ublue-os/akmods](https://github.com/ublue-os/akmods)) takes this a decisive step further for bootc images:

- **Pre-built kmod RPMs are the primary deliverable**, with akmod-based rebuild at first boot demoted to a fallback.
- RPMs are **signed with a Sigstore-verifiable signature on the container image itself** (`cosign verify ghcr.io/ublue-os/akmods`), and the modules inside are kernel-signed with Universal Blue's project MOK.
- The kernel version inside a bootc image is **pinned**, and the akmods RPM matching that kernel version is layered on. No runtime DKMS build ever happens.
- User first-boot includes a `ublue-mok-setup.service` that runs `mokutil --import` for the Universal Blue cert if and only if the user's firmware has Secure Boot enabled.

In other words, Universal Blue converted the DKMS pattern into an **image-build-time + project-signed + sidecar RPM** pattern. The moat-analogue here is nvidia-open; ours is trust.ko. The architectural transform is identical.

Key Universal Blue citations:

- [ublue-os/akmods repo](https://github.com/ublue-os/akmods) — the bootc-friendly akmods caching layer.
- [UCore ZFS kmods now signed for Secure Boot](https://universal-blue.discourse.group/t/ucore-zfs-kmods-are-now-signed-for-secureboot/383) — the blog post describing how UCore moved from unsigned kmods to signed, and the MOK UX changes that followed.
- [BlueBuild akmods module reference](https://blue-build.org/reference/modules/akmods/) — the BlueBuild YAML DSL layer that actually invokes akmods inside a bootc Containerfile.

### 1.3 Silverblue rpm-ostree kernel module layering

Silverblue itself ([Silverblue Discussion thread](https://discussion.fedoraproject.org/t/is-silverblue-rpm-ostree-intended-to-be-used-with-layered-packages/26162)) treats kmods as **layered packages**. User runs `rpm-ostree install kmod-zfs`, the system reboots into a new deployment where the layered kmod is baked in. `akmods` is the backing store; the user-facing verb is `rpm-ostree install`.

For Secure Boot, Silverblue ships `silverblue-akmods-keys` ([Silverblue first impressions, Morales 2025](https://www.mauromorales.com/2025/10/27/fedora-silverblue-first-impressions-from-someone-building-an-immutable-system/)) — a separate RPM whose only job is to drop a pre-enrolled MOK into the target's shim MokList. This makes the enrollment zero-click for the default AK path. Non-default modules (user-compiled, third-party) still need the per-install flow.

### 1.4 Kernel lockdown LSM

[mjg59's canonical writeup](https://mjg59.dreamwidth.org/55105.html) and [kernel_lockdown(7)](https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html) spell out the three modes:

| Mode                   | Cmdline                         | Unsigned modules | Confidential kernel state         | Use case                                         |
|------------------------|---------------------------------|------------------|-----------------------------------|--------------------------------------------------|
| `none`                 | `lockdown=none` or omitted      | Allowed          | Readable by root                  | Dev boxes; pre-2013 hardware; debug              |
| `integrity`            | `lockdown=integrity`            | **Refused**      | Readable by root                  | Default for any Secure Boot + linux-hardened     |
| `confidentiality`      | `lockdown=confidentiality`      | **Refused**      | Hidden even from root             | Paranoid workloads; closed appliances; BPF-lite  |

The critical clause for us: **linux-hardened upstream defaults to `integrity`** (which Arch packages as-is). Any user installing `linux-hardened` on ARCHIMATION with an unsigned `trust.ko` will silently get a system where the Root of Authority never loads. This is the single worst failure mode we need to prevent before Phase 2.

### 1.5 Arch sbctl + mokutil tooling

On the Arch side ([Arch Wiki Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)):

- `sbctl` ([Foxboron/sbctl](https://github.com/Foxboron/sbctl)) — manages PK/KEK/db/dbx and signs EFI binaries. **Does not sign kernel modules directly** (it's a UEFI tool, not a module tool), but its pacman hook ecosystem is the template we copy: on every `pacman -S linux` the hook re-signs `/boot/vmlinuz-linux`.
- `mokutil` — lives in AUR as `mokutil`. Manages the shim MokList. Used for `--import`, `--list-enrolled`, `--sb-state`.
- `scripts/sign-file` — ships in `linux-headers`. The canonical way to append a PKCS#7-over-SHA-256 signature to a `.ko`. [kernel module-signing.rst](https://www.kernel.org/doc/Documentation/admin-guide/module-signing.rst) documents the exact semantics: the signature is an **append-only trailer after the final section**. This means:
  - Strip must happen **before** signing. A post-sign `strip` deletes the signature.
  - The signed payload is deterministic iff the unsigned payload is deterministic — which requires `SOURCE_DATE_EPOCH` and stable `-j` ordering. Our `bootc/build-trust-module.sh` enforces both.

### 1.6 Recent kernel changes we must track

Phoronix reported Nov 2025 that [Linux is dropping SHA-1 from the module signing path](https://www.phoronix.com/news/Linux-Patch-Drop-SHA1-Mod-Sign) entirely — default has been SHA-512 for several kernels, but older tools were still permitted to emit SHA-1 signatures as a fallback. Any scripts still doing `sign-file sha1 ...` will break on future 6.x kernels. We standardize on `sha256` in `build-trust-module.sh` (and document `sha512` as the upgrade path).

---

## 2. ARCHIMATION key management choice

### 2.1 The three key spaces

There are three distinct keys involved in "signed trust.ko loads on boot":

```
┌───────────────────────────────┬────────────────────────────────────────────┐
│ Key                           │ What it signs                              │
├───────────────────────────────┼────────────────────────────────────────────┤
│ Project MOK (our choice)      │ trust.ko at bootc image build time         │
│ Per-install MOK               │ trust.ko when DKMS rebuilds on archiso     │
│ UEFI db signing key (sbctl)   │ GRUB / UKI / kernel itself (Agent γ scope) │
└───────────────────────────────┴────────────────────────────────────────────┘
```

This S72-β doc covers **the first two**. The third is Agent γ's patch and is documented in `docs/research/s71_k_measured_boot.md`.

### 2.2 The decision matrix

| Strategy             | Bootc image UX          | Archiso UX              | Security posture           | Key blast radius     |
|----------------------|-------------------------|-------------------------|----------------------------|----------------------|
| **Project key only** | Zero-click after enrollment | Works (signing in install hook) | Strong (single vetted cert) | One leak = distro-wide incident |
| **Per-install only** | Broken (can't gen key at image build) | Works (lazy gen in install) | Strong (machine-bound)     | Local only           |
| **Hybrid (chosen)**  | Project-signed default; user can override | Project > site > per-install | Strong default, configurable | Project key leak bounded by SBAT + rotation |

**Decision: hybrid.** `bootc/build-trust-module.sh` takes a project key as input (from CI secret), signs at build time, ships cert in image. `trust-dkms.install` tries project key at `/var/lib/ai-control/trust-*.{pem,der}` first, site override at `/etc/ai-control/signing.conf` second, lazy-generated per-install MOK third, unsigned-with-warning fourth. This lets:

- Home users: boot bootc image, run one-time `mokutil --import /usr/share/archimation/trust-pub.der`, reboot, done.
- Fleet operators: drop their own `/etc/ai-control/signing.conf` into the image via a derived layer, re-sign during derive.
- Developers on archiso/legacy: DKMS auto-generates a per-install MOK, prints `mokutil --import` hint, works same as Ubuntu's NVIDIA flow.
- Anti-integrity users (old HW, lockdown=none): everything works without signing; loud warning, no functional loss.

### 2.3 Project MOK lifecycle

- **Generation:** Once, on a secure CI-vault host. 4096-bit RSA, SHA-256, 395-day validity. See `bootc/trust-keys/README.md` §3 for exact openssl invocation.
- **Storage:** Private key only in GitHub Actions secret `TRUST_MOK_PRIV_PEM` (base64). Public cert in image at `/usr/share/archimation/trust-pub.der`. Public also kept next to private in CI vault for audit — never shipped.
- **Rotation:** Annual. New secret name `_V<n+1>`, old `_V<n>` kept for one release cycle. Image ships both pubs, user MOK-enrolls both; two cycles later old pub is dropped. See README §7.
- **Emergency rotation:** Key compromise → SBAT bump + `archimation-trust-revoke` hotfix package + 7-day target update window. Standard Red Hat drill, scaled down.

---

## 3. Build-time signing vs first-boot signing

### 3.1 The tradeoff

| Axis              | Build-time (bootc)       | First-boot (DKMS)        |
|-------------------|--------------------------|--------------------------|
| Immutable OS      | **Required**             | Breaks the contract      |
| Pinned kernel     | **Natural**              | Fights DKMS model        |
| Deterministic     | **Yes** (SOURCE_DATE_EPOCH + fixed key) | No (machine-dependent) |
| Key management    | **Centralized** (vault + rotation) | **Distributed** (every machine)   |
| Offline enrollment| Required (mokutil 1x)    | Required (mokutil 1x for per-install MOK) |
| Kernel match      | Guaranteed by image pin  | Failure mode: DKMS build breaks on kernel upgrade |
| Attack surface    | Single key in vault      | Many keys, each a local target |
| Fits archiso      | No                       | **Yes**                  |
| Fits bootc        | **Yes**                  | No (no writable /usr)    |

Conclusion: build-time signing is strictly better everywhere bootc applies. But archiso still needs the first-boot path because ISO hardware is unknown until boot. So we ship **both**, with clear handoff:

- **bootc image path:** `bootc/build-trust-module.sh` compiles + signs at image build; `trust-dkms.install` detects the pre-built `/usr/lib/modules/<ver>/extra/trust.ko` sentinel and short-circuits DKMS entirely.
- **archiso path:** `trust-dkms.install` runs `dkms build` + `dkms install` + `_sign_all_dkms_outputs` which walks the installed copy and signs with whichever key source is available.

### 3.2 Determinism — the subtle part

Two builds of the same source against the same kernel version with the same compiler must produce **byte-identical** `trust.ko` before signing. This is required so that:

- OCI image layers deduplicate cleanly across rebuilds (no gratuitous cache misses).
- The "is this module the one I expect?" check in field is a simple `sha256sum` comparison, not a semantic-equivalence proof.
- Supply chain attacks via "random byte X in mod header" are detectable.

`build-trust-module.sh` enforces determinism via:

- `SOURCE_DATE_EPOCH` exported from `git log -1 --pretty=%ct` of the trust source tree.
- Bounded `-j` parallelism (bounded by `nproc`, which the build container pins).
- `strip --strip-debug` before signing (otherwise gcc's `.debug_info` section bakes build hostnames).
- Kernel's Kbuild already treats `SOURCE_DATE_EPOCH` as canonical ([kernel reproducible-builds](https://www.kernel.org/doc/html/latest/kbuild/reproducible-builds.html)).

---

## 4. Lockdown, Secure Boot, and graceful degradation

### 4.1 The three enrollment states (user-facing)

**State A — Secure Boot ON + MOK enrolled** (happy path):
- `mokutil --sb-state` → `SecureBoot enabled`
- `mokutil --list-enrolled` contains our cert
- `lockdown` is whatever the kernel defaults to (usually `integrity`)
- `modprobe trust` → succeeds, `dmesg` shows "trust: module verification succeeded"

**State B — Secure Boot ON + MOK not enrolled** (most painful):
- `mokutil --sb-state` → `SecureBoot enabled`
- `mokutil --list-enrolled` does NOT contain our cert
- kernel is in `lockdown=integrity` by default
- `modprobe trust` → fails, `dmesg` shows "module verification failed: signature and/or required key missing — tainting kernel"
- `/dev/trust` missing → ai-control daemon falls back to software-only mode with a loud SCM event

UX response: first-boot wizard `archimation-enroll-mok` detects this state and offers three choices:
1. Enroll project MOK now (recommended; step through `mokutil --import` + reboot)
2. Disable Secure Boot in firmware (F2 walkthrough)
3. Proceed without `trust.ko` (trust-mediated features off, warn loudly)

**State C — Secure Boot OFF** (legacy hardware or user opt-out):
- `mokutil --sb-state` → `SecureBoot disabled`
- Kernel's lockdown defaults to `none` (unless user added `lockdown=integrity` to cmdline)
- `modprobe trust` → loads regardless of signature
- System prints: "NOTICE: trust.ko loaded without signature verification (lockdown=none). Authority root is software-only; enable Secure Boot + enroll MOK for hardware-strength."

### 4.2 linux-hardened compatibility

Hardened kernels have historically been a sharp edge for third-party modules:

- [Arch Forum thread: managing module signing without MOK under SB](https://bbs.archlinux.org/viewtopic.php?id=283289) — user report of `linux-hardened` refusing NVIDIA without signed modules. Same class as our problem.
- [Arch Forum thread, laptop issues](https://bbs.archlinux.org/viewtopic.php?id=295255) — MokManager UX failures with UEFI firmware that does not respect shim's redirect.
- `linux-hardened` compiles with `CONFIG_SECURITY_LOCKDOWN_LSM=y` and `CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT=y` by default, which means SB-enrolled hardware automatically enters `lockdown=integrity`. Unsigned `trust.ko` → `modprobe` refusal → no Root of Authority.

This is why our install path **always** attempts to sign (even on archiso), and why the "unsigned + lockdown=integrity" combination is our must-warn case.

### 4.3 MOK → kernel keyring propagation

There is a subtle gotcha: enrolling a MOK with `mokutil --import` loads it into shim's MokList at reboot, but **does not automatically propagate it to the kernel's `.machine` keyring** on modern kernels. The missing step is `mokutil --trust-mok` (sets `MokListTrustedRT=01`), which is documented in [itsfoss.gitlab.io — module verification signature missing](https://itsfoss.gitlab.io/blog/module-verification-signature-and-or-required-key-missing-tainting-kernel/).

Our `archimation-enroll-mok` wizard runs **both** import and trust-mok in the same flow, so users who go through the wizard don't hit this gotcha. Users who run `mokutil` manually may; we document it in `bootc/trust-keys/README.md` §6.

---

## 5. Transition plan — what S72 ships vs what S73+ will ship

**S72 Phase 1 (this session, all landing together):**

- `bootc/build-trust-module.sh` — image-build-time compile + sign (Agent β, this doc's author).
- `bootc/trust-keys/` — key lifecycle docs + CI hook templates (Agent β).
- `packages/trust-dkms/trust-dkms.install` — signing-aware rewrite with three-tier key resolution (Agent β).
- `bootc/Containerfile` — references `build-trust-module.sh` in a build stage (Agent α; see forward-reference in β's README §4).
- `docs/research/s72_beta_dkms_bootc.md` — this doc.
- Pacman hook for upgrades — still lives in `trust-dkms` PKGBUILD; unchanged.

**S72 known gaps handed off to S73 or later:**

- `archimation-enroll-mok` first-boot wizard. Today users run `mokutil --import` manually; wizard is scoped but not implemented.
- Project MOK genesis. S72 lands the tooling; the actual first keypair must be generated on a CI vault host out-of-band and stored as GitHub Actions secrets before the Containerfile build works for real. Until then, `ALLOW_UNSIGNED=1` is set in CI and the resulting image is marked "unsigned — dev only".
- SBAT integration. Our `trust-pub.der` has no SBAT stanza yet. When we wire it up ([shim SBAT.md](https://github.com/rhboot/shim/blob/main/SBAT.md)), we'll get the "per-generation revocation" property that Red Hat uses post-BootHole.
- Sidecar RPM style kmod-trust packages matching each supported kernel ABI. Right now we only support the one kernel version the bootc base image pins. For rpm-ostree style layering of alternate kernels, we'd need to build kmod-trust-<kver> packages the way akmods does.
- TPM-sealed key storage for the project MOK. Today the private key lives in GHCR Actions secret vault; long term it should live in a HSM or Yubikey (`sbctl` already supports this path via `--keytype`).

---

## 6. Verifying the transition worked

Any one of these commands tells you immediately whether the pipeline is healthy:

```bash
# (1) Image build produced a signed module — inside bootc build CI
tail -c 28 /usr/lib/modules/${KERNEL_VERSION}/extra/trust.ko | \
    grep -q 'Module signature appended' && echo "OK: signed" || echo "BAD: unsigned"

# (2) Running system has loaded a signature-verified module — on a deployed host
dmesg | grep -E 'trust.*verification succeeded' && echo "OK: verified"
dmesg | grep -E 'module verification failed' && echo "BAD: unverified — MOK not enrolled?"

# (3) The cert you have in hand is the cert that signed the module
modinfo /usr/lib/modules/$(uname -r)/extra/trust.ko | grep -E 'sig_hashalgo|signer'
openssl x509 -inform DER -in /usr/share/archimation/trust-pub.der -noout -subject -fingerprint -sha256

# (4) MOK is enrolled AND trusted by kernel
mokutil --list-enrolled | grep -iE 'archimation|trust.ko'
keyctl list %:.machine   # on 5.13+; should include the project cert

# (5) Lockdown state
cat /sys/kernel/security/lockdown   # → "[none]" or "[integrity]" or "[confidentiality]"
```

If (1) passes at image build time AND (2)+(4) pass on the first boot of that image, the transition is real end-to-end. If any of these fail, the module runs in degraded mode and the daemon surfaces an SCM event we can alert on.

---

## 7. References

1. kernel `Documentation/admin-guide/module-signing.rst` — [module-signing.rst](https://www.kernel.org/doc/Documentation/admin-guide/module-signing.rst) — canonical kernel-side docs; defines sign-file, the PKCS#7 trailer format, SHA algorithm options, and CONFIG_MODULE_SIG semantics.
2. `kernel_lockdown(7)` — [man7.org](https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html) — the three lockdown modes, what each one refuses, and the rationale.
3. mjg59 — [Linux kernel lockdown, integrity, and confidentiality](https://mjg59.dreamwidth.org/55105.html) — the design doc from the lockdown LSM's primary author.
4. Red Hat — [Signing a kernel and modules for Secure Boot (RHEL 8)](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/managing_monitoring_and_updating_the_kernel/signing-a-kernel-and-modules-for-secure-boot_managing-monitoring-and-updating-the-kernel) — canonical downstream reference implementation.
5. RPM Fusion — [Packaging/KernelModules/Akmods](https://rpmfusion.org/Packaging/KernelModules/Akmods) — the akmods packaging spec Universal Blue forks.
6. Universal Blue — [ublue-os/akmods GitHub](https://github.com/ublue-os/akmods) — bootc-friendly signed-kmod caching layer. The closest existing project to what we're building.
7. Universal Blue — [UCore ZFS kmods now signed for Secure Boot](https://universal-blue.discourse.group/t/ucore-zfs-kmods-are-now-signed-for-secureboot/383) — narrative of UCore's DKMS-to-signed-kmod transition.
8. BlueBuild — [akmods module reference](https://blue-build.org/reference/modules/akmods/) — DSL-level invocation pattern.
9. Silverblue — [Silverblue first impressions (Morales, Oct 2025)](https://www.mauromorales.com/2025/10/27/fedora-silverblue-first-impressions-from-someone-building-an-immutable-system/) — discusses `silverblue-akmods-keys` and rpm-ostree kmod layering.
10. Bluefin — [Kernel and AKMOD Installation (DeepWiki)](https://deepwiki.com/ublue-os/bluefin/2.6-kernel-and-akmod-installation) — Universal Blue's flagship image's kernel-pin + akmod-layer architecture.
11. Foxboron — [sbctl GitHub](https://github.com/Foxboron/sbctl) — Arch's UEFI Secure Boot key management tool. Our model for the pacman-hook auto-sign pattern.
12. Arch Wiki — [UEFI Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot) — end-to-end PK/KEK/db/dbx + MOK walkthrough.
13. Arch Wiki — [Signed kernel modules](https://wiki.archlinux.org/title/Signed_kernel_modules) — the Arch-specific DKMS + sign-file recipe.
14. Phoronix — [Linux Patch Drops SHA1 From Module Signing](https://www.phoronix.com/news/Linux-Patch-Drop-SHA1-Mod-Sign) (Nov 2025) — reason we default to sha256 and plan sha512 upgrade.
15. shim SBAT — [SBAT.md](https://github.com/rhboot/shim/blob/main/SBAT.md) — the generation-number revocation scheme post-BootHole. We do not yet emit SBAT stanzas; S73 candidate.
16. itsfoss — [module verification signature and/or required key missing](https://itsfoss.gitlab.io/blog/module-verification-signature-and-or-required-key-missing-tainting-kernel/) — the `mokutil --trust-mok` gotcha we document in our enrollment flow.
17. Arch Forum — [Managing module signing without MOK under Secure Boot](https://bbs.archlinux.org/viewtopic.php?id=283289) — field reports on the UX failure mode we want to prevent.
18. S71-K — [`docs/research/s71_k_measured_boot.md`](s71_k_measured_boot.md) — our own doc; upstream view of the whole boot chain.
