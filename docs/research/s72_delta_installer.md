# Session 72 / Agent δ — Two-Mode Installer Design

**Date:** 2026-04-20
**Scope:** Add a parallel `ai-install-bootc` path next to the existing
`ai-install-to-disk` (archiso/pacstrap) installer, wire a mode dispatcher,
update the first-boot-wizard button set, and document capability detection
and old-hardware graceful degradation.

---

## 1. Why two install modes

S72 introduces a bootc/OCI image path (`bootc/Containerfile`, Agent α).
We are **not** deprecating the archiso pacstrap path — it remains the
correct answer for systems that can't host bootc (no container runtime
in the installer's live environment, sub-16-GiB disks where A/B atomic
deploys don't fit, or air-gapped networks with no OCI image cached).

The two modes produce materially different deployed systems:

| Aspect                 | bootc                                           | archiso (legacy)                       |
|------------------------|-------------------------------------------------|----------------------------------------|
| Deploy unit            | OCI image (immutable layer graph)               | pacstrap of individual `.pkg.tar.zst`  |
| `/usr` mutability      | Composefs read-only + ostree overlay            | Read-write; pacman edits in place      |
| Update mechanism       | `bootc upgrade` → reboot (atomic)               | `pacman -Syu`                          |
| Rollback               | `bootc rollback` (one command, prior image)     | Manual; `snapper` if BTRFS configured  |
| Disk minimum           | ~16 GiB (needs A/B room)                        | ~8 GiB                                 |
| Boot path              | ostree + composefs via GRUB/systemd-boot        | Traditional GRUB on ext4/btrfs         |
| Best for               | Appliances, kiosks, attested deployments        | Power users who live in pacman         |

We expose both at the same entry point (`ai-install-to-disk`) via a
`--mode {bootc|archiso}` flag, with auto-detection defaulting to bootc
when the `bootc` binary and `/usr/bin/ai-install-bootc` are both present.
A wizard user who prefers the recommended path just clicks
*"Install (bootc — recommended)"* and never sees the CLI flag; a power
user who wants archiso types `sudo ai-install-to-disk --mode archiso` or
clicks *"Install (legacy archiso)"*.

---

## 2. Capability detection algorithm

`ai-install-bootc` probes four capability axes early, prints a visible
matrix, and prints **unmissable red warnings** for each degradation.
Detection never fails the install by itself — it only downgrades
defaults or refuses the path when no safe fallback exists.

### 2.1 UEFI vs BIOS

```bash
if [ -d /sys/firmware/efi/efivars ] || [ -d /sys/firmware/efi ]; then
    CAP_EFI=yes
else
    CAP_EFI=no                # BIOS/legacy boot path
fi
```

On BIOS systems we create an MBR disklabel, a small (512 MiB) ext4
`/boot`, and a BIOS-boot flag. GRUB BIOS is the only supported
bootloader in that branch. The red warning explicitly calls out
*"NO Secure Boot, NO measured boot"* so the user understands the
trust posture.

### 2.2 Secure Boot state

`mokutil --sb-state` is the canonical probe. If mokutil isn't present
(minimal live ISO), we fall back to parsing `/sys/firmware/efi/efivars/SecureBoot-*`
byte 4. Secure Boot off is not a failure — we note it and proceed.

### 2.3 TPM 2.0 presence + version

```bash
[ -e /sys/class/tpm/tpm0 ] || [ -e /dev/tpm0 ] || [ -e /dev/tpmrm0 ]
# If present, determine version:
tpm2_getcap properties-fixed     # succeeds on 2.0 only
# OR:
cat /sys/class/tpm/tpm0/tpm_version_major  # '2' or '1'
```

Only TPM 2.0 satisfies the trust.ko hardware-attestation path
(Agent γ's `expected-pcr-11`). TPM 1.2 and "TPM present but unknown
version" both downgrade the installer to a soft-attestation posture.

### 2.4 Disk size

```bash
DISK_BYTES="$(lsblk -bdn -o SIZE "$TARGET")"
DISK_GIB=$(( DISK_BYTES / 1073741824 ))
# Refuse if DISK_GIB < 16 — bootc A/B can't fit.
```

Below 16 GiB the installer *refuses* bootc mode and points the user at
`--mode archiso` on the same device. We do not silently cram a tiny
disk into bootc; atomic updates require A/B copies of the image, and
breaking that property is a far worse sin than refusing to install.

### 2.5 Network

We probe with a short-timeout ping to 1.1.1.1 / 8.8.8.8 and a DNS
resolve for ghcr.io. If network is absent *and* no local image cache
exists (neither `containers-storage:localhost/archimation-bootc:latest`
nor `/var/lib/archimation/bootc-image.tar`), the installer hard-fails
with a direct suggestion to retry with `--image-ref`.

---

## 3. Partition strategy

### 3.1 GPT + btrfs (default, UEFI systems, disk ≥ 16 GiB)

```
/dev/sdX1   512 MiB   FAT32   EFI System Partition
/dev/sdX2   rest      btrfs   Archimation (subvols: @ @home @var @log)
```

btrfs is the default because it aligns naturally with atomic patterns —
CoW lets us take snapshots before/after `bootc upgrade` (Agent snap-pac
work in S73 if we go that way). The subvolume split matches Ubuntu's
modern install layout, which gives us a well-understood rollback story
for users who boot-into-snapshot from GRUB.

Mount flags:
```
subvol=@,     compress=zstd:3, ssd, noatime   → /
subvol=@home, compress=zstd:3, ssd, noatime   → /home
subvol=@var,  compress=zstd:3, ssd, noatime   → /var
subvol=@log,  compress=zstd:3, ssd, noatime   → /var/log
```

### 3.2 GPT + xfs / ext4 (on request)

`--fs xfs` and `--fs ext4` use the same GPT layout but swap the root
filesystem. bootc itself is FS-agnostic past the `--filesystem` flag;
xfs is Red Hat's atomic default and is a reasonable alternative for
users who don't want btrfs.

### 3.3 MBR + ext4 (BIOS systems)

```
/dev/sdX1   513 MiB   ext4    /boot (boot flag on)
/dev/sdX2   rest      ext4    Archimation /
```

BIOS path keeps things boring. No composefs (GRUB BIOS + composefs is
an unproven combination in 2026). The user gets a working system with
*no atomic upgrades* — `bootc upgrade` will still run but rollback is
degraded to manual GRUB generation selection.

---

## 4. MOK enrollment UX walkthrough

If `/etc/archimation/keys/mok.der` exists in the deployed image (Agent β's
machine-owner key for signed `trust.ko` and `wdm_host.ko`), the installer
does the following:

1. Runs `mokutil --import /etc/archimation/keys/mok.der` inside the target
   — this writes the import request to EFI vars, persistent across reboot.
2. Generates a one-time random 12-character password, prints it to the
   console in yellow, and writes it to
   `/var/lib/ai-arch/mok-enroll.txt` on the deployed system.
3. On first boot, shim's MokManager intercepts before kernel hand-off.
   User presses any key, selects *Enroll MOK*, types the password from
   step 2, confirms the certificate fingerprint, and MokManager adds
   the key to the platform's Machine Owner Key list.
4. Subsequent boots load `trust.ko` with its signature verified against
   the enrolled MOK — `kernel_lockdown=integrity` on Secure-Boot kernels
   accepts the module.

If MokManager doesn't appear (Secure Boot disabled, no shim in boot
chain), the import request is harmless — it simply stays queued.

---

## 5. Old-hardware graceful degradation messages

Everything in red. Every warning is *specific* (which capability, what
changes, what the user should expect). No silent fallbacks.

### 5.1 No TPM / TPM 1.2

```
!!! OLD-HARDWARE / DEGRADED CAPABILITY PATH !!!
The installer will continue in a reduced-security mode:

  - no TPM detected
    trust.ko will run in SOFTWARE-ONLY mode (no hardware-backed
    APE root of trust).  See docs/research/s71_k_measured_boot.md.
```

Trust posture on the deployed system: APE (Authority Proof Engine)
falls back to software RNG + signed-proof self-consumption, which is
meaningful against a remote attacker but not against physical-access
root-kits.

### 5.2 BIOS / no UEFI

```
  - BIOS/legacy boot (no UEFI)
    Will install MBR + BIOS GRUB.  NO Secure Boot, NO measured boot.
```

The user installs a fully-functional Archimation but the boot chain
has no measurement. This is explicit — we don't pretend the system is
attested.

### 5.3 No network + no cached image

The installer *refuses* to proceed and names its alternatives:

```
[ai-install-bootc] FATAL: no image source resolvable: no local storage,
no /var/lib/archimation/bootc-image.tar, and no network for GHCR.
Provide --image-ref <ref>.
```

### 5.4 Disk below minimum

```
!!! DISK TOO SMALL FOR bootc !!!
/dev/sda is 12 GiB — bootc needs at least 16 GiB for atomic A/B deploys.

Use the legacy installer for small disks:
    sudo ai-install-to-disk --mode archiso --target /dev/sda
```

Points at a working alternative rather than failing hard.

---

## 6. Image source resolution order

1. `--image-ref <ref>` if passed explicitly.
2. `containers-storage:localhost/archimation-bootc:latest` — what
   `podman build` or `buildah build` leaves in the host's storage. On
   the live ISO this is pre-populated by `bootc/build-bootc.sh` during
   ISO bake.
3. `oci-archive:/var/lib/archimation/bootc-image.tar` — a tarball
   shipped on the live ISO for fully-offline installs. S73 TODO:
   wire `build-bootc.sh` to emit this tarball.
4. `docker://ghcr.io/fourzerofour/archimation-bootc:latest` — network
   fallback. CI will push here (aspirational as of S72).

Each step prints which source is being used before launching bootc,
so an installer log always records which image was actually deployed.

---

## 7. Password handling

Reused from `ai-install-to-disk` verbatim:

1. `$AI_INSTALL_PASSWORD` if set in env.
2. Interactive twice-confirmed prompt if not `--yes`.
3. `--yes` without `$AI_INSTALL_PASSWORD` is a hard fail — we never
   ship a default password.
4. `chpasswd` via stdin, never via argv, so `ps` can't see it.

---

## 8. Citations

1. **bootc upstream** — `bootc install to-filesystem`, `bootc install
   to-disk`, `bootc install to-existing-root`.
   https://containers.github.io/bootc/bootc-install.html
2. **bootc manpage** — flags including `--source-imgref`,
   `--target-imgref`, `--root-ssh-authorized-keys`, `--filesystem`.
   https://containers.github.io/bootc/man/bootc-install-to-filesystem.html
3. **Fedora Silverblue / Kinoite install docs** — model for atomic
   installer UX and A/B layout.
   https://docs.fedoraproject.org/en-US/fedora-silverblue/installation/
4. **Arch Wiki — TPM** — TPM 2.0 detection, `tpm2-tools`,
   `tpm2_getcap` semantics.
   https://wiki.archlinux.org/title/Trusted_Platform_Module
5. **Arch Wiki — Secure Boot** — `sbctl` workflow, Microsoft-signed
   shim option, key-pair management.
   https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot
6. **shim MOK** — `mokutil --import`, MokManager boot-time prompt,
   enrollment flow.
   https://github.com/rhboot/shim/blob/main/README.md
7. **kernel_lockdown(7)** — why unsigned modules fail on Secure-Boot
   kernels, `integrity` vs `confidentiality` mode.
   https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html
8. **Ubuntu btrfs subvolume install layout** — `@`, `@home`, `@var`,
   `@log` naming convention that grub-btrfs expects.
   https://ubuntu.com/blog/b-tree-file-system-btrfs-for-linux
9. **S69 / `ai-install-to-disk`** — the existing archiso installer we
   delegate to on `--mode archiso`.
   `profile/airootfs/usr/bin/ai-install-to-disk`
10. **S72 / Agent α / bootc Containerfile** — the OCI image we deploy.
    `bootc/Containerfile`

---

## 9. Files touched by this agent

| Path                                                                 | Status  |
|----------------------------------------------------------------------|---------|
| `profile/airootfs/usr/bin/ai-install-bootc`                          | NEW     |
| `profile/airootfs/usr/share/applications/ai-install-bootc.desktop`   | NEW     |
| `profile/airootfs/usr/bin/ai-install-to-disk`                        | EDITED  |
| `packages/ai-first-boot-wizard/PKGBUILD`                             | EDITED  |
| `docs/research/s72_delta_installer.md`                               | NEW     |

---

## 10. Verification

```bash
bash -n profile/airootfs/usr/bin/ai-install-bootc           # OK
bash -n profile/airootfs/usr/bin/ai-install-to-disk         # OK
bash    profile/airootfs/usr/bin/ai-install-bootc --help    # usage prints, no destructive ops
bash    profile/airootfs/usr/bin/ai-install-to-disk --help  # usage prints with --mode section
```

The wizard's embedded Python parses via `ast.parse` after extracting the
heredoc body — two new buttons, same install flow, same marker file.

---

## 11. Handoffs for future sessions

- **S73:** wire `bootc/build-bootc.sh` to emit an `oci-archive:` tarball
  at `/var/lib/archimation/bootc-image.tar` so fully-offline installs
  work without network *and* without pre-populating container storage.
- **S73:** CI push to `ghcr.io/fourzerofour/archimation-bootc:latest`
  so the network fallback is actually usable.
- **S74:** `bootc install to-existing-root` path — upgrade an
  archiso-installed system to bootc mode in-place. Needs safe snapshot
  taken first; blocked on `@` being the root subvol.
- **S74:** wizard "post-install TPM enroll" page that walks the user
  through the MokManager UI on first boot with screenshots.
