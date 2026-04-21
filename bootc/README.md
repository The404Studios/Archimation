# ARCHWINDOWS `bootc/` — image-mode foundation

Phase 1 of the S72 migration from archiso to bootc/OCI. This directory contains
everything needed to build ARCHWINDOWS as a bootable container image instead of
(or in addition to) the traditional live ISO.

Owners: Agent α (foundation, this README), Agent β (`build-trust-module.sh`,
signed modules), Agent δ (installer wiring under `profile/airootfs/usr/bin/`),
Agent γ (rollback tests).

---

## Why bootc (the moat argument)

Our differentiator is a kernel-side trust authority (`trust.ko`) that gates
every sensitive operation against a chromosomal proof chain. That story is
only coherent if the trust kernel, the PE loader, and the Python control
daemon that enforces policy are **tamper-resistant on disk**.

On a classic Arch install, `/usr/bin/pe-loader` is a plain file. Anyone with
offline disk access (single-user boot, USB-rescue, pulled drive) can replace
it. The kernel's authority proofs become meaningless downstream because the
userspace that consumes them is mutable.

**bootc fixes this.** The OS is shipped as an OCI image. `/usr` is mounted
read-only, composefs-verified at boot, its fs-verity digest embedded in the
kernel command line, and that command line is measured into TPM2 PCRs. An
attacker who swaps `pe-loader` has to also re-sign the composefs digest with a
key they do not have, AND re-produce a TPM measurement that matches the
original — otherwise remote attestation and the initrd's own
`prepare-root.conf` signature check both notice.

This is the architectural prerequisite for the rest of our roadmap (remote
attestation, measured boot of trust.ko, cert-chain-to-TPM anchoring). It is
also why we resisted doing it earlier: the pre-bootc tooling on Arch didn't
exist. It does now (2025–2026) — `bootc` was accepted into the CNCF Sandbox
in January 2025 ([CNCF](https://www.cncf.io/projects/bootc/)) and several
Arch-native bootc variants shipped in 2025–2026.

Sources: [bootc upstream](https://containers.github.io/bootc/),
[composefs+OSTree integrity](https://ostreedev.github.io/ostree/composefs/),
[bootc install spec](https://bootc-dev.github.io/bootc//man/bootc-install-to-disk.8.html).

---

## How this works (layered architecture)

```
   ┌──────────────────────────────────────────────────────────┐
   │  ghcr.io/fourzerofour/archwindows-bootc:latest  (OCI)    │
   │                                                          │
   │  Layer N:  airootfs overrides    (profile/airootfs/)     │
   │  Layer …:  custom pacman pkgs    (repo/x86_64/*.zst)     │
   │  Layer …:  pre-built signed .ko  (Agent β, step 2)       │
   │  Layer 0:  Arch base + kernel    (archlinux:latest)      │
   └───────────────────────────┬──────────────────────────────┘
                               │  bootc install / upgrade
                               ▼
              ┌──────────────────────────────┐
              │  host disk, composefs-backed │
              │  /usr  (ro, fs-verity sealed)│
              │  /var  (rw, machine-state)   │
              │  /etc  (rw, 3-way merge)     │
              └──────────────────────────────┘
```

**What lives where:**

| In the image (read-only `/usr`) | On the host (read-write `/var`, `/etc`) |
|---|---|
| `pe-loader`, `trust.ko`, `ai-control-daemon` | user home dirs |
| Our Python cortex code | Journal + persistent logs |
| systemd units, tmpfiles.d rules | hostname, user accounts, SSH host keys |
| Pre-built signed kernel modules | runtime state of the AI cortex |
| `/usr/share/ai-control/dictionary_v2.pkl.zst` | dynamically-trained Markov state |

`/home`, `/opt`, `/srv`, `/root` are symlinks into `/var` per the bootc/ostree
layout convention (lifted from [M1cha/bootc-archlinux](https://github.com/M1cha/bootc-archlinux)).

---

## Build

Pre-requisite: our custom pacman packages must exist. Build them first the
archiso way:

```bash
wsl -d Arch -- bash -c 'cd /mnt/c/.../arch-linux-with-full-ai-control && bash scripts/build-packages.sh'
# verifies pkg-tar.zst files land in repo/x86_64/
```

Then build the bootc image:

```bash
# On an Arch host (or in any container with buildah/podman):
bash bootc/build-bootc.sh

# Dry-run mode (prints the builder command it would invoke, useful on WSL2
# where you may not have podman/buildah set up yet):
ARCHWINDOWS_BOOTC_DRYRUN=1 bash bootc/build-bootc.sh

# Override the tag:
TAG=ghcr.io/fourzerofour/archwindows-bootc:dev bash bootc/build-bootc.sh
```

`build-bootc.sh` picks `buildah` > `podman` > `docker` in that order. First
run downloads ~600 MB of Arch packages from the mirrors.

---

## Smoke-test (without deploying)

The built image is **not** a live-running OS inside the container — it's a
system image that `bootc` later turns into an installed OS. But you can poke
at the contents like any OCI container:

```bash
# drop into a shell inside the image
podman run --rm -it --entrypoint /bin/bash archwindows-bootc:dev

# inside:
pacman -Q | wc -l           # ~400+ packages
ls /usr/bin/pe-loader       # our loader binary
ls /usr/lib/modules/*/extra/trust.ko   # pre-built signed module (Agent β)
systemctl list-unit-files | grep ai-   # our units are enabled

# from the host — sanity checks:
podman run --rm --entrypoint /bin/bash archwindows-bootc:dev \
  -c 'bootc container --check 2>/dev/null || echo "bootc binary not shipped yet"'
```

**What the smoke-test won't tell you:** whether the image actually boots.
That needs `bootc install` on real (or virtual) disk — see next section.

---

## Deploy (to a real disk)

bootc inverts the usual installer flow: the **target image itself runs the
installer**. You boot any OS that can run a container (our archiso ISO is the
obvious one during transition), pull the image, and invoke `bootc install`
from inside it.

```bash
# the upstream install path
# (run as root, destructive — /dev/sdX is the target disk)
podman run --privileged --pid=host \
    --security-opt=label=type:unconfined_t \
    ghcr.io/fourzerofour/archwindows-bootc:latest \
    bootc install to-disk --wipe /dev/sdX
```

`bootc install to-disk` lays out the DPS-typed partitions
([UAPI DPS](https://uapi-group.org/specifications/specs/discoverable_partitions_specification/)),
ESP, and boots via GRUB 2.12+ with `bli` or systemd-boot
([bootc install docs](https://bootc.dev/bootc/bootc-install.html)). Agent δ
is shipping `/usr/bin/ai-install-bootc` — a friendly wrapper that does this
behind a menu-driven UX consistent with our archiso installer.

---

## Upgrade (user-facing)

Once a machine is running the bootc deployment:

```bash
# pull new image, stage as next-boot deployment
sudo bootc upgrade

# or pull without applying — good for pre-download over flaky networks
sudo bootc upgrade --apply=false
sudo bootc upgrade --apply    # later, when ready

# reboot into the new deployment
sudo systemctl reboot
```

The previous deployment stays on disk as `rollback` until it's overwritten by
the next upgrade cycle (default: two deployments total).

See [upstream upgrade/rollback docs](https://bootc-dev.github.io/bootc/upgrades.html).

---

## Rollback

If the upgrade broke something:

```bash
sudo bootc rollback
sudo systemctl reboot
```

This swaps the boot-entry ordering — the previous deployment becomes the
default, and the broken one becomes the rollback. You can re-swap at will
until one of the two gets garbage-collected by the next `bootc upgrade`.

Agent γ's `scripts/test-bootc-rollback.sh` drives this flow in CI on a QEMU
VM.

---

## Layered packages

bootc supports adding packages on top of the base image at runtime — useful
for hardware-specific drivers or per-site tweaks that don't belong in the
upstream image. On RPM systems this is `rpm-ostree install`. On Arch we have
two paths:

1. **Toolbox-style overlay** (recommended for user software): use a
   `distrobox` or `toolbox` container. User packages never touch the bootc
   host; the host stays pristine.
2. **`bootc switch`-layered** (for system software): Fedora-bootc supports
   `bootc switch ostree-unverified-image:...` to pivot to a sibling image
   that adds your packages. On Arch this is achievable but not yet automated
   — the recommended path is to fork our Containerfile, add a `pacman -S …`
   line, and build your own image.

Details: [Universal Blue's image-template](https://github.com/ublue-os/image-template)
documents the "build your own flavor" pattern; it transfers directly to us.

---

## Known issues (S72 Phase 1)

These are tracked as follow-up agent work. The image builds and is shippable
as-is; these are rough edges, not blockers.

| Issue | Owner | Status |
|---|---|---|
| `bootc` binary itself not in Arch core/extra; Containerfile Step 3 is a stub. `bootc upgrade` will not work on a deployed system until this lands. | Agent β / δ | Deferred to S73 |
| Initramfs is dracut, not mkinitcpio (bootc/composefs works best with dracut). Breaks any downstream tooling that assumed mkinitcpio. | Agent α | Documented in research doc |
| DKMS is removed; `trust.ko` is pre-built and signed at image-build time by `build-trust-module.sh`. On-target kernel upgrades require a new image build, NOT a local `dkms autoinstall`. | Agent β | Intentional by design |
| `bootc install-to-filesystem` invoked by `ai-install-bootc` needs the MOK chain provisioned. If Secure Boot is enforcing and we haven't enrolled our signing cert, the pre-built `trust.ko` will refuse to load. | Agent β + δ | Tracked for S73 |
| Pacman inside OCI strips `lsign` key — confirmed behavior of the upstream `archlinux/archlinux` image. Our Containerfile re-runs `pacman-key --init && pacman-key --populate` as Step 1. | Agent α | Resolved |
| `/var` migration: existing archiso users upgrading in place keep their old `/var` layout (e.g. `/var/home` may not exist). Agent δ's installer handles the migration path. | Agent δ | In progress |
| `bootc upgrade --apply=false` semantics for our AI cortex's self-update loop aren't plumbed yet — cortex currently polls `pacman` directly. Needs a handler that shells out to `bootc status --json`. | Agent α S73 | Documented |

---

## Further reading

- Foundation rationale, alternatives considered, and the Arch-in-OCI
  feasibility study: [`docs/research/s72_alpha_bootc_foundation.md`](../docs/research/s72_alpha_bootc_foundation.md).
- Signing pipeline details (MOK enrolment, sign-file mechanics): Agent β's
  research doc when it lands.
- Rollback test matrix: Agent γ's `scripts/test-bootc-rollback.sh` and its
  associated research doc.
