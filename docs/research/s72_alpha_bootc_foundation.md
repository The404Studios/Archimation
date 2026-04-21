# S72 / Agent α — Bootc Foundation Choice and Arch-in-OCI Feasibility

**Session:** 72 (2026-04-20)
**Author:** Agent α (foundation lead)
**Owners this doc covers:** `bootc/Containerfile`, `bootc/build-bootc.sh`,
`bootc/README.md`, this research doc.
**Peers:** Agent β (signing + modules), Agent γ (rollback tests), Agent δ
(installer UX).

---

## 1. Executive summary

The S72 strategic decision — migrate ARCHIMATION from mutable archiso to an
image-mode OS — commits us to one of four families of tooling:

1. **`bootc` on top of OSTree + composefs** (upstream, CNCF Sandbox).
2. **`rpm-ostree`** (Fedora's older tool, same substrate).
3. **Raw OSTree** (the commit-store library underneath both).
4. **A purpose-built A/B partition scheme** (SteamOS 3, Vanilla OS v1 approach).

We chose (1), bootc, and layered our custom Arch userspace on top of the
upstream `archlinux/archlinux:latest` base image. This doc explains why, what
we inherit from prior art, and what the known risks are.

Headline verdict: **bootc is the right tool for 2026**. The Arch-in-OCI story
is carried by three community projects in active 2025–2026 development
([bootcrew/mono](https://github.com/bootcrew/arch-bootc),
[M1cha/bootc-archlinux](https://github.com/M1cha/bootc-archlinux), and
[apollo-linux/apollo](https://github.com/apollo-linux/apollo)). We are
neither the first nor the tenth Arch-bootc project, which gives us known-good
patterns to cherry-pick without being on the bleeding edge.

---

## 2. Foundation-choice comparison

### 2.1 Criteria

| # | Criterion | Why it matters for ARCHIMATION |
|---|---|---|
| C1 | `/usr` integrity at mount time | The trust kernel's authority proofs are meaningless if `/usr/bin/pe-loader` can be swapped offline. |
| C2 | TPM2 / measured-boot support | We want cert-chain-to-TPM anchoring in S74+. Needs fs-verity digest in cmdline → measured into a PCR. |
| C3 | Rollback UX | Users of a Windows-compat distro ship apps that break. "Upgrade broke my game" → `bootc rollback` has to Just Work. |
| C4 | Arch userspace without Fedora rebase | Our pacman packages are the product. Rebasing to dnf/RPM is a multi-month cost we cannot absorb. |
| C5 | Kernel-module loading story | `trust.ko` + `pe-compat.ko` (and future `wdm_host.ko`) must load signed, and upgrade with the kernel. |
| C6 | OCI registry as distribution channel | Ships to GHCR via `podman push`. Users `podman pull` to upgrade. Familiar ops pattern. |
| C7 | CNCF/community trajectory | We don't want to bet on a tool that's unmaintained in 2028. |
| C8 | Build-time flexibility | Containerfile is a Dockerfile — understood by every CI and every contributor. |

### 2.2 Comparison matrix

| Tool / Distro | C1 /usr integrity | C2 TPM2 | C3 Rollback | C4 Arch? | C5 Modules | C6 OCI | C7 Future | C8 Build UX |
|---|---|---|---|---|---|---|---|---|
| **bootc (upstream)** | YES (composefs-native) | YES (2025+) | `bootc rollback` | YES (arch base image works) | signed, pre-built at image time | **YES** | CNCF Sandbox Jan 2025 | Containerfile |
| rpm-ostree | YES (same substrate) | YES | `rpm-ostree rollback` | NO (RPM-only) | RPM + `rpm-ostree kargs` | partial | predecessor to bootc; Fedora-only | rpm-ostree compose |
| raw OSTree | YES (partial; composefs newer) | partial | YES (ostree admin undeploy) | YES (blendOS used it) | manual tooling | NO (native tree, not OCI) | stable library, not a UX | ostree compose |
| A/B partition (SteamOS) | NO (rw `/usr` on either slot) | NO by default | YES (boot other slot) | OK | normal DKMS | NO | SteamOS-specific | custom | 
| astOS (Arch + BTRFS) | partial (BTRFS snapshots, `/usr` rw) | NO | snapshot-based | YES | normal DKMS | NO | solo maintainer; niche | custom | 
| blendOS v4 | YES (overlay) | NO native | declarative yaml | YES | containerized | NO (uses podman containers as "tracks") | active maint; opinionated | `system.yaml` | 
| Universal Blue (Bluefin) | YES | YES | `bootc rollback` | NO (Fedora-based) | RPM | YES | very active, Dec 2025 refactor | Containerfile |
| Vanilla OS | YES (A/B + overlay) | partial | abroot | NO (Debian-based) | normal | YES (OCI since v2) | opinionated | .vib yaml |

The first column that matters for the moat (C1: `/usr` integrity at mount
time with cryptographic proof) has three winners: bootc, rpm-ostree, and
Universal Blue. Of those, only **bootc lets us keep the Arch userspace we
already have.**

### 2.3 Why not just keep archiso?

archiso is a perfectly good live-ISO builder. It's **not** an image-mode OS.
Packages installed into the airootfs are baked into a read-only squashfs at
ISO-build time, but once the installer (`archinstall`) runs on the target,
the result is a plain Arch install with a mutable `/`. That is exactly the
attack surface we're trying to remove.

We're keeping archiso as a parallel build path for two reasons:
(a) installer media — a bootc image needs a boot environment to run `bootc
install` from, and our archiso is the most convenient one we have; (b)
fallback during the transition — teams still running the archiso-installed
distro should keep getting pacman updates until every feature is reachable
via the bootc path.

---

## 3. The Arch-in-OCI problem

### 3.1 The tension

bootc was originally designed at Red Hat ([developers.redhat.com, Apr
2026](https://developers.redhat.com/articles/2026/04/01/bootable-containers-reduce-friction-red-hat-enterprise-linux-image-mode)),
where the assumption is that the image is built from RPMs and updates are
shipped through RPM streams. The `bootc upgrade` flow is substrate-neutral
at runtime — it just pulls an OCI image, extracts it via composefs, and
boots the new deployment — but the **build** flow assumes your package
manager writes to `/var` (RPM does, pacman does too), and that the package
manager can be invoked inside a rootless buildah step.

Pacman adds two wrinkles:

1. Pacman stores its DB at `/var/lib/pacman`. In a bootc image `/var` is
   machine-state; putting the package DB there means every bootable machine
   thinks its own `/var` is the canonical view. That's wrong — we want the
   DB frozen inside `/usr` so the immutable tree is self-describing.
2. The upstream `archlinux/archlinux:latest` Docker image strips the
   `lsign` key on first start, per [archlinux/archlinux-docker's
   policy](https://github.com/archlinux/archlinux-docker) — multiple
   containers sharing the same lsign key is a real compromise risk. We need
   to re-init it inside the build.

### 3.2 How others solved it

Three prior projects navigated these same shoals, and we borrow from each:

**[bootcrew/arch-bootc](https://github.com/bootcrew/arch-bootc)** — moved
to `bootcrew/mono` on 2026-03-19; originated by the same team (bootcrew)
that maintains similar experiments for openSUSE, Debian, Ubuntu, and GNOME
OS. Key trick: move pacman's `/var/...` state paths into
`/usr/lib/sysimage/...` via `sed` over `pacman.conf`, so the DB rides
inside `/usr` and is therefore part of the composefs-verified immutable
tree. We lifted this pattern verbatim into our Containerfile Step 1.

**[M1cha/bootc-archlinux](https://github.com/M1cha/bootc-archlinux)** — WIP
Arch bootc from 2024, referenced by [the bootc upstream discussion
#110](https://github.com/bootc-dev/bootc/discussions/110) on "Arch Linux
container: expected commit object" errors. Contributed the
`/home`→`var/home`, `/opt`→`var/opt`, `/root`→`var/roothome`,
`/usr/local`→`../var/usrlocal` symlink pattern via the
`ostree-0-integration.conf` tmpfiles.d file. We ship a minimally-edited
copy of that file as `bootc/ostree-integration.conf`.

**[apollo-linux/apollo](https://github.com/apollo-linux/apollo)** —
pre-alpha Arch+GNOME bootc desktop from late-2025 / early-2026. Useful as
existence proof; we did not borrow specific patterns but confirmed that
Arch+bootc+GNOME desktop **works end-to-end** including installer. Apollo
ships as a disk image they call `bootable.img` deployable in GNOME Boxes.

**[XeniaMeraki/XeniaOS](https://github.com/XeniaMeraki/XeniaOS)** — an
opinionated Arch bootc OS featuring Niri, DMS, the Cachy kernel, "Xenia
the Fox" theming, and gaming intent. Same existence proof; the gaming
angle aligns closely to our use case.

**Not-quite-matches (considered and rejected):**

- **[blendOS](https://blendos.co/)** — Arch-based, immutable, but uses
  overlay + podman-as-distro-tracks rather than OSTree+bootc. Its
  declarative `system.yaml` is interesting UX but the substrate differs;
  we'd be rebuilding half of it to get TPM2 integrity. See [blendOS v4
  release](https://blendos.co/blog/2024/06/05/blendos-v4-released-arch-linux-made-immutable-declarative-and-atomic/).
- **[astOS](https://github.com/lambdanil/astOS)** — Arch + BTRFS snapshots.
  Great rollback UX but no `/usr` integrity beyond BTRFS checksumming (no
  fs-verity, no TPM2 cmdline anchor). Fails C1.

### 3.3 What we inherit

From the upstream `archlinux/archlinux` Docker image:

- Weekly-refreshed rolling base. We pin to `:latest` at build time which
  becomes a content-addressed digest in the image layer graph — reproducible
  per-build even though "latest" moves upstream.
- Stripped lsign key (we re-init in Containerfile Step 1).
- Missing `base-devel` (we install it).
- No kernel (we install `linux` + `linux-firmware` + microcode).

From bootcrew/mono:
- The `/var/...` → `/usr/lib/sysimage/...` sed trick.

From M1cha/bootc-archlinux:
- The `ostree-0-integration.conf` tmpfiles.d layout.
- The `/home` → `var/home` symlink convention.

From [ublue-os/image-template](https://github.com/ublue-os/image-template):
- The `build_files/` numbered-step convention for Containerfile organization
  (we don't use it in Phase 1 — the Containerfile is small enough to be one
  file — but Agent δ or S73 may adopt it when the image grows).
- The `COPY` pattern for applying filesystem overrides.

---

## 4. Build flow — decision tree

```
             ┌────────────────────────────────────┐
             │ Input: Arch host or CI with        │
             │ buildah/podman/docker available    │
             └─────────────────┬──────────────────┘
                               │
                               ▼
             ┌────────────────────────────────────┐
             │ bash scripts/build-packages.sh     │
             │ (unchanged from archiso path)      │
             │ → repo/x86_64/*.pkg.tar.zst        │
             └─────────────────┬──────────────────┘
                               │
                               ▼
             ┌────────────────────────────────────┐
             │ bash bootc/build-bootc.sh          │
             │   bind-mounts repo/x86_64/         │
             │   invokes buildah > podman > docker│
             │   writes archimation-bootc:dev     │
             └─────────────────┬──────────────────┘
                               │
                  ┌────────────┴─────────────┐
                  ▼                          ▼
        ┌──────────────────┐     ┌─────────────────────┐
        │ podman run ...   │     │ bootc install ...   │
        │ smoke inside     │     │ onto real disk or   │
        │ image (non-boot) │     │ QEMU (Agent γ CI)   │
        └──────────────────┘     └─────────────────────┘
```

Three decision points, three answers:

1. **Base image: `archlinux:latest` vs pacstrap into `scratch`**? We chose
   `archlinux:latest`. Pacstrap-into-scratch gives tighter control and
   smaller images but duplicates work the upstream Docker maintainers
   already do, and they also handle the lsign-key rotation cleanly.
2. **Kernel source: `linux` stock vs `linux-zen` vs `linux-cachyos`**? Stock
   `linux` for Phase 1. Agent β's signed-module flow pins to the kernel
   version shipped in the image layer; swapping to zen/cachy is a
   per-image-flavor rebuild, easy but not day-one.
3. **Initramfs: `dracut` vs `mkinitcpio`**? **dracut**. Composefs+ostree
   integration is substantially more mature in dracut than mkinitcpio as of
   April 2026 ([ostree-prepare-root
   manual](https://man.archlinux.org/man/ostree-prepare-root.1.en)). Arch
   ships dracut in `extra`, so this is "install it and use it" rather than
   "port custom hooks." Cost: anyone expecting mkinitcpio-style hooks needs
   a dracut-module translation. Benefit: we don't maintain that code.

---

## 5. Layered package strategy

**Phase 1 (now, S72): no layered packages.** The image is the image. Users
who want extra software use distrobox/toolbox sidecar containers — their
user-namespaced userspace is as mutable as they like, but the host's `/usr`
stays sealed.

**Phase 2 (S73+): `bootc switch --layered` once bootc ships it for pacman.**
Fedora has this pattern today via `rpm-ostree install` — `dnf install foo`
at runtime creates a sibling deployment with `foo` overlaid. We will need
the equivalent: a local pacman invocation that produces a sibling image
with the requested packages and makes it the next-boot target. The
mechanism is the same as an upgrade, just with a locally-modified image.

**Phase 3 (S74+, aspirational): declarative overlay spec.** A yaml file
under `/etc/archimation/overlay.yaml` listing packages the user wants;
`bootc upgrade` honors it by producing a sibling image each cycle. This is
how Universal Blue does it, approximately, and it's the best UX — but it's
a non-trivial amount of tooling we haven't designed yet.

---

## 6. Update / rollback UX command table

| Intent | Command | Notes |
|---|---|---|
| Check for updates | `bootc upgrade --check` | Queries registry, reports new digest without staging. |
| Pull but don't apply | `bootc upgrade --apply=false` | Fetches layers, stages nothing. Good for pre-download. |
| Pull and stage for next boot | `bootc upgrade` | Default. Next `systemctl reboot` boots the new image. |
| Apply a previously-downloaded update | `bootc upgrade --apply` | Pairs with `--apply=false`. |
| Switch to a different image stream | `bootc switch ghcr.io/.../archimation-bootc:beta` | Cross-stream; full-image replacement. |
| Rollback to previous deployment | `bootc rollback` | Swaps boot-entry ordering. Next reboot boots previous. |
| Inspect current deployment | `bootc status` | Shows booted, rollback, staged. JSON output via `--json`. |
| Wipe staged update | `bootc upgrade --reset` | Un-stages; keeps booted deployment. |
| Initial install (target disk) | `bootc install to-disk /dev/sdX` | Run from inside the image, privileged. |
| Initial install (pre-formatted) | `bootc install to-filesystem /path` | For custom partition layouts. |

Sources:
- [bootc upgrade/rollback manual](https://bootc-dev.github.io/bootc/upgrades.html)
- [bootc-install-to-disk(8)](https://bootc-dev.github.io/bootc//man/bootc-install-to-disk.8.html)
- [RHEL image mode management (Chapter 12)](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_image_mode_for_rhel_to_build_deploy_and_manage_operating_systems/managing-rhel-bootc-images)
- [download-only mode article (Feb 2026)](https://developers.redhat.com/articles/2026/02/18/control-updates-download-only-mode-bootc)

---

## 7. DKMS in bootc (forward-ref to Agent β)

The archiso path ships `trust-dkms` so that on first boot, DKMS compiles
`trust.ko` against the user's running kernel. That's impossible in bootc:
at image-build time the kernel is **already pinned**, so there's no reason
to defer compilation — and on the deployed system, the kernel can't change
without a new image, so there's also nothing DKMS could rebuild against.

Agent β's approach:

1. Image build step: `bootc/build-trust-module.sh` invokes `make -C
   /usr/lib/modules/<kver>/build` with the trust sources, produces
   `trust.ko`.
2. `scripts/sign-file sha256 <key>.pem <cert>.der trust.ko` appends the
   PKCS#7 signature.
3. Install to `/usr/lib/modules/<kver>/extra/trust.ko` and `depmod -a`.
4. Image ships with the signed, in-tree module. First-boot `modprobe trust`
   succeeds. `kernel lockdown=integrity` honored. `IMA_APPRAISE` can
   optionally demand the signature.

The public cert must be pre-enrolled in MOK (for Secure Boot) or the module
refuses to load on enforcing systems. That's Agent δ's first-boot wizard
territory.

Layering order in the Containerfile:
```
Step 2 (base + kernel)
 → Step 4 (our custom repo + packages EXCEPT dkms)
 → Step X (NEW, inserted by Agent β): invoke build-trust-module.sh
 → Step 5 (airootfs overrides)
```

We deliberately ordered Step 4 before any step that might run Agent β's
module build, because installing the kernel and our repo needs to complete
first for `KERNEL_VERSION` to be a known, pinned quantity.

---

## 8. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `bootc` binary not in Arch repos → no `bootc upgrade` on deployed system | certain (as of Apr 2026) | high (blocks the whole story) | Agent β / δ pull from AUR or a pre-built tarball; tracked in README known-issues. |
| pacman lsign key stripping breaks custom-repo install | medium | high | Containerfile Step 1 re-runs `pacman-key --init && pacman-key --populate archlinux`; `SigLevel = Optional TrustAll` for our repo. |
| dracut doesn't pick up kernel cmdline changes | low | medium | Explicit `COPY` of dracut config; Agent γ's rollback test covers initramfs regeneration. |
| `/var` migration from archiso installs | medium | medium | Agent δ's installer detects pre-existing `/var` and runs a migration pass. |
| Mirror throttling during build (600 MB download) | high | low | buildah `--layers` caches per-step; CI uses a pacman mirror cache. |
| Composefs fs-verity requires kernel support | low (Arch stock has it since 6.8+) | high | Check in Containerfile Step 7 verifies `composefs` pacman pkg is present. |
| Upstream `archlinux/archlinux:latest` breaks without warning | low | high | Pin to content-addressed digest in CI (Agent γ); warn on drift. |
| `bootc install-to-disk` refuses on odd disk geometry | medium | medium | Agent δ's wrapper falls back to `to-filesystem` with explicit partitioning. |
| DKMS drift — users expect `dkms status` to mean something | medium | low | Documented in README; `dkms status` returns empty on bootc installs (intentional). |

---

## 9. What we are NOT doing in Phase 1

To keep scope tight:

- **No `bootc switch --layered`** UX. Users wanting extra pkgs use toolbox.
- **No UKI (Unified Kernel Image)**. Stock GRUB with composefs is the path;
  UKIs are S74+ when measured boot demands it.
- **No remote attestation server**. Just the local TPM2 anchor. Attestation
  is S74+.
- **No rolling "latest" stream**. Fixed tags only (`:dev`, `:2026.04.20`).
  Rolling is S73.
- **No signed OCI images**. `cosign` / Sigstore integration is S73.
- **No user-package overlay declarative spec**. See Phase 3 above.
- **No ARM64 / RISC-V image**. x86_64 only until S75.

---

## 10. Success criteria for S72 Phase 1

(What "done" looks like for Agent α's slice.)

- [x] `bootc/Containerfile` exists, < 150 lines, cherry-picks from known-good prior art with attribution. **Shipped 2026-04-20.**
- [x] `bootc/build-bootc.sh` exists, passes `bash -n`, supports dry-run. **Shipped; `bash -n` clean.**
- [x] `bootc/README.md` documents the build / install / upgrade / rollback flow. **Shipped, ~200 lines.**
- [x] This research doc exists, ≥ 10 citations, named prior art. **This doc, ~450 lines, 13+ citations.**
- [ ] `podman build bootc/` produces an image (deferred to S73 on real Arch host — NOT attempted on WSL2 per agent instruction).
- [ ] Image smoke-tests: `podman run archimation-bootc:dev` drops into a shell, `/usr/bin/pe-loader` present, `pacman -Q trust-system pe-loader ai-control-daemon` returns three installed packages. **Deferred to Agent γ CI.**

---

## 11. Citations (chronological, dates required)

1. [bootc upstream project page (CNCF)](https://www.cncf.io/projects/bootc/) — CNCF Sandbox admission announcement, January 21, 2025.
2. [GitHub discussion: bootc contributed to CNCF (#897)](https://github.com/bootc-dev/bootc/discussions/897) — bootc-dev/bootc, Jan 2025.
3. [CNCF sandbox arrivals — 13 January 2025 bootc entry](https://palark.com/blog/cncf-sandbox-2025-jan/) — Palark, Jan 2025.
4. [How to build, deploy, and manage image mode for RHEL](https://developers.redhat.com/articles/2025/03/12/how-build-deploy-and-manage-image-mode-rhel) — Red Hat Developer, March 12, 2025.
5. [Shape the Future of Linux — contribute to bootc](https://developers.redhat.com/blog/2025/07/23/shape-future-linux-contribute-bootc-open-source-project) — Red Hat Developer, July 23, 2025.
6. [Deploy image mode update in offline and air-gapped environments](https://developers.redhat.com/articles/2025/08/13/deploy-image-mode-update-offline-and-air-gapped-environments) — Red Hat Developer, August 13, 2025.
7. [Bluefin 2025 Wrap-up: State of the Raptor](https://docs.projectbluefin.io/blog/bluefin-2025/) — Project Bluefin, December 2025.
8. [Control updates with download-only mode in bootc](https://developers.redhat.com/articles/2026/02/18/control-updates-download-only-mode-bootc) — Red Hat Developer, February 18, 2026.
9. [Bootable containers: Reduce friction with RHEL image mode](https://developers.redhat.com/articles/2026/04/01/bootable-containers-reduce-friction-red-hat-enterprise-linux-image-mode) — Red Hat Developer, April 1, 2026.
10. [Building Red Hat MCP-ready images with image mode for RHEL](https://developers.redhat.com/articles/2026/04/14/building-red-hat-mcp-ready-images-image-mode-red-hat-enterprise-linux) — Red Hat Developer, April 14, 2026.
11. [bootc install manual pages (official)](https://bootc-dev.github.io/bootc//man/bootc-install-to-disk.8.html) — bootc-dev, retrieved April 2026.
12. [bootc upgrade and rollback documentation](https://bootc-dev.github.io/bootc/upgrades.html) — bootc-dev, retrieved April 2026.
13. [Understanding bootc install](https://bootc.dev/bootc/bootc-install.html) — bootc.dev, retrieved April 2026.
14. [archlinux/archlinux Docker image policy](https://github.com/archlinux/archlinux-docker) — archlinux GitHub org, active maintenance 2024–2026.
15. [bootcrew/arch-bootc (moved to bootcrew/mono)](https://github.com/bootcrew/arch-bootc) — moved March 19, 2026; first Arch-bootc reference implementation.
16. [M1cha/bootc-archlinux WIP](https://github.com/M1cha/bootc-archlinux) — 2024, discussed in [bootc-dev/bootc#110](https://github.com/bootc-dev/bootc/discussions/110).
17. [apollo-linux/apollo pre-alpha](https://github.com/apollo-linux/apollo) — Arch+GNOME desktop bootc, 2025–2026 active.
18. [XeniaMeraki/XeniaOS](https://github.com/XeniaMeraki/XeniaOS) — Arch-bootc gaming variant.
19. [blendOS v4 announcement](https://blendos.co/blog/2024/06/05/blendos-v4-released-arch-linux-made-immutable-declarative-and-atomic/) — June 5, 2024.
20. [lambdanil/astOS](https://github.com/lambdanil/astOS) — Arch+BTRFS immutable, solo maintainer.
21. [Universal Blue image-template](https://github.com/ublue-os/image-template) — ublue-os, active 2025.
22. [ostreedev/ostree composefs integration](https://ostreedev.github.io/ostree/composefs/) — upstream OSTree docs, 2024–2026.
23. [Larsson: Using Composefs in OSTree (2022)](https://blogs.gnome.org/alexl/2022/06/02/using-composefs-in-ostree/) — original composefs+ostree design article.
24. [ostree-prepare-root man page (Arch)](https://man.archlinux.org/man/ostree-prepare-root.1.en) — retrieved April 2026.
25. [Automotive SIG: Immutable atomic tamperproof in-vehicle OS](https://sigs.centos.org/automotive/about/con_immutable-atomic-tamperproof-in-vehicle-OS/) — CentOS Automotive SIG, ongoing 2024–2026.
26. [Road to trusted and measured boot in bootable containers (ASG 2024 talk)](https://media.ccc.de/v/all-systems-go-2024-309-the-road-to-a-trusted-and-measured-boot-chain-in-bootable-containers) — All Systems Go, 2024.
27. [Modernizing Linux Deployments with OSTree and Bootc](https://ubos.tech/news/modernizing-linux-deployments-with-ostree-and-bootc/) — UBOS, 2025.
28. [Immutable Linux in 2026: Fedora, Bazzite, NixOS, bootc](https://www.youtube.com/watch?v=ZAuKjD7Ny6I) — video overview, 2026.
29. [Configure TPM 2.0 Measured Boot on RHEL 9](https://oneuptime.com/blog/post/2026-03-04-configure-tpm-2-0-measured-boot-rhel-9/view) — OneUptime, March 4, 2026.
30. [UAPI Discoverable Partitions Spec](https://uapi-group.org/specifications/specs/discoverable_partitions_specification/) — UAPI Group, used by `bootc install to-disk` since v1.11.

---

## 12. Handoffs to other S72 agents

- **Agent β** (`build-trust-module.sh`, signing): Containerfile Step 3
  reserves space for the bootc binary install and Step 4 installs our
  custom repo BUT intentionally omits `trust-dkms`. You own inserting the
  signed-module build between Steps 4 and 5 (or as a late step — the
  symlink layout is already ready to receive `/usr/lib/modules/<kver>/extra/trust.ko`).
- **Agent γ** (rollback tests, CI): `bootc/build-bootc.sh` writes tag
  `archimation-bootc:dev` by default; your rollback test can pull that
  tag, `bootc install to-disk` it into a QEMU disk, do an `upgrade` to
  `:dev-v2`, then `rollback`. All three commands are documented in the
  README.
- **Agent δ** (installer UX): your `ai-install-bootc` wrapper should shell
  out to `bootc install to-disk` with the right flags; partition layout is
  DPS-typed by default in bootc 1.11+. The README documents the canonical
  command. Don't re-invent the wheel — just front-end it with our usual
  menu UX and handle the pre-flight checks (UEFI vs BIOS, disk size,
  existing OS).

---

*End of document. Next research doc in this sequence: Agent β's
`s72_beta_signed_modules.md` (module build + sign + MOK pipeline).*
