# Session 71 / Research Agent G — Atomic Updates for ARCHIMATION

**Date:** 2026-04-20
**Question:** Should ARCHIMATION adopt atomic / image-based updates (OSTree, BTRFS snapshots, bcachefs, A/B partitions) — and if so, which path?
**Context:** S69 just fixed pacman post-install via HTTPS + `file://` fallback. The question now is whether to go further and make updates *reversible* and *atomic* by construction.

---

## 1. Executive recommendation (TL;DR)

**Two-track proposal:**

1. **Session 72 (1 session, low risk, high ROI):**
   Add a `--fs {ext4,btrfs}` flag to `ai-install-to-disk`. On BTRFS, create the Ubuntu-style flat subvolume layout (`@`, `@home`, `@var`, `@log`, `@pkg`, `@snapshots`), install `snapper` + `snap-pac` + `grub-btrfs`, and configure pacman to auto-snapshot before every transaction. Default: **ext4 on disks <64 GB, BTRFS on disks ≥64 GB**. This gives ARCHIMATION the single biggest practical win of the "immutable distro" trend (*pre-transaction rollback, one-click recovery on bad update*) without leaving pacman or requiring a distro re-architecture.

2. **Long-horizon track (5–10 sessions, separate effort, not S72):**
   An OSTree-backed `archimation-atomic` variant. Keeps the trust kernel, AI daemon, and PE loader, but delivers `/usr` as an OSTree deployment. Build pipeline becomes "container image → ostree commit". This is Silverblue/Kinoite's architecture, retrofitted to Arch + our stack. Useful ceiling, not a S72 task.

The S72 BTRFS-snapper path is the correct next step: it converts 80% of the user-facing value of atomic distros (**"a bad update never bricks the machine"**) into *roughly one new installer flag and three new PKGBUILD dependencies*. The OSTree path buys the remaining 20% but is a distro-architecture rewrite.

---

## 2. Atomic update landscape (2024–2026)

### Fedora Silverblue / Kinoite / Atomic Desktops (rpm-ostree)

* **What it is:** OSTree-backed Fedora desktops. `/usr` is read-only and checkouts hardlink into an OSTree repo; updates are "download new commit, reboot, /usr swaps pointer".
* **Current state (2026):** Fedora 42+ ships Silverblue (GNOME 48), Kinoite (Plasma 6.3), Sway Atomic, Budgie Atomic, and COSMIC Atomic. Fedora Atomic Desktops enabled **composefs by default** starting with Fedora 41 — a big integrity step ([Fedora Magazine][magazine], [siosm.fr][siosm]).
* **Tooling:** `rpm-ostree status`, `rpm-ostree rollback`, `rpm-ostree rebase <ref>`. Packages layer on top via `rpm-ostree install <pkg>` — cost: each layered package needs reapplication on every rebase, so discouraged for heavy use; Flatpak is the preferred app surface.
* **Relevance to us:** This is the gold standard of "atomic desktop". Our `rpm-ostree install` equivalent would have to be a sibling to pacman, not a replacement — that's the retrofit cost.

### Project Bluefin / Universal Blue / bootc

* **What it is:** Bluefin ships a Fedora Silverblue base as an **OCI container image** (not an RPM repo snapshot). Updates = `podman pull` of a new image tag, reboot, system switches to it ([Bluefin][bluefin], [Red Hat on bootc][bootc-rh]).
* **2025 refactor:** Bluefin split into modular OCI configuration containers (`bluefin`, `bluefin-lts` on CentOS, `bluefin-distroless` on GNOME OS). The whole OS is now authored the same way you author a containerized microservice: `Containerfile` + CI → tagged image ([Bluefin 2025 wrap-up][bluefin-wrap]).
* **bootc (CNCF Sandbox, Jan 2025):** The underlying technology. `bootc switch <image>` swaps the running OS to a different container image *in place*; atomic update + rollback for free. RHEL Image Mode, Rocky Image Mode, Fedora Atomic — all now bootc-based ([bootc-dev][bootc-gh]).
* **Relevance to us:** ARCHIMATION-as-container would let a user `bootc switch ghcr.io/fourzerofour/archimation:latest` and get our full OS. Attractive long-term, but it assumes an OSTree-bootc-capable base. Not an Arch-native path yet.

### openSUSE MicroOS / Aeon / Leap Micro (transactional-update + BTRFS)

* **What it is:** Read-only BTRFS root. `transactional-update` (wrapper around `zypper`) clones the current subvolume, makes it writable, runs the update in a chroot, seals it read-only, sets it as next-default. If the update fails to boot, the prior subvolume is the fallback ([openSUSE/transactional-update][txn-update]).
* **Why it matters here:** It's the *architectural closest cousin to what we'd build on Arch*, because (a) both are BTRFS-snapshot-based not OSTree, and (b) there is a general-purpose wrapper that any package manager can call.
* **Specifically:** Snapper creates a new snapshot, the update happens in that snapshot (chrooted), and only on success is it promoted to default. Space-efficient because BTRFS CoW dedups blocks across snapshots. Rollback = switch default subvol + reboot ([orchestrator.dev 2025][microos-orch]).

### NixOS (declarative, generation-based)

* **What it is:** Not *atomic* in the OSTree sense but *generation-based*. Every `nixos-rebuild switch` creates a new "generation" in `/nix/var/nix/profiles/system-*` and a new bootloader entry. Rollback = select previous generation at GRUB ([NixOS docs][nixos-docs], [fosslinux 2026][fosslinux]).
* **Relevance to us:** Not the right model (we're a pacman-based distro, not a Nix-store distro). But the user experience — **"a bad update is never more than a reboot away from fixed"** — is exactly the goal we want for pacman + snapshots.

### ChromeOS / Android / SteamOS 3 (A/B partitions)

* **ChromeOS:** Two root partitions (`ROOT-A`, `ROOT-B`). Update writes to inactive partition, next boot swaps. If the new partition fails to boot 6 times, fallback to the other ([chromium.org][chromium]).
* **SteamOS 3 (Steam Deck):** Eight partitions total; two A/B root sets formatted **BTRFS mounted read-only**, two A/B `/var` in ext4, one `/home` in ext4. Updates use **RAUC + Casync** (signature-verified image chunks). Atomic write to the inactive slot, then swap ([steamos-teardown][steamos-td], [Collabora][collabora], [popsUlfr/steamos-btrfs][steamos-btrfs]).
* **Relevance to us:** A/B is the *simplest* atomic update mechanism — no fancy filesystems required — but it permanently halves user-disk space. Sensible for locked-down appliances (Steam Deck, Chromebook). Too heavy-handed for a general-purpose desktop distro on arbitrary hardware.

### Endless OS (OSTree, Debian-based)

* **What it is:** Debian derivative, but uses OSTree for core + Flatpak for apps. "The only consumer OS outside Fedora using OSTree on desktop." Target: low-bandwidth, intermittent-connectivity, offline-capable deployments ([linuxbsdos][lbos], [Register 2024][reg-endless]).
* **Takeaway:** OSTree on desktop Linux is a small club (Fedora Atomic + Endless). It's proven but niche.

### Linux atomic-distro tracker (2025 snapshot)

Current commonly-listed atomic / immutable desktop distros: Fedora Silverblue, Kinoite, Sway Atomic, COSMIC Atomic, Bluefin, Aurora, Bazzite, openSUSE MicroOS, openSUSE Aeon, SUSE Kalpa, NixOS, GUIX System, VanillaOS (Vibe — Debian-based, ABRoot = A/B + OCI), blendOS, SteamOS 3, Endless OS ([linuxbsdos 9-of-the-best][lbos], [techrefreshing 2025][techref]).

---

## 3. Arch-specific options (low-effort path)

The good news: **everything we need already exists in `extra/`.**

| Package | Purpose | Upstream |
|---|---|---|
| `snapper` | snapshot manager (originally openSUSE) | [openSUSE/snapper][snapper] |
| `snap-pac` | pacman pre-/post-transaction hooks that call snapper | [wesbarnett/snap-pac][snap-pac], [manpage][snap-pac-man] |
| `grub-btrfs` | generate GRUB entries for every BTRFS snapshot so boot-into-snapshot works | [Antynea/grub-btrfs][grub-btrfs] |
| `timeshift` | GUI/CLI snapshot orchestrator, BTRFS-aware, with restore from live USB | [teejee2008/timeshift][timeshift] |
| `btrfs-progs` | userspace for BTRFS itself | in `core/` |

### Pattern (snap-pac + grub-btrfs + snapper)

1. Install Archimation onto BTRFS with the Ubuntu-style flat layout: `@`, `@home`, `@var`, `@log`, `@pkg` (for `/var/cache/pacman/pkg`), `@snapshots`.
2. `pacman -S snapper snap-pac grub-btrfs`.
3. `snapper -c root create-config /` creates a snapper config for `/`.
4. Enable `snapper-timeline.timer` and `snapper-cleanup.timer` — the former takes hourly rolling snapshots, the latter prunes them.
5. snap-pac is **zero-config**: installing it wires up two pacman hooks (`50-bootbackup.hook` + `99-snapshot-post.hook`). From that moment on, every `pacman -Syu` creates a pre-snapshot, runs the transaction, creates a post-snapshot, and records the pacman command in the snapshot description.
6. Enable `grub-btrfsd.service` (watches `/.snapshots/` via inotify, regenerates `grub.cfg` on change). On next boot, GRUB has a submenu listing every snapshot; any entry is bootable read-only for inspection.

### What this buys us

* **"Last good state is always one reboot away."** If an update breaks the system, boot previous snapshot from GRUB, roll back, done.
* **Space cost:** CoW-based, not A/B-based. 50 snapshots of a 20 GB root typically take 2–6 GB extra on BTRFS with zstd:3 compression. *Far* less than doubling the disk.
* **No architectural change.** pacman still owns updates. The trust kernel and AI daemon don't know snapper exists. No new daemon, no new packaging pipeline.

### What it does **not** buy us

* **The OS is still mutable between transactions.** A rogue process with root can modify `/usr/bin/python` between snapshots and snap-pac won't see it (it only fires on pacman events).
* **Not image-based.** Two Archimation installs running the same `pacman -Syu` can still diverge (timing of AUR builds, mirror fallbacks, etc.).
* **Not container-deliverable.** We can't ship ARCHIMATION as an OCI tag.

These are fine trade-offs for S72. The OSTree path (§4) buys these if and when we want them.

---

## 4. Aspirational: OSTree-backed ARCHIMATION (high effort)

**Estimate: 5–10 sessions.** Not S72. Listed for posterity.

### Why it's hard on Arch

Arch is fundamentally a **mutable, rolling, package-centric distro**. OSTree is **immutable, versioned, tree-centric**. The retrofit means:

1. **Build pipeline change.** Instead of `scripts/build-packages.sh` → `pkg.tar.zst`, we'd need `scripts/build-ostree.sh` → OSTree commit on a branch like `archimation/stable/x86_64`. A commit is a hashed filesystem tree; we'd compose it by running a minimal pacstrap into `/var/tmp/rootfs`, then `ostree commit --repo=... --branch=...`.
2. **Boot sequence change.** Bootloader must know about `/ostree/deploy/archimation/deploy/<checksum>/root` and kernel-command-line `ostree=/ostree/boot.1/archimation/<csum>/0`. mkinitcpio needs an OSTree hook (dracut has one upstream; mkinitcpio doesn't yet have a first-class equivalent, though `mkinitcpio-ostree` exists as a community project).
3. **Package installation change.** Users who want to `pacman -S foo` get layered packages (Silverblue-style): every rebase replays the layer. Our choices:
    * (a) Force all apps to Flatpak / AppImage; pacman frozen at base image, no layering.
    * (b) Implement pacman-on-OSTree layering: `archw-ostree install` wraps `pacman -S` into an OSTree-aware transaction. This is real work (think 1000–2000 LOC).
4. **Trust kernel + DKMS.** DKMS builds against `/usr/src/linux-headers-*` — on OSTree, `/usr` is read-only at runtime, so DKMS runs at *image build time*, not at first boot. Every kernel update recomposes the OSTree image. This is cleaner than mutable Arch (no "DKMS failed on update" scenarios) but requires CI running our kernel build.
5. **AI daemon state.** `/var` must stay mutable (models, logs, configs). Silverblue convention: all of `/var` persists across rebases, `/etc` is 3-way-merged. Matches what we need for logs/ and /var/lib/ai-arch.

### Sketch of what the plan would look like (for later)

1. Session X: design doc + build an OSTree repo inside current pipeline; bake a test commit.
2. Session X+1: live-ISO "deploy from OSTree" install path; mkinitcpio + GRUB integration.
3. Session X+2: layered-pacman implementation; keep `pacman -S` working.
4. Session X+3: DKMS at image-build time; trust.ko shipped pre-built inside the tree.
5. Session X+4: rollout plan, A/B test matrix, rebase between channels.

**bootc alternative:** Instead of OSTree native, go **bootc** route (container image as OS). We'd author a `Containerfile` that `FROM archlinux:base`, adds our pkgs, and ships as `ghcr.io/fourzerofour/archimation:latest`. Users run `bootc switch ghcr.io/fourzerofour/archimation:latest` after a minimal bootc base is installed. Currently no *Arch* bootc base exists; Fedora/CentOS/Rocky do. Adding one is non-trivial but modern and aligns with the 2025 trajectory.

---

## 5. Filesystem matrix: when to recommend what

| Filesystem | Snapshots | CoW | Compression | Arch support | Mainline | Recommend for |
|---|---|---|---|---|---|---|
| **ext4** | No (only file-level `cp --reflink` via `-O orphan_file`) | No | No | 100% — default everywhere | Yes | **Disks <64 GB, old hardware, minimal install**. Simple, fast, robust, no metadata overhead. Falls back to timeshift-over-rsync for snapshots (file-level, slow, space-expensive). |
| **BTRFS** | Yes, first-class | Yes | zstd:1–15 | 100% via `btrfs-progs` | Yes (mature as of 2024) | **Default for ARCHIMATION on disks ≥64 GB.** Real atomic snapshots, compressed by default (zstd:3 = 55% more write / 133% more read than uncompressed per [Phoronix 2025][phoronix-btrfs]), snap-pac integration. |
| **bcachefs** | Yes (nascent) | Yes | Yes | AUR `bcachefs-tools` | **REMOVED** from mainline in kernel 6.17 (Aug 2025), ships as DKMS only ([LWN 6.17 removal][lwn-bcachefs], [Phoronix][phoronix-bcachefs]) | **Do not use for ARCHIMATION in 2026.** DKMS-only means the filesystem driver must compile against every kernel update; kernel panic recovery becomes harder; root-on-bcachefs across kernel-ABI breaks is a bad time. Reconsider in ~2027 if upstream relationship stabilizes. |
| **ZFS** | Yes | Yes | lz4/zstd | AUR `zfs-dkms` | No (CDDL/GPL incompat, out-of-tree) | Server / NAS, not desktop. License friction, DKMS cost. Not recommended for Archimation. |
| **XFS** | `xfs_reflink` for files only; no subvolume snapshots | Reflinks only | No | 100% | Yes | Fast on large files, but no snapshot-of-a-tree concept. Not useful for our snapshot goal. |

### Takeaway

* **ext4 = default for "just works on a 32 GB SSD from 2014"**. No snapshots. Updates are non-atomic but pacman works. Post-S69 this is already solid.
* **BTRFS = default for "modern hardware with ≥64 GB"**. Snapshots, CoW, compression, the whole prize. This is the S72 upgrade path.
* **bcachefs = skip in 2026.** Out-of-mainline makes it a DKMS-maintenance burden for a filesystem that has to work to boot.
* **ZFS = skip for desktop.** Server niche, license friction.
* **XFS = skip for this use case.** No tree snapshots.

---

## 6. Integration into `ai-install-to-disk` (concrete plan for S72)

Current installer (`profile/airootfs/usr/bin/ai-install-to-disk`, ~422 lines, reviewed in prep for this report): creates GPT + 512 MiB EFI FAT32 + ext4 root, pacstraps base, genfstab, chroots to configure user/locale/bootloader, enables services. Works, clean, unambiguous.

### New flag

```
--fs <ext4|btrfs|auto>   Filesystem for root
                          auto = BTRFS if disk ≥64 GB, ext4 otherwise (default)
                          ext4 = classic layout
                          btrfs = flat Ubuntu-style subvolumes + snapper + grub-btrfs
```

### Installer additions (BTRFS path)

Around line 259 (`log "Creating filesystems"`):

```bash
case "$FS_CHOICE" in
    ext4)
        mkfs.ext4 -F -L Archimation -m 1 "$ROOT_PART"
        mount "$ROOT_PART" "$MOUNT"
        ;;
    btrfs)
        mkfs.btrfs -f -L Archimation "$ROOT_PART"
        mount -o compress=zstd:3,noatime "$ROOT_PART" "$MOUNT"
        for sv in @ @home @var @log @pkg @snapshots; do
            btrfs subvolume create "$MOUNT/$sv"
        done
        umount "$MOUNT"
        mount -o compress=zstd:3,noatime,subvol=@           "$ROOT_PART" "$MOUNT"
        mkdir -p "$MOUNT"/{home,var,var/log,var/cache/pacman/pkg,.snapshots}
        mount -o compress=zstd:3,noatime,subvol=@home        "$ROOT_PART" "$MOUNT/home"
        mount -o compress=zstd:3,noatime,subvol=@var         "$ROOT_PART" "$MOUNT/var"
        mount -o compress=zstd:3,noatime,subvol=@log         "$ROOT_PART" "$MOUNT/var/log"
        mount -o compress=zstd:3,noatime,subvol=@pkg         "$ROOT_PART" "$MOUNT/var/cache/pacman/pkg"
        mount -o compress=zstd:3,noatime,subvol=@snapshots   "$ROOT_PART" "$MOUNT/.snapshots"
        ;;
esac
```

### Extra pacstrap (BTRFS path)

Around line 276 (`BASE_PKGS="..."`):

```bash
if [ "$FS_CHOICE" = "btrfs" ]; then
    BASE_PKGS="$BASE_PKGS btrfs-progs snapper snap-pac grub-btrfs inotify-tools"
fi
```

### Extra chroot config (BTRFS path)

After genfstab, before services-enable:

```bash
if [ "$FS_CHOICE" = "btrfs" ]; then
    log "Configuring snapper + snap-pac + grub-btrfs"
    arch-chroot "$MOUNT" bash -c '
        # Snapper config for /
        umount /.snapshots 2>/dev/null || true
        rm -rf /.snapshots
        snapper -c root create-config /
        btrfs subvolume delete /.snapshots
        mkdir -p /.snapshots
        mount -a
        chmod 750 /.snapshots
        chown :wheel /.snapshots

        # Limit snapshot retention
        sed -i "s/^TIMELINE_LIMIT_HOURLY=.*/TIMELINE_LIMIT_HOURLY=\"5\"/"   /etc/snapper/configs/root
        sed -i "s/^TIMELINE_LIMIT_DAILY=.*/TIMELINE_LIMIT_DAILY=\"7\"/"     /etc/snapper/configs/root
        sed -i "s/^TIMELINE_LIMIT_WEEKLY=.*/TIMELINE_LIMIT_WEEKLY=\"2\"/"   /etc/snapper/configs/root
        sed -i "s/^TIMELINE_LIMIT_MONTHLY=.*/TIMELINE_LIMIT_MONTHLY=\"0\"/" /etc/snapper/configs/root
        sed -i "s/^NUMBER_LIMIT=.*/NUMBER_LIMIT=\"50\"/"                    /etc/snapper/configs/root

        # Enable timers + grub-btrfs daemon
        systemctl enable snapper-timeline.timer
        systemctl enable snapper-cleanup.timer
        systemctl enable grub-btrfsd.service
    '
fi
```

### Resulting final layout on BTRFS install

```
/dev/XXX2 (BTRFS)
├── @           → mounted at /
├── @home       → mounted at /home
├── @var        → mounted at /var           (not snapshotted on rollback)
├── @log        → mounted at /var/log       (not snapshotted on rollback)
├── @pkg        → mounted at /var/cache/pacman/pkg  (not snapshotted)
└── @snapshots  → mounted at /.snapshots    (snapper stash)
```

**Why the exclusions matter:** rolling back `/` to a previous snapshot shouldn't erase the last week of logs, the current user state, or the pacman package cache. The flat layout ensures `btrfs subvolume snapshot @` captures only root-system state.

### Installer flag validation matrix

| --fs | Disk size | Behavior |
|---|---|---|
| `ext4` | any | classic ext4 install, no snapshots |
| `btrfs` | any | BTRFS + snapper even on 16 GB (honor user intent) |
| `auto` (default) | ≥64 GB | BTRFS |
| `auto` (default) | <64 GB | ext4 |
| `auto` (default) | — with `--yes` | same rule, no prompt |

Prompt in interactive mode shows current auto-choice with (y/[n]) override.

---

## 7. Pre-/post-pacman hook design

**We don't need to write these.** `snap-pac` ships them. The hooks live at:

* `/usr/share/libalpm/hooks/50-bootbackup.hook` — backs up `/boot/vmlinuz-*` and `/boot/initramfs-*` before a kernel update.
* `/usr/share/libalpm/hooks/95-snap-pac-pre.hook` — creates pre-transaction snapper snapshot.
* `/usr/share/libalpm/hooks/05-snap-pac-post.hook` — creates post-transaction snapper snapshot + records pacman command in description.

**What we do need:** a tiny wrapper that surfaces rollback in the AI daemon. Handler: `system.rollback_last_update`.

```python
# ai-control/daemon/contusion_handlers.py (sketch)
async def handle_system_rollback_last_update(args):
    # List snapshots, find most recent pre-pacman, roll back to it.
    cp = await _exec(["snapper", "list", "--type", "pre-post", "--json"], timeout=5)
    if cp.returncode != 0:
        return {"success": False, "error": "snapper not available (ext4 install?)"}
    import json
    snaps = json.loads(cp.stdout)
    # pick most recent "pre" that has a matching "post"
    ...
    # snapper rollback <num>   — marks snapshot <num> as default, reboot to apply
    cp2 = await _exec(["snapper", "rollback", str(target_num)], timeout=30)
    return {
        "success": cp2.returncode == 0,
        "snapshot": target_num,
        "action_required": "reboot to apply",
    }
```

**NL phrases to route here** (to add to `contusion_dictionary.py` in S72):

* "roll back the last update"
* "undo the last pacman update"
* "restore the pre-update snapshot"
* "the last update broke something, go back"

---

## 8. Old-hardware vs new-hardware defaults

| Hardware class | Filesystem | Snapshot mechanism | Update atomicity |
|---|---|---|---|
| 32 GB SSD, <4 GB RAM, pre-2012 CPU | **ext4** | timeshift (rsync, file-level, opt-in) | None — pacman updates as today. S69's HTTPS+file://fallback is the safety net. |
| 64–128 GB SSD, ≥4 GB RAM, modern CPU | **BTRFS** | snapper + snap-pac + grub-btrfs (auto) | Pre-transaction snapshot + boot-into-snapshot rollback |
| 256+ GB NVMe, ≥8 GB RAM | **BTRFS** with zstd:3, retention bumped to 100 snapshots | same as above + weekly timeshift archive to secondary disk if present | Same, plus extra headroom for snapshot churn |

**Rationale for 64 GB cutoff:** BTRFS metadata overhead + a month of 50 snapshots of a 20 GB root uses ~25 GB realistic on a working dev desktop. Below 64 GB total, the safety margin evaporates. Above 64 GB, the "oh no I don't have space" mode is very hard to hit in normal use. (We can tune this — 48 GB is also defensible.)

**Fallback if BTRFS fails to mount:** GRUB's snapshot submenu is the last-resort recovery UI. If *that* fails, boot live ISO, `ai-recover` script mounts @snapshots read-only, writes the selected snapshot's contents back to @.

---

## 9. What we lose / what we keep by doing S72-only

### What we keep vs OSTree/bootc

* Full pacman ecosystem (AUR included) — no layering penalty.
* Arch rolling-release velocity — no waiting on image rebuilds.
* No CI pipeline change — packages are still PKGBUILDs, ISO is still mkarchiso.
* No trust-kernel / DKMS re-architecture.

### What we give up vs OSTree/bootc

* The OS is mutable between transactions (a rogue `rm -rf /usr/lib/whatever` won't auto-recover).
* Two Archimation installs of the same version can diverge over time (mirror timing, AUR states).
* No "rebase to a new channel" UX — no `archimation-stable` / `archimation-testing` / `archimation-nightly` rails.

These are exactly the gaps the **long-horizon OSTree/bootc track** would close. They're not S72.

---

## 10. Recommendation summary

1. **S72: ship BTRFS + snapper + snap-pac + grub-btrfs as an installer option.**
   * `--fs {ext4|btrfs|auto}` flag.
   * Auto = BTRFS on ≥64 GB disks, ext4 otherwise.
   * One new handler: `system.rollback_last_update` + ~10 NL phrases.
   * New PKGBUILD deps in `ai-install-to-disk`'s pacstrap path (`snapper`, `snap-pac`, `grub-btrfs`, `btrfs-progs`, `inotify-tools`).
   * Delivers: **"a bad update never bricks the machine"** as a first-class UX.
   * Estimated effort: 1 session. Estimated LOC: ~150 installer changes + ~80 handler + ~30 dictionary.

2. **Long-horizon (post-S80 or thereabouts): evaluate OSTree / bootc track.**
   * Either OSTree-native retrofit or bootc-container retrofit.
   * 5–10 sessions of work, build pipeline rewrite, DKMS moves to image-build time.
   * Only pursue if user demand for "rebase to channel" / "ship as OCI" materializes — otherwise the BTRFS path covers ~80% of value at ~5% of cost.

3. **Defer bcachefs entirely.** Mainline removal in 6.17/6.18 makes it a DKMS liability — poor fit for "the filesystem your root lives on".

---

## 11. Sources

* [Fedora Atomic Desktops — Silverblue/Kinoite][magazine]
* [What's new for Fedora Atomic Desktops in Fedora 42 (siosm.fr)][siosm]
* [Project Bluefin GitHub][bluefin]
* [Bluefin 2025 Wrap-up — State of the Raptor][bluefin-wrap]
* [bootc-dev GitHub][bootc-gh]
* [Red Hat — bootable containers and image mode][bootc-rh]
* [openSUSE/transactional-update][txn-update]
* [openSUSE MicroOS as a home-server OS (2025)][microos-orch]
* [NixOS Wikipedia][nixos-docs]
* [The Rise of Immutable Linux — NixOS guide (2026)][fosslinux]
* [SteamOS partition teardown][steamos-td]
* [SteamOS BTRFS converter][steamos-btrfs]
* [Collabora — SteamOS 3.6 atomic updates][collabora]
* [ChromeOS autoupdate design][chromium]
* [ArchWiki — Snapper][archwiki-snapper] (cited via search)
* [ArchWiki — Timeshift][timeshift]
* [ArchWiki — Btrfs][archwiki-btrfs] (cited via search)
* [wesbarnett/snap-pac][snap-pac]
* [snap-pac(8) Arch manpage][snap-pac-man]
* [Antynea/grub-btrfs][grub-btrfs]
* [9 of the best atomic/immutable Linux distros in 2025][lbos]
* [Rise of immutable distros 2025][techref]
* [Bcachefs removed from mainline (LWN)][lwn-bcachefs]
* [Linus removes bcachefs — Phoronix][phoronix-bcachefs]
* [Linux 6.15 BTRFS fast zstd — Phoronix][phoronix-btrfs]
* [Endless OS 6 review — The Register][reg-endless]
* [libostree docs][ostree-docs]

[magazine]: https://fedoramagazine.org/introducing-fedora-atomic-desktops/
[siosm]: https://planet.kde.org/siosms-blog-2025-04-14-whats-new-for-fedora-atomic-desktops-in-fedora-42/
[bluefin]: https://github.com/ublue-os/bluefin
[bluefin-wrap]: https://docs.projectbluefin.io/blog/bluefin-2025/
[bootc-gh]: https://github.com/bootc-dev/bootc
[bootc-rh]: https://developers.redhat.com/articles/2026/04/01/bootable-containers-reduce-friction-red-hat-enterprise-linux-image-mode
[txn-update]: https://github.com/openSUSE/transactional-update
[microos-orch]: https://orchestrator.dev/blog/2025-12-27-microos_sustainable_homeserver/
[nixos-docs]: https://en.wikipedia.org/wiki/NixOS
[fosslinux]: https://www.fosslinux.com/154635/mastering-nixos-immutable-linux.htm
[steamos-td]: https://github.com/randombk/steamos-teardown/blob/master/docs/partitions.md
[steamos-btrfs]: https://github.com/popsUlfr/steamos-btrfs
[collabora]: https://www.collabora.com/news-and-blog/news-and-events/steamos-3-6-how-the-steam-deck-atomic-updates-are-improving.html
[chromium]: https://www.chromium.org/chromium-os/chromiumos-design-docs/filesystem-autoupdate/
[archwiki-snapper]: https://wiki.archlinux.org/title/Snapper
[timeshift]: https://github.com/teejee2008/timeshift
[archwiki-btrfs]: https://wiki.archlinux.org/title/Btrfs
[snap-pac]: https://github.com/wesbarnett/snap-pac
[snap-pac-man]: https://man.archlinux.org/man/extra/snap-pac/snap-pac.8.en
[grub-btrfs]: https://github.com/Antynea/grub-btrfs
[lbos]: https://linuxbsdos.com/2025/05/04/9-atomic-or-immutable-linux-distributions/
[techref]: https://techrefreshing.com/the-rise-of-immutable-linux-distributions-in-2025/
[lwn-bcachefs]: https://lwn.net/Articles/1040120/
[phoronix-bcachefs]: https://www.phoronix.com/news/Bcachefs-Removed-Linux-6.18
[phoronix-btrfs]: https://www.phoronix.com/news/Linux-6.15-Btrfs
[reg-endless]: https://www.theregister.com/2024/05/31/endless_os_6/
[ostree-docs]: https://ostreedev.github.io/ostree/introduction/
