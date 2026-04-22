# S80 Revert Cookbook

S80 is commit `743ff32` — four bundled fixes that touched six files
(see `git show 743ff32 --stat`). If user's bricked boot is caused by one of
those four changes, we can bisect by reverting them one at a time and
rebuilding the ISO.

**Baseline (pre-S80):** commit `db68a50` (S79, known-good on user's prior ISO).

---

## Bisect plan — revert ONE change at a time

Try these in the order most-likely-to-be-the-cause first. After each
revert, rebuild and test before moving on to the next.

### 4a — Revert ONLY the Plymouth theme refactor
Most-suspected: the cached-images refactor of `archimation.script`.

```sh
git checkout db68a50 -- profile/airootfs/usr/share/plymouth/themes/archimation/archimation.script
git commit -m "S80 bisect: revert plymouth script to pre-S80 baseline"
bash scripts/build-iso.sh
```

### 4b — Revert ONLY the lightdm systemd drop-in
New file added in S80: `s80-preflight.conf`. If `ConditionPathExists=` is
firing incorrectly, lightdm refuses to start.

```sh
git rm profile/airootfs/etc/systemd/system/lightdm.service.d/s80-preflight.conf
git commit -m "S80 bisect: remove lightdm preflight drop-in"
bash scripts/build-iso.sh
```

### 4c — Revert ONLY the mkinitcpio change
S80 removed the `fsck` hook from HOOKS=. If your target machine has disk
resume / hibernation it may need fsck in initramfs.

```sh
git checkout db68a50 -- profile/airootfs/etc/mkinitcpio.conf
git commit -m "S80 bisect: restore fsck hook in mkinitcpio"
bash scripts/build-iso.sh
```

### 4d — Revert ONLY the ai-hw-detect service
S80 removed `Before=basic.target` to break an ordering cycle. If that
removal caused a different bug, restore the prior version.

```sh
git checkout db68a50 -- profile/airootfs/usr/lib/systemd/system/ai-hw-detect.service
git commit -m "S80 bisect: restore pre-S80 ai-hw-detect ordering"
bash scripts/build-iso.sh
```

### 4e — Revert ONLY the lightdm.conf debug-logging change
Minor — unlikely to cause a brick. Include for completeness.

```sh
git checkout db68a50 -- profile/airootfs/etc/lightdm/lightdm.conf
git commit -m "S80 bisect: restore pre-S80 lightdm.conf"
bash scripts/build-iso.sh
```

### 4f — Revert ONLY the customize_airootfs.sh change
Plymouth DeviceTimeout 5→8 + lightdm mode-restore loop.

```sh
git checkout db68a50 -- profile/airootfs/root/customize_airootfs.sh
git commit -m "S80 bisect: restore pre-S80 customize_airootfs"
bash scripts/build-iso.sh
```

---

## Nuclear option — revert EVERYTHING S80

If bisecting is too slow and the user just wants their machine back:

```sh
git revert 743ff32 --no-edit
bash scripts/build-iso.sh
```

This creates a fresh commit that un-does all six file changes from S80 in
one shot. The tree is then byte-for-byte equivalent to `db68a50` for those
six files (other commits between db68a50 and HEAD are preserved).

---

## Phase 4 — ship a minimal "safe ISO"

If the user asks for an `archimation-safe-YYYY.MM.DD.iso` — a hardened
variant that prioritizes boot-survivability over polish — the
edits below produce it. **DO NOT APPLY THESE NOW.** Listed for reference:

1. **Disable Plymouth entirely** — edit `profile/packages.x86_64` to remove
   `plymouth` and `plymouth-kcm`. Also remove the Plymouth theme files
   under `profile/airootfs/usr/share/plymouth/themes/archimation/`.

2. **Drop the lightdm preflight drop-in** — delete
   `profile/airootfs/etc/systemd/system/lightdm.service.d/s80-preflight.conf`.

3. **Restore fsck hook** — edit `profile/airootfs/etc/mkinitcpio.conf`
   HOOKS= to end in `... filesystems fsck` (matches pre-S80 / distro
   default for installed systems).

4. **Make "nomodeset" the default entry** — edit `profile/grub/grub.cfg`
   line 15 `set default="0"` → `set default="6"` (the "Safe Mode nomodeset"
   entry at line 95). Also edit `profile/syslinux/syslinux.cfg` line 5
   `DEFAULT arch` → `DEFAULT arch_nomodeset`.

5. **Bake it:**
   ```sh
   bash scripts/build-iso.sh
   mv output/archimation-*.iso output/archimation-safe-$(date +%Y.%m.%d).iso
   ```

The resulting ISO refuses to use modesetting, has no Plymouth, and boots
straight to text console → safest possible config on unknown hardware.

---

## Operator communication template (10 lines)

```
Your machine isn't bricked — the S80 ISO has a real-hardware boot bug, but
the USB stick also ships 8 backup boot entries. At the GRUB menu that
appears for 2 seconds on boot, press any arrow key to stop the countdown.
Then pick entry 7 "Safe Mode (nomodeset, no splash)" with arrows and
press Enter. That entry disables the splash and all GPU modesetting, so
it boots to a working console on almost any hardware.

If that works, you're up. If not, try entry 6 "Boot (no splash)" — it
keeps GPU drivers on but disables Plymouth (the animation that's most
likely broken). If THAT fails too, we'll re-flash the S79 ISO. Send me
the journal output from whichever entry got furthest (docs/RECOVERY.md §3).
```
