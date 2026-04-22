# Recovery Guide — S80 ISO Boot Failures

Use this doc when the default S80 ISO boot entry ("AI Arch Linux - Boot (UEFI)"
or "Archimation - Boot (BIOS)") leaves your machine stuck: black screen,
garbled Plymouth, stuck at spinner, lightdm never appears, or the keyboard is
dead at graphical login.

The S80 ISO ships seven alternate boot entries. At least three of them bypass
the code paths most likely to have bricked your boot. **Try them in order
before re-flashing anything.**

---

## 1 — Symptom → next step

| Symptom | Next step |
|---|---|
| GRUB menu appears, default entry hangs at black screen | Try entry **"Safe Mode (nomodeset, no splash)"** (GRUB pos. 7) |
| Plymouth splash visibly flickers / tears / freezes | Try entry **"Boot (no splash)"** (GRUB pos. 6) |
| lightdm login screen never comes up, text console loops | Try entry **"Boot (safe mode - no AI daemon)"** (GRUB pos. 5) |
| Kernel panic, no systemd output | Try entry **"Debug with Serial Console (ttyS0)"** (GRUB pos. 9) on a machine with serial output — or photograph the panic screen |
| Keyboard dead at lightdm greeter | Switch to TTY2 with Ctrl+Alt+F2 and log in as `root` (no password on live ISO). If that fails, use Safe Mode entry |
| Nothing on the list works | Edit cmdline manually — see section 3 |
| No GRUB menu at all | Re-flash with the older S79 ISO (section 4) |

The exact menu order matches `profile/grub/grub.cfg:53-111`:

1. AI Arch Linux - Boot (UEFI)  *[default, the broken one]*
2. Boot with Persistence
3. Boot to RAM
4. Install Archimation to Disk
5. Boot (safe mode - no AI daemon)  *[disables ai-control + ai-cortex]*
6. Boot (no splash)  *[plymouth.enable=0, keeps everything else]*
7. Safe Mode (nomodeset, no splash)  *[nomodeset, all GPU drivers disabled]*
8. Debug (verbose, no splash)
9. Debug with Serial Console (ttyS0)

---

## 2 — Which alternate entries bypass which S80 bug?

S80 introduced four fixes (commit `743ff32`). If a fix itself caused the
brick, these alternates cover you:

| Suspected S80 bug | Entry that bypasses it |
|---|---|
| Plymouth script refactor (`archimation.script` cached-images) | Entries 6, 7, 8, 9 — all pass `plymouth.enable=0` |
| Lightdm `ConditionPathExists` drop-in fails | Entry 5 (`ai.mode=safe` masks ai-control but not lightdm — use entry 7 if lightdm is the culprit since nomodeset often falls back to text console) |
| `ai-hw-detect.service` still broken (ordering cycle) | Entry 5 masks ai-control/cortex; entry 7 (nomodeset) disables the GPU path that ai-hw-detect feeds |
| mkinitcpio `fsck` hook removed breaks disk resume | No entry bypasses mkinitcpio (it's baked into initramfs) — re-flash S79 |

**Recommended order to try:** Entry 6 → Entry 7 → Entry 5. If none work,
move to section 3.

---

## 3 — Manual cmdline edit at GRUB

If none of the pre-built entries work, edit the default entry's cmdline
directly:

1. At the GRUB menu, highlight "AI Arch Linux - Boot (UEFI)"
2. Press **`e`** (edits the entry in place, does NOT save)
3. Find the line starting with `linux /` (use arrow keys)
4. Move cursor to end of line, append:

   ```
    systemd.unit=emergency.target plymouth.enable=0 nomodeset
   ```

5. Press **`Ctrl-X`** or **`F10`** to boot

This drops you to a root shell (no password prompt) with:
- Plymouth OFF
- GPU modesetting OFF
- systemd halts before reaching multi-user / graphical targets

From that shell, capture what went wrong:

```sh
journalctl -b -u lightdm.service -u ai-hw-detect.service -u plymouth-start.service
journalctl -b -p err
systemctl --failed
```

Copy that output (photograph the screen or `journalctl -b > /tmp/log.txt`
then plug in a USB stick: `mount /dev/sdX1 /mnt && cp /tmp/log.txt /mnt/`).

---

## 4 — Re-flash a working older ISO

If S80 is unrecoverable and you need the machine back NOW:

1. On your build machine (Windows/WSL2), check for a prior ISO:
   ```sh
   ls -la output/*.iso output/*.iso.bak 2>/dev/null
   ```
   S79 was built at commit `db68a50` (see `git log --oneline`). If
   `output/*.iso.bak` exists, that is your working fallback.

2. If no `.iso.bak`, rebuild S79:
   ```sh
   git checkout db68a50
   bash scripts/build-iso.sh
   git checkout master        # return to current
   ```

3. Flash it to the same USB drive with your normal tool (Rufus / balenaEtcher
   / `dd`). This **erases** the S80 ISO from the stick.

---

## 5 — Making Plymouth-off permanent on the live USB

Live USB file systems are mounted read-only by the kernel at boot
(ISO9660/SquashFS). You cannot persist changes across reboots without
enabling the "Boot with Persistence" entry *before* the break.

**Workaround:** press `e` at GRUB every boot and append `plymouth.enable=0`
to the cmdline. It's tedious but takes <10 seconds per boot.

For a permanent fix, either:
- Install to disk (entry 4), then edit `/etc/default/grub` on the installed
  system and run `grub-mkconfig`, or
- Rebuild the ISO with plymouth disabled (see `docs/S80_REVERT.md`).
