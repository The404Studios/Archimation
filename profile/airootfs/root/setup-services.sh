#!/bin/bash
# setup-services.sh - Create systemd service symlinks for the live environment
#
# This script is executed during the archiso build process to enable
# services in the resulting ISO image. It creates the necessary symlinks
# in multi-user.target.wants so services start automatically at boot.

set -euo pipefail

WANTS_DIR="/etc/systemd/system/multi-user.target.wants"
GFX_WANTS="/etc/systemd/system/graphical.target.wants"
SYSINIT_WANTS="/etc/systemd/system/sysinit.target.wants"
mkdir -p "$WANTS_DIR" "$GFX_WANTS" "$SYSINIT_WANTS"

# AI Control Daemon - provides full system control via REST API
ln -sf /usr/lib/systemd/system/ai-control.service \
    "$WANTS_DIR/ai-control.service"

# AI hardware detector - classifies the host as OLD / NEW / DEFAULT and
# applies profile-specific tuning (CPU governor, I/O scheduler, swappiness,
# THP mode, nouveau legacy quirk).  Enabled in multi-user.target.wants via
# Before= ordering to run before display-manager and ai-control.
if [ -f /usr/lib/systemd/system/ai-hw-detect.service ]; then
    ln -sf /usr/lib/systemd/system/ai-hw-detect.service \
        "$WANTS_DIR/ai-hw-detect.service"
fi

# AI low-RAM service masker - runs After=ai-hw-detect and shuts off
# services that are luxuries on <=2 GB systems (boot chime, bluetooth,
# tumbler, etc.).  Idempotent: reverses itself on NEW profile upgrades.
if [ -f /usr/lib/systemd/system/ai-low-ram-services.service ]; then
    ln -sf /usr/lib/systemd/system/ai-low-ram-services.service \
        "$WANTS_DIR/ai-low-ram-services.service"
fi

# dbus - required for XFCE desktop session
# (dbus-broker is the default on Arch; fall back to classic dbus-daemon)
if [ -f /usr/lib/systemd/system/dbus-broker.service ]; then
    ln -sf /usr/lib/systemd/system/dbus-broker.service \
        "$WANTS_DIR/dbus-broker.service"
elif [ -f /usr/lib/systemd/system/dbus.service ]; then
    ln -sf /usr/lib/systemd/system/dbus.service \
        "$WANTS_DIR/dbus.service"
fi

# iwd - fast WiFi backend (used by NetworkManager instead of wpa_supplicant)
ln -sf /usr/lib/systemd/system/iwd.service \
    "$WANTS_DIR/iwd.service"

# NetworkManager - network connectivity
ln -sf /usr/lib/systemd/system/NetworkManager.service \
    "$WANTS_DIR/NetworkManager.service"

# LightDM - display manager for graphical login
# Enable in BOTH multi-user and graphical targets for maximum reliability
ln -sf /usr/lib/systemd/system/lightdm.service \
    "$WANTS_DIR/lightdm.service"
ln -sf /usr/lib/systemd/system/lightdm.service \
    "$GFX_WANTS/lightdm.service"

# display-manager.service alias — graphical.target.wants pulls this in.
# 'systemctl enable lightdm' normally creates this, but we can't run
# systemctl inside archiso chroot.  Create the alias manually.
ln -sf /usr/lib/systemd/system/lightdm.service \
    /etc/systemd/system/display-manager.service

# nftables - firewall backend
ln -sf /usr/lib/systemd/system/nftables.service \
    "$WANTS_DIR/nftables.service"

# PE-compat application slice - cgroup v2 parent for per-app firewall scopes.
# The firewall emits `socket cgroupv2 level 2 "pe-compat.slice/<app>.scope"`
# predicates; without this slice the scope cgroups never get created and
# the rules never match.  The slice unit itself is a .slice so we enable
# it by symlink into multi-user.target.wants (systemctl can't run in the
# archiso chroot).  The unit file lives in /etc/systemd/system/ because
# it's shipped via the ISO profile, not a package.
if [ -f /etc/systemd/system/pe-compat.slice ]; then
    ln -sf /etc/systemd/system/pe-compat.slice \
        "$WANTS_DIR/pe-compat.slice"
fi

# Round 32: resource-orchestration slices.
# Each slice carries CPUWeight/MemoryHigh/IOWeight tuning; ai-hw-detect
# writes HW-tiered overrides at boot.  They must be active before the
# first service that references them via Slice= starts, hence
# multi-user.target.wants placement.
for unit in trust.slice ai-daemon.slice observer.slice game.slice; do
    if [ -f "/etc/systemd/system/$unit" ]; then
        ln -sf "/etc/systemd/system/$unit" "$WANTS_DIR/$unit"
    fi
done

# Session 68 (Agent G): PowerShell Core first-boot installer.  Gated on
# !/usr/bin/pwsh via ConditionPathExists in the unit, so this is a no-op
# once pwsh is on disk.  Required to flip tests/pe-loader/run_corpus.sh's
# powershell_hello.ps1 from SKIP → PASS on live ISO without baking an
# AUR dependency into pacstrap.
if [ -f /etc/systemd/system/ai-install-pwsh.service ]; then
    ln -sf /etc/systemd/system/ai-install-pwsh.service \
        "$WANTS_DIR/ai-install-pwsh.service"
fi

# Session 69 (Agent R): first-boot user/group reconciliation.  Idempotent
# oneshot that adds the default non-root user to trust + pe-compat + wheel
# + audio/video/input.  Ordered Before=ai-control.service so the daemon
# sees the final group layout when it chgrp's /run/pe-compat/events.sock.
if [ -f /etc/systemd/system/ai-setup-users.service ]; then
    ln -sf /etc/systemd/system/ai-setup-users.service \
        "$WANTS_DIR/ai-setup-users.service"
fi

# PE-compat firewall - Windows-style firewall layer
# After= pe-compat.slice so the slice directory exists before the firewall
# daemon starts moving PIDs into it.
ln -sf /usr/lib/systemd/system/pe-compat-firewall.service \
    "$WANTS_DIR/pe-compat-firewall.service"

# systemd-binfmt - register PE binary format via binfmt_misc
# Upstream WantedBy=sysinit.target — must run early so .exe binfmt is
# available before multi-user services that may exec PE binaries.
ln -sf /usr/lib/systemd/system/systemd-binfmt.service \
    "$SYSINIT_WANTS/systemd-binfmt.service"

# PE Object Broker daemon - must start before SCM and AI Cortex
# Note: use ln -sf (not systemctl enable) — systemctl doesn't work in archiso chroot
# Guard with existence checks — service files come from custom packages that
# may not be installed yet during early build stages.
if [ -f /usr/lib/systemd/system/pe-objectd.service ]; then
    ln -sf /usr/lib/systemd/system/pe-objectd.service \
        "$WANTS_DIR/pe-objectd.service"
fi

# AI Cortex - system orchestrator
if [ -f /usr/lib/systemd/system/ai-cortex.service ]; then
    ln -sf /usr/lib/systemd/system/ai-cortex.service \
        "$WANTS_DIR/ai-cortex.service"
fi

# SCM daemon - Windows Service Control Manager
if [ -f /usr/lib/systemd/system/scm-daemon.service ]; then
    ln -sf /usr/lib/systemd/system/scm-daemon.service \
        "$WANTS_DIR/scm-daemon.service"
fi

# DKMS first-boot — DISABLED on live ISO.
# DKMS module compilation takes 3+ minutes and blocks multi-user.target,
# preventing LightDM and the desktop from starting. Trust/pe-compat
# modules are optional on the live ISO. The disk installer enables
# dkms-first-boot on installed systems where it runs once at first boot.
# if [ -f /usr/lib/systemd/system/dkms-first-boot.service ]; then
#     ln -sf /usr/lib/systemd/system/dkms-first-boot.service \
#         "$SYSINIT_WANTS/dkms-first-boot.service"
# fi

# First-boot wizard — runs via XDG autostart in XFCE session, NOT as a
# systemd service (which hangs on graphical systems due to symlink detection).
# Users on headless systems can run: ai-first-boot-wizard --headless

# Bluetooth - required for laptop Bluetooth (ThinkPad, etc.)
ln -sf /usr/lib/systemd/system/bluetooth.service \
    "$WANTS_DIR/bluetooth.service"

# SSH daemon - use sshd.service (always-on TCP listener) for reliable access.
# sshd.socket (socket-activated) is fragile in VM testing: spawned instances
# can fail silently. sshd.service binds port 22 at startup unconditionally.
ln -sf /usr/lib/systemd/system/sshd.service \
    "$WANTS_DIR/sshd.service"

# --- Mask services that fail on live ISO / non-TPM hardware ---
# TPM2 setup services fail if no TPM chip is present or if tpm2-tss
# libraries are missing. Mask them to prevent boot errors.
MASK_DIR="/etc/systemd/system"
for svc in systemd-tpm2-setup-early.service systemd-tpm2-setup.service; do
    ln -sf /dev/null "$MASK_DIR/$svc"
done

# systemd-boot-random-seed fails because the ESP (ISO image) isn't writable.
# systemd-random-seed fails on live ISO because /var/lib/systemd may be on
# read-only squashfs early in boot before the overlay is mounted.
# We create an initial seed in customize_airootfs.sh instead.
ln -sf /dev/null "$MASK_DIR/systemd-boot-random-seed.service"
ln -sf /dev/null "$MASK_DIR/systemd-random-seed.service"

# systemd-boot-update also fails on non-systemd-boot systems
ln -sf /dev/null "$MASK_DIR/systemd-boot-update.service"

# --- PipeWire audio (systemd user units, enabled globally) ---
# PipeWire ships socket-activated user units.  Enable them globally so
# every user session gets audio without a manual .xprofile launch.
# `systemctl --global enable` creates symlinks under /etc/systemd/user/
# which is equivalent to per-user enable for all users.
USER_WANTS="/etc/systemd/user/default.target.wants"
SOCKETS_WANTS="/etc/systemd/user/sockets.target.wants"
mkdir -p "$USER_WANTS" "$SOCKETS_WANTS"

# Sockets go into sockets.target.wants (socket-activated) AND default.target
for unit in pipewire.socket pipewire-pulse.socket; do
    src="/usr/lib/systemd/user/$unit"
    if [ -f "$src" ]; then
        ln -sf "$src" "$SOCKETS_WANTS/$unit" 2>/dev/null || true
        ln -sf "$src" "$USER_WANTS/$unit" 2>/dev/null || true
    fi
done

# WirePlumber is a service (session manager), not a socket — only default.target
if [ -f /usr/lib/systemd/user/wireplumber.service ]; then
    ln -sf /usr/lib/systemd/user/wireplumber.service \
        "$USER_WANTS/wireplumber.service" 2>/dev/null || true
fi

# acpid - ACPI event handling (lid close, power button, etc.)
if [ -f /usr/lib/systemd/system/acpid.service ]; then
    ln -sf /usr/lib/systemd/system/acpid.service \
        "$WANTS_DIR/acpid.service"
fi

# TLP - laptop power management / battery optimization
if [ -f /usr/lib/systemd/system/tlp.service ]; then
    ln -sf /usr/lib/systemd/system/tlp.service \
        "$WANTS_DIR/tlp.service"
fi

# Mask power-profiles-daemon if present (conflicts with TLP)
if [ -f /usr/lib/systemd/system/power-profiles-daemon.service ]; then
    ln -sf /dev/null "$MASK_DIR/power-profiles-daemon.service"
fi

# fstrim.timer -- weekly TRIM for SSDs / NVMe.
# Do NOT enable on the live ISO: there's nothing to trim on a read-only
# squashfs.  low-ram-services.sh re-enables it on NEW-tier installs where
# the host has an SSD/NVMe and benefits from weekly TRIM.

# systemd-timesyncd -- network time, critical for HTTPS/TLS handshakes.
# Many of our services (ai-control, claude-code, etc.) will fail cert
# validation if the clock is far off.  Enable explicitly.
if [ -f /usr/lib/systemd/system/systemd-timesyncd.service ]; then
    ln -sf /usr/lib/systemd/system/systemd-timesyncd.service \
        "$SYSINIT_WANTS/systemd-timesyncd.service"
fi

# Mask boot-delay services that waste time on the live ISO.
# These are SAFE to mask unconditionally on the live ISO because the disk
# installer lays a fresh /etc over the user's root partition -- these
# symlinks don't propagate to installed systems (setup-services.sh writes
# into the airootfs, not the target of pacstrap).
#
# Categories:
#   A) cache-regeneration services (pointless on read-only squashfs)
#   B) periodic timers (nothing persistent to rotate on live ISO)
#   C) duplicate network stacks (NM + iwd are authoritative)
#   D) hibernate/suspend helpers (live ISO has no swap)
#   E) hwdb/udev-db regenerators (shipped pre-built in airootfs)
for unit in \
        man-db.service mandb.service man-db.timer \
        updatedb.service plocate-updatedb.service plocate-updatedb.timer \
        mlocate.timer locate.timer \
        systemd-hibernate-resume@.service systemd-hibernate.service \
        logrotate.service logrotate.timer \
        shadow.timer \
        fstrim.service \
        paccache.timer paccache-cleanup.timer \
        archlinux-keyring-wkd-sync.service archlinux-keyring-wkd-sync.timer \
        systemd-time-wait-sync.service \
        systemd-pstore.service \
        btrfs-scrub@.timer \
        abrtd.service abrt-journal-core.service abrt-oops.service abrt-xorg.service \
        systemd-update-done.service \
        systemd-journal-catalog-update.service \
        systemd-hwdb-update.service; do
    if [ -f "/usr/lib/systemd/system/$unit" ]; then
        ln -sf /dev/null "$MASK_DIR/$unit"
    fi
done

# --- Periodic systemd timers: fstrim is no-op on read-only squashfs.
#     tmpfiles-clean has nothing to clean on volatile tmpfs.  We re-enable
#     fstrim.timer on NEW HW via low-ram-services.sh.
for unit in \
        fstrim.timer \
        systemd-tmpfiles-clean.timer; do
    if [ -f "/usr/lib/systemd/system/$unit" ]; then
        ln -sf /dev/null "$MASK_DIR/$unit"
    fi
done

# --- Duplicate network stacks.  We use NetworkManager + iwd.
#     dhcpcd, wpa_supplicant, systemd-networkd all fight over rfkill /
#     netlink with NM and slow boot by 3-5 s each.
for unit in \
        dhcpcd.service \
        dhcpcd@.service \
        wpa_supplicant.service \
        wpa_supplicant@.service \
        wpa_supplicant-nl80211@.service \
        wpa_supplicant-wired@.service \
        systemd-networkd.service \
        systemd-networkd.socket \
        systemd-networkd-wait-online.service \
        systemd-resolved.service; do
    if [ -f "/usr/lib/systemd/system/$unit" ]; then
        ln -sf /dev/null "$MASK_DIR/$unit"
    fi
done

# --- Optional desktop daemons.  Safe to mask on live ISO; NEW-tier
#     installed systems can re-enable via systemctl unmask.  We do NOT
#     mask avahi here (some users rely on mDNS discovery at install time
#     for PXE / network mirrors).
for unit in \
        packagekit.service \
        packagekit-offline-update.service \
        colord.service \
        colord-sane.service \
        cups.service \
        cups.socket \
        cups.path \
        cups-browsed.service \
        org.cups.cupsd.service \
        org.cups.cupsd.socket \
        org.cups.cupsd.path; do
    if [ -f "/usr/lib/systemd/system/$unit" ]; then
        ln -sf /dev/null "$MASK_DIR/$unit"
    fi
done

# --- rpc/nfs client stack: not needed on a live ISO, pulled in
#     transitively by gvfs. ~15 MB RSS for rpcbind + rpc-statd. ---
for unit in \
        rpcbind.service \
        rpcbind.socket \
        rpc-statd.service \
        rpc-statd-notify.service \
        nfs-client.target; do
    if [ -f "/usr/lib/systemd/system/$unit" ]; then
        ln -sf /dev/null "$MASK_DIR/$unit"
    fi
done

# --- Virtualization stacks (dev-laptop extras).  None of them belong on
#     the live ISO; they cost 40-80 MB RSS each once running. ---
for unit in \
        docker.service \
        docker.socket \
        containerd.service \
        libvirtd.service \
        libvirtd.socket \
        podman.service \
        podman.socket \
        podman-auto-update.timer \
        snapd.service \
        snapd.socket; do
    if [ -f "/usr/lib/systemd/system/$unit" ]; then
        ln -sf /dev/null "$MASK_DIR/$unit"
    fi
done

# --- Legacy / redundant systemd helpers that we actively don't need.
#     systemd-binfmt is REQUIRED (binfmt_pe) -- do NOT mask.
#     systemd-vconsole-setup IS needed (sets font + keymap); keep. ---
for unit in \
        systemd-homed.service \
        systemd-userdbd.service \
        systemd-userdbd.socket \
        systemd-boot-update.service; do
    if [ -f "/usr/lib/systemd/system/$unit" ]; then
        ln -sf /dev/null "$MASK_DIR/$unit"
    fi
done

# --- Preserve the nowatchdog kernel param by masking the kernel watchdog
#     timer service (harmless if not present) ---
for unit in systemd-watchdog.service; do
    [ -f "/usr/lib/systemd/system/$unit" ] || continue
done

echo "Service symlinks created successfully."
