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

# fstrim.timer -- weekly TRIM for SSDs / NVMe.  Ships in util-linux and is
# safe to enable unconditionally: the timer is a no-op on rotational media.
if [ -f /usr/lib/systemd/system/fstrim.timer ]; then
    ln -sf /usr/lib/systemd/system/fstrim.timer \
        "$WANTS_DIR/fstrim.timer"
fi

# systemd-timesyncd -- network time, critical for HTTPS/TLS handshakes.
# Many of our services (ai-control, claude-code, etc.) will fail cert
# validation if the clock is far off.  Enable explicitly.
if [ -f /usr/lib/systemd/system/systemd-timesyncd.service ]; then
    ln -sf /usr/lib/systemd/system/systemd-timesyncd.service \
        "$SYSINIT_WANTS/systemd-timesyncd.service"
fi

# Mask boot-delay services that waste time on the live ISO:
# - man-db.service (regenerates mandb cache at boot, 10-20 s on slow HDD)
# - updatedb.service (plocate, takes 30+ s on large roots)
# - pacman-keyring-refresh.timer (network call, fails on offline boots)
for unit in man-db.service updatedb.service mandb.service \
            systemd-hibernate-resume@.service; do
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
