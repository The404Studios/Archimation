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

# PE-compat firewall - Windows-style firewall layer
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

echo "Service symlinks created successfully."
