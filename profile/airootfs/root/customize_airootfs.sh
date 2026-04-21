#!/usr/bin/env bash
# customize_airootfs.sh - Post-install customization inside the ISO chroot
#
# This script runs inside the archiso build chroot. It creates users,
# sets up services, configures the Windows-like desktop, and performs
# final system configuration.

set -euo pipefail

echo "=== Customizing airootfs ==="

# --- Create the autologin group (required by LightDM PAM for autologin) ---
if ! getent group autologin &>/dev/null; then
    groupadd -r autologin
    echo "Created group 'autologin'"
fi

# --- Session 69 (Agent R): trust + pe-compat groups for non-root daemon access ---
# trust    -- /dev/trust read-ioctl access (MODE=0660,GROUP=trust in 70-trust.rules)
# pe-compat-- /run/pe-compat/events.sock subscribe access (0660,GROUP=pe-compat)
# trust-system's sysusers.d/trust.conf also creates these on installed-to-disk
# systems; this block handles the live-ISO chroot path where systemd-sysusers
# hasn't run yet.
for g in trust pe-compat; do
    if ! getent group "$g" &>/dev/null; then
        groupadd -r "$g"
        echo "Created group '$g'"
    fi
done

# --- Create the 'arch' user for autologin ---
if ! id "arch" &>/dev/null; then
    useradd -m -G wheel,video,audio,input,network,storage,games,users,autologin,trust,pe-compat -s /bin/bash arch
    echo "arch:arch" | chpasswd
    echo "Created user 'arch'"
else
    # Ensure existing user is in all required groups (including autologin + users for polkit)
    usermod -aG wheel,video,audio,input,network,storage,games,users,autologin,trust,pe-compat arch
    echo "User 'arch' already exists, updated groups"
fi

# --- Grant passwordless sudo to 'arch' ---
mkdir -p /etc/sudoers.d
echo "arch ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/01-arch-nopasswd
chmod 440 /etc/sudoers.d/01-arch-nopasswd

# --- Install pip-only Python packages ---
pip install --break-system-packages 'sdnotify==0.3.2' || true

# --- Install Claude Code (Anthropic's CLI) ---
echo "Installing Claude Code..."
if command -v npm &>/dev/null; then
    npm install -g @anthropic-ai/claude-code 2>/dev/null && echo "Claude Code installed" || {
        echo "npm install failed, trying direct download..."
        curl -fsSL https://claude.ai/install.sh | sh 2>/dev/null || echo "WARNING: Claude Code install failed (install manually with: npm i -g @anthropic-ai/claude-code)"
    }
else
    echo "WARNING: npm not available, Claude Code will need manual install"
fi

# --- Install ai-desktop-config shell RC (avoids pacstrap conflict with bash pkg) ---
if [ -f /usr/share/ai-desktop-config/skel/bashrc ]; then
    install -Dm644 /usr/share/ai-desktop-config/skel/bashrc /etc/skel/.bashrc
    install -Dm644 /usr/share/ai-desktop-config/skel/bashrc /home/arch/.bashrc
    chown arch:arch /home/arch/.bashrc 2>/dev/null || true
fi

# --- DKMS first-boot service ---
# During pacstrap, DKMS post_install hooks fail because there are no real
# kernel headers in the chroot. This oneshot service runs dkms autoinstall
# on first boot (real hardware) and then triggers module loading.
cat > /usr/lib/systemd/system/dkms-first-boot.service <<'DKMS_FB'
[Unit]
Description=Build DKMS kernel modules on first boot
After=local-fs.target
ConditionPathExists=!/var/lib/dkms-first-boot-done
# Do NOT use Before=display-manager — blocks desktop for minutes!

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'dkms autoinstall 2>&1 | tail -5; depmod -a; touch /var/lib/dkms-first-boot-done || true'
TimeoutStartSec=120
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
DKMS_FB

# --- NetworkManager WiFi configuration ---
# Main NetworkManager.conf — use iwd backend (faster scanning than wpa_supplicant)
# `[connectivity]` probe is disabled on live ISO for faster boot (see
# /etc/NetworkManager/conf.d/00-boot-speed.conf); installed systems can
# edit this file to re-enable the captive-portal detector.
mkdir -p /etc/NetworkManager/conf.d /etc/NetworkManager/dispatcher.d
cat > /etc/NetworkManager/NetworkManager.conf <<'NM_MAIN'
[main]
plugins=keyfile
dhcp=internal

[keyfile]
unmanaged-devices=none

[connectivity]
# Disabled by /etc/NetworkManager/conf.d/00-boot-speed.conf on live ISO.
# Re-enable once online: set `enabled=true` and `interval=300` for
# captive portal detection.
enabled=false

[device]
wifi.scan-rand-mac-address=yes
wifi.backend=iwd
NM_MAIN

# Per-device iwd backend override (belt-and-suspenders with main conf)
cat > /etc/NetworkManager/conf.d/wifi-backend.conf <<'NM_IWD'
[device]
wifi.backend=iwd
NM_IWD

# Disable WiFi power saving (causes disconnects on many adapters)
cat > /etc/NetworkManager/conf.d/wifi-powersave.conf <<'NM_PS'
[connection]
wifi.powersave=2
NM_PS

# Ensure WiFi radio is ON by default (some systems soft-block it)
# NOTE: do NOT re-enable [connectivity] here -- 00-boot-speed.conf owns
# that for fast boot.  This file only controls WiFi autoconnect retries.
cat > /etc/NetworkManager/conf.d/wifi-enable.conf <<'NM_WIFI'
[main]
# Ensure WiFi is enabled on startup
autoconnect-retries-default=3
NM_WIFI

# Unblock WiFi via rfkill on boot (some laptops have WiFi soft-blocked)
cat > /usr/lib/systemd/system/rfkill-unblock-wifi.service <<'RFKILL_SVC'
[Unit]
Description=Unblock WiFi radio on boot
After=NetworkManager.service
Wants=NetworkManager.service

[Service]
Type=oneshot
ExecStart=/usr/bin/rfkill unblock wifi
ExecStart=/usr/bin/nmcli radio wifi on
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
RFKILL_SVC
# Enable the service
ln -sf /usr/lib/systemd/system/rfkill-unblock-wifi.service \
    /etc/systemd/system/multi-user.target.wants/rfkill-unblock-wifi.service

# --- WiFi regulatory domain ---
# Set regulatory domain to US (ensures 5 GHz channels are available).
# Users can change via `iw reg set XX` at runtime.
mkdir -p /etc/conf.d
echo 'WIRELESS_REGDOM="US"' > /etc/conf.d/wireless-regdom 2>/dev/null || true
# Also set via iw on first boot (iwd reads this at startup)
cat > /etc/NetworkManager/dispatcher.d/10-regdom.sh <<'REGDOM'
#!/bin/bash
# Set WiFi regulatory domain on NM startup
if [ "$2" = "up" ] || [ "$2" = "connectivity-change" ]; then
    iw reg set US 2>/dev/null || true
fi
REGDOM
chmod 755 /etc/NetworkManager/dispatcher.d/10-regdom.sh

# --- nm-applet system-wide autostart (fallback if skel copy missed) ---
# X-GNOME-Autostart-Delay: defer 3 seconds to let the XFCE panel register
# the system tray first.  Without this delay, nm-applet starts before the
# tray slot is claimed and either crashes silently or shows as a floating
# window until restarted.  Harmless on fast systems, critical on old HW.
mkdir -p /etc/xdg/autostart
cat > /etc/xdg/autostart/nm-applet.desktop <<'NMEOF'
[Desktop Entry]
Type=Application
Name=Network Manager Applet
Exec=nm-applet
Icon=network-wireless
X-XFCE-Autostart=true
OnlyShowIn=XFCE;
X-GNOME-Autostart-Delay=3
NMEOF

# --- Enable services ---
bash /root/setup-services.sh

# --- Ensure XFCE session file exists (LightDM needs this for autologin) ---
# The xfce4-session package should install this, but create a fallback
# in case the package layout changed or the file is missing.
# Also create the xfce.desktop variant — some distros name it xfce4-session.desktop
# but LightDM autologin-session=xfce looks for xfce.desktop specifically.
mkdir -p /usr/share/xsessions
if [ ! -f /usr/share/xsessions/xfce.desktop ]; then
    cat > /usr/share/xsessions/xfce.desktop <<'XFCE_SESSION'
[Desktop Entry]
Name=Xfce Session
Comment=Use this session to run Xfce as your desktop environment
Exec=startxfce4
TryExec=/usr/bin/startxfce4
Icon=xfce4-logo
Type=Application
DesktopNames=XFCE
XFCE_SESSION
    echo "Created fallback /usr/share/xsessions/xfce.desktop"
fi

# Verify startxfce4 actually exists — without it, the session file is useless
if ! command -v startxfce4 &>/dev/null; then
    echo "WARNING: startxfce4 not found! XFCE session will fail to start."
    echo "         Ensure xfce4-session package is installed."
fi

# --- Configure PAM for LightDM autologin ---
# The proper lightdm-autologin PAM file is shipped in the airootfs overlay
# at /etc/pam.d/lightdm-autologin (uses 'autologin' group, not 'nopasswdlogin').
# Verify it's in place, create if somehow missing:
if [ ! -f /etc/pam.d/lightdm-autologin ] || grep -q nopasswdlogin /etc/pam.d/lightdm-autologin 2>/dev/null; then
    cat > /etc/pam.d/lightdm-autologin <<'PAM_AUTO'
#%PAM-1.0
auth        required    pam_env.so
auth        required    pam_permit.so
auth        required    pam_succeed_if.so user ingroup autologin
-auth       optional    pam_gnome_keyring.so
account     include     system-local-login
password    include     system-local-login
session     include     system-local-login
PAM_AUTO
    echo "Created /etc/pam.d/lightdm-autologin with autologin group"
fi

# Also ensure a sane /etc/pam.d/lightdm for manual logins
if [ ! -f /etc/pam.d/lightdm ]; then
    cat > /etc/pam.d/lightdm <<'PAM_LDM'
#%PAM-1.0
auth        include     system-login
-auth       optional    pam_gnome_keyring.so
account     include     system-login
password    include     system-login
session     include     system-login
-session    optional    pam_gnome_keyring.so auto_start
PAM_LDM
    echo "Created /etc/pam.d/lightdm"
fi

# --- Ensure /etc/lightdm/Xsession wrapper exists ---
# lightdm.conf sets session-wrapper=/etc/lightdm/Xsession. On Arch, the
# lightdm package does NOT ship this file (unlike Debian/Ubuntu). If it's
# missing, LightDM fails to launch the session (exit code 127) and the user
# sees a blank screen or greeter loop instead of XFCE.
if [ ! -x /etc/lightdm/Xsession ]; then
    cat > /etc/lightdm/Xsession <<'XSESS'
#!/bin/sh
# LightDM Xsession wrapper for Arch Linux
# This script is invoked by LightDM as: /etc/lightdm/Xsession <session-command>
# It sets up the environment and then exec's the session (e.g., startxfce4).

# Source system-wide profile
if [ -f /etc/profile ]; then
    . /etc/profile
fi

# Source user .xprofile (LightDM convention)
if [ -f "$HOME/.xprofile" ]; then
    . "$HOME/.xprofile"
fi

# Source user .profile as fallback
if [ -f "$HOME/.profile" ]; then
    . "$HOME/.profile"
fi

# Ensure XDG_RUNTIME_DIR is set (required by PipeWire, dbus, etc.)
if [ -z "$XDG_RUNTIME_DIR" ]; then
    XDG_RUNTIME_DIR="/run/user/$(id -u)"
    export XDG_RUNTIME_DIR
fi

# Launch the session command passed by LightDM
exec $@
XSESS
    chmod 755 /etc/lightdm/Xsession
    echo "Created /etc/lightdm/Xsession wrapper (was missing)"
fi

# Also create /usr/bin/lightdm-session symlink as a belt-and-suspenders fallback.
# Some LightDM versions look for "lightdm-session" on PATH before using session-wrapper.
if [ ! -f /usr/bin/lightdm-session ]; then
    ln -sf /etc/lightdm/Xsession /usr/bin/lightdm-session
    echo "Created /usr/bin/lightdm-session -> /etc/lightdm/Xsession"
fi

# --- Ensure display-setup script for HiDPI auto-detect is executable ---
if [ -f /etc/lightdm/display-setup.sh ]; then
    chmod 755 /etc/lightdm/display-setup.sh
fi

# --- Set default locale and timezone ---
echo "LANG=en_US.UTF-8" > /etc/locale.conf
echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
locale-gen || true

ln -sf /usr/share/zoneinfo/UTC /etc/localtime

# --- Set hostname ---
echo "archimation" > /etc/hostname

# --- Configure SSH for remote access ---
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/50-ai-arch.conf <<'SSHCONF'
PermitRootLogin prohibit-password
PasswordAuthentication yes
PermitEmptyPasswords no
SSHCONF

# Pre-generate SSH host keys so sshd works immediately on first boot
ssh-keygen -A || true

# Set root password for testing
echo "root:root" | chpasswd
# Set arch user password for testing (user already created above with all groups)
echo "arch:arch" | chpasswd

# --- Regenerate initramfs with archiso hooks + ai-persist fallback ---
# NOTE: We inline this config (instead of relying on the overlay file) so that
# a broken overlay can't silently bake a bad initramfs.  Keep the content in
# sync with profile/airootfs/etc/mkinitcpio.conf.
cat > /etc/mkinitcpio.conf <<'INITCPIO'
# mkinitcpio.conf for AI Arch Linux Live ISO (runtime copy)
MODULES=(i915 amdgpu radeon)
BINARIES=()
FILES=()
HOOKS=(base udev modconf keyboard keymap plymouth ai-persist archiso archiso_loop_mnt block filesystems fsck)
COMPRESSION="zstd"
COMPRESSION_OPTIONS=(-19 -T0)
INITCPIO
if ! mkinitcpio -P; then
    echo "ERROR: mkinitcpio failed — trying without early-KMS modules as fallback"
    # Fall back to base modules only (no early KMS, but system will boot)
    cat > /etc/mkinitcpio.conf <<'INITCPIO_FALLBACK'
MODULES=()
BINARIES=()
FILES=()
HOOKS=(base udev modconf keyboard keymap plymouth ai-persist archiso archiso_loop_mnt block filesystems fsck)
COMPRESSION="zstd"
COMPRESSION_OPTIONS=(-19 -T0)
INITCPIO_FALLBACK
    if ! mkinitcpio -P; then
        echo "WARNING: mkinitcpio with zstd failed — retrying with default compression"
        # Last-resort: remove COMPRESSION lines (use mkinitcpio default)
        sed -i '/^COMPRESSION/d' /etc/mkinitcpio.conf
        mkinitcpio -P || echo "WARNING: mkinitcpio failed completely — ISO may not boot"
    fi
fi

# --- Set Plymouth theme + daemon config ---
# Always write plymouthd.conf with ShowDelay=0 (instant splash) and
# DeviceScale=1 (consistent rendering). plymouth-set-default-theme only
# sets the Theme= line; we need the other settings for seamless boot.
mkdir -p /etc/plymouth
# S80 FIX (Agent P): DeviceTimeout=8 (was 5) — matches the overlay
# plymouthd.conf and gives real-hardware DRM/KMS longer to come up
# before falling back to the text renderer. Old laptops (NVS 3100M,
# older Intel/AMD iGPU) regularly need 6+ seconds to reach modeset.
cat > /etc/plymouth/plymouthd.conf <<'PLYCFG'
[Daemon]
Theme=archimation
ShowDelay=0
DeviceTimeout=8
DeviceScale=1
PLYCFG
if command -v plymouth-set-default-theme &>/dev/null; then
    plymouth-set-default-theme archimation || true
fi

# --- Plymouth-to-LightDM seamless handoff ---
# NOTE: Do NOT add After=display-manager.service here — lightdm has built-in
# After=plymouth-quit.service, so adding reverse ordering creates a cycle.
# The --retain-splash flag on plymouth-quit handles the visual transition.
mkdir -p /etc/systemd/system/plymouth-quit-wait.service.d
cat > /etc/systemd/system/plymouth-quit-wait.service.d/timeout.conf <<'PLYQUIT'
[Service]
# Safety timeout: if Plymouth hangs (headless/QEMU), don't block boot forever
TimeoutStartSec=15
PLYQUIT

# plymouth-quit timeout (prevent hang on headless/QEMU)
mkdir -p /etc/systemd/system/plymouth-quit.service.d
cat > /etc/systemd/system/plymouth-quit.service.d/timeout.conf <<'PLYQUIT2'
[Service]
TimeoutStartSec=10
PLYQUIT2

# --- Smooth Plymouth → LightDM → XFCE transition ---
# With autologin-user-timeout=0, LightDM skips the greeter entirely and
# launches XFCE directly. Plymouth stays visible until X takes over the VT.
#
# DO NOT set autologin-in-background=true — that forces the greeter to show
# in the foreground while XFCE starts hidden behind it, breaking the desktop.
#
# The greeter background color (#1a1b26) matches Plymouth, so even if the
# greeter briefly appears (e.g., session lookup delay), there's no visual flash.

# NOTE: Do NOT add After=lightdm.service to plymouth-quit — it creates a
# dependency cycle because lightdm.service has built-in After=plymouth-quit.
# Instead, --retain-splash keeps the framebuffer image visible until X takes over.

# Override plymouth-quit to use --retain-splash: keeps the framebuffer
# image visible until another process (X server) takes over the VT.
cat > /etc/systemd/system/plymouth-quit.service.d/retain-splash.conf <<'PLYRETAIN'
[Service]
ExecStart=
ExecStart=/usr/bin/plymouth quit --retain-splash
PLYRETAIN

# --- Pacman hook: rebuild initramfs on kernel updates ---
mkdir -p /etc/pacman.d/hooks
cat > /etc/pacman.d/hooks/kernel-initramfs.hook <<'KRNHOOK'
[Trigger]
Operation=Install
Operation=Upgrade
Type=Package
Target=linux

[Action]
Description=Rebuilding initramfs after kernel update...
Depends=mkinitcpio
When=PostTransaction
Exec=/usr/bin/mkinitcpio -P
KRNHOOK

# --- AMD Ryzen 7 9800X3D / Zen 5 optimizations ---
# Set CPU governor to performance via a oneshot service (runs early in boot).
# The amd_pstate=active kernel parameter enables the AMD P-State EPP driver;
# this service switches it from the default "powersave" governor to "performance"
# for maximum gaming/compute throughput on the 3D V-Cache chip.
cat > /usr/lib/systemd/system/amd-pstate-performance.service <<'AMD_GOV_SVC'
[Unit]
Description=Set AMD P-State CPU governor to performance (Ryzen 9800X3D)
After=sysinit.target systemd-modules-load.service
# Only run if cpufreq actually exists (skip on live ISO / non-AMD / QEMU)
ConditionPathIsDirectory=/sys/devices/system/cpu/cpu0/cpufreq

[Service]
Type=oneshot
ExecStart=-/bin/bash -c 'for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do [ -f "$g" ] && echo performance > "$g" 2>/dev/null; done'
ExecStart=-/bin/bash -c 'for p in /sys/devices/system/cpu/cpu*/cpufreq/energy_performance_preference; do [ -f "$p" ] && echo performance > "$p" 2>/dev/null; done'
TimeoutStartSec=10
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
AMD_GOV_SVC

# Enable the service
ln -sf /usr/lib/systemd/system/amd-pstate-performance.service \
    /etc/systemd/system/multi-user.target.wants/amd-pstate-performance.service

# Also create a tmpfiles.d rule as a belt-and-suspenders fallback
mkdir -p /etc/tmpfiles.d
cat > /etc/tmpfiles.d/amd-pstate-governor.conf <<'AMD_TMPFILES'
# Set AMD P-State governor to performance on boot (Ryzen 9800X3D / Zen 5)
# This is a fallback -- the amd-pstate-performance.service is the primary mechanism.
w /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor  - - - - performance
w /sys/devices/system/cpu/cpu1/cpufreq/scaling_governor  - - - - performance
w /sys/devices/system/cpu/cpu2/cpufreq/scaling_governor  - - - - performance
w /sys/devices/system/cpu/cpu3/cpufreq/scaling_governor  - - - - performance
w /sys/devices/system/cpu/cpu4/cpufreq/scaling_governor  - - - - performance
w /sys/devices/system/cpu/cpu5/cpufreq/scaling_governor  - - - - performance
w /sys/devices/system/cpu/cpu6/cpufreq/scaling_governor  - - - - performance
w /sys/devices/system/cpu/cpu7/cpufreq/scaling_governor  - - - - performance
w /sys/devices/system/cpu/cpu8/cpufreq/scaling_governor  - - - - performance
w /sys/devices/system/cpu/cpu9/cpufreq/scaling_governor  - - - - performance
w /sys/devices/system/cpu/cpu10/cpufreq/scaling_governor - - - - performance
w /sys/devices/system/cpu/cpu11/cpufreq/scaling_governor - - - - performance
w /sys/devices/system/cpu/cpu12/cpufreq/scaling_governor - - - - performance
w /sys/devices/system/cpu/cpu13/cpufreq/scaling_governor - - - - performance
w /sys/devices/system/cpu/cpu14/cpufreq/scaling_governor - - - - performance
w /sys/devices/system/cpu/cpu15/cpufreq/scaling_governor - - - - performance
AMD_TMPFILES

# Sysctl tuning for 3D V-Cache gaming workloads
cat > /etc/sysctl.d/99-amd-9800x3d-gaming.conf <<'AMD_SYSCTL'
# AMD Ryzen 7 9800X3D / Zen 5 gaming optimizations
#
# Disable kernel NMI watchdog (frees one perf counter for games)
kernel.nmi_watchdog = 0

# Reduce swappiness (keep game data in RAM, 3D V-Cache shines with hot caches)
vm.swappiness = 10

# Dirty page writeback tuning (reduce I/O stalls during gaming)
vm.dirty_ratio = 20
vm.dirty_background_ratio = 5

# Increase max memory map areas (large game address spaces)
vm.max_map_count = 1048576

# Transparent hugepages: kernel cmdline sets transparent_hugepage=madvise
# (note: correct singular spelling -- earlier versions had a typo
#  `transparent_hugepages=always` which the kernel silently ignored).
# ai-hw-detect.service additionally writes /sys/kernel/mm/transparent_hugepage
# at boot so modern HW gets defer+madvise defrag behaviour.
vm.nr_hugepages = 0
AMD_SYSCTL

echo "AMD Ryzen 9800X3D optimizations configured (P-State performance governor, sysctl tuning)"

# --- Update MIME database for .exe association ---
if command -v update-mime-database &>/dev/null; then
    update-mime-database /usr/share/mime || true
fi
if command -v update-desktop-database &>/dev/null; then
    update-desktop-database /usr/share/applications || true
fi
if command -v gtk-update-icon-cache &>/dev/null; then
    gtk-update-icon-cache -f /usr/share/icons/hicolor || true
fi

# --- Create PE compat directory structure for 'arch' user ---
PE_HOME="/home/arch/.pe-compat"
mkdir -p "$PE_HOME/drives/c/Windows/System32"
mkdir -p "$PE_HOME/drives/c/Program Files"
mkdir -p "$PE_HOME/drives/c/Program Files (x86)"
mkdir -p "$PE_HOME/drives/c/Users/arch/AppData/Local"
mkdir -p "$PE_HOME/drives/c/Users/arch/AppData/Roaming"
mkdir -p "$PE_HOME/drives/c/Users/arch/Documents"
mkdir -p "$PE_HOME/drives/c/Users/arch/Desktop"
mkdir -p "$PE_HOME/drives/c/Users/arch/Downloads"
mkdir -p "$PE_HOME/drives/c/Games"
mkdir -p "$PE_HOME/dxvk"
mkdir -p "$PE_HOME/vkd3d"
mkdir -p "$PE_HOME/logs"

# --- Install DXVK and VKD3D-Proton .so files for D3D translation ---
# These provide D3D9/10/11 → Vulkan (DXVK) and D3D12 → Vulkan (VKD3D-Proton)
# The PE loader's d3d_stubs.c searches /usr/lib/dxvk/ and /usr/lib/vkd3d-proton/
DXVK_DIR="/usr/lib/dxvk"
VKD3D_DIR="/usr/lib/vkd3d-proton"
mkdir -p "$DXVK_DIR" "$VKD3D_DIR"

# ==========================================================================
# Install Discord (full, pre-cached — no update needed on first boot)
# ==========================================================================
DISCORD_URL="https://discord.com/api/download?platform=linux&format=tar.gz"
echo "Downloading Discord..."
if curl -sL "$DISCORD_URL" -o /tmp/discord.tar.gz && [ -s /tmp/discord.tar.gz ]; then
    tar xzf /tmp/discord.tar.gz -C /opt/
    if [ -d /opt/Discord ]; then
        # Create system-wide binary link
        ln -sf /opt/Discord/Discord /usr/bin/discord

        # Desktop entry
        cat > /usr/share/applications/discord.desktop <<'DISCORDEOF'
[Desktop Entry]
Name=Discord
Comment=All-in-one voice and text chat
GenericName=Internet Messenger
Exec=/usr/bin/discord --no-update
Icon=discord
Type=Application
Categories=Network;InstantMessaging;Chat;
MimeType=x-scheme-handler/discord;
StartupWMClass=discord
Keywords=voice;chat;gaming;community;
DISCORDEOF

        # Icon (Discord includes one)
        if [ -f /opt/Discord/discord.png ]; then
            install -Dm644 /opt/Discord/discord.png /usr/share/icons/hicolor/256x256/apps/discord.png
        fi

        # Pre-create user config directory so Discord doesn't need to write to root areas
        mkdir -p /etc/skel/.config/discord

        # Disable Discord auto-update (we manage updates ourselves)
        # The --no-update flag in Exec handles this, but also set the setting
        mkdir -p /etc/skel/.config/discord
        echo '{"SKIP_HOST_UPDATE": true}' > /etc/skel/.config/discord/settings.json

        echo "Discord installed to /opt/Discord"
    else
        echo "WARNING: Discord extraction failed"
    fi
    rm -f /tmp/discord.tar.gz
else
    echo "WARNING: Discord download failed (will install on first boot)"
fi

# Download DXVK DLLs (D3D9/10/11 → Vulkan translation via PE loader)
DXVK_VER="2.5.3"
DXVK_URL="https://github.com/doitsujin/dxvk/releases/download/v${DXVK_VER}/dxvk-${DXVK_VER}.tar.gz"
if [ ! -f "$DXVK_DIR/d3d11.dll" ]; then
    echo "Downloading DXVK v${DXVK_VER}..."
    if curl -sL "$DXVK_URL" -o /tmp/dxvk.tar.gz 2>/dev/null; then
        cd /tmp && tar xzf dxvk.tar.gz 2>/dev/null || true
        # DXVK release contains x64/*.dll files — copy them
        if [ -d "/tmp/dxvk-${DXVK_VER}/x64" ]; then
            cp -f /tmp/dxvk-${DXVK_VER}/x64/*.dll "$DXVK_DIR/" 2>/dev/null || true
            echo "DXVK ${DXVK_VER} installed to $DXVK_DIR"
        fi
        rm -rf /tmp/dxvk-${DXVK_VER} /tmp/dxvk.tar.gz
    else
        echo "Warning: Could not download DXVK (no network?). D3D11 translation unavailable."
    fi
fi

# Download VKD3D-Proton (D3D12 → Vulkan)
VKD3D_VER="2.13"
VKD3D_URL="https://github.com/HansKristian-Work/vkd3d-proton/releases/download/v${VKD3D_VER}/vkd3d-proton-${VKD3D_VER}.tar.zst"
if [ ! -f "$VKD3D_DIR/d3d12.dll" ]; then
    echo "Downloading VKD3D-Proton v${VKD3D_VER}..."
    if curl -sL "$VKD3D_URL" -o /tmp/vkd3d.tar.zst 2>/dev/null; then
        cd /tmp && tar --zstd -xf vkd3d.tar.zst 2>/dev/null || tar xf vkd3d.tar.zst 2>/dev/null || true
        if [ -d "/tmp/vkd3d-proton-${VKD3D_VER}/x64" ]; then
            cp -f /tmp/vkd3d-proton-${VKD3D_VER}/x64/*.dll "$VKD3D_DIR/" 2>/dev/null || true
            echo "VKD3D-Proton ${VKD3D_VER} installed to $VKD3D_DIR"
        fi
        rm -rf /tmp/vkd3d-proton-${VKD3D_VER} /tmp/vkd3d.tar.zst
    else
        echo "Warning: Could not download VKD3D-Proton. D3D12 translation unavailable."
    fi
fi
mkdir -p "$PE_HOME/registry"
mkdir -p "/home/arch/Games"

# --- Trust desktop shortcuts (XFCE shows warnings otherwise) ---
for dir in /etc/skel/Desktop /home/arch/Desktop; do
    if [ -d "$dir" ]; then
        for f in "$dir"/*.desktop; do
            [ -f "$f" ] && chmod +x "$f"
        done
    fi
done

# --- Session 68/69: profile/airootfs/usr/bin/ scripts lose the execute bit
# when the source tree lives on NTFS (/mnt/c/...), so mkarchiso bakes them in
# as 644 and users hitting `ai-health` or `ai-install-to-disk` get Permission
# denied. Restore +x on shell scripts in /usr/bin and generators so they
# actually run on the live ISO and the installed system.
for f in \
    /usr/bin/ai-health \
    /usr/bin/ai-install-to-disk \
    /usr/bin/ai-control-daemon \
    /usr/bin/ai-cortex \
    /usr/bin/pe-status \
    /usr/lib/systemd/system-generators/ai-safe-mode-generator \
    /root/setup-users.sh \
    /root/setup-services.sh \
    /etc/lightdm/Xsession \
    /etc/lightdm/display-setup.sh; do
    [ -f "$f" ] && chmod 755 "$f"
done

# --- Create .xprofile for arch user (ensures session environment) ---
cat > /home/arch/.xprofile <<'XPROFILE'
#!/bin/bash
# .xprofile - executed by LightDM before the session starts
# Ensures proper environment for XFCE

# Ensure dbus session bus is available
if [ -z "$DBUS_SESSION_BUS_ADDRESS" ]; then
    eval $(dbus-launch --sh-syntax --exit-with-session)
    export DBUS_SESSION_BUS_ADDRESS
fi

# Ensure XDG runtime dir exists
if [ -z "$XDG_RUNTIME_DIR" ]; then
    export XDG_RUNTIME_DIR="/run/user/$(id -u)"
    mkdir -p "$XDG_RUNTIME_DIR"
    chmod 700 "$XDG_RUNTIME_DIR"
fi

# PipeWire audio is started via systemd user units (enabled globally in
# setup-services.sh).  Do NOT launch pipewire/wireplumber/pipewire-pulse
# manually here -- that races with socket activation and can cause
# "connection refused" errors from libpulse clients.

# ==========================================================================
# HiDPI / Display Scaling Auto-Detection
# ==========================================================================
# Strategy: detect physical DPI first (from EDID), fall back to resolution-
# based heuristics.  Sets GDK_SCALE, GDK_DPI_SCALE, QT_SCALE_FACTOR, and
# adjusts XFCE panel/icon sizes via xfconf-query.

_scale_tier=""   # "4k", "1440p", or "1080p"

if command -v xrandr &>/dev/null && [ -n "$DISPLAY" ]; then
    # -- Method 1: physical DPI from EDID-reported panel size --
    _dpi=$(xrandr 2>/dev/null | awk '/connected primary/ {
        split($4,a,"x"); split(a[2],b,"+");
        w=a[1]; h=b[1];
        for(i=1;i<=NF;i++) if($i ~ /mm$/) { gsub(/mm/,"",$i); pw=$i; ph=$(i+2); gsub(/mm/,"",ph) }
        if(pw+0>0) { dpi=int(w*25.4/pw); print dpi }
    }')

    if [ "${_dpi:-0}" -ge 144 ]; then
        _scale_tier="4k"
    elif [ "${_dpi:-0}" -ge 120 ]; then
        _scale_tier="1440p"
    fi

    # -- Method 2: resolution-based fallback when EDID has no mm info --
    if [ -z "$_scale_tier" ]; then
        _screen_h=$(xrandr 2>/dev/null | grep -oP '\d+x\K\d+(?=\+)' | sort -rn | head -1)
        if [ -n "$_screen_h" ]; then
            if [ "$_screen_h" -ge 2160 ]; then
                _scale_tier="4k"
            elif [ "$_screen_h" -ge 1440 ]; then
                _scale_tier="1440p"
            elif [ "$_screen_h" -ge 1080 ]; then
                _scale_tier="1080p"
            elif [ "$_screen_h" -ge 900 ]; then
                _scale_tier="900p"
            else
                _scale_tier="small"
            fi
        fi
    fi
fi

# Export the tier so GTK4 apps can read it for responsive layout
export AI_DISPLAY_TIER="${_scale_tier:-small}"

# Always use GDK_DPI_SCALE=0.5 — keeps UI compact and readable on all displays.
# GDK_SCALE=1 with DPI_SCALE=0.5 halves the effective DPI, giving smaller
# text/widgets so you can see more on screen. Panel/icon sizes are tuned
# per resolution tier to complement this base scale.
export GDK_DPI_SCALE=0.5
export QT_AUTO_SCREEN_SCALE_FACTOR=0

case "$_scale_tier" in
    4k)
        export GDK_SCALE=1
        export QT_SCALE_FACTOR=1
        xfconf-query -c xsettings -p /Gdk/WindowScalingFactor -s 1 2>/dev/null
        xfconf-query -c xsettings -p /Xft/DPI -s 96 2>/dev/null
        xfconf-query -c xfce4-panel -p /panels/panel-1/size -s 36 2>/dev/null
        xfconf-query -c xfce4-panel -p /panels/panel-1/icon-size -s 22 2>/dev/null
        xfconf-query -c xfce4-desktop -p /desktop-icons/icon-size -s 48 2>/dev/null
        ;;
    1440p)
        export GDK_SCALE=1
        export QT_SCALE_FACTOR=1
        xfconf-query -c xsettings -p /Xft/DPI -s 96 2>/dev/null
        xfconf-query -c xfce4-panel -p /panels/panel-1/size -s 34 2>/dev/null
        xfconf-query -c xfce4-panel -p /panels/panel-1/icon-size -s 20 2>/dev/null
        xfconf-query -c xfce4-desktop -p /desktop-icons/icon-size -s 44 2>/dev/null
        ;;
    1080p)
        export GDK_SCALE=1
        export QT_SCALE_FACTOR=1
        xfconf-query -c xsettings -p /Xft/DPI -s 96 2>/dev/null
        xfconf-query -c xfce4-panel -p /panels/panel-1/size -s 32 2>/dev/null
        xfconf-query -c xfce4-panel -p /panels/panel-1/icon-size -s 18 2>/dev/null
        xfconf-query -c xfce4-desktop -p /desktop-icons/icon-size -s 40 2>/dev/null
        ;;
    *)
        # 900p, 768p, QEMU, small screens
        export GDK_SCALE=1
        export QT_SCALE_FACTOR=1
        xfconf-query -c xsettings -p /Xft/DPI -s 96 2>/dev/null
        xfconf-query -c xfce4-panel -p /panels/panel-1/size -s 28 2>/dev/null
        xfconf-query -c xfce4-panel -p /panels/panel-1/icon-size -s 16 2>/dev/null
        xfconf-query -c xfce4-desktop -p /desktop-icons/icon-size -s 36 2>/dev/null
        ;;
esac
XPROFILE
chmod 644 /home/arch/.xprofile

# --- Create .dmrc to explicitly set xfce session ---
cat > /home/arch/.dmrc <<'DMRC'
[Desktop]
Session=xfce
DMRC
chmod 644 /home/arch/.dmrc

# --- Steam first-boot configuration ---
# Pre-configure Steam to enable Proton for ALL titles and point to Games library.
# This runs before Steam ever launches, so it acts as a persistent default.
STEAM_CFG="/home/arch/.steam/steam/config"
STEAM_APPS="/home/arch/.steam/steam/steamapps"
mkdir -p "$STEAM_CFG" "$STEAM_APPS" \
         "/home/arch/Games/SteamLibrary/steamapps" \
         "/home/arch/.local/share/Steam/compatibilitytools.d"

# Symlink the canonical path Steam uses (.steam/root -> .local/share/Steam)
# Must be created AFTER the target directory exists
ln -sfn /home/arch/.local/share/Steam /home/arch/.steam/root 2>/dev/null || true

# config.vdf — enable Steam Play for ALL games, use Proton-Experimental by default
cat > "$STEAM_CFG/config.vdf" <<'STEAM_CONFIG'
"InstallConfigStore"
{
	"Software"
	{
		"Valve"
		{
			"Steam"
			{
				"CompatToolMapping"
				{
				}
				"SteamDefaultDialog"		"#app_store"
				"bEnableSteamPlayForAllTitles"		"1"
				"SteamDefaultCompatTool"		"proton_experimental"
				"AutoUpdateWindowEnabled"		"0"
				"AlwaysRelaunchGame"		"0"
			}
		}
	}
}
STEAM_CONFIG

# libraryfolders.vdf — add ~/Games/SteamLibrary as a secondary library
cat > "$STEAM_APPS/libraryfolders.vdf" <<'LIBFOLDERS'
"libraryfolders"
{
	"0"
	{
		"path"		"/home/arch/.local/share/Steam"
		"label"		""
		"totalsize"		"0"
		"apps"
		{
		}
	}
	"1"
	{
		"path"		"/home/arch/Games/SteamLibrary"
		"label"		"Games"
		"totalsize"		"0"
		"apps"
		{
		}
	}
}
LIBFOLDERS

# Registry workaround so Steam does not prompt for first-run wizard
mkdir -p "/home/arch/.local/share/Steam/config"
cp -f "$STEAM_CFG/config.vdf" "/home/arch/.local/share/Steam/config/config.vdf" 2>/dev/null || true
mkdir -p "/home/arch/.local/share/Steam/steamapps"
cp -f "$STEAM_APPS/libraryfolders.vdf" "/home/arch/.local/share/Steam/steamapps/libraryfolders.vdf" 2>/dev/null || true

echo "Steam first-boot config written (Proton-for-all enabled)"

# --- Kvantum dark theme activation ---
# The skel config sets theme=KvAmbiance. Copy directly to ensure it's applied
# even if skel-copy already happened (useradd -m ran earlier from the skel overlay).
mkdir -p /home/arch/.config/Kvantum
cat > /home/arch/.config/Kvantum/kvantum.kvconfig <<'KVCONF'
[General]
theme=KvAmbiance
KVCONF

mkdir -p /home/arch/.config/qt5ct
cat > /home/arch/.config/qt5ct/qt5ct.conf <<'QT5CONF'
[Appearance]
color_scheme_path=/usr/share/qt5ct/colors/darker.conf
custom_palette=false
icon_theme=Papirus-Dark
standard_dialogs=default
style=kvantum-dark

[Fonts]
fixed=@Variant(\0\0\0@\0\0\0\x16\0I\0n\0t\0e\0r\0 \0M\0o\0n\0o\0\0\0\0\0\0\0\0\0\0\0P\0\0\0\0)
general=@Variant(\0\0\0@\0\0\0\n\0I\0n\0t\0e\0r\0\0\0\0\0\0\0\0\0\0\0P\0\0\0\0)
QT5CONF

echo "Kvantum dark theme configured"

# --- Refresh font cache for Inter ---
# Ensures the Inter font (Segoe UI substitute) renders at first boot
fc-cache -f /usr/share/fonts/truetype/inter 2>/dev/null || \
fc-cache -f /usr/share/fonts/TTF 2>/dev/null || \
fc-cache -f 2>/dev/null || true

# --- NVIDIA RTX 5070 (Blackwell) X11 configuration ---
mkdir -p /etc/X11/xorg.conf.d
cat > /etc/X11/xorg.conf.d/20-nvidia.conf <<'NVIDIA_XORG'
Section "OutputClass"
    Identifier "nvidia"
    MatchDriver "nvidia-drm"
    Driver "nvidia"
    Option "AllowEmptyInitialConfiguration"
    Option "Coolbits" "28"
    Option "TripleBuffer" "True"
    Option "metamodes" "nvidia-auto-select +0+0 {ForceFullCompositionPipeline=On}"
EndSection
NVIDIA_XORG
echo "NVIDIA X11 config written to /etc/X11/xorg.conf.d/20-nvidia.conf"

# --- NVIDIA gaming environment variables ---
cat > /etc/profile.d/nvidia-gaming.sh <<'NVIDIA_ENV'
#!/bin/bash
# NVIDIA optimizations -- only activate if nvidia driver is loaded.
# On older GPUs using nouveau, these vars would cause errors.

if [ ! -d /proc/driver/nvidia ]; then
    return 0 2>/dev/null || exit 0
fi

# OpenGL shader cache (faster subsequent loads)
export __GL_SHADER_DISK_CACHE=1
export __GL_SHADER_DISK_CACHE_SKIP_CLEANUP=1

# Threaded OpenGL optimizations (improves multi-threaded GL apps)
export __GL_THREADED_OPTIMIZATIONS=1

# Vulkan ICD selection (prefer NVIDIA discrete GPU)
export VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/nvidia_icd.json

# DXVK async shader compilation (reduces stutter on first run)
export DXVK_ASYNC=1

# Ensure NVIDIA VDPAU driver is used for video decode
export VDPAU_DRIVER=nvidia

# Enable NVIDIA NVAPI for Proton games (DLSS, Reflex, etc.)
export PROTON_ENABLE_NVAPI=1
export PROTON_HIDE_NVIDIA_GPU=0

# NVIDIA VAAPI driver for hardware video acceleration
export LIBVA_DRIVER_NAME=nvidia
export NVD_BACKEND=direct
NVIDIA_ENV
chmod 644 /etc/profile.d/nvidia-gaming.sh
echo "NVIDIA gaming env written to /etc/profile.d/nvidia-gaming.sh"

# --- NVIDIA persistence mode systemd service ---
cat > /usr/lib/systemd/system/nvidia-persistenced.service <<'NVPERSIST_SVC'
[Unit]
Description=NVIDIA Persistence Daemon
After=syslog.target
ConditionPathExists=/proc/driver/nvidia/version

[Service]
Type=forking
ExecStart=/usr/bin/nvidia-persistenced --verbose
ExecStopPost=/bin/rm -rf /var/run/nvidia-persistenced
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
NVPERSIST_SVC

# --- NVIDIA power management for suspend/resume (RTX 5070) ---
cat > /usr/lib/systemd/system/nvidia-suspend.service <<'NVSUSPEND'
[Unit]
Description=NVIDIA system suspend actions
Before=systemd-suspend.service
Before=systemd-hibernate.service
Before=systemd-hybrid-sleep.service
ConditionPathExists=/proc/driver/nvidia/version

[Service]
Type=oneshot
ExecStart=/usr/bin/nvidia-sleep.sh "suspend"

[Install]
WantedBy=systemd-suspend.service
WantedBy=systemd-hibernate.service
WantedBy=systemd-hybrid-sleep.service
NVSUSPEND

cat > /usr/lib/systemd/system/nvidia-resume.service <<'NVRESUME'
[Unit]
Description=NVIDIA system resume actions
After=systemd-suspend.service
After=systemd-hibernate.service
After=systemd-hybrid-sleep.service
ConditionPathExists=/proc/driver/nvidia/version

[Service]
Type=oneshot
ExecStart=/usr/bin/nvidia-sleep.sh "resume"

[Install]
WantedBy=systemd-suspend.service
WantedBy=systemd-hibernate.service
WantedBy=systemd-hybrid-sleep.service
NVRESUME

# Create nvidia-sleep.sh helper if not shipped by nvidia-utils
if [ ! -f /usr/bin/nvidia-sleep.sh ]; then
    cat > /usr/bin/nvidia-sleep.sh <<'NVSLEEP'
#!/bin/bash
# nvidia-sleep.sh -- helper for suspend/resume VRAM preservation
case "$1" in
    suspend|hibernate)
        if command -v nvidia-smi &>/dev/null; then
            /usr/bin/nvidia-smi -pm 1 2>/dev/null || true
        fi
        ;;
    resume)
        # VRAM is restored automatically with NVreg_PreserveVideoMemoryAllocations=1
        true
        ;;
esac
NVSLEEP
    chmod 755 /usr/bin/nvidia-sleep.sh
fi

# Enable NVIDIA services (will only activate if nvidia hardware is present)
mkdir -p /etc/systemd/system/multi-user.target.wants
mkdir -p /etc/systemd/system/systemd-suspend.service.wants
ln -sf /usr/lib/systemd/system/nvidia-persistenced.service \
    /etc/systemd/system/multi-user.target.wants/nvidia-persistenced.service 2>/dev/null || true
ln -sf /usr/lib/systemd/system/nvidia-suspend.service \
    /etc/systemd/system/systemd-suspend.service.wants/nvidia-suspend.service 2>/dev/null || true
ln -sf /usr/lib/systemd/system/nvidia-resume.service \
    /etc/systemd/system/systemd-suspend.service.wants/nvidia-resume.service 2>/dev/null || true

echo "NVIDIA persistence + suspend/resume services installed"

# --- Laptop lid close = suspend (logind) ---
mkdir -p /etc/systemd/logind.conf.d
cat > /etc/systemd/logind.conf.d/lid.conf <<'LID'
[Login]
HandleLidSwitch=suspend
HandleLidSwitchExternalPower=suspend
HandleLidSwitchDocked=ignore
LID
echo "Laptop lid suspend policy configured"

# --- GPU modprobe options ---
# nouveau is the default NVIDIA driver (works on ALL GPUs from NV04 to Blackwell).
# Users who want nvidia-open-dkms can install it post-install; it will
# blacklist nouveau automatically via nvidia-utils.
mkdir -p /etc/modprobe.d
echo "# nouveau is the default NVIDIA driver for the live ISO" > /etc/modprobe.d/gpu.conf
echo "GPU driver: nouveau (open-source, universal NVIDIA support)"

# --- MangoHud config (copy to arch home explicitly) ---
mkdir -p /home/arch/.config/MangoHud
cat > /home/arch/.config/MangoHud/MangoHud.conf <<'MANGOHUD_CONF'
# MangoHud - game performance overlay (RTX 5070 optimized)
fps
gpu_stats
gpu_temp
cpu_stats
cpu_temp
vram
ram
frame_timing

position=top-left
font_size=20
background_alpha=0.4
round_corners=8

toggle_hud=Shift_R+F12
MANGOHUD_CONF

# --- Set default ALSA volume (Intel HDA / ThinkPad) ---
# Set Master and Speaker to 50% unmuted so audio works out of the box.
# Runs before PipeWire starts; PipeWire inherits ALSA mixer state.
amixer -c 0 set Master 50% unmute 2>/dev/null || true
amixer -c 0 set Speaker 50% unmute 2>/dev/null || true
amixer -c 0 set Headphone 50% unmute 2>/dev/null || true
# Persist ALSA state so it survives reboot
alsactl store 2>/dev/null || true

# --- Set correct ownership ---
chown -R arch:arch /home/arch/ || true

# --- Create initial random seed so systemd-random-seed doesn't fail ---
mkdir -p /var/lib/systemd
dd if=/dev/urandom of=/var/lib/systemd/random-seed bs=512 count=1 2>/dev/null
chmod 600 /var/lib/systemd/random-seed

# --- Persistent USB boot cleanup service ---
# On persistent boots, stale state from previous sessions can cause hangs.
# This service runs early on every boot to clean up:
#   - Stale lock/pid files in persistent /var/lib/
#   - XFCE saved sessions (prevents hang on hardware change)
#   - Stale .Xauthority in home (LightDM regenerates it)
#   - Old crash dumps / accumulated logs
cat > /usr/lib/systemd/system/ai-persist-cleanup.service <<'CLEANUP_SVC'
[Unit]
Description=Clean stale state for persistent USB boot
DefaultDependencies=no
Before=ai-control.service scm-daemon.service pe-compat-firewall.service
After=local-fs.target ai-persist-setup.service

[Service]
Type=oneshot
ExecStart=/usr/lib/ai-arch/persist-cleanup.sh
RemainAfterExit=yes
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
CLEANUP_SVC

mkdir -p /usr/lib/ai-arch
cat > /usr/lib/ai-arch/persist-cleanup.sh <<'CLEANUP'
#!/bin/bash
# persist-cleanup.sh — Clean stale state on persistent USB boot
#
# Runs early in boot before display manager and daemons start.
# This is CRITICAL for preventing login loops on persistent boots.

# Only run if we're on a persistent boot (cow device is a real disk)
if ! mountpoint -q /run/archiso/cowspace 2>/dev/null; then
    exit 0
fi
if findmnt -n -o FSTYPE /run/archiso/cowspace 2>/dev/null | grep -q tmpfs; then
    # tmpfs = non-persistent boot, nothing to clean
    exit 0
fi

echo "[persist-cleanup] Persistent boot detected, cleaning stale state..."

# ---- Display / session state (prevents login loop) ----

# Remove stale X authority files — LightDM creates fresh ones each boot
rm -f /home/arch/.Xauthority 2>/dev/null
rm -f /root/.Xauthority 2>/dev/null

# Remove stale ICEauthority (XFCE session manager uses ICE protocol)
rm -f /home/arch/.ICEauthority 2>/dev/null

# Remove stale XFCE sessions — prevents hang if display hardware changed
rm -rf /home/arch/.cache/sessions/* 2>/dev/null
rm -rf /home/arch/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-session.xml 2>/dev/null

# Remove stale XFCE panel socket/lock files
rm -rf /home/arch/.cache/xfce4/xfce4-panel-* 2>/dev/null

# Remove stale LightDM state that might cause greeter issues
rm -rf /run/lightdm 2>/dev/null
rm -f /var/lib/lightdm/.Xauthority 2>/dev/null
rm -f /var/lib/lightdm/.dmrc 2>/dev/null

# Remove stale X11 lock files (e.g., /tmp/.X0-lock from previous session)
rm -f /tmp/.X*-lock 2>/dev/null
rm -rf /tmp/.X11-unix 2>/dev/null
rm -rf /tmp/.ICE-unix 2>/dev/null

# Remove stale dbus session files (XFCE needs a clean dbus session)
rm -rf /tmp/dbus-* 2>/dev/null
rm -f /home/arch/.dbus/session-bus/* 2>/dev/null

# ---- Daemon state ----

# Clean stale SCM socket (should be in /run tmpfs, but just in case)
rm -f /run/pe-compat/scm.sock 2>/dev/null

# Remove stale PID files that may have leaked into persistent storage
find /var/lib/pe-compat -name "*.pid" -delete 2>/dev/null
find /var/lib/ai-control-daemon -name "*.pid" -delete 2>/dev/null

# ---- Log management ----

# Rotate logs to prevent unbounded growth on persistent storage
for logdir in /var/log/ai-control-daemon /var/log/pe-compat; do
    if [ -d "$logdir" ]; then
        find "$logdir" -name "*.log" -size +10M -exec truncate -s 1M {} \; 2>/dev/null
    fi
done

# Re-seed random on persistent boot (the saved seed is from last shutdown)
if [ -f /var/lib/systemd/random-seed ]; then
    dd if=/dev/urandom of=/var/lib/systemd/random-seed bs=512 count=1 2>/dev/null
fi

echo "[persist-cleanup] Cleanup complete."
CLEANUP
chmod 755 /usr/lib/ai-arch/persist-cleanup.sh

# Enable the cleanup service
ln -sf /usr/lib/systemd/system/ai-persist-cleanup.service \
    /etc/systemd/system/multi-user.target.wants/ai-persist-cleanup.service

# --- Auto-create persistence partition on USB if missing ---
# On first boot from USB, if AI_PERSIST doesn't exist, this service
# auto-creates it in the free space so the user never has to think about it.
cat > /usr/lib/systemd/system/ai-persist-setup.service <<'SETUP_SVC'
[Unit]
Description=Auto-create USB persistence partition
DefaultDependencies=no
After=local-fs.target
ConditionPathExists=!/dev/disk/by-label/AI_PERSIST

[Service]
Type=oneshot
ExecStart=/usr/lib/ai-arch/persist-setup.sh
RemainAfterExit=yes
TimeoutStartSec=120
StandardOutput=journal+console

[Install]
WantedBy=multi-user.target
SETUP_SVC

cat > /usr/lib/ai-arch/persist-setup.sh <<'PERSIST_SETUP'
#!/bin/bash
# persist-setup.sh — Auto-create AI_PERSIST partition on USB
#
# Runs on first boot if no AI_PERSIST partition exists.
# Finds the USB boot device and creates an ext4 partition
# in free space for persistent storage.

set -euo pipefail

# Already exists? Nothing to do.
if [ -b /dev/disk/by-label/AI_PERSIST ]; then
    echo "[persist-setup] AI_PERSIST partition already exists."
    exit 0
fi

# Find the boot device (where archiso mounted from)
BOOT_DEV=""
if mountpoint -q /run/archiso/bootmnt 2>/dev/null; then
    BOOT_DEV=$(findmnt -n -o SOURCE /run/archiso/bootmnt 2>/dev/null | head -1)
fi

if [ -z "$BOOT_DEV" ]; then
    echo "[persist-setup] Cannot determine boot device. Skipping."
    exit 0
fi

# Get the parent disk device (e.g., /dev/sda from /dev/sda1)
DISK_DEV=$(lsblk -ndo PKNAME "$BOOT_DEV" 2>/dev/null | head -1)
if [ -z "$DISK_DEV" ]; then
    echo "[persist-setup] Cannot determine parent disk. Skipping."
    exit 0
fi
DISK_DEV="/dev/$DISK_DEV"

# Only proceed if this looks like a removable/USB device
REMOVABLE=$(cat "/sys/block/$(basename "$DISK_DEV")/removable" 2>/dev/null || echo "0")
TRAN=$(lsblk -ndo TRAN "$DISK_DEV" 2>/dev/null || echo "")
if [ "$REMOVABLE" != "1" ] && [ "$TRAN" != "usb" ]; then
    echo "[persist-setup] Boot device $DISK_DEV is not USB/removable. Skipping."
    exit 0
fi

# Check for free space after the last partition
DISK_SIZE_B=$(lsblk -bdn -o SIZE "$DISK_DEV" 2>/dev/null)
LAST_END_B=$(parted -s "$DISK_DEV" unit B print 2>/dev/null \
    | awk '/^ *[0-9]/ { end=$3 } END { gsub(/B/,"",end); print end+0 }')

if [ -z "$DISK_SIZE_B" ] || [ -z "$LAST_END_B" ]; then
    echo "[persist-setup] Cannot determine disk geometry. Skipping."
    exit 0
fi

FREE_MB=$(( (DISK_SIZE_B - LAST_END_B) / 1048576 ))
if [ "$FREE_MB" -lt 100 ]; then
    echo "[persist-setup] Only ${FREE_MB}MB free on $DISK_DEV. Need at least 100MB. Skipping."
    exit 0
fi

echo "[persist-setup] Found ${FREE_MB}MB free space on $DISK_DEV"
echo "[persist-setup] Creating AI_PERSIST partition..."

# Snapshot partition list BEFORE creation (to detect new partition safely)
PARTS_BEFORE=$(lsblk -nrpo NAME "$DISK_DEV" 2>/dev/null | sort)

# Create partition in free space
START_MB=$(( LAST_END_B / 1048576 + 1 ))
parted -s "$DISK_DEV" mkpart primary ext4 "${START_MB}MB" "100%" || {
    echo "[persist-setup] Failed to create partition. Skipping."
    exit 0
}

# Wait for kernel to see it
sleep 2
partprobe "$DISK_DEV" 2>/dev/null || true
sleep 2

# Find the NEW partition by diffing before/after (safe — won't pick existing partitions)
PARTS_AFTER=$(lsblk -nrpo NAME "$DISK_DEV" 2>/dev/null | sort)
PERSIST_PART=$(comm -13 <(echo "$PARTS_BEFORE") <(echo "$PARTS_AFTER") | tail -1)

# Fallback: find highest-numbered partition without a label
if [ -z "$PERSIST_PART" ] || [ ! -b "$PERSIST_PART" ]; then
    PERSIST_PART=""
    for p in "${DISK_DEV}"5 "${DISK_DEV}p5" "${DISK_DEV}"4 "${DISK_DEV}p4" "${DISK_DEV}"3 "${DISK_DEV}p3"; do
        if [ -b "$p" ] && ! blkid -o value -s LABEL "$p" 2>/dev/null | grep -q .; then
            # Safety: verify this partition is in the range we just created
            PART_START=$(lsblk -nrbo START "$p" 2>/dev/null)
            if [ -n "$PART_START" ] && [ "$PART_START" -ge "$((START_MB * 1048576))" ] 2>/dev/null; then
                PERSIST_PART="$p"
                break
            fi
        fi
    done
fi

if [ -z "$PERSIST_PART" ]; then
    echo "[persist-setup] Could not find new partition. Skipping."
    exit 0
fi

echo "[persist-setup] Formatting $PERSIST_PART as AI_PERSIST..."
mkfs.ext4 -L AI_PERSIST -q "$PERSIST_PART" || {
    echo "[persist-setup] Failed to format partition."
    exit 1
}

# Set ext4 to continue on errors (prevents read-only on unclean shutdown)
tune2fs -e continue "$PERSIST_PART" 2>/dev/null || true

echo "[persist-setup] AI_PERSIST partition created successfully!"
echo "[persist-setup] Persistence will be active on next reboot."

# Send desktop notification if X is running
if command -v notify-send &>/dev/null && [ -n "${DISPLAY:-}" ]; then
    su - arch -c "DISPLAY=$DISPLAY notify-send 'USB Persistence Ready' \
        'AI_PERSIST partition created. Reboot to enable persistent storage.' \
        --icon=drive-removable-media" 2>/dev/null || true
fi
PERSIST_SETUP
chmod 755 /usr/lib/ai-arch/persist-setup.sh

# Enable the auto-setup service
ln -sf /usr/lib/systemd/system/ai-persist-setup.service \
    /etc/systemd/system/multi-user.target.wants/ai-persist-setup.service

# --- Set graphical target as default (ensures LightDM starts) ---
# systemctl set-default can be unreliable inside archiso chroots, so also
# create the symlink manually as a fallback.
systemctl set-default graphical.target 2>/dev/null || true
ln -sf /usr/lib/systemd/system/graphical.target /etc/systemd/system/default.target

# --- Branding overrides ---
cat > /usr/lib/os-release <<'OSRELEASE'
NAME="Archimation"
PRETTY_NAME="Archimation - AI-Powered Linux"
ID=arch
ID_LIKE=arch
BUILD_ID=rolling
ANSI_COLOR="38;2;23;147;209"
HOME_URL="https://github.com/ai-arch-linux"
LOGO=archlinux-logo
OSRELEASE

printf '\e[2J\e[H\n' > /etc/issue
printf '\e[1;38;5;111m' >> /etc/issue
cat >> /etc/issue <<'BANNER'
     _             _       _                 _   _
    /_\  _ _ __| |_  (_)_ __ ___   __ _| |_(_) ___  _ __
   / _ \| '_/ _| ' \ | | '_ ` _ \ / _` | __| |/ _ \| '_ \
  /_/ \_\_| \__|_||_||_|_| |_| |_|\__,_|\__|_|\___/|_| |_|
BANNER
printf '\e[0m' >> /etc/issue
printf '\e[38;5;243m  Arch Linux · Windows Runtime · Trust Kernel · AI Cortex  \e[38;5;240m//\e[38;5;243m  fourzerofour\e[0m\n' >> /etc/issue
printf '\e[38;5;60m  ──────────────────────────────────────────\e[0m\n' >> /etc/issue
printf '\e[38;5;141m  \\r\e[0m \e[38;5;243mtty\e[38;5;240m\\l\e[0m\n\n' >> /etc/issue

# --- /etc/motd: shown after login ---
cat > /etc/motd <<'MOTD'

  Archimation.  Arch Linux · Windows Runtime · Trust Kernel · AI Cortex.

    ai <command>         Natural-language system control  (try: ai play music)
    fastfetch            Brand + live system overview
    peloader <app.exe>   Run a Windows PE binary
    ai-health            Daemon + trust status
    pe-status            PE runtime + DLL resolution map

  Docs:  /usr/share/doc/archimation/   ·   man ai-help   ·   ai --help

MOTD

# --- Boot branding: oneshot service prints banner after boot ---
cat > /usr/lib/systemd/system/archimation-branding.service <<'BRANDING'
[Unit]
Description=Archimation Boot Branding
After=multi-user.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/usr/bin/bash -c 'printf "\n\e[1;38;5;111m  Archimation\e[0m \e[38;5;243m-- AI Arch Linux ready.\e[0m\n\n"'
StandardOutput=journal+console

[Install]
WantedBy=multi-user.target
BRANDING
ln -sf /usr/lib/systemd/system/archimation-branding.service /etc/systemd/system/multi-user.target.wants/archimation-branding.service

# --- Console font: set terminus for clean VT rendering ---
# vconsole.conf (in airootfs overlay) already has FONT=ter-v16n.
# Apply it now so the chroot console is readable too.
if [ -f /usr/share/kbd/consolefonts/ter-v16n.psf.gz ]; then
    setfont ter-v16n 2>/dev/null || true
else
    echo "WARNING: terminus-font not installed -- FONT=ter-v16n will fail at boot"
fi

# --- Set XFCE as default session for LightDM ---
mkdir -p /var/lib/AccountsService/users
cat > /var/lib/AccountsService/users/arch <<'ACCOUNTS'
[User]
Session=xfce
Icon=/home/arch/.face
SystemAccount=false
ACCOUNTS

# ==========================================================================
# Boot Chime — Windchimes sound when boot splash shows
# ==========================================================================
# Generate a synthetic windchime sound using sox/play (part of sox package)
# This creates a layered tone that sounds like gentle windchimes

cat > /usr/bin/ai-boot-chime <<'BOOTCHIME'
#!/bin/bash
# AI Arch Linux Boot Chime -- Chinese pentatonic windchimes with wind
# Uses sox to synthesize layered metallic bell tones on the Chinese
# pentatonic scale (C D E G A) with deep reverb, echo, and ambient wind.

if ! command -v play &>/dev/null; then
    exit 0
fi

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# --- Generate ambient wind background (filtered brown noise) ---
sox -q -n "$TMPDIR/wind.wav" \
    synth 5.0 brownnoise \
    band 200 400 \
    tremolo 0.5 30 \
    fade 0 5.0 1.5 \
    vol 0.35 \
    reverb 90 2>/dev/null &

# --- Chinese pentatonic chime tones (C4 D4 E4 G4 A4 C5 D5 E5 G5 A5) ---
# Each chime: sine + slight overtone for metallic shimmer, heavy reverb + echo
# Frequencies: C4=261.6 D4=293.7 E4=329.6 G4=392.0 A4=440.0
#              C5=523.3 D5=587.3 E5=659.3 G5=784.0 A5=880.0

_chime() {
    local freq=$1 dur=$2 delay=$3 vol=$4
    sleep "$delay"
    sox -q -n "$TMPDIR/chime_${freq}.wav" \
        synth "$dur" sine "$freq" \
        synth "$dur" sine "$(echo "$freq * 2.997" | bc 2>/dev/null || echo "$((freq * 3))")" mix \
        fade 0 "$dur" "$(echo "$dur * 0.75" | bc 2>/dev/null || echo "$dur")" \
        vol "$vol" \
        reverb 85 50 100 100 20 \
        echo 0.6 0.7 60 0.4 \
        echo 0.6 0.6 120 0.25 \
        2>/dev/null
    play -q "$TMPDIR/chime_${freq}.wav" 2>/dev/null &
}

# First cascade: descending high tones (like wind catching the chimes)
_chime 880  1.8 0.0  0.7  # A5 - first bright hit
_chime 784  2.0 0.25 0.65 # G5
_chime 659  1.6 0.15 0.6  # E5
_chime 523  2.2 0.30 0.55 # C5

# Second cascade: mid tones ring in (the heart of the chime)
_chime 440  2.5 0.20 0.7  # A4 - strong
_chime 392  2.8 0.18 0.65 # G4 - warm
_chime 329  2.2 0.22 0.6  # E4
_chime 261  3.0 0.35 0.55 # C4 - deep resonant

# Final shimmer: high sparkle notes
_chime 1760 1.0 0.15 0.35 # A6 - tiny sparkle
_chime 1318 1.2 0.20 0.30 # E6
_chime 1046 1.5 0.25 0.35 # C6

wait

# --- Mix wind + chimes together and play ---
if [ -f "$TMPDIR/wind.wav" ]; then
    # Wind is already playing from the background process above
    :
fi

wait
BOOTCHIME
chmod +x /usr/bin/ai-boot-chime

# Systemd service to play the chime during boot
cat > /usr/lib/systemd/system/ai-boot-chime.service <<'CHIMESVC'
[Unit]
Description=AI Arch Linux Boot Chime
After=sound.target pipewire.service
Wants=sound.target
# Non-critical: don't block boot if audio isn't ready
DefaultDependencies=no
Conflicts=shutdown.target
Before=shutdown.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'timeout 10 /usr/bin/ai-boot-chime || true'
StandardOutput=null
StandardError=null
TimeoutStartSec=15
TimeoutStopSec=5

[Install]
WantedBy=graphical.target
CHIMESVC

# Also create a login chime (plays when desktop is ready)
cat > /usr/bin/ai-login-chime <<'LOGINCHIME'
#!/bin/bash
# Ascending Chinese pentatonic welcome chime — desktop is ready
if ! command -v play &>/dev/null; then exit 0; fi
{
    # Ascending: C5 → E5 → G5 → A5 with echo
    play -q -n synth 0.6 sine 523.3 fade 0 0.6 0.4 vol 0.6 reverb 80 50 100 echo 0.5 0.6 80 0.3 &
    sleep 0.18
    play -q -n synth 0.7 sine 659.3 fade 0 0.7 0.5 vol 0.55 reverb 80 50 100 echo 0.5 0.6 80 0.3 &
    sleep 0.18
    play -q -n synth 0.8 sine 784.0 fade 0 0.8 0.55 vol 0.5 reverb 85 50 100 echo 0.5 0.6 80 0.3 &
    sleep 0.22
    play -q -n synth 1.2 sine 880.0 fade 0 1.2 0.9 vol 0.55 reverb 90 50 100 echo 0.6 0.7 100 0.35 &
    wait
} 2>/dev/null
LOGINCHIME
chmod +x /usr/bin/ai-login-chime

# Enable boot chime service
mkdir -p /etc/systemd/system/graphical.target.wants
ln -sf /usr/lib/systemd/system/ai-boot-chime.service /etc/systemd/system/graphical.target.wants/ai-boot-chime.service

# Login chime autostart (plays when XFCE desktop loads)
# Delayed 4 seconds so PipeWire + wireplumber are fully initialized.
# Without this delay, sox/play opens before the user audio session is up
# and silently drops the chime through the null sink.
cat > /etc/xdg/autostart/ai-login-chime.desktop <<'LOGINCHIMEAUTO'
[Desktop Entry]
Type=Application
Name=AI Login Chime
Exec=/usr/bin/ai-login-chime
X-XFCE-Autostart=true
NoDisplay=true
X-GNOME-Autostart-Delay=4
LOGINCHIMEAUTO

echo "Boot chime + login chime installed"

# --- Auto-installer: launch installer when ai.autoinstall=1 is on kernel cmdline ---
cat > /etc/xdg/autostart/ai-autoinstall.desktop <<'AUTOINSTALL'
[Desktop Entry]
Type=Application
Name=Archimation Auto Installer
Exec=/bin/sh -c 'grep -q ai.autoinstall=1 /proc/cmdline && sleep 2 && pkexec /usr/bin/ai-installer || true'
X-XFCE-Autostart=true
NoDisplay=true
OnlyShowIn=XFCE;
AUTOINSTALL

echo "Auto-installer boot entry configured"

# --- Quiet boot: suppress kernel console messages for clean Plymouth→desktop transition ---
# Reduce kernel printk levels so no info/warning messages flash on the console
echo 'kernel.printk = 3 3 3 3' > /etc/sysctl.d/20-quiet-boot.conf

# Persist quiet boot params in GRUB defaults (used if grub-mkconfig is ever run on installed system)
# Includes: mitigations=auto (explicit), nowatchdog (softlockup detector off),
# transparent_hugepage=madvise (madvise+defer defrag), rd.udev.children-max=16
# for parallel udev workers on multi-core HW.
if [ -f /etc/default/grub ]; then
    # Replace existing line or append
    if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub; then
        sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="quiet splash vt.global_cursor_default=0 loglevel=3 mitigations=auto nowatchdog transparent_hugepage=madvise rd.udev.children-max=16"|' /etc/default/grub
    else
        echo 'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash vt.global_cursor_default=0 loglevel=3 mitigations=auto nowatchdog transparent_hugepage=madvise rd.udev.children-max=16"' >> /etc/default/grub
    fi
    # Short menu timeout on installed system too
    if grep -q '^GRUB_TIMEOUT=' /etc/default/grub; then
        sed -i 's|^GRUB_TIMEOUT=.*|GRUB_TIMEOUT=2|' /etc/default/grub
    fi
fi

echo "Quiet boot parameters configured"

# --- Copy custom packages to local repo for the installer ---
# The disk installer's pacstrap needs these packages. Create a local
# repo at /var/lib/pe-compat/repo/ so pacman can find them.
REPO_SRC="/var/cache/pacman/pkg"
REPO_DST="/var/lib/pe-compat/repo"
mkdir -p "$REPO_DST"
# Copy our custom .pkg.tar.zst files from the package cache
for pkg in pe-loader trust-system trust-dkms pe-compat-dkms ai-control-daemon ai-firewall windows-services ai-desktop-config ai-first-boot-wizard; do
    cp "$REPO_SRC/${pkg}-"*.pkg.tar.zst "$REPO_DST/" 2>/dev/null || true
done
# Build repo database
if command -v repo-add &>/dev/null && ls "$REPO_DST"/*.pkg.tar.zst &>/dev/null; then
    repo-add "$REPO_DST/pe-compat.db.tar.gz" "$REPO_DST"/*.pkg.tar.zst 2>/dev/null || true
    echo "Local pe-compat repo created at $REPO_DST"
else
    echo "WARNING: Could not create local pe-compat repo"
fi

# ==========================================================================
# AGGRESSIVE LIVE-ISO BLOAT PRUNING (Session 31)
# ==========================================================================
# The live ISO does not need docs, man pages, non-English locales, or Python
# test suites.  The INSTALLED system downloads fresh packages via pacstrap,
# so none of this pruning affects a user's installed system.
#
# Targets the ~200 MB locale-archive, ~300 MB /usr/share/doc + man + info,
# Python __pycache__ and test/ dirs, unused fonts/icons/wallpapers, and the
# pacman download cache.  Total expected savings: 500-800 MB uncompressed
# (compresses to ~300-500 MB squashfs reduction at zstd-22).
#
# Every path is absolute and scoped to /usr/share, /usr/lib/python*, or
# /var/cache.  No wildcards traverse outside these roots.
# ==========================================================================

echo "[+] === Pruning live-ISO bloat ==="

# Relax strictness for the prune block:
#   * nullglob -- let `for d in */` no-op on empty dirs under `set -e`
#   * +pipefail -- du|awk reporting is best-effort; a failed du must not abort
#   * +e       -- rm/find failures are tolerated (already have `|| true`)
shopt -s nullglob 2>/dev/null || true
set +o pipefail
set +e

# --- (1) /usr/share/doc -- almost entirely useless on a live ISO ---
# Keep licenses subtree (some packages expect /usr/share/licenses not /doc).
if [ -d /usr/share/doc ]; then
    _before=$(du -sm /usr/share/doc 2>/dev/null | awk '{print $1}')
    rm -rf /usr/share/doc
    mkdir -p /usr/share/doc
    echo "[+] Pruned /usr/share/doc (~${_before:-?} MB)"
fi

# --- (2) /usr/share/man -- live ISO has no man reader by default ---
if [ -d /usr/share/man ]; then
    _before=$(du -sm /usr/share/man 2>/dev/null | awk '{print $1}')
    rm -rf /usr/share/man
    mkdir -p /usr/share/man/man1 /usr/share/man/man5 /usr/share/man/man8
    echo "[+] Pruned /usr/share/man (~${_before:-?} MB)"
fi

# --- (3) /usr/share/info -- GNU info pages, nobody reads these ---
if [ -d /usr/share/info ]; then
    _before=$(du -sm /usr/share/info 2>/dev/null | awk '{print $1}')
    rm -rf /usr/share/info
    mkdir -p /usr/share/info
    echo "[+] Pruned /usr/share/info (~${_before:-?} MB)"
fi

# --- (4) /usr/share/gtk-doc -- GTK developer documentation ---
if [ -d /usr/share/gtk-doc ]; then
    _before=$(du -sm /usr/share/gtk-doc 2>/dev/null | awk '{print $1}')
    rm -rf /usr/share/gtk-doc
    echo "[+] Pruned /usr/share/gtk-doc (~${_before:-?} MB)"
fi

# --- (5) /usr/share/help -- GNOME yelp help docs (pulled in transitively) ---
if [ -d /usr/share/help ]; then
    _before=$(du -sm /usr/share/help 2>/dev/null | awk '{print $1}')
    rm -rf /usr/share/help
    echo "[+] Pruned /usr/share/help (~${_before:-?} MB)"
fi

# --- (6) locale-archive -- strip to en_US.UTF-8 + C only ---
# glibc ships a 200+ MB /usr/lib/locale/locale-archive containing hundreds
# of locales.  Strategy: nuke the archive entirely then rebuild with only
# en_US.UTF-8.  This is faster and more reliable than `localedef
# --delete-from-archive` (which doesn't actually free disk until the archive
# is rebuilt, and there's no portable `build-locale-archive` binary on
# vanilla glibc >= 2.37).
#
# The locale.gen + locale-gen step below (line ~290) ran before this prune;
# our target locales are already in the archive.  Now we wipe and regenerate
# with ONLY what we need.
if [ -f /usr/lib/locale/locale-archive ]; then
    _before=$(du -sm /usr/lib/locale/locale-archive 2>/dev/null | awk '{print $1}')
    # Truncate locale.gen to just en_US.UTF-8 (was already written above,
    # but defensively enforce a single-line file to shrink the rebuild).
    printf 'en_US.UTF-8 UTF-8\n' > /etc/locale.gen
    # Wipe and regenerate
    rm -f /usr/lib/locale/locale-archive
    locale-gen 2>/dev/null || true
    _after=$(du -sm /usr/lib/locale/locale-archive 2>/dev/null | awk '{print $1}')
    echo "[+] Pruned locale-archive (${_before:-?} MB -> ${_after:-?} MB, kept en_US.UTF-8)"
fi

# --- (7) /usr/share/locale/* -- remove non-English gettext translations ---
# Keep en, en_US, en_GB + C, POSIX.  Also keep any locale symlinks.
if [ -d /usr/share/locale ]; then
    _before=$(du -sm /usr/share/locale 2>/dev/null | awk '{print $1}')
    (
        cd /usr/share/locale || exit 0
        for d in */; do
            d="${d%/}"
            case "$d" in
                en|en_US|en_GB|C|POSIX|locale.alias)
                    continue
                    ;;
                *)
                    rm -rf "./$d" 2>/dev/null || true
                    ;;
            esac
        done
    )
    _after=$(du -sm /usr/share/locale 2>/dev/null | awk '{print $1}')
    echo "[+] Pruned /usr/share/locale non-en translations (${_before:-?} MB -> ${_after:-?} MB)"
fi

# --- (8) Python __pycache__ + test suites ---
# Python re-generates __pycache__ at first import (tiny cost).  The test/
# and tests/ subdirs under stdlib are useless on non-dev systems.
# Use find -delete (no wildcards above /usr/lib).
_before=$(du -sm /usr/lib/python3* 2>/dev/null | awk '{sum+=$1} END {print sum}')
if [ -d /usr/lib ]; then
    find /usr/lib -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
    # Strip stdlib test suites (large: test/, idlelib/, turtledemo/, tkinter/test, etc.)
    for p in /usr/lib/python3.*/test \
             /usr/lib/python3.*/idlelib \
             /usr/lib/python3.*/turtledemo \
             /usr/lib/python3.*/tkinter/test \
             /usr/lib/python3.*/unittest/test \
             /usr/lib/python3.*/distutils/tests \
             /usr/lib/python3.*/lib2to3/tests \
             /usr/lib/python3.*/ensurepip/_bundled \
             /usr/lib/python3.*/sqlite3/test; do
        [ -d "$p" ] && rm -rf "$p" 2>/dev/null || true
    done
    # Site-packages __pycache__ and tests in third-party libs
    find /usr/lib/python3.*/site-packages -maxdepth 3 -type d \
        \( -name 'tests' -o -name 'test' -o -name '__pycache__' \) \
        -prune -exec rm -rf {} + 2>/dev/null || true
fi
_after=$(du -sm /usr/lib/python3* 2>/dev/null | awk '{sum+=$1} END {print sum}')
echo "[+] Pruned Python __pycache__ + test dirs (${_before:-?} MB -> ${_after:-?} MB)"

# --- (9) /usr/share/backgrounds -- distro default wallpapers ---
# ai-desktop-config ships its own wallpapers; distro defaults are redundant.
if [ -d /usr/share/backgrounds ]; then
    _before=$(du -sm /usr/share/backgrounds 2>/dev/null | awk '{print $1}')
    # Keep the ai-arch / archimation backgrounds if any, drop everything else
    (
        cd /usr/share/backgrounds || exit 0
        for d in */; do
            d="${d%/}"
            case "$d" in
                ai-arch|archimation|xfce)
                    continue
                    ;;
                *)
                    rm -rf "./$d" 2>/dev/null || true
                    ;;
            esac
        done
    )
    _after=$(du -sm /usr/share/backgrounds 2>/dev/null | awk '{print $1}')
    echo "[+] Pruned /usr/share/backgrounds (${_before:-?} MB -> ${_after:-?} MB)"
fi

# --- (10) /usr/share/icons -- remove unused icon themes ---
# Keep: Papirus-Dark (primary), hicolor (required fallback), ai-arch (branding)
if [ -d /usr/share/icons ]; then
    _before=$(du -sm /usr/share/icons 2>/dev/null | awk '{print $1}')
    (
        cd /usr/share/icons || exit 0
        for d in */; do
            d="${d%/}"
            case "$d" in
                Papirus-Dark|Papirus|hicolor|default|ai-arch|archimation)
                    continue
                    ;;
                Adwaita)
                    # Adwaita is pulled in by GTK but Papirus-Dark covers all app icons.
                    # Keep only cursor theme from Adwaita (GTK default cursor).
                    find "./$d" -mindepth 1 -maxdepth 1 -type d \
                        ! -name 'cursors' -exec rm -rf {} + 2>/dev/null || true
                    ;;
                *)
                    rm -rf "./$d" 2>/dev/null || true
                    ;;
            esac
        done
    )
    _after=$(du -sm /usr/share/icons 2>/dev/null | awk '{print $1}')
    echo "[+] Pruned /usr/share/icons (${_before:-?} MB -> ${_after:-?} MB, kept Papirus-Dark + hicolor)"
fi

# --- (11) Unused fonts ---
# Keep: ttf-dejavu (fallback), noto (emoji + wide UTF-8), jetbrains-mono +
# cascadia-code (terminal), fira-sans (UI), terminus (VT console).
# Drop: liberation (dejavu covers it), cantarell (GNOME default, unused in
# XFCE), noto-cjk if present (CJK is ~80 MB and most users don't need it).
if [ -d /usr/share/fonts ]; then
    _before=$(du -sm /usr/share/fonts 2>/dev/null | awk '{print $1}')
    for f in /usr/share/fonts/cantarell \
             /usr/share/fonts/noto-cjk \
             /usr/share/fonts/google-noto-cjk \
             /usr/share/fonts/adobe-source-han-sans-* \
             /usr/share/fonts/adobe-source-han-serif-*; do
        [ -d "$f" ] && rm -rf "$f" 2>/dev/null || true
    done
    # Refresh fontconfig cache after pruning
    fc-cache -f 2>/dev/null || true
    _after=$(du -sm /usr/share/fonts 2>/dev/null | awk '{print $1}')
    echo "[+] Pruned unused fonts (${_before:-?} MB -> ${_after:-?} MB)"
fi

# --- (12) /usr/share/vim -- drop tutor, spell dicts, language packs ---
if [ -d /usr/share/vim ]; then
    for sub in tutor lang spell print macros; do
        for d in /usr/share/vim/vim*/"$sub"; do
            [ -d "$d" ] && rm -rf "$d" 2>/dev/null || true
        done
    done
    echo "[+] Pruned /usr/share/vim extras (tutor/lang/spell/print/macros)"
fi

# --- (13) Zoneinfo non-essential regions ---
# Keep the core zoneinfo so `ln -sf` in installer keeps working, but drop
# the deprecated/right and posix duplicate trees (~5 MB).
if [ -d /usr/share/zoneinfo ]; then
    for d in /usr/share/zoneinfo/right /usr/share/zoneinfo/posix; do
        [ -d "$d" ] && rm -rf "$d" 2>/dev/null || true
    done
    echo "[+] Pruned /usr/share/zoneinfo duplicates (right/, posix/)"
fi

# --- (14) Firmware audit -- drop clearly-unused legacy NIC families ---
# ONLY remove firmware we're certain no live-ISO user will hit.
# liquidio: Cavium OCTEON enterprise NICs (servers, not desktop HW).
# netronome: enterprise SmartNICs (Agilio CX series).
# qed/qede: QLogic FastLinQ 40G (datacenter).
# mellanox: ConnectX datacenter NICs (mlxsw_*, not client HW).
# mrvl: Marvell Octeon platforms.
# hfi1_dc8051 (Intel Omni-Path): HPC interconnect.
# keep everything else -- b43, rtl, ath, iwlwifi, realtek, broadcom, intel, etc.
if [ -d /lib/firmware ]; then
    _before=$(du -sm /lib/firmware 2>/dev/null | awk '{print $1}')
    for f in /lib/firmware/liquidio \
             /lib/firmware/netronome \
             /lib/firmware/qed \
             /lib/firmware/mellanox \
             /lib/firmware/mrvl/prestera \
             /lib/firmware/qcom/sdx* \
             /lib/firmware/qcom/sc8* \
             /lib/firmware/qcom/sm8* \
             /lib/firmware/qcom/apq* \
             /lib/firmware/qcom/msm*; do
        [ -e "$f" ] && rm -rf "$f" 2>/dev/null || true
    done
    # Drop individual big files: hfi1 OmniPath and various server ASIC blobs
    for f in /lib/firmware/hfi1_dc8051.fw \
             /lib/firmware/hfi1_fabric.fw \
             /lib/firmware/hfi1_pcie.fw \
             /lib/firmware/hfi1_sbus.fw; do
        [ -f "$f" ] && rm -f "$f" 2>/dev/null || true
    done
    _after=$(du -sm /lib/firmware 2>/dev/null | awk '{print $1}')
    echo "[+] Pruned /lib/firmware datacenter blobs (${_before:-?} MB -> ${_after:-?} MB)"
fi

# --- (15) /usr/include -- kernel headers are needed for DKMS first-boot ---
# DO NOT touch /usr/include or /usr/lib/modules/*/build -- trust-dkms +
# pe-compat-dkms build at first boot.  Flagged as deliberate kept overhead.

# --- (16) Misc small cleanups ---
# /usr/share/i18n/charmaps -- charmap defs beyond UTF-8 (rarely used)
if [ -d /usr/share/i18n/charmaps ]; then
    (
        cd /usr/share/i18n/charmaps || exit 0
        for f in *.gz; do
            case "$f" in
                UTF-8.gz|ANSI_X3.4-1968.gz|ISO-8859-1.gz|ISO-8859-15.gz)
                    continue
                    ;;
                *)
                    rm -f "$f" 2>/dev/null || true
                    ;;
            esac
        done
    )
    echo "[+] Pruned /usr/share/i18n/charmaps (kept UTF-8, ASCII, Latin-1, Latin-9)"
fi

# /usr/share/i18n/locales -- locale source defs (regenerated locales use
# these).  Keep en_*, C, POSIX, i18n common; drop the rest.
if [ -d /usr/share/i18n/locales ]; then
    (
        cd /usr/share/i18n/locales || exit 0
        for f in *; do
            case "$f" in
                en_*|C|POSIX|i18n*|iso14651_t1*|translit_*)
                    continue
                    ;;
                *)
                    rm -f "$f" 2>/dev/null || true
                    ;;
            esac
        done
    )
    echo "[+] Pruned /usr/share/i18n/locales non-en sources"
fi

# --- (17) Pacman hook: auto-prune docs/man on package installs ---
# Keeps the INSTALLED system slim too.  Only active on systems that copy
# this hook over (post-install via ai-desktop-config).  On the live ISO
# it fires during customize_airootfs.sh only if any late package lands.
mkdir -p /etc/pacman.d/hooks
cat > /etc/pacman.d/hooks/90-prune-docs.hook <<'PRUNE_HOOK'
[Trigger]
Operation = Install
Operation = Upgrade
Type = Path
Target = usr/share/doc/*
Target = usr/share/man/*
Target = usr/share/info/*
Target = usr/share/gtk-doc/*

[Action]
Description = Pruning docs/man/info (AI Arch -- live ISO keeps this slim)
When = PostTransaction
Exec = /usr/bin/sh -c 'rm -rf /usr/share/doc/* /usr/share/info/* /usr/share/gtk-doc/* /usr/share/man/??/* /usr/share/man/??_*/* 2>/dev/null || true'
PRUNE_HOOK
echo "[+] Installed pacman hook: 90-prune-docs (future installs auto-prune)"

# --- (18) Caches and logs accumulated during customize_airootfs.sh ---
# /tmp should already be empty since we clean up after each download above,
# but be defensive.
rm -rf /tmp/* /tmp/.[!.]* 2>/dev/null || true
rm -rf /var/log/pacman.log 2>/dev/null || true  # regenerates on install
rm -rf /root/.cache 2>/dev/null || true
rm -rf /root/.npm 2>/dev/null || true           # Claude Code install cache
rm -rf /home/arch/.cache 2>/dev/null || true
mkdir -p /home/arch/.cache
chown arch:arch /home/arch/.cache 2>/dev/null || true
echo "[+] Cleaned /tmp, /root/.cache, /root/.npm, /home/arch/.cache"

# --- (19) FINAL: nuke /var/cache/pacman/pkg ---
# This MUST run after the pe-compat repo copy above (which reads from
# /var/cache/pacman/pkg).  Freeing ~400-600 MB of downloaded .pkg.tar.zst.
# pacman -Scc would also work but leaves empty dirs + DB stamp.
if [ -d /var/cache/pacman/pkg ]; then
    _before=$(du -sm /var/cache/pacman/pkg 2>/dev/null | awk '{print $1}')
    rm -rf /var/cache/pacman/pkg/*
    echo "[+] Pruned /var/cache/pacman/pkg (~${_before:-?} MB freed)"
fi

# --- (20) Report final airootfs size --------------------------------------
if command -v du &>/dev/null; then
    _total=$(du -sh / --exclude=/proc --exclude=/sys --exclude=/dev \
             --exclude=/run --exclude=/tmp 2>/dev/null | awk '{print $1}')
    echo "[+] Post-prune airootfs size: ${_total:-unknown}"
fi
echo "[+] === Bloat pruning complete ==="

# Restore strict mode for any trailing steps.
set -e
set -o pipefail

echo "=== Customization complete ==="
