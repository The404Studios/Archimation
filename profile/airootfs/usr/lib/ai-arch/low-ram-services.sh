#!/bin/bash
# ai-arch/low-ram-services.sh -- mask memory-hungry services on small systems.
#
# Runs After=ai-hw-detect.service.  Consumes /run/ai-arch-hw-profile.  On an
# OLD profile this script switches off services that are nice-to-have but
# eat RAM/CPU the host needs for the desktop to be usable.  It is reversible:
# the mask points at /dev/null so removing the symlink restores the unit.
#
# Tiers (lowest-common-denominator -> most permissive):
#   OLD     -- aggressive mask list, saves ~50-100 MB RSS + 5-10 s boot
#   DEFAULT -- moderate mask list, saves ~20 MB RSS
#   NEW     -- unmask everything previously masked (idempotent restore)

set -u
set +e

PROFILE_FILE=/run/ai-arch-hw-profile
PROFILE=DEFAULT
MEM_MB=0

if [ -r "$PROFILE_FILE" ]; then
    # shellcheck disable=SC1090
    . "$PROFILE_FILE" || true
fi

# -- OLD tier --------------------------------------------------------------
# Heavy-handed masks for <=2 GB / pre-Kepler systems.  Every item here has
# been triaged: the user can re-enable via `systemctl unmask <unit>` if they
# truly need the feature.
OLD_MASK_LIST=(
    # --- AI Arch internal timers / nice-to-haves ---
    "ai-update-checker.timer"      # polls network every 6h
    "tlp-sleep.service"            # rfkill helper, oscillates on old laptops
    "systemd-boot-random-seed.service"  # fails on read-only ESP
    "ai-boot-chime.service"        # sox loads ~40 MB of codecs

    # --- Desktop bloat ---
    "bluetooth.service"            # ~20 MB RSS, rarely needed on old desktops
    "bluetooth.target"             # pulls in bluetooth via alias
    "flatpak-update.timer"
    "packagekit.service"           # background metadata refresh, 40 MB RSS
    "packagekit-offline-update.service"

    # --- Printing / color / zeroconf (none useful on a P4 desktop) ---
    "cups.service"
    "cups.socket"
    "cups.path"
    "cups-browsed.service"
    "org.cups.cupsd.service"
    "org.cups.cupsd.socket"
    "org.cups.cupsd.path"
    "avahi-daemon.service"
    "avahi-daemon.socket"
    "colord.service"
    "geoclue.service"

    # --- Laptop-only hardware managers (safe to mask on old HW that rarely
    # has cellular or smart-card readers) ---
    "ModemManager.service"
    "pcscd.service"
    "pcscd.socket"

    # --- Periodic timers that cost CPU on a crawling system ---
    "man-db.timer"                 # mandb regen, huge I/O storm
    "logrotate.timer"              # journal rotation covers our logging
    "shadow.timer"                 # /etc/shadow age-check, pointless on live ISO
    "archlinux-keyring-wkd-sync.timer"  # 10 MB Python, slow
    "paccache.timer"               # cache cleanup, no cache on ISO
    "btrfs-scrub.timer"            # no btrfs on live ISO
    "fstrim.timer"                 # rotational only; NEW tier re-enables

    # --- Duplicate network stacks (we use NetworkManager + iwd) ---
    "wpa_supplicant.service"       # NM drives iwd directly
    "dhcpcd.service"               # NM provides DHCP
    "systemd-networkd.service"     # conflicts with NM
    "systemd-networkd.socket"
    "systemd-networkd-wait-online.service"

    # --- Diagnostic / crash-report services ---
    "abrtd.service"
    "abrt-journal-core.service"
    "abrt-oops.service"
    "abrt-xorg.service"
    "systemd-coredump.socket"      # coredumps eat /var; small systems can't afford
)

# -- DEFAULT tier ----------------------------------------------------------
# Mid-range laptops / desktops.  Mask obvious live-ISO waste but keep
# printing/bluetooth optional so the user can toggle them.
DEFAULT_MASK_LIST=(
    # Printing: mask by default on live ISO, user can unmask on installed sys
    "cups.service"
    "cups.socket"
    "cups.path"
    "cups-browsed.service"
    # Periodic maintenance that has nothing to do on a live ISO
    "man-db.timer"
    "logrotate.timer"
    "shadow.timer"
    "archlinux-keyring-wkd-sync.timer"
    "paccache.timer"
    # Network duplicates
    "systemd-networkd.service"
    "systemd-networkd-wait-online.service"
    "wpa_supplicant.service"       # iwd handles WiFi; NM calls iwd, not wpa_s
    "dhcpcd.service"
    # Crash-report daemons (Arch default-off, but mask defensively)
    "abrtd.service"
)

# -- Tight (<=1 GB) add-on mask --------------------------------------------
TIGHT_MASK_LIST=(
    # Thumbnail pipeline costs ~30 MB + disk I/O on every file manager open
    "tumbler.service"
    "tumblerd.service"
    "gvfs-metadata.service"
    "gvfs-udisks2-volume-monitor.service"
    "gvfs-afc-volume-monitor.service"
    "gvfs-mtp-volume-monitor.service"
    "gvfs-goa-volume-monitor.service"
    "gvfs-gphoto2-volume-monitor.service"
    # Coredump socket (can consume unbounded disk)
    "systemd-coredump.socket"
    "systemd-coredump@.service"
    # File-indexers if anything pulled them in
    "tracker-miner-fs-3.service"
    "tracker-extract-3.service"
    # Geoclue -- location API, not needed headless
    "geoclue.service"
    # Xorg crash reporter
    "xorg-crash-reporter.service"
)

MASK_DIR=/etc/systemd/system
mkdir -p "$MASK_DIR"

mask_unit() {
    local u=$1
    # Only mask if unit file actually exists in the search path -- avoids
    # creating orphan /dev/null symlinks that confuse `systemctl status`.
    if systemctl cat "$u" &>/dev/null || [ -f "/usr/lib/systemd/system/$u" ]; then
        ln -sf /dev/null "$MASK_DIR/$u" 2>/dev/null || true
    fi
}

unmask_unit() {
    local u=$1
    if [ -L "$MASK_DIR/$u" ] && [ "$(readlink "$MASK_DIR/$u")" = "/dev/null" ]; then
        rm -f "$MASK_DIR/$u"
    fi
}

apply_journald_cap() {
    local sysmax=$1 runmax=$2
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/50-low-ram.conf <<JOURNAL
[Journal]
# Applied by ai-low-ram-services.sh; remove to restore defaults.
Storage=volatile
RuntimeMaxUse=${runmax}
SystemMaxUse=${sysmax}
ForwardToWall=no
ForwardToConsole=no
# Seal boot-time logs quickly so we don't hold RAM pages forever
MaxRetentionSec=1week
JOURNAL
}

case "$PROFILE" in
    OLD)
        for u in "${OLD_MASK_LIST[@]}"; do mask_unit "$u"; done
        if [ "${MEM_MB:-0}" -gt 0 ] && [ "$MEM_MB" -le 1024 ]; then
            for u in "${TIGHT_MASK_LIST[@]}"; do mask_unit "$u"; done
            apply_journald_cap 32M 8M
        else
            apply_journald_cap 64M 16M
        fi
        echo "ai-low-ram-services: OLD profile -> ${#OLD_MASK_LIST[@]} units masked (mem=${MEM_MB}MB)"
        ;;
    NEW)
        # Idempotent upgrade path: unmask anything we might have masked
        # previously.  Also drop the journald override so a NEW host can
        # use the full 500 MB rolling window from 50-boot-speed.conf.
        for u in "${OLD_MASK_LIST[@]}" "${DEFAULT_MASK_LIST[@]}" \
                 "${TIGHT_MASK_LIST[@]}"; do
            unmask_unit "$u"
        done
        rm -f /etc/systemd/journald.conf.d/50-low-ram.conf
        # NEW HW: ensure fstrim.timer is enabled (SSDs benefit from weekly TRIM)
        if [ -f /usr/lib/systemd/system/fstrim.timer ] && \
           [ ! -L /etc/systemd/system/timers.target.wants/fstrim.timer ]; then
            mkdir -p /etc/systemd/system/timers.target.wants
            ln -sf /usr/lib/systemd/system/fstrim.timer \
                /etc/systemd/system/timers.target.wants/fstrim.timer \
                2>/dev/null || true
        fi
        echo "ai-low-ram-services: NEW profile -> all services restored"
        ;;
    *)
        # DEFAULT tier: moderate mask list, modest journald cap
        for u in "${DEFAULT_MASK_LIST[@]}"; do mask_unit "$u"; done
        apply_journald_cap 128M 32M
        echo "ai-low-ram-services: DEFAULT profile -> ${#DEFAULT_MASK_LIST[@]} units masked"
        ;;
esac

exit 0
