#!/bin/bash
# ai-arch/low-ram-services.sh -- mask memory-hungry services on small systems.
#
# Runs After=ai-hw-detect.service.  Consumes /run/ai-arch-hw-profile.  On an
# OLD profile this script switches off services that are nice-to-have but
# eat RAM/CPU the host needs for the desktop to be usable.  It is reversible:
# the mask points at /dev/null so removing the symlink restores the unit.

set -u
set +e

PROFILE_FILE=/run/ai-arch-hw-profile
PROFILE=DEFAULT
MEM_MB=0

if [ -r "$PROFILE_FILE" ]; then
    # shellcheck disable=SC1090
    . "$PROFILE_FILE" || true
fi

# Services to mask on OLD profile (low memory, single-core CPUs).
OLD_MASK_LIST=(
    # Update checker timer -- polls network every 6h, wastes battery
    "ai-update-checker.timer"
    # TLP's rfkill helper -- sometimes oscillates on old laptops
    "tlp-sleep.service"
    # Boot random seed refresh -- skips on read-only ESP (already masked in
    # setup-services.sh but harmless to double-mask)
    "systemd-boot-random-seed.service"
    # Bluetooth: rarely needed on desktop P4 / NVS 3100M laptops, costs ~20 MB
    "bluetooth.service"
    # Boot chime: uses sox which loads ~40 MB of codecs
    "ai-boot-chime.service"
    # Flatpak metadata refresh timer (if installed)
    "flatpak-update.timer"
    # PackageKit refresh (if installed)
    "packagekit-offline-update.service"
)

# Additional mask: if under 1 GB, also drop Tumbler thumbnailer + gvfs-metadata
TIGHT_MASK_LIST=(
    "tumbler.service"
    "tumblerd.service"
    "gvfs-metadata.service"
    # CPU-stall detector that pins one core on old systems
    "systemd-coredump.socket"
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

if [ "$PROFILE" = "OLD" ]; then
    for u in "${OLD_MASK_LIST[@]}"; do
        mask_unit "$u"
    done
    if [ "${MEM_MB:-0}" -gt 0 ] && [ "$MEM_MB" -le 1024 ]; then
        for u in "${TIGHT_MASK_LIST[@]}"; do
            mask_unit "$u"
        done
        # Reduce journal size on tight systems so it doesn't consume /run
        mkdir -p /etc/systemd/journald.conf.d
        cat > /etc/systemd/journald.conf.d/50-low-ram.conf <<'JOURNAL'
[Journal]
# Runtime journal capped at 16 MB on <=1GB systems (default is 10% of /run).
RuntimeMaxUse=16M
SystemMaxUse=64M
# Disable forward-to-wall for low-mem boxes (spams console with every warn)
ForwardToWall=no
JOURNAL
    fi
    echo "ai-low-ram-services: OLD profile -> ${#OLD_MASK_LIST[@]} units masked"
elif [ "$PROFILE" = "NEW" ]; then
    # Unmask anything we might have masked previously (idempotent upgrade path)
    for u in "${OLD_MASK_LIST[@]}" "${TIGHT_MASK_LIST[@]}"; do
        if [ -L "$MASK_DIR/$u" ] && [ "$(readlink "$MASK_DIR/$u")" = "/dev/null" ]; then
            rm -f "$MASK_DIR/$u"
        fi
    done
    rm -f /etc/systemd/journald.conf.d/50-low-ram.conf
    echo "ai-low-ram-services: NEW profile -> all services enabled"
else
    echo "ai-low-ram-services: DEFAULT profile -> no action"
fi

exit 0
