#!/bin/bash
# Build everything on the Linux-native filesystem, then copy ISO back
set -euo pipefail

# Must be run as root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    echo "Usage: sudo bash $0"
    exit 1
fi

# Ensure builder user exists
if ! id builder &>/dev/null; then
    echo "Creating builder user..."
    useradd -m builder 2>/dev/null || true
fi

# Ensure required packages are installed
for pkg in base-devel archiso xorriso squashfs-tools dosfstools mtools libxkbcommon; do
    if ! pacman -Qi "$pkg" &>/dev/null; then
        echo "Installing missing package: $pkg"
        pacman -S --noconfirm --needed "$pkg" 2>/dev/null || true
    fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(dirname "$SCRIPT_DIR")"
BUILD="/home/builder/project"
WORK="/tmp/iso-work"
OUTPUT="/tmp/iso-output"

echo "=== Phase 1: Sync project to Linux filesystem ==="
rm -rf "$BUILD"
mkdir -p "$BUILD"
cp -a "$PROJECT/packages" "$BUILD/"
cp -a "$PROJECT/scripts" "$BUILD/"
cp -a "$PROJECT/pe-loader" "$BUILD/"
cp -a "$PROJECT/ai-control" "$BUILD/"
cp -a "$PROJECT/services" "$BUILD/"
cp -a "$PROJECT/firewall" "$BUILD/"
cp -a "$PROJECT/trust" "$BUILD/"
cp -a "$PROJECT/profile" "$BUILD/"
mkdir -p "$BUILD/repo/x86_64"
chown -R builder:builder "$BUILD"
echo "Sync done."

echo ""
echo "=== Phase 2: Build packages ==="
su - builder -c "cd /home/builder/project && bash scripts/build-packages.sh"

echo ""
echo "=== Phase 3: Clear stale caches ==="
rm -f /var/cache/pacman/pkg/pe-loader-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/trust-system-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/ai-control-daemon-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/ai-firewall-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/ai-desktop-config-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/ai-first-boot-wizard-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/windows-services-*.pkg.tar.zst

echo ""
echo "=== Phase 4: Build ISO on Linux filesystem ==="
REPO_DIR="$BUILD/repo/x86_64"
sed -i "s|Server = file://.*|Server = file://${REPO_DIR}|" "$BUILD/profile/pacman.conf"

rm -rf "$WORK" "$OUTPUT"
mkdir -p "$WORK" "$OUTPUT"

mkarchiso -v -w "$WORK" -o "$OUTPUT" "$BUILD/profile"

echo ""
echo "=== Phase 5: Copy ISO back to Windows ==="
mkdir -p "$PROJECT/output"
rm -f "$PROJECT/output/"*.iso
cp -f "$OUTPUT/"*.iso "$PROJECT/output/"

echo ""
echo "=== Done ==="
ls -lh "$PROJECT/output/"*.iso 2>/dev/null || echo "No ISO found"
