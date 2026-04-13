#!/bin/bash
# Build ISO using the already-built package repository
set -euo pipefail

BUILD="/home/builder/project"
REPO_DIR="$BUILD/repo/x86_64"
WORK="/tmp/iso-work"
OUTPUT="/tmp/iso-output"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(dirname "$SCRIPT_DIR")"

echo "=== Verifying package repository ==="
ls "$REPO_DIR/"*.pkg.tar.zst || {
    echo "ERROR: No packages found in $REPO_DIR"
    exit 1
}

echo ""
echo "=== Updating pacman.conf with local repo path ==="
sed -i "s|Server = file://.*|Server = file://${REPO_DIR}|" "$BUILD/profile/pacman.conf"

echo ""
echo "=== Clearing stale caches ==="
rm -f /var/cache/pacman/pkg/pe-loader-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/trust-system-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/ai-control-daemon-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/ai-firewall-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/ai-desktop-config-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/ai-first-boot-wizard-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/windows-services-*.pkg.tar.zst

echo ""
echo "=== Building ISO ==="
rm -rf "$WORK" "$OUTPUT"
mkdir -p "$WORK" "$OUTPUT"

mkarchiso -v -w "$WORK" -o "$OUTPUT" "$BUILD/profile" 2>&1

echo ""
echo "=== Copying ISO back to Windows ==="
mkdir -p "$PROJECT/output"
rm -f "$PROJECT/output/"*.iso
cp -f "$OUTPUT/"*.iso "$PROJECT/output/" 2>/dev/null || true

echo ""
echo "=== Done ==="
ls -lh "$PROJECT/output/"*.iso 2>/dev/null || ls -lh "$OUTPUT/"*.iso 2>/dev/null || echo "ISO location check failed"
