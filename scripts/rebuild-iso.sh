#!/bin/bash
# rebuild-iso.sh - Rebuild ISO from existing packages (skip package build)
set -euo pipefail

BUILD_BASE="/tmp/ai-arch-build"
NATIVE_PROJECT="${BUILD_BASE}/project"
REPO_DIR="${NATIVE_PROJECT}/repo/x86_64"
ISO_OUTPUT="/tmp/iso-output"
WORK_DIR="${BUILD_BASE}/work"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Updating profile with latest fixes ==="
cp -a "$PROJECT_DIR/profile/"* "${NATIVE_PROJECT}/profile/"
# Also update customize_airootfs.sh
cp -a "$PROJECT_DIR/profile/airootfs/root/"*.sh "${NATIVE_PROJECT}/profile/airootfs/root/"
cp -a "$PROJECT_DIR/profile/airootfs/etc/lightdm/"* "${NATIVE_PROJECT}/profile/airootfs/etc/lightdm/"
cp -a "$PROJECT_DIR/profile/airootfs/etc/pam.d/"* "${NATIVE_PROJECT}/profile/airootfs/etc/pam.d/"
echo "Updated"

# Update pacman.conf repo path
sed -i "s|Server = file://.*|Server = file://${REPO_DIR}|" "${NATIVE_PROJECT}/profile/pacman.conf"

# Clean and rebuild
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
rm -f "$ISO_OUTPUT"/*.iso 2>/dev/null || true

echo ""
echo "=== Building ISO ==="
mkarchiso -v -w "$WORK_DIR" -o "$ISO_OUTPUT" "${NATIVE_PROJECT}/profile" 2>&1 | tail -20

echo ""
ISO_FILE=$(ls "$ISO_OUTPUT"/*.iso 2>/dev/null | head -1)
if [ -n "$ISO_FILE" ]; then
    echo "ISO: $ISO_FILE"
    echo "Size: $(du -h "$ISO_FILE" | cut -f1)"
else
    echo "FATAL: No ISO built!"
    exit 1
fi
