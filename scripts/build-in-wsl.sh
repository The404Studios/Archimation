#!/bin/bash
# Build packages and ISO from Linux-native filesystem
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT="$PROJECT_DIR"
BUILD="/home/builder/project"

echo "=== Copying project to Linux filesystem ==="
rm -rf "$BUILD"
mkdir -p "$BUILD"
cp -a "$PROJECT/packages" "$BUILD/"
cp -a "$PROJECT/scripts" "$BUILD/"
cp -a "$PROJECT/pe-loader" "$BUILD/" 2>/dev/null || true
cp -a "$PROJECT/ai-control" "$BUILD/" 2>/dev/null || true
cp -a "$PROJECT/services" "$BUILD/" 2>/dev/null || true
cp -a "$PROJECT/firewall" "$BUILD/" 2>/dev/null || true
cp -a "$PROJECT/trust" "$BUILD/" 2>/dev/null || true
cp -a "$PROJECT/profile" "$BUILD/" 2>/dev/null || true
mkdir -p "$BUILD/repo/x86_64"
chown -R builder:builder "$BUILD"
echo "Copy done."

echo ""
echo "=== Building packages ==="
su - builder -c "cd /home/builder/project && bash scripts/build-packages.sh"

echo ""
echo "=== Copying repo back ==="
mkdir -p "$PROJECT/repo/x86_64"
cp -f "$BUILD"/repo/x86_64/*.pkg.tar.zst "$PROJECT/repo/x86_64/" 2>/dev/null || true
cp -f "$BUILD"/repo/x86_64/pe-compat.db* "$PROJECT/repo/x86_64/" 2>/dev/null || true
cp -f "$BUILD"/repo/x86_64/pe-compat.files* "$PROJECT/repo/x86_64/" 2>/dev/null || true
echo "Repo copied back."

echo ""
echo "=== Building ISO ==="
# Use native Linux filesystem for work dir (NTFS breaks symlinks, case-sensitivity, hardlinks)
ISO_WORK="/home/builder/iso-work"
ISO_OUT="/home/builder/iso-out"
rm -rf "$ISO_WORK" "$ISO_OUT"
mkdir -p "$ISO_WORK" "$ISO_OUT"

# Copy repo to native fs so pacman.conf can reference it
NATIVE_REPO="$BUILD/repo/x86_64"

# Copy profile to native fs (it may reference airootfs overlay files)
NATIVE_PROFILE="$BUILD/profile"

# Fix pacman.conf repo path to point at native repo
sed -i "s|Server = file://.*|Server = file://${NATIVE_REPO}|" "$NATIVE_PROFILE/pacman.conf"

mkarchiso -v -w "$ISO_WORK" -o "$ISO_OUT" "$NATIVE_PROFILE"

echo ""
echo "=== Copying ISO back ==="
mkdir -p "$PROJECT/output"
cp -f "$ISO_OUT"/*.iso "$PROJECT/output/" 2>/dev/null || true
cp -f "$ISO_OUT"/*.sha256 "$PROJECT/output/" 2>/dev/null || true

echo ""
echo "=== Cleaning up work dir ==="
rm -rf "$ISO_WORK"

echo ""
echo "=== Done ==="
ls -lh "$PROJECT/output/"*.iso 2>/dev/null || echo "No ISO found"
