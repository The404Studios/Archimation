#!/bin/bash
# Sync project to Linux-native filesystem and build packages
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT="$PROJECT_DIR"
BUILD="/home/builder/project"

echo "=== Syncing project to Linux filesystem ==="
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
echo "Sync complete."

echo ""
echo "=== Building packages ==="

BUILD_ORDER=(
    pe-loader
    trust-system
    windows-services
    ai-control-daemon
    ai-firewall
    ai-desktop-config
    ai-first-boot-wizard
)

REPO_DIR="$BUILD/repo/x86_64"

for pkg in "${BUILD_ORDER[@]}"; do
    echo ""
    echo "--- Building $pkg ---"
    cd "$BUILD/packages/$pkg"
    su builder -c "cd $BUILD/packages/$pkg && makepkg -f --nodeps 2>&1" || {
        echo "WARNING: $pkg failed to build, skipping"
        continue
    }
    # Move built package to repo
    mv -f *.pkg.tar.zst "$REPO_DIR/" 2>/dev/null || true
    echo "$pkg built successfully."
done

echo ""
echo "=== Creating package repository ==="
cd "$REPO_DIR"
repo-add pe-compat.db.tar.gz *.pkg.tar.zst 2>/dev/null || true

echo ""
echo "=== All packages built ==="
ls -lh "$REPO_DIR/"*.pkg.tar.zst 2>/dev/null || echo "No packages found"
