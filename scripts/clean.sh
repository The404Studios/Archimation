#!/bin/bash
# Clean build artifacts
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Cleaning build artifacts..."

# ISO and workdir (both project-local and the /tmp shadow used on WSL NTFS)
rm -rf "$PROJECT_DIR/work"
rm -rf "$PROJECT_DIR/output"
rm -rf /tmp/ai-arch-build 2>/dev/null || true
rm -rf /tmp/ai-arch-pkgbuild 2>/dev/null || true

# Package repo
rm -f "$PROJECT_DIR/repo/x86_64"/*.pkg.tar.zst
rm -f "$PROJECT_DIR/repo/x86_64"/*.db*
rm -f "$PROJECT_DIR/repo/x86_64"/*.files*
rm -rf "$PROJECT_DIR/repo/x86_64/.build-hashes"

# makepkg byproducts inside each package dir
for pkg_dir in "$PROJECT_DIR"/packages/*/; do
    [ -d "$pkg_dir" ] || continue
    rm -rf "${pkg_dir}pkg" "${pkg_dir}src" 2>/dev/null || true
    rm -f "${pkg_dir}"*.pkg.tar.zst "${pkg_dir}"*.log 2>/dev/null || true
done

# C build artifacts
find "$PROJECT_DIR" \
    -path "$PROJECT_DIR/.git" -prune -o \
    -name '*.o' -type f -print -o \
    -name '*.a' -type f -print -o \
    -name '*.so' -type f -print 2>/dev/null | xargs -r rm -f 2>/dev/null || true

# Stray QEMU serial logs (created by test-qemu.sh in /tmp)
rm -f /tmp/qemu-serial.log /tmp/qemu-stdout.log 2>/dev/null || true

echo "Done."
