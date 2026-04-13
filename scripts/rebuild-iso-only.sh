#!/bin/bash
# Rebuild the ISO only (packages already built)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$PROJECT/repo/x86_64"

echo "=== Clearing stale pacman cache ==="
rm -f /var/cache/pacman/pkg/pe-loader-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/trust-system-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/ai-control-daemon-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/ai-firewall-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/ai-desktop-config-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/ai-first-boot-wizard-*.pkg.tar.zst
rm -f /var/cache/pacman/pkg/windows-services-*.pkg.tar.zst

echo "=== Rebuilding repo database from scratch ==="
rm -f "$REPO_DIR/pe-compat.db"* "$REPO_DIR/pe-compat.files"*
repo-add "$REPO_DIR/pe-compat.db.tar.gz" "$REPO_DIR"/*.pkg.tar.zst

echo "=== Fixing pacman.conf repo path ==="
sed -i "s|Server = file://.*|Server = file://${REPO_DIR}|" "$PROJECT/profile/pacman.conf"

echo "=== Cleaning work directory ==="
rm -rf "$PROJECT/work"
mkdir -p "$PROJECT/output"
rm -f "$PROJECT/output/"*.iso

echo "=== Building ISO ==="
mkarchiso -v -w "$PROJECT/work" -o "$PROJECT/output" "$PROJECT/profile"

echo ""
echo "=== Done ==="
ls -lh "$PROJECT/output/"*.iso 2>/dev/null || echo "No ISO found"
