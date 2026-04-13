#!/bin/bash
# Rebuild just the ai-control-daemon package with latest sources
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT="$PROJECT_DIR"
BUILD="/home/builder/project"

echo "=== Syncing updated sources ==="
rm -rf "$BUILD/ai-control" "$BUILD/packages/ai-control-daemon" "$BUILD/profile"
cp -a "$PROJECT/ai-control" "$BUILD/"
cp -a "$PROJECT/packages/ai-control-daemon" "$BUILD/packages/"
cp -a "$PROJECT/profile" "$BUILD/"
chown -R builder:builder "$BUILD"

echo "=== Rebuilding ai-control-daemon ==="
su - builder -c "cd /home/builder/project/packages/ai-control-daemon && makepkg -f --nodeps --noconfirm" 2>&1 | tail -10

echo "=== Copying package to repo ==="
cp -f "$BUILD/packages/ai-control-daemon/"*.pkg.tar.zst "$PROJECT/repo/x86_64/"

echo "=== Verifying fixes in package ==="
echo -n "_safe_init count: "
bsdtar -xf "$PROJECT/repo/x86_64/ai-control-daemon-0.1.0-1-any.pkg.tar.zst" -O usr/lib/ai-control-daemon/api_server.py 2>/dev/null | grep -c '_safe_init' || echo "0"
echo -n "OSError catch in keyboard: "
bsdtar -xf "$PROJECT/repo/x86_64/ai-control-daemon-0.1.0-1-any.pkg.tar.zst" -O usr/lib/ai-control-daemon/keyboard.py 2>/dev/null | grep -c 'OSError' || echo "0"

echo "=== Updating repo database ==="
repo-add "$PROJECT/repo/x86_64/pe-compat.db.tar.gz" "$PROJECT/repo/x86_64/"*.pkg.tar.zst 2>/dev/null || true

echo ""
echo "=== Building ISO ==="
REPO_DIR="$PROJECT/repo/x86_64"
sed -i "s|Server = file://.*|Server = file://${REPO_DIR}|" "$PROJECT/profile/pacman.conf"
rm -rf "$PROJECT/work"
mkdir -p "$PROJECT/output"
mkarchiso -v -w "$PROJECT/work" -o "$PROJECT/output" "$PROJECT/profile" 2>&1 | tail -30

echo ""
echo "=== Done ==="
ls -lh "$PROJECT/output/"*.iso 2>/dev/null || echo "No ISO found"
