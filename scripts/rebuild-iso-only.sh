#!/bin/bash
# Rebuild the ISO only (packages already built).
# Faster path than run-full-build: skips the entire package rebuild phase when
# only profile/airootfs changes. Shares pacman cache and parallelism tunings.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$PROJECT/repo/x86_64"

: "${JOBS:=$(nproc 2>/dev/null || echo 4)}"
export JOBS
export MAKEFLAGS="${MAKEFLAGS:--j$JOBS}"

echo "=== [$(date +%H:%M:%S)] Clearing stale pacman cache for project packages ==="
# Only remove OUR packages from the cache so pacstrap picks up fresh builds.
# Preserves all upstream Arch packages (those are ~2 GB of downloads).
for pkg in pe-loader trust-system trust-dkms pe-compat-dkms ai-control-daemon \
           ai-firewall ai-desktop-config ai-first-boot-wizard windows-services; do
    rm -f /var/cache/pacman/pkg/${pkg}-*.pkg.tar.zst 2>/dev/null || true
done

echo "=== [$(date +%H:%M:%S)] Rebuilding repo database ==="
rm -f "$REPO_DIR/pe-compat.db"* "$REPO_DIR/pe-compat.files"*
# -q quiet, -n new-only, -R remove-obsolete: much faster on re-add
repo-add -q -n -R "$REPO_DIR/pe-compat.db.tar.gz" "$REPO_DIR"/*.pkg.tar.zst

echo "=== [$(date +%H:%M:%S)] Fixing pacman.conf repo path ==="
sed -i "s|Server = file://.*|Server = file://${REPO_DIR}|" "$PROJECT/profile/pacman.conf"

echo "=== [$(date +%H:%M:%S)] Cleaning work directory ==="
rm -rf "$PROJECT/work"
mkdir -p "$PROJECT/output"
rm -f "$PROJECT/output/"*.iso

echo "=== [$(date +%H:%M:%S)] Building ISO (JOBS=$JOBS) ==="
T_START=$(date +%s)
# Pass parallel-friendly compression env through to mksquashfs + zstd.
sudo env JOBS="$JOBS" ZSTD_NBTHREADS="$JOBS" XZ_OPT="-T$JOBS" \
    mkarchiso -v -w "$PROJECT/work" -o "$PROJECT/output" "$PROJECT/profile"
DT=$(( $(date +%s) - T_START ))

echo ""
echo "=== Done in $((DT/60))m$((DT%60))s ==="
ls -lh "$PROJECT/output/"*.iso 2>/dev/null || echo "No ISO found"
