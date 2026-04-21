#!/bin/bash
# release-to-repo.sh — stage the pe-compat repo for a public release.
#
# Copies every *.pkg.tar.zst + pe-compat.db* + pe-compat.files* from
# $REPO_DIR into $TARGET, emits a manifest.json with sha256sums, and
# prints the `gh release upload` one-liner for operators to run manually.
#
# Usage:
#   bash scripts/release-to-repo.sh [TARGET]
#   REPO_DIR=repo/x86_64 TARGET=/tmp/pe-compat-release bash scripts/release-to-repo.sh
#
# Design: idempotent (rsync + manifest overwrite), no network calls, no
# gh-auth. The operator runs `gh release upload` themselves — see
# docs/release-process.md.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

REPO_DIR="${REPO_DIR:-$PROJECT_DIR/repo/x86_64}"
TARGET="${1:-${TARGET:-$PROJECT_DIR/release-stage/x86_64}}"

[ -d "$REPO_DIR" ] || { echo "ERROR: REPO_DIR '$REPO_DIR' missing — run scripts/build-packages.sh first." >&2; exit 1; }

# repo-add output files live alongside the packages
shopt -s nullglob
pkgs=( "$REPO_DIR"/*.pkg.tar.zst )
dbs=(  "$REPO_DIR"/pe-compat.db*  "$REPO_DIR"/pe-compat.files* )
shopt -u nullglob

[ "${#pkgs[@]}" -gt 0 ] || { echo "ERROR: no *.pkg.tar.zst in $REPO_DIR — nothing to release." >&2; exit 1; }

mkdir -p "$TARGET"

# rsync -c = checksum-based (idempotent), -a = preserve perms/times
if command -v rsync >/dev/null 2>&1; then
    rsync -ac --delete-after \
        --include='*.pkg.tar.zst' \
        --include='pe-compat.db*' \
        --include='pe-compat.files*' \
        --exclude='.build-hashes/***' \
        --exclude='*' \
        "$REPO_DIR/" "$TARGET/"
else
    # Portable fallback
    rm -f "$TARGET"/*.pkg.tar.zst "$TARGET"/pe-compat.db* "$TARGET"/pe-compat.files* 2>/dev/null || true
    cp -f "${pkgs[@]}" "${dbs[@]}" "$TARGET/"
fi

# Emit manifest.json with sha256sums — future release-tool can verify uploads
: > "$TARGET/manifest.json"
{
    echo '{'
    echo '  "repo": "pe-compat",'
    echo '  "arch": "x86_64",'
    echo "  \"generated_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo '  "files": ['
    first=1
    for f in "$TARGET"/*.pkg.tar.zst "$TARGET"/pe-compat.db* "$TARGET"/pe-compat.files*; do
        [ -f "$f" ] || continue
        sum=$(sha256sum "$f" | awk '{print $1}')
        size=$(stat -c%s "$f" 2>/dev/null || wc -c < "$f")
        name=$(basename "$f")
        [ "$first" = "1" ] && first=0 || echo ','
        printf '    {"name": "%s", "sha256": "%s", "size": %s}' "$name" "$sum" "$size"
    done
    echo ''
    echo '  ]'
    echo '}'
} >> "$TARGET/manifest.json"

echo "release staged: $TARGET (${#pkgs[@]} pkg, $(du -sh "$TARGET" 2>/dev/null | cut -f1))"
echo "next: gh release upload <tag> \"$TARGET\"/*.pkg.tar.zst \"$TARGET\"/pe-compat.* \"$TARGET\"/manifest.json"
