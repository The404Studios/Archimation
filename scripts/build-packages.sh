#!/bin/bash
# Build all custom Arch packages and populate the local repository
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$PROJECT_DIR/repo/x86_64"
HASH_DIR="$REPO_DIR/.build-hashes"

mkdir -p "$REPO_DIR" "$HASH_DIR"

# ── Rebuild-needed check ────────────────────────────────────────────────────
# Hash the package source directory.  Skip rebuilding when sources haven't
# changed.  Pass --force or set FORCE_REBUILD=1 to bypass this check.
# ────────────────────────────────────────────────────────────────────────────
FORCE_REBUILD="${FORCE_REBUILD:-0}"
[[ "${1:-}" = "--force" ]] && FORCE_REBUILD=1

_check_rebuild_needed() {
    local pkg_name="$1"
    local pkg_dir="$2"
    [[ "$FORCE_REBUILD" = "1" ]] && return 0  # always rebuild when forced

    local hash_file="$HASH_DIR/${pkg_name}.md5"
    local current_hash
    current_hash=$(find "$pkg_dir" -maxdepth 1 -type f | sort | xargs md5sum 2>/dev/null | md5sum | cut -d' ' -f1)

    if [ -f "$hash_file" ] && [ "$(cat "$hash_file")" = "$current_hash" ]; then
        # Also confirm we still have the .pkg.tar.zst in the repo
        if compgen -G "$REPO_DIR/${pkg_name}-"*.pkg.tar.zst >/dev/null 2>&1; then
            return 1  # No rebuild needed
        fi
    fi
    echo "$current_hash" > "$hash_file"
    return 0  # Rebuild needed
}

# ── Stale version cleanup ──────────────────────────────────────────────────
# Remove old .pkg.tar.zst files from the repo, keeping only the newest for
# each package name.  Called after ALL packages are built so the final repo
# contains exactly one version per package.
# ────────────────────────────────────────────────────────────────────────────
_clean_stale_versions() {
    echo "  Cleaning stale package versions..."
    local cleaned=0
    local seen_names=()

    # Collect unique package base names from .pkg.tar.zst filenames
    # Arch package naming: <pkgname>-<pkgver>-<pkgrel>-<arch>.pkg.tar.zst
    # We parse the name by stripping from the FIRST version-like segment onward.
    for pkg_file in "$REPO_DIR"/*.pkg.tar.zst; do
        [ -f "$pkg_file" ] || continue
        local base
        base=$(basename "$pkg_file")

        # Extract package name: everything before -<digit> pattern that starts
        # the version component.  Use sed to grab the longest non-version prefix.
        local name
        name=$(echo "$base" | sed 's/-[0-9][^-]*-[0-9][^-]*-[a-z_][a-z0-9_]*.pkg.tar.zst$//')

        # Deduplicate names
        local already_seen=0
        for sn in "${seen_names[@]+"${seen_names[@]}"}"; do
            [ "$sn" = "$name" ] && { already_seen=1; break; }
        done
        [ "$already_seen" = "1" ] && continue
        seen_names+=("$name")

        # Find all versions of this package, keep only the newest (by mtime)
        local latest
        latest=$(ls -t "$REPO_DIR/${name}-"*.pkg.tar.zst 2>/dev/null | head -1)
        for old in "$REPO_DIR/${name}-"*.pkg.tar.zst; do
            [ -f "$old" ] || continue
            if [ "$old" != "$latest" ]; then
                echo "    Removing stale: $(basename "$old")"
                rm -f "$old"
                ((cleaned++)) || true
            fi
        done
    done
    if [ "$cleaned" -gt 0 ]; then
        echo "  Removed $cleaned stale package file(s)"
    fi
}

# ── Root-safe makepkg wrapper ────────────────────────────────────────────────
# makepkg refuses to run as root. When we ARE root (WSL default), we:
#   1. Create a 'buildpkg' user if needed
#   2. Mirror PKGBUILD files into /tmp (tmpfs honours real Unix permissions)
#   3. Symlink source roots from /tmp so _srcdir="${startdir}/../../<dir>" works
#   4. Run makepkg as buildpkg from the /tmp mirror
#
# This avoids chown on NTFS (/mnt/c) which silently fails in WSL.
# ─────────────────────────────────────────────────────────────────────────────
if [ "$(id -u)" = "0" ]; then
    if ! id buildpkg &>/dev/null; then
        useradd -m -r -s /bin/bash buildpkg
        echo "Created build user: buildpkg"
    fi

    # Build tree lives on Linux tmpfs where permissions work
    BTREE="/tmp/ai-arch-pkgbuild"
    rm -rf "$BTREE"
    mkdir -p "$BTREE/packages"
    chown buildpkg: "$BTREE" "$BTREE/packages"

    # Symlink source roots so relative _srcdir paths resolve correctly.
    # PKGBUILDs use _srcdir="${startdir}/../../<subdir>", startdir=$BTREE/packages/<pkg>
    # so startdir/../.. = $BTREE — symlink each top-level source dir there.
    for src_subdir in ai-control pe-loader trust services firewall packages; do
        [ -d "$PROJECT_DIR/$src_subdir" ] && \
            ln -sf "$PROJECT_DIR/$src_subdir" "$BTREE/$src_subdir"
    done

    _run_makepkg() {
        local pkg_name="$1"
        local src_pkg="$PROJECT_DIR/packages/$pkg_name"
        local bld_pkg="$BTREE/packages/$pkg_name"

        mkdir -p "$bld_pkg"
        cp "$src_pkg/PKGBUILD" "$bld_pkg/"
        # Copy install script and any supplementary files
        find "$src_pkg" -maxdepth 1 -type f ! -name 'PKGBUILD' ! -name '*.pkg.tar.zst' \
            -exec cp {} "$bld_pkg/" \;

        # Strip CRLF from all text files — Windows editors / git autocrlf can
        # inject CRLF which makes makepkg fail with "PKGBUILD contains CRLF".
        for f in "$bld_pkg/PKGBUILD" "$bld_pkg"/*.install "$bld_pkg"/*.hook; do
            [ -f "$f" ] && sed -i 's/\r$//' "$f"
        done

        chown -R buildpkg: "$bld_pkg"
        # runuser is root-only and bypasses PAM (unlike su which needs a tty+PAM in WSL)
        runuser -u buildpkg -- bash -c "cd '$bld_pkg' && makepkg -f --nodeps --noconfirm 2>&1 | tail -10"

        # Copy the resulting package tarball back to the source dir and repo
        cp -f "$bld_pkg"/*.pkg.tar.zst "$src_pkg/" 2>/dev/null || true
    }
else
    _run_makepkg() {
        local pkg_name="$1"
        (cd "$PROJECT_DIR/packages/$pkg_name" && \
            makepkg -f --nodeps --noconfirm 2>&1 | tail -10)
    }
fi

echo "=== Building custom Arch packages ==="

# Build order: pe-loader must come first (other packages depend on it),
# then windows-services, then everything else
BUILD_ORDER=(pe-loader trust-system trust-dkms pe-compat-dkms windows-services ai-firewall ai-control-daemon ai-desktop-config ai-first-boot-wizard)

# Build ordered packages first
for pkg_name in "${BUILD_ORDER[@]}"; do
    pkg_dir="$PROJECT_DIR/packages/$pkg_name"
    if [ -d "$pkg_dir" ] && [ -f "$pkg_dir/PKGBUILD" ]; then
        if _check_rebuild_needed "$pkg_name" "$pkg_dir"; then
            echo "  Building (ordered): $pkg_name"
            _run_makepkg "$pkg_name"
            # Remove ALL old versions before copying the new one
            rm -f "$REPO_DIR/${pkg_name}-"*.pkg.tar.zst 2>/dev/null || true
            cp -f "$pkg_dir"/*.pkg.tar.zst "$REPO_DIR/" 2>/dev/null || true
            # Add to repo immediately so subsequent packages can find this one
            repo-add "$REPO_DIR/pe-compat.db.tar.gz" "$REPO_DIR"/${pkg_name}-*.pkg.tar.zst 2>/dev/null || true
        else
            echo "  Skipping (unchanged): $pkg_name"
        fi
    fi
done

# Build any remaining packages not in the ordered list
for pkg_dir in "$PROJECT_DIR"/packages/*/; do
    pkg_name=$(basename "$pkg_dir")

    # Skip already-built ordered packages
    for built in "${BUILD_ORDER[@]}"; do
        if [ "$pkg_name" = "$built" ]; then
            continue 2
        fi
    done

    if [ ! -f "$pkg_dir/PKGBUILD" ]; then
        echo "  Skipping $pkg_name (no PKGBUILD)"
        continue
    fi

    if _check_rebuild_needed "$pkg_name" "$pkg_dir"; then
        echo "  Building: $pkg_name"
        _run_makepkg "$pkg_name"

        # Remove ALL old versions before copying the new one
        rm -f "$REPO_DIR/${pkg_name}-"*.pkg.tar.zst 2>/dev/null || true
        cp -f "$pkg_dir"/*.pkg.tar.zst "$REPO_DIR/" 2>/dev/null || true
        repo-add "$REPO_DIR/pe-compat.db.tar.gz" "$REPO_DIR"/${pkg_name}-*.pkg.tar.zst 2>/dev/null || true
    else
        echo "  Skipping (unchanged): $pkg_name"
    fi
done

echo ""
echo "=== Finalizing package repository ==="

# Clean stale versions before finalizing (keeps only the newest per package)
_clean_stale_versions

# Also remove old .pkg.tar.zst files from inside packages/ source dirs
for pkg_src_dir in "$PROJECT_DIR"/packages/*/; do
    [ -d "$pkg_src_dir" ] || continue
    local_pkgs=("$pkg_src_dir"*.pkg.tar.zst)
    if [ -e "${local_pkgs[0]:-}" ] && [ "${#local_pkgs[@]}" -gt 1 ]; then
        latest=$(ls -t "$pkg_src_dir"*.pkg.tar.zst 2>/dev/null | head -1)
        for old in "$pkg_src_dir"*.pkg.tar.zst; do
            [ "$old" != "$latest" ] && rm -f "$old"
        done
    fi
done

# Rebuild the repo database from scratch so it reflects exactly what is on disk
rm -f "$REPO_DIR/pe-compat.db"* "$REPO_DIR/pe-compat.files"* 2>/dev/null || true
if compgen -G "$REPO_DIR"/*.pkg.tar.zst >/dev/null 2>&1; then
    repo-add "$REPO_DIR/pe-compat.db.tar.gz" "$REPO_DIR"/*.pkg.tar.zst 2>/dev/null || true
fi

# Summary
echo ""
echo "=== Package build complete ==="
echo "Repository: $REPO_DIR"
echo "Packages:"
for p in "$REPO_DIR"/*.pkg.tar.zst; do
    [ -f "$p" ] && echo "  $(basename "$p")"
done
