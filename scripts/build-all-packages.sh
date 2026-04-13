#!/bin/bash
# Build all custom packages and create local repository
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT="$PROJECT_DIR"
REPO_DIR="${PROJECT}/repo/x86_64"
mkdir -p "${REPO_DIR}"

echo "=== Step 1: Build trust library ==="
cd "${PROJECT}/trust/lib"
make clean 2>/dev/null || true
make all 2>&1 | tail -5
echo "Trust lib built: $(ls -la libtrust.a libtrust.so 2>/dev/null | wc -l) files"

echo ""
echo "=== Step 2: Build PE loader ==="
cd "${PROJECT}/pe-loader"
make clean 2>/dev/null || true
make -j$(nproc) all 2>&1 | tail -10
echo "PE loader: $(ls loader/peloader 2>/dev/null && echo OK || echo FAIL)"
echo "DLL count: $(ls dlls/libpe_*.so 2>/dev/null | wc -l)"

echo ""
echo "=== Step 3: Build packages ==="
chown -R builder:builder "${REPO_DIR}" 2>/dev/null || true

BUILD_ORDER="trust-system pe-loader windows-services ai-control-daemon ai-firewall ai-desktop-config ai-first-boot-wizard"

for pkg in ${BUILD_ORDER}; do
    PKG_DIR="${PROJECT}/packages/${pkg}"
    if [ ! -f "${PKG_DIR}/PKGBUILD" ]; then
        echo "  SKIP: ${pkg} (no PKGBUILD)"
        continue
    fi
    echo "  Building: ${pkg}"
    cd "${PKG_DIR}"
    rm -f *.pkg.tar.zst 2>/dev/null || true
    rm -rf pkg src 2>/dev/null || true
    su builder -c "makepkg -f --nodeps --noconfirm 2>&1" | tail -3
    cp -f *.pkg.tar.zst "${REPO_DIR}/" 2>/dev/null && echo "    -> copied to repo" || echo "    -> NO PACKAGE BUILT"
done

echo ""
echo "=== Step 4: Create repo database ==="
cd "${REPO_DIR}"
rm -f pe-compat.db* pe-compat.files* 2>/dev/null || true
repo-add pe-compat.db.tar.gz *.pkg.tar.zst 2>&1 | tail -5
echo ""
echo "Repo contents:"
ls -lh *.pkg.tar.zst 2>/dev/null || echo "No packages found!"
echo ""
echo "=== Package build complete ==="
