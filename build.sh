#!/bin/bash
# Master build orchestrator for AI Control Linux.
# Delegates to make / scripts but ensures JOBS + MAKEFLAGS propagate.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Auto-pick core count, propagate to every child (make, makepkg, mkarchiso).
: "${JOBS:=$(nproc 2>/dev/null || echo 4)}"
export JOBS
export MAKEFLAGS="${MAKEFLAGS:--j$JOBS}"

echo "=== AI Control Linux Build System (JOBS=$JOBS) ==="
echo ""

case "${1:-all}" in
    pe-loader)
        echo "[1/1] Building PE Loader..."
        make pe-loader
        ;;
    services)
        echo "[1/1] Building Windows Services layer..."
        make services
        ;;
    packages)
        echo "[1/1] Building Arch packages..."
        bash scripts/build-packages.sh
        ;;
    iso)
        echo "[1/3] Building PE Loader and Services (parallel)..."
        # make -j already propagates via MAKEFLAGS; this builds pe-loader
        # and services concurrently. services has no pe-loader dep (they
        # both depend on trust-lib which pe-loader builds first).
        make pe-loader services
        echo "[2/3] Building Arch packages..."
        bash scripts/build-packages.sh
        echo "[3/3] Building ISO..."
        bash scripts/build-iso.sh
        echo ""
        echo "=== ISO built successfully ==="
        echo "Output: output/"
        ;;
    clean)
        make clean
        ;;
    test)
        make test
        ;;
    all)
        echo "[1/3] Building PE Loader..."
        make pe-loader
        echo "[2/3] Building Windows Services layer..."
        make services
        echo "[3/3] Building packages..."
        bash scripts/build-packages.sh
        echo ""
        echo "=== Build complete ==="
        ;;
    help|-h|--help)
        echo "Usage: $0 {all|pe-loader|services|packages|iso|clean|test}"
        echo ""
        echo "  JOBS=N $0 …       — override parallel job count (default: nproc)"
        echo "  REFLECTOR=1 $0 iso — refresh mirrorlist before pacstrap"
        exit 0
        ;;
    *)
        echo "Usage: $0 {all|pe-loader|services|packages|iso|clean|test}"
        exit 1
        ;;
esac
