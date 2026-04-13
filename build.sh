#!/bin/bash
# Master build orchestrator for AI Control Linux
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== AI Control Linux Build System ==="
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
        echo "[1/3] Building PE Loader and Services..."
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
    *)
        echo "Usage: $0 {all|pe-loader|services|packages|iso|clean|test}"
        exit 1
        ;;
esac
