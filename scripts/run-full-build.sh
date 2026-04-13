#!/bin/bash
# Full build: packages + ISO
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT="$PROJECT_DIR"

echo "=== Full build started at $(date) ==="
cd "$PROJECT"

# Remove old ISO so we know the new one is fresh
rm -f output/*.iso

echo "--- Building packages ---"
bash scripts/build-packages.sh

echo ""
echo "--- Building ISO ---"
bash scripts/build-iso.sh

echo ""
echo "=== Full build complete at $(date) ==="
ls -lh output/*.iso 2>/dev/null || echo "No ISO found"
