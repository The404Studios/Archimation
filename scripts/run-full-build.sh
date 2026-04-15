#!/bin/bash
# Full build: packages + ISO
# set -e ensures we stop immediately on ANY failure in either substep.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT="$PROJECT_DIR"

# Propagate parallelism + ccache to all sub-scripts. Without this export,
# child shells get only MAKEFLAGS="-j4" from a possible parent `make -j`, and
# build-packages.sh's runuser strips the environment entirely.
: "${JOBS:=$(nproc 2>/dev/null || echo 4)}"
export JOBS
export MAKEFLAGS="${MAKEFLAGS:--j$JOBS}"

# Global timing
T_FULL_START=$(date +%s)
_mins() { printf '%dm%02ds' $(( $1 / 60 )) $(( $1 % 60 )); }

# Cleanup trap: always print total wall time, even on failure.
_summary() {
    local rc=$?
    local dt=$(( $(date +%s) - T_FULL_START ))
    if [ "$rc" -eq 0 ]; then
        echo "=== Full build SUCCESS in $(_mins $dt) ==="
    else
        echo "=== Full build FAILED after $(_mins $dt) (exit $rc) ===" >&2
    fi
    exit "$rc"
}
trap _summary EXIT

echo "=== Full build started at $(date) (JOBS=$JOBS) ==="
cd "$PROJECT"

# Remove old ISO so we know the new one is fresh
rm -f output/*.iso 2>/dev/null || true

echo ""
echo "--- [1/2] Building packages ---"
T_PKG_START=$(date +%s)
if ! bash "$SCRIPT_DIR/build-packages.sh"; then
    echo "ERROR: Package build failed; aborting full build." >&2
    exit 1
fi
echo "--- packages done in $(_mins $(( $(date +%s) - T_PKG_START ))) ---"

echo ""
echo "--- [2/2] Building ISO ---"
T_ISO_START=$(date +%s)
if ! bash "$SCRIPT_DIR/build-iso.sh"; then
    echo "ERROR: ISO build failed." >&2
    exit 1
fi
echo "--- ISO done in $(_mins $(( $(date +%s) - T_ISO_START ))) ---"

echo ""
ls -lh output/*.iso 2>/dev/null || { echo "ERROR: No ISO produced" >&2; exit 1; }
