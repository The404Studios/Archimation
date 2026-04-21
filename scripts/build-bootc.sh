#!/usr/bin/env bash
# scripts/build-bootc.sh — Archimation bootc OCI bake (S78 Dev D, Phase 2)
#
# Thin orchestrator that:
#   1. runs scripts/build-packages.sh if repo/x86_64/ is empty (shared with ISO)
#   2. delegates the actual buildah/podman invocation to bootc/build-bootc.sh
#   3. exports the resulting image as output/archimation-bootc-<date>.tar
#
# Matches the phase-echo shape of scripts/run-full-build.sh: every step prints
# a [N/M] banner with wall-clock timing, and a trap emits a final summary on
# exit regardless of outcome.
#
# NOT a replacement for scripts/run-full-build.sh. That drives the archiso
# pipeline (packages + mkarchiso); this one drives the bootc pipeline (packages
# + OCI bake). They share stage 1 and diverge at stage 2.
#
# Env overrides:
#   TAG                        image tag (default archimation-bootc:dev)
#   ARCHIMATION_BOOTC_DRYRUN   =1 → print builder cmd, no bake
#   SKIP_PACKAGE_BUILD         =1 → trust whatever is already in repo/x86_64/
#   OUTPUT_DIR                 default $PROJECT/output
#   NO_TAR_EXPORT              =1 → skip the final tarball save step

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT="$PROJECT_DIR"

TAG="${TAG:-archimation-bootc:dev}"
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT/output}"
SKIP_PACKAGE_BUILD="${SKIP_PACKAGE_BUILD:-0}"
NO_TAR_EXPORT="${NO_TAR_EXPORT:-0}"
DRYRUN="${ARCHIMATION_BOOTC_DRYRUN:-0}"

# ---- wall-clock + summary trap (pattern lifted from run-full-build.sh) -------
T_FULL_START=$(date +%s)
_mins() { printf '%dm%02ds' $(( $1 / 60 )) $(( $1 % 60 )); }
_summary() {
    local rc=$?
    local dt=$(( $(date +%s) - T_FULL_START ))
    if [ "$rc" -eq 0 ]; then
        echo "=== bootc build SUCCESS in $(_mins $dt) ==="
    else
        echo "=== bootc build FAILED after $(_mins $dt) (exit $rc) ===" >&2
    fi
    exit "$rc"
}
trap _summary EXIT

echo "=== Archimation bootc build started at $(date) ==="
echo "    project: $PROJECT"
echo "    tag:     $TAG"
echo "    output:  $OUTPUT_DIR"
echo "    dry-run: $DRYRUN"
cd "$PROJECT"
mkdir -p "$OUTPUT_DIR"

# ---- [1/3] packages ----------------------------------------------------------
echo ""
echo "--- [1/3] Custom pacman packages ---"
T_PKG_START=$(date +%s)

PKG_COUNT=0
if [ -d repo/x86_64 ]; then
    PKG_COUNT="$(find repo/x86_64 -maxdepth 1 -name '*.pkg.tar.zst' 2>/dev/null | wc -l)"
fi

if [ "$SKIP_PACKAGE_BUILD" = "1" ]; then
    echo "SKIP_PACKAGE_BUILD=1 — reusing repo/x86_64/ ($PKG_COUNT packages present)"
elif [ "$PKG_COUNT" -ge 5 ]; then
    echo "OK — repo/x86_64/ has $PKG_COUNT packages; skipping rebuild"
    echo "    (set SKIP_PACKAGE_BUILD=0 force-off if you want a rebuild)"
else
    echo "repo/x86_64/ has only $PKG_COUNT packages; running scripts/build-packages.sh"
    if ! bash "$SCRIPT_DIR/build-packages.sh"; then
        echo "ERROR: package build failed; aborting bootc build" >&2
        exit 1
    fi
fi
echo "--- packages done in $(_mins $(( $(date +%s) - T_PKG_START ))) ---"

# ---- [2/3] bootc bake --------------------------------------------------------
echo ""
echo "--- [2/3] Bake OCI image (bootc/build-bootc.sh) ---"
T_BAKE_START=$(date +%s)

if [ ! -x "$PROJECT/bootc/build-bootc.sh" ]; then
    echo "ERROR: bootc/build-bootc.sh missing or not executable" >&2
    exit 2
fi

# Re-export env so bootc/build-bootc.sh picks them up.
export TAG
export ARCHIMATION_BOOTC_DRYRUN="$DRYRUN"

if ! bash "$PROJECT/bootc/build-bootc.sh"; then
    echo "ERROR: bootc/build-bootc.sh failed" >&2
    exit 3
fi
echo "--- bake done in $(_mins $(( $(date +%s) - T_BAKE_START ))) ---"

# ---- [3/3] export tar artifact -----------------------------------------------
echo ""
echo "--- [3/3] Export OCI image to tarball ---"
T_EXPORT_START=$(date +%s)

if [ "$DRYRUN" = "1" ]; then
    echo "DRY-RUN — no image built; skipping tarball export"
elif [ "$NO_TAR_EXPORT" = "1" ]; then
    echo "NO_TAR_EXPORT=1 — skipping tarball export"
else
    DATE_TAG="$(date -u +%Y%m%d-%H%M%S)"
    OUT_TAR="$OUTPUT_DIR/archimation-bootc-${DATE_TAG}.tar"

    # Pick whichever container engine built the image; reuse the precedence
    # order from bootc/build-bootc.sh (buildah > podman > docker).
    ENGINE=""
    if command -v podman >/dev/null 2>&1; then
        ENGINE="podman"
    elif command -v docker >/dev/null 2>&1; then
        ENGINE="docker"
    else
        echo "WARN: no podman/docker found; cannot export tarball" >&2
        echo "      (image should still exist in buildah's storage)" >&2
        exit 0
    fi

    echo "Exporting $TAG → $OUT_TAR via $ENGINE"
    if ! "$ENGINE" image save --output "$OUT_TAR" "$TAG"; then
        echo "ERROR: image save failed" >&2
        exit 4
    fi
    sha256sum "$OUT_TAR" > "${OUT_TAR}.sha256"
    ls -lh "$OUT_TAR" "${OUT_TAR}.sha256"
fi
echo "--- export done in $(_mins $(( $(date +%s) - T_EXPORT_START ))) ---"
echo ""
echo "=== bootc pipeline complete ==="
echo "    smoke-test: podman run --rm -it --entrypoint /bin/bash $TAG"
echo "    further:    see docs/bootc-phase2.md"
