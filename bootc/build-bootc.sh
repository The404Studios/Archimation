#!/bin/bash
# build-bootc.sh — orchestrator for ARCHIMATION bootc image builds.
#
# Session 72 / Agent α / Phase 1 foundation. Wraps `buildah build` (preferred,
# rootless) or `podman build` (fallback) and ties together:
#   - our local pacman repo at repo/x86_64/       (bind-mounted into RUN steps)
#   - our archiso airootfs at profile/airootfs/   (COPY'd verbatim into /)
#   - our Containerfile at bootc/Containerfile    (the actual build graph)
#
# Output: a local OCI image tagged `archimation-bootc:dev` (override with $TAG).
# Smoke-test: `podman run --rm -it archimation-bootc:dev /bin/bash`
# Deploy:     `bootc install to-disk /dev/sdX` (from within the image, booted)
# Upgrade:    `bootc upgrade` (user-facing, on deployed system)
#
# DOES NOT run the build automatically if ARCHIMATION_BOOTC_DRYRUN=1 is set;
# it just prints the command it would run. That's the default way to smoke
# this script on WSL2 where podman may not be installed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

TAG="${TAG:-archimation-bootc:dev}"
CONTAINERFILE="${CONTAINERFILE:-bootc/Containerfile}"
DRYRUN="${ARCHIMATION_BOOTC_DRYRUN:-0}"

# ---- sanity --------------------------------------------------------------------
if [ ! -f "$CONTAINERFILE" ]; then
    echo "FATAL: $CONTAINERFILE not found (wrong cwd?)" >&2
    exit 2
fi

if [ ! -d repo/x86_64 ]; then
    echo "FATAL: repo/x86_64/ missing — run scripts/build-packages.sh first." >&2
    echo "       (bootc build needs our custom packages as a pacman source.)" >&2
    exit 2
fi

PKG_COUNT="$(find repo/x86_64 -maxdepth 1 -name '*.pkg.tar.zst' 2>/dev/null | wc -l)"
if [ "$PKG_COUNT" -lt 5 ]; then
    echo "WARN: only $PKG_COUNT packages in repo/x86_64/ — build may fail on pacman -S." >&2
    echo "      Expected ~9: ai-control-daemon, ai-desktop-config, ai-firewall," >&2
    echo "      ai-first-boot-wizard, pe-loader, trust-system, windows-services, etc." >&2
fi

if [ ! -d profile/airootfs ]; then
    echo "FATAL: profile/airootfs/ missing — nothing to COPY into image." >&2
    exit 2
fi

# ---- pick a builder ------------------------------------------------------------
BUILDER=""
if command -v buildah >/dev/null 2>&1; then
    BUILDER="buildah"
elif command -v podman >/dev/null 2>&1; then
    BUILDER="podman"
elif command -v docker >/dev/null 2>&1; then
    # docker works but lacks buildah's rootless-friendly bind-mount semantics;
    # the Containerfile uses --mount=type=bind which docker's BuildKit supports
    # since 20.10+. Warn but proceed.
    BUILDER="docker"
    echo "WARN: using docker (buildah/podman preferred for rootless bootc builds)" >&2
else
    echo "FATAL: none of buildah, podman, docker found in PATH." >&2
    echo "       Install:  pacman -S buildah podman   (on the Arch host)" >&2
    exit 3
fi

# ---- assemble command ----------------------------------------------------------
case "$BUILDER" in
    buildah)
        CMD=(buildah build
             --file "$CONTAINERFILE"
             --tag "$TAG"
             --layers
             --format oci
             .)
        ;;
    podman)
        CMD=(podman build
             --file "$CONTAINERFILE"
             --tag "$TAG"
             --format oci
             .)
        ;;
    docker)
        CMD=(docker buildx build
             --file "$CONTAINERFILE"
             --tag "$TAG"
             --load
             .)
        ;;
esac

# ---- run (or print) ------------------------------------------------------------
echo "=== ARCHIMATION bootc build ==="
echo "    builder:       $BUILDER"
echo "    tag:           $TAG"
echo "    containerfile: $CONTAINERFILE"
echo "    local pkgs:    $PKG_COUNT in repo/x86_64/"
echo "    workdir:       $PROJECT_DIR"
echo ""

if [ "$DRYRUN" = "1" ]; then
    echo "DRY-RUN (ARCHIMATION_BOOTC_DRYRUN=1). Would run:"
    printf '    %q ' "${CMD[@]}"
    echo ""
    exit 0
fi

echo "Building (this will download ~600 MB of Arch packages on first run)..."
echo "+ ${CMD[*]}"
"${CMD[@]}"

# ---- next-steps hint -----------------------------------------------------------
cat <<EOF

=== Build complete ===

Smoke-test the image (runs as a plain container, NOT a real boot):
    podman run --rm -it --entrypoint /bin/bash $TAG
    podman run --rm -it --entrypoint /bin/bash $TAG -c 'ls /usr/bin/pe-loader /usr/bin/ai-control-daemon 2>/dev/null'
    podman run --rm -it --entrypoint /bin/bash $TAG -c 'pacman -Q | wc -l'

Deploy to a real disk (destructive, requires booting into the image first):
    # From within a booted instance of the image:
    bootc install to-disk /dev/sdX

Upgrade a deployed system (user-facing):
    bootc upgrade
    systemctl reboot    # new image only takes effect at next boot

Rollback (if upgrade broke something):
    bootc rollback
    systemctl reboot

See bootc/README.md for the full story, and docs/research/s72_alpha_bootc_foundation.md
for the foundation-choice rationale.
EOF
