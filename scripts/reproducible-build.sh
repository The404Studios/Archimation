#!/bin/bash
# reproducible-build.sh - Best-effort deterministic package build.
#
# Sets the reproducible-builds.org canonical env vars (SOURCE_DATE_EPOCH
# et al.) then hands off to scripts/build-packages.sh. Extra args are
# forwarded (e.g. --force, --dry-run).
#
# ── What this guarantees ───────────────────────────────────────────────────
# - File mtimes inside packages are clamped to SOURCE_DATE_EPOCH.
# - Kernel-build timestamps (used by dkms modules embedding __DATE__ /
#   __TIME__) match the commit time.
# - Locale-dependent sort orders (ls, sort, find) produce C-locale output.
# - Timezone-dependent output (date, logs, tar headers) uses UTC.
# - Python dict / set iteration order is hash-seed-stable.
#
# ── What this does NOT guarantee ───────────────────────────────────────────
# Bytewise-identical ISO output additionally requires:
#   - Identical mkarchiso version
#   - Identical package cache (same pacman mirror timestamps)
#   - Identical kernel-headers / linux package versions
#   - Identical gcc / glibc versions
#   - Identical squashfs-tools version (compression algorithm tuning)
#   - Identical grub / syslinux (embedded config + bootloader bytes)
# If any of those drift between builds, the ISO hash will differ even
# though the *sources* are reproducibly timestamped.
#
# For binary reproducibility, pin those versions via an Arch archive
# snapshot (https://archive.archlinux.org/repos/YYYY/MM/DD/) and rebuild
# inside that snapshot container. This script does not do that for you —
# it's best-effort.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

# ── Deterministic timestamp ─────────────────────────────────────────────────
# Prefer SOURCE_DATE_EPOCH if already set (e.g. by a higher-level CI).
# Otherwise derive from the last commit. Fall back to `date -u +%s` if the
# directory isn't a git checkout (e.g. tarball build).
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    if git -C "$PROJECT_DIR" rev-parse --git-dir >/dev/null 2>&1; then
        SOURCE_DATE_EPOCH="$(git -C "$PROJECT_DIR" log -1 --format=%ct 2>/dev/null || date -u +%s)"
    else
        SOURCE_DATE_EPOCH="$(date -u +%s)"
    fi
fi
export SOURCE_DATE_EPOCH
export KBUILD_BUILD_TIMESTAMP="@$SOURCE_DATE_EPOCH"

# Canonical reproducible-builds locale & timezone.
export LC_ALL=C
export LANG=C
export TZ=UTC

# Deterministic Python hash seed.
export PYTHONHASHSEED=0

# Stabilize a few more common variables that creep into toolchain output.
export KBUILD_BUILD_USER="${KBUILD_BUILD_USER:-builder}"
export KBUILD_BUILD_HOST="${KBUILD_BUILD_HOST:-ai-arch}"

# Ensure a canonical umask so installed-file modes don't drift.
umask 022

echo "reproducible-build: SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH ($(date -u -d @$SOURCE_DATE_EPOCH 2>/dev/null || echo '<bad epoch>'))"
echo "reproducible-build: TZ=UTC LC_ALL=C PYTHONHASHSEED=0"
echo "reproducible-build: NOTE - bytewise determinism also requires identical toolchain & pacman mirror snapshot."

exec bash "$SCRIPT_DIR/build-packages.sh" "$@"
