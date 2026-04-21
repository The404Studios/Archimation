#!/usr/bin/env bash
# bootc/build-trust-module.sh — Image-build-time compile + sign of trust.ko
#
# Agent beta / S72 Phase 1 — DKMS→bootc transition.
#
# This script replaces DKMS first-boot build with a deterministic,
# signed, image-construction-time build. It runs inside the bootc
# Containerfile build (mode=bootc) or inside the archiso package
# build (mode=archiso). In bootc mode the signed trust.ko is placed
# at /usr/lib/modules/<kver>/extra/trust.ko so it is part of the
# immutable OCI image and loads before userspace. In archiso mode it
# preserves the historic DKMS path — emit the tarball where
# trust-dkms.install can still invoke dkms build on target.
#
# Inputs (env):
#   KERNEL_VERSION   required, kernel pinned by bootc base layer
#                    (e.g. 6.12.4-arch1-1). In archiso mode, falls back
#                    to the uname -r of the build container.
#   TRUST_SRC_DIR    optional, default /src/trust (bootc) or
#                    $(realpath $(dirname $0)/../trust) (archiso).
#   SIGNING_KEY_PEM  optional path to PEM private key. Can be empty — in
#                    that case we emit an unsigned .ko and WARN. In
#                    bootc mode this is fatal unless ALLOW_UNSIGNED=1.
#   SIGNING_CERT_DER optional path to DER public cert. Paired with key.
#   BOOTC_MODE       "bootc" or "archiso". Auto-detected if unset:
#                    presence of /run/.containerenv or $CI → bootc.
#   OUT_DIR          where the final signed trust.ko lands (bootc mode
#                    default /usr/lib/modules/$KERNEL_VERSION/extra;
#                    archiso default writes to $TRUST_SRC_DIR/build/).
#   ALLOW_UNSIGNED   if "1", bootc mode will not abort when SIGNING_KEY
#                    is absent (used for CI smoke before keys land).
#
# Exit 0 on success. Any failure during compile or sign is fatal.
#
# Determinism note: SOURCE_DATE_EPOCH from env is honored by the
# kernel's Kbuild; we set it explicitly from git HEAD if unset so the
# OCI image layer diff is clean across rebuilds of identical source.

set -euo pipefail

log() { printf '[build-trust-module] %s\n' "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

# ─── Mode detection ──────────────────────────────────────────────────
_detect_mode() {
    if [ -n "${BOOTC_MODE:-}" ]; then
        echo "$BOOTC_MODE"; return
    fi
    if [ -f /run/.containerenv ] || [ -n "${CI:-}" ] || [ -n "${BOOTC_BUILD:-}" ]; then
        echo "bootc"; return
    fi
    echo "archiso"
}
BOOTC_MODE="$(_detect_mode)"
log "mode=$BOOTC_MODE"

# ─── Kernel version resolution ───────────────────────────────────────
if [ -z "${KERNEL_VERSION:-}" ]; then
    if [ "$BOOTC_MODE" = "archiso" ]; then
        KERNEL_VERSION="$(uname -r)"
        log "archiso: using running kernel $KERNEL_VERSION"
    else
        die "KERNEL_VERSION required in bootc mode"
    fi
fi

# Verify kernel headers exist for this version
KHDR="/usr/lib/modules/${KERNEL_VERSION}/build"
[ -d "$KHDR" ] || die "kernel headers not found at $KHDR (need linux-headers-${KERNEL_VERSION}?)"
log "kernel headers: $KHDR"

# ─── Source tree location ────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRUST_SRC_DIR="${TRUST_SRC_DIR:-$SCRIPT_DIR/../trust}"
[ -d "$TRUST_SRC_DIR/kernel" ] || die "trust kernel sources not at $TRUST_SRC_DIR/kernel"
[ -f "$TRUST_SRC_DIR/kernel/Kbuild" ] || die "$TRUST_SRC_DIR/kernel/Kbuild missing"
log "trust source: $TRUST_SRC_DIR"

# ─── Determinism: SOURCE_DATE_EPOCH ──────────────────────────────────
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    if command -v git >/dev/null 2>&1 && [ -d "$TRUST_SRC_DIR/.git" ] || \
       git -C "$TRUST_SRC_DIR" rev-parse --git-dir >/dev/null 2>&1; then
        SOURCE_DATE_EPOCH="$(git -C "$TRUST_SRC_DIR" log -1 --pretty=%ct 2>/dev/null || echo 0)"
    fi
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
fi
export SOURCE_DATE_EPOCH
log "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"

# ─── Output directory ────────────────────────────────────────────────
if [ -z "${OUT_DIR:-}" ]; then
    if [ "$BOOTC_MODE" = "bootc" ]; then
        OUT_DIR="/usr/lib/modules/${KERNEL_VERSION}/extra"
    else
        OUT_DIR="$TRUST_SRC_DIR/build"
    fi
fi
mkdir -p "$OUT_DIR"
log "out: $OUT_DIR"

# ─── Work directory ──────────────────────────────────────────────────
WORK="$(mktemp -d -t trustko-build-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
log "work: $WORK"

# Copy sources (flat, matching dkms layout)
install -d "$WORK/include"
cp -t "$WORK" "$TRUST_SRC_DIR/kernel/"*.c "$TRUST_SRC_DIR/kernel/"*.h "$TRUST_SRC_DIR/kernel/Kbuild"
cp -t "$WORK/include" "$TRUST_SRC_DIR/include/trust_types.h" \
                     "$TRUST_SRC_DIR/include/trust_ioctl.h" \
                     "$TRUST_SRC_DIR/include/trust_uapi.h" \
                     "$TRUST_SRC_DIR/include/trust_chromosome.h"

# ─── Generate autoconf.h if missing (Arch quirk) ─────────────────────
# Arch's linux-headers omits include/generated/autoconf.h; DKMS's install
# script regenerates it from auto.conf, and we do the same here so the
# build container doesn't need the trust-dkms package installed.
_gen_autoconf_if_missing() {
    local autoconf="$KHDR/include/generated/autoconf.h"
    local auto_conf="$KHDR/include/config/auto.conf"
    [ -f "$autoconf" ] && return 0
    [ -f "$auto_conf" ] || { log "WARN: neither autoconf.h nor auto.conf present in $KHDR"; return 0; }
    log "generating $autoconf from auto.conf"
    mkdir -p "$KHDR/include/generated"
    awk '
        /^[[:space:]]*#/ { next }
        /^CONFIG_[A-Z0-9_]+=y$/ { sub(/=y$/, ""); printf "#define %s 1\n", $0; next }
        /^CONFIG_[A-Z0-9_]+=m$/ { sub(/=m$/, ""); printf "#define %s_MODULE 1\n", $0; next }
        /^CONFIG_[A-Z0-9_]+=$/  { sub(/=$/, "");  printf "#define %s \"\"\n", $0; next }
        /^CONFIG_[A-Z0-9_]+=/ {
            n = index($0, "="); key = substr($0, 1, n-1); val = substr($0, n+1);
            printf "#define %s %s\n", key, val
        }
    ' "$auto_conf" > "$autoconf"
}
_gen_autoconf_if_missing

# ─── Compile ─────────────────────────────────────────────────────────
log "compiling trust.ko against $KERNEL_VERSION"
# -j is bounded: bootc builds run in CI with limited parallelism; capping at
# nproc prevents spawning 64 cc1's on a big runner when only 8 cores are
# allocated to the container. SOURCE_DATE_EPOCH exported earlier guarantees
# deterministic timestamps in the resulting .ko.
make -C "$KHDR" M="$WORK" modules -j"$(nproc 2>/dev/null || echo 2)" \
    KBUILD_EXTMOD="$WORK" \
    KCPPFLAGS="-DARCHWINDOWS_BOOTC_BUILD=1" \
    >&2

KO="$WORK/trust.ko"
[ -f "$KO" ] || die "compile produced no trust.ko"
log "compiled: $(stat -c '%n %s bytes' "$KO" 2>/dev/null || echo "$KO")"

# Strip debug info for determinism AND size. The kernel signs the full ELF
# including debuginfo, and strip ordering matters: signing must happen AFTER
# stripping because the signature is an append-only trailer outside the ELF
# container (see kernel Documentation/admin-guide/module-signing.rst).
if command -v strip >/dev/null 2>&1; then
    strip --strip-debug "$KO" 2>/dev/null || log "WARN: strip --strip-debug failed (non-fatal)"
    log "stripped debuginfo: $(stat -c %s "$KO") bytes"
fi

# ─── Sign ────────────────────────────────────────────────────────────
SIGN_TOOL="$KHDR/scripts/sign-file"
if [ ! -x "$SIGN_TOOL" ]; then
    # Some kernel-headers packages miss sign-file exec bit; try fallback
    if [ -f "$SIGN_TOOL" ]; then
        chmod +x "$SIGN_TOOL" 2>/dev/null || true
    fi
fi

_signing_available() {
    [ -n "${SIGNING_KEY_PEM:-}" ] && [ -f "${SIGNING_KEY_PEM:-/dev/null}" ] &&
    [ -n "${SIGNING_CERT_DER:-}" ] && [ -f "${SIGNING_CERT_DER:-/dev/null}" ] &&
    [ -x "$SIGN_TOOL" ]
}

if _signing_available; then
    log "signing with SIGNING_KEY_PEM=$SIGNING_KEY_PEM SIGNING_CERT_DER=$SIGNING_CERT_DER"
    "$SIGN_TOOL" sha256 "$SIGNING_KEY_PEM" "$SIGNING_CERT_DER" "$KO"
    # Verify the signature appended
    if tail -c 28 "$KO" | grep -q 'Module signature appended'; then
        log "signature appended (Module signature appended sentinel present)"
    else
        die "sign-file reported success but sentinel missing"
    fi
else
    if [ "$BOOTC_MODE" = "bootc" ] && [ "${ALLOW_UNSIGNED:-0}" != "1" ]; then
        die "bootc mode requires signed modules; set SIGNING_KEY_PEM + SIGNING_CERT_DER, or set ALLOW_UNSIGNED=1 for CI smoke"
    fi
    log "WARN: building unsigned trust.ko (archiso compat mode or ALLOW_UNSIGNED=1)"
    log "WARN: this module will REFUSE TO LOAD under lockdown=integrity or Secure Boot with no MOK"
fi

# ─── Install ─────────────────────────────────────────────────────────
install -Dm644 "$KO" "$OUT_DIR/trust.ko"
log "installed: $OUT_DIR/trust.ko ($(stat -c %s "$OUT_DIR/trust.ko") bytes)"

# In bootc mode, also run depmod so modprobe trust works in the OCI image.
# In archiso mode leave depmod to trust-dkms.install / runtime.
if [ "$BOOTC_MODE" = "bootc" ]; then
    if command -v depmod >/dev/null 2>&1; then
        depmod -a "$KERNEL_VERSION" 2>&1 | sed 's/^/[depmod] /' >&2 || \
            log "WARN: depmod failed; modprobe trust will need manual depmod on first boot"
    else
        log "WARN: depmod not available in build env; modprobe trust needs manual depmod on first boot"
    fi
fi

log "done."
exit 0
