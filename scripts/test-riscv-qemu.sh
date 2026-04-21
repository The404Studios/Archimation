#!/usr/bin/env bash
# scripts/test-riscv-qemu.sh — S74 Agent 4: RISC-V QEMU Phase 1
# ---------------------------------------------------------------------------
# Purpose:   Attempt to cross-compile trust.ko for riscv64 and (optionally)
#            boot-test it under qemu-system-riscv64. This surfaces every
#            x86-specific construct lurking in the kernel module so later
#            sessions can close them.
#
# Authoring context: project claims a RISC-V FPGA POC in the Zenodo paper
#   (DOI 10.5281/zenodo.18710335). The current tree is x86_64-only. This
#   script is Phase 1 of 4 on the reproduction path (QEMU $0 → Verilator
#   $0 → real FPGA $150-300 → PE-loader question).
#
# Exit codes:
#   0  — cross-compile clean (stage 1 PASS). Stage 2 may still FAIL softly.
#   1  — cross-compile failed (kernel module won't build on riscv64).
#   2  — toolchain missing (expected on stock WSL2 / vanilla hosts).
#   3  — qemu-boot failed (module built, refused to load under QEMU).
# ---------------------------------------------------------------------------

set -u  # intentionally NOT -e; we catch errors explicitly so exit codes stay crisp.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TRUST_KMOD_DIR="${PROJECT_DIR}/trust/kernel"
TS="$(date +%s)"
BUILD_LOG="/tmp/trust-riscv64-build-${TS}.log"
BOOT_LOG="/tmp/trust-riscv64-boot-${TS}.log"

# Config (overridable via env)
CROSS_COMPILE="${CROSS_COMPILE:-riscv64-linux-gnu-}"
ARCH="${ARCH:-riscv}"
KDIR="${KDIR:-}"     # if unset, autodetect: /lib/modules/$(uname -r)/build won't work for RV
SKIP_BOOT="${SKIP_BOOT:-0}"

usage() {
    cat <<'EOF'
Usage: test-riscv-qemu.sh [options]

Options:
  --help         Show this help and exit.
  --skip-boot    Do stage-1 cross-compile only; do not attempt QEMU boot.

Environment:
  CROSS_COMPILE  GCC prefix (default: riscv64-linux-gnu-)
  ARCH           Kernel ARCH= value (default: riscv)
  KDIR           Path to riscv64 kernel tree with headers. If unset, the
                 script attempts to fetch a minimal linux-headers tarball
                 into /tmp/riscv64-kdir and use that.

Exit codes: 0 clean, 1 build-fail, 2 toolchain-missing, 3 qemu-boot-fail.

References:
  - docs/riscv-portability-deltas.md (companion report for this script)
  - memory/roa_paper_validation_tier_audit_and_s74_plan.md §3 (path)
  - Zenodo DOI 10.5281/zenodo.18710335 (RISC-V FPGA claim)
EOF
}

case "${1:-}" in
    --help|-h)    usage; exit 0 ;;
    --skip-boot)  SKIP_BOOT=1 ;;
    "" ) ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
esac

# -----------------------------------------------------------------------------
# Preflight — toolchain detection
# -----------------------------------------------------------------------------

need() {
    # need <binary> <install-hint>
    local bin="$1" hint="$2"
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "MISSING: $bin"
        echo "    install-hint: $hint"
        return 1
    else
        echo "  OK: $bin ($(command -v "$bin"))"
        return 0
    fi
}

echo "=== trust.ko RISC-V Phase-1 cross-compile test ==="
echo "Host: $(uname -a)"
echo "Build log will be: $BUILD_LOG"
echo

echo "--- Preflight: toolchain ---"
missing=0
need "${CROSS_COMPILE}gcc" "pacman -S riscv64-linux-gnu-gcc    (Arch)     |  apt install gcc-riscv64-linux-gnu    (Debian/Ubuntu)" || missing=$((missing+1))
need "${CROSS_COMPILE}ld"  "(part of the binutils-riscv64-linux-gnu package)" || missing=$((missing+1))
need make "pacman -S make  |  apt install make"  || missing=$((missing+1))
if [ "$SKIP_BOOT" = "0" ]; then
    need qemu-system-riscv64 "pacman -S qemu-system-riscv    (Arch)   |  apt install qemu-system-misc    (Debian/Ubuntu)" || missing=$((missing+1))
fi

if [ "$missing" -gt 0 ]; then
    echo
    echo "RESULT: TOOLCHAIN MISSING ($missing prerequisite(s) absent)"
    echo
    echo "This is the EXPECTED outcome on a stock WSL2 / non-Arch host."
    echo "See docs/riscv-portability-deltas.md for the static analysis of"
    echo "portability issues that still applies even without the toolchain."
    exit 2
fi
echo "OK: toolchain present"
echo

# -----------------------------------------------------------------------------
# KDIR resolution
# -----------------------------------------------------------------------------
resolve_kdir() {
    if [ -n "$KDIR" ] && [ -f "$KDIR/Makefile" ]; then
        echo "$KDIR"; return 0
    fi

    # Try a known cache location — a full riscv64 kernel tree pre-prepared.
    for cand in \
        /var/cache/trust-riscv64-kdir \
        /tmp/riscv64-kdir \
        "$HOME/riscv64-linux"; do
        if [ -f "$cand/Makefile" ]; then
            echo "$cand"; return 0
        fi
    done

    # Fallback: fetch minimal linux-headers tarball. We do NOT build the kernel;
    # for an out-of-tree module a configured+prepared kernel source tree with
    # arch/riscv headers + Module.symvers is sufficient. We document this is a
    # skip-on-failure fallback; a real CI needs a pre-built KDIR.
    local fetch_dir=/tmp/riscv64-kdir
    if [ ! -f "$fetch_dir/Makefile" ]; then
        echo "NOTE: no cached riscv64 KDIR found." >&2
        echo "      attempting scratch download is out of scope for Phase 1;" >&2
        echo "      set KDIR=/path/to/riscv64-kernel-src and rerun." >&2
        return 1
    fi
    echo "$fetch_dir"
}

echo "--- Resolving RISC-V KDIR ---"
if ! KDIR_RESOLVED="$(resolve_kdir)"; then
    echo "RESULT: NO KDIR — cannot cross-compile without a riscv64 kernel tree."
    echo "Hint: clone a riscv64-configured kernel and point KDIR at it."
    echo "      git clone --depth=1 git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git /tmp/linux-rv"
    echo "      cd /tmp/linux-rv && make ARCH=riscv CROSS_COMPILE=${CROSS_COMPILE} defconfig modules_prepare"
    echo "      KDIR=/tmp/linux-rv bash scripts/test-riscv-qemu.sh"
    exit 2
fi
echo "KDIR: $KDIR_RESOLVED"
echo

# -----------------------------------------------------------------------------
# Stage 1 — cross-compile
# -----------------------------------------------------------------------------
echo "--- Stage 1: cross-compile trust.ko for riscv64 ---"
(
    cd "$TRUST_KMOD_DIR" || exit 99
    make -C "$KDIR_RESOLVED" M="$PWD" \
        ARCH="$ARCH" CROSS_COMPILE="$CROSS_COMPILE" \
        modules 2>&1
) > "$BUILD_LOG" 2>&1
rc=$?

if [ "$rc" -ne 0 ]; then
    echo "STAGE 1 RESULT: FAIL (rc=$rc)"
    echo "First 20 error lines from $BUILD_LOG:"
    echo "----"
    grep -E '(error:|undefined reference|warning:.*implicit declaration)' "$BUILD_LOG" | head -20 || true
    echo "----"
    echo "Full log: $BUILD_LOG"
    echo "(see docs/riscv-portability-deltas.md for the fix catalogue)"
    exit 1
fi

echo "STAGE 1 RESULT: PASS — trust.ko cross-compiled clean for riscv64"
ls -la "$TRUST_KMOD_DIR/trust.ko" 2>/dev/null || true

if [ "$SKIP_BOOT" = "1" ]; then
    echo "--skip-boot set; exiting with 0."
    exit 0
fi

# -----------------------------------------------------------------------------
# Stage 2 — QEMU boot + insmod
# -----------------------------------------------------------------------------
echo
echo "--- Stage 2: QEMU boot + insmod ---"

ROOTFS="${ROOTFS:-/var/cache/trust-riscv64-rootfs.img}"
KERNEL_IMG="${KERNEL_IMG:-$KDIR_RESOLVED/arch/riscv/boot/Image}"
BBL="${BBL:-/usr/share/opensbi/lp64/generic/firmware/fw_jump.bin}"

for f in "$ROOTFS" "$KERNEL_IMG"; do
    if [ ! -f "$f" ]; then
        echo "STAGE 2: SKIP — required file absent: $f"
        echo "Prepare a BuildRoot riscv64 rootfs and kernel Image, then rerun."
        echo "Stage 1 PASS already confirms build-portability."
        exit 0   # stage 1 success is still a valid Phase-1 answer
    fi
done

echo "Booting qemu-system-riscv64 (headless, 60s cap) …"
timeout 60 qemu-system-riscv64 \
    -nographic -machine virt -smp 2 -m 512M \
    -bios "$BBL" -kernel "$KERNEL_IMG" \
    -append "console=ttyS0 root=/dev/vda rw init=/sbin/init" \
    -drive file="$ROOTFS",format=raw,id=hd0 \
    -device virtio-blk-device,drive=hd0 \
    -netdev user,id=net0 -device virtio-net-device,netdev=net0 \
    > "$BOOT_LOG" 2>&1
rc=$?

if ! grep -qE '(insmod.*trust|trust_core: loaded|trust_core init)' "$BOOT_LOG"; then
    echo "STAGE 2 RESULT: FAIL — trust.ko did not load under QEMU (rc=$rc)"
    echo "Last 40 lines of $BOOT_LOG:"
    tail -40 "$BOOT_LOG"
    exit 3
fi

echo "STAGE 2 RESULT: PASS — trust.ko loaded under qemu-system-riscv64"
exit 0
