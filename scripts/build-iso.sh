#!/bin/bash
# Build the custom Arch Linux ISO using mkarchiso
# Supports parallel asset generation, reflector mirror selection, pacman
# cache reuse, and pre-flight disk-space checks.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PROFILE_DIR="$PROJECT_DIR/profile"
OUTPUT_DIR="$PROJECT_DIR/output"

# Use native Linux filesystem for work dir when building on NTFS/WSL.
# NTFS causes permission errors and can't represent Unix special files
# (symlinks, device nodes) that pacman needs during package extraction.
if [[ "$PROJECT_DIR" == /mnt/* ]]; then
    WORK_DIR="/tmp/ai-arch-build/work"
    echo "NOTE: Project is on NTFS, using native Linux workdir: $WORK_DIR"
else
    WORK_DIR="$PROJECT_DIR/work"
fi

# Persistent pacman cache — shared across ISO rebuilds. Saves 2-5 minutes
# of repeated downloads per build. Lives under /var/cache/pacman/pkg by
# default (what pacstrap uses). Keep it unless you need a clean slate.
PACMAN_CACHE="${PACMAN_CACHE:-/var/cache/pacman/pkg}"
# CPU core count propagated to xz/zstd compression
: "${JOBS:=$(nproc 2>/dev/null || echo 4)}"
export JOBS

echo "=== Building AI Control Linux ISO ==="
echo "Profile:       $PROFILE_DIR"
echo "Work dir:      $WORK_DIR"
echo "Output:        $OUTPUT_DIR"
echo "Pacman cache:  $PACMAN_CACHE"
echo "Parallel jobs: $JOBS"
echo ""

# Step timing for CI logs
_step_start() { STEP_NAME="$1"; STEP_T0=$(date +%s); echo "=== [$(date +%H:%M:%S)] $STEP_NAME ==="; }
_step_end()   { local dt=$(( $(date +%s) - STEP_T0 )); echo "=== [$(date +%H:%M:%S)] $STEP_NAME done (${dt}s) ==="; }

# Pre-flight: ISO builds burn ~6 GB in /tmp for work/ plus ~3 GB for the final
# squashfs. Fail fast if disk is low rather than dying halfway through squashfs.
_preflight_space() {
    local target_dir="$1" need_mb="$2"
    # Walk up until we find an existing parent to probe
    while [ ! -d "$target_dir" ] && [ "$target_dir" != "/" ]; do
        target_dir=$(dirname "$target_dir")
    done
    local avail
    avail=$(df -m "$target_dir" 2>/dev/null | awk 'NR==2 {print $4}')
    if [ -z "$avail" ]; then return 0; fi
    if [ "$avail" -lt "$need_mb" ]; then
        echo "WARNING: $target_dir has only ${avail} MB free, need ~${need_mb} MB." >&2
        echo "         ISO build may fail with ENOSPC partway through squashfs." >&2
    fi
}
_preflight_space "$WORK_DIR" 8192
_preflight_space "$OUTPUT_DIR" 4096

# Resolve the local repo path in pacman.conf
_step_start "Configuring pacman.conf"
REPO_DIR="$PROJECT_DIR/repo/x86_64"
if [ -f "$PROFILE_DIR/pacman.conf" ]; then
    sed -i "s|Server = file://.*|Server = file://${REPO_DIR}|" "$PROFILE_DIR/pacman.conf"
fi
_step_end

# --- Optional: refresh mirrorlist with reflector before pacstrap ---
# Only runs when REFLECTOR=1 is set to avoid slowing down the common path.
# Saves 10-30+ minutes when the default mirror is distant/slow.
if [ "${REFLECTOR:-0}" = "1" ] && command -v reflector >/dev/null 2>&1; then
    _step_start "Refreshing mirrorlist (reflector)"
    sudo reflector --age 12 --latest 20 --protocol https --sort rate \
         --save /etc/pacman.d/mirrorlist 2>&1 | tail -3 || \
         echo "WARNING: reflector failed; keeping existing mirrorlist"
    _step_end
fi

# Generate GRUB theme assets (fonts + background + selection highlight).
# These are idempotent: skip when already up to date to save 5-10s per rebuild.
THEME_DIR="$PROFILE_DIR/grub/themes/archwindows"
if [ -d "$THEME_DIR" ]; then
    _step_start "Generating GRUB theme assets"
    DEJAVU_TTF="/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    DEJAVU_BOLD_TTF="/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
    # Try alternate paths (Arch vs Debian font locations)
    [ -f "$DEJAVU_TTF" ] || DEJAVU_TTF="/usr/share/fonts/TTF/DejaVuSans.ttf"
    [ -f "$DEJAVU_BOLD_TTF" ] || DEJAVU_BOLD_TTF="/usr/share/fonts/TTF/DejaVuSans-Bold.ttf"

    # Skip font regen if every expected output exists AND is newer than the TTF source
    _need_fonts=1
    if [ -f "$DEJAVU_TTF" ] && \
       [ -f "$THEME_DIR/DejaVu_Sans_Regular_10.pf2" ] && \
       [ -f "$THEME_DIR/DejaVu_Sans_Regular_12.pf2" ] && \
       [ -f "$THEME_DIR/DejaVu_Sans_Regular_14.pf2" ] && \
       [ -f "$THEME_DIR/DejaVu_Sans_Bold_14.pf2" ] && \
       [ -f "$THEME_DIR/DejaVu_Sans_Bold_24.pf2" ] && \
       [ "$THEME_DIR/DejaVu_Sans_Regular_10.pf2" -nt "$DEJAVU_TTF" ]; then
        _need_fonts=0
        echo "  GRUB theme fonts up to date — skipping regen"
    fi

    if [ "$_need_fonts" = "1" ] && command -v grub-mkfont &>/dev/null && [ -f "$DEJAVU_TTF" ]; then
        # Generate all 5 .pf2 files in parallel (independent outputs)
        grub-mkfont -s 10 -o "$THEME_DIR/DejaVu_Sans_Regular_10.pf2" "$DEJAVU_TTF" &
        grub-mkfont -s 12 -o "$THEME_DIR/DejaVu_Sans_Regular_12.pf2" "$DEJAVU_TTF" &
        grub-mkfont -s 14 -o "$THEME_DIR/DejaVu_Sans_Regular_14.pf2" "$DEJAVU_TTF" &
        grub-mkfont -s 14 -o "$THEME_DIR/DejaVu_Sans_Bold_14.pf2"    "$DEJAVU_BOLD_TTF" &
        grub-mkfont -s 24 -o "$THEME_DIR/DejaVu_Sans_Bold_24.pf2"    "$DEJAVU_BOLD_TTF" &
        wait
        echo "  Generated .pf2 theme fonts (parallel)"
    elif [ "$_need_fonts" = "1" ]; then
        echo "  WARNING: grub-mkfont or DejaVu TTF not found, skipping theme font generation"
        echo "  Theme will fall back to GRUB default font"
    fi

    # Generate background.png (1920x1080 Tokyo Night gradient) using Python.
    # Skip when the file already exists — content is deterministic.
    if [ ! -f "$THEME_DIR/background.png" ] && command -v python3 &>/dev/null; then
        python3 -c "
import struct, zlib

W, H = 1920, 1080
# Tokyo Night gradient: #1a1b26 (top) -> #24283b (bottom)
r0, g0, b0 = 0x1a, 0x1b, 0x26
r1, g1, b1 = 0x24, 0x28, 0x3b

raw = b''
for y in range(H):
    t = y / (H - 1)
    r = int(r0 + (r1 - r0) * t)
    g = int(g0 + (g1 - g0) * t)
    b = int(b0 + (b1 - b0) * t)
    raw += b'\x00' + bytes([r, g, b]) * W

def png_chunk(ctype, data):
    c = ctype + data
    return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

hdr = struct.pack('>IIBBBBB', W, H, 8, 2, 0, 0, 0)
with open('$THEME_DIR/background.png', 'wb') as f:
    f.write(b'\x89PNG\r\n\x1a\n')
    f.write(png_chunk(b'IHDR', hdr))
    f.write(png_chunk(b'IDAT', zlib.compress(raw, 9)))
    f.write(png_chunk(b'IEND', b''))
" && echo "  Generated background.png (1920x1080 Tokyo Night gradient)" \
        || echo "  WARNING: Failed to generate background.png"
    fi

    # Generate select_c.png (selection highlight bar, #7aa2f7 accent)
    if [ ! -f "$THEME_DIR/select_c.png" ] && command -v python3 &>/dev/null; then
        python3 -c "
import struct, zlib

W, H = 4, 36
r, g, b = 0x7a, 0xa2, 0xf7
raw = b''
for y in range(H):
    raw += b'\x00' + bytes([r, g, b]) * W

def png_chunk(ctype, data):
    c = ctype + data
    return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

hdr = struct.pack('>IIBBBBB', W, H, 8, 2, 0, 0, 0)
with open('$THEME_DIR/select_c.png', 'wb') as f:
    f.write(b'\x89PNG\r\n\x1a\n')
    f.write(png_chunk(b'IHDR', hdr))
    f.write(png_chunk(b'IDAT', zlib.compress(raw, 9)))
    f.write(png_chunk(b'IEND', b''))
" && echo "  Generated select_c.png (accent selection bar)" \
        || echo "  WARNING: Failed to generate select_c.png"
    fi

    # Generate scrollbar_thumb_c.png (small scrollbar thumb)
    if [ ! -f "$THEME_DIR/scrollbar_thumb_c.png" ] && command -v python3 &>/dev/null; then
        python3 -c "
import struct, zlib

W, H = 4, 16
r, g, b = 0x41, 0x48, 0x68
raw = b''
for y in range(H):
    raw += b'\x00' + bytes([r, g, b]) * W

def png_chunk(ctype, data):
    c = ctype + data
    return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

hdr = struct.pack('>IIBBBBB', W, H, 8, 2, 0, 0, 0)
with open('$THEME_DIR/scrollbar_thumb_c.png', 'wb') as f:
    f.write(b'\x89PNG\r\n\x1a\n')
    f.write(png_chunk(b'IHDR', hdr))
    f.write(png_chunk(b'IDAT', zlib.compress(raw, 9)))
    f.write(png_chunk(b'IEND', b''))
" && echo "  Generated scrollbar_thumb_c.png" \
        || echo "  WARNING: Failed to generate scrollbar_thumb_c.png"
    fi
    _step_end
fi

# Clean previous build
_step_start "Preparing work directory"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$OUTPUT_DIR"
_step_end

# Build ISO. Pass pacman cache through so pacstrap doesn't re-download every
# run (saves ~2-5 min depending on mirror speed). Also export JOBS so any
# sub-tools that honour it (xz, zstd via mksquashfs) get full parallelism.
_step_start "Running mkarchiso (this is the long step)"
sudo env \
    JOBS="$JOBS" \
    XZ_OPT="-T$JOBS --threads=$JOBS" \
    ZSTD_NBTHREADS="$JOBS" \
    mkarchiso -v \
        -w "$WORK_DIR" \
        -o "$OUTPUT_DIR" \
        "$PROFILE_DIR"
_step_end

echo ""
echo "=== ISO build complete ==="
ls -lh "$OUTPUT_DIR"/*.iso 2>/dev/null || { echo "No ISO found in output directory" >&2; exit 1; }
