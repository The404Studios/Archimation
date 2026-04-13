#!/bin/bash
# Build the custom Arch Linux ISO using mkarchiso
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

echo "=== Building AI Control Linux ISO ==="
echo "Profile:  $PROFILE_DIR"
echo "Work dir: $WORK_DIR"
echo "Output:   $OUTPUT_DIR"
echo ""

# Resolve the local repo path in pacman.conf
REPO_DIR="$PROJECT_DIR/repo/x86_64"
if [ -f "$PROFILE_DIR/pacman.conf" ]; then
    sed -i "s|Server = file://.*|Server = file://${REPO_DIR}|" "$PROFILE_DIR/pacman.conf"
fi

# Generate GRUB theme assets (fonts + background + selection highlight)
THEME_DIR="$PROFILE_DIR/grub/themes/archwindows"
if [ -d "$THEME_DIR" ]; then
    echo "=== Generating GRUB theme assets ==="
    DEJAVU_TTF="/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    DEJAVU_BOLD_TTF="/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
    # Try alternate paths (Arch vs Debian font locations)
    [ -f "$DEJAVU_TTF" ] || DEJAVU_TTF="/usr/share/fonts/TTF/DejaVuSans.ttf"
    [ -f "$DEJAVU_BOLD_TTF" ] || DEJAVU_BOLD_TTF="/usr/share/fonts/TTF/DejaVuSans-Bold.ttf"

    if command -v grub-mkfont &>/dev/null && [ -f "$DEJAVU_TTF" ]; then
        grub-mkfont -s 10 -o "$THEME_DIR/DejaVu_Sans_Regular_10.pf2" "$DEJAVU_TTF"
        grub-mkfont -s 12 -o "$THEME_DIR/DejaVu_Sans_Regular_12.pf2" "$DEJAVU_TTF"
        grub-mkfont -s 14 -o "$THEME_DIR/DejaVu_Sans_Regular_14.pf2" "$DEJAVU_TTF"
        grub-mkfont -s 14 -o "$THEME_DIR/DejaVu_Sans_Bold_14.pf2" "$DEJAVU_BOLD_TTF"
        grub-mkfont -s 24 -o "$THEME_DIR/DejaVu_Sans_Bold_24.pf2" "$DEJAVU_BOLD_TTF"
        echo "  Generated .pf2 theme fonts"
    else
        echo "  WARNING: grub-mkfont or DejaVu TTF not found, skipping theme font generation"
        echo "  Theme will fall back to GRUB default font"
    fi

    # Generate background.png (1920x1080 Tokyo Night gradient) using Python
    if command -v python3 &>/dev/null; then
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
    if command -v python3 &>/dev/null; then
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
    if command -v python3 &>/dev/null; then
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
fi

# Clean previous build
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$OUTPUT_DIR"

# Build ISO
sudo mkarchiso -v -w "$WORK_DIR" -o "$OUTPUT_DIR" "$PROFILE_DIR"

echo ""
echo "=== ISO build complete ==="
ls -lh "$OUTPUT_DIR"/*.iso 2>/dev/null || echo "No ISO found in output directory"
