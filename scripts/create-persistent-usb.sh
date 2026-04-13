#!/bin/bash
# create-persistent-usb.sh — Write AI Arch Linux ISO to USB with persistent storage
#
# This script:
#   1. Writes the ISO to a USB drive (making it bootable)
#   2. Creates a persistence partition (ext4, labeled AI_PERSIST)
#   3. All changes you make while running from USB will survive reboots
#
# Usage:
#   sudo ./create-persistent-usb.sh /dev/sdX [path/to/iso]
#
# WARNING: This will DESTROY ALL DATA on the target USB drive!

set -euo pipefail

# --- Parse arguments ---
if [[ $# -lt 1 ]]; then
    echo "Usage: sudo $0 /dev/sdX [path/to/iso]"
    echo ""
    echo "Available USB devices:"
    lsblk -d -o NAME,SIZE,MODEL,TRAN | grep -E "usb|removable" || lsblk -d -o NAME,SIZE,MODEL
    echo ""
    echo "WARNING: This will erase ALL data on the selected device!"
    exit 1
fi

USB_DEV="$1"
ISO_PATH="${2:-$(dirname "$0")/../output/ai-arch-linux-*.iso}"

# Expand glob
ISO_PATH=$(ls -t $ISO_PATH 2>/dev/null | head -1)

if [[ -z "$ISO_PATH" || ! -f "$ISO_PATH" ]]; then
    echo "Error: ISO file not found. Specify path as second argument."
    exit 1
fi

# Safety checks
if [[ "$EUID" -ne 0 ]]; then
    echo "Error: Must run as root (sudo)"
    exit 1
fi

if [[ ! -b "$USB_DEV" ]]; then
    echo "Error: $USB_DEV is not a block device"
    exit 1
fi

# Prevent accidentally wiping system drives
if mount | grep -q "^$USB_DEV"; then
    echo "Error: $USB_DEV has mounted partitions. Unmount them first:"
    mount | grep "^$USB_DEV"
    exit 1
fi

# Double-check with user
USB_SIZE=$(lsblk -dn -o SIZE "$USB_DEV" 2>/dev/null || echo "unknown")
USB_MODEL=$(lsblk -dn -o MODEL "$USB_DEV" 2>/dev/null || echo "unknown")
echo "========================================="
echo "  AI Arch Linux USB Creator"
echo "========================================="
echo ""
echo "  ISO:    $ISO_PATH"
echo "  Device: $USB_DEV ($USB_SIZE, $USB_MODEL)"
echo ""
echo "  WARNING: ALL DATA ON $USB_DEV WILL BE DESTROYED!"
echo ""
read -p "  Type YES to continue: " CONFIRM
if [[ "$CONFIRM" != "YES" ]]; then
    echo "Aborted."
    exit 1
fi

# --- Step 1: Write ISO to USB ---
echo ""
echo "[1/3] Writing ISO to USB drive..."
dd if="$ISO_PATH" of="$USB_DEV" bs=4M status=progress oflag=sync
sync

echo "[1/3] ISO written successfully."

# --- Step 2: Create persistence partition ---
echo ""
echo "[2/3] Creating persistence partition..."

# Get ISO size to know where free space starts
ISO_SIZE=$(stat -c %s "$ISO_PATH")
ISO_SIZE_MB=$(( (ISO_SIZE / 1048576) + 1 ))

# Get total disk size
DISK_SIZE_MB=$(lsblk -dn -o SIZE -b "$USB_DEV" | awk '{print int($1/1048576)}')
PERSIST_SIZE_MB=$(( DISK_SIZE_MB - ISO_SIZE_MB - 10 ))

if [[ $PERSIST_SIZE_MB -lt 512 ]]; then
    echo "Warning: Only ${PERSIST_SIZE_MB}MB available for persistence."
    echo "         Recommend at least 4GB USB drive for a good experience."
    if [[ $PERSIST_SIZE_MB -lt 100 ]]; then
        echo "Error: Not enough space for persistence partition."
        echo "       Use a larger USB drive (8GB+ recommended)."
        exit 1
    fi
fi

echo "  Persistence partition: ${PERSIST_SIZE_MB}MB"

# Reload partition table
partprobe "$USB_DEV" 2>/dev/null || sleep 2

# Find the end of the last ISO partition (use awk to get the End column
# of the last numbered partition line, which is more robust than tail/head)
LAST_END=$(parted -s "$USB_DEV" unit MB print 2>/dev/null \
    | awk '/^ *[0-9]/ { end=$3 } END { gsub(/MB/,"",end); print end }')
if [[ -z "$LAST_END" || "$LAST_END" == "0" ]]; then
    LAST_END=$ISO_SIZE_MB
fi
START_MB=$(( LAST_END + 1 ))

# Create new partition
echo "  Creating partition at ${START_MB}MB..."
parted -s "$USB_DEV" mkpart primary ext4 "${START_MB}MB" "100%"

# Wait for kernel to see new partition
sleep 2
partprobe "$USB_DEV" 2>/dev/null || sleep 2

# Find the new partition device name
PERSIST_PART=""
# Check likely partition numbers: archiso ISOs typically have 2 partitions
# (ISO9660 + ESP), so the new one is usually partition 3.
for p in "${USB_DEV}"3 "${USB_DEV}p3" "${USB_DEV}"4 "${USB_DEV}p4" "${USB_DEV}"5 "${USB_DEV}p5"; do
    if [[ -b "$p" ]]; then
        PERSIST_PART="$p"
        break
    fi
done

if [[ -z "$PERSIST_PART" ]]; then
    echo "Warning: Could not find persistence partition automatically."
    echo "         You may need to create it manually:"
    echo "         1. Run: fdisk $USB_DEV"
    echo "         2. Create new partition in free space"
    echo "         3. Run: mkfs.ext4 -L AI_PERSIST <partition>"
    echo ""
    echo "The USB is still bootable without persistence (changes won't survive reboot)."
    exit 0
fi

# --- Step 3: Format persistence partition ---
echo ""
echo "[3/3] Formatting persistence partition ($PERSIST_PART)..."
mkfs.ext4 -L AI_PERSIST -q "$PERSIST_PART"

# Set ext4 to continue on errors instead of remount-ro.
# This prevents unclean shutdowns (common with USB) from making
# the persistence partition read-only on next boot.
tune2fs -e continue "$PERSIST_PART" 2>/dev/null || true

echo ""
echo "========================================="
echo "  USB drive ready!"
echo "========================================="
echo ""
echo "  Boot menu options:"
echo "    - 'AI Arch Linux' .............. Auto-persistent (uses AI_PERSIST if found)"
echo "    - 'Copy to RAM' ............... Load everything into RAM (no persistence)"
echo "    - 'Nomodeset' ................. For GPU driver issues"
echo ""
echo "  To boot:"
echo "    1. Plug USB into target computer"
echo "    2. Enter BIOS/UEFI boot menu (usually F12, F2, or Del)"
echo "    3. Select the USB drive"
echo "    4. Default entry auto-detects persistence"
echo ""
echo "  Persistence partition: $PERSIST_PART ($(lsblk -dn -o SIZE "$PERSIST_PART"))"
echo ""
echo "  For Steam games:"
echo "    - Games are installed to the persistence partition"
echo "    - Right-click any .exe → 'Open With' → 'Windows Application'"
echo "    - Or use: pe-run-game game.exe"
echo ""
