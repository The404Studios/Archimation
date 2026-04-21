#!/bin/bash
# start-qemu-daemon.sh - Start QEMU in daemon mode for testing
set -euo pipefail

ISO_FILE="$(ls /tmp/iso-output/archimation*.iso 2>/dev/null | head -1)"
EXTRACT_DIR="/tmp/iso-extract"
SERIAL_LOG="/tmp/qemu-serial.log"

if [ -z "$ISO_FILE" ]; then
    echo "No ISO found"
    exit 1
fi

VMLINUZ="$EXTRACT_DIR/arch/boot/x86_64/vmlinuz-linux"
INITRD="$EXTRACT_DIR/arch/boot/x86_64/initramfs-linux.img"

if [ ! -f "$VMLINUZ" ]; then
    echo "Extracting kernel..."
    rm -rf "$EXTRACT_DIR"
    mkdir -p "$EXTRACT_DIR"
    cd "$EXTRACT_DIR"
    bsdtar xf "$ISO_FILE" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null
fi

LABEL="ARCHWIN_202602"

pkill -9 qemu-system 2>/dev/null || true
sleep 1
rm -f "$SERIAL_LOG"

echo "Starting QEMU (no KVM, software emulation)..."
qemu-system-x86_64 \
    -m 4096 -smp 2 \
    -cdrom "$ISO_FILE" \
    -kernel "$VMLINUZ" -initrd "$INITRD" \
    -append "archisobasedir=arch archisolabel=${LABEL} console=ttyS0,115200 systemd.log_level=info" \
    -display none \
    -serial "file:${SERIAL_LOG}" \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::2222-:22,hostfwd=tcp::8421-:8420 \
    -no-reboot -daemonize

sleep 2
if pgrep qemu-system > /dev/null; then
    echo "QEMU running (PID: $(pgrep qemu-system))"
    echo "SSH will be on port 2222, AI daemon on port 8421"
    echo "Serial log: $SERIAL_LOG"
else
    echo "QEMU failed to start"
    exit 1
fi
