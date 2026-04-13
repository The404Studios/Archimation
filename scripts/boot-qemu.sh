#!/bin/bash
# boot-qemu.sh - Boot QEMU from existing ISO for PE loader testing
set -euo pipefail

pkill -9 qemu-system 2>/dev/null || true
sleep 1

ISO_FILE="$(ls -t /tmp/iso-output/ai-arch-linux-*.iso 2>/dev/null | head -1)"
if [ -z "$ISO_FILE" ] || [ ! -f "$ISO_FILE" ]; then
    echo "ERROR: No ISO found in /tmp/iso-output/"; exit 1
fi
EXTRACT_DIR="/tmp/iso-extract"
SERIAL_LOG="/tmp/qemu-serial.log"

rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"
cd "$EXTRACT_DIR"
bsdtar xf "$ISO_FILE" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null

VMLINUZ="$EXTRACT_DIR/arch/boot/x86_64/vmlinuz-linux"
INITRD="$EXTRACT_DIR/arch/boot/x86_64/initramfs-linux.img"

if [ ! -f "$VMLINUZ" ]; then
    echo "FAIL: no kernel extracted"
    exit 1
fi

LABEL=$(isoinfo -d -i "$ISO_FILE" 2>/dev/null | grep "Volume id:" | sed 's/Volume id: //' || echo "AI_ARCH_202602")
echo "Label: $LABEL"

rm -f "$SERIAL_LOG"

nohup qemu-system-x86_64 \
    -enable-kvm -m 4096 -smp 2 \
    -cdrom "$ISO_FILE" \
    -kernel "$VMLINUZ" -initrd "$INITRD" \
    -append "archisobasedir=arch archisolabel=${LABEL} console=ttyS0,115200" \
    -display none \
    -serial file:${SERIAL_LOG} \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::2222-:22 \
    -no-reboot > /tmp/qemu-stdout.log 2>&1 &

QEMU_PID=$!
echo "$QEMU_PID" > /tmp/qemu-pid
echo "QEMU PID: $QEMU_PID"
echo "Waiting for boot..."

for i in $(seq 1 90); do
    sleep 2
    if grep -q "login:" "$SERIAL_LOG" 2>/dev/null || grep -q "Reached target.*Multi-User" "$SERIAL_LOG" 2>/dev/null; then
        echo "System booted in ~$((i*2))s"
        sleep 10
        echo "Ready for SSH on port 2222"
        exit 0
    fi
    if ! kill -0 $(cat /tmp/qemu-pid 2>/dev/null || echo $$) 2>/dev/null && ! pgrep -q qemu-system; then
        echo "QEMU died"
        cat /tmp/qemu-stdout.log 2>/dev/null
        exit 1
    fi
    printf "\r  Waiting... %ds" "$((i*2))"
done

echo ""
echo "TIMEOUT - last 20 lines of serial:"
tail -20 "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'
