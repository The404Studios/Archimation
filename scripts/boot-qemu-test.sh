#!/bin/bash
set -euo pipefail

# Kill any existing QEMU
pkill -9 qemu-system 2>/dev/null || true
sleep 1

ISO="$(ls -t /tmp/iso-output/ai-arch-linux-*.iso 2>/dev/null | head -1)"
if [ -z "$ISO" ] || [ ! -f "$ISO" ]; then
    echo "ERROR: No ISO found in /tmp/iso-output/"
    exit 1
fi
echo "ISO: $ISO"

# Extract kernel/initrd for direct boot
EXTRACT_DIR="/tmp/iso-extract"
rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"
cd "$EXTRACT_DIR"
bsdtar xf "$ISO" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null

VMLINUZ="$EXTRACT_DIR/arch/boot/x86_64/vmlinuz-linux"
INITRD="$EXTRACT_DIR/arch/boot/x86_64/initramfs-linux.img"

if [ ! -f "$VMLINUZ" ] || [ ! -f "$INITRD" ]; then
    echo "Failed to extract kernel/initrd"
    exit 1
fi
echo "Kernel + initrd extracted"

LABEL=$(isoinfo -d -i "$ISO" 2>/dev/null | grep "Volume id:" | sed 's/Volume id: //' || echo "AI_ARCH_202602")
echo "Label: $LABEL"

# Launch QEMU in background
rm -f /tmp/qemu-serial.log
qemu-system-x86_64 \
    -enable-kvm \
    -m 4096 \
    -smp 2 \
    -cdrom "$ISO" \
    -kernel "$VMLINUZ" \
    -initrd "$INITRD" \
    -append "archisobasedir=arch archisolabel=${LABEL} console=ttyS0,115200" \
    -display none \
    -serial file:/tmp/qemu-serial.log \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::2222-:22 \
    -no-reboot \
    > /tmp/qemu-stdout.log 2>&1 &

QEMU_PID=$!
echo "QEMU PID: $QEMU_PID"

# Wait for boot
echo "Waiting for boot..."
for i in $(seq 1 90); do
    sleep 2
    if ! kill -0 $QEMU_PID 2>/dev/null; then
        echo "QEMU died!"
        cat /tmp/qemu-stdout.log 2>/dev/null
        exit 1
    fi
    if grep -q "Reached target.*Multi-User" /tmp/qemu-serial.log 2>/dev/null; then
        echo "Booted in $((i*2))s"
        break
    fi
    if [ $i -eq 90 ]; then
        echo "Timeout after 180s"
        tail -20 /tmp/qemu-serial.log 2>/dev/null
    fi
done

# Wait for SSH
sleep 10
echo "Testing SSH..."
for i in $(seq 1 10); do
    if sshpass -p root ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR root@127.0.0.1 -p 2222 "echo SSH_OK" 2>/dev/null; then
        echo "SSH connected!"
        break
    fi
    sleep 3
done
echo "QEMU running. PID=$QEMU_PID"
