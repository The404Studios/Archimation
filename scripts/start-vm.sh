#!/bin/bash
# start-vm.sh - Start QEMU in background, wait for SSH, keep running
set -euo pipefail

pkill -9 qemu-system 2>/dev/null || true
sleep 1

ISO_FILE="$(ls -t /tmp/iso-output/ai-arch-linux-*.iso 2>/dev/null | head -1)"
if [ -z "$ISO_FILE" ] || [ ! -f "$ISO_FILE" ]; then
    echo "ERROR: No ISO found in /tmp/iso-output/"; exit 1
fi
EXTRACT_DIR="/tmp/iso-extract"
SERIAL_LOG="/tmp/qemu-serial.log"

rm -rf "$EXTRACT_DIR" && mkdir -p "$EXTRACT_DIR"
cd "$EXTRACT_DIR"
bsdtar xf "$ISO_FILE" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null

VMLINUZ="$EXTRACT_DIR/arch/boot/x86_64/vmlinuz-linux"
INITRD="$EXTRACT_DIR/arch/boot/x86_64/initramfs-linux.img"
LABEL=$(isoinfo -d -i "$ISO_FILE" 2>/dev/null | grep "Volume id:" | sed 's/Volume id: //' || echo "AI_ARCH_202602")

rm -f "$SERIAL_LOG"

# Start QEMU as a daemon
qemu-system-x86_64 \
    -enable-kvm -m 4096 -smp 2 \
    -cdrom "$ISO_FILE" \
    -kernel "$VMLINUZ" -initrd "$INITRD" \
    -append "archisobasedir=arch archisolabel=${LABEL} console=ttyS0,115200" \
    -display none \
    -serial file:${SERIAL_LOG} \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::2222-:22 \
    -no-reboot \
    -daemonize -pidfile /tmp/qemu.pid

echo "QEMU started (PID: $(cat /tmp/qemu.pid))"

# Wait for SSH
for i in $(seq 1 60); do
    if sshpass -p root ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o LogLevel=ERROR -p 2222 root@127.0.0.1 "echo SSH_OK" 2>/dev/null; then
        echo "SSH ready in ~$((i*3))s"
        exit 0
    fi
    sleep 3
done

echo "TIMEOUT waiting for SSH"
tail -20 "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'
exit 1
