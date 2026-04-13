#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
SSH_CMD="sshpass -p root ssh $SSH_OPTS root@127.0.0.1 -p 2222"
SCP_CMD="sshpass -p root scp $SSH_OPTS -P 2222"
PE_DIR="$PROJECT_DIR/pe-loader"

# Kill any existing QEMU
pkill -9 qemu-system 2>/dev/null || true
sleep 1

ISO="$(ls -t /tmp/iso-output/ai-arch-linux-*.iso 2>/dev/null | head -1)"
if [ -z "$ISO" ] || [ ! -f "$ISO" ]; then echo "ERROR: No ISO found in /tmp/iso-output/"; exit 1; fi
EXTRACT_DIR="/tmp/iso-extract"
rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"
cd "$EXTRACT_DIR"
bsdtar xf "$ISO" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null

VMLINUZ="$EXTRACT_DIR/arch/boot/x86_64/vmlinuz-linux"
INITRD="$EXTRACT_DIR/arch/boot/x86_64/initramfs-linux.img"
LABEL=$(isoinfo -d -i "$ISO" 2>/dev/null | grep "Volume id:" | sed 's/Volume id: //' || echo "AI_ARCH_202602")

echo "Booting QEMU..."
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
for i in $(seq 1 90); do
    sleep 2
    if ! kill -0 $QEMU_PID 2>/dev/null; then
        echo "QEMU died!"; cat /tmp/qemu-stdout.log 2>/dev/null; exit 1
    fi
    if grep -q "login:" /tmp/qemu-serial.log 2>/dev/null; then
        echo "Login prompt in $((i*2))s"
        break
    fi
    if [ $i -eq 90 ]; then echo "Timeout 180s"; tail -20 /tmp/qemu-serial.log; fi
done

# Wait for SSH
sleep 5
echo "Waiting for SSH..."
for i in $(seq 1 15); do
    if $SSH_CMD "echo SSH_OK" 2>/dev/null | grep -q SSH_OK; then
        echo "SSH ready"
        break
    fi
    sleep 3
done

# Deploy PE loader
echo "=== Deploying PE loader ==="
$SSH_CMD "mkdir -p /usr/lib/pe-compat /tmp/pe-test"
$SCP_CMD "$PE_DIR/loader/peloader" root@127.0.0.1:/usr/bin/peloader
$SSH_CMD "chmod +x /usr/bin/peloader"
$SCP_CMD $PE_DIR/dlls/*.so root@127.0.0.1:/usr/lib/pe-compat/
echo "PE loader deployed"

# Copy test binaries
for f in "$PROJECT_DIR"/tests/*.exe; do
    [ -f "$f" ] && $SCP_CMD "$f" root@127.0.0.1:/tmp/pe-test/ 2>/dev/null || true
done
echo "Test binaries copied"

# Test hello.exe
echo ""
echo "=== Testing hello.exe ==="
$SSH_CMD "cd /tmp/pe-test && PE_COMPAT_DLL_PATH=/usr/lib/pe-compat peloader hello.exe 2>&1" || echo "(exit code: $?)"

echo ""
echo "=== Testing win32test.exe ==="
$SSH_CMD "cd /tmp/pe-test && PE_COMPAT_DLL_PATH=/usr/lib/pe-compat peloader win32test.exe 2>&1" || echo "(exit code: $?)"

echo ""
echo "QEMU still running as PID $QEMU_PID"
echo "SSH: sshpass -p root ssh -p 2222 root@127.0.0.1"

# Keep QEMU alive
wait $QEMU_PID 2>/dev/null || true
