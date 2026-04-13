#!/bin/bash
# test-pe-loader.sh - Boot QEMU, copy hello.exe in, test the PE loader
set -euo pipefail

ISO_FILE="$(ls /tmp/iso-output/*.iso 2>/dev/null | head -1)"
EXTRACT_DIR="/tmp/iso-extract"
SERIAL_LOG="/tmp/qemu-serial-pe.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(dirname "$SCRIPT_DIR")"
RESULT_FILE="/tmp/pe-test-results.txt"

if [ -z "$ISO_FILE" ]; then
    echo "ERROR: No ISO found in /tmp/iso-output"
    exit 1
fi

# Kill stale QEMU
pkill -9 qemu-system 2>/dev/null || true
sleep 2

VMLINUZ="$EXTRACT_DIR/arch/boot/x86_64/vmlinuz-linux"
INITRD="$EXTRACT_DIR/arch/boot/x86_64/initramfs-linux.img"
LABEL=$(isoinfo -d -i "$ISO_FILE" 2>/dev/null | grep "Volume id:" | sed 's/Volume id: //' || echo "AI_ARCH_202602")

rm -f "$SERIAL_LOG" "$RESULT_FILE"

echo "Booting QEMU..."
qemu-system-x86_64 \
    -enable-kvm -m 4096 -smp 2 \
    -cdrom "$ISO_FILE" \
    -kernel "$VMLINUZ" -initrd "$INITRD" \
    -append "archisobasedir=arch archisolabel=${LABEL} console=ttyS0,115200" \
    -display none -serial file:${SERIAL_LOG} \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::2223-:22 \
    -no-reboot \
    -daemonize

sleep 3

# Wait for boot
echo "Waiting for boot..."
BOOT_START=$(date +%s)
while true; do
    ELAPSED=$(( $(date +%s) - BOOT_START ))
    if [ $ELAPSED -ge 120 ]; then echo "TIMEOUT"; exit 1; fi
    if grep -q "Reached target.*Multi-User" "$SERIAL_LOG" 2>/dev/null; then
        echo "Booted in ${ELAPSED}s"
        break
    fi
    sleep 2
done

echo "Waiting 12s for services..."
sleep 12

# SSH helper
sshr() {
    sshpass -p root ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=15 \
        -o LogLevel=ERROR \
        root@127.0.0.1 -p 2223 "$@"
}

scpr() {
    sshpass -p root scp \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -P 2223 "$@"
}

# Collect all output
exec > >(tee "$RESULT_FILE") 2>&1

echo ""
echo "=== SSH check ==="
sshr "echo SSH_OK" || { echo "SSH FAILED"; exit 1; }

echo ""
echo "=== PE loader installation ==="
sshr "which peloader 2>/dev/null && peloader --version 2>&1" || echo "NOT FOUND"
sshr "ls -la /usr/lib/pe-compat/ 2>&1" || echo "no pe-compat dir"

echo ""
echo "=== Copying hello.exe ==="
scpr "$PROJECT/tests/pe-loader/hello.exe" root@127.0.0.1:/tmp/hello.exe 2>&1
sshr "ls -la /tmp/hello.exe"

echo ""
echo "=========================================="
echo "  PE LOADER TESTS"
echo "=========================================="

echo ""
echo "--- [1] peloader --help ---"
sshr "peloader --help 2>&1" || true

echo ""
echo "--- [2] peloader --version ---"
sshr "peloader --version 2>&1" || true

echo ""
echo "--- [3] peloader -v /tmp/hello.exe ---"
sshr "peloader -v /tmp/hello.exe 2>&1; echo EXITCODE=\$?" || true

echo ""
echo "--- [4] peloader /tmp/hello.exe ---"
sshr "peloader /tmp/hello.exe 2>&1; echo EXITCODE=\$?" || true

echo ""
echo "--- [5] peloader -d /tmp/hello.exe (debug) ---"
sshr "peloader -d /tmp/hello.exe 2>&1; echo EXITCODE=\$?" || true

echo ""
echo "--- [6] binfmt_misc status ---"
sshr "cat /proc/sys/fs/binfmt_misc/status 2>/dev/null" || echo "binfmt not available"
sshr "ls /proc/sys/fs/binfmt_misc/ 2>/dev/null" || echo "binfmt not mounted"

echo ""
echo "--- [7] Direct ./hello.exe via binfmt ---"
sshr "chmod +x /tmp/hello.exe && /tmp/hello.exe 2>&1; echo EXITCODE=\$?" || true

echo ""
echo "=========================================="
echo "  TESTS COMPLETE"
echo "=========================================="

# Shutdown
pkill -9 qemu-system 2>/dev/null || true
echo "QEMU stopped."
