#!/bin/bash
# qemu-test-only.sh - Boot existing ISO in QEMU and run smoke tests
set -euo pipefail

cleanup() {
    if [ -n "${QEMU_PID:-}" ]; then
        kill "$QEMU_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$QEMU_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

ISO_FILE="$(ls /tmp/iso-output/archwindows*.iso 2>/dev/null | head -1)"
EXTRACT_DIR="/tmp/iso-extract"
SERIAL_LOG="/tmp/qemu-serial.log"

if [ -z "$ISO_FILE" ] || [ ! -f "$ISO_FILE" ]; then
    echo "No ArchWindows ISO found in /tmp/iso-output/"
    ls /tmp/iso-output/ 2>/dev/null || echo "  (directory doesn't exist)"
    exit 1
fi

echo "ISO: $ISO_FILE ($(du -h "$ISO_FILE" | cut -f1))"

pkill -9 qemu-system 2>/dev/null || true
sleep 1

rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"
cd "$EXTRACT_DIR"
bsdtar xf "$ISO_FILE" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null

VMLINUZ="$EXTRACT_DIR/arch/boot/x86_64/vmlinuz-linux"
INITRD="$EXTRACT_DIR/arch/boot/x86_64/initramfs-linux.img"

if [ ! -f "$VMLINUZ" ]; then
    echo "Failed to extract kernel"
    exit 1
fi

LABEL=$(isoinfo -d -i "$ISO_FILE" 2>/dev/null | grep "Volume id:" | sed 's/Volume id: //' || echo "ARCHWIN_202602")
echo "Label: $LABEL"
rm -f "$SERIAL_LOG"

KVM_FLAG=""
if [ -e /dev/kvm ] && [ -r /dev/kvm ]; then
    KVM_FLAG="-enable-kvm"
    echo "Using KVM acceleration"
else
    echo "No KVM, using TCG software emulation (boot will take 3-5 min)"
fi

nohup qemu-system-x86_64 \
    $KVM_FLAG \
    -m 4096 -smp 2 \
    -cdrom "$ISO_FILE" \
    -kernel "$VMLINUZ" -initrd "$INITRD" \
    -append "archisobasedir=arch archisolabel=${LABEL} console=ttyS0,115200 systemd.log_level=info" \
    -display none \
    -serial file:${SERIAL_LOG} \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::2222-:22,hostfwd=tcp::8421-:8420 \
    -no-reboot > /tmp/qemu-stdout.log 2>&1 &

QEMU_PID=$!
echo "QEMU PID: $QEMU_PID"
sleep 2

if ! kill -0 $QEMU_PID 2>/dev/null; then
    echo "QEMU died immediately!"
    cat /tmp/qemu-stdout.log
    exit 1
fi

echo "Waiting for boot..."
BOOTED=0
for i in $(seq 1 150); do
    sleep 2
    if ! kill -0 $QEMU_PID 2>/dev/null; then
        echo "QEMU died at ${i}x2s"
        tail -20 /tmp/qemu-stdout.log 2>/dev/null
        exit 1
    fi
    if grep -q "Reached target.*Multi-User" "$SERIAL_LOG" 2>/dev/null; then
        echo "Booted to multi-user in ~$((i*2))s"
        BOOTED=1
        break
    fi
    if grep -q "emergency mode" "$SERIAL_LOG" 2>/dev/null; then
        echo "EMERGENCY MODE!"
        tail -50 "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'
        kill -9 $QEMU_PID 2>/dev/null || true
        exit 1
    fi
    if [ $((i % 15)) -eq 0 ]; then
        echo "  Still booting... $((i*2))s elapsed"
        tail -2 "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' || true
    fi
done

if [ $BOOTED -eq 0 ]; then
    echo "TIMEOUT - boot did not complete"
    echo "=== Last 30 lines of serial ==="
    tail -30 "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'
    kill -9 $QEMU_PID 2>/dev/null || true
    exit 1
fi

echo "Waiting 20s for services to start..."
sleep 20

echo ""
echo "========================================"
echo "  SMOKE TESTS"
echo "========================================"

SSH_ROOT="sshpass -p root ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o LogLevel=ERROR root@127.0.0.1 -p 2222"
SSH_ARCH="sshpass -p arch ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o LogLevel=ERROR arch@127.0.0.1 -p 2222"
SSH=""

echo -n "  [1] SSH port: "
if timeout 10 bash -c "echo > /dev/tcp/127.0.0.1/2222" 2>/dev/null; then
    echo "PASS"
else
    echo "FAIL"
fi

echo -n "  [2] SSH login: "
if $SSH_ROOT "echo ok" 2>/dev/null | grep -q "ok"; then
    echo "PASS (root)"
    SSH="$SSH_ROOT"
elif $SSH_ARCH "echo ok" 2>/dev/null | grep -q "ok"; then
    echo "PASS (arch)"
    SSH="$SSH_ARCH"
else
    echo "FAIL (no SSH access)"
    SSH=""
fi

if [ -n "$SSH" ]; then
    echo -n "  [3] AI daemon: "
    STATUS=$($SSH "systemctl is-active ai-control" 2>/dev/null || echo "unknown")
    echo "$STATUS"

    echo -n "  [4] LightDM: "
    STATUS=$($SSH "systemctl is-active lightdm" 2>/dev/null || echo "unknown")
    echo "$STATUS"

    echo -n "  [5] X server: "
    XPID=$($SSH "pgrep Xorg 2>/dev/null || pgrep X 2>/dev/null || echo none" 2>/dev/null)
    echo "$XPID"

    echo -n "  [6] Hostname: "
    $SSH "hostname" 2>/dev/null || echo "unknown"

    echo -n "  [7] OS: "
    $SSH "grep PRETTY_NAME /etc/os-release" 2>/dev/null || echo "unknown"

    echo -n "  [8] AI /health: "
    $SSH "curl -s --connect-timeout 5 http://localhost:8420/health" 2>/dev/null || echo "no response"
    echo ""

    echo ""
    echo "=== Failed Services ==="
    $SSH "systemctl --failed --no-pager --no-legend" 2>/dev/null || echo "(none or unable to check)"

    echo ""
    echo "=== AI Daemon Journal (last 15 lines) ==="
    $SSH "journalctl -u ai-control --no-pager -n 15" 2>/dev/null || echo "(no logs)"

    echo ""
    echo "=== LightDM Journal (last 15 lines) ==="
    $SSH "journalctl -u lightdm --no-pager -n 15" 2>/dev/null || echo "(no logs)"

    echo ""
    echo "=== Random Seed Status ==="
    $SSH "systemctl status systemd-random-seed --no-pager 2>&1 || true" 2>/dev/null
    $SSH "systemctl status systemd-boot-random-seed --no-pager 2>&1 || true" 2>/dev/null
fi

echo ""
echo "=== Boot Log Highlights ==="
grep -E "(Started|FAILED|Failed|ERROR|ai-control|lightdm|random)" "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | tail -30

echo ""
echo "Shutting down QEMU..."
kill $QEMU_PID 2>/dev/null || true
sleep 2
kill -9 $QEMU_PID 2>/dev/null || true
echo "Done."
