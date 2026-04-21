#!/bin/bash
# Diagnostic: boot the existing ISO, SSH in, capture coherence.service state
# + journal + standalone run output, then shut down.
#
# This reuses the exact QEMU invocation from test-qemu.sh so we don't drift.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ISO_DIR="${ISO_DIR:-${PROJECT_DIR}/output}"
ISO_FILE="$(ls "${ISO_DIR}"/*.iso 2>/dev/null | head -1)"
EXTRACT_DIR="/tmp/iso-extract-diag"
SERIAL_LOG="/tmp/qemu-diag-serial.log"
OUT="/tmp/coh-diag-output.txt"

if [ -z "$ISO_FILE" ]; then
    echo "ERROR: No ISO found in ${ISO_DIR}" >&2
    exit 1
fi

# Clean prior QEMU
pkill -9 -x qemu-system-x86_64 2>/dev/null || true
sleep 1

rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"
rm -f "$SERIAL_LOG" "$OUT"

echo "Extract kernel + initrd..."
cd "$EXTRACT_DIR"
bsdtar xf "$ISO_FILE" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img
VMLINUZ="$EXTRACT_DIR/arch/boot/x86_64/vmlinuz-linux"
INITRD="$EXTRACT_DIR/arch/boot/x86_64/initramfs-linux.img"
LABEL=$(isoinfo -d -i "$ISO_FILE" 2>/dev/null | awk -F': ' '/Volume id/{print $2}' || echo "AI_ARCH")

KVM_FLAG=""
if [ -r /dev/kvm ]; then KVM_FLAG="-enable-kvm"; fi
echo "KVM: ${KVM_FLAG:-(tcg)}"

echo "Launching QEMU..."
nohup qemu-system-x86_64 \
    $KVM_FLAG \
    -m 4096 -smp 2 \
    -drive file="$ISO_FILE",media=cdrom,if=ide,index=1 \
    -kernel "$VMLINUZ" -initrd "$INITRD" \
    -append "archisobasedir=arch archisolabel=${LABEL} archisodevice=/dev/sr0 console=ttyS0,115200 systemd.log_level=info tsc=unstable" \
    -display none -serial "file:${SERIAL_LOG}" \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::8421-:8420,hostfwd=tcp::2222-:22 \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -no-reboot >/tmp/qemu-diag-stdout.log 2>&1 &
QEMU_PID=$!
echo "QEMU pid=$QEMU_PID"

cleanup() {
    kill "$QEMU_PID" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
        kill -0 "$QEMU_PID" 2>/dev/null || break
        sleep 1
    done
    kill -9 "$QEMU_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

BOOT_TIMEOUT=300
[ -n "$KVM_FLAG" ] && BOOT_TIMEOUT=120
echo "Waiting for boot (timeout ${BOOT_TIMEOUT}s)..."
T0=$(date +%s)
while :; do
    E=$(( $(date +%s) - T0 ))
    if [ "$E" -ge "$BOOT_TIMEOUT" ]; then
        echo "TIMEOUT"; tail -50 "$SERIAL_LOG"; exit 2
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "QEMU died early"; tail -50 "$SERIAL_LOG"; exit 2
    fi
    if grep -qE "login:|Reached target.*Multi-User|Reached target.*multi-user" "$SERIAL_LOG" 2>/dev/null; then
        echo "booted in ${E}s"; break
    fi
    sleep 2
    printf "\r  %ds" "$E"
done
echo ""

# Wait for sshd port
echo "Waiting for ssh port 2222..."
for i in $(seq 1 120); do
    if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/2222" 2>/dev/null; then
        echo "  sshd up after ${i}s"; break
    fi
    sleep 1
done

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"
SSH_ROOT="sshpass -p root ssh $SSH_OPTS root@127.0.0.1 -p 2222"

# Try root first, fall back to arch
SSH=""
if $SSH_ROOT "echo ok" 2>/dev/null | grep -q ok; then
    SSH="$SSH_ROOT"; echo "  login: root"
else
    SSH="sshpass -p arch ssh $SSH_OPTS arch@127.0.0.1 -p 2222"
    if $SSH "echo ok" 2>/dev/null | grep -q ok; then
        echo "  login: arch (sudo)"
    else
        echo "  SSH login failed"; exit 3
    fi
fi

run() {
    local label="$1"; shift
    {
        echo "=========================================="
        echo "== $label"
        echo "=========================================="
        $SSH "$@" 2>&1
        echo
    } | tee -a "$OUT"
}

run "systemctl status coherence.service" "sudo systemctl status coherence.service --no-pager -l || true"
run "journalctl -u coherence.service -b" "sudo journalctl -u coherence.service -b --no-pager -o short-iso || true"
run "journalctl _SYSTEMD_UNIT=coherence.service" "sudo journalctl _SYSTEMD_UNIT=coherence.service -b --no-pager || true"
run "ls /usr/bin/coherenced" "ls -la /usr/bin/coherenced"
run "ls -la /etc/coherence" "ls -la /etc/coherence/ 2>&1"
run "ls -la /run/coherence" "ls -la /run/coherence/ 2>&1 || true"
run "file /usr/bin/coherenced" "file /usr/bin/coherenced"
run "ldd /usr/bin/coherenced" "ldd /usr/bin/coherenced"
run "coherenced --help" "sudo /usr/bin/coherenced --help 2>&1 || true"
run "standalone run (5s timeout, dry-run)" "sudo timeout 5 /usr/bin/coherenced --dry-run --config=/etc/coherence/coherence.conf 2>&1 || echo 'exit='$?"
run "systemctl show coherence - core" "sudo systemctl show coherence.service -p ExecMainStatus,ExecMainPID,ExecMainCode,Result,ActiveState,SubState,NRestarts"
run "sudo auditctl dmesg seccomp" "sudo dmesg | grep -iE 'seccomp|audit' | tail -30 || true"

echo ""
echo "=== OUTPUT TO $OUT ==="
ls -la "$OUT"
echo "==="
