#!/bin/bash
# diag-cortex.sh -- boot QEMU on newest ISO, SSH in after settle, dump cortex
# state to /tmp/diag-result.log.  Used to diagnose s56e test failures.

set +e

ISO_DIR="/mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control/output"
ISO=$(ls -t "$ISO_DIR"/*.iso 2>/dev/null | grep -v '\.bak$' | head -1)
EXTRACT=/tmp/iso-diag
SERIAL=/tmp/serial-diag.log
RESULT=/tmp/diag-result.log
SSH_PORT=2230
DAEMON_PORT=8430

> "$RESULT"
echo "ISO=$ISO" >> "$RESULT"

mkdir -p "$EXTRACT"
cd "$EXTRACT"
bsdtar xf "$ISO" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null

qemu-system-x86_64 -m 4096 -smp 2 \
    -drive file="$ISO",media=cdrom,if=ide,index=1 \
    -kernel "$EXTRACT/arch/boot/x86_64/vmlinuz-linux" \
    -initrd "$EXTRACT/arch/boot/x86_64/initramfs-linux.img" \
    -append "archisobasedir=arch archisolabel=AI_ARCH_202604 archisodevice=/dev/sr0 console=ttyS0,115200 tsc=unstable" \
    -display none -serial "file:$SERIAL" \
    -net nic,model=virtio -net "user,hostfwd=tcp::${SSH_PORT}-:22,hostfwd=tcp::${DAEMON_PORT}-:8420" \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 -no-reboot >/dev/null 2>&1 &
QEMU=$!
echo "QEMU_PID=$QEMU" >> "$RESULT"

wait_for_boot() {
    local log="$1" max="${2:-300}"
    local start=$(date +%s)
    while true; do
        if grep -qE "Reached target.*[Mm]ulti-[Uu]ser|login:|Archimation.*ready|AI Arch Linux ready" "$log" 2>/dev/null; then
            echo "wait_for_boot: boot detected after $(($(date +%s) - start))s"
            return 0
        fi
        if [ $(($(date +%s) - start)) -gt $max ]; then
            echo "wait_for_boot: timeout after ${max}s" >&2
            return 1
        fi
        sleep 2
    done
}

wait_for_boot "$SERIAL" 300 >> "$RESULT" 2>&1

# Try root then arch (live ISO autologin user)
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -p $SSH_PORT)
if sshpass -p root ssh "${SSH_OPTS[@]}" root@127.0.0.1 "echo SSHOK" 2>/dev/null | grep -q SSHOK; then
    SSH_USER=root; SSH_PASS=root
elif sshpass -p arch ssh "${SSH_OPTS[@]}" arch@127.0.0.1 "echo SSHOK" 2>/dev/null | grep -q SSHOK; then
    SSH_USER=arch; SSH_PASS=arch
else
    echo "SSH FAILED on both root@root and arch@arch" >> "$RESULT"
    SSH_USER=arch; SSH_PASS=arch  # fallback so subsequent calls don't error harder
fi
echo "SSH_USER=$SSH_USER" >> "$RESULT"
SSH="sshpass -p $SSH_PASS ssh ${SSH_OPTS[*]} ${SSH_USER}@127.0.0.1"

{
    echo ""
    echo "=== ai-cortex status ==="
    $SSH "systemctl is-active ai-cortex"
    $SSH "systemctl status ai-cortex --no-pager 2>&1 | head -15"
    echo ""
    echo "=== cortex journal (last 30) ==="
    $SSH "journalctl -u ai-cortex --no-pager -b 0 2>&1 | tail -30"
    echo ""
    echo "=== listening ports ==="
    $SSH "ss -tlnp 2>/dev/null | grep -E '8421|8420' | head -10"
    echo ""
    echo "=== curl /emergency/status (cortex direct) ==="
    $SSH "curl -s --max-time 5 http://127.0.0.1:8421/emergency/status 2>&1 | head -c 300"
    echo ""
    echo "=== curl /health (cortex direct) ==="
    $SSH "curl -s --max-time 5 http://127.0.0.1:8421/health 2>&1 | head -c 300"
    echo ""
    echo "=== curl /health (daemon) ==="
    $SSH "curl -s --max-time 5 http://127.0.0.1:8420/health 2>&1 | head -c 300"
    echo ""
    echo "=== systemd failed units ==="
    $SSH "systemctl --failed --no-legend 2>&1 | head -10"
} >> "$RESULT" 2>&1

kill "$QEMU" 2>/dev/null
sleep 1
kill -9 "$QEMU" 2>/dev/null
echo "DONE" >> "$RESULT"
exit 0
