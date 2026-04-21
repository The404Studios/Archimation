#!/bin/bash
# test-qemu-live-debug.sh — interactive-probe companion to test-qemu.sh.
#
# S79: after scripts/test-qemu.sh completes the scripted smoke, this script
# brings up a FRESH QEMU instance, keeps it running, and SSHes in to
# interrogate S78's new surfaces:
#   - /sys/kernel/trust_attest_quine/{text_hash, recompute_count, quine_uninit_reads}
#   - /sys/kernel/trust/quorum/{last_hmac, hmac_computed, hmac_failed}
#   - /metrics/ecosystem     (library_census)
#   - /metrics/depth         (depth_observer)
#   - /metrics/deltas        (differential_observer)
#   - /cortex/monte_carlo/rollout
#   - journalctl ai-setup-users.service  (S77 +x-bit fix verification)
#   - dmesg (kernel-side trust.ko if it loaded)
#
# The script shuts the VM down cleanly at end via `ssh poweroff` + timeout.
#
# Pre-req: scripts/test-qemu.sh already succeeded on this ISO (BOOT_TIMEOUT=120
# is not long enough for cold TCG; the smoke test's warm-up helps).

set -u

cd "$(dirname "$0")/.."

ISO_FILE=$(ls -t output/archimation-*.iso 2>/dev/null | head -1)
[ -z "$ISO_FILE" ] && { echo "FAIL: no ISO in output/"; exit 1; }
echo "ISO: $ISO_FILE"

# Extract initrd + vmlinuz from ISO
TMP=/tmp/s79-livedebug
rm -rf "$TMP" && mkdir -p "$TMP"
ISO_MOUNT=/tmp/s79-livedebug-iso
sudo mkdir -p "$ISO_MOUNT"
sudo mount -o loop,ro "$ISO_FILE" "$ISO_MOUNT" 2>/dev/null || {
    echo "FAIL: cannot mount ISO"; exit 1
}
VMLINUZ="$TMP/vmlinuz"
INITRD="$TMP/initrd.img"
cp "$ISO_MOUNT/arch/boot/x86_64/vmlinuz-linux" "$VMLINUZ" 2>/dev/null || \
    cp "$ISO_MOUNT/arch/boot/x86_64/vmlinuz" "$VMLINUZ" 2>/dev/null || {
    echo "FAIL: no vmlinuz in ISO"; sudo umount "$ISO_MOUNT"; exit 1
}
cp "$ISO_MOUNT/arch/boot/x86_64/initramfs-linux.img" "$INITRD" 2>/dev/null || \
    cp "$ISO_MOUNT/arch/boot/x86_64/archiso.img" "$INITRD" 2>/dev/null || {
    echo "FAIL: no initrd in ISO"; sudo umount "$ISO_MOUNT"; exit 1
}
LABEL=$(ls "$ISO_MOUNT" | grep -v '^\.' | head -1 2>/dev/null || echo "ARCHIMATION")
# archisolabel is usually in efi/boot — easier to just hardcode from ISO metadata
LABEL=$(blkid -o value -s LABEL "$ISO_FILE" 2>/dev/null || echo "ARCH_202604")
sudo umount "$ISO_MOUNT"
rmdir "$ISO_MOUNT" 2>/dev/null || true
echo "VMLINUZ: $VMLINUZ, INITRD: $INITRD, LABEL: $LABEL"

# Kill any orphan QEMU
pkill -9 qemu-system-x86_64 2>/dev/null || true
sleep 2

SERIAL_LOG=/tmp/s79-livedebug-serial.log
rm -f "$SERIAL_LOG"

nohup qemu-system-x86_64 \
    -m 4096 \
    -smp 2 \
    -drive file="$ISO_FILE",media=cdrom,if=ide,index=1 \
    -kernel "$VMLINUZ" \
    -initrd "$INITRD" \
    -append "archisobasedir=arch archisolabel=${LABEL} archisodevice=/dev/sr0 console=ttyS0,115200 systemd.log_level=info tsc=unstable" \
    -display none \
    -serial "file:${SERIAL_LOG}" \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::8421-:8420,hostfwd=tcp::2222-:22 \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -no-reboot \
    > /tmp/qemu-live-stdout.log 2>&1 &
QEMU_PID=$!
echo "QEMU PID: $QEMU_PID"

# Wait for SSH to bind
echo "Waiting for SSH on :2222..."
for i in $(seq 1 180); do
    if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/2222" 2>/dev/null; then
        echo "  SSH up after ${i}s"
        break
    fi
    sleep 1
done

# SSH auth retry — PAM/getty may need time after port 2222 binds
SSH=""
for attempt in $(seq 1 30); do
    for creds in "root:root" "arch:arch"; do
        user="${creds%:*}"; pass="${creds#*:}"
        if sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR "${user}@127.0.0.1" -p 2222 "echo ok" 2>/dev/null | grep -q ok; then
            SSH="sshpass -p $pass ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR ${user}@127.0.0.1 -p 2222"
            echo "  SSH auth as ${user} OK after ${attempt} attempt(s)"
            SSH_USER="$user"
            break 2
        fi
    done
    sleep 3
done
if [ -z "$SSH" ]; then
    echo "FAIL: SSH auth failed for both root and arch after 30 attempts (90s)"
    kill -9 "$QEMU_PID" 2>/dev/null
    exit 1
fi

# Wait for ai-control daemon to come up
for i in $(seq 1 60); do
    if $SSH "curl -s -m 2 http://127.0.0.1:8420/health 2>/dev/null" | grep -q '"status":"ok"'; then
        echo "  ai-control /health up after ${i}s"
        break
    fi
    sleep 1
done

echo ""
echo "========================================"
echo "  S79 LIVE DEBUG PROBES"
echo "========================================"

probe() {
    local label="$1"; shift
    echo ""
    echo "### $label"
    $SSH "$@" 2>&1 | head -40
}

# --- S77 regressions that S78 should have fixed ---
probe "[S77-fix-1] ai-setup-users.service status (previously FAILED)" \
    "systemctl status ai-setup-users.service --no-pager 2>&1 | head -20; journalctl -u ai-setup-users.service --no-pager -n 30"
probe "[S77-fix-2] pe-objectd unix socket path (smoke previously WARN'd)" \
    "ls -la /run/pe-compat/ 2>&1; ss -lx 2>/dev/null | grep -E 'objects|pe-compat' | head -5"

# --- S78 new surfaces: trust_attest_quine ---
probe "[S78-Dev-B] /sys/kernel/trust_attest_quine/ (NEW S78)" \
    "ls /sys/kernel/trust_attest_quine/ 2>&1; for f in text_hash recompute_count quine_uninit_reads; do echo -n \"  \$f: \"; cat /sys/kernel/trust_attest_quine/\$f 2>/dev/null || echo '(absent - trust.ko not loaded)'; done"

# --- S78 new surfaces: trust_quorum HMAC ---
probe "[S78-Dev-B] /sys/kernel/trust/quorum/ (S75+S78 HMAC extension)" \
    "ls /sys/kernel/trust/quorum/ 2>&1; for f in last_hmac hmac_computed hmac_failed consistent discrepant divergent; do echo -n \"  \$f: \"; cat /sys/kernel/trust/quorum/\$f 2>/dev/null || echo '(absent - trust.ko not loaded)'; done"

# --- S75 library_census endpoint ---
probe "[S75 Agent B] GET /metrics/ecosystem" \
    "curl -s -m 5 http://127.0.0.1:8420/metrics/ecosystem 2>&1 | head -30"

# --- S76 Agent D depth_observer endpoint ---
probe "[S76 Agent D] GET /metrics/depth" \
    "curl -s -m 5 http://127.0.0.1:8420/metrics/depth 2>&1 | head -30"

# --- S76 Agent D differential_observer endpoint ---
probe "[S76 Agent D] GET /metrics/deltas" \
    "curl -s -m 5 http://127.0.0.1:8420/metrics/deltas 2>&1 | head -40"

# --- S75 Agent C Monte Carlo rollout ---
probe "[S75 Agent C] POST /cortex/monte_carlo/rollout" \
    "curl -s -m 5 -X POST -H 'Content-Type: application/json' -d '{\"actions\":[\"noop\",\"allow\",\"deny\"],\"n_rollouts\":32,\"reward_profile\":\"uniform\"}' http://127.0.0.1:8420/cortex/monte_carlo/rollout 2>&1 | head -40"

# --- dmesg for kernel side ---
probe "[kernel] dmesg (trust.ko attempts + anything unusual)" \
    "dmesg 2>/dev/null | tail -40 | grep -iE 'trust|error|fail|panic' | head -30"

# --- journal for all S78 init ---
probe "[journal] ai-control + ai-cortex last 20 lines each" \
    "journalctl -u ai-control.service --no-pager -n 20; echo ---; journalctl -u ai-cortex.service --no-pager -n 20"

# --- final state ---
probe "[summary] systemctl --failed + service rollup" \
    "systemctl --failed --no-pager; echo ---; systemctl is-active ai-control ai-cortex pe-objectd scm-daemon"

echo ""
echo "========================================"
echo "  LIVE DEBUG COMPLETE — shutting down"
echo "========================================"

# Shutdown
$SSH "poweroff" 2>/dev/null || true
sleep 5
kill -TERM "$QEMU_PID" 2>/dev/null || true
sleep 3
kill -9 "$QEMU_PID" 2>/dev/null || true
rm -rf "$TMP" 2>/dev/null || true
echo "Serial log preserved: $SERIAL_LOG"
