#!/bin/bash
# sweep_run.sh — boot pkg-8 ISO in QEMU, scp sweep_handlers.py in, run it,
# write the JSON result to /tmp/sweep_result.json.
#
# Caller: bash scripts/sweep_run.sh
# Output: /tmp/sweep_result.json (parsed by humans or downstream tools)

set +e

ISO_DIR="/mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control/output"
ISO=$(ls -t "$ISO_DIR"/*.iso 2>/dev/null | grep -v '\.bak$' | head -1)
EXTRACT=/tmp/iso-sweep
SERIAL=/tmp/serial-sweep.log
RESULT=/tmp/sweep_result.json
SSH_PORT=2231
SCRIPT_SRC="/mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control/scripts/sweep_handlers.py"

echo "ISO=$ISO"
echo "RESULT=$RESULT"

mkdir -p "$EXTRACT"
cd "$EXTRACT" || exit 1
bsdtar xf "$ISO" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null

# Boot QEMU TCG (no KVM in WSL2)
qemu-system-x86_64 -m 4096 -smp 2 \
    -drive file="$ISO",media=cdrom,if=ide,index=1 \
    -kernel "$EXTRACT/arch/boot/x86_64/vmlinuz-linux" \
    -initrd "$EXTRACT/arch/boot/x86_64/initramfs-linux.img" \
    -append "archisobasedir=arch archisolabel=AI_ARCH_202604 archisodevice=/dev/sr0 console=ttyS0,115200 tsc=unstable" \
    -display none -serial "file:$SERIAL" \
    -net nic,model=virtio -net "user,hostfwd=tcp::${SSH_PORT}-:22" \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 -no-reboot >/dev/null 2>&1 &
QEMU=$!
echo "QEMU_PID=$QEMU"

# Boot takes ~82s under TCG; settle to 150s for daemons + cortex
echo "Waiting 150s for boot + cortex..."
sleep 150

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -p $SSH_PORT)

if sshpass -p root ssh "${SSH_OPTS[@]}" root@127.0.0.1 "echo SSHOK" 2>/dev/null | grep -q SSHOK; then
    SSH_USER=root; SSH_PASS=root
elif sshpass -p arch ssh "${SSH_OPTS[@]}" arch@127.0.0.1 "echo SSHOK" 2>/dev/null | grep -q SSHOK; then
    SSH_USER=arch; SSH_PASS=arch
else
    echo "SSH FAILED on both root@root and arch@arch"
    kill $QEMU 2>/dev/null
    exit 1
fi
echo "SSH_USER=$SSH_USER"

SSH_BASE=(sshpass -p "$SSH_PASS" ssh "${SSH_OPTS[@]}" "${SSH_USER}@127.0.0.1")
SCP_BASE=(sshpass -p "$SSH_PASS" scp "${SSH_OPTS[@]/-p $SSH_PORT/-P $SSH_PORT}")

# Wait for ai-control daemon to be listening
echo "Waiting for ai-control daemon..."
for i in $(seq 1 30); do
    if "${SSH_BASE[@]}" "ss -tlnp 2>/dev/null | grep -q :8420"; then
        echo "  daemon listening after ${i}s"
        break
    fi
    sleep 2
done

# 30s settle for cortex + circuit-breaker cooldown
sleep 30

# scp the sweep script in
echo "Copying sweep_handlers.py to VM..."
sshpass -p "$SSH_PASS" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -P $SSH_PORT "$SCRIPT_SRC" "${SSH_USER}@127.0.0.1:/tmp/sweep_handlers.py"

# Run it as root via sudo (or directly if SSH_USER=root)
echo "Running sweep on VM (timeout 240s)..."
if [ "$SSH_USER" = "root" ]; then
    "${SSH_BASE[@]}" "timeout 240 python3 /tmp/sweep_handlers.py" > "$RESULT" 2>/tmp/sweep_stderr.log
else
    "${SSH_BASE[@]}" "echo $SSH_PASS | sudo -S timeout 240 python3 /tmp/sweep_handlers.py 2>/dev/null" > "$RESULT" 2>/tmp/sweep_stderr.log
fi
SWEEP_RC=$?

echo "Sweep exit code: $SWEEP_RC"
echo "Result size: $(wc -c < "$RESULT") bytes"

# Tear down
kill $QEMU 2>/dev/null
wait $QEMU 2>/dev/null

# Quick tally on stdout for the operator
echo ""
echo "=== TALLY ==="
python3 -c "
import json, sys
try:
    d = json.load(open('$RESULT'))
    print('total_handlers:', d.get('total_handlers'))
    print('tally:', d.get('tally'))
    if d.get('errors_detail'):
        print('ERRORS:')
        for e in d['errors_detail']:
            print(f\"  {e['handler']}: {e['detail']}\")
    if d.get('timeouts_detail'):
        print('TIMEOUTS:', d['timeouts_detail'])
    print('by_family:')
    for fam, t in sorted(d.get('by_family', {}).items()):
        print(f'  {fam}: {t}')
except Exception as e:
    print(f'parse failed: {e}')
    print('--- raw stderr ---')
    print(open('/tmp/sweep_stderr.log').read()[-2000:])
"

exit $SWEEP_RC
