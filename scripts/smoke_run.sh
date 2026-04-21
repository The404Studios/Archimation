#!/bin/bash
# smoke_run.sh — boot newest ISO, mint token, run sweep_handlers_with_nl.py + sweep_handlers.py.
# Output: /tmp/smoke_full.json (NL + binary probe) and /tmp/smoke_sweep.json (handler dispatch).

set +e

ISO_DIR="/mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control/output"
ISO=$(ls -t "$ISO_DIR"/*.iso 2>/dev/null | grep -v '\.bak\|\.pkg' | head -1)
EXTRACT=/tmp/iso-smoke
SERIAL=/tmp/serial-smoke.log
NL_RESULT=/tmp/smoke_full.json
SWEEP_RESULT=/tmp/smoke_sweep.json
SSH_PORT=2232
DAEMON_PORT=8432
SCRIPTS_DIR="/mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control/scripts"

echo "ISO=$ISO"
mkdir -p "$EXTRACT"
cd "$EXTRACT" || exit 1
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
echo "QEMU_PID=$QEMU"

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

echo "Waiting for boot (max 300s)..."
wait_for_boot "$SERIAL" 300

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -p $SSH_PORT)
if sshpass -p root ssh "${SSH_OPTS[@]}" root@127.0.0.1 "echo SSHOK" 2>/dev/null | grep -q SSHOK; then
    SSH_USER=root; SSH_PASS=root
elif sshpass -p arch ssh "${SSH_OPTS[@]}" arch@127.0.0.1 "echo SSHOK" 2>/dev/null | grep -q SSHOK; then
    SSH_USER=arch; SSH_PASS=arch
else
    echo "SSH FAILED on both"
    kill $QEMU 2>/dev/null; exit 1
fi
echo "SSH_USER=$SSH_USER"

SSH_BASE=(sshpass -p "$SSH_PASS" ssh "${SSH_OPTS[@]}" "${SSH_USER}@127.0.0.1")

# Wait for daemon
for i in $(seq 1 30); do
    "${SSH_BASE[@]}" "ss -tlnp 2>/dev/null | grep -q :8420" && { echo "  daemon listening after ${i}s"; break; }
    sleep 2
done
sleep 30  # CB cooldown

# Mint TRUST_INTERACT token via localhost-bypass
echo "Minting bearer token..."
TOKEN=$("${SSH_BASE[@]}" "curl -sS -X POST http://127.0.0.1:8420/auth/token -H 'Content-Type: application/json' -d '{\"subject_id\": 1, \"name\": \"smoke-run\", \"trust_level\": 600}' 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin).get(\"token\",\"\"))' 2>/dev/null")
if [ -z "$TOKEN" ]; then
    # Fallback to TRUST_OPERATOR (400)
    TOKEN=$("${SSH_BASE[@]}" "curl -sS -X POST http://127.0.0.1:8420/auth/token -H 'Content-Type: application/json' -d '{\"subject_id\": 1, \"name\": \"smoke-run\", \"trust_level\": 400}' 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin).get(\"token\",\"\"))' 2>/dev/null")
fi
if [ -z "$TOKEN" ]; then
    echo "Token mint FAILED — falling back to anonymous"
fi
echo "TOKEN length: ${#TOKEN}"

# Copy both scripts in
sshpass -p "$SSH_PASS" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P $SSH_PORT \
    "$SCRIPTS_DIR/sweep_handlers.py" "$SCRIPTS_DIR/sweep_handlers_with_nl.py" "${SSH_USER}@127.0.0.1:/tmp/"

# Run binaries + NL probe (needs token via env)
echo "=== Running NL + binary probe ==="
if [ "$SSH_USER" = "root" ]; then
    "${SSH_BASE[@]}" "AICONTROL_TOKEN='$TOKEN' timeout 120 python3 /tmp/sweep_handlers_with_nl.py" > "$NL_RESULT" 2>/tmp/smoke_nl_stderr.log
else
    "${SSH_BASE[@]}" "AICONTROL_TOKEN='$TOKEN' timeout 120 python3 /tmp/sweep_handlers_with_nl.py" > "$NL_RESULT" 2>/tmp/smoke_nl_stderr.log
fi
echo "NL probe exit: $? size=$(wc -c < "$NL_RESULT")"

# Run handler sweep (no token needed — direct python import)
echo "=== Running handler sweep ==="
if [ "$SSH_USER" = "root" ]; then
    "${SSH_BASE[@]}" "timeout 240 python3 /tmp/sweep_handlers.py" > "$SWEEP_RESULT" 2>/tmp/smoke_sw_stderr.log
else
    "${SSH_BASE[@]}" "echo $SSH_PASS | sudo -S timeout 240 python3 /tmp/sweep_handlers.py 2>/dev/null" > "$SWEEP_RESULT" 2>/tmp/smoke_sw_stderr.log
fi
echo "Sweep exit: $? size=$(wc -c < "$SWEEP_RESULT")"

kill $QEMU 2>/dev/null
wait $QEMU 2>/dev/null

# Tally
echo ""
echo "=== BINARY PRESENCE ==="
python3 -c "
import json
try:
    d = json.load(open('$NL_RESULT'))
    print('summary:', d.get('summary'))
    for b in d.get('binaries', []):
        flag = 'OK ' if b['present'] else 'MISS'
        print(f\"  [{flag}] {b['binary']:18s} ({b['package']:18s}) {b.get('path') or ''}\")
except Exception as e:
    print(f'parse failed: {e}')
    print('--- stderr tail ---')
    try: print(open('/tmp/smoke_nl_stderr.log').read()[-1500:])
    except: pass
"

echo ""
echo "=== NL COMMANDS ==="
python3 -c "
import json
try:
    d = json.load(open('$NL_RESULT'))
    rows = d.get('nl_commands', [])
    matched = [r for r in rows if r['matched']]
    miss = [r for r in rows if not r['matched']]
    print(f'matched: {len(matched)} / {len(rows)}')
    if miss:
        print('MISSED:')
        for r in miss:
            print(f\"  '{r[\"phrase\"]}' (wanted {r[\"expected_substr\"]}, got {r[\"actual_handler\"]!r}, http={r[\"http_status\"]})\")
except Exception as e:
    print(f'parse failed: {e}')
"

echo ""
echo "=== SWEEP TALLY ==="
python3 -c "
import json
try:
    d = json.load(open('$SWEEP_RESULT'))
    print('total:', d.get('total_handlers'))
    print('tally:', d.get('tally'))
    print('errors:', d.get('errors_detail'))
    print('timeouts:', d.get('timeouts_detail'))
    print('by_family:')
    for fam, t in sorted(d.get('by_family', {}).items()):
        print(f'  {fam}: PASS={t[\"PASS\"]} REJECT={t[\"SAFE_REJECT\"]} TIMEOUT={t[\"TIMEOUT\"]} ERROR={t[\"ERROR\"]}')
except Exception as e:
    print(f'parse failed: {e}')
"
