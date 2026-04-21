#!/bin/bash
# set_smoke_run.sh — boot newest ISO, mint TRUST_ADMIN bearer, run set_smoke.py.
# Output: /tmp/set_smoke.json + a per-set GREEN/YELLOW/RED tally on stdout.

set +e

ISO_DIR="/mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control/output"
ISO=$(ls -t "$ISO_DIR"/*.iso 2>/dev/null | grep -v '\.bak\|\.pkg' | head -1)
EXTRACT=/tmp/iso-set-smoke
SERIAL=/tmp/serial-set-smoke.log
RESULT=/tmp/set_smoke.json
SSH_PORT=2233
DAEMON_PORT=8433
SCRIPT_SRC="/mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control/scripts/set_smoke.py"
# S70: piggyback the impressive_demo onto the same booted QEMU to save ~3 min.
DEMO_SRC="/mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control/scripts/ai_impressive_demo.py"
DEMO_RESULT=/tmp/ai_impressive_demo.log

echo "ISO=$ISO"
mkdir -p "$EXTRACT"
cd "$EXTRACT" || exit 1
bsdtar xf "$ISO" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null

# Truncate serial log — QEMU's `file:` mode opens O_WRONLY|O_CREAT (not O_TRUNC),
# so a leftover log from a prior run would let wait_for_boot's grep match stale
# boot text before the fresh QEMU has written anything.
: > "$SERIAL"

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
SSH_USER=""
# Retry SSH for up to 90s — wait_for_boot matches "Reached target Multi-User"
# which fires BEFORE sshd binds. Match test-qemu.sh's retry pattern.
for i in $(seq 1 18); do
    if sshpass -p root ssh "${SSH_OPTS[@]}" root@127.0.0.1 "echo SSHOK" 2>/dev/null | grep -q SSHOK; then
        SSH_USER=root; SSH_PASS=root
        echo "  SSH ready after ${i} attempts"
        break
    elif sshpass -p arch ssh "${SSH_OPTS[@]}" arch@127.0.0.1 "echo SSHOK" 2>/dev/null | grep -q SSHOK; then
        SSH_USER=arch; SSH_PASS=arch
        echo "  SSH ready after ${i} attempts"
        break
    fi
    sleep 5
done
if [ -z "$SSH_USER" ]; then
    echo "SSH FAILED after 90s retry"; kill $QEMU 2>/dev/null; exit 1
fi
echo "SSH_USER=$SSH_USER"

SSH_BASE=(sshpass -p "$SSH_PASS" ssh "${SSH_OPTS[@]}" "${SSH_USER}@127.0.0.1")

# Wait for daemon
for i in $(seq 1 30); do
    "${SSH_BASE[@]}" "ss -tlnp 2>/dev/null | grep -q :8420" && { echo "  daemon up after ${i}s"; break; }
    sleep 2
done
sleep 30  # CB cooldown

# Mint TRUST_ADMIN bearer (working S56 payload)
TOKEN=$("${SSH_BASE[@]}" "curl -sS -X POST http://127.0.0.1:8420/auth/token -H 'Content-Type: application/json' -d '{\"subject_id\": 1, \"name\": \"set-smoke\", \"trust_level\": 600}' 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin).get(\"token\",\"\"))' 2>/dev/null")
echo "TOKEN length: ${#TOKEN}"

# scp + run
sshpass -p "$SSH_PASS" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -P $SSH_PORT "$SCRIPT_SRC" "${SSH_USER}@127.0.0.1:/tmp/set_smoke.py"

"${SSH_BASE[@]}" "AICONTROL_TOKEN='$TOKEN' timeout 180 python3 /tmp/set_smoke.py" > "$RESULT" 2>/tmp/set_smoke_stderr.log
echo "Smoke exit: $? size=$(wc -c < "$RESULT") bytes"

# S70: piggyback ai_impressive_demo on the same booted QEMU (5+ groups,
# ~40 phrases across ONE_WORD / QUERIES / COMPOUND / SOFTWARE_INSTALL /
# PE_LOADER / FILE_OPS / CLARIFICATION). Reuses the same $TOKEN, so we
# save a full ~3min QEMU boot cycle by running it here.
if [ -f "$DEMO_SRC" ]; then
    echo ""
    echo "--- ai_impressive_demo.py ---"
    sshpass -p "$SSH_PASS" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -P $SSH_PORT "$DEMO_SRC" "${SSH_USER}@127.0.0.1:/tmp/ai_impressive_demo.py"
    "${SSH_BASE[@]}" "AICONTROL_TOKEN='$TOKEN' timeout 120 python3 /tmp/ai_impressive_demo.py" \
        > "$DEMO_RESULT" 2>&1
    echo "Demo exit: $? size=$(wc -c < "$DEMO_RESULT") bytes"
    # Print the final tally lines only (last ~15 lines)
    tail -20 "$DEMO_RESULT" || true
fi

kill $QEMU 2>/dev/null
wait $QEMU 2>/dev/null

# Pretty per-set tally
echo ""
echo "============================================================"
echo "  SET-ORGANIZED SMOKE RESULTS"
echo "============================================================"
python3 -c "
import json
try:
    d = json.load(open('$RESULT'))
except Exception as e:
    print('parse failed:', e)
    print(open('/tmp/set_smoke_stderr.log').read()[-1500:])
    exit(1)

s = d['summary']
print(f\"  TOTAL: {s['phrases_routed']}/{s['total_phrases']} phrases routed\")
print(f\"  SETS:  GREEN={s['GREEN']}  YELLOW={s['YELLOW']}  RED={s['RED']} (of {s['total_sets']})\")
print()

for set_name, info in d['sets'].items():
    color = info['status']
    icon = {'GREEN': '[OK]  ', 'YELLOW': '[WARN]', 'RED': '[FAIL]'}.get(color, '[??]')
    print(f\"{icon} {set_name:14s} {info['routed']:>6s}  status={color}\")
    if color != 'GREEN':
        for p in info['phrases']:
            if not p['routed']:
                print(f\"           - '{p['phrase']}' wanted {p['expected']} got {p['actual_handler']!r} (http={p['http_status']}, {p['elapsed_ms']}ms)\")
"
