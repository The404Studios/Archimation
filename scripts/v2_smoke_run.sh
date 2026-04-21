#!/bin/bash
# v2_smoke_run.sh — boot newest ISO, mint TRUST_ADMIN bearer, run v2_smoke.py.
# Mirrors set_smoke_run.sh but routes long-tail phrases that should hit v2.

set +e

ISO_DIR="/mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control/output"
ISO=$(ls -t "$ISO_DIR"/*.iso 2>/dev/null | grep -v '\.bak\|\.pkg' | head -1)
EXTRACT=/tmp/iso-v2-smoke
SERIAL=/tmp/serial-v2-smoke.log
RESULT=/tmp/v2_smoke.json
SSH_PORT=2234
DAEMON_PORT=8434
SCRIPT_SRC="/mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control/scripts/v2_smoke.py"

echo "ISO=$ISO"
mkdir -p "$EXTRACT"
cd "$EXTRACT" || exit 1
bsdtar xf "$ISO" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null

# S74-V: Truncate serial log — QEMU opens file:$SERIAL in O_WRONLY|O_CREAT
# (no O_TRUNC), so leftover boot text from a prior run causes wait_for_boot
# to false-match before the new QEMU has written anything.
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
# S74-V: Retry SSH for up to 90s — wait_for_boot can match banner text
# BEFORE sshd binds. Match set_smoke_run.sh's retry pattern.
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

# Mint TRUST_ADMIN bearer
TOKEN=$("${SSH_BASE[@]}" "curl -sS -X POST http://127.0.0.1:8420/auth/token -H 'Content-Type: application/json' -d '{\"subject_id\": 1, \"name\": \"v2-smoke\", \"trust_level\": 600}' 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin).get(\"token\",\"\"))' 2>/dev/null")
echo "TOKEN length: ${#TOKEN}"

# Verify v2 artifact present
echo ""
echo "=== checking v2 artifact in VM ==="
"${SSH_BASE[@]}" "ls -la /usr/share/ai-control/dictionary_v2.pkl.zst 2>&1"

# scp + run
sshpass -p "$SSH_PASS" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -P $SSH_PORT "$SCRIPT_SRC" "${SSH_USER}@127.0.0.1:/tmp/v2_smoke.py"

echo ""
echo "=== running v2_smoke.py ==="
"${SSH_BASE[@]}" "AICONTROL_TOKEN='$TOKEN' timeout 300 python3 /tmp/v2_smoke.py" > "$RESULT" 2>/tmp/v2_smoke_stderr.log
RC=$?
echo "Smoke exit: $RC size=$(wc -c < "$RESULT") bytes"
cat /tmp/v2_smoke_stderr.log

kill $QEMU 2>/dev/null
wait $QEMU 2>/dev/null

# Pretty per-family tally
echo ""
echo "============================================================"
echo "  V2 LONG-TAIL SMOKE RESULTS"
echo "============================================================"
python3 <<PYEOF
import json
try:
    d = json.load(open('$RESULT'))
except Exception as e:
    print('parse failed:', e)
    raise SystemExit(1)

results = d.get('results', [])
total = d.get('total', 0)
routed = d.get('routed', 0)
v2_hits = d.get('v2_template_hits', 0)
print(f"  TOTAL: {routed}/{total} phrases routed")
print(f"  SOURCE=v2_template: {v2_hits}/{total}")
print()

by_family = {}
for r in results:
    fam = r['expected'].split('.', 1)[0]
    by_family.setdefault(fam, []).append(r)

for fam in sorted(by_family):
    rows = by_family[fam]
    ok = sum(1 for r in rows if r['routed'])
    bad = [r for r in rows if not r['routed']]
    icon = '[OK]' if ok == len(rows) else '[WARN]'
    print(f"{icon:6s} {fam:15s} {ok}/{len(rows)}")
    for r in bad:
        print(f"           - {r['phrase']!r} wanted {r['expected']} got {r['actual_handler']} (http={r['http_status']}, {r['elapsed_ms']}ms)")
PYEOF

exit $RC
