#!/bin/bash
# Boot QEMU, SSH in, diagnose the Contusion 503 issue, tear down.
set -uo pipefail
PROJECT_DIR="/mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control"
ISO="$(ls "$PROJECT_DIR/output"/*.iso | head -1)"
EXTRACT="$(mktemp -d)"
cd "$EXTRACT"
bsdtar xf "$ISO" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null
LABEL="$(isoinfo -d -i "$ISO" 2>/dev/null | grep "Volume id:" | sed 's/Volume id: //' 2>/dev/null || true)"
[ -z "$LABEL" ] && LABEL="AI_ARCH_202602"
echo "Using ISO label: $LABEL"
pkill -9 qemu-system-x86_64 2>/dev/null
sleep 1
qemu-system-x86_64 -m 3G -smp 2 \
  -kernel arch/boot/x86_64/vmlinuz-linux -initrd arch/boot/x86_64/initramfs-linux.img \
  -append "archisobasedir=arch archisolabel=${LABEL} archisodevice=/dev/sr0 console=ttyS0,115200 tsc=unstable" \
  -drive file="$ISO",media=cdrom,if=ide,index=1 \
  -netdev "user,id=n0,hostfwd=tcp::2222-:22" -device e1000,netdev=n0 \
  -serial file:/tmp/diag-serial.log -display none -daemonize

echo "Booting QEMU (waiting up to 180s for SSH)..."
SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -p 2222 arch@localhost"
for i in $(seq 1 36); do
    sleep 5
    if $SSH "echo ready" 2>/dev/null | grep -q ready; then
        echo "SSH OK after $((i*5))s"
        break
    fi
done

echo
echo "=== cortex systemd state ==="
$SSH "systemctl is-active ai-cortex 2>&1; echo ---; systemctl is-failed ai-cortex 2>&1"

echo
echo "=== cortex journal (last 80) ==="
$SSH "sudo journalctl -u ai-cortex -n 80 --no-pager 2>&1 | tail -80"

echo
echo "=== cortex /health + /emergency/status direct ==="
$SSH "curl -s --max-time 5 http://127.0.0.1:8421/health 2>&1 | head -c 300; echo; curl -s --max-time 5 http://127.0.0.1:8421/emergency/status 2>&1 | head -c 300"

echo
echo "=== Journal: Contusion init warnings ==="
$SSH "sudo journalctl -u ai-control -n 200 --no-pager 2>&1 | grep -iE 'contusion|macro|handler' | head -30"

echo
echo "=== Daemon /contusion/apps raw response ==="
$SSH "curl -s -X POST http://localhost:8420/auth/token -H 'Content-Type: application/json' -d '{\"subject_id\":1,\"name\":\"diag\",\"trust_level\":400}'" > /tmp/token.json
TOK=$(python3 -c 'import sys,json; print(json.load(open("/tmp/token.json")).get("token",""))')
echo "Token first 20: ${TOK:0:20}"
echo
echo "--- /contusion/apps ---"
$SSH "curl -s -H 'Authorization: Bearer $TOK' http://localhost:8420/contusion/apps" | head -c 400
echo
echo
echo "--- /contusion/context POST ---"
$SSH "curl -s -w '\nHTTP:%{http_code}' -H 'Authorization: Bearer $TOK' -H 'Content-Type: application/json' -X POST http://localhost:8420/contusion/context -d '{\"request\":\"turn up the volume\"}'"
echo
echo
echo "--- Python import test inside VM ---"
$SSH "cd /usr/lib/ai-control-daemon && sudo -u root python3 -c 'import sys; sys.path.insert(0, \".\"); from contusion import Contusion; print(\"inst:\", Contusion()); print(\"MACRO:\", __import__(\"contusion\").MACRO_DIR)' 2>&1 | head -10"

echo
pkill -9 qemu-system-x86_64 2>/dev/null
echo "QEMU shut down"
