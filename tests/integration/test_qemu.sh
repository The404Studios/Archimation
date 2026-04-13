#!/bin/bash
# Integration test: Boot ISO in QEMU, wait for AI daemon, run smoke tests.
#
# Usage:
#   ./test_qemu.sh              # Interactive mode (GUI)
#   ./test_qemu.sh --headless   # CI mode (no display)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
OUTPUT_DIR="$ROOT_DIR/output"
HOST="127.0.0.1"
PORT=8420
TIMEOUT=120  # Max seconds to wait for daemon

HEADLESS=0
if [[ "${1:-}" == "--headless" || "${1:-}" == "--ci" ]]; then
    HEADLESS=1
fi

# Find ISO
ISO=$(ls -t "$OUTPUT_DIR"/*.iso 2>/dev/null | head -1)
if [ -z "$ISO" ]; then
    echo "ERROR: No ISO found in $OUTPUT_DIR"
    echo "Run 'make iso' first."
    exit 1
fi

echo "=== QEMU Integration Test ==="
echo "ISO: $ISO"
echo "Mode: $([ $HEADLESS -eq 1 ] && echo 'headless' || echo 'interactive')"
echo ""

# Build QEMU command
KVM_FLAG=""
if [ -e /dev/kvm ]; then
    KVM_FLAG="-enable-kvm"
fi

DISPLAY_OPT="-vga virtio -display sdl"
if [ $HEADLESS -eq 1 ]; then
    DISPLAY_OPT="-nographic"
fi

# Start QEMU in background
echo "[*] Starting QEMU..."
qemu-system-x86_64 \
    $KVM_FLAG \
    -cdrom "$ISO" \
    -m 4G \
    -smp 2 \
    -boot d \
    $DISPLAY_OPT \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::${PORT}-:${PORT},hostfwd=tcp::2222-:22 \
    -usb \
    -device usb-tablet \
    -serial mon:stdio \
    &
QEMU_PID=$!

cleanup() {
    echo ""
    echo "[*] Stopping QEMU (pid=$QEMU_PID)..."
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for SSH to become available first (more reliable than direct HTTP)
SSH_PORT=2222
echo "[*] Waiting for SSH on $HOST:$SSH_PORT (timeout=${TIMEOUT}s)..."
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if timeout 3 bash -c "echo > /dev/tcp/$HOST/$SSH_PORT" 2>/dev/null; then
        echo "[+] SSH is UP after ${ELAPSED}s"
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    if [ $((ELAPSED % 10)) -eq 0 ]; then
        echo "    ...waiting (${ELAPSED}s)"
    fi
done

if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "[-] TIMEOUT: SSH did not respond within ${TIMEOUT}s"
    exit 1
fi

# Give services time to start after SSH is up
echo "[*] Waiting 15s for services to stabilize..."
sleep 15

# Test AI daemon: try direct first, then SSH tunnel
echo "[*] Checking AI daemon..."
DAEMON_UP=0
# Method 1: Direct port forward
if curl -s -o /dev/null -w '%{http_code}' "http://$HOST:$PORT/health" 2>/dev/null | grep -q 200; then
    DAEMON_UP=1
    DAEMON_METHOD="direct"
fi
# Method 2: Via SSH (WSL2 port forwarding can be unreliable)
if [ "$DAEMON_UP" -eq 0 ] && command -v sshpass >/dev/null 2>&1; then
    SSH_HEALTH=$(sshpass -p arch ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        arch@$HOST -p $SSH_PORT "curl -s http://localhost:8420/health" 2>/dev/null || echo "")
    if echo "$SSH_HEALTH" | grep -q '"status":"ok"'; then
        DAEMON_UP=1
        DAEMON_METHOD="ssh"
    fi
fi

if [ "$DAEMON_UP" -eq 0 ]; then
    echo "[-] AI daemon not reachable (tried direct and SSH)"
    exit 1
fi
echo "[+] AI daemon is UP (via $DAEMON_METHOD)"

# Run smoke tests
echo ""
echo "=== Smoke Tests ==="
TESTS_PASSED=0
TESTS_FAILED=0

smoke_test() {
    local name="$1"
    local method="$2"
    local path="$3"
    local expected="${4:-200}"

    printf "  %-45s " "$name"
    local status
    if [ "$DAEMON_METHOD" = "ssh" ]; then
        status=$(sshpass -p arch ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
            arch@$HOST -p $SSH_PORT \
            "curl -s -o /dev/null -w '%{http_code}' -X $method http://localhost:8420$path" 2>/dev/null)
    else
        status=$(curl -s -o /dev/null -w '%{http_code}' -X "$method" "http://$HOST:$PORT$path" 2>/dev/null)
    fi

    if [ "$status" = "$expected" ]; then
        echo -e "\033[32mPASS\033[0m ($status)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "\033[31mFAIL\033[0m (got $status, expected $expected)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

smoke_test "Health check"              GET  /health
smoke_test "System info"               GET  /system/info
smoke_test "Screen size"               GET  /screen/size
smoke_test "Network IP"                GET  /network/ip
smoke_test "DNS servers"               GET  /network/dns
smoke_test "Firewall status"           GET  /firewall/status
smoke_test "Services list"             GET  /services
smoke_test "Win services list"         GET  /win-services
smoke_test "SCM daemon status"         GET  /win-services-scm/status
smoke_test "Trust subjects"            GET  /trust/subjects
smoke_test "Trust anomalies"           GET  /trust/anomalies
smoke_test "Trust architecture"        GET  /trust/architecture
smoke_test "Audit log"                 GET  /audit/recent
smoke_test "Auth token creation"       POST /auth/token
smoke_test "Screen capture (base64)"   GET  /screen/capture/base64

# Check AI daemon version
echo ""
echo "[*] Daemon info:"
curl -s "http://$HOST:$PORT/health" | python3 -m json.tool 2>/dev/null || curl -s "http://$HOST:$PORT/health"
echo ""

# Summary
echo ""
echo "=== Results: $TESTS_PASSED passed, $TESTS_FAILED failed ==="

if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
fi

echo ""
echo "[+] All smoke tests passed!"
exit 0
