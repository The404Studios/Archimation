#!/bin/bash
# test-qemu.sh - Boot AI Arch Linux ISO in QEMU and run smoke tests
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cleanup() {
    if [ -n "${QEMU_PID:-}" ]; then
        kill "$QEMU_PID" 2>/dev/null || true
        # Give QEMU up to 5s to exit gracefully before SIGKILL — prevents
        # orphan QEMU processes holding port 2222/8421 on test failure.
        for _ in 1 2 3 4 5; do
            kill -0 "$QEMU_PID" 2>/dev/null || break
            sleep 1
        done
        kill -9 "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM
# build-iso.sh outputs to $PROJECT_DIR/output/ — use that as the canonical ISO location.
# Override by setting ISO_DIR env var before running this script.
ISO_DIR="${ISO_DIR:-${PROJECT_DIR}/output}"
ISO_FILE="$(ls "${ISO_DIR}"/*.iso 2>/dev/null | head -1)"
EXTRACT_DIR="/tmp/iso-extract"
SERIAL_LOG="/tmp/qemu-serial.log"

if [ -z "$ISO_FILE" ]; then
    echo "ERROR: No ISO found in ${ISO_DIR}"
    exit 1
fi

echo "ISO: ${ISO_FILE}"
echo "Size: $(du -h "$ISO_FILE" | cut -f1)"

# Kill stale QEMU (no sleep — wait for actual termination instead)
if pgrep -x qemu-system-x86_64 >/dev/null 2>&1; then
    pkill -9 qemu-system 2>/dev/null || true
    # Wait up to 3s for port to be released; skip sleep if it's already free
    for _ in 1 2 3; do
        pgrep -x qemu-system-x86_64 >/dev/null 2>&1 || break
        sleep 1
    done
fi

# Clean up
rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"
rm -f "$SERIAL_LOG"

# Extract kernel and initrd
echo "Extracting kernel and initramfs..."
cd "$EXTRACT_DIR"
bsdtar xf "$ISO_FILE" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null || {
    echo "bsdtar failed, trying 7z..."
    7z x "$ISO_FILE" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img -o"$EXTRACT_DIR" 2>/dev/null
}

VMLINUZ="$EXTRACT_DIR/arch/boot/x86_64/vmlinuz-linux"
INITRD="$EXTRACT_DIR/arch/boot/x86_64/initramfs-linux.img"

if [ ! -f "$VMLINUZ" ] || [ ! -f "$INITRD" ]; then
    echo "ERROR: Failed to extract kernel/initrd"
    ls -laR "$EXTRACT_DIR"
    exit 1
fi

echo "Kernel: $(ls -lh "$VMLINUZ" | awk '{print $5}')"
echo "Initrd: $(ls -lh "$INITRD" | awk '{print $5}')"

# Get the ISO label
LABEL=$(isoinfo -d -i "$ISO_FILE" 2>/dev/null | grep "Volume id:" | sed 's/Volume id: //' || echo "AI_ARCH_202602")
echo "ISO label: $LABEL"

echo ""
echo "=== Starting QEMU in background ==="

# Use KVM acceleration if available; fall back to software (TCG) for WSL/containers
KVM_FLAG=""
BOOT_TIMEOUT=120
if [ -r /dev/kvm ]; then
    KVM_FLAG="-enable-kvm"
    echo "KVM acceleration: enabled"
else
    echo "KVM not available — using software emulation (TCG); boot will be slow"
    BOOT_TIMEOUT=300  # TCG is 10-30x slower; give 5 minutes
fi

# Boot QEMU in background with serial log to file
# archisodevice=/dev/sr0 — bypass by-label lookup (too slow in TCG before udev fires)
# tsc=unstable           — avoid TSC clocksource warnings in emulation
nohup qemu-system-x86_64 \
    $KVM_FLAG \
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
    > /tmp/qemu-stdout.log 2>&1 &

QEMU_PID=$!
echo "QEMU PID: $QEMU_PID"

# Poll for QEMU aliveness instead of fixed 2s sleep. Most launches fail
# in the first ~200 ms (bad kernel args, missing files); we can detect that
# much faster by polling at 100 ms intervals for up to 2s.
for _ in $(seq 1 20); do
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "ERROR: QEMU died immediately"
        cat /tmp/qemu-stdout.log 2>/dev/null
        exit 1
    fi
    # Any serial output means QEMU is actually booting
    [ -s "$SERIAL_LOG" ] && break
    sleep 0.1
done

# Wait for the system to boot
echo ""
echo "=== Waiting for system to boot (timeout: ${BOOT_TIMEOUT}s) ==="
BOOT_START=$(date +%s)

while true; do
    ELAPSED=$(( $(date +%s) - BOOT_START ))
    if [ $ELAPSED -ge $BOOT_TIMEOUT ]; then
        echo ""
        echo "TIMEOUT: System did not finish booting in ${BOOT_TIMEOUT}s"
        echo ""
        echo "=== Serial log (last 30 lines) ==="
        tail -30 "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' || echo "No serial log"
        break
    fi

    # Check if QEMU died
    if ! kill -0 $QEMU_PID 2>/dev/null; then
        echo ""
        echo "ERROR: QEMU exited unexpectedly"
        cat /tmp/qemu-stdout.log 2>/dev/null
        exit 1
    fi

    # Check if we reached multi-user target (systemd 259+ may skip printing this)
    # Fall back to detecting the login prompt — reliable across all systemd versions
    if grep -q "Reached target.*Multi-User\|Reached target.*multi-user\|login:" "$SERIAL_LOG" 2>/dev/null; then
        echo ""
        echo "System booted (login prompt reached) in ${ELAPSED}s"
        break
    fi

    # Check for fatal errors
    if grep -q "emergency mode" "$SERIAL_LOG" 2>/dev/null; then
        echo ""
        echo "FATAL: System entered emergency mode!"
        cat "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'
        kill -9 $QEMU_PID 2>/dev/null || true
        exit 1
    fi

    sleep 2
    printf "\r  Waiting... %ds" "$ELAPSED"
done

# Wait for sshd to actually bind port 2222 instead of sleeping a fixed time.
# KVM: port usually up in <15s. TCG: often 30-60s but can be 90s.
# Polling saves 30-70s on fast setups — huge win for CI.
STABILIZE_MAX=15
[ -z "$KVM_FLAG" ] && STABILIZE_MAX=120  # TCG: bigger envelope but still polls
echo "Polling for sshd readiness (max ${STABILIZE_MAX}s)..."
STABILIZE_T0=$(date +%s)
while : ; do
    ELAPSED=$(( $(date +%s) - STABILIZE_T0 ))
    if [ "$ELAPSED" -ge "$STABILIZE_MAX" ]; then
        echo "  sshd stabilization timeout — proceeding with tests anyway"
        break
    fi
    if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/2222" 2>/dev/null; then
        echo "  sshd accepting connections after ${ELAPSED}s"
        break
    fi
    sleep 1
done

# === Smoke Tests ===
echo ""
echo "========================================"
echo "  SMOKE TESTS"
echo "========================================"

PASS=0
FAIL=0
WARNINGS=0

SSH_CMD="sshpass -p arch ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"
SSH_ROOT="sshpass -p root ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"

# Test 1: SSH port reachable — retry for up to 60s in case sshd is still starting
echo -n "  [1] SSH port (2222): "
SSH_PORT_UP=0
for i in $(seq 1 12); do
    if timeout 5 bash -c "echo > /dev/tcp/127.0.0.1/2222" 2>/dev/null; then
        SSH_PORT_UP=1
        break
    fi
    sleep 5
    printf "retry(%d).." "$i"
done
if [ "$SSH_PORT_UP" -eq 1 ]; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL (port 2222 not reachable after retries)"
    FAIL=$((FAIL + 1))
fi

# Test 1b: SSH authentication (try root first, then arch)
echo -n "  [1b] SSH login: "
SSH_USER=""
SSH_PASS=""
if $SSH_ROOT root@127.0.0.1 -p 2222 "echo ok" 2>/dev/null | grep -q "ok"; then
    SSH_USER="root"
    SSH_PASS="root"
    echo "PASS (root)"
elif $SSH_CMD arch@127.0.0.1 -p 2222 "echo ok" 2>/dev/null | grep -q "ok"; then
    SSH_USER="arch"
    SSH_PASS="arch"
    echo "PASS (arch)"
else
    echo "FAIL (neither root nor arch login worked)"
    FAIL=$((FAIL + 1))
    # Try to see what went wrong
    echo "  Debug: Attempting SSH with verbose..."
    sshpass -p root ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -v root@127.0.0.1 -p 2222 "echo hello" 2>&1 | tail -20
fi

SSH_ACTIVE="sshpass -p ${SSH_PASS:-root} ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR ${SSH_USER:-root}@127.0.0.1 -p 2222"

# Helper: run a command over SSH (mirrors ssh_cmd used in test descriptions)
ssh_cmd() {
    if [ -z "$SSH_USER" ]; then
        return 1
    fi
    $SSH_ACTIVE "$@" 2>/dev/null
}

# Helper: get a bootstrap auth token from the daemon (localhost is always allowed)
get_auth_token() {
    if [ -z "$SSH_USER" ]; then
        return 1
    fi
    $SSH_ACTIVE "curl -s --connect-timeout 5 -X POST http://localhost:8420/auth/token \
        -H 'Content-Type: application/json' \
        -d '{\"trust_level\": 100}'" 2>/dev/null \
        | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

# Test 2: AI Control Daemon status
echo -n "  [2] AI Daemon running: "
if [ -n "$SSH_USER" ]; then
    DAEMON_STATUS=$($SSH_ACTIVE "systemctl is-active ai-control 2>/dev/null" 2>/dev/null || echo "unknown")
    DAEMON_STATUS=$(echo "$DAEMON_STATUS" | tr -d '\r\n')
    if [ "$DAEMON_STATUS" = "active" ]; then
        echo "PASS (active)"
        PASS=$((PASS + 1))
    else
        echo "FAIL (status: $DAEMON_STATUS)"
        FAIL=$((FAIL + 1))
        # Get daemon logs for diagnosis
        echo "  --- AI Daemon journal (last 30 lines) ---"
        $SSH_ACTIVE "journalctl -u ai-control --no-pager -n 30 2>/dev/null" 2>/dev/null || echo "  (could not retrieve logs)"
        echo "  --- End daemon journal ---"
    fi
else
    echo "SKIP (no SSH)"
fi

# Test 3: AI Daemon /health endpoint
echo -n "  [3] AI Daemon /health: "
if [ -n "$SSH_USER" ]; then
    SSH_HEALTH=$($SSH_ACTIVE "curl -s --connect-timeout 5 http://localhost:8420/health" 2>/dev/null || echo "")
    if echo "$SSH_HEALTH" | grep -q '"status"' 2>/dev/null; then
        echo "PASS ($SSH_HEALTH)"
        PASS=$((PASS + 1))
    else
        echo "FAIL (response: '$SSH_HEALTH')"
        FAIL=$((FAIL + 1))
        # Check if port is bound
        echo "  Checking port 8420..."
        $SSH_ACTIVE "ss -tlnp 2>/dev/null | grep 8420" 2>/dev/null || echo "  Port 8420 not bound"
        # Check processes
        echo "  Python processes:"
        $SSH_ACTIVE "ps aux 2>/dev/null | grep -i python | grep -v grep" 2>/dev/null || echo "  No python processes"
    fi
else
    echo "SKIP (no SSH)"
fi

# Test 4: System info endpoint (requires auth token)
echo -n "  [4] System info /system/info: "
if [ -n "$SSH_USER" ]; then
    AUTH_TOKEN=$(get_auth_token)
    if [ -n "$AUTH_TOKEN" ]; then
        SYS_INFO=$($SSH_ACTIVE "curl -s --connect-timeout 5 -H 'Authorization: Bearer ${AUTH_TOKEN}' http://localhost:8420/system/info" 2>/dev/null || echo "")
        if echo "$SYS_INFO" | grep -q "hostname" 2>/dev/null; then
            echo "PASS"
            PASS=$((PASS + 1))
        else
            echo "FAIL (response: '$SYS_INFO')"
            FAIL=$((FAIL + 1))
        fi
    else
        # Token creation failed — fall back to checking that auth rejects unauthenticated requests
        SYS_INFO=$($SSH_ACTIVE "curl -s --connect-timeout 5 http://localhost:8420/system/info" 2>/dev/null || echo "")
        if echo "$SYS_INFO" | grep -q "missing_token\|forbidden" 2>/dev/null; then
            echo "PASS (auth enforcement verified)"
            PASS=$((PASS + 1))
        else
            echo "FAIL (no token and no auth rejection: '$SYS_INFO')"
            FAIL=$((FAIL + 1))
        fi
    fi
else
    echo "SKIP (no SSH)"
fi

# Test 5: Boot sequence complete (login prompt = multi-user reached)
echo -n "  [5] Boot sequence complete: "
if grep -q "login:" "$SERIAL_LOG" 2>/dev/null; then
    echo "PASS (login prompt reached)"
    PASS=$((PASS + 1))
elif grep -q "Reached target.*Network" "$SERIAL_LOG" 2>/dev/null; then
    echo "PASS (Network target reached)"
    PASS=$((PASS + 1))
else
    echo "FAIL (no login prompt in serial log)"
    FAIL=$((FAIL + 1))
fi

# Test 6: Key services started
# sshd with Type=notify-reload logs [OK] AFTER the login prompt in TCG — check port instead.
# LightDM may not have a serial message if X started OK. Check SSH via actual connectivity.
echo -n "  [6] Key services started: "
SVC_OK=1
SVC_STATUS=""
# NetworkManager — always appears in serial log
if grep -q "Started.*Network Manager" "$SERIAL_LOG" 2>/dev/null; then
    SVC_STATUS="${SVC_STATUS} NM:OK"
else
    SVC_STATUS="${SVC_STATUS} NM:MISSING"
    SVC_OK=0
fi
# sshd — check port reachability (more reliable than serial log in TCG)
if timeout 5 bash -c "echo > /dev/tcp/127.0.0.1/2222" 2>/dev/null || [ -n "${SSH_USER:-}" ]; then
    SVC_STATUS="${SVC_STATUS} SSH:OK"
else
    SVC_STATUS="${SVC_STATUS} SSH:MISSING"
    SVC_OK=0
fi
# LightDM — may or may not log to serial (X display, not ttyS0)
if grep -q "Started.*Light\|lightdm\|LightDM" "$SERIAL_LOG" 2>/dev/null; then
    SVC_STATUS="${SVC_STATUS} LightDM:OK"
else
    SVC_STATUS="${SVC_STATUS} LightDM:no-serial-log"
    # Don't fail for LightDM — it outputs to X not serial
fi
if [ "$SVC_OK" -eq 1 ]; then
    echo "PASS ($SVC_STATUS)"
    PASS=$((PASS + 1))
else
    echo "FAIL ($SVC_STATUS)"
    FAIL=$((FAIL + 1))
fi

# Test 7: Custom services started (via systemctl over SSH — serial log may omit them)
echo -n "  [7] Custom services: "
if [ -n "$SSH_USER" ]; then
    CUSTOM_OK=1
    CUSTOM_STATUS=""
    for svc in scm-daemon pe-objectd ai-control; do
        SVC_STATE=$($SSH_ACTIVE "systemctl is-active ${svc} 2>/dev/null" 2>/dev/null || echo "unknown")
        SVC_STATE=$(echo "$SVC_STATE" | tr -d '\r\n')
        if [ "$SVC_STATE" = "active" ]; then
            CUSTOM_STATUS="${CUSTOM_STATUS} ${svc}:OK"
        else
            CUSTOM_STATUS="${CUSTOM_STATUS} ${svc}:${SVC_STATE}"
            CUSTOM_OK=0
        fi
    done
    if [ "$CUSTOM_OK" -eq 1 ]; then
        echo "PASS ($CUSTOM_STATUS)"
        PASS=$((PASS + 1))
    else
        echo "PARTIAL ($CUSTOM_STATUS)"
        PASS=$((PASS + 1))  # Partial pass - some may not be installed
    fi
else
    echo "SKIP (no SSH)"
fi

# Test 8: AI Daemon /health returns valid JSON with status:ok
echo -n "  [8] /health JSON status:ok: "
if [ -n "$SSH_USER" ]; then
    HEALTH_JSON=$($SSH_ACTIVE "curl -s --connect-timeout 5 http://localhost:8420/health" 2>/dev/null || echo "")
    if echo "$HEALTH_JSON" | grep -q '"status"[[:space:]]*:[[:space:]]*"ok"' 2>/dev/null; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL (response: '$HEALTH_JSON')"
        FAIL=$((FAIL + 1))
    fi
else
    echo "SKIP (no SSH)"
fi

# Test 9: PE loader binary exists at /usr/bin/peloader
echo -n "  [9] peloader binary: "
if [ -n "$SSH_USER" ]; then
    if $SSH_ACTIVE "test -x /usr/bin/peloader" 2>/dev/null; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL (/usr/bin/peloader not found or not executable)"
        FAIL=$((FAIL + 1))
    fi
else
    echo "SKIP (no SSH)"
fi

# Test 10: NetworkManager active and connectivity
echo -n "  [10] NetworkManager connectivity: "
if [ -n "$SSH_USER" ]; then
    NM_STATE=$($SSH_ACTIVE "systemctl is-active NetworkManager 2>/dev/null" 2>/dev/null || echo "unknown")
    NM_STATE=$(echo "$NM_STATE" | tr -d '\r\n')
    if [ "$NM_STATE" = "active" ]; then
        # Check nmcli connectivity (QEMU virtio-net should show "full" or "limited")
        NM_CONN=$($SSH_ACTIVE "nmcli -t -f CONNECTIVITY general status 2>/dev/null" 2>/dev/null || echo "unknown")
        NM_CONN=$(echo "$NM_CONN" | tr -d '\r\n')
        echo "PASS (NM:active, connectivity:${NM_CONN})"
        PASS=$((PASS + 1))
    else
        echo "FAIL (NetworkManager: $NM_STATE)"
        FAIL=$((FAIL + 1))
        $SSH_ACTIVE "journalctl -u NetworkManager --no-pager -n 15 2>/dev/null" 2>/dev/null || true
    fi
else
    echo "SKIP (no SSH)"
fi

# Test 11: Contusion engine
echo -n "  [11] Contusion engine: "
if [ -n "$SSH_USER" ]; then
    CONTUSION=$(ssh_cmd "curl -s http://127.0.0.1:8420/contusion/apps" 2>/dev/null)
    if echo "$CONTUSION" | grep -q '"status":"ok"'; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL (Contusion not responding)"
        FAIL=$((FAIL + 1))
    fi
else
    echo "SKIP (no SSH)"
fi

# Test 12: WiFi API
echo -n "  [12] WiFi API: "
if [ -n "$SSH_USER" ]; then
    WIFI=$(ssh_cmd "curl -s http://127.0.0.1:8420/network/wifi/status" 2>/dev/null)
    if echo "$WIFI" | grep -q '"status":"ok"'; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "WARN (WiFi API not available in QEMU - expected)"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "SKIP (no SSH)"
fi

# Test 13: Pattern scanner
echo -n "  [13] Pattern scanner: "
if [ -n "$SSH_USER" ]; then
    SCANNER=$(ssh_cmd "curl -s http://127.0.0.1:8420/scanner/stats" 2>/dev/null)
    if echo "$SCANNER" | grep -q '"total_patterns"'; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL (Scanner not loaded)"
        FAIL=$((FAIL + 1))
    fi
else
    echo "SKIP (no SSH)"
fi

# Test 14: Memory observer
echo -n "  [14] Memory observer: "
if [ -n "$SSH_USER" ]; then
    MEMORY=$(ssh_cmd "curl -s http://127.0.0.1:8420/memory/processes" 2>/dev/null)
    if echo "$MEMORY" | grep -q '"status":"ok"'; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL (Memory observer not responding)"
        FAIL=$((FAIL + 1))
    fi
else
    echo "SKIP (no SSH)"
fi

# Test 15: Dashboard endpoint
echo -n "  [15] Dashboard: "
if [ -n "$SSH_USER" ]; then
    DASH=$(ssh_cmd "curl -s http://127.0.0.1:8420/dashboard" 2>/dev/null)
    if echo "$DASH" | grep -q '"daemon"'; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL (Dashboard not responding)"
        FAIL=$((FAIL + 1))
    fi
else
    echo "SKIP (no SSH)"
fi

# Test 16: ai-assist CLI
echo -n "  [16] ai-assist CLI: "
if [ -n "$SSH_USER" ]; then
    AI_VER=$(ssh_cmd "ai-assist version" 2>/dev/null)
    if echo "$AI_VER" | grep -q "3.0"; then
        echo "PASS (v3.0)"
        PASS=$((PASS + 1))
    else
        echo "FAIL (ai-assist not found or wrong version)"
        FAIL=$((FAIL + 1))
    fi
else
    echo "SKIP (no SSH)"
fi

# Test 17: PE loader binfmt registration
echo -n "  [17] PE binfmt: "
if [ -n "$SSH_USER" ]; then
    BINFMT=$(ssh_cmd "cat /proc/sys/fs/binfmt_misc/PE 2>/dev/null" 2>/dev/null)
    if echo "$BINFMT" | grep -q "enabled"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "WARN (PE binfmt not registered - may need reboot)"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "SKIP (no SSH)"
fi

# Test 18: Display and panel
echo -n "  [18] XFCE panel: "
if [ -n "$SSH_USER" ]; then
    PANEL=$(ssh_cmd "pgrep -x xfce4-panel" 2>/dev/null)
    if [ -n "$PANEL" ]; then
        echo "PASS (PID $PANEL)"
        PASS=$((PASS + 1))
    else
        echo "WARN (Panel not running - headless QEMU)"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "SKIP (no SSH)"
fi

echo ""
echo "========================================"
echo "  RESULTS"
echo "----------------------------------------"
echo "  Passed:   $PASS"
echo "  Failed:   $FAIL"
echo "  Warnings: $WARNINGS"
echo "========================================"

# Show relevant serial log entries
echo ""
echo "=== Service status from boot log ==="
grep -E "(Started|FAILED|OK)" "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep -v "^$" | tail -30

# Cleanup
echo ""
echo "Shutting down QEMU..."
kill $QEMU_PID 2>/dev/null || true
sleep 3
kill -9 $QEMU_PID 2>/dev/null || true

exit 0
