#!/bin/bash
# test-incremental.sh - Deploy and test with retries
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

SSH="sshpass -p root ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ServerAliveInterval=5 -p 2222 root@127.0.0.1"
SCP="sshpass -p root scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P 2222"

PE_DIR="$PROJECT_DIR/pe-loader"
TEST_DIR="$PROJECT_DIR/tests/pe-loader"

scp_retry() {
    for i in 1 2 3; do
        $SCP "$1" root@127.0.0.1:"$2" 2>/dev/null && return 0
        sleep 1
    done
    echo "WARN: Failed to copy $1"
    return 1
}

echo "=== Deploy ==="
$SSH "mkdir -p /opt/pe-loader/dlls" 2>/dev/null

scp_retry "$PE_DIR/loader/peloader" /opt/pe-loader/
echo "  peloader"

# Copy .so files one by one
for f in $PE_DIR/dlls/libpe_*.so; do
    scp_retry "$f" /opt/pe-loader/dlls/
done
echo "  .so files"

for f in test_minimal.exe test_full_exe.exe test_service.exe test_driver.sys; do
    scp_retry "$TEST_DIR/$f" /opt/pe-loader/ 2>/dev/null || true
done
echo "  test executables"

scp_retry /tmp/putty64.exe /opt/pe-loader/ 2>/dev/null || true
echo "  putty64.exe"
STEAM_SETUP="${STEAM_SETUP:-$HOME/Downloads/SteamSetup.exe}"
scp_retry "$STEAM_SETUP" /opt/pe-loader/ 2>/dev/null || true
echo "  SteamSetup.exe"

echo ""
echo "=== Tests ==="
PASS=0; FAIL=0

run_test() {
    local name="$1"
    local cmd="$2"
    local match="$3"
    echo "--- $name ---"
    local out
    out=$($SSH "$cmd" 2>&1 || true)
    echo "$out" | tail -8
    if echo "$out" | grep -q "$match"; then
        echo "  PASS"
        PASS=$((PASS+1))
    else
        echo "  FAIL"
        FAIL=$((FAIL+1))
    fi
    echo ""
}

run_test "test_minimal.exe" \
    "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader test_minimal.exe" \
    "HELLO FROM PE"

run_test "test_full_exe.exe" \
    "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 15 ./peloader test_full_exe.exe" \
    "ALL TESTS PASSED"

run_test "test_service.exe" \
    "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader test_service.exe" \
    "entry point"

run_test "test_driver.sys" \
    "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader test_driver.sys" \
    "driver"

run_test "SteamSetup.exe (PE32 reject)" \
    "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader SteamSetup.exe" \
    "32-bit"

echo "--- putty64.exe --diag ---"
OUT=$($SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 15 ./peloader --diag putty64.exe" 2>&1 || true)
echo "$OUT" | head -12
echo "..."
UNRESOLVED=$(echo "$OUT" | grep -c "UNRESOLVED" || echo 0)
echo "Unresolved imports: $UNRESOLVED"
echo "$OUT" | grep "UNRESOLVED" | head -15
echo "$OUT" | tail -3
if echo "$OUT" | grep -qE "PE32\+|AMD64"; then
    echo "  PASS"; PASS=$((PASS+1))
else
    echo "  FAIL"; FAIL=$((FAIL+1))
fi
echo ""

echo "--- putty64.exe (execution) ---"
OUT=$($SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 5 ./peloader putty64.exe" 2>&1 || true)
echo "$OUT" | head -30
echo "..."
echo "$OUT" | tail -10
echo ""

echo "============================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "============================================"
