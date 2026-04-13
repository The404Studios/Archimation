#!/bin/bash
# full-test-v2.sh - Deploy and test PE loader on QEMU VM
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

SSH="sshpass -p root ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p 2222 root@127.0.0.1"
SCP="sshpass -p root scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P 2222"

PE_DIR="$PROJECT_DIR/pe-loader"
TEST_DIR="$PROJECT_DIR/tests/pe-loader"

echo "=== Deploying PE Loader ==="
$SSH "mkdir -p /opt/pe-loader/dlls"

$SCP "$PE_DIR/loader/peloader" root@127.0.0.1:/opt/pe-loader/
echo "  peloader binary"

$SCP $PE_DIR/dlls/*.so root@127.0.0.1:/opt/pe-loader/dlls/
echo "  $(ls $PE_DIR/dlls/*.so | wc -l) DLL .so files"

for f in hello.exe test_minimal.exe test_full_exe.exe test_service.exe test_driver.sys; do
    if [ -f "$TEST_DIR/$f" ]; then
        $SCP "$TEST_DIR/$f" root@127.0.0.1:/opt/pe-loader/
    fi
done
echo "  test executables"

if [ -f /tmp/putty64.exe ]; then
    $SCP /tmp/putty64.exe root@127.0.0.1:/opt/pe-loader/
    echo "  putty64.exe (PE32+)"
fi
STEAM_SETUP="${STEAM_SETUP:-$HOME/Downloads/SteamSetup.exe}"
if [ -f "$STEAM_SETUP" ]; then
    $SCP "$STEAM_SETUP" root@127.0.0.1:/opt/pe-loader/
    echo "  SteamSetup.exe (PE32)"
fi

echo ""
echo "============================================"
echo "  PE LOADER TEST SUITE"
echo "============================================"
echo ""

PASS=0
FAIL=0

echo "--- [1] test_minimal.exe ---"
OUT=$($SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader test_minimal.exe 2>&1" || true)
echo "$OUT" | tail -3
if echo "$OUT" | grep -q "HELLO FROM PE"; then
    echo "  RESULT: PASS"; PASS=$((PASS+1))
else
    echo "  RESULT: FAIL"; FAIL=$((FAIL+1))
fi
echo ""

echo "--- [2] test_full_exe.exe ---"
OUT=$($SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 15 ./peloader test_full_exe.exe 2>&1" || true)
echo "$OUT" | grep -E "PASS|FAIL|Results" | tail -25
if echo "$OUT" | grep -q "ALL TESTS PASSED"; then
    echo "  RESULT: PASS"; PASS=$((PASS+1))
else
    echo "  RESULT: FAIL"; FAIL=$((FAIL+1))
fi
echo ""

echo "--- [3] test_service.exe ---"
OUT=$($SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader test_service.exe 2>&1" || true)
echo "$OUT" | tail -8
if echo "$OUT" | grep -qE "entry point"; then
    echo "  RESULT: PASS"; PASS=$((PASS+1))
else
    echo "  RESULT: FAIL"; FAIL=$((FAIL+1))
fi
echo ""

echo "--- [4] test_driver.sys ---"
OUT=$($SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader test_driver.sys 2>&1" || true)
echo "$OUT" | tail -8
if echo "$OUT" | grep -qi "driver"; then
    echo "  RESULT: PASS"; PASS=$((PASS+1))
else
    echo "  RESULT: FAIL"; FAIL=$((FAIL+1))
fi
echo ""

echo "--- [5] SteamSetup.exe (PE32 rejection) ---"
OUT=$($SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader SteamSetup.exe 2>&1" || true)
echo "$OUT" | tail -5
if echo "$OUT" | grep -q "32-bit"; then
    echo "  RESULT: PASS (correctly rejected)"; PASS=$((PASS+1))
else
    echo "  RESULT: FAIL"; FAIL=$((FAIL+1))
fi
echo ""

echo "--- [6] putty64.exe --diag ---"
OUT=$($SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 15 ./peloader --diag putty64.exe 2>&1" || true)
echo "$OUT" | head -10
echo "..."
echo "$OUT" | grep -iE "UNRESOLVED" | head -20
echo "..."
echo "$OUT" | tail -5
if echo "$OUT" | grep -qiE "PE32\+|AMD64"; then
    echo "  RESULT: PASS"; PASS=$((PASS+1))
else
    echo "  RESULT: FAIL"; FAIL=$((FAIL+1))
fi
echo ""

echo "--- [7] putty64.exe (execution) ---"
OUT=$($SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 5 ./peloader putty64.exe >/tmp/p1.log 2>/tmp/p2.log; echo EXIT:\$?; cat /tmp/p2.log" || true)
echo "$OUT" | head -40
echo "..."
echo "$OUT" | tail -10
echo ""

echo "============================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "============================================"
