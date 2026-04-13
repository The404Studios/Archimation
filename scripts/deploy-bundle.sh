#!/bin/bash
# deploy-bundle.sh - Bundle, deploy, and test PE loader
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PE_DIR="$PROJECT_DIR/pe-loader"
TEST_DIR="$PROJECT_DIR/tests/pe-loader"
BUNDLE="/tmp/pe-bundle.tar.gz"

echo "=== Creating bundle ==="
cd /tmp
rm -rf pe-bundle pe-bundle.tar.gz
mkdir -p pe-bundle/dlls

cp "$PE_DIR/loader/peloader" pe-bundle/
cp $PE_DIR/dlls/libpe_*.so pe-bundle/dlls/

for f in test_minimal.exe test_full_exe.exe test_service.exe test_driver.sys; do
    [ -f "$TEST_DIR/$f" ] && cp "$TEST_DIR/$f" pe-bundle/
done

[ -f /tmp/putty64.exe ] && cp /tmp/putty64.exe pe-bundle/
STEAM_SETUP="${STEAM_SETUP:-$HOME/Downloads/SteamSetup.exe}"
[ -f "$STEAM_SETUP" ] && cp "$STEAM_SETUP" pe-bundle/

tar czf "$BUNDLE" -C /tmp pe-bundle
echo "Bundle: $(du -h $BUNDLE | cut -f1)"

echo ""
echo "=== Deploying ==="
sshpass -p root scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P 2222 "$BUNDLE" root@127.0.0.1:/tmp/
echo "Bundle transferred"

SSH="sshpass -p root ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p 2222 root@127.0.0.1"
$SSH "cd /tmp && tar xzf pe-bundle.tar.gz && rm -rf /opt/pe-loader && mv pe-bundle /opt/pe-loader && chmod +x /opt/pe-loader/peloader && ls /opt/pe-loader/"
echo "Deployed"

echo ""
echo "============================================"
echo "  PE LOADER TESTS"
echo "============================================"
echo ""

PASS=0; FAIL=0

echo "--- [1] test_minimal.exe ---"
OUT=$($SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader test_minimal.exe 2>&1" 2>&1 || true)
echo "$OUT" | tail -3
if echo "$OUT" | grep -q "HELLO FROM PE"; then
    echo "  PASS"; PASS=$((PASS+1))
else echo "  FAIL"; FAIL=$((FAIL+1)); fi
echo ""

echo "--- [2] test_full_exe.exe ---"
OUT=$($SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 15 ./peloader test_full_exe.exe 2>&1" 2>&1 || true)
echo "$OUT" | grep -E "PASS|FAIL|Results" | tail -25
if echo "$OUT" | grep -q "ALL TESTS PASSED"; then
    echo "  PASS"; PASS=$((PASS+1))
else echo "  FAIL"; FAIL=$((FAIL+1)); fi
echo ""

echo "--- [3] test_service.exe ---"
OUT=$($SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader test_service.exe 2>&1" 2>&1 || true)
echo "$OUT" | tail -8
if echo "$OUT" | grep -qE "entry point"; then
    echo "  PASS"; PASS=$((PASS+1))
else echo "  FAIL"; FAIL=$((FAIL+1)); fi
echo ""

echo "--- [4] test_driver.sys ---"
OUT=$($SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader test_driver.sys 2>&1" 2>&1 || true)
echo "$OUT" | tail -8
if echo "$OUT" | grep -qi "driver"; then
    echo "  PASS"; PASS=$((PASS+1))
else echo "  FAIL"; FAIL=$((FAIL+1)); fi
echo ""

echo "--- [5] SteamSetup.exe (PE32 reject) ---"
OUT=$($SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader SteamSetup.exe 2>&1" 2>&1 || true)
echo "$OUT" | tail -5
if echo "$OUT" | grep -q "32-bit"; then
    echo "  PASS (correctly rejected)"; PASS=$((PASS+1))
else echo "  FAIL"; FAIL=$((FAIL+1)); fi
echo ""

echo "--- [6] putty64.exe --diag ---"
OUT=$($SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 15 ./peloader --diag putty64.exe 2>&1" 2>&1 || true)
echo "$OUT" | head -12
echo "..."
echo "$OUT" | grep "UNRESOLVED" | head -15
echo "..."
echo "$OUT" | tail -3
if echo "$OUT" | grep -qE "PE32\+|AMD64"; then
    echo "  PASS"; PASS=$((PASS+1))
else echo "  FAIL"; FAIL=$((FAIL+1)); fi
echo ""

echo "--- [7] putty64.exe (execution) ---"
$SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 5 ./peloader putty64.exe >/tmp/p1.log 2>/tmp/p2.log; echo EXIT_CODE:\$?; echo '--- stderr ---'; cat /tmp/p2.log | head -40" 2>&1 || true
echo ""

echo "============================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "============================================"
