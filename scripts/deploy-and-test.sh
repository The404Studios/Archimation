#!/bin/bash
# deploy-and-test.sh - Deploy PE loader bundle and test
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PE_DIR="$PROJECT_DIR/pe-loader"
TEST_DIR="$PROJECT_DIR/tests/pe-loader"
BUNDLE="/tmp/pe-bundle.tar.gz"

SSH="sshpass -p root ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ServerAliveInterval=10 -p 2222 root@127.0.0.1"
SCP="sshpass -p root scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P 2222"

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
$SCP "$BUNDLE" root@127.0.0.1:/tmp/
$SSH "cd /tmp && tar xzf pe-bundle.tar.gz && rm -rf /opt/pe-loader && mv pe-bundle /opt/pe-loader && chmod +x /opt/pe-loader/peloader && echo DEPLOYED && ls /opt/pe-loader/"

echo ""
echo "============================================"
echo "  PE LOADER TESTS"
echo "============================================"

PASS=0
FAIL=0

run_test() {
    local name="$1"
    local cmd="$2"
    local match="$3"
    echo ""
    echo "--- $name ---"
    # Run the command, capturing output to a file on the VM so crashes don't kill SSH
    $SSH "cd /opt/pe-loader && $cmd >/tmp/pe_stdout.log 2>/tmp/pe_stderr.log; echo EXIT_RC=\$?" 2>&1 || true
    # Fetch logs
    local stdout stderr
    stdout=$($SSH "cat /tmp/pe_stdout.log" 2>/dev/null || echo "(no stdout)")
    stderr=$($SSH "cat /tmp/pe_stderr.log" 2>/dev/null || echo "(no stderr)")
    echo "$stdout" | tail -10
    if [ -n "$stderr" ] && [ "$stderr" != "(no stderr)" ]; then
        echo "  [stderr]: $(echo "$stderr" | tail -3)"
    fi
    if echo "$stdout" | grep -q "$match" 2>/dev/null || echo "$stderr" | grep -q "$match" 2>/dev/null; then
        echo "  PASS"
        PASS=$((PASS+1))
    else
        echo "  FAIL"
        FAIL=$((FAIL+1))
    fi
}

run_test "test_minimal.exe" \
    "LD_LIBRARY_PATH=dlls timeout 10 ./peloader test_minimal.exe" \
    "HELLO FROM PE"

run_test "test_full_exe.exe" \
    "LD_LIBRARY_PATH=dlls timeout 15 ./peloader test_full_exe.exe" \
    "ALL TESTS PASSED"

run_test "test_service.exe" \
    "LD_LIBRARY_PATH=dlls timeout 10 ./peloader test_service.exe" \
    "entry point"

run_test "test_driver.sys" \
    "LD_LIBRARY_PATH=dlls timeout 10 ./peloader test_driver.sys" \
    "driver"

run_test "SteamSetup.exe (PE32 reject)" \
    "LD_LIBRARY_PATH=dlls timeout 10 ./peloader SteamSetup.exe" \
    "32-bit"

echo ""
echo "--- putty64.exe --diag ---"
$SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 15 ./peloader --diag putty64.exe >/tmp/pe_stdout.log 2>/tmp/pe_stderr.log; echo EXIT_RC=\$?" 2>&1 || true
DIAG=$($SSH "cat /tmp/pe_stdout.log" 2>/dev/null || echo "")
echo "$DIAG" | head -15
echo "..."
UNRESOLVED=$(echo "$DIAG" | grep -c "UNRESOLVED" || echo "0")
echo "Unresolved imports: $UNRESOLVED"
echo "$DIAG" | grep "UNRESOLVED" | head -20
echo "..."
echo "$DIAG" | tail -5
if echo "$DIAG" | grep -qE "PE32\+|AMD64"; then
    echo "  PASS"; PASS=$((PASS+1))
else
    echo "  FAIL"; FAIL=$((FAIL+1))
fi

echo ""
echo "--- putty64.exe (execution) ---"
$SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 5 ./peloader putty64.exe >/tmp/pe_stdout.log 2>/tmp/pe_stderr.log; echo EXIT_RC=\$?" 2>&1 || true
OUT=$($SSH "cat /tmp/pe_stdout.log 2>/dev/null; echo '---STDERR---'; cat /tmp/pe_stderr.log 2>/dev/null" 2>/dev/null || echo "(crashed)")
echo "$OUT" | head -40
echo "..."
echo "$OUT" | tail -10

echo ""
echo "============================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "============================================"
