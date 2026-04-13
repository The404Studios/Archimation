#!/bin/bash
# deploy-pe.sh - Deploy PE loader to QEMU VM and run tests
set -euo pipefail

SSH="sshpass -p root ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p 2222 root@127.0.0.1"
SCP="sshpass -p root scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P 2222"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PE_DIR="$PROJECT_DIR/pe-loader"

echo "Testing SSH..."
$SSH "echo SSH_OK" || {
    echo "SSH failed!"
    exit 1
}

echo "Deploying PE loader..."
$SSH "mkdir -p /opt/pe-loader/dlls"

$SCP "$PE_DIR/loader/peloader" root@127.0.0.1:/opt/pe-loader/
echo "  peloader binary deployed"

$SCP $PE_DIR/dlls/*.so root@127.0.0.1:/opt/pe-loader/dlls/
echo "  $(ls $PE_DIR/dlls/*.so | wc -l) DLL .so files deployed"

# Copy test executables
for f in "$PE_DIR"/tests/*.exe "$PE_DIR"/tests/*.sys; do
    if [ -f "$f" ]; then
        $SCP "$f" root@127.0.0.1:/opt/pe-loader/
        echo "  Deployed $(basename $f)"
    fi
done

# Also check for SteamSetup and putty
for f in /tmp/SteamSetup.exe /tmp/putty.exe; do
    if [ -f "$f" ]; then
        $SCP "$f" root@127.0.0.1:/opt/pe-loader/
        echo "  Deployed $(basename $f)"
    fi
done

echo ""
echo "=== Running tests ==="
echo ""

# Test 1: hello.exe
echo "--- Test: hello.exe ---"
$SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader hello.exe 2>&1" || echo "  (exit code: $?)"
echo ""

# Test 2: test_full_exe.exe
echo "--- Test: test_full_exe.exe ---"
$SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 15 ./peloader test_full_exe.exe 2>&1" || echo "  (exit code: $?)"
echo ""

# Test 3: putty.exe (if available)
if $SSH "test -f /opt/pe-loader/putty.exe" 2>/dev/null; then
    echo "--- Test: putty.exe (import resolution) ---"
    $SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader --diag putty.exe 2>&1 | head -60" || echo "  (exit code: $?)"
    echo ""
fi

# Test 4: SteamSetup.exe (if available)
if $SSH "test -f /opt/pe-loader/SteamSetup.exe" 2>/dev/null; then
    echo "--- Test: SteamSetup.exe (import resolution) ---"
    $SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader --diag SteamSetup.exe 2>&1 | head -60" || echo "  (exit code: $?)"
    echo ""
fi

echo "=== Tests complete ==="
