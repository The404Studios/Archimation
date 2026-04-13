#!/bin/bash
set -euo pipefail

SCP="sshpass -p root scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P 2222"
SSH="sshpass -p root ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p 2222 root@127.0.0.1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SRC="$PROJECT_DIR/tests/pe-loader"

for f in hello.exe test_full_exe.exe test_minimal.exe test_service.exe test_driver.sys; do
    if [ -f "$SRC/$f" ]; then
        $SCP "$SRC/$f" root@127.0.0.1:/opt/pe-loader/
        echo "Deployed $f"
    else
        echo "MISSING: $SRC/$f"
    fi
done

echo ""
echo "Files on VM:"
$SSH "ls -la /opt/pe-loader/*.exe /opt/pe-loader/*.sys 2>/dev/null"

echo ""
echo "=== Running tests ==="
echo ""

echo "--- hello.exe ---"
$SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader hello.exe 2>&1" || echo "EXIT: $?"
echo ""

echo "--- test_minimal.exe ---"
$SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 10 ./peloader test_minimal.exe 2>&1" || echo "EXIT: $?"
echo ""

echo "--- test_full_exe.exe ---"
$SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 15 ./peloader test_full_exe.exe 2>&1" || echo "EXIT: $?"
echo ""

echo "--- SteamSetup.exe (diag) ---"
$SSH "cd /opt/pe-loader && LD_LIBRARY_PATH=dlls timeout 15 ./peloader --diag SteamSetup.exe 2>&1 | head -80" || echo "EXIT: $?"
echo ""
