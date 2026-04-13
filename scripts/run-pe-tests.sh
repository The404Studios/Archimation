#!/bin/bash
set -euo pipefail

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
SSH_CMD="sshpass -p root ssh $SSH_OPTS root@127.0.0.1 -p 2222"
SCP_CMD="sshpass -p root scp $SSH_OPTS -P 2222"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TEST_DIR="$PROJECT_DIR/tests/pe-loader"

echo "=== Copying test binaries ==="
$SSH_CMD "mkdir -p /tmp/pe-test"

for f in "$TEST_DIR"/*.exe; do
    name=$(basename "$f")
    echo "  Copying $name..."
    $SCP_CMD "$f" root@127.0.0.1:/tmp/pe-test/
done

echo ""
echo "=== Testing hello.exe ==="
$SSH_CMD "cd /tmp/pe-test && PE_COMPAT_DLL_PATH=/usr/lib/pe-compat peloader hello.exe 2>&1" || true

echo ""
echo "=== Testing test_minimal.exe ==="
$SSH_CMD "cd /tmp/pe-test && PE_COMPAT_DLL_PATH=/usr/lib/pe-compat peloader test_minimal.exe 2>&1" || true

echo ""
echo "=== Testing test_full_exe.exe ==="
$SSH_CMD "cd /tmp/pe-test && PE_COMPAT_DLL_PATH=/usr/lib/pe-compat peloader test_full_exe.exe 2>&1" || true

echo ""
echo "=== Testing test_service.exe ==="
$SSH_CMD "cd /tmp/pe-test && PE_COMPAT_DLL_PATH=/usr/lib/pe-compat peloader test_service.exe 2>&1" || true

echo ""
echo "=== All tests done ==="
