#!/bin/bash
set -euo pipefail

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
SSH_CMD="sshpass -p root ssh $SSH_OPTS root@127.0.0.1 -p 2222"
SCP_CMD="sshpass -p root scp $SSH_OPTS -P 2222"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PE_DIR="$PROJECT_DIR/pe-loader"

echo "=== Deploying PE loader to QEMU VM ==="

# Create directories
$SSH_CMD mkdir -p /usr/lib/pe-compat /usr/bin /tmp/pe-test
echo "Directories created"

# Copy peloader binary
$SCP_CMD "$PE_DIR/loader/peloader" root@127.0.0.1:/usr/bin/peloader
$SSH_CMD chmod +x /usr/bin/peloader
echo "peloader binary deployed"

# Copy all .so DLL stubs
$SCP_CMD $PE_DIR/dlls/*.so root@127.0.0.1:/usr/lib/pe-compat/
echo "DLL stubs deployed"

# Verify
$SSH_CMD "ls /usr/lib/pe-compat/*.so | wc -l"
echo ".so files on VM"

# Copy test binaries if they exist
if [ -d "$PE_DIR/../tests" ]; then
    for f in "$PE_DIR/../tests"/*.exe "$PE_DIR/../tests"/*.sys; do
        [ -f "$f" ] && $SCP_CMD "$f" root@127.0.0.1:/tmp/pe-test/ 2>/dev/null || true
    done
    echo "Test binaries copied"
fi

echo "=== Deployment complete ==="
