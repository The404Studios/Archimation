#!/bin/bash
set -euo pipefail

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
SSH_CMD="sshpass -p root ssh $SSH_OPTS root@127.0.0.1 -p 2222"
SCP_CMD="sshpass -p root scp $SSH_OPTS -P 2222"

echo "=== Checking what we can test ==="

# Check if Steam installer can be downloaded
echo "Attempting to download SteamSetup.exe..."
$SSH_CMD "cd /tmp/pe-test && curl -sL -o SteamSetup.exe 'https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe' && ls -la SteamSetup.exe" || echo "Download failed"

# Also try a simpler test - putty.exe is a well-known single-file Windows app
echo ""
echo "Downloading putty.exe (simple standalone Windows app)..."
$SSH_CMD "cd /tmp/pe-test && curl -sL -o putty.exe 'https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe' && ls -la putty.exe" || echo "Download failed"

echo ""
echo "=== Testing SteamSetup.exe ==="
$SSH_CMD "cd /tmp/pe-test && PE_COMPAT_DLL_PATH=/usr/lib/pe-compat timeout 30 peloader SteamSetup.exe 2>&1 | head -80" || echo "(exited)"

echo ""
echo "=== Testing putty.exe ==="
$SSH_CMD "cd /tmp/pe-test && PE_COMPAT_DLL_PATH=/usr/lib/pe-compat timeout 15 peloader putty.exe 2>&1 | head -80" || echo "(exited)"

echo ""
echo "=== Done ==="
