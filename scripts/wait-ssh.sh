#!/bin/bash
# Wait for VM SSH to become available
set -euo pipefail
for i in $(seq 1 30); do
    if sshpass -p root ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=3 -p 2222 root@127.0.0.1 'echo VM_READY' 2>/dev/null; then
        exit 0
    fi
    echo "Waiting... $i"
    sleep 3
done
echo "TIMEOUT"
exit 1
