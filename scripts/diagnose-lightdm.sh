#!/bin/bash
# Diagnose LightDM issues via SSH into running QEMU VM
set -uo pipefail

SSH="sshpass -p arch ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR arch@127.0.0.1 -p 2222"

# Wait for SSH
echo "Waiting for SSH..."
for i in $(seq 1 60); do
    if $SSH "echo ok" 2>/dev/null | grep -q ok; then
        echo "SSH ready"
        break
    fi
    sleep 5
done

echo "========================================="
echo "1. DEFAULT TARGET"
$SSH "systemctl get-default" 2>/dev/null || echo "FAILED"

echo ""
echo "2. LIGHTDM SERVICE STATUS"
$SSH "systemctl is-active lightdm" 2>/dev/null || echo "FAILED"
$SSH "systemctl status lightdm --no-pager -l 2>&1" 2>/dev/null || echo "FAILED"

echo ""
echo "3. LIGHTDM JOURNAL"
$SSH "journalctl -u lightdm --no-pager -n 30 2>&1" 2>/dev/null || echo "FAILED"

echo ""
echo "4. FAILED UNITS"
$SSH "systemctl --failed --no-pager 2>&1" 2>/dev/null || echo "FAILED"

echo ""
echo "5. STUCK JOBS"
$SSH "systemctl list-jobs --no-pager 2>&1" 2>/dev/null || echo "FAILED"

echo ""
echo "6. XORG LOG (errors only)"
$SSH "cat /var/log/Xorg.0.log 2>/dev/null | grep -E 'EE|Fatal|error|failed' | head -20" 2>/dev/null || echo "No Xorg log"

echo ""
echo "7. XSESSION FILE"
$SSH "ls -la /etc/lightdm/Xsession 2>&1" 2>/dev/null || echo "MISSING"

echo ""
echo "8. XFCE SESSION FILES"
$SSH "ls /usr/share/xsessions/ 2>&1" 2>/dev/null || echo "EMPTY"

echo ""
echo "9. LIGHTDM CONFIG"
$SSH "cat /etc/lightdm/lightdm.conf 2>&1" 2>/dev/null || echo "MISSING"

echo ""
echo "10. DISPLAY-MANAGER ALIAS"
$SSH "readlink /etc/systemd/system/display-manager.service 2>&1" 2>/dev/null || echo "MISSING"

echo ""
echo "11. MULTI-USER WANTS (lightdm present?)"
$SSH "ls /etc/systemd/system/multi-user.target.wants/ 2>&1" 2>/dev/null || echo "EMPTY"

echo ""
echo "12. GRAPHICAL WANTS"
$SSH "ls /etc/systemd/system/graphical.target.wants/ 2>&1" 2>/dev/null || echo "EMPTY"

echo ""
echo "13. ARCH USER GROUPS (autologin?)"
$SSH "id arch 2>&1" 2>/dev/null || echo "FAILED"

echo ""
echo "14. X PROCESSES RUNNING?"
$SSH "ps aux 2>&1 | grep -i 'xorg\|lightdm\|xfce' | grep -v grep" 2>/dev/null || echo "NONE"

echo ""
echo "15. ENSURE-GPU DROP-IN"
$SSH "cat /etc/systemd/system/lightdm.service.d/ensure-gpu.conf 2>&1" 2>/dev/null || echo "MISSING"

echo "========================================="
