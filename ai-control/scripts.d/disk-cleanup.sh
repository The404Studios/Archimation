#!/bin/bash
# AI-Description: Clean pacman cache + remove orphaned packages
# AI-Confirm: yes
# AI-Network: prohibited
# AI-Trust-Band: 400
echo "=== Pacman cache size ==="
sudo du -sh /var/cache/pacman/pkg 2>/dev/null
echo "=== Cleaning ==="
sudo paccache -rk1 2>&1 | tail -3 || echo "(paccache not installed)"
echo "=== Orphans ==="
ORPH=$(pacman -Qtdq 2>/dev/null)
if [ -n "$ORPH" ]; then
    echo "$ORPH" | wc -l | xargs printf "%s orphans found\n"
else
    echo "No orphans"
fi
