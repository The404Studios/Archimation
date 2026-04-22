#!/bin/bash
# AI-Description: Show system summary (uptime, load, memory, disk)
# AI-Confirm: no
# AI-Network: prohibited
# AI-Trust-Band: 100
echo "=== AI Arch Linux Status ==="
echo "Uptime: $(uptime -p)"
echo "Load:   $(uptime | awk -F'load average:' '{print $2}')"
echo "Memory: $(free -h | awk '/^Mem:/{print $3"/"$2}')"
echo "Disk:   $(df -h / | awk 'NR==2{print $3"/"$2" ("$5")"}')"
echo "Kernel: $(uname -r)"
