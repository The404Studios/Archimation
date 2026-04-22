# AI-Description: Show system info via PowerShell (top 10 CPU consumers)
# AI-Confirm: no
# AI-Network: prohibited
# AI-Trust-Band: 100
#
# Sample .ps1 demonstrating the AI script-extension surface for PowerShell
# Core (pwsh).  Requires `bash /opt/ai-control/scripts/install-pwsh.sh` to
# install pwsh first.  Invoke via the AI:
#
#     ai run powershell system-info
#     ai execute system-info.ps1
#
# Or directly (binfmt_misc routes .ps1 to pwsh):
#
#     /etc/ai-control/scripts.d/system-info.ps1

Write-Host "=== AI Arch Linux (PowerShell) ==="
Write-Host "OS:       $(uname -s -r)"
Write-Host "Hostname: $(hostname)"
Write-Host "Uptime:   $(uptime -p)"
Write-Host ""
Write-Host "=== Top 10 processes by CPU ==="
Get-Process |
    Sort-Object -Property CPU -Descending |
    Select-Object -First 10 -Property ProcessName, Id, CPU |
    Format-Table -AutoSize
