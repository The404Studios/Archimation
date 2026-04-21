# powershell_hello.ps1 -- PowerShell integration smoke test (A9 from Session 66).
#
# AI-Description: Validates that .ps1 files are routed to pwsh by the
#                 loader/binfmt layer.  Not a PE — invoked directly via pwsh
#                 by run_corpus.sh (so this file works even if PowerShell
#                 binfmt registration isn't installed on the build host).
#
# Harness expectation: outputs:POWERSHELL_HELLO_OK
#
# Why two-tier acceptance: on the live ISO, the loader's binfmt hook may
# route .ps1 transparently; locally we just exec `pwsh -File`.  Either
# path must produce the marker.

Write-Host "POWERSHELL_HELLO_OK"
exit 0
