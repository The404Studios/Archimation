#!/bin/bash
# install-pwsh.sh — install PowerShell Core 7.x to /opt/microsoft/powershell/7
#
# PowerShell Core (pwsh) is Microsoft's open-source PowerShell that runs
# natively on Linux (no Wine).  It's not in Arch's official repos and the
# AUR `powershell-bin` package adds churn we don't want at pacstrap time,
# so we ship this opt-in installer instead.
#
# Run as root on the live ISO (or any Arch system) when you want to enable
# the AI daemon's `script.run_ps1` handler and the binfmt_misc registration
# for `.ps1` files.
#
#   sudo bash /opt/ai-control/scripts/install-pwsh.sh
#
# After install:
#   * `/usr/local/bin/pwsh`      — symlink to the installed binary
#   * `pwsh --version`           — should print "PowerShell 7.x.y"
#   * `./hello.ps1`              — directly executable via binfmt_misc
#   * AI: "run powershell hello" — routes to script.run_ps1
#
# Tarballs are pulled from the official PowerShell GitHub release page; no
# Microsoft repo configuration / GPG-key juggling is required.
set -euo pipefail

VERSION="${PWSH_VERSION:-7.4.6}"
ARCH="${PWSH_ARCH:-x64}"
PREFIX="${PWSH_PREFIX:-/opt/microsoft/powershell/7}"
URL="https://github.com/PowerShell/PowerShell/releases/download/v${VERSION}/powershell-${VERSION}-linux-${ARCH}.tar.gz"

if [ "$(id -u)" -ne 0 ]; then
    echo "install-pwsh.sh: must be run as root (try: sudo $0)" >&2
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "install-pwsh.sh: curl is required" >&2
    exit 1
fi

if ! command -v tar >/dev/null 2>&1; then
    echo "install-pwsh.sh: tar is required" >&2
    exit 1
fi

# Session 68 (Agent G): fail fast if the network is unreachable.  The
# first-boot systemd unit wraps this in a 120s timeout, but we'd rather
# exit cleanly with a clear diagnostic than burn a full TCP timeout.
# `curl -sfI --max-time 8 --connect-timeout 5` does a HEAD that follows
# no redirects; github.com returns 301 which curl treats as success for -f.
if ! curl -sfI --max-time 8 --connect-timeout 5 https://github.com >/dev/null 2>&1; then
    echo "install-pwsh.sh: no network route to github.com — skipping install" >&2
    echo "install-pwsh.sh: re-run manually once connectivity is available:" >&2
    echo "install-pwsh.sh:   sudo /usr/share/ai-control/scripts/install-pwsh.sh" >&2
    # Exit 0 so the oneshot systemd unit marks "activated" and doesn't retry
    # on every boot.  User re-runs manually when network is back.
    exit 0
fi

echo "==> Installing PowerShell ${VERSION} (${ARCH}) to ${PREFIX}"
mkdir -p "${PREFIX}"
# Session 68: explicitly check PIPESTATUS[0] so curl failures aren't masked
# by tar succeeding on a truncated/empty stream (set -o pipefail also catches
# this, but the explicit check gives a clearer error message).
curl -fL "${URL}" | tar xz -C "${PREFIX}"
if [ "${PIPESTATUS[0]}" -ne 0 ]; then
    echo "install-pwsh: curl failed — aborting" >&2
    exit 1
fi
chmod +x "${PREFIX}/pwsh"
ln -sf "${PREFIX}/pwsh" /usr/local/bin/pwsh

# Re-trigger the systemd-binfmt unit so the .ps1 registration (shipped in
# /etc/binfmt.d/powershell.conf) actually takes effect now that pwsh exists.
if command -v systemctl >/dev/null 2>&1; then
    systemctl restart systemd-binfmt.service 2>/dev/null || true
fi

echo "==> PowerShell installed:"
/usr/local/bin/pwsh --version
echo
echo "Test it:"
echo "    pwsh -c 'Write-Host hello from pwsh'"
echo "    ./yourscript.ps1   # binfmt_misc routes to pwsh"
