#!/bin/bash
# build-and-test.sh - Full build + QEMU test pipeline
# Copies project to native Linux fs, builds packages, builds ISO, boots QEMU
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(dirname "$SCRIPT_DIR")"
BUILD_BASE="/tmp/ai-arch-build"
NATIVE_PROJECT="${BUILD_BASE}/project"
REPO_DIR="${NATIVE_PROJECT}/repo/x86_64"
ISO_OUTPUT="/tmp/iso-output"

echo "============================================"
echo "  ArchWindows - Full Build & Test Pipeline"
echo "============================================"
echo ""

# ---- Step 0: Copy to native filesystem ----
echo "=== Step 0: Copy to native Linux filesystem ==="
rm -rf "$NATIVE_PROJECT"
mkdir -p "$NATIVE_PROJECT"
for d in trust pe-loader packages ai-control services firewall profile scripts; do
    if [ -d "$PROJECT/$d" ]; then
        cp -a "$PROJECT/$d" "$NATIVE_PROJECT/"
        echo "  Copied $d"
    fi
done

# Ensure builder user exists
if ! id builder &>/dev/null; then
    useradd -m builder 2>/dev/null || true
fi

# ---- Step 1: Build trust library ----
echo ""
echo "=== Step 1: Build trust library ==="
cd "${NATIVE_PROJECT}/trust/lib"
make clean 2>/dev/null || true
make all 2>&1 | tail -3
echo "Trust lib: OK"

# ---- Step 2: Build PE loader ----
echo ""
echo "=== Step 2: Build PE loader ==="
cd "${NATIVE_PROJECT}/pe-loader"
make clean 2>/dev/null || true
make -j$(nproc) all 2>&1 | tail -5
echo "PE loader: $(ls loader/peloader 2>/dev/null && echo OK || echo FAIL)"
echo "DLL count: $(ls dlls/libpe_*.so 2>/dev/null | wc -l)"

# ---- Step 3: Build packages ----
echo ""
echo "=== Step 3: Build packages ==="
mkdir -p "${REPO_DIR}"
chown -R builder:builder "${NATIVE_PROJECT}"

BUILD_ORDER="trust-system pe-loader windows-services ai-control-daemon ai-firewall ai-desktop-config ai-first-boot-wizard"

for pkg in ${BUILD_ORDER}; do
    PKG_DIR="${NATIVE_PROJECT}/packages/${pkg}"
    if [ ! -f "${PKG_DIR}/PKGBUILD" ]; then
        echo "  SKIP: ${pkg} (no PKGBUILD)"
        continue
    fi
    echo "  Building: ${pkg}..."
    cd "${PKG_DIR}"
    rm -f *.pkg.tar.zst 2>/dev/null || true
    rm -rf pkg src 2>/dev/null || true

    # Fix source paths that reference the original project location
    sed -i "s|\${startdir}/../../|${NATIVE_PROJECT}/|g" PKGBUILD 2>/dev/null || true

    su builder -c "makepkg -f --nodeps --noconfirm 2>&1" | tail -3
    cp -f *.pkg.tar.zst "${REPO_DIR}/" 2>/dev/null && echo "    -> OK" || echo "    -> FAILED"
done

# ---- Step 4: Create repo database ----
echo ""
echo "=== Step 4: Create repo database ==="
cd "${REPO_DIR}"
chown -R builder:builder "${REPO_DIR}"
rm -f pe-compat.db* pe-compat.files* 2>/dev/null || true
su builder -c "repo-add pe-compat.db.tar.gz *.pkg.tar.zst 2>&1" | tail -5
echo "Packages in repo:"
ls *.pkg.tar.zst 2>/dev/null | wc -l

# ---- Step 5: Build ISO ----
echo ""
echo "=== Step 5: Build ISO ==="
PROFILE_DIR="${NATIVE_PROJECT}/profile"
WORK_DIR="${BUILD_BASE}/work"

# Update pacman.conf to point to our local repo
if [ -f "${PROFILE_DIR}/pacman.conf" ]; then
    sed -i "s|Server = file://.*|Server = file://${REPO_DIR}|" "${PROFILE_DIR}/pacman.conf"
fi

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$ISO_OUTPUT"
rm -f "$ISO_OUTPUT"/*.iso 2>/dev/null || true

mkarchiso -v -w "$WORK_DIR" -o "$ISO_OUTPUT" "$PROFILE_DIR" 2>&1 | tail -30

ISO_FILE=$(ls "$ISO_OUTPUT"/*.iso 2>/dev/null | head -1)
if [ -z "$ISO_FILE" ]; then
    echo "FATAL: No ISO built!"
    exit 1
fi
echo ""
echo "ISO built: $ISO_FILE"
echo "Size: $(du -h "$ISO_FILE" | cut -f1)"

# ---- Step 6: Boot QEMU ----
echo ""
echo "=== Step 6: Boot QEMU ==="

# Kill stale QEMU
pkill -9 qemu-system 2>/dev/null || true
sleep 1

EXTRACT_DIR="/tmp/iso-extract"
SERIAL_LOG="/tmp/qemu-serial.log"

rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"
cd "$EXTRACT_DIR"

# Extract kernel
bsdtar xf "$ISO_FILE" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null || {
    echo "Trying 7z..."
    7z x "$ISO_FILE" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img -o"$EXTRACT_DIR" 2>/dev/null
}

VMLINUZ="$EXTRACT_DIR/arch/boot/x86_64/vmlinuz-linux"
INITRD="$EXTRACT_DIR/arch/boot/x86_64/initramfs-linux.img"

if [ ! -f "$VMLINUZ" ]; then
    echo "FATAL: Could not extract kernel"
    exit 1
fi

LABEL=$(isoinfo -d -i "$ISO_FILE" 2>/dev/null | grep "Volume id:" | sed 's/Volume id: //' || echo "ARCHWIN_202602")
echo "ISO label: $LABEL"

rm -f "$SERIAL_LOG"

# Boot QEMU headless with serial console
# Use KVM if available, fall back to software emulation
KVM_FLAG=""
if [ -e /dev/kvm ] && [ -r /dev/kvm ]; then
    KVM_FLAG="-enable-kvm"
    echo "Using KVM acceleration"
else
    echo "KVM not available, using software emulation (slower)"
fi

nohup qemu-system-x86_64 \
    $KVM_FLAG \
    -m 4096 \
    -smp 2 \
    -cdrom "$ISO_FILE" \
    -kernel "$VMLINUZ" \
    -initrd "$INITRD" \
    -append "archisobasedir=arch archisolabel=${LABEL} console=ttyS0,115200 systemd.log_level=info" \
    -display none \
    -serial file:${SERIAL_LOG} \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::2222-:22,hostfwd=tcp::8421-:8420 \
    -no-reboot \
    > /tmp/qemu-stdout.log 2>&1 &

QEMU_PID=$!
echo "QEMU PID: $QEMU_PID"

# Wait for boot
echo "Waiting for system to boot..."
BOOT_TIMEOUT=300
BOOT_START=$(date +%s)

while true; do
    ELAPSED=$(( $(date +%s) - BOOT_START ))
    if [ $ELAPSED -ge $BOOT_TIMEOUT ]; then
        echo ""
        echo "TIMEOUT after ${BOOT_TIMEOUT}s"
        echo "=== Last 30 lines of serial ==="
        tail -30 "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'
        break
    fi

    if ! kill -0 $QEMU_PID 2>/dev/null; then
        echo ""
        echo "QEMU exited"
        cat /tmp/qemu-stdout.log 2>/dev/null
        exit 1
    fi

    if grep -q "Reached target.*Multi-User" "$SERIAL_LOG" 2>/dev/null; then
        echo ""
        echo "System booted to multi-user target in ${ELAPSED}s"
        break
    fi

    if grep -q "emergency mode" "$SERIAL_LOG" 2>/dev/null; then
        echo ""
        echo "FATAL: Emergency mode!"
        cat "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | tail -50
        kill -9 $QEMU_PID 2>/dev/null || true
        exit 1
    fi

    sleep 2
    printf "\r  Waiting... %ds" "$ELAPSED"
done

# Give services time to start
echo "Waiting 15s for services to stabilize..."
sleep 15

# ---- Step 7: Smoke Tests ----
echo ""
echo "========================================"
echo "  SMOKE TESTS"
echo "========================================"

PASS=0
FAIL=0
SSH_CMD="sshpass -p root ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR root@127.0.0.1 -p 2222"

# Test 1: SSH
echo -n "  [1] SSH connectivity: "
if timeout 5 bash -c "echo > /dev/tcp/127.0.0.1/2222" 2>/dev/null; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL"
    FAIL=$((FAIL + 1))
fi

# Test 1b: SSH login
echo -n "  [1b] SSH login: "
if $SSH_CMD "echo ok" 2>/dev/null | grep -q "ok"; then
    echo "PASS (root)"
    PASS=$((PASS + 1))
else
    # Try arch user
    SSH_CMD="sshpass -p arch ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR arch@127.0.0.1 -p 2222"
    if $SSH_CMD "echo ok" 2>/dev/null | grep -q "ok"; then
        echo "PASS (arch)"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        FAIL=$((FAIL + 1))
    fi
fi

# Test 2: AI Daemon
echo -n "  [2] AI daemon status: "
DAEMON_STATUS=$($SSH_CMD "systemctl is-active ai-control 2>/dev/null" 2>/dev/null || echo "unknown")
DAEMON_STATUS=$(echo "$DAEMON_STATUS" | tr -d '\r\n')
if [ "$DAEMON_STATUS" = "active" ]; then
    echo "PASS (active)"
    PASS=$((PASS + 1))
else
    echo "FAIL (status: $DAEMON_STATUS)"
    FAIL=$((FAIL + 1))
    echo "  --- AI Daemon journal ---"
    $SSH_CMD "journalctl -u ai-control --no-pager -n 20 2>/dev/null" 2>/dev/null || echo "  (no logs)"
fi

# Test 3: AI daemon health endpoint
echo -n "  [3] AI daemon /health: "
HEALTH=$($SSH_CMD "curl -s --connect-timeout 5 http://localhost:8420/health" 2>/dev/null || echo "")
if echo "$HEALTH" | grep -q "status" 2>/dev/null; then
    echo "PASS ($HEALTH)"
    PASS=$((PASS + 1))
else
    echo "FAIL (response: '$HEALTH')"
    FAIL=$((FAIL + 1))
fi

# Test 4: Random seed (should NOT be failing)
echo -n "  [4] Random seed masked: "
SEED_STATUS=$($SSH_CMD "systemctl is-enabled systemd-random-seed 2>/dev/null" 2>/dev/null || echo "unknown")
SEED_STATUS=$(echo "$SEED_STATUS" | tr -d '\r\n')
if [ "$SEED_STATUS" = "masked" ]; then
    echo "PASS (masked)"
    PASS=$((PASS + 1))
else
    echo "INFO (status: $SEED_STATUS)"
    SEED_ACTIVE=$($SSH_CMD "systemctl is-active systemd-random-seed 2>/dev/null" 2>/dev/null || echo "unknown")
    echo "  active: $SEED_ACTIVE"
fi

# Test 5: LightDM running
echo -n "  [5] LightDM status: "
LDM_STATUS=$($SSH_CMD "systemctl is-active lightdm 2>/dev/null" 2>/dev/null || echo "unknown")
LDM_STATUS=$(echo "$LDM_STATUS" | tr -d '\r\n')
if [ "$LDM_STATUS" = "active" ]; then
    echo "PASS (active)"
    PASS=$((PASS + 1))
else
    echo "FAIL (status: $LDM_STATUS)"
    FAIL=$((FAIL + 1))
    echo "  --- LightDM journal ---"
    $SSH_CMD "journalctl -u lightdm --no-pager -n 20 2>/dev/null" 2>/dev/null || echo "  (no logs)"
fi

# Test 6: XFCE session (check if X is running)
echo -n "  [6] X server running: "
X_PID=$($SSH_CMD "pgrep -x Xorg 2>/dev/null || pgrep -x X 2>/dev/null" 2>/dev/null || echo "")
X_PID=$(echo "$X_PID" | tr -d '\r\n')
if [ -n "$X_PID" ]; then
    echo "PASS (PID: $X_PID)"
    PASS=$((PASS + 1))
else
    echo "FAIL (no X server)"
    FAIL=$((FAIL + 1))
fi

# Test 7: Check for failed services
echo -n "  [7] Failed services: "
FAILED=$($SSH_CMD "systemctl --failed --no-pager --no-legend 2>/dev/null" 2>/dev/null || echo "unknown")
FAILED_COUNT=$(echo "$FAILED" | grep -c "failed" || echo "0")
if [ "$FAILED_COUNT" = "0" ] || [ -z "$FAILED" ] || [ "$FAILED" = "unknown" ]; then
    echo "PASS (none)"
    PASS=$((PASS + 1))
else
    echo "WARN ($FAILED_COUNT failed)"
    echo "$FAILED" | head -10
fi

# Test 8: Hostname
echo -n "  [8] Hostname: "
HOSTNAME=$($SSH_CMD "hostname" 2>/dev/null || echo "unknown")
HOSTNAME=$(echo "$HOSTNAME" | tr -d '\r\n')
echo "$HOSTNAME"

# Test 9: OS release
echo -n "  [9] OS name: "
OS_NAME=$($SSH_CMD "grep PRETTY_NAME /etc/os-release 2>/dev/null" 2>/dev/null || echo "unknown")
echo "$OS_NAME"

echo ""
echo "========================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "========================================"

# Show boot log highlights
echo ""
echo "=== Boot log highlights ==="
grep -E "(Started|FAILED|Failed|ERROR)" "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | tail -30

# Cleanup QEMU
echo ""
echo "Shutting down QEMU..."
kill $QEMU_PID 2>/dev/null || true
sleep 3
kill -9 $QEMU_PID 2>/dev/null || true

echo "Done."
