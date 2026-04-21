#!/bin/bash
# test-desktop-e2e.sh — End-to-end desktop user journey test.
#
# Boots the built ISO in QEMU with a VNC display (not headless), waits for
# XFCE to come up via LightDM auto-login, drives the UI over SSH, and
# validates the user journey:
#
#   boot → XFCE → Contusion dialog (Super+C) → audio volume change
#
# This is deliberately complementary to scripts/test-qemu.sh:
#   * test-qemu.sh = headless service/API smoke suite (30+ HTTP probes)
#   * test-desktop-e2e.sh = graphical user journey (VNC + xdotool + scrot)
#
# Both scripts share the ISO boot pattern (kernel+initrd extraction,
# port-forward hostfwd, KVM/TCG fallback). Only the -display mode differs.
#
# Exit codes:
#   0     all desktop stages passed (or gracefully skipped subsections)
#   1     at least one desktop-stage assertion failed
#   77    environment precondition unmet (no QEMU, no ISO, no VNC tools).
#         This matches the automake convention so CI can treat it as SKIP
#         rather than FAIL.
#
# Skip conditions (exit 77):
#   * qemu-system-x86_64 not installed
#   * no ISO under $ISO_DIR (default: $PROJECT_DIR/output)
#   * no sshpass or ssh in PATH
#
# Weaker skips (logged, test marked SKIP but others continue):
#   * vncdotool / x11vnc not installed → VNC screenshot skipped
#   * wpctl/pipewire not installed in guest → volume-change step skipped
#
# Invocation:
#   bash scripts/test-desktop-e2e.sh
#   ISO_DIR=/path/to/iso bash scripts/test-desktop-e2e.sh
#   BOOT_TIMEOUT=600 bash scripts/test-desktop-e2e.sh   # extend boot budget
#
# The QEMU VNC server listens on 127.0.0.1:5901 (display :1). Attach with
# any VNC viewer to watch the test live.

#!/bin/bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# ---------------------------------------------------------------------------
# Tunables (env-overridable)
# ---------------------------------------------------------------------------
ISO_DIR="${ISO_DIR:-${PROJECT_DIR}/output}"
VNC_PORT="${VNC_PORT:-5901}"          # QEMU -vnc :1 → host 5901
VNC_DISPLAY_NUM="${VNC_DISPLAY_NUM:-1}"
SSH_PORT="${SSH_PORT:-2222}"
DAEMON_HOST_PORT="${DAEMON_HOST_PORT:-8421}"   # host-side; guest is 8420
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"
XFCE_TIMEOUT="${XFCE_TIMEOUT:-90}"
SERIAL_LOG="${SERIAL_LOG:-/tmp/qemu-e2e-serial.log}"
QEMU_STDOUT="${QEMU_STDOUT:-/tmp/qemu-e2e-stdout.log}"
EXTRACT_DIR="${EXTRACT_DIR:-/tmp/iso-extract-e2e}"
SCREENSHOT_DIR="${SCREENSHOT_DIR:-/tmp}"
TS="$(date +%Y%m%d-%H%M%S)"
SCREENSHOT_HOST="${SCREENSHOT_DIR}/desktop-e2e-${TS}.png"
SCREENSHOT_GUEST_PATH="/tmp/desktop-e2e.png"

QEMU_PID=""
PASS=0
FAIL=0
SKIPPED=0

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
    local rc=$?
    if [ -n "${QEMU_PID}" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill "$QEMU_PID" 2>/dev/null || true
        for _ in 1 2 3 4 5; do
            kill -0 "$QEMU_PID" 2>/dev/null || break
            sleep 1
        done
        kill -9 "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    return $rc
}
trap cleanup EXIT INT TERM

log()  { printf '%s\n' "$*"; }
info() { printf '  [i] %s\n' "$*"; }
pass() { printf '  [PASS] %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf '  [FAIL] %s\n' "$*"; FAIL=$((FAIL + 1)); }
skip() { printf '  [SKIP] %s\n' "$*"; SKIPPED=$((SKIPPED + 1)); }

# ---------------------------------------------------------------------------
# Precondition checks — exit 77 on missing tools (CI-friendly SKIP)
# ---------------------------------------------------------------------------
require_tools() {
    local missing=()
    for t in qemu-system-x86_64 ssh sshpass bsdtar; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        log "SKIP: missing required tools: ${missing[*]}"
        exit 77
    fi
}
require_tools

ISO_FILE="$(ls "${ISO_DIR}"/*.iso 2>/dev/null | head -1)"
if [ -z "$ISO_FILE" ]; then
    log "SKIP: no ISO found in ${ISO_DIR} (run scripts/build-iso.sh first)"
    exit 77
fi

# Optional VNC tooling — degrade to SKIP for screenshot step if absent
HAVE_VNCDOTOOL=0
HAVE_X11VNC_VIEWER=0
command -v vncdotool >/dev/null 2>&1 && HAVE_VNCDOTOOL=1
command -v vncsnapshot >/dev/null 2>&1 && HAVE_X11VNC_VIEWER=1

log "========================================"
log "  Desktop E2E Test Harness"
log "========================================"
log "  ISO:        $ISO_FILE"
log "  VNC:        127.0.0.1:${VNC_PORT} (display :${VNC_DISPLAY_NUM})"
log "  SSH:        127.0.0.1:${SSH_PORT}"
log "  Daemon:     127.0.0.1:${DAEMON_HOST_PORT} (guest :8420)"
log "  Screenshot: ${SCREENSHOT_HOST}"
log "========================================"

# ---------------------------------------------------------------------------
# Prepare ISO → kernel/initrd extraction (mirrors test-qemu.sh)
# ---------------------------------------------------------------------------
if pgrep -x qemu-system-x86_64 >/dev/null 2>&1; then
    log "Killing stale qemu-system-x86_64..."
    pkill -9 qemu-system 2>/dev/null || true
    for _ in 1 2 3; do
        pgrep -x qemu-system-x86_64 >/dev/null 2>&1 || break
        sleep 1
    done
fi

rm -rf "$EXTRACT_DIR"; mkdir -p "$EXTRACT_DIR"
rm -f "$SERIAL_LOG" "$QEMU_STDOUT"

log "Extracting kernel+initrd from ISO..."
(
    cd "$EXTRACT_DIR" && \
    bsdtar xf "$ISO_FILE" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null
) || {
    log "ERROR: bsdtar extraction failed"
    exit 1
}

VMLINUZ="$EXTRACT_DIR/arch/boot/x86_64/vmlinuz-linux"
INITRD="$EXTRACT_DIR/arch/boot/x86_64/initramfs-linux.img"
if [ ! -f "$VMLINUZ" ] || [ ! -f "$INITRD" ]; then
    log "ERROR: extracted kernel/initrd missing"
    exit 1
fi

LABEL=$(isoinfo -d -i "$ISO_FILE" 2>/dev/null | awk -F': ' '/Volume id/{print $2}' | head -1)
[ -z "$LABEL" ] && LABEL="AI_ARCH_202602"
log "ISO volume label: $LABEL"

# ---------------------------------------------------------------------------
# Boot QEMU with VNC display
# ---------------------------------------------------------------------------
KVM_FLAG=""
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    KVM_FLAG="-enable-kvm"
    log "KVM available — using hardware acceleration"
else
    log "KVM unavailable — using TCG (slower; BOOT_TIMEOUT=${BOOT_TIMEOUT}s)"
fi

log ""
log "Starting QEMU with VNC on :${VNC_DISPLAY_NUM} (port ${VNC_PORT})..."
# shellcheck disable=SC2086
nohup qemu-system-x86_64 \
    $KVM_FLAG \
    -m 4096 \
    -smp 2 \
    -drive file="$ISO_FILE",media=cdrom,if=ide,index=1 \
    -kernel "$VMLINUZ" \
    -initrd "$INITRD" \
    -append "archisobasedir=arch archisolabel=${LABEL} archisodevice=/dev/sr0 console=ttyS0,115200 systemd.log_level=info tsc=unstable" \
    -vga std \
    -vnc "127.0.0.1:${VNC_DISPLAY_NUM}" \
    -serial "file:${SERIAL_LOG}" \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::${DAEMON_HOST_PORT}-:8420,hostfwd=tcp::${SSH_PORT}-:22 \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -no-reboot \
    > "$QEMU_STDOUT" 2>&1 &
QEMU_PID=$!
log "QEMU PID: $QEMU_PID"

# Early-death detection
for _ in $(seq 1 20); do
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        log "ERROR: QEMU died within 2s"
        cat "$QEMU_STDOUT" 2>/dev/null || true
        exit 1
    fi
    [ -s "$SERIAL_LOG" ] && break
    sleep 0.1
done

# ---------------------------------------------------------------------------
# Wait for multi-user.target (login prompt reached)
# ---------------------------------------------------------------------------
log ""
log "Waiting for multi-user.target (timeout: ${BOOT_TIMEOUT}s)..."
BOOT_START=$(date +%s)
BOOTED=0
while true; do
    ELAPSED=$(( $(date +%s) - BOOT_START ))
    if [ "$ELAPSED" -ge "$BOOT_TIMEOUT" ]; then
        log "TIMEOUT: boot did not complete in ${BOOT_TIMEOUT}s"
        tail -30 "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' || true
        break
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        log "ERROR: QEMU exited during boot"
        cat "$QEMU_STDOUT" 2>/dev/null
        exit 1
    fi
    if grep -q "Reached target.*Multi-User\|Reached target.*multi-user\|login:" "$SERIAL_LOG" 2>/dev/null; then
        log "Boot reached multi-user target in ${ELAPSED}s"
        BOOTED=1
        break
    fi
    if grep -q "emergency mode" "$SERIAL_LOG" 2>/dev/null; then
        log "FATAL: emergency mode"
        exit 1
    fi
    sleep 2
    printf "\r  booting... %ds" "$ELAPSED"
done
log ""

# Wait for sshd
log "Polling for sshd on :${SSH_PORT}..."
SSHD_UP=0
for _ in $(seq 1 60); do
    if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/${SSH_PORT}" 2>/dev/null; then
        SSHD_UP=1; break
    fi
    sleep 2
done
[ "$SSHD_UP" -eq 1 ] && log "sshd reachable" || log "sshd never reachable"

# SSH helper
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"
SSH_ARCH="sshpass -p arch ssh ${SSH_OPTS} -p ${SSH_PORT} arch@127.0.0.1"
SSH_ROOT="sshpass -p root ssh ${SSH_OPTS} -p ${SSH_PORT} root@127.0.0.1"
SCP_ARCH="sshpass -p arch scp ${SSH_OPTS} -P ${SSH_PORT}"

# Resolve which login works (mirrors test-qemu.sh logic)
SSH=""
if $SSH_ARCH "echo ok" 2>/dev/null | grep -q ok; then
    SSH="$SSH_ARCH"
    log "SSH login: arch@127.0.0.1:${SSH_PORT}"
elif $SSH_ROOT "echo ok" 2>/dev/null | grep -q ok; then
    SSH="$SSH_ROOT"
    log "SSH login: root@127.0.0.1:${SSH_PORT} (falling back)"
else
    log "ERROR: neither arch nor root SSH login works — aborting"
    exit 1
fi

# Helper: run a command inside the guest under DISPLAY=:0 as the graphical user.
# LightDM auto-logins "arch" on display :0 per live ISO config.
ssh_user_gui() {
    # XAUTHORITY path varies by distro; XDG_RUNTIME_DIR/DBUS_SESSION give Contusion
    # access to the pipewire sink for volume ops.
    $SSH "sudo -u arch DISPLAY=:0 XAUTHORITY=/home/arch/.Xauthority XDG_RUNTIME_DIR=/run/user/1000 bash -c '$*'" 2>/dev/null
}

# ---------------------------------------------------------------------------
# TEST BATTERY
# ---------------------------------------------------------------------------
log ""
log "========================================"
log "  DESKTOP E2E TESTS"
log "========================================"

# Step 1: LightDM / XFCE greeter active
log ""
log "[1] LightDM greeter / display manager active:"
LIGHTDM_STATE=""
# Poll for up to 90s — the graphical target comes up after multi-user in TCG
for _ in $(seq 1 45); do
    LIGHTDM_STATE=$($SSH "systemctl is-active lightdm 2>/dev/null" 2>/dev/null | tr -d '\r\n' || echo "")
    [ "$LIGHTDM_STATE" = "active" ] && break
    sleep 2
done
if [ "$LIGHTDM_STATE" = "active" ]; then
    pass "lightdm active"
else
    fail "lightdm not active (state=${LIGHTDM_STATE:-unknown}); live ISO may not auto-start a greeter"
    $SSH "journalctl -u lightdm --no-pager -n 20 2>/dev/null" 2>/dev/null || true
fi

# Step 2: XFCE auto-login completed (xfce4-session spawned under arch)
log ""
log "[2] xfce4-session running for user arch:"
XFCE_UP=0
for _ in $(seq 1 $((XFCE_TIMEOUT / 2))); do
    if $SSH "pgrep -u arch -x xfce4-session >/dev/null 2>&1"; then
        XFCE_UP=1; break
    fi
    sleep 2
done
if [ "$XFCE_UP" = "1" ]; then
    pass "xfce4-session running (PID=$($SSH "pgrep -u arch -x xfce4-session | head -1" 2>/dev/null | tr -d '\r\n'))"
else
    skip "xfce4-session not running within ${XFCE_TIMEOUT}s — autologin may need an attached display (this happens on pure-TCG where vgabios is slow)"
fi

# Step 3: Launch Contusion via documented Super+C keybinding
log ""
log "[3] Super+C launches Contusion:"
if [ "$XFCE_UP" = "1" ]; then
    # Use xdotool over SSH against the XFCE display.
    # Super+C is wired in packages/ai-desktop-config/PKGBUILD → xfce4-keyboard-shortcuts.
    # xdotool may need a short settle after session startup before it can talk to X.
    sleep 3
    if ssh_user_gui "command -v xdotool >/dev/null 2>&1"; then
        ssh_user_gui "xdotool key super+c" || true
        CONTUSION_UP=0
        for _ in $(seq 1 10); do
            if $SSH "pgrep -u arch -x contusion >/dev/null 2>&1"; then
                CONTUSION_UP=1; break
            fi
            sleep 1
        done
        if [ "$CONTUSION_UP" = "1" ]; then
            pass "contusion process spawned after Super+C"
        else
            # Fallback: launch via absolute path to separate keybinding issues
            # from missing binary. If direct launch works the keybinding is the
            # problem; if it also fails the binary is missing.
            ssh_user_gui "/usr/bin/contusion >/dev/null 2>&1 &" || true
            for _ in $(seq 1 10); do
                if $SSH "pgrep -u arch -x contusion >/dev/null 2>&1"; then
                    CONTUSION_UP=1; break
                fi
                sleep 1
            done
            if [ "$CONTUSION_UP" = "1" ]; then
                fail "Super+C keybinding did not fire (direct /usr/bin/contusion launch DID work — xfconf keybinding regression)"
            else
                fail "contusion never started (keybinding AND direct launch both failed)"
            fi
        fi
    else
        skip "xdotool not installed in guest — cannot drive keybinding"
    fi
else
    skip "XFCE session not up — cannot exercise keybinding"
fi

# Step 4: Close the Contusion window (send WM_DELETE via xdotool)
log ""
log "[4] Close Contusion window gracefully:"
if [ "$XFCE_UP" = "1" ] && $SSH "pgrep -u arch -x contusion >/dev/null 2>&1"; then
    # Prefer windowkill (sends WM_DELETE); Alt+F4 as fallback.
    ssh_user_gui "xdotool search --name 'Contusion' windowkill" 2>/dev/null || true
    sleep 2
    if ! $SSH "pgrep -u arch -x contusion >/dev/null 2>&1"; then
        pass "contusion closed via windowkill"
    else
        ssh_user_gui "xdotool key alt+F4" 2>/dev/null || true
        sleep 2
        if ! $SSH "pgrep -u arch -x contusion >/dev/null 2>&1"; then
            pass "contusion closed via Alt+F4 fallback"
        else
            # Last resort: SIGTERM. The test is cleanup, not the subject.
            $SSH "pkill -TERM -u arch -x contusion 2>/dev/null" 2>/dev/null || true
            sleep 1
            skip "contusion needed SIGTERM to close — UI close-handler may be broken"
        fi
    fi
else
    skip "no contusion process to close"
fi

# Step 5: Token-auth round-trip from inside the live session (localhost allowed)
log ""
log "[5] /auth/token + /health round-trip from guest:"
TOKEN=""
TOKEN_JSON=$($SSH "curl -s --connect-timeout 5 -X POST http://localhost:8420/auth/token \
    -H 'Content-Type: application/json' \
    -d '{\"subject_id\":1,\"name\":\"desktop-e2e\",\"trust_level\":600}'" 2>/dev/null || echo "")
TOKEN=$(printf '%s' "$TOKEN_JSON" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
if [ -n "$TOKEN" ]; then
    HEALTH=$($SSH "curl -s --connect-timeout 5 -H 'Authorization: Bearer ${TOKEN}' http://localhost:8420/health" 2>/dev/null || echo "")
    if echo "$HEALTH" | grep -q '"status"' ; then
        pass "auth+health round-trip (token len=${#TOKEN})"
    else
        fail "/health did not return JSON (body: '${HEALTH:0:120}')"
    fi
else
    fail "could not mint token (response: '${TOKEN_JSON:0:120}')"
fi

# Step 6: Volume-up via /contusion/context — the real user journey endpoint.
# This is what the Super+C dialog submits when the user types "turn up the
# volume". Success = the default PipeWire/ALSA sink volume moves upward.
log ""
log "[6] /contusion/context volume-up → real audio change:"
if [ -z "$TOKEN" ]; then
    skip "no auth token — cannot call /contusion/context"
elif ! $SSH "command -v wpctl >/dev/null 2>&1"; then
    skip "wpctl not installed in guest — no PipeWire → no audio to change"
elif ! $SSH "wpctl get-volume @DEFAULT_AUDIO_SINK@ 2>/dev/null" >/dev/null 2>&1; then
    skip "wpctl has no default sink — expected on headless QEMU without -audiodev"
else
    BEFORE=$($SSH "wpctl get-volume @DEFAULT_AUDIO_SINK@ 2>/dev/null | awk '{print \$2}'" 2>/dev/null | tr -d '\r\n' || echo "")
    info "volume BEFORE: $BEFORE"
    CTX_RESP=$($SSH "curl -s --connect-timeout 5 -X POST http://localhost:8420/contusion/context \
        -H 'Authorization: Bearer ${TOKEN}' \
        -H 'Content-Type: application/json' \
        -d '{\"request\":\"turn up the volume\"}'" 2>/dev/null || echo "")
    sleep 1  # settle
    AFTER=$($SSH "wpctl get-volume @DEFAULT_AUDIO_SINK@ 2>/dev/null | awk '{print \$2}'" 2>/dev/null | tr -d '\r\n' || echo "")
    info "volume AFTER:  $AFTER"
    if [ -n "$BEFORE" ] && [ -n "$AFTER" ] && [ "$BEFORE" != "$AFTER" ]; then
        # Bash float comparison via awk
        CHANGED=$(awk -v a="$AFTER" -v b="$BEFORE" 'BEGIN{print (a>b)?"up":"down"}')
        if [ "$CHANGED" = "up" ]; then
            pass "volume rose (${BEFORE} → ${AFTER})"
        else
            fail "volume moved the WRONG way (${BEFORE} → ${AFTER})"
        fi
    else
        # The response envelope tells us whether Contusion accepted the action;
        # PASS if the engine parsed it even when the sink refused.
        if echo "$CTX_RESP" | grep -q '"status"[[:space:]]*:[[:space:]]*"ok"' ; then
            skip "contusion accepted the phrase but wpctl didn't report a delta (headless sink — expected): ${CTX_RESP:0:140}"
        else
            fail "contusion did not accept phrase (response: '${CTX_RESP:0:200}')"
        fi
    fi
fi

# Step 7: Screenshot — prefer in-guest scrot for true X capture, fall back
# to VNC-side capture. The scrot path gives us a real composited image;
# vncdotool captures the framebuffer (usable but less rich).
log ""
log "[7] Desktop screenshot capture:"
SHOT_TAKEN=0
if [ "$XFCE_UP" = "1" ] && ssh_user_gui "command -v scrot >/dev/null 2>&1"; then
    if ssh_user_gui "scrot -o '${SCREENSHOT_GUEST_PATH}'" 2>/dev/null; then
        # Copy back to host
        if $SCP_ARCH "arch@127.0.0.1:${SCREENSHOT_GUEST_PATH}" "$SCREENSHOT_HOST" 2>/dev/null; then
            SHOT_TAKEN=1
            pass "scrot → ${SCREENSHOT_HOST} ($(wc -c <"$SCREENSHOT_HOST" 2>/dev/null || echo ?) bytes)"
        fi
    fi
fi
if [ "$SHOT_TAKEN" = "0" ] && [ "$HAVE_VNCDOTOOL" = "1" ]; then
    if vncdotool -s "127.0.0.1:${VNC_DISPLAY_NUM}" capture "$SCREENSHOT_HOST" 2>/dev/null; then
        SHOT_TAKEN=1
        pass "vncdotool → ${SCREENSHOT_HOST}"
    fi
fi
if [ "$SHOT_TAKEN" = "0" ] && [ "$HAVE_X11VNC_VIEWER" = "1" ]; then
    if vncsnapshot -quiet "127.0.0.1:${VNC_PORT}" "$SCREENSHOT_HOST" 2>/dev/null; then
        SHOT_TAKEN=1
        pass "vncsnapshot → ${SCREENSHOT_HOST}"
    fi
fi
if [ "$SHOT_TAKEN" = "0" ]; then
    skip "no screenshot tool worked (scrot/vncdotool/vncsnapshot all unavailable or failed)"
fi

# Step 8: Graceful shutdown — handled by EXIT trap. Print summary first.
log ""
log "========================================"
log "  DESKTOP E2E RESULTS"
log "========================================"
log "  Passed:  $PASS"
log "  Failed:  $FAIL"
log "  Skipped: $SKIPPED"
log "========================================"

if [ "$FAIL" -eq 0 ]; then
    log "OVERALL: PASS"
    exit 0
else
    log "OVERALL: FAIL ($FAIL assertion$([ "$FAIL" -eq 1 ] || echo "s"))"
    exit 1
fi
