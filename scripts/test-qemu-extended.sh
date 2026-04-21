#!/bin/bash
# test-qemu-extended.sh -- production-quality QEMU smoke for AI Arch Linux ISO.
# Boots the ISO and runs sections A..H over SSH. Port defaults are 2222 for
# SSH and 8421 for cortex-forward; both are dynamically re-allocated if the
# default is busy (Session 68 A4 fix for the sequential-QEMU TIME_WAIT
# collision). Standalone: does NOT depend on scripts/test-qemu.sh's tallies.
#
# Sections:
#   A -- Boot health (system-running, failed-units, dmesg, journal err, uptime)
#   B -- X session  (lightdm/Xorg/.X11-unix/xrandr)
#   C -- WiFi/Network (nmcli/rfkill/devices/default route)
#   D -- Trust kernel module (lsmod/sysfs/invariants/subject pool)
#   E -- AI daemon + cortex (5 services + /health + Contusion + state + cortex + ai/status)
#   F -- ai CLI (which/help/version)
#   G -- Memory leak surveillance (60s RSS delta on daemon + cortex + kmemleak)
#   H -- Functional AI command (LLM-gated; SKIP if model not loaded)
#
# Exit code: 0 if 0 FAIL; 1 otherwise. SKIP/WARN do not fail the run.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Shared QEMU port helpers (Session 68 A4 fix for 8421 collision).
# shellcheck source=lib/qemu_port.sh
# shellcheck disable=SC1091
if [ -r "$SCRIPT_DIR/lib/qemu_port.sh" ]; then
    # shellcheck source=/dev/null
    . "$SCRIPT_DIR/lib/qemu_port.sh"
else
    echo "WARN: $SCRIPT_DIR/lib/qemu_port.sh not found — falling back to hard-coded ports" >&2
fi

cleanup() {
    if [ -n "${QEMU_PID:-}" ]; then
        kill "$QEMU_PID" 2>/dev/null || true
        for _ in 1 2 3 4 5; do
            kill -0 "$QEMU_PID" 2>/dev/null || break
            sleep 1
        done
        kill -9 "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

ISO_DIR="${ISO_DIR:-${PROJECT_DIR}/output}"
# S52: pick NEWEST ISO by mtime, not alphabetical first. Override via ISO_FILE.
ISO_FILE="${ISO_FILE:-$(ls -t "${ISO_DIR}"/*.iso 2>/dev/null | head -1)}"
EXTRACT_DIR="/tmp/iso-extract-extended"
SERIAL_LOG="/tmp/qemu-extended-serial.log"

# S68: dynamic cortex host-forward port. The pytest wrapper allocates a
# free port via socket bind(:0) and passes it here to avoid collisions
# with the session-scoped fake_cortex fixture (which binds 8421). For
# back-compat with direct invocations (running this script by hand) we
# first try 8421 and poll for it to be free (TIME_WAIT release window);
# if it's still bound after a bounded wait we allocate a fresh free
# port via the kernel's ephemeral picker.
#
# Env var contract (both backward-compatible):
#   AICONTROL_CORTEX_PORT / AICONTROL_QEMU_DAEMON_PORT
#       -- pin the cortex/daemon host-forward port (caller owns freshness)
#   AICONTROL_QEMU_SSH_PORT
#       -- pin the SSH host-forward port (default 2222 preserved)
CORTEX_PORT="${AICONTROL_CORTEX_PORT:-${AICONTROL_QEMU_DAEMON_PORT:-}}"
if [ -z "$CORTEX_PORT" ]; then
    # No caller-pinned port; try 8421 first, wait briefly for TIME_WAIT
    # drain, then fall back to an OS-assigned ephemeral port.
    if type _qemu_port_is_free >/dev/null 2>&1; then
        if _qemu_port_is_free 8421; then
            CORTEX_PORT=8421
            echo "Cortex host-forward port: 8421 (default, verified free)"
        else
            echo "Port 8421 busy — waiting up to 20s for TIME_WAIT drain..."
            if WAITED=$(_qemu_port_wait_free 8421 20); then
                CORTEX_PORT="$WAITED"
                echo "Cortex host-forward port: 8421 (released after wait)"
            else
                CORTEX_PORT="$(_qemu_port_pick_ephemeral || true)"
                if [ -z "$CORTEX_PORT" ]; then
                    echo "FATAL: 8421 still bound and ephemeral port-pick failed." >&2
                    echo "       Close other QEMU instances or set AICONTROL_CORTEX_PORT." >&2
                    exit 2
                fi
                echo "Cortex host-forward port: ${CORTEX_PORT} (dynamic — 8421 unavailable)"
            fi
        fi
    else
        # Helper library missing — preserve legacy hardcoded behavior.
        CORTEX_PORT=8421
        echo "Cortex host-forward port: 8421 (legacy fallback — helper unavailable)"
    fi
else
    echo "Cortex host-forward port: ${CORTEX_PORT} (caller-pinned)"
fi

# SSH host-forward. Parameterized for future parallel runs but default to
# 2222 so every existing caller (pkg-16 tests, shells with `ssh -p 2222`
# in muscle memory) keeps working. We still free-check it and fail fast
# with a clear message if it's taken — no silent port drift for SSH.
SSH_PORT="${AICONTROL_QEMU_SSH_PORT:-2222}"
if type _qemu_port_is_free >/dev/null 2>&1; then
    if ! _qemu_port_is_free "$SSH_PORT"; then
        if [ -n "${AICONTROL_QEMU_SSH_PORT:-}" ]; then
            echo "FATAL: caller pinned SSH_PORT=${SSH_PORT} but it is already bound." >&2
            exit 2
        fi
        echo "Port ${SSH_PORT} busy — waiting up to 20s for TIME_WAIT drain..."
        if WAITED=$(_qemu_port_wait_free "$SSH_PORT" 20); then
            SSH_PORT="$WAITED"
        else
            SSH_PORT="$(_qemu_port_pick_ephemeral || true)"
            if [ -z "$SSH_PORT" ]; then
                echo "FATAL: SSH port could not be allocated." >&2
                exit 2
            fi
            echo "SSH host-forward port: ${SSH_PORT} (dynamic — 2222 unavailable)"
        fi
    fi
fi
echo "SSH host-forward port: ${SSH_PORT}"

if [ -z "$ISO_FILE" ]; then
    echo "ERROR: No ISO found in ${ISO_DIR}"
    exit 1
fi

echo "ISO: ${ISO_FILE}"
echo "Size: $(du -h "$ISO_FILE" | cut -f1)"

if pgrep -x qemu-system-x86_64 >/dev/null 2>&1; then
    pkill -9 qemu-system 2>/dev/null || true
    for _ in 1 2 3; do
        pgrep -x qemu-system-x86_64 >/dev/null 2>&1 || break
        sleep 1
    done
fi

rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"
rm -f "$SERIAL_LOG"

echo "Extracting kernel and initramfs..."
cd "$EXTRACT_DIR"
bsdtar xf "$ISO_FILE" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null || {
    echo "bsdtar failed, trying 7z..."
    7z x "$ISO_FILE" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img -o"$EXTRACT_DIR" 2>/dev/null
}

VMLINUZ="$EXTRACT_DIR/arch/boot/x86_64/vmlinuz-linux"
INITRD="$EXTRACT_DIR/arch/boot/x86_64/initramfs-linux.img"

if [ ! -f "$VMLINUZ" ] || [ ! -f "$INITRD" ]; then
    echo "ERROR: Failed to extract kernel/initrd"
    ls -laR "$EXTRACT_DIR"
    exit 1
fi

LABEL=$(isoinfo -d -i "$ISO_FILE" 2>/dev/null | grep "Volume id:" | sed 's/Volume id: //' || echo "AI_ARCH_202602")
echo "ISO label: $LABEL"

echo ""
echo "=== Starting QEMU in background (extended smoke) ==="

KVM_FLAG=""
BOOT_TIMEOUT=120
if [ -r /dev/kvm ]; then
    KVM_FLAG="-enable-kvm"
    echo "KVM acceleration: enabled"
else
    echo "KVM not available -- using TCG emulation"
    BOOT_TIMEOUT=300
fi

nohup qemu-system-x86_64 \
    $KVM_FLAG \
    -m 4096 \
    -smp 2 \
    -drive file="$ISO_FILE",media=cdrom,if=ide,index=1 \
    -kernel "$VMLINUZ" \
    -initrd "$INITRD" \
    -append "archisobasedir=arch archisolabel=${LABEL} archisodevice=/dev/sr0 console=ttyS0,115200 systemd.log_level=info tsc=unstable" \
    -display none \
    -serial "file:${SERIAL_LOG}" \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::${CORTEX_PORT}-:8420,hostfwd=tcp::${SSH_PORT}-:22 \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -no-reboot \
    > /tmp/qemu-extended-stdout.log 2>&1 &

QEMU_PID=$!
echo "QEMU PID: $QEMU_PID"

for _ in $(seq 1 20); do
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "ERROR: QEMU died immediately"
        cat /tmp/qemu-extended-stdout.log 2>/dev/null
        exit 1
    fi
    [ -s "$SERIAL_LOG" ] && break
    sleep 0.1
done

echo ""
echo "=== Waiting for system to boot (timeout: ${BOOT_TIMEOUT}s) ==="
BOOT_START=$(date +%s)
while true; do
    ELAPSED=$(( $(date +%s) - BOOT_START ))
    if [ $ELAPSED -ge $BOOT_TIMEOUT ]; then
        echo ""
        echo "TIMEOUT: System did not finish booting in ${BOOT_TIMEOUT}s"
        tail -30 "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' || true
        break
    fi
    if ! kill -0 $QEMU_PID 2>/dev/null; then
        echo "ERROR: QEMU exited unexpectedly"
        cat /tmp/qemu-extended-stdout.log 2>/dev/null
        exit 1
    fi
    if grep -q "Reached target.*Multi-User\|Reached target.*multi-user\|login:" "$SERIAL_LOG" 2>/dev/null; then
        echo ""
        echo "System booted (login prompt) in ${ELAPSED}s"
        break
    fi
    if grep -q "emergency mode" "$SERIAL_LOG" 2>/dev/null; then
        echo "FATAL: emergency mode!"
        kill -9 $QEMU_PID 2>/dev/null || true
        exit 1
    fi
    sleep 2
    printf "\r  Waiting... %ds" "$ELAPSED"
done

STABILIZE_MAX=15
[ -z "$KVM_FLAG" ] && STABILIZE_MAX=120
echo "Polling for sshd readiness (max ${STABILIZE_MAX}s)..."
STABILIZE_T0=$(date +%s)
while : ; do
    ELAPSED=$(( $(date +%s) - STABILIZE_T0 ))
    if [ "$ELAPSED" -ge "$STABILIZE_MAX" ]; then
        echo "  sshd stabilization timeout -- proceeding"
        break
    fi
    if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/${SSH_PORT}" 2>/dev/null; then
        echo "  sshd up after ${ELAPSED}s"
        break
    fi
    sleep 1
done

# ============================================================
# Test-result tally + helpers
# ============================================================

PASS=0
FAIL=0
WARN=0
SKIP=0

_check_pass() {
    local name="$1"; shift
    local res="${*:-}"
    echo "  [PASS] ${name}${res:+ -- ${res}}"
    PASS=$((PASS + 1))
}
_check_fail() {
    local name="$1"; shift
    local res="${*:-}"
    echo "  [FAIL] ${name}${res:+ -- ${res}}"
    FAIL=$((FAIL + 1))
}
_check_warn() {
    local name="$1"; shift
    local res="${*:-}"
    echo "  [WARN] ${name}${res:+ -- ${res}}"
    WARN=$((WARN + 1))
}
_check_skip() {
    local name="$1"; shift
    local res="${*:-}"
    echo "  [SKIP] ${name}${res:+ -- ${res}}"
    SKIP=$((SKIP + 1))
}

SSH_ROOT="sshpass -p root ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"
SSH_USER_PASS="sshpass -p arch ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"
SSH_USER=""

# Resolve which credentials work; populate SSH_ACTIVE
if $SSH_ROOT root@127.0.0.1 -p "$SSH_PORT" "echo ok" 2>/dev/null | grep -q "ok"; then
    SSH_USER="root"
    SSH_ACTIVE="$SSH_ROOT root@127.0.0.1 -p $SSH_PORT"
elif $SSH_USER_PASS arch@127.0.0.1 -p "$SSH_PORT" "echo ok" 2>/dev/null | grep -q "ok"; then
    SSH_USER="arch"
    SSH_ACTIVE="$SSH_USER_PASS arch@127.0.0.1 -p $SSH_PORT"
fi

ssh_run() {
    if [ -z "$SSH_USER" ]; then
        return 1
    fi
    $SSH_ACTIVE "$@" 2>/dev/null
}

# Bootstrap auth token via daemon localhost-bypass; cached for sections E and H.
AUTH_TOKEN=""
get_auth_token() {
    if [ -n "${AUTH_TOKEN:-}" ]; then
        printf '%s' "$AUTH_TOKEN"
        return 0
    fi
    [ -z "$SSH_USER" ] && return 1
    AUTH_TOKEN=$($SSH_ACTIVE "curl -s --connect-timeout 5 -X POST http://localhost:8420/auth/token \
        -H 'Content-Type: application/json' \
        -d '{\"subject_id\": 1, \"name\": \"qemu-extended\", \"trust_level\": 600}'" 2>/dev/null \
        | sed -n 's/.*\"token\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p')
    [ -n "$AUTH_TOKEN" ] && printf '%s' "$AUTH_TOKEN"
}

curl_authed() {
    local path="$1"
    local tok
    tok=$(get_auth_token)
    [ -z "$tok" ] && { echo ""; return 0; }
    $SSH_ACTIVE "curl -s --connect-timeout 5 -H 'Authorization: Bearer ${tok}' http://127.0.0.1:8420${path}" 2>/dev/null || echo ""
}

curl_authed_status() {
    local path="$1"
    local tok
    tok=$(get_auth_token)
    [ -z "$tok" ] && { echo "000"; return 0; }
    $SSH_ACTIVE "curl -s --connect-timeout 5 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer ${tok}' http://127.0.0.1:8420${path}" 2>/dev/null || echo "000"
}

if [ -z "$SSH_USER" ]; then
    echo ""
    echo "FATAL: SSH unreachable -- cannot run extended sections"
    echo "OVERALL: FAIL"
    exit 1
fi

echo ""
echo "========================================"
echo "  EXTENDED SMOKE  (SSH user: ${SSH_USER})"
echo "========================================"

# ============================================================
# Section A -- Boot health
# ============================================================
echo ""
echo "--- Section A: Boot health ---"

# A.1: use --wait so systemd reports the FINAL state (running/degraded)
# instead of `starting` snapshot mid-boot.  Bound the wait at 60s so a
# truly-stuck boot still surfaces as a fail rather than hanging the test.
A_RUN=$(ssh_run "timeout 60 systemctl is-system-running --wait 2>/dev/null" | tr -d '\r\n' || echo "")
case "$A_RUN" in
    running|degraded) _check_pass "A.1 system-running" "state=${A_RUN}" ;;
    starting)         _check_fail "A.1 system-running" "still starting after 60s wait" ;;
    *)                _check_fail "A.1 system-running" "state=${A_RUN:-empty}" ;;
esac

A_FAILED=$(ssh_run "systemctl --failed --no-legend 2>/dev/null | wc -l" | tr -d '\r\n' || echo "x")
if [ "$A_FAILED" = "0" ]; then
    _check_pass "A.2 failed-units" "count=0"
else
    _check_fail "A.2 failed-units" "count=${A_FAILED}"
fi

# A.3: `grep -c` exits 1 when the count is zero (its idiomatic "no
# matches" signal), which under remote `set -o pipefail` propagates
# to ssh_run as exit 1. The previous `|| echo "0"` fallback then
# fired on the SUCCESS path (zero matches), prepending a second "0"
# and yielding the spurious `matches=00` FAIL. Use `|| true` on the
# remote side so the pipeline always exits 0 when grep simply found
# nothing; keep the local fallback for genuine transport failure
# (ssh died, host unreachable, etc.).
A_DMESG=$(ssh_run "dmesg 2>/dev/null | grep -ciE 'oops|panic|bug|warn|softlockup' || true" | tr -d '\r\n' || echo "0")
if [ "$A_DMESG" = "0" ]; then
    _check_pass "A.3 dmesg-clean" "matches=0"
else
    _check_fail "A.3 dmesg-clean" "matches=${A_DMESG}"
fi

A_JERR=$(ssh_run "journalctl -p err --since boot --no-pager 2>/dev/null | wc -l" | tr -d '\r\n' || echo "x")
if [ "$A_JERR" != "x" ] && [ "$A_JERR" -le 5 ] 2>/dev/null; then
    _check_pass "A.4 journal-err<=5" "lines=${A_JERR}"
else
    _check_fail "A.4 journal-err<=5" "lines=${A_JERR}"
fi

A_LAST=$(ssh_run "last -F 2>/dev/null | head -1" | tr -d '\r' || echo "")
if echo "$A_LAST" | grep -q "still running"; then
    _check_pass "A.5 uptime-ok" "still running"
else
    _check_warn "A.5 uptime-ok" "last: $(echo "$A_LAST" | head -c 80)"
fi

# ============================================================
# Section B -- X session
# ============================================================
echo ""
echo "--- Section B: X session ---"

B_LDM=$(ssh_run "systemctl is-active lightdm 2>/dev/null" | tr -d '\r\n' || echo "unknown")
if [ "$B_LDM" = "active" ]; then
    _check_pass "B.1 lightdm-active" "state=active"
else
    _check_fail "B.1 lightdm-active" "state=${B_LDM}"
fi

B_X=$(ssh_run "pgrep -a Xorg 2>/dev/null; pgrep -a Xwayland 2>/dev/null" | head -1 | tr -d '\r' || echo "")
if [ -n "$B_X" ]; then
    _check_pass "B.2 X-process" "$(echo "$B_X" | head -c 60)"
else
    _check_fail "B.2 X-process" "neither Xorg nor Xwayland running"
fi

B_X11U=$(ssh_run "ls /tmp/.X11-unix/ 2>/dev/null" | tr -d '\r' || echo "")
if echo "$B_X11U" | grep -qE "^X[0-9]+"; then
    _check_pass "B.3 .X11-unix" "$(echo "$B_X11U" | tr '\n' ' ')"
else
    _check_fail "B.3 .X11-unix" "no X<n> socket present"
fi

B_XR=$(ssh_run "DISPLAY=:0 xrandr 2>&1 | head -3" | tr -d '\r' || echo "")
if echo "$B_XR" | grep -q "Screen 0:"; then
    _check_pass "B.4 xrandr" "$(echo "$B_XR" | head -1 | head -c 80)"
else
    _check_fail "B.4 xrandr" "$(echo "$B_XR" | head -1 | head -c 80)"
fi

# ============================================================
# Section C -- WiFi/Network
# ============================================================
echo ""
echo "--- Section C: WiFi/Network ---"

C_NM=$(ssh_run "nmcli general status 2>/dev/null | tail -1" | tr -d '\r' || echo "")
if echo "$C_NM" | grep -qiE "asleep"; then
    _check_fail "C.1 nmcli-not-asleep" "$(echo "$C_NM" | head -c 80)"
elif [ -n "$C_NM" ]; then
    _check_pass "C.1 nmcli-not-asleep" "$(echo "$C_NM" | head -c 80)"
else
    _check_warn "C.1 nmcli-not-asleep" "nmcli unavailable"
fi

C_RFK=$(ssh_run "rfkill list wifi 2>&1" | tr -d '\r' || echo "")
if [ -z "$C_RFK" ] || echo "$C_RFK" | grep -qi "no.*device\|usage:"; then
    _check_skip "C.2 rfkill-wifi" "no wifi radio in QEMU virtio-net"
elif echo "$C_RFK" | grep -qiE "soft blocked: yes|hard blocked: yes"; then
    _check_fail "C.2 rfkill-wifi" "blocked"
else
    _check_pass "C.2 rfkill-wifi" "soft+hard=no"
fi

C_DEV=$(ssh_run "nmcli device status 2>/dev/null | grep -cE 'wifi|ethernet' || true" | tr -d '\r\n' || echo "0")
if [ "$C_DEV" != "0" ] && [ "$C_DEV" -ge 1 ] 2>/dev/null; then
    _check_pass "C.3 net-devices" "count=${C_DEV}"
else
    _check_fail "C.3 net-devices" "count=${C_DEV}"
fi

C_RT=$(ssh_run "ip route show default 2>&1 | head -1" | tr -d '\r' || echo "")
if echo "$C_RT" | grep -q "default via"; then
    _check_pass "C.4 default-route" "$(echo "$C_RT" | head -c 80)"
else
    _check_warn "C.4 default-route" "no default route (QEMU virtio-net DHCP may be slow)"
fi

# ============================================================
# Section D -- Trust kernel module
# ============================================================
echo ""
echo "--- Section D: Trust kernel ---"

D_LSMOD=$(ssh_run "lsmod 2>/dev/null | grep -c '^trust ' || true" | tr -d '\r\n' || echo "0")
if [ "$D_LSMOD" = "1" ]; then
    _check_pass "D.1 lsmod-trust" "loaded"
else
    _check_skip "D.1 lsmod-trust" "trust.ko absent (DKMS needs kernel headers)"
fi

D_SYSFS=$(ssh_run "ls /sys/kernel/trust/ 2>/dev/null | wc -l" | tr -d '\r\n' || echo "0")
if [ "$D_SYSFS" != "0" ] && [ "$D_SYSFS" -ge 5 ] 2>/dev/null; then
    _check_pass "D.2 /sys/kernel/trust" "entries=${D_SYSFS}"
elif [ "$D_LSMOD" = "1" ]; then
    _check_fail "D.2 /sys/kernel/trust" "entries=${D_SYSFS} (module loaded)"
else
    _check_skip "D.2 /sys/kernel/trust" "module not loaded"
fi

D_INV=$(ssh_run "ls /sys/kernel/trust_invariants/theorem*_violations 2>/dev/null | wc -l" | tr -d '\r\n' || echo "0")
if [ "$D_INV" = "5" ]; then
    _check_pass "D.3 invariants-theorems" "files=5"
elif [ "$D_LSMOD" = "1" ]; then
    _check_fail "D.3 invariants-theorems" "files=${D_INV} (expected 5)"
else
    _check_skip "D.3 invariants-theorems" "module not loaded"
fi

D_POOL=$(ssh_run "ls /sys/kernel/trust_subject_pool/ 2>/dev/null | wc -l" | tr -d '\r\n' || echo "0")
if [ "$D_POOL" != "0" ] && [ "$D_POOL" -ge 5 ] 2>/dev/null; then
    _check_pass "D.4 subject-pool" "entries=${D_POOL}"
elif [ "$D_LSMOD" = "1" ]; then
    _check_fail "D.4 subject-pool" "entries=${D_POOL} (expected >=5)"
else
    _check_skip "D.4 subject-pool" "module not loaded"
fi

D_NONCE=$(ssh_run "cat /sys/kernel/trust_invariants/global_nonce 2>/dev/null" | tr -d '\r\n' || echo "")
if [ -n "$D_NONCE" ] && echo "$D_NONCE" | grep -qE '^[0-9]+$'; then
    _check_pass "D.5 global-nonce" "value=${D_NONCE}"
elif [ "$D_LSMOD" = "1" ]; then
    _check_fail "D.5 global-nonce" "value='${D_NONCE}'"
else
    _check_skip "D.5 global-nonce" "module not loaded"
fi

# ============================================================
# Section E -- AI daemon + cortex
# ============================================================
echo ""
echo "--- Section E: AI daemon + cortex ---"

E_SVC_OK=0
E_SVC_TOTAL=0
E_SVC_DETAIL=""
for svc in ai-control ai-cortex coherenced pe-objectd scm-daemon; do
    E_SVC_TOTAL=$((E_SVC_TOTAL + 1))
    s=$(ssh_run "systemctl is-active ${svc} 2>/dev/null" | tr -d '\r\n' || echo "unknown")
    E_SVC_DETAIL="${E_SVC_DETAIL} ${svc}:${s}"
    [ "$s" = "active" ] && E_SVC_OK=$((E_SVC_OK + 1))
done
if [ "$E_SVC_OK" -eq "$E_SVC_TOTAL" ]; then
    _check_pass "E.1 5x-services-active" "${E_SVC_OK}/${E_SVC_TOTAL}"
elif [ "$E_SVC_OK" -ge 3 ]; then
    _check_warn "E.1 5x-services-active" "${E_SVC_OK}/${E_SVC_TOTAL}:${E_SVC_DETAIL}"
else
    _check_fail "E.1 5x-services-active" "${E_SVC_OK}/${E_SVC_TOTAL}:${E_SVC_DETAIL}"
fi

E_HEALTH=$(ssh_run "curl -s --connect-timeout 5 http://localhost:8420/health 2>/dev/null" || echo "")
E_HC=$(echo "$E_HEALTH" | { grep -ciE 'healthy|ok' || true; })
E_HC=$(echo "$E_HC" | tr -d '\r\n')
if [ "$E_HC" != "0" ] && [ "$E_HC" -ge 1 ] 2>/dev/null; then
    _check_pass "E.2 /health" "$(echo "$E_HEALTH" | head -c 80)"
else
    _check_fail "E.2 /health" "response='$(echo "$E_HEALTH" | head -c 80)'"
fi

E_APPS=$(curl_authed "/contusion/apps")
E_APPS_N=$(echo "$E_APPS" | $SSH_ACTIVE "python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d) if isinstance(d,(list,dict)) else 0)'" 2>/dev/null | tr -d '\r\n' || echo "0")
if [ -z "$E_APPS_N" ]; then E_APPS_N=0; fi
if [ "$E_APPS_N" != "0" ] && [ "$E_APPS_N" -ge 1 ] 2>/dev/null; then
    _check_pass "E.3 /contusion/apps" "n=${E_APPS_N}"
else
    _check_fail "E.3 /contusion/apps" "len=${E_APPS_N} body=$(echo "$E_APPS" | head -c 80)"
fi

E_STATE=$(curl_authed "/system/state")
E_SV=$(echo "$E_STATE" | $SSH_ACTIVE "python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get(\"schema_version\",\"\"))'" 2>/dev/null | tr -d '\r\n' || echo "")
if [ "$E_SV" = "1" ]; then
    _check_pass "E.4 /system/state schema_version" "1"
elif [ -n "$E_SV" ]; then
    _check_warn "E.4 /system/state schema_version" "got '${E_SV}' expected '1'"
else
    _check_fail "E.4 /system/state schema_version" "no schema_version in $(echo "$E_STATE" | head -c 80)"
fi

E_CTX_CODE=$(curl_authed_status "/cortex/hyperlation/state")
case "$E_CTX_CODE" in
    200|401|403)
        _check_pass "E.5 cortex-hyperlation" "HTTP ${E_CTX_CODE}"
        ;;
    404)
        _check_warn "E.5 cortex-hyperlation" "endpoint missing (HTTP 404)"
        ;;
    *)
        _check_fail "E.5 cortex-hyperlation" "HTTP ${E_CTX_CODE}"
        ;;
esac

E_AIST=$(ssh_run "curl -s --connect-timeout 5 http://localhost:8420/ai/status 2>/dev/null" || echo "")
if echo "$E_AIST" | grep -q '"status"'; then
    _check_pass "E.6 /ai/status" "$(echo "$E_AIST" | head -c 80)"
else
    _check_fail "E.6 /ai/status" "no 'status' field: $(echo "$E_AIST" | head -c 80)"
fi

# ============================================================
# Section F -- ai CLI
# ============================================================
echo ""
echo "--- Section F: ai CLI ---"

F_WHICH=$(ssh_run "which ai 2>/dev/null" | tr -d '\r\n' || echo "")
if [ "$F_WHICH" = "/usr/bin/ai" ]; then
    _check_pass "F.1 which-ai" "${F_WHICH}"
elif [ -n "$F_WHICH" ]; then
    _check_warn "F.1 which-ai" "found at ${F_WHICH} (expected /usr/bin/ai)"
else
    _check_fail "F.1 which-ai" "not in PATH"
fi

F_HELP=$(ssh_run "ai --help 2>&1 | head -1" | tr -d '\r' || echo "")
if echo "$F_HELP" | grep -qi "usage: ai"; then
    _check_pass "F.2 ai --help" "$(echo "$F_HELP" | head -c 80)"
elif [ -n "$F_HELP" ]; then
    _check_warn "F.2 ai --help" "first line: $(echo "$F_HELP" | head -c 80)"
else
    _check_fail "F.2 ai --help" "no output"
fi

F_VER=$(ssh_run "ai --version 2>&1 | head -1" | tr -d '\r' || echo "")
if echo "$F_VER" | grep -q "ai 0.1.0"; then
    _check_pass "F.3 ai --version" "${F_VER}"
elif echo "$F_VER" | grep -qi "ai .*[0-9]"; then
    _check_warn "F.3 ai --version" "got '${F_VER}' expected 'ai 0.1.0'"
else
    _check_fail "F.3 ai --version" "got '$(echo "$F_VER" | head -c 80)'"
fi

# ============================================================
# Section G -- Memory leak surveillance
# ============================================================
echo ""
echo "--- Section G: Memory leak surveillance (60s idle) ---"

_rss() {
    local pat="$1"
    ssh_run "ps -o rss= -p \$(pgrep -f '${pat}' | head -1) 2>/dev/null | awk '{print \$1}'" \
        | tr -d '\r\n' | head -c 16
}

G_DAEMON_INIT=$(_rss "ai-control-daemon")
G_CORTEX_INIT=$(_rss "ai-cortex")
echo "    [G.0] sample-initial daemon=${G_DAEMON_INIT:-0}KB cortex=${G_CORTEX_INIT:-0}KB"
echo "    [G.0] sleeping 60s for memory drift window..."
sleep 60
G_DAEMON_FIN=$(_rss "ai-control-daemon")
G_CORTEX_FIN=$(_rss "ai-cortex")
echo "    [G.0] sample-final   daemon=${G_DAEMON_FIN:-0}KB cortex=${G_CORTEX_FIN:-0}KB"

_growth_check() {
    local label="$1" init="$2" fin="$3"
    if [ -z "$init" ] || [ -z "$fin" ] || [ "$init" = "0" ]; then
        _check_skip "${label}" "process not present (init='${init}' fin='${fin}')"
        return
    fi
    # Allow 10% growth: fin*100 < init*110 == fin*10 < init*11
    local lhs=$((fin * 10))
    local rhs=$((init * 11))
    if [ "$lhs" -lt "$rhs" ]; then
        _check_pass "${label}" "init=${init}KB fin=${fin}KB (within +10%)"
    else
        _check_fail "${label}" "init=${init}KB fin=${fin}KB (>+10% growth)"
    fi
}
_growth_check "G.1 daemon-rss-stable" "$G_DAEMON_INIT" "$G_DAEMON_FIN"
_growth_check "G.2 cortex-rss-stable" "$G_CORTEX_INIT" "$G_CORTEX_FIN"

G_KMEM_AVAIL=$(ssh_run "test -r /sys/kernel/debug/kmemleak && echo y || echo n" | tr -d '\r\n' || echo "n")
if [ "$G_KMEM_AVAIL" = "y" ]; then
    G_KMEM=$(ssh_run "cat /sys/kernel/debug/kmemleak 2>/dev/null | wc -l" | tr -d '\r\n' || echo "x")
    if [ "$G_KMEM" = "0" ]; then
        _check_pass "G.3 kmemleak" "0 lines"
    else
        _check_warn "G.3 kmemleak" "${G_KMEM} lines reported"
    fi
else
    _check_skip "G.3 kmemleak" "/sys/kernel/debug/kmemleak unavailable"
fi

# ============================================================
# Section H -- Functional AI command (LLM-gated)
# ============================================================
echo ""
echo "--- Section H: Functional AI command ---"

H_AISTAT=$(ssh_run "curl -s --connect-timeout 5 http://localhost:8420/ai/status 2>/dev/null" || echo "")
if ! echo "$H_AISTAT" | grep -qE '"loaded"[[:space:]]*:[[:space:]]*true|"model_loaded"[[:space:]]*:[[:space:]]*true'; then
    _check_skip "H.1 ai-dry-run-screenshot" "LLM not loaded ($(echo "$H_AISTAT" | head -c 60))"
    _check_skip "H.2 contusion-parse-screenshot" "LLM not loaded"
else
    H_TOK=$(get_auth_token)
    H_DRY=$(ssh_run "echo 'take a screenshot' | ai --dry-run --token ${H_TOK} 2>&1" | tr -d '\r' || echo "")
    if echo "$H_DRY" | grep -qi "screenshot"; then
        _check_pass "H.1 ai-dry-run-screenshot" "$(echo "$H_DRY" | grep -i screenshot | head -1 | head -c 80)"
    else
        _check_fail "H.1 ai-dry-run-screenshot" "no 'screenshot' in: $(echo "$H_DRY" | head -c 100)"
    fi

    H_PARSE_BODY=$(ssh_run "curl -s --connect-timeout 10 -X POST http://localhost:8420/contusion/parse -H 'Content-Type: application/json' -H 'Authorization: Bearer ${H_TOK}' -d '{\"instruction\":\"take a screenshot\"}' 2>/dev/null" || echo "")
    if echo "$H_PARSE_BODY" | grep -q "handler_type"; then
        _check_pass "H.2 contusion-parse-screenshot" "$(echo "$H_PARSE_BODY" | head -c 100)"
    else
        _check_fail "H.2 contusion-parse-screenshot" "no handler_type: $(echo "$H_PARSE_BODY" | head -c 100)"
    fi
fi

# ============================================================
# Tally + exit
# ============================================================
TOTAL=$((PASS + FAIL + WARN + SKIP))

echo ""
echo "========================================"
echo "  EXTENDED SMOKE RESULTS"
echo "========================================"
echo "  Passed:   $PASS"
echo "  Failed:   $FAIL"
echo "  Warned:   $WARN"
echo "  Skipped:  $SKIP"
echo "  ------------------------"
echo "  TOTAL:    $TOTAL checks"
echo "========================================"
if [ "$FAIL" -eq 0 ]; then
    echo "OVERALL: PASS"
    OVERALL_RC=0
else
    echo "OVERALL: FAIL ($FAIL failure$([ "$FAIL" -eq 1 ] || echo "s"))"
    OVERALL_RC=1
fi

echo ""
echo "Shutting down QEMU..."
kill "$QEMU_PID" 2>/dev/null || true
for _ in 1 2 3; do
    kill -0 "$QEMU_PID" 2>/dev/null || break
    sleep 1
done
kill -9 "$QEMU_PID" 2>/dev/null || true

exit "$OVERALL_RC"
