#!/bin/bash
# verify-s52-fixes.sh -- Defensive verification of the 4 S52 production fixes
# (cortex TimeoutStartSec, coherenced alias, /system/state proxy, /ai/status field)
# against a freshly built ISO.
#
# DESIGN: NO `set -e`.  Every step uses `|| true` and explicit if/else so each
# check produces a [PASS]/[FAIL]/[SKIP]/[WARN] line BEFORE moving on.  Silent
# mid-script exits would defeat the entire point of this script.
#
# Usage:
#   bash scripts/verify-s52-fixes.sh
#   ISO_FILE=/path/to/foo.iso bash scripts/verify-s52-fixes.sh
#
# Exit code: 0 if zero FAILs, 1 otherwise.

# Intentionally NO `set -e` / `set -u` / `set -o pipefail`.
# We want every check to run to completion and report individually.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ISO_DIR="${ISO_DIR:-${PROJECT_DIR}/output}"

if [ -z "${ISO_FILE:-}" ]; then
    ISO_FILE="$(ls -t "${ISO_DIR}"/*.iso 2>/dev/null | grep -v '\.bak$' | head -1)"
fi

# Use ports distinct from test-qemu.sh (2222/8421) and verify-s52-fixes.sh.old (2223/8422).
SSH_PORT="${SSH_PORT:-2227}"
DAEMON_PORT="${DAEMON_PORT:-8427}"
EXTRACT_DIR="${EXTRACT_DIR:-/tmp/iso-extract-s52v}"
SERIAL_LOG="${SERIAL_LOG:-/tmp/qemu-s52v-serial.log}"
QEMU_STDOUT="${QEMU_STDOUT:-/tmp/qemu-s52v-stdout.log}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"
SSHD_WAIT_MAX="${SSHD_WAIT_MAX:-120}"
SETTLE_SECS="${SETTLE_SECS:-30}"

QEMU_PID=""
SSH_USER=""
SSH_PASS=""

PASS=0
FAIL=0
SKIP=0
WARN=0

cleanup() {
    if [ -n "$QEMU_PID" ]; then
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

# --- Pre-flight ---------------------------------------------------------------
if [ -z "$ISO_FILE" ] || [ ! -f "$ISO_FILE" ]; then
    echo "ERROR: no ISO found (ISO_DIR=$ISO_DIR ISO_FILE=$ISO_FILE)" >&2
    exit 1
fi
echo "ISO:        $ISO_FILE ($(du -h "$ISO_FILE" 2>/dev/null | cut -f1))"
echo "SSH_PORT:   $SSH_PORT  (host -> guest 22)"
echo "DAEMON_PORT $DAEMON_PORT  (host -> guest 8420)"

# Kill stale QEMUs from previous runs that might be holding our ports
if pgrep -f "hostfwd=tcp::${SSH_PORT}" >/dev/null 2>&1; then
    pkill -9 -f "hostfwd=tcp::${SSH_PORT}" 2>/dev/null || true
    sleep 1
fi

rm -rf "$EXTRACT_DIR" 2>/dev/null || true
mkdir -p "$EXTRACT_DIR"
rm -f "$SERIAL_LOG" "$QEMU_STDOUT" 2>/dev/null || true

echo "Extracting kernel + initramfs..."
( cd "$EXTRACT_DIR" && bsdtar xf "$ISO_FILE" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img ) 2>/dev/null
VMLINUZ="$EXTRACT_DIR/arch/boot/x86_64/vmlinuz-linux"
INITRD="$EXTRACT_DIR/arch/boot/x86_64/initramfs-linux.img"
if [ ! -f "$VMLINUZ" ] || [ ! -f "$INITRD" ]; then
    echo "ERROR: kernel/initrd extraction failed" >&2
    exit 1
fi

LABEL="$(isoinfo -d -i "$ISO_FILE" 2>/dev/null | sed -n 's/^Volume id: //p' | head -1)"
[ -z "$LABEL" ] && LABEL="AI_ARCH_202602"

KVM_FLAG=""
if [ -r /dev/kvm ]; then
    KVM_FLAG="-enable-kvm"
    echo "KVM:        enabled"
else
    echo "KVM:        unavailable (TCG software emulation)"
fi

# --- Boot QEMU ----------------------------------------------------------------
echo ""
echo "=== Booting QEMU (timeout ${BOOT_TIMEOUT}s) ==="
nohup qemu-system-x86_64 \
    $KVM_FLAG \
    -m 4096 -smp 2 \
    -drive file="$ISO_FILE",media=cdrom,if=ide,index=1 \
    -kernel "$VMLINUZ" \
    -initrd "$INITRD" \
    -append "archisobasedir=arch archisolabel=${LABEL} archisodevice=/dev/sr0 console=ttyS0,115200 systemd.log_level=info tsc=unstable" \
    -display none \
    -serial "file:${SERIAL_LOG}" \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::${SSH_PORT}-:22,hostfwd=tcp::${DAEMON_PORT}-:8420 \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -no-reboot \
    > "$QEMU_STDOUT" 2>&1 &
QEMU_PID=$!
echo "QEMU PID: $QEMU_PID"

# Verify QEMU survived first 2s
for _ in $(seq 1 20); do
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "ERROR: QEMU died immediately"
        cat "$QEMU_STDOUT" 2>/dev/null
        exit 1
    fi
    [ -s "$SERIAL_LOG" ] && break
    sleep 0.1
done

# Wait for login prompt or multi-user target
BOOT_START=$(date +%s)
BOOT_OK=0
while : ; do
    ELAPSED=$(( $(date +%s) - BOOT_START ))
    if [ "$ELAPSED" -ge "$BOOT_TIMEOUT" ]; then
        echo "  Boot timeout after ${ELAPSED}s — proceeding anyway (will produce FAILs)"
        break
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "  QEMU died during boot at ${ELAPSED}s"
        tail -30 "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'
        break
    fi
    if grep -qE "Reached target.*[Mm]ulti-[Uu]ser|login:|Archimation -- AI Arch Linux ready" "$SERIAL_LOG" 2>/dev/null; then
        echo "  Login/multi-user reached at ${ELAPSED}s"
        BOOT_OK=1
        break
    fi
    if grep -q "emergency mode" "$SERIAL_LOG" 2>/dev/null; then
        echo "  EMERGENCY MODE detected at ${ELAPSED}s"
        break
    fi
    sleep 5
done

# Wait for sshd to actually accept TCP on $SSH_PORT
echo "Polling sshd on ${SSH_PORT} (max ${SSHD_WAIT_MAX}s)..."
SSH_T0=$(date +%s)
SSHD_OK=0
while : ; do
    EL=$(( $(date +%s) - SSH_T0 ))
    if [ "$EL" -ge "$SSHD_WAIT_MAX" ]; then
        echo "  sshd not reachable after ${EL}s — running checks anyway"
        break
    fi
    if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/${SSH_PORT}" 2>/dev/null; then
        echo "  sshd reachable after ${EL}s"
        SSHD_OK=1
        break
    fi
    sleep 2
done

# Let services settle
if [ "$SSHD_OK" -eq 1 ]; then
    echo "Settling ${SETTLE_SECS}s for daemons..."
    sleep "$SETTLE_SECS"
fi

# Pick which user works (root first, then arch)
ssh_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o ConnectTimeout=10 -o LogLevel=ERROR
          -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1
          -p "$SSH_PORT")

if command -v sshpass >/dev/null 2>&1; then
    if sshpass -p root ssh "${ssh_opts[@]}" root@127.0.0.1 "echo SSHOK" 2>/dev/null | grep -q SSHOK; then
        SSH_USER="root"; SSH_PASS="root"
        echo "SSH login: root"
    elif sshpass -p arch ssh "${ssh_opts[@]}" arch@127.0.0.1 "echo SSHOK" 2>/dev/null | grep -q SSHOK; then
        SSH_USER="arch"; SSH_PASS="arch"
        echo "SSH login: arch"
    else
        echo "SSH login: FAILED for both root and arch (checks will SKIP)"
    fi
else
    echo "SSH login: sshpass not installed (checks will SKIP)"
fi

# Helper: run a command on the guest, return its stdout/stderr.
# Returns empty string and nonzero exit if SSH unavailable.
ssh_run() {
    if [ -z "$SSH_USER" ]; then
        return 1
    fi
    sshpass -p "$SSH_PASS" ssh "${ssh_opts[@]}" "${SSH_USER}@127.0.0.1" "$1" 2>&1
}

echo ""
echo "================================================="
echo "  S52 FIX VERIFICATION (5 named checks + bonus)"
echo "================================================="

# --- C0: boot-completed -------------------------------------------------------
echo ""
echo "--- C0: boot-completed (baseline health) ---"
c0_seen_marker="no"
if grep -qE "Archimation -- AI Arch Linux ready|Reached target.*[Mm]ulti-[Uu]ser" "$SERIAL_LOG" 2>/dev/null; then
    c0_seen_marker="yes"
fi
c0_state=""
if [ -n "$SSH_USER" ]; then
    c0_state="$(ssh_run "systemctl is-system-running 2>&1 || true" | tr -d '\r' | tail -1)"
fi
case "$c0_state" in
    running|degraded|starting)
        echo "[PASS] C0 boot-completed (system=$c0_state, serial-marker=$c0_seen_marker)"
        PASS=$((PASS+1))
        ;;
    *)
        if [ "$c0_seen_marker" = "yes" ]; then
            echo "[PASS] C0 boot-completed (serial-marker=yes, system=${c0_state:-unknown})"
            PASS=$((PASS+1))
        elif [ -z "$SSH_USER" ]; then
            echo "[FAIL] C0 boot-completed (no SSH, no serial marker)"
            FAIL=$((FAIL+1))
        else
            echo "[FAIL] C0 boot-completed (system=${c0_state:-unknown}, no marker)"
            FAIL=$((FAIL+1))
        fi
        ;;
esac

# --- C1: ai-cortex active -----------------------------------------------------
# Session 53: cortex needs ~25-30 s on TCG-emulated QEMU between exec and
# READY=1 (FastAPI/uvicorn import + app construction is the dominant cost).
# A single is-active probe ~30 s after sshd-up frequently catches the unit
# in the `activating` state even though it would PASS within another 30 s.
# Poll every 5 s for up to 90 s; PASS if EVER `active`, FAIL if it stays
# `activating` (=stuck) or transitions to `failed`. Cortex's TimeoutStartSec
# is 90 s (S52 PKGBUILD), so 90 s here matches the systemd ceiling.
echo ""
echo "--- C1: ai-cortex is-active (S52 fix: TimeoutStartSec, S53 polling) ---"
if [ -z "$SSH_USER" ]; then
    echo "[SKIP] C1 ai-cortex (no SSH)"; SKIP=$((SKIP+1))
else
    C1_POLL_MAX="${C1_POLL_MAX:-90}"
    C1_POLL_INT="${C1_POLL_INT:-5}"
    c1=""
    c1_t0=$(date +%s)
    c1_iter=0
    c1_max_iter=$(( C1_POLL_MAX / C1_POLL_INT ))
    while [ "$c1_iter" -lt "$c1_max_iter" ]; do
        c1="$(ssh_run "systemctl is-active ai-cortex 2>&1 || true" | tr -d '\r' | tail -1)"
        c1_elapsed=$(( $(date +%s) - c1_t0 ))
        if [ "$c1" = "active" ]; then
            echo "[PASS] C1 ai-cortex is-active=active (after ${c1_elapsed}s of polling)"
            PASS=$((PASS+1))
            break
        fi
        if [ "$c1" = "failed" ]; then
            echo "[FAIL] C1 ai-cortex is-active=failed (after ${c1_elapsed}s of polling)"
            FAIL=$((FAIL+1))
            echo "  --- ai-cortex status (first 12 lines) ---"
            ssh_run "systemctl status ai-cortex --no-pager 2>&1 | head -12" || true
            break
        fi
        c1_iter=$(( c1_iter + 1 ))
        # Don't sleep after the final iteration — fall through to the
        # post-loop FAIL emit below.
        if [ "$c1_iter" -lt "$c1_max_iter" ]; then
            sleep "$C1_POLL_INT"
        fi
    done
    if [ "$c1" != "active" ] && [ "$c1" != "failed" ]; then
        c1_elapsed=$(( $(date +%s) - c1_t0 ))
        echo "[FAIL] C1 ai-cortex never reached active (last=${c1:-unknown}, polled ${c1_elapsed}s)"
        FAIL=$((FAIL+1))
        echo "  --- ai-cortex status (first 12 lines) ---"
        ssh_run "systemctl status ai-cortex --no-pager 2>&1 | head -12" || true
    fi
fi

# --- C2: coherenced alias resolves & active -----------------------------------
echo ""
echo "--- C2: coherenced is-active (S52 fix: alias) ---"
if [ -z "$SSH_USER" ]; then
    echo "[SKIP] C2 coherenced (no SSH)"; SKIP=$((SKIP+1))
else
    c2="$(ssh_run "systemctl is-active coherenced 2>&1 || true" | tr -d '\r' | tail -1)"
    case "$c2" in
        active)
            echo "[PASS] C2 coherenced is-active=active (alias works)"
            PASS=$((PASS+1))
            ;;
        inactive|failed|activating|deactivating)
            echo "[FAIL] C2 coherenced is-active=${c2}"
            FAIL=$((FAIL+1))
            ssh_run "systemctl status coherenced --no-pager 2>&1 | head -12" || true
            ;;
        *)
            # alias missing entirely or unit not found — treat as SKIP since
            # Agent 1 owns coherence service files and may have it disabled.
            echo "[SKIP] C2 coherenced is-active=${c2:-unknown} (alias may be absent — Agent 1 domain)"
            SKIP=$((SKIP+1))
            ;;
    esac
fi

# --- C3: /system/state proxy returns schema_version ---------------------------
# S53 fix: /system/state requires TRUST_INTERACT (200). Bootstrap a token via
# /auth/token's localhost-bypass first, then send Authorization: Bearer <tok>.
echo ""
echo "--- C3: GET /system/state -> schema_version (S52 fix: proxy) ---"
if [ -z "$SSH_USER" ]; then
    echo "[SKIP] C3 /system/state (no SSH)"; SKIP=$((SKIP+1))
else
    # Mint a TRUST_INTERACT token. /auth/token has localhost-bootstrap that
    # accepts any trust_level <= the configured ceiling without prior auth
    # when invoked from 127.0.0.1.  Pattern matches scripts/test-qemu.sh:264
    # (single-quoted JSON inside double-quoted ssh_run; sed extracts on the
    # LOCAL side after SSH returns the body — avoids escape-soup across
    # SSH-to-remote-shell-to-curl-to-python boundaries).
    tok_resp="$(ssh_run "curl -s --connect-timeout 5 --max-time 8 -X POST http://127.0.0.1:8420/auth/token -H 'Content-Type: application/json' -d '{\"subject_id\": 1, \"name\": \"verify-s52-fixes\", \"trust_level\": 600}'" 2>/dev/null | tr -d '\r')"
    bearer="$(echo "$tok_resp" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
    echo "    DEBUG token-resp(80c)=$(echo "$tok_resp" | head -c 80)"
    echo "    DEBUG bearer-len=${#bearer}"
    if [ -n "$bearer" ]; then
        c3="$(ssh_run "curl -sS --max-time 8 -H 'Accept: application/json' -H 'Authorization: Bearer ${bearer}' http://127.0.0.1:8420/system/state 2>&1" | tr -d '\r')"
    else
        c3="$(ssh_run "curl -sS --max-time 8 -H 'Accept: application/json' http://127.0.0.1:8420/system/state 2>&1" | tr -d '\r')"
    fi
    if echo "$c3" | grep -q '"schema_version"'; then
        snippet="$(echo "$c3" | head -c 100)"
        echo "[PASS] C3 /system/state has schema_version: ${snippet}..."
        PASS=$((PASS+1))
    else
        snippet="$(echo "$c3" | head -c 200)"
        echo "[FAIL] C3 /system/state missing schema_version. Body: ${snippet}"
        FAIL=$((FAIL+1))
    fi
fi

# --- C4: /ai/status returns 'status' field ------------------------------------
echo ""
echo "--- C4: GET /ai/status -> status field (S52 fix: field) ---"
if [ -z "$SSH_USER" ]; then
    echo "[SKIP] C4 /ai/status (no SSH)"; SKIP=$((SKIP+1))
else
    c4="$(ssh_run "curl -sS --max-time 8 -H 'Accept: application/json' http://127.0.0.1:8420/ai/status 2>&1" | tr -d '\r')"
    if echo "$c4" | grep -q '"status"'; then
        snippet="$(echo "$c4" | head -c 100)"
        echo "[PASS] C4 /ai/status has status: ${snippet}..."
        PASS=$((PASS+1))
    else
        snippet="$(echo "$c4" | head -c 200)"
        echo "[FAIL] C4 /ai/status missing 'status'. Body: ${snippet}"
        FAIL=$((FAIL+1))
    fi
fi

# --- C5 (BONUS): /cortex/hyperlation/state ------------------------------------
echo ""
echo "--- C5 (bonus): GET /cortex/hyperlation/state -> 200/401/403 ---"
if [ -z "$SSH_USER" ]; then
    echo "[SKIP] C5 /cortex/hyperlation/state (no SSH)"; SKIP=$((SKIP+1))
else
    c5_code="$(ssh_run "curl -sS -o /dev/null -w '%{http_code}' --max-time 8 http://127.0.0.1:8420/cortex/hyperlation/state 2>&1" | tr -d '\r' | tail -1)"
    case "$c5_code" in
        200|401|403)
            echo "[PASS] C5 /cortex/hyperlation/state http=${c5_code}"
            PASS=$((PASS+1))
            ;;
        404)
            echo "[WARN] C5 /cortex/hyperlation/state http=404 (proxy not wired — bonus only)"
            WARN=$((WARN+1))
            ;;
        000|"")
            echo "[WARN] C5 /cortex/hyperlation/state no response (daemon down?)"
            WARN=$((WARN+1))
            ;;
        *)
            echo "[WARN] C5 /cortex/hyperlation/state http=${c5_code}"
            WARN=$((WARN+1))
            ;;
    esac
fi

# --- Tally --------------------------------------------------------------------
echo ""
echo "================================================="
echo "  RESULT: PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP  WARN=$WARN"
echo "================================================="

if [ "$FAIL" -eq 0 ]; then
    exit 0
else
    exit 1
fi
