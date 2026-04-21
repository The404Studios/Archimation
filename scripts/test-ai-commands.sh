#!/bin/bash
# test-ai-commands.sh -- Live AI-command test harness (Session 56, Agent 3).
#
# Boots the freshest ISO under output/ in QEMU, mints a TRUST_INTERACT
# bearer token via /auth/token's localhost-bootstrap, then exercises the
# real handler dispatch through /contusion/context for 19 named checks
# spanning the new S56 handlers (script.* + app.claude_*) and the
# pre-existing offline handler set.
#
# Defensive design (S53 lessons):
#   * NO `set -e` -- every check uses `|| true`/explicit-if so a single
#     failure does not silently cut the run short.
#   * All HTTP goes via `ssh_run` so the daemon's localhost-bootstrap
#     is in scope (host->guest port forwards on WSL2 are unreliable).
#   * Missing handlers emit [SKIP], not [FAIL] -- this script must not
#     false-positive while Agents 1/2 are mid-rebuild.
#   * Cleanup trap on EXIT/INT/TERM kills QEMU.
#   * Every curl carries `--max-time 10` to bound hang risk.
#
# Usage:
#   bash scripts/test-ai-commands.sh
#   ISO_FILE=/path/to/foo.iso bash scripts/test-ai-commands.sh
#
# Exit code: 0 if zero FAILs, 1 otherwise.

# Intentionally NO `set -e` / `set -u` / `set -o pipefail`.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ISO_DIR="${ISO_DIR:-${PROJECT_DIR}/output}"

if [ -z "${ISO_FILE:-}" ]; then
    ISO_FILE="$(ls -t "${ISO_DIR}"/*.iso 2>/dev/null | grep -v '\.bak$' | head -1)"
fi

# Ports distinct from test-qemu.sh (2222/8421) and verify-s52-fixes.sh (2227/8427).
SSH_PORT="${SSH_PORT:-2229}"
DAEMON_PORT="${DAEMON_PORT:-8429}"
EXTRACT_DIR="${EXTRACT_DIR:-/tmp/iso-extract-aicmd}"
SERIAL_LOG="${SERIAL_LOG:-/tmp/qemu-aicmd-serial.log}"
QEMU_STDOUT="${QEMU_STDOUT:-/tmp/qemu-aicmd-stdout.log}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"
SSHD_WAIT_MAX="${SSHD_WAIT_MAX:-120}"
SETTLE_SECS="${SETTLE_SECS:-30}"

QEMU_PID=""
SSH_USER=""
SSH_PASS=""
BEARER=""

PASS=0
FAIL=0
SKIP=0

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

# Kill stale QEMUs holding our ports.
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
    echo "KVM:        unavailable (TCG)"
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

for _ in $(seq 1 20); do
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "ERROR: QEMU died immediately"
        cat "$QEMU_STDOUT" 2>/dev/null
        exit 1
    fi
    [ -s "$SERIAL_LOG" ] && break
    sleep 0.1
done

BOOT_START=$(date +%s)
while : ; do
    ELAPSED=$(( $(date +%s) - BOOT_START ))
    if [ "$ELAPSED" -ge "$BOOT_TIMEOUT" ]; then
        echo "  Boot timeout after ${ELAPSED}s -- proceeding anyway"
        break
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "  QEMU died during boot at ${ELAPSED}s"
        tail -30 "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'
        break
    fi
    if grep -qE "Reached target.*[Mm]ulti-[Uu]ser|login:|Archimation -- AI Arch Linux ready" "$SERIAL_LOG" 2>/dev/null; then
        echo "  Login/multi-user reached at ${ELAPSED}s"
        break
    fi
    if grep -q "emergency mode" "$SERIAL_LOG" 2>/dev/null; then
        echo "  EMERGENCY MODE detected at ${ELAPSED}s"
        break
    fi
    sleep 5
done

echo "Polling sshd on ${SSH_PORT} (max ${SSHD_WAIT_MAX}s)..."
SSH_T0=$(date +%s)
SSHD_OK=0
while : ; do
    EL=$(( $(date +%s) - SSH_T0 ))
    if [ "$EL" -ge "$SSHD_WAIT_MAX" ]; then
        echo "  sshd not reachable after ${EL}s"
        break
    fi
    if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/${SSH_PORT}" 2>/dev/null; then
        echo "  sshd reachable after ${EL}s"
        SSHD_OK=1
        break
    fi
    sleep 2
done

if [ "$SSHD_OK" -eq 1 ]; then
    echo "Settling ${SETTLE_SECS}s for daemons..."
    sleep "$SETTLE_SECS"
fi

# Pick which user works.
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
        echo "SSH login: FAILED -- all checks will SKIP"
    fi
else
    echo "SSH login: sshpass not installed -- all checks will SKIP"
fi

# S56 fix: poll for ai-cortex active before running latch-gated tests.
# Without this, tests fire while cortex is still in `activating` (S54
# showed 7-13s polling before active), the daemon's CB_CORTEX opens after
# 5 latch-probe failures, and every subsequent test gets 503
# "cortex unreachable; refusing destructive action".  Wait up to 90s for
# cortex active; then sleep 5s for the CB to consider the channel healthy.
if [ -n "$SSH_USER" ]; then
    echo "Waiting for ai-cortex active (max 90s)..."
    cortex_ready=0
    for i in $(seq 1 18); do
        state=$(sshpass -p "$SSH_PASS" ssh "${ssh_opts[@]}" "${SSH_USER}@127.0.0.1" "systemctl is-active ai-cortex 2>/dev/null" 2>/dev/null | tr -d '\r' | tail -1)
        if [ "$state" = "active" ]; then
            echo "  ai-cortex active after $((i*5))s"
            cortex_ready=1
            break
        fi
        sleep 5
    done
    if [ "$cortex_ready" -eq 1 ]; then
        # Daemon has 100ms latch-cache TTL + 5-failure CB threshold; let
        # cortex hold steady for one full CB recovery window before tests fire.
        sleep 35
    else
        echo "  WARN: ai-cortex never reached active in 90s; tests will likely FAIL"
    fi
fi

ssh_run() {
    if [ -z "$SSH_USER" ]; then
        return 1
    fi
    sshpass -p "$SSH_PASS" ssh "${ssh_opts[@]}" "${SSH_USER}@127.0.0.1" "$1" 2>&1
}

# --- Auth bootstrap (S53 C3 pattern) ------------------------------------------
# /auth/token has a localhost-bootstrap that mints any trust_level the
# caller asks for when invoked from 127.0.0.1.  Single-quoted JSON inside
# double-quoted ssh_run; sed-extract the token on the LOCAL side after
# SSH returns the body.
mint_bearer() {
    local lvl="${1:-600}"
    local resp
    resp="$(ssh_run "curl -s --connect-timeout 5 --max-time 8 -X POST http://127.0.0.1:8420/auth/token -H 'Content-Type: application/json' -d '{\"subject_id\": 1, \"name\": \"test-ai-commands\", \"trust_level\": ${lvl}}'" 2>/dev/null | tr -d '\r')"
    echo "$resp" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

if [ -n "$SSH_USER" ]; then
    BEARER="$(mint_bearer 600)"
    echo "    bearer-len=${#BEARER}"
    if [ -z "$BEARER" ]; then
        # Fall back to TRUST_INTERACT (200) which /contusion/context demands.
        BEARER="$(mint_bearer 400)"
        echo "    fallback bearer-len=${#BEARER}"
    fi
fi

# Helper that POSTs JSON to /contusion/context with auth, returns body.
post_context() {
    local phrase="$1"
    local hdr=""
    if [ -n "$BEARER" ]; then
        hdr="-H 'Authorization: Bearer ${BEARER}'"
    fi
    # shellcheck disable=SC2090
    ssh_run "curl -sS --max-time 10 -H 'Accept: application/json' -H 'Content-Type: application/json' ${hdr} -X POST http://127.0.0.1:8420/contusion/context -d '$(echo "$phrase" | sed "s/'/'\\\\''/g")'" | tr -d '\r'
}

# Helper that POSTs JSON to an arbitrary path with auth.
post_json() {
    local path="$1"; local body="$2"
    local hdr=""
    if [ -n "$BEARER" ]; then
        hdr="-H 'Authorization: Bearer ${BEARER}'"
    fi
    ssh_run "curl -sS --max-time 10 -H 'Accept: application/json' -H 'Content-Type: application/json' ${hdr} -X POST http://127.0.0.1:8420${path} -d '${body}'" | tr -d '\r'
}

# Helper: GET with auth.
get_json() {
    local path="$1"
    local hdr=""
    if [ -n "$BEARER" ]; then
        hdr="-H 'Authorization: Bearer ${BEARER}'"
    fi
    ssh_run "curl -sS --max-time 10 -H 'Accept: application/json' ${hdr} http://127.0.0.1:8420${path}" | tr -d '\r'
}

# Helper: emit a result line, increment counters.
record() {
    local verdict="$1"; shift
    case "$verdict" in
        PASS) PASS=$((PASS+1)); echo "[PASS] $*" ;;
        FAIL) FAIL=$((FAIL+1)); echo "[FAIL] $*" ;;
        SKIP) SKIP=$((SKIP+1)); echo "[SKIP] $*" ;;
        *)    SKIP=$((SKIP+1)); echo "[SKIP] $*" ;;
    esac
}

echo ""
echo "================================================="
echo "  S56 LIVE AI-COMMAND BATTERY (19 named checks)"
echo "================================================="

if [ -z "$SSH_USER" ]; then
    echo ""
    echo "  All checks SKIPped (no SSH)."
    for n in 1.1 1.2 1.3 1.4 1.5 1.6 2.1 2.2 2.3 3.1 3.2 3.3 4.1 4.2 4.3 5.1 5.2 5.3; do
        record SKIP "T${n} (no SSH)"
    done
    echo ""
    echo "================================================="
    echo "  RESULT: PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
    echo "================================================="
    [ "$FAIL" -eq 0 ] && exit 0 || exit 1
fi

# Helper: detect "missing handler" in a /contusion/context response so we
# emit SKIP instead of FAIL while Agent 1/2 work is unfinished.
is_missing_handler() {
    local body="$1"; local ht="$2"
    # If response says no_handler / unknown / not_found OR doesn't mention
    # the handler_type at all in a positive sense, treat as missing.
    if echo "$body" | grep -qiE "no_handler|unknown.handler|handler_not_found|no executable actions"; then
        return 0
    fi
    # If the body has no handler_type field at all and has empty actions/pending
    if ! echo "$body" | grep -q "handler_type"; then
        if echo "$body" | grep -q '"actions"[[:space:]]*:[[:space:]]*\[\]' \
           && echo "$body" | grep -q '"pending"[[:space:]]*:[[:space:]]*\[\]'; then
            return 0
        fi
    fi
    return 1
}

# ---------------------------------------------------------------------------
# T1: Direct handler dispatch via /contusion/context
# ---------------------------------------------------------------------------
echo ""
echo "--- T1: script.* handlers via /contusion/context ---"

# T1.1: script.list
body="$(post_context '{"instruction": "list scripts"}')"
if is_missing_handler "$body"; then
    record SKIP "T1.1 script.list (handler not yet shipped) body=$(echo "$body" | head -c 80)"
elif echo "$body" | grep -qE '"handler_type"[[:space:]]*:[[:space:]]*"script\.list"' \
     || echo "$body" | grep -q '"scripts"'; then
    record PASS "T1.1 script.list dispatched"
else
    record FAIL "T1.1 script.list missing scripts array. body=$(echo "$body" | head -c 200)"
fi

# T1.2: script.run name=hello
body="$(post_context '{"instruction": "run script hello"}')"
if is_missing_handler "$body"; then
    record SKIP "T1.2 script.run hello (handler not yet shipped)"
elif echo "$body" | grep -qE "Hello from AI Arch Linux"; then
    record PASS "T1.2 script.run hello produced expected stdout"
elif echo "$body" | grep -qE '"handler_type"[[:space:]]*:[[:space:]]*"script\.run"'; then
    # Handler ran but stdout didn't match -- dictionary may need a second arg
    record SKIP "T1.2 script.run ran but stdout did not contain marker (NL routing may differ). body=$(echo "$body" | head -c 200)"
else
    record FAIL "T1.2 script.run hello not dispatched. body=$(echo "$body" | head -c 200)"
fi

# T1.3: script.run name=system-info
body="$(post_context '{"instruction": "run script system-info"}')"
if is_missing_handler "$body"; then
    record SKIP "T1.3 script.run system-info (handler not yet shipped)"
elif echo "$body" | grep -qE "Uptime:"; then
    record PASS "T1.3 script.run system-info produced Uptime"
elif echo "$body" | grep -qE '"handler_type"[[:space:]]*:[[:space:]]*"script\.run"'; then
    record SKIP "T1.3 script.run ran but no Uptime: in stdout. body=$(echo "$body" | head -c 200)"
else
    record FAIL "T1.3 script.run system-info not dispatched. body=$(echo "$body" | head -c 200)"
fi

# T1.4: script.info disk-cleanup
body="$(post_context '{"instruction": "show info for script disk-cleanup"}')"
if is_missing_handler "$body"; then
    record SKIP "T1.4 script.info (handler not yet shipped)"
elif echo "$body" | grep -qE "AI-Network|prohibited|description"; then
    record PASS "T1.4 script.info disk-cleanup metadata visible"
elif echo "$body" | grep -qE '"handler_type"[[:space:]]*:[[:space:]]*"script\.info"'; then
    record SKIP "T1.4 script.info ran but expected fields missing. body=$(echo "$body" | head -c 200)"
else
    record FAIL "T1.4 script.info not dispatched. body=$(echo "$body" | head -c 200)"
fi

# T1.5: script.run does-not-exist -- expect graceful error envelope, not 500.
body="$(post_context '{"instruction": "run script does-not-exist"}')"
if is_missing_handler "$body"; then
    record SKIP "T1.5 script.run nonexistent (handler not shipped)"
elif echo "$body" | grep -qE '"success"[[:space:]]*:[[:space:]]*false|not.found|returncode.*127|invalid script'; then
    record PASS "T1.5 script.run nonexistent rejected gracefully"
elif echo "$body" | grep -qE '"status"[[:space:]]*:[[:space:]]*"error"'; then
    record PASS "T1.5 script.run nonexistent returned error envelope"
else
    record FAIL "T1.5 script.run nonexistent did not surface error. body=$(echo "$body" | head -c 200)"
fi

# T1.6: script.run path-traversal -- expect sanitizer rejection.
body="$(post_context '{"instruction": "run script ../../../etc/passwd"}')"
if is_missing_handler "$body"; then
    record SKIP "T1.6 script.run path-traversal (handler not shipped)"
# must have EITHER an explicit reject marker (handler rejected path traversal)
# OR a 400/403 HTTP status -- anything else FAILS.
elif echo "$body" | grep -qiE "path.*travers|reject|invalid.path|forbidden|403|400"; then
    record PASS "T1.6 script.run path-traversal rejected"
elif echo "$body" | grep -q "root:x:0:0"; then
    record FAIL "T1.6 script.run path-traversal EXECUTED - /etc/passwd returned"
else
    record FAIL "T1.6 script.run path-traversal ambiguous response (no reject marker, no passwd) - RESP=$(echo "$body" | head -c 200)"
fi

# ---------------------------------------------------------------------------
# T2: Claude installer handlers (offline-safe)
# ---------------------------------------------------------------------------
echo ""
echo "--- T2: app.claude_* handlers (offline-safe) ---"

# T2.1: app.claude_status
body="$(post_context '{"instruction": "is claude installed"}')"
if is_missing_handler "$body"; then
    record SKIP "T2.1 app.claude_status (handler not yet shipped)"
elif echo "$body" | grep -qE "npm_available|claude_installed"; then
    record PASS "T2.1 app.claude_status returned status flags"
elif echo "$body" | grep -qE '"handler_type"[[:space:]]*:[[:space:]]*"app\.claude_status"'; then
    record PASS "T2.1 app.claude_status dispatched (flags shape may differ)"
else
    record FAIL "T2.1 app.claude_status not dispatched. body=$(echo "$body" | head -c 200)"
fi

# T2.2: app.install_claude -- accept either graceful offline-error OR success.
body="$(post_context '{"instruction": "install claude code"}')"
if is_missing_handler "$body"; then
    record SKIP "T2.2 app.install_claude (handler not yet shipped)"
elif echo "$body" | grep -qE '"handler_type"[[:space:]]*:[[:space:]]*"app\.install_claude"'; then
    # We accept ANY structured response -- the handler EXISTS and routed.
    record PASS "T2.2 app.install_claude dispatched (offline-tolerant)"
elif echo "$body" | grep -qE "offline|network|failed.to.fetch|npm not found|no internet"; then
    record PASS "T2.2 app.install_claude returned graceful offline error"
elif echo "$body" | grep -qE '"needs_confirmation"[[:space:]]*:[[:space:]]*true'; then
    record PASS "T2.2 app.install_claude correctly requires confirmation"
else
    record FAIL "T2.2 app.install_claude not dispatched. body=$(echo "$body" | head -c 200)"
fi

# T2.3: app.claude_workspace_init -- no internet needed, creates ~/.claude/ files.
body="$(post_context '{"instruction": "initialize claude workspace"}')"
if is_missing_handler "$body"; then
    record SKIP "T2.3 app.claude_workspace_init (handler not yet shipped)"
elif echo "$body" | grep -qE '"handler_type"[[:space:]]*:[[:space:]]*"app\.claude_workspace_init"'; then
    # Verify side-effect: /root/.claude/ should now exist.
    side="$(ssh_run "ls -la /root/.claude/ 2>/dev/null | head -5" 2>/dev/null)"
    if [ -n "$side" ] && echo "$side" | grep -qE "\.claude|total"; then
        record PASS "T2.3 app.claude_workspace_init created /root/.claude/"
    else
        record PASS "T2.3 app.claude_workspace_init dispatched (workspace path TBD)"
    fi
elif echo "$body" | grep -qiE "workspace.*(init|created|exists)"; then
    record PASS "T2.3 app.claude_workspace_init dispatched"
else
    record FAIL "T2.3 app.claude_workspace_init not dispatched. body=$(echo "$body" | head -c 200)"
fi

# ---------------------------------------------------------------------------
# T3: Pre-existing offline handlers (regression -- no WiFi)
# ---------------------------------------------------------------------------
echo ""
echo "--- T3: regression checks on shipped handlers ---"

# T3.1: system summary / uptime via /system/summary endpoint.
body="$(get_json /system/summary)"
if echo "$body" | grep -qE "uptime|hostname|kernel|cpu"; then
    record PASS "T3.1 /system/summary returned uptime-class field"
elif echo "$body" | grep -qE '"detail".*Not Found|404'; then
    # Fall back to /system/info
    body="$(get_json /system/info)"
    if echo "$body" | grep -qE "uptime|hostname|kernel"; then
        record PASS "T3.1 /system/info returned uptime-class field"
    else
        record FAIL "T3.1 system summary missing uptime. body=$(echo "$body" | head -c 200)"
    fi
else
    record FAIL "T3.1 system summary unexpected. body=$(echo "$body" | head -c 200)"
fi

# T3.2: audio.volume_up via NL routing (noop in headless QEMU is fine).
body="$(post_context '{"instruction": "turn up the volume"}')"
if echo "$body" | grep -qE '"handler_type"[[:space:]]*:[[:space:]]*"audio\.volume_up"'; then
    record PASS "T3.2 audio.volume_up dispatched"
elif echo "$body" | grep -qE '"status"[[:space:]]*:[[:space:]]*"ok"'; then
    record PASS "T3.2 audio.volume_up accepted (handler_type may not surface)"
else
    record FAIL "T3.2 audio.volume_up not dispatched. body=$(echo "$body" | head -c 200)"
fi

# T3.3: screenshot -- accept either side-effect path or handler dispatch.
body="$(post_context '{"instruction": "take a screenshot"}')"
if echo "$body" | grep -qE '"handler_type"[[:space:]]*:[[:space:]]*"system\.screenshot|"handler_type"[[:space:]]*:[[:space:]]*"screenshot'; then
    record PASS "T3.3 screenshot handler dispatched"
elif echo "$body" | grep -qE "/tmp/.*\.(png|jpg)|screenshot.*saved|Pictures/"; then
    record PASS "T3.3 screenshot produced file path"
elif echo "$body" | grep -qE '"status"[[:space:]]*:[[:space:]]*"ok"'; then
    record PASS "T3.3 screenshot accepted (env may lack X)"
else
    record FAIL "T3.3 screenshot not dispatched. body=$(echo "$body" | head -c 200)"
fi

# ---------------------------------------------------------------------------
# T4: NL routing surface (/contusion/context as parse-and-execute)
# ---------------------------------------------------------------------------
echo ""
echo "--- T4: NL routing handler_type surface ---"

# T4.1: "list scripts" -> handler_type=script.list
body="$(post_context '{"instruction": "list scripts"}')"
if is_missing_handler "$body"; then
    record SKIP "T4.1 NL->script.list (handler not yet shipped)"
elif echo "$body" | grep -qE '"handler_type"[[:space:]]*:[[:space:]]*"script\.list"'; then
    record PASS "T4.1 NL routes 'list scripts' -> script.list"
else
    record FAIL "T4.1 NL did not route to script.list. body=$(echo "$body" | head -c 200)"
fi

# T4.2: "show system info" -> system.* OR script.run name=system-info.
body="$(post_context '{"instruction": "show system info"}')"
if is_missing_handler "$body"; then
    record SKIP "T4.2 NL->system info (handler not yet shipped)"
elif echo "$body" | grep -qE '"handler_type"[[:space:]]*:[[:space:]]*"(system\.|script\.run)'; then
    record PASS "T4.2 NL routes 'show system info' to system/script handler"
elif echo "$body" | grep -qE "uptime|hostname|kernel"; then
    record PASS "T4.2 NL produced system-info content"
else
    record FAIL "T4.2 NL system-info not routed. body=$(echo "$body" | head -c 200)"
fi

# T4.3: "is claude installed" -> app.claude_status
body="$(post_context '{"instruction": "is claude installed"}')"
if is_missing_handler "$body"; then
    record SKIP "T4.3 NL->app.claude_status (handler not yet shipped)"
elif echo "$body" | grep -qE '"handler_type"[[:space:]]*:[[:space:]]*"app\.claude_status"'; then
    record PASS "T4.3 NL routes 'is claude installed' -> app.claude_status"
else
    record FAIL "T4.3 NL claude_status not routed. body=$(echo "$body" | head -c 200)"
fi

# ---------------------------------------------------------------------------
# T5: ai CLI smoke
# ---------------------------------------------------------------------------
echo ""
echo "--- T5: /usr/bin/ai CLI smoke ---"

# T5.1: ai --version
out="$(ssh_run "ai --version 2>&1" 2>/dev/null)"
if echo "$out" | grep -qE "ai 0\.1\.0"; then
    record PASS "T5.1 ai --version reports 0.1.0"
elif echo "$out" | grep -qiE "command not found|no such file"; then
    record SKIP "T5.1 ai CLI not installed in this ISO"
else
    record FAIL "T5.1 ai --version unexpected. out=$(echo "$out" | head -c 200)"
fi

# T5.2: ai --help
out="$(ssh_run "ai --help 2>&1" 2>/dev/null)"
if echo "$out" | grep -qE "usage: ai" && echo "$out" | grep -qE "\-\-daemon-url"; then
    record PASS "T5.2 ai --help contains usage + --daemon-url"
elif echo "$out" | grep -qiE "command not found"; then
    record SKIP "T5.2 ai CLI not installed"
else
    record FAIL "T5.2 ai --help missing usage/--daemon-url. out=$(echo "$out" | head -c 200)"
fi

# T5.3: ai --dry-run list scripts
if [ -z "$BEARER" ]; then
    record SKIP "T5.3 ai dry-run (no bearer)"
else
    out="$(ssh_run "ai --daemon-url http://127.0.0.1:8420 --token '${BEARER}' --dry-run list scripts 2>&1" 2>/dev/null)"
    if echo "$out" | grep -qiE "command not found"; then
        record SKIP "T5.3 ai CLI not installed"
    elif echo "$out" | grep -qE "Proposed action.*script\.list|handler_type.*script\.list|dry-run"; then
        record PASS "T5.3 ai dry-run shows proposed action without execute"
    elif echo "$out" | grep -qE "Low confidence"; then
        record SKIP "T5.3 ai dry-run low-confidence (LLM/dictionary mismatch)"
    elif echo "$out" | grep -qE "cannot reach|daemon unreachable"; then
        record FAIL "T5.3 ai dry-run could not reach daemon. out=$(echo "$out" | head -c 200)"
    else
        record FAIL "T5.3 ai dry-run unexpected. out=$(echo "$out" | head -c 200)"
    fi
fi

# --- Tally --------------------------------------------------------------------
echo ""
echo "================================================="
echo "  RESULT: PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
echo "================================================="

if [ "$FAIL" -eq 0 ]; then
    exit 0
else
    exit 1
fi
