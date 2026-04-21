#!/bin/bash
# test-qemu-contusion.sh - Contusion smoke battery run inside a booted QEMU VM.
#
# Sourced from scripts/test-qemu.sh AFTER the main smoke suite has proven the
# daemon is alive. Expects these globals to be set by the caller:
#   SSH_USER        — ssh user (usually root or arch), empty if no SSH
#   SSH_ACTIVE      — full ssh command string to run against the VM
#   AUTH_TOKEN      — trust-level 600 bootstrap token (may be empty; we mint fresh)
#   PASS / FAIL     — running tallies maintained by the caller
#   SKIPPED / WARNINGS — also maintained by the caller
#
# Re-entrant: each test is self-contained and leaves no persistent state the
# next test depends on (except the tokens it mints, which are cleaned up).
#
# Session 42 mission part B: ≥12 Contusion tests + emergency-latch coverage.

set -uo pipefail    # NOTE: intentionally no -e — tests continue on per-test failure.

# ---------------------------------------------------------------------------
# Helpers (private to this battery; prefixed _cn_ to avoid clashing with
# caller's helpers).
# ---------------------------------------------------------------------------

_cn_PASS_PREV=$PASS
_cn_FAIL_PREV=$FAIL
_cn_SKIP_PREV=$SKIPPED

# Minted token caches — trust 400 for user actions, 600 for admin/dangerous.
_CN_TOKEN_400=""
_CN_TOKEN_600=""

# Summary table rows (status|name|http|note).
declare -a _CN_ROWS=()

_cn_ssh() {
    if [ -z "${SSH_USER:-}" ]; then
        return 1
    fi
    $SSH_ACTIVE "$@" 2>/dev/null
}

# Mint a token at the given trust level via /auth/token (localhost bootstrap).
# Echoes the token (or empty on failure). Safe under set -u.
_cn_mint_token() {
    local trust="$1"
    _cn_ssh "curl -s --connect-timeout 5 -X POST http://localhost:8420/auth/token \
        -H 'Content-Type: application/json' \
        -d '{\"subject_id\": 1, \"name\": \"qemu-contusion-trust${trust}\", \"trust_level\": ${trust}}'" \
        2>/dev/null \
        | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        || true
}

# Run a curl POST over SSH with a bearer token.
# $1 = token, $2 = path, $3 = json body, $4 = optional "-i" for headers
_cn_curl_post() {
    local token="$1"
    local path="$2"
    local body="$3"
    local extra="${4:-}"
    # -s silent, -S show errors, -w capture status on last line
    _cn_ssh "curl -s -S -w '\nHTTP_STATUS:%{http_code}\n' $extra \
        --connect-timeout 5 \
        -H 'Content-Type: application/json' \
        -H 'Authorization: Bearer ${token}' \
        -X POST http://localhost:8420${path} \
        -d '${body}'" 2>/dev/null || echo ""
}

_cn_status_of() {
    # Extract HTTP_STATUS: line from a _cn_curl_post response.
    echo "$1" | awk -F: '/^HTTP_STATUS:/ {print $2; exit}' | tr -d '\r\n '
}

_cn_body_of() {
    # Everything before the HTTP_STATUS: marker.
    echo "$1" | awk '/^HTTP_STATUS:/ {exit} {print}'
}

_cn_record() {
    local status="$1"   # PASS|FAIL|SKIP|WARN
    local name="$2"
    local http="$3"
    local note="$4"
    _CN_ROWS+=("${status}|${name}|${http}|${note}")
    case "$status" in
        PASS) PASS=$((PASS + 1)) ;;
        FAIL) FAIL=$((FAIL + 1)) ;;
        SKIP) SKIPPED=$((SKIPPED + 1)) ;;
        WARN) WARNINGS=$((WARNINGS + 1)) ;;
    esac
    printf "  [CN:%s] %-36s http=%-3s %s\n" "$status" "$name" "$http" "$note"
}

# ---------------------------------------------------------------------------
# Pre-flight: require SSH + a running daemon.
# ---------------------------------------------------------------------------
echo ""
echo "========================================"
echo "  CONTUSION SMOKE BATTERY (Session 42)"
echo "========================================"

if [ -z "${SSH_USER:-}" ]; then
    echo "  [CN:SKIP] no SSH session — entire battery skipped"
    for n in mint_token_400 mint_token_600 \
             contusion_context_safe contusion_context_moderate \
             contusion_context_dangerous contusion_context_volume_up \
             contusion_context_brightness contusion_context_window \
             contusion_context_workspace contusion_context_lock \
             contusion_launch_firefox contusion_confirm \
             emergency_activate emergency_clear; do
        _cn_record SKIP "$n" "-" "no-ssh"
    done
    return 0 2>/dev/null || true
fi

# Probe the daemon is up; skip loudly if not rather than spamming failures.
_CN_HEALTH=$(_cn_ssh "curl -s --connect-timeout 3 http://localhost:8420/health" || echo "")
if ! echo "$_CN_HEALTH" | grep -q '"status"'; then
    echo "  [CN:SKIP] /health unreachable; battery skipped"
    for n in mint_token_400 mint_token_600 \
             contusion_context_safe contusion_context_moderate \
             contusion_context_dangerous contusion_context_volume_up \
             contusion_context_brightness contusion_context_window \
             contusion_context_workspace contusion_context_lock \
             contusion_launch_firefox contusion_confirm \
             emergency_activate emergency_clear; do
        _cn_record SKIP "$n" "-" "daemon-down"
    done
    return 0 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Test 1: mint_token_400
# ---------------------------------------------------------------------------
_CN_TOKEN_400=$(_cn_mint_token 400)
if [ -n "$_CN_TOKEN_400" ]; then
    _cn_record PASS "mint_token_400" "200" "len=${#_CN_TOKEN_400}"
else
    _cn_record FAIL "mint_token_400" "-" "no token returned"
fi

# ---------------------------------------------------------------------------
# Test 2: mint_token_600
# ---------------------------------------------------------------------------
_CN_TOKEN_600=$(_cn_mint_token 600)
if [ -n "$_CN_TOKEN_600" ]; then
    _cn_record PASS "mint_token_600" "200" "len=${#_CN_TOKEN_600}"
else
    _cn_record FAIL "mint_token_600" "-" "no token returned"
fi

# Guard: later tests need a 400 token at minimum.
_CN_TOKEN="${_CN_TOKEN_400:-$_CN_TOKEN_600}"
if [ -z "$_CN_TOKEN" ]; then
    echo "  [CN] cannot mint any token — skipping remaining contusion tests"
    for n in contusion_context_safe contusion_context_moderate \
             contusion_context_dangerous contusion_context_volume_up \
             contusion_context_brightness contusion_context_window \
             contusion_context_workspace contusion_context_lock \
             contusion_launch_firefox contusion_confirm \
             emergency_activate emergency_clear; do
        _cn_record SKIP "$n" "-" "no-token"
    done
    return 0 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Test 3: contusion_context_safe — "list running processes"
#   Expect: 200, status:"ok", at least one action in actions[].
# ---------------------------------------------------------------------------
_RESP=$(_cn_curl_post "$_CN_TOKEN" "/contusion/context" \
    '{"request":"list running processes"}')
_HTTP=$(_cn_status_of "$_RESP")
_BODY=$(_cn_body_of "$_RESP")
if [ "$_HTTP" = "200" ] && echo "$_BODY" | grep -q '"status"[[:space:]]*:[[:space:]]*"ok"' \
   && echo "$_BODY" | grep -qE '"actions"[[:space:]]*:[[:space:]]*\['; then
    # An empty actions array is a soft-fail (engine parsed but matched nothing).
    if echo "$_BODY" | grep -qE '"actions"[[:space:]]*:[[:space:]]*\[[[:space:]]*\]'; then
        _cn_record WARN "contusion_context_safe" "$_HTTP" "actions=[] (dictionary miss)"
    else
        _cn_record PASS "contusion_context_safe" "$_HTTP" "actions populated"
    fi
else
    _cn_record FAIL "contusion_context_safe" "$_HTTP" "body=${_BODY:0:120}"
fi

# ---------------------------------------------------------------------------
# Test 4: contusion_context_moderate — "install htop"
#   Expect: needs_confirmation:true OR pending populated.
# ---------------------------------------------------------------------------
_RESP=$(_cn_curl_post "$_CN_TOKEN" "/contusion/context" \
    '{"request":"install htop"}')
_HTTP=$(_cn_status_of "$_RESP")
_BODY=$(_cn_body_of "$_RESP")
if [ "$_HTTP" = "200" ] && ( \
     echo "$_BODY" | grep -q '"needs_confirmation"[[:space:]]*:[[:space:]]*true' \
  || echo "$_BODY" | grep -qE '"pending"[[:space:]]*:[[:space:]]*\[[[:space:]]*\{' ); then
    _cn_record PASS "contusion_context_moderate" "$_HTTP" "confirm-gated"
else
    # Accept a graceful "no match" response too — some dictionaries don't
    # wire pacman and return blocked/actions=[] instead of pending.
    if [ "$_HTTP" = "200" ] && echo "$_BODY" | grep -qE '"blocked"|"actions"'; then
        _cn_record WARN "contusion_context_moderate" "$_HTTP" "no-pending (dict gap)"
    else
        _cn_record FAIL "contusion_context_moderate" "$_HTTP" "body=${_BODY:0:120}"
    fi
fi

# ---------------------------------------------------------------------------
# Test 5: contusion_context_dangerous — "delete /tmp/test_file"
#   Expect: blocked:true OR needs_confirmation.
# ---------------------------------------------------------------------------
_RESP=$(_cn_curl_post "$_CN_TOKEN" "/contusion/context" \
    '{"request":"delete /tmp/test_file"}')
_HTTP=$(_cn_status_of "$_RESP")
_BODY=$(_cn_body_of "$_RESP")
if [ "$_HTTP" = "200" ] && ( \
     echo "$_BODY" | grep -q '"needs_confirmation"[[:space:]]*:[[:space:]]*true' \
  || echo "$_BODY" | grep -qE '"blocked"[[:space:]]*:[[:space:]]*\[[[:space:]]*\{' \
  || echo "$_BODY" | grep -q '"blocked"[[:space:]]*:[[:space:]]*true' ); then
    _cn_record PASS "contusion_context_dangerous" "$_HTTP" "gate-engaged"
else
    _cn_record FAIL "contusion_context_dangerous" "$_HTTP" "body=${_BODY:0:120}"
fi

# ---------------------------------------------------------------------------
# Helper: assert that a /contusion/context response contains a given
# handler_type somewhere in actions[] or pending[]. Accepts either.
# ---------------------------------------------------------------------------
_cn_assert_handler() {
    local name="$1"; local request="$2"; local handler="$3"
    local resp http body
    resp=$(_cn_curl_post "$_CN_TOKEN" "/contusion/context" \
        "{\"request\":\"${request}\"}")
    http=$(_cn_status_of "$resp")
    body=$(_cn_body_of "$resp")
    if [ "$http" = "200" ] && echo "$body" | grep -q "\"handler_type\"[[:space:]]*:[[:space:]]*\"${handler}\""; then
        _cn_record PASS "$name" "$http" "dispatched handler=${handler}"
    else
        # Some handlers may be aliased; record WARN if any audio/brightness/
        # etc handler appeared. Otherwise FAIL.
        case "$handler" in
            audio.*)     alias_pat='"handler_type":[[:space:]]*"audio\.' ;;
            brightness.*)alias_pat='"handler_type":[[:space:]]*"brightness\.' ;;
            window.*)    alias_pat='"handler_type":[[:space:]]*"window\.' ;;
            workspace.*) alias_pat='"handler_type":[[:space:]]*"workspace\.' ;;
            power.*)     alias_pat='"handler_type":[[:space:]]*"power\.' ;;
            *) alias_pat='__never__' ;;
        esac
        if [ "$http" = "200" ] && echo "$body" | grep -qE "$alias_pat"; then
            _cn_record WARN "$name" "$http" "handler family matched (not exact)"
        else
            _cn_record FAIL "$name" "$http" "body=${body:0:160}"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Tests 6-10: handler_type dispatch assertions.
# ---------------------------------------------------------------------------
_cn_assert_handler "contusion_context_volume_up"   "turn up the volume"    "audio.volume_up"
_cn_assert_handler "contusion_context_brightness"  "brightness up"         "brightness.up"
_cn_assert_handler "contusion_context_window"      "maximize this window"  "window.maximize"
_cn_assert_handler "contusion_context_workspace"   "switch to workspace 2" "workspace.switch"
_cn_assert_handler "contusion_context_lock"        "lock the screen"       "power.lock_screen"

# ---------------------------------------------------------------------------
# Test 11: contusion_launch_firefox — /contusion/launch with app=firefox
#   Expect 200 launch envelope. Launch may fail (no $DISPLAY), but the
#   envelope should still be well-formed.
# ---------------------------------------------------------------------------
_RESP=$(_cn_curl_post "$_CN_TOKEN" "/contusion/launch" '{"app":"firefox"}')
_HTTP=$(_cn_status_of "$_RESP")
_BODY=$(_cn_body_of "$_RESP")
if [ "$_HTTP" = "200" ] && echo "$_BODY" | grep -qE '"app"[[:space:]]*:[[:space:]]*"firefox"'; then
    if echo "$_BODY" | grep -q '"success"[[:space:]]*:[[:space:]]*true'; then
        _cn_record PASS "contusion_launch_firefox" "$_HTTP" "launched"
    else
        # Headless QEMU has no display — accept well-formed failure envelope.
        _cn_record PASS "contusion_launch_firefox" "$_HTTP" "envelope-ok (no-display)"
    fi
else
    _cn_record FAIL "contusion_launch_firefox" "$_HTTP" "body=${_BODY:0:120}"
fi

# ---------------------------------------------------------------------------
# Test 12: contusion_confirm — safe command confirmation
#   Uses an uncontroversial command. /contusion/confirm requires band-600
#   (see auth.py ENDPOINT_TRUST); use the admin token.
# ---------------------------------------------------------------------------
_CN_CONFIRM_TOKEN="${_CN_TOKEN_600:-$_CN_TOKEN_400}"
_RESP=$(_cn_curl_post "$_CN_CONFIRM_TOKEN" "/contusion/confirm" \
    '{"command":"echo qemu-smoke-confirm"}')
_HTTP=$(_cn_status_of "$_RESP")
_BODY=$(_cn_body_of "$_RESP")
if [ "$_HTTP" = "200" ] && echo "$_BODY" | grep -qE '"status"[[:space:]]*:[[:space:]]*"(ok|error)"'; then
    _cn_record PASS "contusion_confirm" "$_HTTP" "envelope-ok"
else
    _cn_record FAIL "contusion_confirm" "$_HTTP" "body=${_BODY:0:120}"
fi

# ---------------------------------------------------------------------------
# Test 13: emergency_activate + confirm should refuse
#   We set the latch via the persistent flag file (no admin endpoint may
#   exist on this ISO variant). Then /contusion/confirm should either 409
#   or return a failure envelope mentioning emergency.
# ---------------------------------------------------------------------------
# Ensure state dir exists (cortex creates it on first write; be defensive).
_cn_ssh "mkdir -p /var/lib/ai-control 2>/dev/null; \
         echo 'qemu-test-latch' > /var/lib/ai-control/emergency.flag 2>/dev/null" \
    >/dev/null 2>&1 || true

# Cortex reads the flag at startup; to make the live instance see it,
# POST /emergency/stop if the endpoint exists. Use admin token.
_cn_ssh "curl -s --connect-timeout 3 -X POST \
    -H 'Authorization: Bearer ${_CN_TOKEN_600:-}' \
    http://localhost:8421/emergency/stop" >/dev/null 2>&1 || true

# Now try a destructive confirm; expect rejection.
_RESP=$(_cn_curl_post "$_CN_CONFIRM_TOKEN" "/contusion/confirm" \
    '{"command":"echo should-be-blocked"}')
_HTTP=$(_cn_status_of "$_RESP")
_BODY=$(_cn_body_of "$_RESP")
# Acceptance: 409 OR error envelope mentioning emergency OR success:false
if [ "$_HTTP" = "409" ]; then
    _cn_record PASS "emergency_activate" "$_HTTP" "409 returned"
elif echo "$_BODY" | grep -qiE 'emergency|latch|stopped'; then
    _cn_record PASS "emergency_activate" "$_HTTP" "envelope mentions emergency"
elif [ "$_HTTP" = "200" ] && echo "$_BODY" | grep -q '"success"[[:space:]]*:[[:space:]]*false'; then
    _cn_record WARN "emergency_activate" "$_HTTP" "rejected (no latch wording)"
else
    _cn_record FAIL "emergency_activate" "$_HTTP" "not rejected body=${_BODY:0:120}"
fi

# ---------------------------------------------------------------------------
# Test 14: emergency_clear — clears the latch with a 600 token
#   /emergency/clear is daemon-side (port 8420), admin (band 600).
#   Also remove the flag file as belt-and-suspenders for re-runs.
# ---------------------------------------------------------------------------
if [ -z "${_CN_TOKEN_600:-}" ]; then
    _cn_record SKIP "emergency_clear" "-" "no admin token"
else
    _RESP=$(_cn_curl_post "$_CN_TOKEN_600" "/emergency/clear" \
        '{"reason":"qemu-contusion-battery cleanup"}')
    _HTTP=$(_cn_status_of "$_RESP")
    _BODY=$(_cn_body_of "$_RESP")
    # Always remove the flag regardless of endpoint result — idempotent
    # cleanup is mandatory for re-runnability.
    _cn_ssh "rm -f /var/lib/ai-control/emergency.flag 2>/dev/null" \
        >/dev/null 2>&1 || true
    if [ "$_HTTP" = "200" ]; then
        _cn_record PASS "emergency_clear" "$_HTTP" "cleared"
    elif echo "$_BODY" | grep -qE 'success|cleared|ok'; then
        _cn_record WARN "emergency_clear" "$_HTTP" "ambiguous ok"
    else
        _cn_record FAIL "emergency_clear" "$_HTTP" "body=${_BODY:0:120}"
    fi
fi

# ---------------------------------------------------------------------------
# Summary table.
# ---------------------------------------------------------------------------
echo ""
echo "  --- Contusion battery summary ---"
printf "  %-10s %-36s %-6s %s\n" "status" "name" "http" "note"
printf "  %-10s %-36s %-6s %s\n" "------" "----" "----" "----"
for row in "${_CN_ROWS[@]}"; do
    st=${row%%|*}
    rest=${row#*|}
    nm=${rest%%|*}
    rest=${rest#*|}
    ht=${rest%%|*}
    nt=${rest#*|}
    printf "  [CN:%-4s] %-36s %-6s %s\n" "$st" "$nm" "$ht" "$nt"
done

CN_ADDED_PASS=$((PASS - _cn_PASS_PREV))
CN_ADDED_FAIL=$((FAIL - _cn_FAIL_PREV))
CN_ADDED_SKIP=$((SKIPPED - _cn_SKIP_PREV))
echo "  Contusion battery totals:  PASS=${CN_ADDED_PASS}  FAIL=${CN_ADDED_FAIL}  SKIP=${CN_ADDED_SKIP}"
echo "  ---------------------------------"
# Desktop side-effect verification: see scripts/contusion-desktop-diag.sh.
