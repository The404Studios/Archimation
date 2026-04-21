#!/bin/bash
# contusion-desktop-diag.sh — Contusion desktop side-effect validator.
#
# Headless QEMU smoke tests (scripts/test-qemu-contusion.sh) can only verify
# that the daemon RESPONDS to Contusion phrases — they cannot verify the
# side effect actually happened because there is no audio device, no X
# display, and no window manager in CI.
#
# This script is the real-desktop complement. Run it on the INSTALLED
# system as the `arch` user with X up (or any X session on any Arch
# install that has the AI daemon running). For each check it:
#
#   1. Captures a BEFORE snapshot of the relevant system state.
#   2. POSTs the Contusion phrase to http://127.0.0.1:8420/contusion/context.
#   3. Sleeps 300–500 ms so the handler has time to dispatch to the
#      compositor / audio server / brightness backend.
#   4. Captures an AFTER snapshot and diffs.
#   5. Records PASS / FAIL / SKIP with a short reason.
#
# Categories covered:
#   • audio volume up, down, mute          (wpctl snapshot of sink)
#   • brightness up, down                  (brightnessctl get)
#   • workspace switch                     (wmctrl -d '*' row)
#   • window maximize / minimize           (xdotool + _NET_WM_STATE)
#   • screenshot                           (inotify-free: mtime + file count)
#   • clipboard round-trip                 (xclip -selection clipboard)
#
# Skipped (intentionally):
#   • power actions (lock_screen, suspend, shutdown, reboot) — destructive
#     for the operator running the diag. Documented at the bottom.
#   • media playback control — depends on a playerctl-compatible player
#     already running with media loaded.
#
# Usage:
#   ./scripts/contusion-desktop-diag.sh               # default host/port
#   ./scripts/contusion-desktop-diag.sh --host 127.0.0.1 --port 8420
#   ./scripts/contusion-desktop-diag.sh --verbose     # dump request bodies
#
# Requirements (installer manifest):
#   wmctrl xdotool brightnessctl wireplumber xclip scrot curl jq procps
#   (jq is optional; we grep-fallback on its absence.)
#
# Idempotent: pre-captures volume and brightness at start, restores them
# unconditionally in an EXIT trap. Safe to re-run.

set -uo pipefail    # NOTE: no -e — we want every test to run.

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
HOST="127.0.0.1"
PORT="8420"
VERBOSE=0
SETTLE_MS=400

while [ "$#" -gt 0 ]; do
    case "$1" in
        --host)    HOST="${2:-127.0.0.1}"; shift 2 ;;
        --port)    PORT="${2:-8420}";      shift 2 ;;
        --verbose) VERBOSE=1;              shift ;;
        -h|--help)
            sed -n '1,60p' "$0"
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

BASE="http://${HOST}:${PORT}"

# ---------------------------------------------------------------------------
# Counters + result table
# ---------------------------------------------------------------------------
PASS=0
FAIL=0
SKIP=0
declare -a ROWS=()

_record() {
    local status="$1"   # PASS | FAIL | SKIP
    local name="$2"
    local note="$3"
    ROWS+=("${status}|${name}|${note}")
    case "$status" in
        PASS) PASS=$((PASS + 1)) ;;
        FAIL) FAIL=$((FAIL + 1)) ;;
        SKIP) SKIP=$((SKIP + 1)) ;;
    esac
    printf "  [%-4s] %-36s %s\n" "$status" "$name" "$note"
}

_settle() {
    # sleep SETTLE_MS milliseconds. Coreutils sleep accepts fractional seconds.
    local ms="${1:-$SETTLE_MS}"
    local s
    s=$(awk -v ms="$ms" 'BEGIN { printf "%.3f", ms/1000.0 }')
    sleep "$s"
}

_have() { command -v "$1" >/dev/null 2>&1; }

_dbg() {
    [ "$VERBOSE" -eq 1 ] && echo "    # $*"
    return 0
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
echo "========================================"
echo "  CONTUSION DESKTOP SIDE-EFFECT DIAG"
echo "========================================"
echo "  daemon: $BASE"
echo "  DISPLAY=${DISPLAY:-<unset>}"
echo "  user:   $(id -un)  uid=$(id -u)"
echo ""

if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    _record SKIP "pre-flight: X/Wayland" "no DISPLAY/WAYLAND_DISPLAY — aborting"
    echo ""
    echo "This tool must run inside a graphical session. Log in on the XFCE"
    echo "desktop (or any X/Wayland session) and run it again."
    exit 2
fi

# Require the daemon is reachable.
if ! curl -s --connect-timeout 3 "${BASE}/health" | grep -q '"status"'; then
    _record SKIP "pre-flight: daemon" "${BASE}/health unreachable"
    echo ""
    echo "Start the AI daemon first: systemctl start ai-control"
    exit 2
fi
_record PASS "pre-flight: daemon" "${BASE}/health ok"

# Soft dependency audit — missing tools only skip the tests that need them.
for t in curl wmctrl xdotool brightnessctl wpctl xclip scrot xprop; do
    if _have "$t"; then
        _dbg "found: $t"
    else
        echo "  [WARN] missing optional tool: $t (tests that need it will SKIP)"
    fi
done

# ---------------------------------------------------------------------------
# Auth: mint a trust-400 token (context), trust-600 (confirm — unused here
# but kept for symmetry with the pytest/qemu batteries).
# ---------------------------------------------------------------------------
_mint_token() {
    local trust="$1"
    local name="desktop-diag-${trust}"
    curl -s --connect-timeout 5 \
        -X POST "${BASE}/auth/token" \
        -H 'Content-Type: application/json' \
        -d "{\"subject_id\": 1, \"name\": \"${name}\", \"trust_level\": ${trust}, \"ttl\": 600}" \
        2>/dev/null \
        | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

TOKEN_400="$(_mint_token 400)"
TOKEN_600="$(_mint_token 600)"
if [ -z "$TOKEN_400" ]; then
    _record FAIL "auth: mint trust-400" "no token (daemon auth broken?)"
    echo "cannot proceed without a token"
    exit 1
fi
_record PASS "auth: mint trust-400" "len=${#TOKEN_400}"
[ -n "$TOKEN_600" ] && _record PASS "auth: mint trust-600" "len=${#TOKEN_600}" \
                    || _record SKIP "auth: mint trust-600" "skipped (confirm not exercised)"

# ---------------------------------------------------------------------------
# Token revocation on exit (best effort — /auth/revoke may not exist; we
# also let the TTL expire in 10 minutes).
# ---------------------------------------------------------------------------
_cleanup_token() {
    local tok="$1"
    [ -z "$tok" ] && return 0
    curl -s --connect-timeout 2 \
        -X POST "${BASE}/auth/revoke" \
        -H "Authorization: Bearer ${tok}" \
        -H 'Content-Type: application/json' \
        -d '{}' >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# State-capture helpers: return pre-change snapshots to restore on exit.
# ---------------------------------------------------------------------------
ORIG_VOL=""
ORIG_BRIGHT=""

_capture_volume_pct() {
    # wpctl get-volume @DEFAULT_AUDIO_SINK@  ->  "Volume: 0.45 [MUTED]"
    _have wpctl || { echo ""; return; }
    wpctl get-volume @DEFAULT_AUDIO_SINK@ 2>/dev/null \
        | sed -n 's/.*Volume:[[:space:]]*\([0-9.]*\).*/\1/p' \
        | head -1
}

_capture_volume_muted() {
    _have wpctl || { echo "0"; return; }
    if wpctl get-volume @DEFAULT_AUDIO_SINK@ 2>/dev/null | grep -q MUTED; then
        echo "1"
    else
        echo "0"
    fi
}

_capture_brightness() {
    _have brightnessctl || { echo ""; return; }
    brightnessctl get 2>/dev/null | head -1
}

_capture_workspace() {
    # Line marked '*' in wmctrl -d is the active workspace.
    _have wmctrl || { echo ""; return; }
    wmctrl -d 2>/dev/null | awk '/\*/ {print $1; exit}'
}

_capture_active_window_state() {
    # _NET_WM_STATE atoms on the focused window.
    if ! _have xdotool || ! _have xprop; then echo ""; return; fi
    local wid
    wid=$(xdotool getactivewindow 2>/dev/null || true)
    [ -z "$wid" ] && { echo ""; return; }
    # xprop prints e.g. "_NET_WM_STATE(ATOM) = _NET_WM_STATE_MAXIMIZED_HORZ, ..."
    xprop -id "$wid" _NET_WM_STATE 2>/dev/null \
        | sed -n 's/.*= *//p'
}

# ---------------------------------------------------------------------------
# Pre-capture baselines for restore. These run once up front.
# ---------------------------------------------------------------------------
ORIG_VOL="$(_capture_volume_pct)"
ORIG_VOL_MUTED="$(_capture_volume_muted)"
ORIG_BRIGHT="$(_capture_brightness)"

_restore_defaults() {
    # Restore volume (best effort).
    if _have wpctl && [ -n "$ORIG_VOL" ]; then
        wpctl set-volume @DEFAULT_AUDIO_SINK@ "$ORIG_VOL" >/dev/null 2>&1 || true
        if [ "$ORIG_VOL_MUTED" = "1" ]; then
            wpctl set-mute @DEFAULT_AUDIO_SINK@ 1 >/dev/null 2>&1 || true
        else
            wpctl set-mute @DEFAULT_AUDIO_SINK@ 0 >/dev/null 2>&1 || true
        fi
        echo "  [restored] volume=${ORIG_VOL} muted=${ORIG_VOL_MUTED}"
    fi
    if _have brightnessctl && [ -n "$ORIG_BRIGHT" ]; then
        brightnessctl set "$ORIG_BRIGHT" >/dev/null 2>&1 || true
        echo "  [restored] brightness=${ORIG_BRIGHT}"
    fi
    _cleanup_token "$TOKEN_400"
    _cleanup_token "$TOKEN_600"
}
trap _restore_defaults EXIT INT TERM

# ---------------------------------------------------------------------------
# POST /contusion/context
# ---------------------------------------------------------------------------
_post_context() {
    local phrase="$1"
    local body
    body=$(curl -s --connect-timeout 5 \
        -X POST "${BASE}/contusion/context" \
        -H 'Content-Type: application/json' \
        -H "Authorization: Bearer ${TOKEN_400}" \
        -d "{\"prompt\": $(printf '%s' "$phrase" | python3 -c 'import sys, json; print(json.dumps(sys.stdin.read()))')}" \
        2>/dev/null)
    _dbg "phrase=\"$phrase\""
    _dbg "response=${body:0:200}"
    printf '%s' "$body"
}

# ---------------------------------------------------------------------------
# TEST: volume up
# ---------------------------------------------------------------------------
if _have wpctl; then
    before="$(_capture_volume_pct)"
    before_mute="$(_capture_volume_muted)"
    # Ensure we aren't pinned at 100% or muted (both would mask the effect).
    if [ "$before_mute" = "1" ]; then
        wpctl set-mute @DEFAULT_AUDIO_SINK@ 0 >/dev/null 2>&1 || true
    fi
    # If already >= 0.90, pre-lower so "up" has room to move.
    if awk -v v="$before" 'BEGIN { exit (v >= 0.90) ? 0 : 1 }'; then
        wpctl set-volume @DEFAULT_AUDIO_SINK@ 0.50 >/dev/null 2>&1 || true
        _settle 150
        before="$(_capture_volume_pct)"
    fi
    _post_context "turn up the volume" >/dev/null
    _settle
    after="$(_capture_volume_pct)"
    if [ -n "$before" ] && [ -n "$after" ] && \
       awk -v a="$after" -v b="$before" 'BEGIN { exit (a > b) ? 0 : 1 }'; then
        _record PASS "audio.volume_up" "${before} -> ${after}"
    else
        _record FAIL "audio.volume_up" "${before} -> ${after} (no increase)"
    fi
else
    _record SKIP "audio.volume_up" "wpctl not installed"
fi

# ---------------------------------------------------------------------------
# TEST: volume down
# ---------------------------------------------------------------------------
if _have wpctl; then
    before="$(_capture_volume_pct)"
    # If already very low, pre-raise.
    if awk -v v="$before" 'BEGIN { exit (v <= 0.10) ? 0 : 1 }'; then
        wpctl set-volume @DEFAULT_AUDIO_SINK@ 0.50 >/dev/null 2>&1 || true
        _settle 150
        before="$(_capture_volume_pct)"
    fi
    _post_context "turn down the volume" >/dev/null
    _settle
    after="$(_capture_volume_pct)"
    if [ -n "$before" ] && [ -n "$after" ] && \
       awk -v a="$after" -v b="$before" 'BEGIN { exit (a < b) ? 0 : 1 }'; then
        _record PASS "audio.volume_down" "${before} -> ${after}"
    else
        _record FAIL "audio.volume_down" "${before} -> ${after} (no decrease)"
    fi
else
    _record SKIP "audio.volume_down" "wpctl not installed"
fi

# ---------------------------------------------------------------------------
# TEST: mute toggle
# ---------------------------------------------------------------------------
if _have wpctl; then
    before="$(_capture_volume_muted)"
    _post_context "mute the audio" >/dev/null
    _settle
    after="$(_capture_volume_muted)"
    if [ "$before" != "$after" ]; then
        _record PASS "audio.mute_toggle" "muted=${before} -> muted=${after}"
    else
        # "mute" on an already-muted sink is a no-op; allow either-direction.
        # Unmute via API and try again.
        wpctl set-mute @DEFAULT_AUDIO_SINK@ 0 >/dev/null 2>&1 || true
        _settle 150
        before2="$(_capture_volume_muted)"
        _post_context "mute the audio" >/dev/null
        _settle
        after2="$(_capture_volume_muted)"
        if [ "$before2" != "$after2" ]; then
            _record PASS "audio.mute_toggle" "(retry) ${before2} -> ${after2}"
        else
            _record FAIL "audio.mute_toggle" "no change across two attempts"
        fi
    fi
    # Leave mute state alone — the trap restores to ORIG_VOL_MUTED anyway.
else
    _record SKIP "audio.mute_toggle" "wpctl not installed"
fi

# ---------------------------------------------------------------------------
# TEST: brightness up
# ---------------------------------------------------------------------------
if _have brightnessctl; then
    before="$(_capture_brightness)"
    max="$(brightnessctl max 2>/dev/null || echo 0)"
    # If at max already, pre-drop.
    if [ -n "$before" ] && [ -n "$max" ] && [ "$max" -gt 0 ] && \
       [ "$before" -ge "$((max * 9 / 10))" ]; then
        brightnessctl set "$((max * 50 / 100))" >/dev/null 2>&1 || true
        _settle 150
        before="$(_capture_brightness)"
    fi
    _post_context "increase brightness" >/dev/null
    _settle
    after="$(_capture_brightness)"
    if [ -n "$before" ] && [ -n "$after" ] && [ "$after" -gt "$before" ]; then
        _record PASS "brightness.up" "${before} -> ${after}"
    else
        _record FAIL "brightness.up" "${before} -> ${after} (no increase)"
    fi
else
    _record SKIP "brightness.up" "brightnessctl not installed"
fi

# ---------------------------------------------------------------------------
# TEST: brightness down
# ---------------------------------------------------------------------------
if _have brightnessctl; then
    before="$(_capture_brightness)"
    # If near 0, pre-raise.
    if [ -n "$before" ] && [ "$before" -le 2 ]; then
        max="$(brightnessctl max 2>/dev/null || echo 100)"
        brightnessctl set "$((max * 50 / 100))" >/dev/null 2>&1 || true
        _settle 150
        before="$(_capture_brightness)"
    fi
    _post_context "decrease brightness" >/dev/null
    _settle
    after="$(_capture_brightness)"
    if [ -n "$before" ] && [ -n "$after" ] && [ "$after" -lt "$before" ]; then
        _record PASS "brightness.down" "${before} -> ${after}"
    else
        _record FAIL "brightness.down" "${before} -> ${after} (no decrease)"
    fi
else
    _record SKIP "brightness.down" "brightnessctl not installed"
fi

# ---------------------------------------------------------------------------
# TEST: workspace switch
# ---------------------------------------------------------------------------
if _have wmctrl; then
    total_ws=$(wmctrl -d 2>/dev/null | wc -l | tr -d ' ')
    if [ "${total_ws:-0}" -lt 2 ]; then
        _record SKIP "workspace.switch" "only ${total_ws:-0} workspace(s) — need >=2"
    else
        before="$(_capture_workspace)"
        target=0
        # Pick a workspace that is NOT current.
        if [ "$before" = "0" ]; then target=1; else target=0; fi
        _post_context "switch to workspace $((target + 1))" >/dev/null
        _settle
        after="$(_capture_workspace)"
        if [ -n "$before" ] && [ -n "$after" ] && [ "$before" != "$after" ]; then
            _record PASS "workspace.switch" "ws${before} -> ws${after}"
        else
            _record FAIL "workspace.switch" "ws${before} -> ws${after} (no change)"
        fi
        # Restore.
        wmctrl -s "$before" >/dev/null 2>&1 || true
    fi
else
    _record SKIP "workspace.switch" "wmctrl not installed"
fi

# ---------------------------------------------------------------------------
# TEST: window maximize
#   We spawn a disposable xterm as the test target so we don't mess with
#   the operator's windows. If no xterm/xmessage, we SKIP.
# ---------------------------------------------------------------------------
_spawn_test_window() {
    # Prefer xterm; fall back to xmessage; fall back to xeyes.
    if _have xterm; then
        xterm -geometry 80x24+100+100 -title "ctn-diag-test" -e "sleep 30" >/dev/null 2>&1 &
        echo "$!"
    elif _have xmessage; then
        xmessage -center -timeout 30 "contusion diag test window" >/dev/null 2>&1 &
        echo "$!"
    elif _have xeyes; then
        xeyes -geometry 200x200+100+100 >/dev/null 2>&1 &
        echo "$!"
    else
        echo ""
    fi
}

TEST_WIN_PID=""
if _have xdotool && _have xprop && _have wmctrl; then
    TEST_WIN_PID="$(_spawn_test_window)"
    if [ -z "$TEST_WIN_PID" ]; then
        _record SKIP "window.maximize" "no xterm/xmessage/xeyes — cannot create test window"
        _record SKIP "window.minimize" "no xterm/xmessage/xeyes — cannot create test window"
    else
        # Wait for the window to actually appear, then focus it.
        _settle 500
        # Find window by title (most reliable).
        TEST_WID="$(xdotool search --name "ctn-diag-test" 2>/dev/null | head -1)"
        if [ -z "$TEST_WID" ]; then
            # xmessage/xeyes fallback — pick the top window of the pid.
            TEST_WID="$(xdotool search --pid "$TEST_WIN_PID" 2>/dev/null | head -1)"
        fi
        if [ -n "$TEST_WID" ]; then
            xdotool windowactivate "$TEST_WID" >/dev/null 2>&1 || true
            _settle 150

            # --- maximize ---
            before="$(_capture_active_window_state)"
            _post_context "maximize this window" >/dev/null
            _settle
            after="$(_capture_active_window_state)"
            if echo "$after" | grep -qi "MAXIMIZED" && \
               ! echo "$before" | grep -qi "MAXIMIZED"; then
                _record PASS "window.maximize" "state ${before:-[]} -> ${after:-[]}"
            elif echo "$before" | grep -qi "MAXIMIZED" && \
                 echo "$after" | grep -qi "MAXIMIZED"; then
                # Already maximized — demote to WARN-style FAIL (inconclusive).
                _record SKIP "window.maximize" "window was already maximized"
            else
                _record FAIL "window.maximize" "state ${before:-[]} -> ${after:-[]}"
            fi

            # --- minimize ---
            # Re-activate in case maximize changed focus.
            xdotool windowactivate "$TEST_WID" >/dev/null 2>&1 || true
            _settle 150
            before="$(_capture_active_window_state)"
            # Record whether the window appears in active-list BEFORE.
            was_visible=$(xdotool search --name "ctn-diag-test" --onlyvisible 2>/dev/null | wc -l | tr -d ' ')
            _post_context "minimize this window" >/dev/null
            _settle
            now_visible=$(xdotool search --name "ctn-diag-test" --onlyvisible 2>/dev/null | wc -l | tr -d ' ')
            after_state="$(xprop -id "$TEST_WID" _NET_WM_STATE 2>/dev/null | sed -n 's/.*= *//p')"
            if echo "$after_state" | grep -qi "HIDDEN" \
               || [ "${now_visible:-0}" -lt "${was_visible:-0}" ]; then
                _record PASS "window.minimize" "visible ${was_visible}->${now_visible} state=${after_state:-[]}"
            else
                _record FAIL "window.minimize" "visible ${was_visible}->${now_visible} state=${after_state:-[]}"
            fi
        else
            _record FAIL "window.maximize" "could not locate spawned test window"
            _record SKIP "window.minimize" "no window to test"
        fi

        # Kill the test window regardless of outcome.
        kill "$TEST_WIN_PID" >/dev/null 2>&1 || true
    fi
else
    _record SKIP "window.maximize" "xdotool+xprop+wmctrl required"
    _record SKIP "window.minimize" "xdotool+xprop+wmctrl required"
fi

# ---------------------------------------------------------------------------
# TEST: screenshot
#   Count files under ~/Pictures (or XDG_PICTURES_DIR) before and after.
# ---------------------------------------------------------------------------
PICDIR="${XDG_PICTURES_DIR:-$HOME/Pictures}"
mkdir -p "$PICDIR" 2>/dev/null || true
if [ -d "$PICDIR" ] && _have scrot; then
    before_count=$(find "$PICDIR" -maxdepth 2 -type f -name '*.png' 2>/dev/null | wc -l | tr -d ' ')
    # mtime-based detection: record current wall clock.
    marker="$(date +%s)"
    _post_context "take a screenshot" >/dev/null
    _settle 800   # screenshots often take longer than other actions
    after_count=$(find "$PICDIR" -maxdepth 2 -type f -name '*.png' 2>/dev/null | wc -l | tr -d ' ')
    # Also check for any .png mtime >= marker.
    fresh=$(find "$PICDIR" -maxdepth 2 -type f -name '*.png' \
            -newermt "@$((marker - 2))" 2>/dev/null | wc -l | tr -d ' ')
    if [ "${after_count:-0}" -gt "${before_count:-0}" ] || [ "${fresh:-0}" -gt 0 ]; then
        _record PASS "screenshot" "${before_count}->${after_count} png (fresh=${fresh})"
    else
        _record FAIL "screenshot" "${before_count}->${after_count} png under ${PICDIR}"
    fi
else
    _record SKIP "screenshot" "scrot missing or ${PICDIR} unavailable"
fi

# ---------------------------------------------------------------------------
# TEST: clipboard round-trip
#   Contusion "copy 'hello-ctn' to clipboard" -> read back via xclip.
# ---------------------------------------------------------------------------
if _have xclip; then
    unique="ctn-diag-$(date +%s)-$$"
    # Pre-clear clipboard to avoid a false positive.
    printf '' | xclip -selection clipboard -in 2>/dev/null || true
    _settle 100
    _post_context "copy '${unique}' to clipboard" >/dev/null
    _settle
    got="$(xclip -selection clipboard -out 2>/dev/null || true)"
    if [ "$got" = "$unique" ]; then
        _record PASS "clipboard.roundtrip" "exact match"
    elif echo "$got" | grep -qF "$unique"; then
        _record PASS "clipboard.roundtrip" "contains token (got='${got:0:60}')"
    else
        _record FAIL "clipboard.roundtrip" "expected='${unique}' got='${got:0:60}'"
    fi
else
    _record SKIP "clipboard.roundtrip" "xclip not installed"
fi

# ---------------------------------------------------------------------------
# Documented skips (intentional)
# ---------------------------------------------------------------------------
_record SKIP "power.lock_screen"    "destructive for operator — not exercised"
_record SKIP "power.suspend"        "destructive for operator — not exercised"
_record SKIP "power.reboot"         "destructive for operator — not exercised"
_record SKIP "power.shutdown"       "destructive for operator — not exercised"
_record SKIP "media.play_pause"     "requires a playerctl-compatible player running"

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
echo ""
echo "  --- Desktop diag summary ---"
printf "  %-6s %-36s %s\n" "status" "test" "note"
printf "  %-6s %-36s %s\n" "------" "----" "----"
for row in "${ROWS[@]}"; do
    st=${row%%|*}
    rest=${row#*|}
    nm=${rest%%|*}
    nt=${rest#*|}
    printf "  [%-4s] %-36s %s\n" "$st" "$nm" "$nt"
done
echo ""
echo "  TOTAL:  PASS=${PASS}  FAIL=${FAIL}  SKIP=${SKIP}"
echo ""

# Exit non-zero iff any FAIL was recorded.
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
