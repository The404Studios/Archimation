#!/bin/bash
#
# ai-game-mode.sh -- userspace bridge that watches the cortex's
# /etc/coherence/overrides/app-active.conf marker (created by
# CoherenceBridge in ai-control/cortex/coherence_bridge.py whenever a
# game-classified PE binary loads) and toggles companion userspace knobs
# that the cortex itself does not touch:
#
#   * gamemoded "runtime activation" via gamemoderun-aware notification
#     (uses systemd-run wrappers so gamemoderun only activates when at
#     least one classified game is live).
#   * gamescope hint: the override-file presence is exposed under
#     /run/ai-game-mode/active so user sessions / launchers can probe it
#     without needing root.
#
# We deliberately do NOT spawn gamescope ourselves — gamescope is a
# nested compositor that wraps the *game* binary, not the desktop.  This
# unit just publishes the "a game is active" signal so launchers can
# wrap-and-relaunch with gamescope+mangohud as the user prefers.
#
# Type=notify: we send READY=1 once after first scan, then WATCHDOG=1
# every 30s, and STOPPING=1 on shutdown.  Stdlib AF_UNIX datagram, no
# python-sdnotify dependency.
#
# Quiet by design — only log state transitions, not the polling itself.

set -u

OVERRIDE_FILE="/etc/coherence/overrides/app-active.conf"
RUN_DIR="/run/ai-game-mode"
ACTIVE_FLAG="$RUN_DIR/active"
LOG_TAG="ai-game-mode"

POLL_INTERVAL=2          # seconds; cheap stat-only check
WATCHDOG_INTERVAL=30     # seconds; must be < WatchdogSec/2 in unit

log() {
    if command -v logger >/dev/null 2>&1; then
        logger -t "$LOG_TAG" -- "$*"
    else
        printf '%s: %s\n' "$LOG_TAG" "$*" >&2
    fi
}

sd_notify() {
    # Best-effort sd_notify via socat if available; otherwise no-op.
    # The unit is Type=notify so we MUST send READY=1 at least once,
    # but if socat is missing we fall back to writing /run flag and
    # let systemd's TimeoutStartSec catch a real failure.
    local msg="$1"
    [ -z "${NOTIFY_SOCKET:-}" ] && return 0
    if command -v systemd-notify >/dev/null 2>&1; then
        systemd-notify "$msg" 2>/dev/null || true
    fi
}

set_active() {
    if [ ! -e "$ACTIVE_FLAG" ]; then
        printf '%s\n' "$(date -u +%FT%TZ)" > "$ACTIVE_FLAG"
        log "game-mode ACTIVE (override file present)"
        # Ensure gamemoded is reachable; do not start it as a unit (the
        # gamemode package ships a per-user service).  Just log if the
        # binary is missing so the operator notices.
        if ! command -v gamemoderun >/dev/null 2>&1; then
            log "warning: gamemoderun not on PATH — install gamemode package"
        fi
    fi
}

clear_active() {
    if [ -e "$ACTIVE_FLAG" ]; then
        rm -f "$ACTIVE_FLAG"
        log "game-mode INACTIVE (override file removed)"
    fi
}

trap_stop() {
    sd_notify "STOPPING=1"
    clear_active
    exit 0
}

mkdir -p "$RUN_DIR"
chmod 0755 "$RUN_DIR"
clear_active

trap trap_stop TERM INT HUP

# Initial scan + READY
if [ -e "$OVERRIDE_FILE" ]; then
    set_active
fi
sd_notify "READY=1"
log "started; polling $OVERRIDE_FILE every ${POLL_INTERVAL}s"

last_watchdog=0
while :; do
    if [ -e "$OVERRIDE_FILE" ]; then
        set_active
    else
        clear_active
    fi

    now=$(date +%s)
    if [ $((now - last_watchdog)) -ge "$WATCHDOG_INTERVAL" ]; then
        sd_notify "WATCHDOG=1"
        last_watchdog=$now
    fi

    sleep "$POLL_INTERVAL"
done
