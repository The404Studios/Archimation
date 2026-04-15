#!/bin/bash
# ai-arch/power-profile.sh -- governor switcher + power profile helper.
#
# Single source of truth for how the AI daemon flips the CPU governor.
# Called from ai-control-daemon via ``power.py::_run_helper()`` and from
# systemd's ai-power.service on boot.
#
# Subcommands
# -----------
#   init                    Apply the default governor for the current
#                           hw profile (from /run/ai-arch-hw-profile).
#   set <governor>          Write <governor> to every CPU's
#                           scaling_governor, where <governor> is one of
#                           performance|powersave|ondemand|conservative|
#                           schedutil|userspace.
#   boost                   Short-hand for "set performance".
#   restore                 Short-hand for "init" but preserves the user
#                           override recorded in /run/ai-arch-power-baseline
#                           if present.
#   show                    Print the current governor for every CPU.
#
# Exit codes
# ----------
#   0   success
#   1   invalid argument / bad governor
#   2   no cpufreq on this kernel
#
# Security
# --------
# This script writes to /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
# which requires root.  Callers must already be root (either the daemon or
# systemd's ai-power.service).  We do NOT escalate via sudo / pkexec here
# to keep the privilege model simple and auditable.

set -u
set +e

PROFILE_FILE=/run/ai-arch-hw-profile
BASELINE_FILE=/run/ai-arch-power-baseline

VALID_GOVERNORS="performance powersave ondemand conservative schedutil userspace"

log() {
    # Prefer systemd-cat so messages land in the journal with a clean tag.
    if command -v systemd-cat >/dev/null 2>&1; then
        echo "$*" | systemd-cat -t ai-power-profile
    else
        echo "ai-power-profile: $*" >&2
    fi
}

have_cpufreq() {
    [ -d /sys/devices/system/cpu/cpu0/cpufreq ]
}

available_governors() {
    local f=/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors
    [ -r "$f" ] && cat "$f" 2>/dev/null || return 1
}

is_valid_governor() {
    local want=$1
    local g
    for g in $VALID_GOVERNORS; do
        [ "$g" = "$want" ] && return 0
    done
    return 1
}

is_kernel_supported_governor() {
    local want=$1
    local avail
    avail=$(available_governors 2>/dev/null) || return 0  # permit if we can't tell
    for g in $avail; do
        [ "$g" = "$want" ] && return 0
    done
    return 1
}

write_governor() {
    local gov=$1
    local count=0
    local f
    for f in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do
        [ -w "$f" ] || continue
        printf '%s' "$gov" > "$f" 2>/dev/null && count=$((count + 1))
    done
    echo "$count"
}

read_profile_governor() {
    # Map PROFILE=OLD|NEW|DEFAULT from /run/ai-arch-hw-profile to a governor.
    local profile="DEFAULT"
    if [ -r "$PROFILE_FILE" ]; then
        profile=$(awk -F= '/^PROFILE=/{print $2; exit}' "$PROFILE_FILE" 2>/dev/null)
        [ -z "$profile" ] && profile="DEFAULT"
    fi
    case "$profile" in
        OLD)    echo "ondemand" ;;
        NEW)    echo "schedutil" ;;
        *)      echo "schedutil" ;;
    esac
}

cmd_init() {
    if ! have_cpufreq; then
        log "no cpufreq on this kernel"
        return 2
    fi
    local gov
    # A user-saved baseline takes precedence over the profile default.
    if [ -r "$BASELINE_FILE" ]; then
        gov=$(cat "$BASELINE_FILE" 2>/dev/null)
    fi
    [ -z "${gov:-}" ] && gov=$(read_profile_governor)
    if ! is_kernel_supported_governor "$gov"; then
        log "init: governor $gov unsupported by kernel; falling back to schedutil"
        gov="schedutil"
    fi
    local n
    n=$(write_governor "$gov")
    log "init: governor=$gov cpus=$n"
    return 0
}

cmd_set() {
    local gov=${1:-}
    if [ -z "$gov" ]; then
        echo "set: missing governor" >&2
        return 1
    fi
    if ! is_valid_governor "$gov"; then
        echo "set: invalid governor '$gov'" >&2
        return 1
    fi
    if ! have_cpufreq; then
        log "set: no cpufreq on this kernel"
        return 2
    fi
    if ! is_kernel_supported_governor "$gov"; then
        log "set: governor $gov unsupported by kernel (avail=$(available_governors 2>/dev/null))"
        return 1
    fi
    local n
    n=$(write_governor "$gov")
    log "set: governor=$gov cpus=$n"
    [ "$n" -gt 0 ]
}

cmd_boost() { cmd_set performance; }

cmd_restore() { cmd_init; }

cmd_show() {
    local f gov
    for f in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do
        [ -r "$f" ] || continue
        gov=$(cat "$f" 2>/dev/null)
        echo "$(basename "$(dirname "$(dirname "$f")")")=$gov"
    done
}

cmd_save_baseline() {
    local gov=${1:-}
    if [ -z "$gov" ]; then
        # Snapshot whatever's currently active on cpu0.
        gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || true)
    fi
    [ -z "$gov" ] && return 1
    mkdir -p /run
    printf '%s\n' "$gov" > "$BASELINE_FILE" 2>/dev/null
}

main() {
    local sub=${1:-init}
    shift 2>/dev/null || true
    case "$sub" in
        init)          cmd_init "$@" ;;
        set)           cmd_set "$@" ;;
        boost)         cmd_boost ;;
        restore)       cmd_restore ;;
        show)          cmd_show ;;
        save-baseline) cmd_save_baseline "$@" ;;
        *)
            echo "usage: $0 {init|set <gov>|boost|restore|show|save-baseline [gov]}" >&2
            return 1
            ;;
    esac
}

main "$@"
exit $?
