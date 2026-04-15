#!/bin/bash
# ai-arch/power-profile.sh -- governor + EPP + min_perf_pct helper.
#
# Single source of truth for how the AI daemon flips CPU power knobs.
# Called from ai-control-daemon via ``power.py::_run_helper()`` and from
# systemd's ai-power.service on boot.
#
# Subcommands
# -----------
#   init                    Apply the default governor for the current
#                           hw profile (from /run/ai-arch-hw-profile).
#   set <governor>          LEGACY: write <governor> to every CPU's
#                           scaling_governor.  Used only on CPUs lacking
#                           intel_pstate / amd_pstate.
#   epp set <value>         Session 33: write <value> to every CPU's
#                           energy_performance_preference.  Accepts
#                           performance | balance_performance | default |
#                           balance_power | power.
#   minperf set <pct>       Session 33: write <pct> to the active
#                           pstate driver's min_perf_pct.
#   boost on                Session 33 compound helper: EPP=performance
#                           + min_perf_pct=60.  Falls back to
#                           "set performance" if no pstate driver.
#   boost off               Undo "boost on" — restore EPP=default,
#                           min_perf_pct=0 (or the governor saved in
#                           /run/ai-arch-power-baseline, legacy mode).
#   restore                 Short-hand for "init" but preserves the user
#                           override recorded in /run/ai-arch-power-baseline
#                           if present.
#   show                    Print the current governor, EPP, and
#                           min_perf_pct for every CPU / pstate driver.
#
# Exit codes
# ----------
#   0   success
#   1   invalid argument / bad value
#   2   no cpufreq on this kernel
#   3   EPP / pstate not supported on this CPU
#
# Security
# --------
# This script writes to /sys/devices/system/cpu/** which requires root.
# Callers must already be root (either the daemon or systemd's
# ai-power.service).  We do NOT escalate via sudo / pkexec here
# to keep the privilege model simple and auditable.

set -u
set +e

PROFILE_FILE=/run/ai-arch-hw-profile
BASELINE_FILE=/run/ai-arch-power-baseline
EPP_BASELINE_FILE=/run/ai-arch-power-epp-baseline
MINPERF_BASELINE_FILE=/run/ai-arch-power-minperf-baseline

VALID_GOVERNORS="performance powersave ondemand conservative schedutil userspace"
VALID_EPP="performance balance_performance default balance_power power"

PSTATE_INTEL_DIR=/sys/devices/system/cpu/intel_pstate
PSTATE_AMD_DIR=/sys/devices/system/cpu/amd_pstate

PE_MIN_PERF_FLOOR=60
PE_EPP_BOOST=performance

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

# ----- Session 33: EPP + min_perf_pct helpers -----

is_valid_epp() {
    local want=$1
    local e
    for e in $VALID_EPP; do
        [ "$e" = "$want" ] && return 0
    done
    return 1
}

have_epp() {
    # CPU0 exposes the EPP node iff pstate supports EPP.
    [ -e /sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference ]
}

detect_pstate_driver() {
    if [ -d "$PSTATE_INTEL_DIR" ]; then
        echo "intel"
    elif [ -d "$PSTATE_AMD_DIR" ]; then
        echo "amd"
    else
        return 1
    fi
}

write_epp() {
    local value=$1
    local count=0
    local f
    for f in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/energy_performance_preference; do
        [ -w "$f" ] || continue
        printf '%s' "$value" > "$f" 2>/dev/null && count=$((count + 1))
    done
    echo "$count"
}

read_current_epp() {
    local f=/sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference
    [ -r "$f" ] && cat "$f" 2>/dev/null || return 1
}

pstate_minperf_path() {
    local drv
    drv=$(detect_pstate_driver) || return 1
    if [ "$drv" = "intel" ]; then
        echo "$PSTATE_INTEL_DIR/min_perf_pct"
    else
        echo "$PSTATE_AMD_DIR/min_perf_pct"
    fi
}

write_min_perf_pct() {
    local pct=$1
    local path
    path=$(pstate_minperf_path) || return 1
    [ -w "$path" ] || return 1
    printf '%s' "$pct" > "$path" 2>/dev/null
}

read_min_perf_pct() {
    local path
    path=$(pstate_minperf_path) || return 1
    cat "$path" 2>/dev/null
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

# ----- Session 33 verbs: epp / minperf / boost on|off -----

cmd_epp() {
    local verb=${1:-}
    case "$verb" in
        set)
            local value=${2:-}
            if [ -z "$value" ]; then
                echo "epp set: missing value" >&2
                return 1
            fi
            if ! is_valid_epp "$value"; then
                echo "epp set: invalid value '$value' (want one of: $VALID_EPP)" >&2
                return 1
            fi
            if ! have_epp; then
                log "epp set: EPP unsupported on this CPU"
                return 3
            fi
            local n
            n=$(write_epp "$value")
            log "epp set: value=$value cpus=$n"
            [ "$n" -gt 0 ]
            ;;
        get|show|"")
            if ! have_epp; then
                echo "(EPP unsupported)"
                return 3
            fi
            read_current_epp
            ;;
        *)
            echo "epp: unknown verb '$verb' (want set|get)" >&2
            return 1
            ;;
    esac
}

cmd_minperf() {
    local verb=${1:-}
    case "$verb" in
        set)
            local pct=${2:-}
            if [ -z "$pct" ]; then
                echo "minperf set: missing percentage" >&2
                return 1
            fi
            case "$pct" in ''|*[!0-9]*)
                echo "minperf set: non-numeric '$pct'" >&2
                return 1
                ;;
            esac
            if [ "$pct" -lt 0 ] || [ "$pct" -gt 100 ]; then
                echo "minperf set: out of range '$pct'" >&2
                return 1
            fi
            if ! detect_pstate_driver >/dev/null; then
                log "minperf set: no pstate driver loaded"
                return 3
            fi
            if write_min_perf_pct "$pct"; then
                log "minperf set: pct=$pct driver=$(detect_pstate_driver)"
                return 0
            fi
            log "minperf set: failed to write min_perf_pct"
            return 1
            ;;
        get|show|"")
            if ! detect_pstate_driver >/dev/null; then
                echo "(no pstate driver)"
                return 3
            fi
            read_min_perf_pct
            ;;
        *)
            echo "minperf: unknown verb '$verb' (want set|get)" >&2
            return 1
            ;;
    esac
}

# boost on  -> EPP=performance + min_perf_pct=60 (fallback: governor=performance)
# boost off -> restore EPP=default + min_perf_pct=0 (fallback: cmd_restore)
cmd_boost() {
    local verb=${1:-on}
    case "$verb" in
        on)
            if have_epp && detect_pstate_driver >/dev/null; then
                cmd_epp set "$PE_EPP_BOOST" || true
                cmd_minperf set "$PE_MIN_PERF_FLOOR" || true
                log "boost on: EPP=$PE_EPP_BOOST min_perf_pct=$PE_MIN_PERF_FLOOR"
                return 0
            fi
            # Legacy fallback: flip governor to performance.
            log "boost on: legacy fallback (no pstate/EPP), governor=performance"
            cmd_set performance
            ;;
        off)
            if have_epp && detect_pstate_driver >/dev/null; then
                local saved_epp="default"
                local saved_min="0"
                [ -r "$EPP_BASELINE_FILE" ] && saved_epp=$(cat "$EPP_BASELINE_FILE" 2>/dev/null)
                [ -r "$MINPERF_BASELINE_FILE" ] && saved_min=$(cat "$MINPERF_BASELINE_FILE" 2>/dev/null)
                [ -z "$saved_epp" ] && saved_epp="default"
                [ -z "$saved_min" ] && saved_min="0"
                cmd_epp set "$saved_epp" || true
                cmd_minperf set "$saved_min" || true
                log "boost off: EPP=$saved_epp min_perf_pct=$saved_min"
                return 0
            fi
            log "boost off: legacy fallback, restoring governor"
            cmd_restore
            ;;
        *)
            echo "boost: want on|off, got '$verb'" >&2
            return 1
            ;;
    esac
}

cmd_restore() { cmd_init; }

cmd_show() {
    local f gov
    for f in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do
        [ -r "$f" ] || continue
        gov=$(cat "$f" 2>/dev/null)
        echo "$(basename "$(dirname "$(dirname "$f")")")=$gov"
    done
    if have_epp; then
        echo "epp=$(read_current_epp)"
    fi
    if detect_pstate_driver >/dev/null; then
        echo "pstate_driver=$(detect_pstate_driver)"
        echo "min_perf_pct=$(read_min_perf_pct)"
    fi
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

    # Also snapshot EPP + min_perf_pct when available so `boost off`
    # can restore to the pre-boost baseline.
    if have_epp; then
        local epp
        epp=$(read_current_epp 2>/dev/null || true)
        [ -n "$epp" ] && printf '%s\n' "$epp" > "$EPP_BASELINE_FILE" 2>/dev/null
    fi
    if detect_pstate_driver >/dev/null; then
        local pct
        pct=$(read_min_perf_pct 2>/dev/null || true)
        [ -n "$pct" ] && printf '%s\n' "$pct" > "$MINPERF_BASELINE_FILE" 2>/dev/null
    fi
}

main() {
    local sub=${1:-init}
    shift 2>/dev/null || true
    case "$sub" in
        init)          cmd_init "$@" ;;
        set)           cmd_set "$@" ;;
        epp)           cmd_epp "$@" ;;
        minperf)       cmd_minperf "$@" ;;
        boost)         cmd_boost "$@" ;;
        restore)       cmd_restore ;;
        show)          cmd_show ;;
        save-baseline) cmd_save_baseline "$@" ;;
        *)
            echo "usage: $0 {init | set <gov> | epp set <value> | minperf set <pct> |" >&2
            echo "             boost on|off | restore | show | save-baseline [gov]}" >&2
            return 1
            ;;
    esac
}

main "$@"
exit $?
