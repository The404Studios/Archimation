#!/bin/bash
# ai-arch/gamescope-launch.sh -- compositor-bypass wrapper for PE launches.
#
# Runs /usr/bin/peloader inside gamescope's nested compositor so the game
# sees a guaranteed MAILBOX/IMMEDIATE path to the outer display, bypassing
# any xfwm4/hyprland sync-to-vblank policy.
#
# INVOCATION:
#   gamescope-launch.sh /path/to/game.exe [args...]
#
# ENV INPUTS (read-only; set by pe-launch-wrapper.sh):
#   COHERENCE_NO_GAMESCOPE=1  -- user opt-out (fall back to caller)
#   GAMESCOPE_OUTPUT_W / GAMESCOPE_OUTPUT_H -- explicit output size
#   GAMESCOPE_FULLSCREEN=1    -- request borderless (default)
#   GAMESCOPE_HDR=1           -- enable HDR output (if supported)
#
# DEPENDENCIES: gamescope (mandatory), xdpyinfo or wlr-randr (for auto-
# size).  Missing gamescope is treated as configuration error -- the
# caller (pe-launch-wrapper.sh) guarantees HW tier NEW/MID before us.

set -u

TARGET_EXE="${1:-}"
if [ -z "$TARGET_EXE" ]; then
    echo "gamescope-launch: no target executable given" >&2
    exit 2
fi
shift || true

LOG_DIR=/var/log/ai-arch
mkdir -p "$LOG_DIR" 2>/dev/null

log() {
    printf '[%s] gamescope-launch: %s\n' "$(date -Iseconds 2>/dev/null)" "$*" \
        >> "$LOG_DIR/pe-launch.log" 2>/dev/null
}

# --- Early bail: explicit opt-out -----------------------------------------
if [ "${COHERENCE_NO_GAMESCOPE:-0}" = "1" ]; then
    log "opt-out via COHERENCE_NO_GAMESCOPE; exec peloader directly"
    PELOADER=/usr/bin/peloader
    [ -x "$PELOADER" ] || PELOADER=$(command -v peloader 2>/dev/null || echo /usr/bin/peloader)
    exec "$PELOADER" "$TARGET_EXE" "$@"
fi

# --- Locate gamescope -----------------------------------------------------
GAMESCOPE_BIN=$(command -v gamescope 2>/dev/null)
if [ -z "$GAMESCOPE_BIN" ]; then
    log "gamescope binary not found; falling back to direct peloader exec"
    PELOADER=/usr/bin/peloader
    [ -x "$PELOADER" ] || PELOADER=$(command -v peloader 2>/dev/null || echo /usr/bin/peloader)
    exec "$PELOADER" "$TARGET_EXE" "$@"
fi

# --- Detect output resolution --------------------------------------------
# Priority: explicit env -> xdpyinfo (X11) -> wlr-randr (wlroots) ->
# /sys/class/drm connector modes -> 1920x1080 default.
OUT_W="${GAMESCOPE_OUTPUT_W:-0}"
OUT_H="${GAMESCOPE_OUTPUT_H:-0}"

detect_xdpy() {
    command -v xdpyinfo >/dev/null 2>&1 || return 1
    [ -n "${DISPLAY:-}" ] || return 1
    local line w h
    line=$(xdpyinfo 2>/dev/null | awk '/dimensions:/ {print $2; exit}')
    [ -z "$line" ] && return 1
    w="${line%x*}"
    h="${line#*x}"
    # h may still contain "1080 pixels"; strip non-digits.
    h="${h%% *}"
    case "$w" in *[!0-9]*|"") return 1 ;; esac
    case "$h" in *[!0-9]*|"") return 1 ;; esac
    OUT_W="$w"; OUT_H="$h"
    return 0
}

detect_wlrrandr() {
    command -v wlr-randr >/dev/null 2>&1 || return 1
    [ -n "${WAYLAND_DISPLAY:-}" ] || return 1
    local line w h
    # Pick the first enabled output's current mode (marked "current").
    line=$(wlr-randr 2>/dev/null | awk '/current/ {print $1; exit}')
    [ -z "$line" ] && return 1
    w="${line%x*}"
    h="${line#*x}"
    h="${h%%px*}"
    case "$w" in *[!0-9]*|"") return 1 ;; esac
    case "$h" in *[!0-9]*|"") return 1 ;; esac
    OUT_W="$w"; OUT_H="$h"
    return 0
}

detect_sysfs_mode() {
    local f mode w h
    for f in /sys/class/drm/card*-*/modes; do
        [ -r "$f" ] || continue
        mode=$(head -1 "$f" 2>/dev/null)
        [ -z "$mode" ] && continue
        w="${mode%x*}"
        h="${mode#*x}"
        case "$w" in *[!0-9]*|"") continue ;; esac
        case "$h" in *[!0-9]*|"") continue ;; esac
        OUT_W="$w"; OUT_H="$h"
        return 0
    done
    return 1
}

if [ "$OUT_W" = "0" ] || [ "$OUT_H" = "0" ]; then
    detect_xdpy || detect_wlrrandr || detect_sysfs_mode || {
        OUT_W=1920
        OUT_H=1080
    }
fi
log "output resolution: ${OUT_W}x${OUT_H}"

# --- Check DRM-direct allowlist ------------------------------------------
# If the primary GPU is on the allowlist, request --drm-backend for
# minimum-latency scan-out.  Otherwise run nested (wayland/X11).
ALLOWLIST=/usr/lib/ai-arch/drm-direct-allowlist.txt
USE_DRM_BACKEND=0

probe_gpu_allowlisted() {
    [ -r "$ALLOWLIST" ] || return 1
    local vend dev
    # Pick the boot_vga if set, else card0.
    local sysdir=""
    for s in /sys/class/drm/card[0-9]*; do
        [ -d "$s/device" ] || continue
        if [ "$(cat "$s/device/boot_vga" 2>/dev/null)" = "1" ]; then
            sysdir="$s/device"
            break
        fi
        [ -z "$sysdir" ] && sysdir="$s/device"
    done
    [ -z "$sysdir" ] && return 1
    vend=$(tr -d '\n' < "$sysdir/vendor" 2>/dev/null)
    dev=$(tr -d '\n' < "$sysdir/device" 2>/dev/null)
    [ -z "$vend" ] || [ -z "$dev" ] && return 1
    vend=$(printf '%s' "$vend" | tr 'A-Z' 'a-z')
    dev=$(printf '%s' "$dev" | tr 'A-Z' 'a-z')
    # Match against allowlist (ignore comments, whitespace-tolerant).
    local v d
    while read -r v d _; do
        case "$v" in ''|\#*) continue ;; esac
        v=$(printf '%s' "$v" | tr 'A-Z' 'a-z')
        d=$(printf '%s' "$d" | tr 'A-Z' 'a-z')
        if [ "$v" = "$vend" ] && [ "$d" = "$dev" ]; then
            return 0
        fi
    done < "$ALLOWLIST"
    return 1
}

if probe_gpu_allowlisted; then
    USE_DRM_BACKEND=1
    log "GPU is on drm-direct allowlist; using --backend drm"
else
    log "GPU not in drm-direct allowlist; using nested backend"
fi

# --- Assemble gamescope args ---------------------------------------------
# Flags chosen:
#   --rt               -- SCHED_FIFO real-time priority for gamescope itself
#                          (reduces compositor jitter under load)
#   --immediate-flips  -- skip the spare frame buffer; flip as soon as GPU
#                          finishes.  Equivalent to forcing IMMEDIATE at
#                          the outer surface; our layer still asks MAILBOX
#                          inside, so the game renders unthrottled while
#                          the presenter shows the freshest completed frame.
#   --adaptive-sync    -- FreeSync/G-Sync (VRR) on supported displays.
#                          Silently ignored on displays that don't support.
#   -W / -H            -- output extent matched to the real display so we
#                          don't scale twice.
#   -f                 -- fullscreen.
#   --expose-wayland   -- publish XDG_SESSION_TYPE=wayland inside so DXVK
#                          picks VK_KHR_wayland_surface (better than X11).
GS_ARGS=(
    --rt
    --immediate-flips
    --adaptive-sync
    -W "$OUT_W"
    -H "$OUT_H"
    --output-width  "$OUT_W"
    --output-height "$OUT_H"
    --expose-wayland
)

if [ "${GAMESCOPE_FULLSCREEN:-1}" = "1" ]; then
    GS_ARGS+=( -f )
fi

if [ "${GAMESCOPE_HDR:-0}" = "1" ]; then
    GS_ARGS+=( --hdr-enabled )
fi

if [ "$USE_DRM_BACKEND" = "1" ]; then
    GS_ARGS+=( --backend drm )
fi

# --- Locate peloader ------------------------------------------------------
PELOADER=/usr/bin/peloader
[ -x "$PELOADER" ] || PELOADER=$(command -v peloader 2>/dev/null || echo /usr/bin/peloader)
if [ ! -x "$PELOADER" ]; then
    log "peloader not executable: $PELOADER"
    exit 127
fi

# --- Exec ----------------------------------------------------------------
log "exec: $GAMESCOPE_BIN ${GS_ARGS[*]} -- $PELOADER $TARGET_EXE $*"
exec "$GAMESCOPE_BIN" "${GS_ARGS[@]}" -- "$PELOADER" "$TARGET_EXE" "$@"
