#!/bin/bash
# ai-arch/pe-launch-wrapper.sh -- environment fixup shim for PE executables.
#
# Invoked either:
#   (a) from binfmt_misc (replace /usr/bin/peloader with this wrapper), OR
#   (b) directly from the AI daemon / Whisker menu as:
#         /usr/lib/ai-arch/pe-launch-wrapper.sh /path/to/game.exe [args...]
#
# What it does on launch:
#   1. Sources /etc/profile, /run/ai-arch/gpu-env.sh so DXVK/VKD3D env is set.
#   2. Reads /run/ai-arch-gpu-profile to decide per-game tuning (async off
#      on GT218, memory cap on 1 GB systems, VKD3D DXR only on RTX/RDNA2+).
#   3. Disables compositor vsync during play (xfwm4 `/general/use_compositing`
#      -> false, Hyprland `misc:vrr` -> 2) and restores on exit via trap.
#   4. Copies /usr/share/dxvk-conf/<basename>.conf next to the exe if present
#      (per-app DXVK tweaks — e.g., deadlock fix for "The Witcher 3.exe").
#   5. exec's /usr/bin/peloader with the chosen env.
#
# IDEMPOTENT + SAFE: every compositor tweak is guarded with a trap so a
# crashed game leaves the desktop in a healthy state.

set -u

# --- Locate the target exe --------------------------------------------
TARGET_EXE="${1:-}"
if [ -z "$TARGET_EXE" ]; then
    echo "pe-launch-wrapper: no target executable given" >&2
    exit 2
fi
shift || true

# --- Source environment (profile.d + GPU probe output) ---------------
# profile may already be loaded if called from bash login shell; re-sourcing
# is idempotent.
if [ -r /etc/profile ]; then
    # shellcheck disable=SC1091
    . /etc/profile 2>/dev/null || true
fi
if [ -r /run/ai-arch/gpu-env.sh ]; then
    # shellcheck disable=SC1091
    . /run/ai-arch/gpu-env.sh 2>/dev/null || true
fi

# --- Read GPU profile -------------------------------------------------
GPU_PROFILE=DEFAULT
GPU_VENDOR=unknown
GPU_ARCH=unknown
DXVK_ASYNC=0
DXVK_STATE_CACHE=1
if [ -r /run/ai-arch-gpu-profile ]; then
    # shellcheck disable=SC1091
    . /run/ai-arch-gpu-profile 2>/dev/null || true
fi

# --- Per-app config overlay -------------------------------------------
# DXVK reads <exe>.dxvk.conf next to the binary.  We ship tweaks in
# /usr/share/dxvk-conf/<basename>.conf; link (not copy) to preserve the
# game's dir when installed on read-only media.
EXE_BASENAME=$(basename "$TARGET_EXE")
EXE_DIR=$(dirname "$TARGET_EXE")
CONF_SRC="/usr/share/dxvk-conf/${EXE_BASENAME%.exe}.conf"
CONF_SRC_LOWER="/usr/share/dxvk-conf/$(printf '%s' "${EXE_BASENAME%.exe}" | tr '[:upper:]' '[:lower:]').conf"
CONF_DST="$EXE_DIR/${EXE_BASENAME%.exe}.dxvk.conf"

install_per_app_conf() {
    local src=""
    [ -r "$CONF_SRC" ]       && src="$CONF_SRC"
    [ -r "$CONF_SRC_LOWER" ] && src="$CONF_SRC_LOWER"
    [ -z "$src" ] && return 0
    # Only write if destination differs and dir is writable.
    if [ -w "$EXE_DIR" ] && [ ! -e "$CONF_DST" ]; then
        cp -f "$src" "$CONF_DST" 2>/dev/null || true
        # Register for cleanup so the game dir stays pristine.
        WROTE_CONF="$CONF_DST"
    elif [ ! -w "$EXE_DIR" ]; then
        # Read-only game dir: pass conf via DXVK_CONFIG_FILE (DXVK 2.x).
        export DXVK_CONFIG_FILE="$src"
    fi
}
install_per_app_conf

# --- Compositor state toggle ------------------------------------------
# Record previous state in globals so trap can restore.
XFWM_WAS_COMPOSITING=""
HYPR_WAS_VRR=""
COMPOSITOR_TYPE=""

detect_compositor() {
    if [ -n "${HYPRLAND_INSTANCE_SIGNATURE:-}" ] && command -v hyprctl >/dev/null 2>&1; then
        COMPOSITOR_TYPE="hyprland"
    elif command -v xfconf-query >/dev/null 2>&1 && \
         [ -n "${DISPLAY:-}" ] && pgrep -x xfwm4 >/dev/null 2>&1; then
        COMPOSITOR_TYPE="xfwm4"
    fi
}
detect_compositor

compositor_game_mode_on() {
    case "$COMPOSITOR_TYPE" in
        xfwm4)
            XFWM_WAS_COMPOSITING=$(xfconf-query -c xfwm4 -p /general/use_compositing 2>/dev/null)
            xfconf-query -c xfwm4 -p /general/use_compositing -s false 2>/dev/null || true
            # Also drop sync_to_vblank so games that target the root window
            # do not get pinned to the monitor refresh.
            xfconf-query -c xfwm4 -p /general/sync_to_vblank -s false 2>/dev/null || true
            ;;
        hyprland)
            # vrr 2 = adaptive (only kicks in when content is dynamic).
            HYPR_WAS_VRR=$(hyprctl getoption misc:vrr 2>/dev/null | awk '/^int:/ {print $2}')
            hyprctl keyword misc:vrr 2 >/dev/null 2>&1 || true
            # Disable blur during play — a big CPU/GPU saving on old HW.
            hyprctl keyword decoration:blur:enabled false >/dev/null 2>&1 || true
            ;;
    esac
}

compositor_game_mode_off() {
    case "$COMPOSITOR_TYPE" in
        xfwm4)
            if [ -n "$XFWM_WAS_COMPOSITING" ]; then
                xfconf-query -c xfwm4 -p /general/use_compositing -s "$XFWM_WAS_COMPOSITING" 2>/dev/null || true
            else
                xfconf-query -c xfwm4 -p /general/use_compositing -s true 2>/dev/null || true
            fi
            xfconf-query -c xfwm4 -p /general/sync_to_vblank -s true 2>/dev/null || true
            ;;
        hyprland)
            if [ -n "$HYPR_WAS_VRR" ]; then
                hyprctl keyword misc:vrr "$HYPR_WAS_VRR" >/dev/null 2>&1 || true
            fi
            hyprctl keyword decoration:blur:enabled true >/dev/null 2>&1 || true
            ;;
    esac
    # Remove per-app conf if we wrote one.
    [ -n "${WROTE_CONF:-}" ] && rm -f "$WROTE_CONF" 2>/dev/null || true
}

# Always restore compositor on exit -- even on crash / SIGTERM.
trap 'compositor_game_mode_off' EXIT INT TERM HUP

# --- Per-game heuristic overrides -------------------------------------
# Some games need DXVK_ASYNC disabled even on capable HW (known-bad
# shader streaming, e.g. "DOOM Eternal" below a patch level).  We
# consult /usr/share/ai-arch/game-quirks.list if present.
QUIRKS_FILE=/usr/share/ai-arch/game-quirks.list
if [ -r "$QUIRKS_FILE" ]; then
    # Format: one rule per line:
    #   <exe>\t<VAR1=val>\t<VAR2=val>...
    # Lines starting with # ignored.
    while IFS=$'\t' read -r exe_pat rest; do
        [ -z "$exe_pat" ] && continue
        case "$exe_pat" in \#*) continue ;; esac
        if [ "$exe_pat" = "$EXE_BASENAME" ]; then
            # shellcheck disable=SC2086
            set -a
            eval $rest
            set +a
            break
        fi
    done < "$QUIRKS_FILE"
fi

# --- Activate game mode -----------------------------------------------
compositor_game_mode_on

# --- Force CPU governor to performance during play (OLD tier only) ---
# NEW tier already runs schedutil which handles boost well.  OLD tier
# ondemand can leave cores idle during shader compile and stutter.
PREV_GOV=""
if [ "$GPU_PROFILE" = "OLD" ] && [ -w /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
    PREV_GOV=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null)
    for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo performance > "$f" 2>/dev/null || true
    done
    # Restore on exit.
    trap 'compositor_game_mode_off; for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo "$PREV_GOV" > "$f" 2>/dev/null || true; done' EXIT INT TERM HUP
fi

# --- Log and exec peloader --------------------------------------------
LOG_DIR=/var/log/ai-arch
mkdir -p "$LOG_DIR" 2>/dev/null
{
    echo "[$(date -Iseconds 2>/dev/null)] pe-launch-wrapper:"
    echo "  exe=$TARGET_EXE"
    echo "  vendor=$GPU_VENDOR arch=$GPU_ARCH profile=$GPU_PROFILE"
    echo "  DXVK_ASYNC=${DXVK_ASYNC:-0} DXVK_STATE_CACHE=${DXVK_STATE_CACHE:-1}"
    echo "  VKD3D_CONFIG=${VKD3D_CONFIG:-} VKD3D_SHADER_CACHE_PATH=${VKD3D_SHADER_CACHE_PATH:-}"
    echo "  compositor=${COMPOSITOR_TYPE:-none}"
} >> "$LOG_DIR/pe-launch.log" 2>/dev/null

# --- Gamescope routing (Session 33 compositor bypass) -----------------
# Default: launch through gamescope for guaranteed compositor bypass.
# gamescope gives us an isolated nested compositor whose present mode is
# fully controlled; combined with the coherence Vulkan layer this forces
# MAILBOX/IMMEDIATE end-to-end.
#
# HW tier gating:
#   NEW / MID / DEFAULT : route through gamescope-launch.sh
#   OLD / legacy        : keep existing xfconf-compositor path (gamescope
#                         requires Vulkan 1.2+ which some legacy ICDs lack)
#
# User override: COHERENCE_NO_GAMESCOPE=1 skips gamescope entirely.
GAMESCOPE_LAUNCH=/usr/lib/ai-arch/gamescope-launch.sh
HW_PROFILE_FILE=/run/ai-arch-hw-profile
HW_PROFILE=""
if [ -r "$HW_PROFILE_FILE" ]; then
    # Same file format used by hw-detect.sh (`PROFILE=NEW|OLD|DEFAULT`).
    HW_PROFILE=$(awk -F= '/^PROFILE=/{gsub(/"/,"",$2); print $2; exit}' \
                  "$HW_PROFILE_FILE" 2>/dev/null)
fi

use_gamescope=0
case "$HW_PROFILE" in
    NEW|DEFAULT|MID) use_gamescope=1 ;;
    OLD)             use_gamescope=0 ;;
    *)
        # Unknown profile: fall back by GPU tier (software -> no gamescope).
        if [ "${GPU_TIER:-}" = "software" ] || [ "${GPU_TIER:-}" = "legacy" ]; then
            use_gamescope=0
        else
            use_gamescope=1
        fi
        ;;
esac
[ "${COHERENCE_NO_GAMESCOPE:-0}" = "1" ] && use_gamescope=0
[ -x "$GAMESCOPE_LAUNCH" ] || use_gamescope=0
command -v gamescope >/dev/null 2>&1 || use_gamescope=0

if [ "$use_gamescope" = "1" ]; then
    {
        echo "  gamescope=yes (profile=$HW_PROFILE)"
    } >> "$LOG_DIR/pe-launch.log" 2>/dev/null
    # gamescope owns the outer present loop; our xfconf/hyprctl tweaks
    # are redundant (but already installed via trap for restore on exit).
    exec "$GAMESCOPE_LAUNCH" "$TARGET_EXE" "$@"
fi

# --- OLD-tier fallback: stay on xfconf-compositor path ----------------
{
    echo "  gamescope=no (profile=$HW_PROFILE) — xfconf-compositor fallback"
} >> "$LOG_DIR/pe-launch.log" 2>/dev/null

# Prefer peloader in /usr/bin; fall back to PATH lookup.
PELOADER=/usr/bin/peloader
[ -x "$PELOADER" ] || PELOADER=$(command -v peloader 2>/dev/null || echo /usr/bin/peloader)

exec "$PELOADER" "$TARGET_EXE" "$@"
