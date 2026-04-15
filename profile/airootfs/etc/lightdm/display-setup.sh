#!/bin/bash
# display-setup.sh - Called by LightDM when X starts.
# 1. Force VT switch to the one X is running on so the desktop is visible.
#    Without this, the console stays on VT1 after Plymouth quits.
# 2. Deactivate Plymouth if still running (seamless splash -> desktop).
# 3. Set Xft.dpi for the greeter, detected from EDID when possible.

# --- Detect X's VT from systemd, fall back to 7 ---
# LightDM exposes its seat's VT via the LIGHTDM_VT env var on modern
# versions; older versions default to VT7.  fgconsole(1) returns the
# currently active foreground console, which is what we want to target.
X_VT=""
if [ -n "${LIGHTDM_VT:-}" ]; then
    X_VT="$LIGHTDM_VT"
elif command -v fgconsole &>/dev/null; then
    X_VT=$(fgconsole 2>/dev/null)
fi
# Fall back to VT7 (the Arch / LightDM default) if detection failed
[ -z "$X_VT" ] && X_VT=7
# Accept only a single digit to avoid injection from stale env
case "$X_VT" in
    [1-9]) chvt "$X_VT" 2>/dev/null || true ;;
    *)     chvt 7 2>/dev/null || true ;;
esac

# Tell Plymouth to release the display if it's still active.
# Use `quit --retain-splash` when available so the background stays up
# until X has claimed the framebuffer; pure `deactivate` is a fallback.
if command -v plymouth &>/dev/null && plymouth --ping 2>/dev/null; then
    plymouth quit --retain-splash 2>/dev/null || \
        plymouth deactivate 2>/dev/null || true
fi

# --- Auto-detect DPI from EDID and feed Xft.dpi ---
# Physical DPI = screen_width_px * 25.4 / screen_width_mm.  For HiDPI
# panels (>=144 DPI) we'll boost Xft by the integer ratio; below we
# clamp at 96 to avoid scaling regressions on over-reporting panels.
DETECTED_DPI=96
if command -v xrandr &>/dev/null; then
    DETECTED_DPI=$(xrandr 2>/dev/null | awk '
        /connected primary/ || /connected \(/ {
            for (i=1;i<=NF;i++)
                if ($i ~ /^[0-9]+x[0-9]+\+/) { split($i,p,"x"); w=p[1]; break }
            for (i=1;i<=NF;i++) if ($i ~ /mm$/) { pw=$i; sub("mm","",pw); break }
            if (w+0>0 && pw+0>0) { printf "%d", int(w*25.4/pw); exit }
        }
    ' 2>/dev/null)
    [ -z "$DETECTED_DPI" ] && DETECTED_DPI=96
    # Clamp to sane bounds: some panels report absurd mm values
    [ "$DETECTED_DPI" -lt 72 ] 2>/dev/null && DETECTED_DPI=96
    [ "$DETECTED_DPI" -gt 300 ] 2>/dev/null && DETECTED_DPI=192
fi
echo "Xft.dpi: $DETECTED_DPI" | xrdb -merge 2>/dev/null || true
