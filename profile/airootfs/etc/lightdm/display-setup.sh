#!/bin/bash
# display-setup.sh - Auto-detect display DPI for LightDM greeter
# Called by LightDM before the greeter starts.
# Sets Xft.dpi via xrdb so the greeter renders at the right scale.

if ! command -v xrandr &>/dev/null; then
    exit 0
fi

# Get the vertical resolution of the primary/first connected display
SCREEN_H=$(xrandr 2>/dev/null | grep -oP '\d+x\K\d+(?=\+)' | sort -rn | head -1)

if [ -z "$SCREEN_H" ]; then
    exit 0
fi

# Use consistent 96 DPI across all resolutions — GDK_DPI_SCALE=0.5
# in the session handles the actual scaling. This prevents the greeter
# from rendering at oversized DPI on HiDPI screens.
DPI=96

# Apply DPI to the X server for the greeter session
echo "Xft.dpi: $DPI" | xrdb -merge 2>/dev/null || true
