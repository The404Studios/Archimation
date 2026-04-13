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

if [ "$SCREEN_H" -ge 2160 ]; then
    DPI=192
elif [ "$SCREEN_H" -ge 1440 ]; then
    DPI=120
else
    DPI=96
fi

# Apply DPI to the X server for the greeter session
echo "Xft.dpi: $DPI" | xrdb -merge 2>/dev/null || true
