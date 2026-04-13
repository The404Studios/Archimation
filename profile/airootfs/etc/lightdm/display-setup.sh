#!/bin/bash
# display-setup.sh - Called by LightDM when X starts.
# 1. Forces VT switch to VT7 (where X runs) so the desktop is visible.
#    Without this, the console stays on VT1 after Plymouth quits.
# 2. Deactivates Plymouth if still running (seamless splash → desktop).
# 3. Sets Xft.dpi for the greeter.

# Force switch to VT7 where X is running
chvt 7 2>/dev/null || true

# Tell Plymouth to release the display if it's still active
if command -v plymouth &>/dev/null && plymouth --ping 2>/dev/null; then
    plymouth deactivate 2>/dev/null || true
fi

# Set DPI (96 base — GDK_DPI_SCALE=0.5 in session handles HiDPI)
echo "Xft.dpi: 96" | xrdb -merge 2>/dev/null || true
