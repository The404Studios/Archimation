#!/bin/sh
# ~/.xsession - fallback session script.
# LightDM invokes this when user-session resolves to 'default' or the
# configured session's .desktop file is missing. Normal path is
# /usr/share/xsessions/xfce.desktop -> startxfce4; this is a safety net.

# Load user X environment.
if [ -f "$HOME/.xprofile" ]; then
    . "$HOME/.xprofile"
fi

# Prefer startxfce4 if available; fall back to xfce4-session directly, then xterm.
if command -v startxfce4 >/dev/null 2>&1; then
    exec startxfce4
elif command -v xfce4-session >/dev/null 2>&1; then
    exec xfce4-session
elif command -v xterm >/dev/null 2>&1; then
    # Last-resort rescue shell so the user can see what's wrong instead of
    # staring at a blank screen.
    exec xterm -geometry 120x40 -title "Rescue Session (no desktop found)"
else
    # Nothing to exec — exit cleanly so LightDM can report the failure.
    exit 1
fi
