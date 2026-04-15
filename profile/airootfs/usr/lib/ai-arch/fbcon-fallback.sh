#!/bin/bash
# ai-arch/fbcon-fallback.sh -- text-mode emergency shell on framebuffer console.
#
# If X fails to start 3 times in a row, ai-fbcon-fallback.service invokes
# this script.  It brings up a usable diagnostic shell on tty2 with:
#   - an informative banner explaining why we're here
#   - helpful commands pre-printed (journalctl, systemctl status, re-try X)
#   - agetty to spawn a login prompt
#
# Why not just drop into emergency.target?  Emergency mode disables user
# daemons and networking; the AI daemon is still running and accessible via
# SSH / curl on localhost -- we want to preserve that so the user / AI agent
# can diagnose remotely.  fbcon fallback is a LESS destructive recovery.
#
# Trigger:
#   systemd notices lightdm.service hit the start-limit-burst (3 in 120 s)
#   -> ai-fbcon-fallback.service conditional-starts (see .service unit)
#   -> this script runs.
#
# Clear path:
#   Users run /usr/lib/ai-arch/fbcon-fallback.sh unblock to re-enable lightdm
#   after fixing their config (or they just reboot).

set -u
set +e

MODE="${1:-run}"

STAMP_DIR=/run/ai-arch
STAMP_BLOCKED=$STAMP_DIR/x-blocked
TTY_TARGET=/dev/tty2

banner() {
    # Using printf to stay ASCII-only; cat <<EOF occasionally has CRLF issues
    # when the script was edited on Windows.
    printf '\n'
    printf '========================================================\n'
    printf ' AI Arch Linux -- FRAMEBUFFER FALLBACK SHELL\n'
    printf '========================================================\n'
    printf '\n'
    printf ' X11 (lightdm) failed to start multiple times in a row.\n'
    printf ' We have dropped to a text-mode shell on tty2 so you\n'
    printf ' can diagnose without rebooting.\n'
    printf '\n'
    printf ' Useful commands:\n'
    printf '   journalctl -u lightdm.service -b          # see X errors\n'
    printf '   journalctl -p err -b                      # all errors\n'
    printf '   cat /var/log/lightdm/x-0.log              # Xorg log\n'
    printf '   systemctl status ai-control.service       # daemon OK?\n'
    printf '   startx                                    # manual X retry\n'
    printf '   /usr/lib/ai-arch/fbcon-fallback.sh unblock # re-enable X\n'
    printf '\n'
    printf ' The AI daemon is still running at 127.0.0.1:8420.\n'
    printf ' SSH (if enabled) is still reachable.\n'
    printf '\n'
    printf '========================================================\n'
    printf '\n'
}

case "$MODE" in
    run)
        mkdir -p "$STAMP_DIR" 2>/dev/null
        : > "$STAMP_BLOCKED"
        # Switch to tty2 and show the banner there (not on tty1 which may
        # still have Plymouth or a half-dead X server on it).
        if [ -w "$TTY_TARGET" ]; then
            banner > "$TTY_TARGET" 2>/dev/null
        fi
        # Pick the best terminal program available:
        #   fbterm  -- bitmap fonts, Unicode, scrollback (if installed)
        #   agetty  -- plain vt, always available (provided by util-linux)
        # We don't install fbterm by default so agetty is the common path.
        if command -v fbterm >/dev/null 2>&1; then
            # fbterm needs to run as root to access /dev/fb0; on this fallback
            # unit we ARE root, so this works without CAP_SYS_ADMIN gymnastics.
            exec fbterm -- /bin/bash --login
        fi
        # Fall back to a login prompt on tty2.  agetty handles the vt
        # allocation and exec's login(1), so we end up with a proper session.
        exec /sbin/agetty --autologin root \
                          --noclear \
                          --keep-baud \
                          --login-pause \
                          tty2 linux
        ;;

    unblock)
        # Clear the blocked stamp and reset the lightdm start-limit counters
        # so the user can retry without rebooting.
        rm -f "$STAMP_BLOCKED" 2>/dev/null
        systemctl reset-failed lightdm.service 2>/dev/null || true
        systemctl reset-failed ai-fbcon-fallback.service 2>/dev/null || true
        # Stop fallback if it's currently running
        systemctl stop ai-fbcon-fallback.service 2>/dev/null || true
        # Restart lightdm
        if systemctl start lightdm.service 2>/dev/null; then
            echo "fbcon-fallback: lightdm restarted"
        else
            echo "fbcon-fallback: lightdm still failing; check journalctl" >&2
            exit 1
        fi
        ;;

    status)
        if [ -f "$STAMP_BLOCKED" ]; then
            echo "blocked=yes"
            stat -c 'blocked_at=%y' "$STAMP_BLOCKED" 2>/dev/null || true
        else
            echo "blocked=no"
        fi
        systemctl is-active lightdm.service 2>/dev/null || true
        ;;

    *)
        echo "Usage: $0 {run|unblock|status}" >&2
        exit 2
        ;;
esac
