#!/bin/bash
# ai-arch/hid-bypass.sh -- optional low-latency input path via uhid.
#
# The default input path is evdev -- X11/Wayland reads /dev/input/event* and
# forwards to focused window.  This adds a full trip through the kernel's
# input subsystem (5-15 ms typical).  For twitch-reflex AI workloads and
# real-time synthetic input injection, uhid lets the daemon CREATE a virtual
# HID device that sits directly on the HID bus -- roughly half the latency.
#
# This is OPT-IN.  Default boot uses evdev (universal, stable).  Power users
# and AI-daemon-driven automation may enable this via:
#   systemctl enable ai-hid-bypass.service   (NOT created here; user's choice)
#   or manually:  /usr/lib/ai-arch/hid-bypass.sh enable
#
# Modes:
#   status      -- print current state (modules, /dev nodes, groups)
#   probe       -- verify uhid is loadable on this kernel
#   enable      -- load uhid, create /dev/uhid if missing, set permissions
#   disable     -- drop uhid module (safe: no persistent users after unload)
#
# IDEMPOTENT.  Never fails boot; only touches sysfs on explicit request.

set -u
set +e

MODE="${1:-status}"

have_module() {
    local m=$1
    # Prefer /sys/module (already loaded) over modinfo (available but not loaded)
    [ -d "/sys/module/$m" ] && return 0
    modinfo "$m" >/dev/null 2>&1 && return 0
    return 1
}

is_loaded() {
    [ -d "/sys/module/$1" ]
}

case "$MODE" in
    status)
        echo "# hid-bypass status @$(date -Iseconds 2>/dev/null || date)"
        if is_loaded uhid; then
            echo "uhid=loaded"
        else
            echo "uhid=unloaded"
        fi
        if [ -c /dev/uhid ]; then
            ls -l /dev/uhid 2>/dev/null
        else
            echo "/dev/uhid=missing"
        fi
        # Count evdev devices -- informational
        evcount=$(ls /dev/input/event[0-9]* 2>/dev/null | wc -l)
        echo "evdev_count=$evcount"
        ;;

    probe)
        # Reports 'ok' if the kernel has the module built (in or built-in)
        if have_module uhid; then
            echo "uhid=available"
            exit 0
        else
            echo "uhid=unavailable"
            exit 1
        fi
        ;;

    enable)
        if ! have_module uhid; then
            echo "hid-bypass: uhid not available on this kernel" >&2
            exit 1
        fi
        if ! is_loaded uhid; then
            modprobe uhid 2>&1 || {
                echo "hid-bypass: modprobe uhid failed" >&2
                exit 1
            }
        fi
        # Wait up to 2s for the char device node
        for _i in 1 2 3 4 5 6 7 8 9 10; do
            [ -c /dev/uhid ] && break
            sleep 0.2
        done
        if [ ! -c /dev/uhid ]; then
            echo "hid-bypass: /dev/uhid did not appear after modprobe" >&2
            exit 1
        fi
        # Fix up perms in case udev hasn't applied them yet
        chgrp input /dev/uhid 2>/dev/null || true
        chmod 0660 /dev/uhid 2>/dev/null || true
        echo "hid-bypass: uhid enabled ($(ls -l /dev/uhid 2>/dev/null))"
        ;;

    disable)
        if is_loaded uhid; then
            # Force-remove only if no open refs.  modprobe -r refuses if busy,
            # which is the correct behavior -- don't yank the device under an
            # in-flight daemon.
            if modprobe -r uhid 2>/dev/null; then
                echo "hid-bypass: uhid unloaded"
            else
                echo "hid-bypass: uhid in use; refusing to unload" >&2
                exit 1
            fi
        else
            echo "hid-bypass: uhid already unloaded"
        fi
        ;;

    *)
        echo "Usage: $0 {status|probe|enable|disable}" >&2
        exit 2
        ;;
esac

exit 0
