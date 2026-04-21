#!/bin/bash
#
# ai-load-drivers.sh -- on-boot kernel module loader for the AI Arch Linux
# distribution.  Operators (and the cortex via /etc) can drop additional
# module names into either of:
#
#     /etc/ai-control/modules.d/*.conf      (preferred, package-friendly)
#     /etc/ai-control/extra-modules.list    (single flat list, legacy)
#
# Each line is one module name OR `modulename arg1=val arg2=val ...`.
# Lines beginning with `#` and blank lines are ignored.  Module names
# matching `^[a-zA-Z0-9_-]+$` are passed to modprobe; anything else is
# rejected with a journal warning.
#
# This unit runs After=systemd-modules-load.service so it composes with the
# stock /etc/modules-load.d/ pipeline rather than competing with it; we own
# the "stuff cortex/operator dropped at runtime" bucket.
#
# Idempotent: modprobe is itself a no-op when the module is already loaded,
# so re-running this script never destabilises the kernel module graph.
#
# Exit code is always 0 on completion (the systemd unit Type=oneshot stays
# `active (exited)` even when individual modules fail to load — we don't
# want a missing optional module to wedge graphical.target).

set -u
shopt -s nullglob

CONF_DIR="/etc/ai-control/modules.d"
EXTRA_LIST="/etc/ai-control/extra-modules.list"
LOG_TAG="ai-driver-loader"

log() {
    # Prefer logger -> journal; fall back to stderr if logger is missing
    if command -v logger >/dev/null 2>&1; then
        logger -t "$LOG_TAG" -- "$*"
    else
        printf '%s: %s\n' "$LOG_TAG" "$*" >&2
    fi
}

load_one() {
    local raw="$1"
    # Strip leading/trailing whitespace + comments
    local line="${raw%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [ -z "$line" ] && return 0

    # First token = module name, rest = parameters
    local name="${line%% *}"
    local args="${line#"$name"}"

    # Allow only safe module names — block path traversal / shell metas
    if ! [[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        log "rejected invalid module name: '$name'"
        return 1
    fi

    # -q: quiet on already-loaded; -b: respect blacklists
    if modprobe -q -b "$name" $args 2>/dev/null; then
        log "loaded module: $name${args:+ $args}"
    else
        log "failed to load module: $name (modprobe rc=$?)"
    fi
}

main() {
    local count=0

    if [ -d "$CONF_DIR" ]; then
        for f in "$CONF_DIR"/*.conf; do
            [ -r "$f" ] || continue
            while IFS= read -r line || [ -n "$line" ]; do
                load_one "$line"
                count=$((count + 1))
            done < "$f"
        done
    fi

    if [ -r "$EXTRA_LIST" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            load_one "$line"
            count=$((count + 1))
        done < "$EXTRA_LIST"
    fi

    log "processed $count module entries"
    return 0
}

main "$@"
exit 0
