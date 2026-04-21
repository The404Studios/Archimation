#!/bin/bash
# setup-users.sh - First-boot idempotent user/group setup
#
# Session 69 (Agent R).  Ensures the default non-root user (whether that's
# the live-ISO "arch" account or whatever Agent O's disk installer created)
# is a member of every group needed to call the AI daemon, subscribe to the
# event bus, and read /dev/trust without sudo.
#
# Called in two contexts:
#   * Live ISO:       already handled by customize_airootfs.sh at build time;
#                     this script is the idempotent post-boot reconciler.
#   * Installed disk: ai-install-to-disk (Agent O) runs this after first-boot
#                     user creation.  The script is safe to re-run N times.
#
# All operations check-then-create; "already exists" is a no-op success.

set -u  # not -e: we want to continue on a single usermod failure.

# --- Group creation (-r = system group, GID < 1000) ------------------------
for g in trust pe-compat; do
    if ! getent group "$g" >/dev/null 2>&1; then
        if groupadd -r "$g"; then
            echo "setup-users: created group '$g'"
        else
            echo "setup-users: WARN failed to create group '$g'" >&2
        fi
    fi
done

# --- Identify the target user ---------------------------------------------
#
# Priority:
#   1. $SETUP_USERS_TARGET (explicit override from caller)
#   2. The first regular user (UID >= 1000, has a home dir, has a shell)
#   3. "arch" if it exists (live-ISO default)
#
# This avoids hardcoding "arch" so the script also works on installed-to-disk
# systems where Agent O's installer let the user pick a different name.

pick_target_user() {
    if [ -n "${SETUP_USERS_TARGET:-}" ]; then
        printf '%s' "$SETUP_USERS_TARGET"
        return 0
    fi
    local first_regular
    first_regular=$(
        awk -F: '$3 >= 1000 && $3 < 65000 && $6 != "" && $7 !~ /(nologin|false)$/ {print $1; exit}' /etc/passwd
    )
    if [ -n "$first_regular" ]; then
        printf '%s' "$first_regular"
        return 0
    fi
    if id arch >/dev/null 2>&1; then
        printf '%s' arch
        return 0
    fi
    return 1
}

TARGET_USER=$(pick_target_user) || {
    echo "setup-users: no target user found (no regular UID, no 'arch'); nothing to do" >&2
    exit 0
}

echo "setup-users: target user = $TARGET_USER"

# --- Group membership -----------------------------------------------------
#
# Append-only (-aG).  usermod refuses to add nonexistent groups, so we filter
# the list to only include groups that actually exist on this system.

DESIRED_GROUPS="wheel trust pe-compat audio video input network storage users"
FILTERED_GROUPS=""
for g in $DESIRED_GROUPS; do
    if getent group "$g" >/dev/null 2>&1; then
        if [ -z "$FILTERED_GROUPS" ]; then
            FILTERED_GROUPS="$g"
        else
            FILTERED_GROUPS="$FILTERED_GROUPS,$g"
        fi
    fi
done

if [ -n "$FILTERED_GROUPS" ]; then
    if usermod -aG "$FILTERED_GROUPS" "$TARGET_USER"; then
        echo "setup-users: added $TARGET_USER to groups: $FILTERED_GROUPS"
    else
        echo "setup-users: WARN usermod -aG failed for $TARGET_USER" >&2
    fi
fi

# --- Touch marker so we don't log every subsequent boot -------------------
# Non-fatal; purely for operator visibility via `ls -la /var/lib/ai-control/`.
MARKER_DIR=/var/lib/ai-control
mkdir -p "$MARKER_DIR" 2>/dev/null || true
{
    echo "setup-users ran: $(date -Iseconds)"
    echo "target_user=$TARGET_USER"
    echo "groups=$FILTERED_GROUPS"
} > "$MARKER_DIR/setup-users.last" 2>/dev/null || true

echo "setup-users: done (idempotent; safe to re-run)"
exit 0
