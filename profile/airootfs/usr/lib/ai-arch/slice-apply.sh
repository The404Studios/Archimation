#!/bin/bash
# ai-arch/slice-apply.sh -- HW-tiered cgroup v2 resource tuning.
#
# Called by ai-hw-detect.service after the profile has been written.
# Reads /run/ai-arch-hw-profile and writes runtime overrides to the
# cgroup v2 knobs of our custom slices (trust, ai-daemon, pe-compat,
# observer, game).
#
# Why not bake the values into the .slice files?
#   Static values don't differentiate the 1 GiB Pentium 4 lab machine
#   from a 64 GiB modern workstation.  A CPUQuota=5% that's sensible
#   on a 4-core box is way too generous on the P4 (5% of one core = 5%
#   of the ONLY core).  We write /run/systemd/system/*.slice.d/10-hw.conf
#   drop-ins at boot, then reload.
#
# The script is IDEMPOTENT and FAILSAFE -- every write is guarded.

set -u
set +e

PROFILE_FILE="/run/ai-arch-hw-profile"
if [ ! -r "$PROFILE_FILE" ]; then
    echo "slice-apply: no $PROFILE_FILE, defaulting to DEFAULT profile" >&2
    PROFILE="DEFAULT"
    MEM_MB=4096
else
    # shellcheck disable=SC1090
    . "$PROFILE_FILE"
    PROFILE="${PROFILE:-DEFAULT}"
    MEM_MB="${MEM_MB:-4096}"
fi

DROP_ROOT="/run/systemd/system"
mkdir -p "$DROP_ROOT"

# ---------------------------------------------------------------------------
# Compute tier-specific values
# ---------------------------------------------------------------------------
# Totals in MiB; cgroup v2 accepts percent strings but we precompute the
# bytes so old kernels without percent support still work.

case "$PROFILE" in
    OLD)
        # 1-2 GiB total: every byte matters.
        PE_MEM_HIGH="512M"
        PE_MEM_MAX="768M"
        AI_MEM_HIGH="192M"
        AI_MEM_MAX="384M"
        OBS_CPU_QUOTA="2%"
        OBS_MEM_HIGH="32M"
        OBS_MEM_MAX="64M"
        OBS_IO_READ_MAX="1M"    # 1 MB/s cap on rotational
        GAME_MEM_MIN="128M"
        GAME_MEM_LOW="256M"
        TRUST_MEM_HIGH="128M"
        ;;
    NEW)
        # 8+ GiB, AVX2, SSD: be generous to PE.
        # Compute 80% of total RAM for PE_MEM_HIGH.
        PE_MEM_HIGH="$(( MEM_MB * 80 / 100 ))M"
        PE_MEM_MAX="$(( MEM_MB * 95 / 100 ))M"
        AI_MEM_HIGH="1024M"
        AI_MEM_MAX="2048M"
        OBS_CPU_QUOTA="10%"
        OBS_MEM_HIGH="256M"
        OBS_MEM_MAX="512M"
        OBS_IO_READ_MAX=""       # no cap on SSD/NVMe
        GAME_MEM_MIN="2048M"
        GAME_MEM_LOW="4096M"
        TRUST_MEM_HIGH="512M"
        ;;
    *)
        # DEFAULT profile: sensible middle ground.
        PE_MEM_HIGH="$(( MEM_MB * 70 / 100 ))M"
        PE_MEM_MAX="$(( MEM_MB * 90 / 100 ))M"
        AI_MEM_HIGH="512M"
        AI_MEM_MAX="1024M"
        OBS_CPU_QUOTA="5%"
        OBS_MEM_HIGH="128M"
        OBS_MEM_MAX="256M"
        OBS_IO_READ_MAX=""
        GAME_MEM_MIN="512M"
        GAME_MEM_LOW="1024M"
        TRUST_MEM_HIGH="256M"
        ;;
esac

# ---------------------------------------------------------------------------
# Helper: write a drop-in atomically
# ---------------------------------------------------------------------------
write_drop() {
    local slice="$1" content="$2"
    local dir="$DROP_ROOT/${slice}.d"
    mkdir -p "$dir" 2>/dev/null || return 1
    local tmp="$dir/10-hw.conf.tmp"
    printf '%s\n' "$content" > "$tmp" 2>/dev/null || return 1
    mv -f "$tmp" "$dir/10-hw.conf" 2>/dev/null || return 1
    chmod 0644 "$dir/10-hw.conf" 2>/dev/null || true
    return 0
}

# ---------------------------------------------------------------------------
# pe-compat.slice: size MemoryHigh/Max to available RAM
# ---------------------------------------------------------------------------
write_drop pe-compat.slice "\
# HW-tier drop-in (profile=$PROFILE, mem=${MEM_MB}MB)
# Written by /usr/lib/ai-arch/slice-apply.sh; DO NOT EDIT.
# Rewritten on every ai-hw-detect.service invocation.
[Slice]
MemoryHigh=${PE_MEM_HIGH}
MemoryMax=${PE_MEM_MAX}
"

# ---------------------------------------------------------------------------
# ai-daemon.slice
# ---------------------------------------------------------------------------
write_drop ai-daemon.slice "\
# HW-tier drop-in (profile=$PROFILE, mem=${MEM_MB}MB)
[Slice]
MemoryHigh=${AI_MEM_HIGH}
MemoryMax=${AI_MEM_MAX}
"

# ---------------------------------------------------------------------------
# observer.slice: tight CPU quota + memory + IO
# ---------------------------------------------------------------------------
obs_io_lines=""
if [ -n "$OBS_IO_READ_MAX" ] && [ "$ROOT_ROTATIONAL" = "1" ]; then
    # Cap disk read bandwidth on rotational to protect latency for games
    # and foreground apps.  Applied to every block device; systemd will
    # drop the ones it can't parse.
    for blk in /sys/block/sd? /sys/block/hd?; do
        [ -d "$blk" ] || continue
        bdev="/dev/${blk##*/}"
        obs_io_lines="${obs_io_lines}IOReadBandwidthMax=${bdev} ${OBS_IO_READ_MAX}
"
    done
fi
write_drop observer.slice "\
# HW-tier drop-in (profile=$PROFILE, mem=${MEM_MB}MB)
[Slice]
CPUQuota=${OBS_CPU_QUOTA}
MemoryHigh=${OBS_MEM_HIGH}
MemoryMax=${OBS_MEM_MAX}
${obs_io_lines}"

# ---------------------------------------------------------------------------
# trust.slice: only adjust MemoryHigh (MemoryMin stays at 64M everywhere)
# ---------------------------------------------------------------------------
write_drop trust.slice "\
# HW-tier drop-in (profile=$PROFILE, mem=${MEM_MB}MB)
[Slice]
MemoryHigh=${TRUST_MEM_HIGH}
"

# ---------------------------------------------------------------------------
# game.slice: reserve MemoryMin/MemoryLow appropriate to HW
# ---------------------------------------------------------------------------
write_drop game.slice "\
# HW-tier drop-in (profile=$PROFILE, mem=${MEM_MB}MB)
[Slice]
MemoryMin=${GAME_MEM_MIN}
MemoryLow=${GAME_MEM_LOW}
"

# ---------------------------------------------------------------------------
# Reload so overrides take effect
# ---------------------------------------------------------------------------
# systemctl daemon-reload picks up drop-ins from /run/systemd/system/.
# Best-effort: if systemctl isn't on PATH (minimal initramfs) we skip.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null || true
fi

echo "slice-apply: profile=$PROFILE applied (pe_high=$PE_MEM_HIGH ai_high=$AI_MEM_HIGH obs_quota=$OBS_CPU_QUOTA)"
exit 0
