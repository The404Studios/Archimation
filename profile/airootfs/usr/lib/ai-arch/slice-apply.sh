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
    CPU_CORES=2
else
    # shellcheck disable=SC1090
    . "$PROFILE_FILE"
    PROFILE="${PROFILE:-DEFAULT}"
    MEM_MB="${MEM_MB:-4096}"
    CPU_CORES="${CPU_CORES:-2}"
fi

DROP_ROOT="/run/systemd/system"
mkdir -p "$DROP_ROOT"

# ---------------------------------------------------------------------------
# NUMA topology detection (Session 33: CPU-isolation for game.slice)
# ---------------------------------------------------------------------------
# Populate:
#   GAME_NODE          -- the NUMA node that game.slice should pin to (usually 0)
#   NUMA_NODE_CPULIST  -- the node's full CPU list as kernel cpulist string (e.g. "0-15")
#   GAME_CPUS          -- cpulist range for game.slice (CPUs minus reserved)
#   RESERVED_CPUS      -- cpulist range of CPUs reserved for system/observer
#   SYS_MEMNODE        -- memory node spec for AllowedMemoryNodes=
#
# Failure modes fall back to "everything":
#   - No /sys/devices/system/node       -> cpulist = 0-$((CPU_CORES-1))
#   - Unreadable node0/cpulist          -> same
#   - Single-CPU system                 -> no reservation; game gets the one CPU
#
# The script writes these into /run/ai-arch-numa (a sidecar profile file) so
# Agent 6's coherence daemon can read the same values when it rewrites the
# drop-in at runtime.

numa_detect() {
    # Defaults if /sys/devices/system/node doesn't exist (non-NUMA, minimal VMs)
    GAME_NODE=0
    SYS_MEMNODE=""
    if [ $CPU_CORES -ge 1 ]; then
        NUMA_NODE_CPULIST="0-$(( CPU_CORES - 1 ))"
    else
        NUMA_NODE_CPULIST="0"
    fi
    # Pick the node with the most CPUs — rare for asymmetric nodes, but real on
    # some multi-socket workstations. Iterate online nodes and count.
    if [ -d /sys/devices/system/node ]; then
        best_node=""
        best_count=0
        for nd in /sys/devices/system/node/node[0-9]*; do
            [ -d "$nd" ] || continue
            [ -r "$nd/cpulist" ] || continue
            cl=$(cat "$nd/cpulist" 2>/dev/null)
            [ -z "$cl" ] && continue
            # Count CPUs by expanding cpulist. Rough heuristic: count commas and
            # ranges via awk so we avoid spawning python.
            cnt=$(printf '%s' "$cl" | awk -F, '{
                n = 0
                for (i = 1; i <= NF; i++) {
                    split($i, r, "-")
                    if (length(r[2]) > 0) n += (r[2] - r[1] + 1); else n += 1
                }
                print n
            }')
            if [ -n "$cnt" ] && [ "$cnt" -gt "$best_count" ]; then
                best_count=$cnt
                best_node=${nd##*/node}
                best_cpulist=$cl
            fi
        done
        if [ -n "$best_node" ]; then
            GAME_NODE=$best_node
            NUMA_NODE_CPULIST=$best_cpulist
            SYS_MEMNODE=$best_node
        fi
    fi
}
numa_detect

# ---------------------------------------------------------------------------
# CPU reservation (tiered by HW class)
# ---------------------------------------------------------------------------
# OLD (<=2 cores): no reservation; game gets everything or we throttle the OS
# MID (4-8 cores): reserve CPU 0 for system/observer
# NEW (8+ cores):  reserve CPU 0-1 for system/observer
#
# Output: GAME_CPUS and RESERVED_CPUS as cpulist strings.
#
# Note: we derive reservations purely from CPU_CORES + PROFILE, NOT from parsing
# the raw cpulist (which might be sparse like "0,2,4-7"). The reservation is
# applied as the LOWEST-numbered CPUs of the chosen NUMA node. If the node's
# cpulist isn't "0-N" we still carve from the lowest offsets present.

numa_first_n() {
    # Print the first N CPUs from a cpulist string, as a new cpulist.
    # Handles ranges and single CPUs. E.g. numa_first_n 2 "0,2,4-7" -> "0,2"
    n=$1
    cl=$2
    out=""
    count=0
    # shellcheck disable=SC2086
    set -f
    IFS=','
    for tok in $cl; do
        IFS=''
        lo=${tok%%-*}
        hi=${tok##*-}
        [ "$lo" = "$hi" ] && hi=$lo
        i=$lo
        while [ "$i" -le "$hi" ] && [ "$count" -lt "$n" ]; do
            if [ -z "$out" ]; then
                out=$i
            else
                out="$out,$i"
            fi
            count=$(( count + 1 ))
            i=$(( i + 1 ))
        done
        IFS=','
        [ "$count" -ge "$n" ] && break
    done
    IFS=' '
    set +f
    printf '%s' "$out"
}

numa_skip_n() {
    # Print cpulist with first N CPUs removed. Same format assumptions.
    n=$1
    cl=$2
    out=""
    skipped=0
    # shellcheck disable=SC2086
    set -f
    IFS=','
    for tok in $cl; do
        IFS=''
        lo=${tok%%-*}
        hi=${tok##*-}
        [ "$lo" = "$hi" ] && hi=$lo
        i=$lo
        while [ "$i" -le "$hi" ]; do
            if [ "$skipped" -lt "$n" ]; then
                skipped=$(( skipped + 1 ))
            else
                if [ -z "$out" ]; then
                    out=$i
                else
                    out="$out,$i"
                fi
            fi
            i=$(( i + 1 ))
        done
        IFS=','
    done
    IFS=' '
    set +f
    printf '%s' "$out"
}

reserve_cpus() {
    # Choose how many CPUs to hold back for system/observer.
    if [ "$PROFILE" = "OLD" ] || [ "$CPU_CORES" -le 2 ]; then
        RESERVED_N=0
    elif [ "$PROFILE" = "NEW" ] || [ "$CPU_CORES" -ge 8 ]; then
        RESERVED_N=2
    else
        RESERVED_N=1
    fi
    if [ "$RESERVED_N" -ge "$CPU_CORES" ]; then
        # Safety: never reserve ALL CPUs.
        RESERVED_N=0
    fi
    if [ "$RESERVED_N" -eq 0 ]; then
        RESERVED_CPUS=""
        GAME_CPUS=$NUMA_NODE_CPULIST
    else
        RESERVED_CPUS=$(numa_first_n "$RESERVED_N" "$NUMA_NODE_CPULIST")
        GAME_CPUS=$(numa_skip_n "$RESERVED_N" "$NUMA_NODE_CPULIST")
        # Last-ditch safety: if skip-n produced empty string (single-CPU node),
        # fall back to giving game.slice everything.
        if [ -z "$GAME_CPUS" ]; then
            RESERVED_CPUS=""
            GAME_CPUS=$NUMA_NODE_CPULIST
            RESERVED_N=0
        fi
    fi
}
reserve_cpus

# Sidecar file consumed by:
#   - this script (re-exec on SIGHUP from ai-irq-balance)
#   - /usr/lib/ai-arch/irq-balancer.sh (IRQ affinity masks)
#   - Agent 6's coherence daemon actuation (reads to know what's pinned)
{
    echo "GAME_NODE=$GAME_NODE"
    echo "NUMA_NODE_CPULIST=\"$NUMA_NODE_CPULIST\""
    echo "GAME_CPUS=\"$GAME_CPUS\""
    echo "RESERVED_CPUS=\"$RESERVED_CPUS\""
    echo "RESERVED_N=$RESERVED_N"
    echo "SYS_MEMNODE=\"$SYS_MEMNODE\""
} > /run/ai-arch-numa 2>/dev/null || true

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
# game.slice NUMA drop-in (separate file so coherence daemon can rewrite
# independently via Agent 6's actuation without overwriting memory knobs).
# Written as /run/systemd/system/game.slice.d/10-numa.conf.
# ---------------------------------------------------------------------------
_game_numa_body="\
# NUMA-aware drop-in (profile=$PROFILE, game_node=$GAME_NODE, reserved=$RESERVED_N)
# Written by /usr/lib/ai-arch/slice-apply.sh; coherence daemon may rewrite at runtime.
[Slice]
AllowedCPUs=${GAME_CPUS}"
if [ -n "$SYS_MEMNODE" ]; then
    _game_numa_body="${_game_numa_body}
AllowedMemoryNodes=${SYS_MEMNODE}"
fi
# Use a second drop-in file so mem tuning (10-hw.conf) and NUMA pinning
# (10-numa.conf) can be independently updated by different actors.
_game_dir="$DROP_ROOT/game.slice.d"
mkdir -p "$_game_dir" 2>/dev/null || true
_numa_tmp="$_game_dir/10-numa.conf.tmp"
printf '%s\n' "$_game_numa_body" > "$_numa_tmp" 2>/dev/null && \
    mv -f "$_numa_tmp" "$_game_dir/10-numa.conf" 2>/dev/null && \
    chmod 0644 "$_game_dir/10-numa.conf" 2>/dev/null || true

# observer.slice NUMA drop-in: observers live on the reserved CPUs so they
# never compete with the game for a core. If nothing is reserved (OLD tier),
# we skip this file and leave observers free-floating on all CPUs.
if [ -n "$RESERVED_CPUS" ]; then
    _obs_numa_body="\
# NUMA drop-in for observer.slice (reserved OS cores)
[Slice]
AllowedCPUs=${RESERVED_CPUS}"
    if [ -n "$SYS_MEMNODE" ]; then
        _obs_numa_body="${_obs_numa_body}
AllowedMemoryNodes=${SYS_MEMNODE}"
    fi
    _obs_dir="$DROP_ROOT/observer.slice.d"
    mkdir -p "$_obs_dir" 2>/dev/null || true
    _obs_tmp="$_obs_dir/10-numa.conf.tmp"
    printf '%s\n' "$_obs_numa_body" > "$_obs_tmp" 2>/dev/null && \
        mv -f "$_obs_tmp" "$_obs_dir/10-numa.conf" 2>/dev/null && \
        chmod 0644 "$_obs_dir/10-numa.conf" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Reload so overrides take effect
# ---------------------------------------------------------------------------
# systemctl daemon-reload picks up drop-ins from /run/systemd/system/.
# Best-effort: if systemctl isn't on PATH (minimal initramfs) we skip.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null || true
fi

echo "slice-apply: profile=$PROFILE applied (pe_high=$PE_MEM_HIGH ai_high=$AI_MEM_HIGH obs_quota=$OBS_CPU_QUOTA)"
echo "slice-apply: numa node=$GAME_NODE game_cpus=$GAME_CPUS reserved=${RESERVED_CPUS:-none}"
exit 0
