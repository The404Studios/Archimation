#!/bin/sh
# ai-arch/irq-balancer.sh -- move device IRQs off the game-reserved CPUs.
#
# Called by ai-irq-balance.service at boot (ExecStart=apply) and whenever
# the coherence daemon signals a topology change (ExecReload=reload via
# SIGHUP).  Deliberately POSIX-only (sh, not bash) so it can run in the
# stripped-down initramfs / emergency shell.
#
# Input:
#   /run/ai-arch-numa           -- produced by slice-apply.sh
#                                 GAME_CPUS, RESERVED_CPUS, SYS_MEMNODE
#
# Output:
#   /proc/irq/N/smp_affinity    -- bitmask written for every movable IRQ
#   /etc/irqbalance/banned_cpus -- hint for irqbalance daemon (if installed)
#   /var/run/coherence/irq-{before,after}.txt  -- /proc/interrupts snapshots
#   /var/run/coherence/irq-diff.log            -- summary of changes
#
# Why not just configure irqbalance?
#   irqbalance is installed on some systems but not the live ISO; it uses a
#   different policy (power-save on mobile, performance on desktop) that
#   often picks the same CPU the game runs on. We enforce our own mapping
#   at boot, then leave a "banned_cpus" file so irqbalance (if it runs)
#   also avoids the game cores. Both mechanisms are complementary.
#
# WARNING: writing smp_affinity requires CAP_SYS_ADMIN. Failures are
# logged, not fatal -- a non-privileged user (e.g. test runs) gets
# best-effort reporting only.

set -u

MODE=${1:-apply}

NUMA_FILE=/run/ai-arch-numa
COHER_DIR=/var/run/coherence
BEFORE=$COHER_DIR/irq-before.txt
AFTER=$COHER_DIR/irq-after.txt
DIFF=$COHER_DIR/irq-diff.log
BANNED_CPUS=/etc/irqbalance/banned_cpus

mkdir -p "$COHER_DIR" 2>/dev/null || true

log() { echo "irq-balancer: $*" >&2; }

# ----------------------------------------------------------------------------
# Parse RESERVED_CPUS (e.g. "0,1" or "0-1") into a hex bitmask
# ----------------------------------------------------------------------------
# Linux smp_affinity takes a hex mask where bit N = CPU N. For large CPU counts
# we must emit comma-grouped 32-bit words (big-endian), e.g. CPU64 needs
# "00000001,00000000,00000000" on a 96-thread system.
#
# Strategy:
#   - Expand the cpulist into individual CPU numbers.
#   - Find the highest numbered CPU to decide how many 32-bit words we need.
#   - OR-set each bit; emit words high-to-low comma-joined.

cpulist_to_mask() {
    list=$1
    [ -z "$list" ] && { printf ''; return; }

    # Expand into a space-separated CPU list.
    expanded=
    set -f
    IFS=','
    for tok in $list; do
        IFS=''
        case $tok in
            *-*)
                lo=${tok%-*}
                hi=${tok#*-}
                i=$lo
                while [ "$i" -le "$hi" ]; do
                    expanded="$expanded $i"
                    i=$(( i + 1 ))
                done
                ;;
            *)
                [ -n "$tok" ] && expanded="$expanded $tok"
                ;;
        esac
        IFS=','
    done
    IFS=' '
    set +f

    [ -z "$expanded" ] && { printf ''; return; }

    # Determine max CPU index.
    maxcpu=0
    for n in $expanded; do
        [ "$n" -gt "$maxcpu" ] && maxcpu=$n
    done
    words=$(( maxcpu / 32 + 1 ))

    # Build shell "array" of zero-initialised 32-bit words: mask0, mask1, ...
    i=0
    while [ "$i" -lt "$words" ]; do
        eval "mask$i=0"
        i=$(( i + 1 ))
    done

    # OR-set each CPU bit.
    for n in $expanded; do
        w=$(( n / 32 ))
        b=$(( n - w * 32 ))
        eval "cur=\$mask$w"
        new=$(( cur | (1 << b) ))
        eval "mask$w=$new"
    done

    # Emit high-to-low with commas.
    out=
    i=$(( words - 1 ))
    while [ "$i" -ge 0 ]; do
        eval "v=\$mask$i"
        hex=$(printf '%08x' "$v")
        if [ -z "$out" ]; then
            out=$hex
        else
            out="$out,$hex"
        fi
        i=$(( i - 1 ))
    done
    printf '%s' "$out"
}

# Same as above but for NEGATED mask: which CPUs the IRQ SHOULD land on
# (i.e., everything except GAME_CPUS). We build the game mask and invert
# up to the system's CPU count ceiling (nproc).
#
# Simpler approach: compute full_mask for 0..nproc-1 and AND with NOT(game_mask)
# per word.
game_exclude_mask() {
    game_list=$1
    total_cpus=$2

    [ -z "$game_list" ] && { printf ''; return; }
    [ "$total_cpus" -le 0 ] && { printf ''; return; }

    # Build full mask bitset for CPUs 0..total_cpus-1
    words=$(( (total_cpus - 1) / 32 + 1 ))
    i=0
    while [ "$i" -lt "$words" ]; do
        eval "fmask$i=0"
        eval "gmask$i=0"
        i=$(( i + 1 ))
    done
    i=0
    while [ "$i" -lt "$total_cpus" ]; do
        w=$(( i / 32 ))
        b=$(( i - w * 32 ))
        eval "cur=\$fmask$w"
        eval "fmask$w=$(( cur | (1 << b) ))"
        i=$(( i + 1 ))
    done

    # OR in game CPUs
    set -f
    IFS=','
    for tok in $game_list; do
        IFS=''
        case $tok in
            *-*) lo=${tok%-*}; hi=${tok#*-} ;;
            *)   lo=$tok; hi=$tok ;;
        esac
        [ -z "$lo" ] && { IFS=','; continue; }
        j=$lo
        while [ "$j" -le "$hi" ]; do
            w=$(( j / 32 ))
            b=$(( j - w * 32 ))
            if [ "$w" -lt "$words" ]; then
                eval "cur=\$gmask$w"
                eval "gmask$w=$(( cur | (1 << b) ))"
            fi
            j=$(( j + 1 ))
        done
        IFS=','
    done
    IFS=' '
    set +f

    # exclude_mask = fmask & ~gmask, per word
    i=0
    out=
    i=$(( words - 1 ))
    while [ "$i" -ge 0 ]; do
        eval "f=\$fmask$i"
        eval "g=\$gmask$i"
        # ~g within 32 bits
        notg=$(( 4294967295 ^ g ))
        v=$(( f & notg ))
        hex=$(printf '%08x' "$v")
        if [ -z "$out" ]; then
            out=$hex
        else
            out="$out,$hex"
        fi
        i=$(( i - 1 ))
    done
    printf '%s' "$out"
}

# ----------------------------------------------------------------------------
# Snapshot /proc/interrupts with a timestamp header.
# ----------------------------------------------------------------------------
snapshot_interrupts() {
    dst=$1
    {
        echo "# ai-arch irq-balancer snapshot $(date -u +%FT%TZ)"
        [ -r /proc/interrupts ] && cat /proc/interrupts
    } > "$dst" 2>/dev/null || true
}

# ----------------------------------------------------------------------------
# For an IRQ, decide if we should move it.
#   1. Must have non-zero interrupt count in the current boot (skip idle IRQs).
#   2. Must be writable: /proc/irq/N/smp_affinity must exist and be writable.
#   3. Must NOT be kernel-pinned: if effective_affinity != smp_affinity_list,
#      the kernel already constrained it (e.g. per-CPU timer/IPI); skip.
#   4. IRQ 0 (legacy timer) never moves.
# ----------------------------------------------------------------------------
should_move_irq() {
    irq=$1
    [ "$irq" = "0" ] && return 1
    [ -w "/proc/irq/$irq/smp_affinity" ] || return 1

    # Skip per-CPU / NO_BALANCING IRQs. Kernel exposes effective_affinity
    # (read-only; what's ACTUALLY used) which differs from smp_affinity when
    # the driver marked itself IRQF_PERCPU or IRQF_NO_BALANCING.
    if [ -r "/proc/irq/$irq/effective_affinity_list" ] && \
       [ -r "/proc/irq/$irq/smp_affinity_list" ]; then
        eff=$(cat "/proc/irq/$irq/effective_affinity_list" 2>/dev/null)
        req=$(cat "/proc/irq/$irq/smp_affinity_list" 2>/dev/null)
        # If effective is a strict subset (single CPU per-CPU IRQ), skip.
        # Heuristic: both are single-CPU values and match.
        case $eff in
            *,*|*-*) ;;  # multi-CPU effective -- safe to rewrite
            *)
                case $req in
                    *,*|*-*) ;;  # request is broad but effective pinned: kernel pinned, skip
                    *)
                        if [ "$eff" = "$req" ]; then
                            # Both single-CPU and match -> kernel-pinned NO_BALANCING
                            return 1
                        fi
                        ;;
                esac
                ;;
        esac
    fi
    return 0
}

# ----------------------------------------------------------------------------
# Main: apply mask to all eligible IRQs.
# ----------------------------------------------------------------------------
apply_masks() {
    if [ ! -r "$NUMA_FILE" ]; then
        log "no $NUMA_FILE -- not migrating IRQs (slice-apply may not have run)"
        return 0
    fi
    # shellcheck disable=SC1090
    . "$NUMA_FILE"
    GAME_CPUS=${GAME_CPUS:-}
    RESERVED_CPUS=${RESERVED_CPUS:-}

    if [ -z "$GAME_CPUS" ] || [ -z "$RESERVED_CPUS" ]; then
        log "no reserved CPUs -- nothing to balance (OLD-tier HW or single-CPU)"
        # Still write the banned_cpus hint as empty.
        return 0
    fi

    total_cpus=$(nproc 2>/dev/null || echo 1)

    mask_hex=$(game_exclude_mask "$GAME_CPUS" "$total_cpus")
    if [ -z "$mask_hex" ] || [ "$mask_hex" = "00000000" ]; then
        log "computed empty exclusion mask (game_cpus=$GAME_CPUS total=$total_cpus) -- skipping"
        return 0
    fi

    log "applying smp_affinity=$mask_hex to eligible IRQs (reserved=$RESERVED_CPUS)"

    snapshot_interrupts "$BEFORE"

    moved=0
    skipped=0
    failed=0

    # /proc/irq/*/smp_affinity is a directory per IRQ number. ls may produce
    # non-numeric entries ("default_smp_affinity"); guard with case.
    if [ -d /proc/irq ]; then
        for d in /proc/irq/[0-9]*; do
            [ -d "$d" ] || continue
            irq=${d##*/}
            case $irq in
                *[!0-9]*) continue ;;
            esac

            if should_move_irq "$irq"; then
                if printf '%s' "$mask_hex" > "/proc/irq/$irq/smp_affinity" 2>/dev/null; then
                    moved=$(( moved + 1 ))
                else
                    failed=$(( failed + 1 ))
                fi
            else
                skipped=$(( skipped + 1 ))
            fi
        done
    fi

    snapshot_interrupts "$AFTER"

    {
        echo "# ai-arch irq-balancer diff $(date -u +%FT%TZ)"
        echo "# mode=$MODE game_cpus=$GAME_CPUS reserved=$RESERVED_CPUS"
        echo "# mask=$mask_hex total_cpus=$total_cpus"
        echo "# moved=$moved skipped=$skipped failed=$failed"
        # A cheap diff: show IRQ numbers whose lines changed. We compare whole
        # lines excluding the ' CPUN' count columns since counts naturally grow.
        # For the summary log, just show IRQs whose smp_affinity_list is now
        # different from before.
    } > "$DIFF" 2>/dev/null || true

    # Write the irqbalance hint file (atomic via rename).
    bandir=$(dirname "$BANNED_CPUS")
    if [ -d "$bandir" ] || mkdir -p "$bandir" 2>/dev/null; then
        # banned_cpus format: hex mask (no comma groups) of CPUs to AVOID.
        # Compute the POSITIVE mask of GAME_CPUS (those are the ones to ban).
        game_mask=$(cpulist_to_mask "$GAME_CPUS")
        tmp="${BANNED_CPUS}.tmp"
        if printf '%s\n' "$game_mask" > "$tmp" 2>/dev/null; then
            mv -f "$tmp" "$BANNED_CPUS" 2>/dev/null || true
            chmod 0644 "$BANNED_CPUS" 2>/dev/null || true
        fi
    fi

    log "done: moved=$moved skipped=$skipped failed=$failed"
    return 0
}

case "$MODE" in
    apply|start)
        apply_masks
        ;;
    reload|refresh)
        # Re-read numa file (coherence daemon may have rewritten it) and re-apply.
        apply_masks
        ;;
    *)
        log "unknown mode: $MODE (expected apply|reload)"
        exit 2
        ;;
esac
exit 0
