#!/bin/bash
# ai-arch/hw-detect.sh -- central hardware profiler for AI Arch Linux.
#
# Runs early during boot (ordered After=systemd-modules-load, Before=display-
# manager) and classifies the host into one of three profiles:
#
#   OLD     -- Pentium 4 / Core 2 era, <=2 GB RAM, spinning disk, legacy BIOS,
#              or pre-Kepler NVIDIA.  Tuned for minimum resource use.
#   NEW     -- AVX2 / AVX-512 CPU, 8+ GB RAM, NVMe root, UEFI boot.
#              Tuned for parallel systemd, aggressive readahead, GPU compositing.
#   DEFAULT -- Anything in between (most laptops / typical desktops).
#
# Output: writes /run/ai-arch-hw-profile and /etc/ai-arch-hw-profile so that
# later systemd units (display manager, ai-control, firewall) can branch
# their own tuning without re-doing the probe.
#
# IMPORTANT: this script is IDEMPOTENT and FAILSAFE -- any error short-
# circuits to DEFAULT.  It must never prevent boot.

set -u
set +e

PROFILE="DEFAULT"
REASONS=()
PROFILE_FILE_RUN="/run/ai-arch-hw-profile"
PROFILE_FILE_ETC="/etc/ai-arch-hw-profile"

# --- Memory (single biggest discriminator) -------------------------------
MEM_KB=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 0)
MEM_MB=$(( MEM_KB / 1024 ))

# --- CPU features ---------------------------------------------------------
CPU_FLAGS=$(awk '/^flags\b/ {print; exit}' /proc/cpuinfo 2>/dev/null)
CPU_CORES=$(nproc 2>/dev/null || echo 1)

has_flag() { printf '%s' "$CPU_FLAGS" | grep -qw "$1"; }

HAS_AVX2=0; has_flag avx2 && HAS_AVX2=1
HAS_AVX512=0; has_flag avx512f && HAS_AVX512=1
HAS_SSE42=0; has_flag sse4_2 && HAS_SSE42=1

# --- Boot firmware (UEFI vs legacy BIOS) ---------------------------------
FIRMWARE="bios"
[ -d /sys/firmware/efi ] && FIRMWARE="uefi"

# --- Root device rotational vs SSD ---------------------------------------
# We stat the device that /  (or / on the live overlay) is backed by.  For
# live ISO this is usually the USB drive, so we additionally check /run/archiso
# to find the real boot media.
ROOT_ROTATIONAL="?"
detect_rotational() {
    local dev devname blk
    # Prefer /run/archiso/bootmnt on live systems; else the backing of /
    if [ -d /run/archiso/bootmnt ]; then
        dev=$(findmnt -no SOURCE /run/archiso/bootmnt 2>/dev/null)
    else
        dev=$(findmnt -no SOURCE / 2>/dev/null)
    fi
    [ -z "$dev" ] && return
    devname=${dev##*/}
    # Resolve partition -> parent block device
    blk=$(lsblk -no PKNAME "$dev" 2>/dev/null | head -1)
    [ -z "$blk" ] && blk="$devname"
    if [ -r "/sys/block/$blk/queue/rotational" ]; then
        ROOT_ROTATIONAL=$(cat "/sys/block/$blk/queue/rotational")
    fi
}
detect_rotational

# --- GPU detection --------------------------------------------------------
# Identify primary GPU via lspci; fall back to reading /sys/class/drm
GPU_VENDOR="unknown"
GPU_OLD_NVIDIA=0    # 1 if a pre-Kepler NVIDIA card is present
GPU_LINE=$(lspci -nnk 2>/dev/null | grep -E 'VGA|3D|Display' | head -1)
if printf '%s' "$GPU_LINE" | grep -qi nvidia; then
    GPU_VENDOR="nvidia"
    # Known old PCI IDs (GT218 family: NVS 3100M, GeForce 210/310/315)
    # Device IDs: 0a20..0a2d (GT218), 0ca3..0cb1 (G92-based Quadro FX)
    if printf '%s' "$GPU_LINE" | grep -qiE '\[10de:(0a[0-9a-f]{2}|0b[0-9a-f]{2}|0c[0-9a-f]{2}|0d[0-9a-f]{2})\]'; then
        GPU_OLD_NVIDIA=1
    fi
elif printf '%s' "$GPU_LINE" | grep -qi intel; then
    GPU_VENDOR="intel"
elif printf '%s' "$GPU_LINE" | grep -qiE 'amd|ati|radeon'; then
    GPU_VENDOR="amd"
fi

# --- DMI / SMBIOS model ---------------------------------------------------
DMI_VENDOR=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo unknown)
DMI_MODEL=$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo unknown)

# --- Classification rules ------------------------------------------------
# OLD if any of:
#   - <= 2 GB RAM
#   - no SSE4.2 (pre-Nehalem / pre-Core2 2007)
#   - legacy BIOS AND <= 4 GB RAM AND rotational root AND 2 or fewer cores
#   - pre-Kepler NVIDIA (GT218 family)
if [ "$MEM_MB" -le 2048 ]; then
    PROFILE="OLD"; REASONS+=("ram<=2GB (${MEM_MB} MB)")
fi
if [ "$HAS_SSE42" -eq 0 ]; then
    PROFILE="OLD"; REASONS+=("no-sse4.2")
fi
if [ "$GPU_OLD_NVIDIA" -eq 1 ]; then
    PROFILE="OLD"; REASONS+=("pre-kepler-nvidia")
fi
if [ "$FIRMWARE" = "bios" ] && [ "$MEM_MB" -le 4096 ] && \
   [ "$ROOT_ROTATIONAL" = "1" ] && [ "$CPU_CORES" -le 2 ]; then
    PROFILE="OLD"; REASONS+=("legacy-bios+rotational+<=2core")
fi

# NEW if ALL of:
#   - UEFI firmware
#   - >= 8 GB RAM
#   - AVX2 (Haswell+ 2013 / Zen+ 2018)
#   - non-rotational (or unknown, which is most VM cases)
#   - 4+ cores
if [ "$PROFILE" = "DEFAULT" ] && \
   [ "$FIRMWARE" = "uefi" ] && \
   [ "$MEM_MB" -ge 8192 ] && \
   [ "$HAS_AVX2" -eq 1 ] && \
   [ "$ROOT_ROTATIONAL" != "1" ] && \
   [ "$CPU_CORES" -ge 4 ]; then
    PROFILE="NEW"
    [ "$HAS_AVX512" -eq 1 ] && REASONS+=("avx-512") || REASONS+=("avx2")
    REASONS+=("mem=${MEM_MB}MB" "cores=${CPU_CORES}" "ssd" "uefi")
fi

# --- Apply profile-specific tunings ---------------------------------------
# These are best-effort; every write is guarded with 2>/dev/null.

# CPU governor: OLD -> ondemand (save power, lower thermals), NEW -> schedutil
# (modern kernel default, superior for AVX-heavy workloads), DEFAULT -> keep
# whatever amd-pstate-performance.service or BIOS set.
set_governor() {
    local gov=$1 f
    for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        [ -w "$f" ] && printf '%s' "$gov" > "$f" 2>/dev/null
    done
}
case "$PROFILE" in
    OLD)  set_governor ondemand ;;
    NEW)  set_governor schedutil ;;
esac

# Transparent huge pages: OLD -> madvise (reduce khugepaged churn),
# NEW -> madvise (default sensible); never 'always' because it hurts latency
echo madvise > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null
echo defer+madvise > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null

# I/O scheduler: OLD rotational -> bfq (best fairness on HDD),
#                NEW nvme       -> none (NVMe hw queues), SATA SSD -> mq-deadline
set_scheduler() {
    local dev sched
    for dev in /sys/block/*/queue/scheduler; do
        [ -w "$dev" ] || continue
        # Walk back up to find parent block device name
        local blk="${dev%/queue/scheduler}"
        blk="${blk##*/}"
        # Decide per-device
        if [ -r "/sys/block/$blk/queue/rotational" ]; then
            local rot
            rot=$(cat "/sys/block/$blk/queue/rotational")
            if [ "$rot" = "1" ]; then
                sched="bfq"
            elif [[ "$blk" == nvme* ]]; then
                sched="none"
            else
                sched="mq-deadline"
            fi
            # grep for availability before writing; kernel may not have bfq
            if grep -qw "$sched" "$dev"; then
                printf '%s' "$sched" > "$dev" 2>/dev/null
            fi
        fi
    done
}
set_scheduler

# NVMe polling tuning (NEW HW): enables hybrid polling for low-latency syscalls
if [ "$PROFILE" = "NEW" ]; then
    for q in /sys/block/nvme*/queue/io_poll; do
        [ -w "$q" ] && echo 1 > "$q" 2>/dev/null
    done
    for q in /sys/block/nvme*/queue/io_poll_delay; do
        [ -w "$q" ] && echo 0 > "$q" 2>/dev/null
    done
fi

# Swappiness: OLD -> 60 (aggressive, small systems lean on swap),
#             NEW -> 10 (keep data hot in RAM)
case "$PROFILE" in
    OLD) echo 60 > /proc/sys/vm/swappiness 2>/dev/null ;;
    NEW) echo 10 > /proc/sys/vm/swappiness 2>/dev/null ;;
esac

# --- Remove nouveau-legacy quirk on Maxwell+ cards -----------------------
# The live ISO ships /etc/modprobe.d/nouveau-legacy.conf with noaccel=1 to
# keep GT218 stable. On a modern NVIDIA host this cripples 3D; remove it.
if [ "$GPU_VENDOR" = "nvidia" ] && [ "$GPU_OLD_NVIDIA" -eq 0 ]; then
    [ -f /etc/modprobe.d/nouveau-legacy.conf ] && \
        mv /etc/modprobe.d/nouveau-legacy.conf /etc/modprobe.d/nouveau-legacy.conf.disabled 2>/dev/null
fi

# --- Write profile report -------------------------------------------------
mkdir -p /run
{
    echo "# AI Arch hardware profile -- written by ai-hw-detect.service"
    echo "PROFILE=$PROFILE"
    echo "MEM_MB=$MEM_MB"
    echo "CPU_CORES=$CPU_CORES"
    echo "CPU_HAS_AVX2=$HAS_AVX2"
    echo "CPU_HAS_AVX512=$HAS_AVX512"
    echo "CPU_HAS_SSE42=$HAS_SSE42"
    echo "FIRMWARE=$FIRMWARE"
    echo "ROOT_ROTATIONAL=$ROOT_ROTATIONAL"
    echo "GPU_VENDOR=$GPU_VENDOR"
    echo "GPU_OLD_NVIDIA=$GPU_OLD_NVIDIA"
    echo "DMI_VENDOR=$DMI_VENDOR"
    echo "DMI_MODEL=$DMI_MODEL"
    echo "REASONS=${REASONS[*]:-none}"
} > "$PROFILE_FILE_RUN" 2>/dev/null

# Mirror to /etc on installed systems only (squashfs is read-only on live ISO)
if [ -w /etc ] && ! mountpoint -q /etc 2>/dev/null && [ ! -L /etc ]; then
    cp -f "$PROFILE_FILE_RUN" "$PROFILE_FILE_ETC" 2>/dev/null || true
fi

# --- HW-tiered sysctl application -----------------------------------------
# Invokes the companion script, which writes /run/sysctl.d/90-ai-arch-hw.conf
# and runs `sysctl --system`.  Ordering matters: the profile file must exist
# first (we just wrote it above), so sysctl-tune.sh can source it.
if [ -x /usr/lib/ai-arch/sysctl-tune.sh ]; then
    /usr/lib/ai-arch/sysctl-tune.sh || true
fi

# --- HW-tiered cgroup v2 slice application --------------------------------
# Writes /run/systemd/system/*.slice.d/10-hw.conf drop-ins so each slice's
# CPUQuota / MemoryHigh / MemoryMax / IOReadBandwidthMax scales with the
# detected hardware class (OLD uses tight caps, NEW uses 80% of RAM for
# pe-compat, DEFAULT sits in between).  Must run AFTER the profile file
# is written and AFTER sysctl-tune so memory accounting settings from
# sysctl are in place before systemd re-reads unit state.
if [ -x /usr/lib/ai-arch/slice-apply.sh ]; then
    /usr/lib/ai-arch/slice-apply.sh || true
fi

# --- GPU-tiered shader / DXVK / VKD3D env generation ----------------------
# Invokes gpu-profile.sh which probes vulkaninfo / lspci and writes
# /run/ai-arch/gpu-env.sh for /etc/profile.d/gpu-tuning.sh to source.
# Runs AFTER the profile file is written so GPU_VENDOR is available.
if [ -x /usr/lib/ai-arch/gpu-profile.sh ]; then
    /usr/lib/ai-arch/gpu-profile.sh || true
fi

# --- GT218 nouveau Xorg-conf removal --------------------------------------
# hw-detect.sh above already renames /etc/modprobe.d/nouveau-legacy.conf on
# Maxwell+ hosts; extend the quirk to the Xorg-conf drop-in so TearFree
# isn't forcibly off on modern NVIDIA boxes.
if [ "$GPU_VENDOR" = "nvidia" ] && [ "$GPU_OLD_NVIDIA" -eq 0 ]; then
    [ -f /etc/X11/xorg.conf.d/20-nouveau-legacy.conf ] && \
        mv /etc/X11/xorg.conf.d/20-nouveau-legacy.conf \
           /etc/X11/xorg.conf.d/20-nouveau-legacy.conf.disabled 2>/dev/null
fi

echo "ai-hw-detect: profile=$PROFILE reasons=${REASONS[*]:-default}"
exit 0
