#!/bin/bash
# ai-arch/fstab-optimize.sh -- installer-side filesystem defaults library.
#
# Sourced (or invoked) by the disk installer (ai-installer) after pacstrap
# and genfstab have produced a raw /etc/fstab in the target root.  Rewrites
# mount options for better performance + safety, adds tmp.mount tmpfs cap,
# propagates I/O-scheduler udev rules, sets swappiness / THP for the
# installed system, and -- when zram is preferred over a real swapfile --
# copies the live-ISO zram-generator config instead of relying on a
# partition-based swap.
#
# USAGE:
#   source /usr/lib/ai-arch/fstab-optimize.sh
#   fstab_optimize_all <target_mount>
#
# or selectively:
#   fstab_rewrite_options <target_mount>         # rewrite mount opts
#   fstab_write_tmp_mount <target_mount>         # tmpfs /tmp cap
#   fstab_copy_udev_rules <target_mount>         # scheduler/readahead
#   fstab_set_swappiness <target_mount> <ram_mb> # sysctl value
#   fstab_set_thp_cmdline <target_mount>         # GRUB cmdline
#   fstab_copy_zram_config <target_mount>        # zram-generator.conf
#
# Design constraints:
#   - Never change UUID= fields produced by genfstab.
#   - Detect FS type per-entry via the third fstab column (no blkid calls
#     on the target -- we trust genfstab output).
#   - HW profile is read from /run/ai-arch-hw-profile if present (produced
#     by ai-hw-detect.sh).  Falls back to live-time detection.
#   - Every tuning logs "[+] fstab-optimize: ..." so the installer captures
#     it in the Gtk log view.
#   - All writes are idempotent: running twice on the same target is safe.

set -u
# Don't set -e so the installer can continue even if one tuning fails.
# Each function returns 0 unless something catastrophic happens.

# ---------------------------------------------------------------------------
# Logging -- matches hw-detect.sh / low-ram-services.sh style
# ---------------------------------------------------------------------------
_fo_log() { printf '[+] fstab-optimize: %s\n' "$*"; }
_fo_warn() { printf '[!] fstab-optimize: %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Profile loading
# ---------------------------------------------------------------------------
# Populates globals: FO_PROFILE, FO_MEM_MB, FO_ROOT_ROTATIONAL, FO_CPU_CORES.
# Falls back to live-time /proc reads if no profile file exists yet.
_fo_load_profile() {
    FO_PROFILE="${FO_PROFILE:-DEFAULT}"
    FO_MEM_MB="${FO_MEM_MB:-0}"
    FO_ROOT_ROTATIONAL="${FO_ROOT_ROTATIONAL:-?}"
    FO_CPU_CORES="${FO_CPU_CORES:-1}"

    if [ -r /run/ai-arch-hw-profile ]; then
        # shellcheck disable=SC1091
        . /run/ai-arch-hw-profile 2>/dev/null || true
        FO_PROFILE="${PROFILE:-$FO_PROFILE}"
        FO_MEM_MB="${MEM_MB:-$FO_MEM_MB}"
        FO_ROOT_ROTATIONAL="${ROOT_ROTATIONAL:-$FO_ROOT_ROTATIONAL}"
        FO_CPU_CORES="${CPU_CORES:-$FO_CPU_CORES}"
    fi

    # Fallbacks if profile wasn't populated
    if [ "$FO_MEM_MB" -le 0 ] 2>/dev/null; then
        local mem_kb
        mem_kb=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 0)
        FO_MEM_MB=$(( mem_kb / 1024 ))
    fi
    if [ "${FO_CPU_CORES}" -le 0 ] 2>/dev/null; then
        FO_CPU_CORES=$(nproc 2>/dev/null || echo 1)
    fi
}

# ---------------------------------------------------------------------------
# Per-partition rotational detection (for the INSTALL target, not live root).
# Takes device path like /dev/nvme0n1p2 and returns 0/1/? via stdout.
# ---------------------------------------------------------------------------
_fo_dev_is_rotational() {
    local dev="$1" name blk
    name=${dev##*/}
    blk=$(lsblk -no PKNAME "$dev" 2>/dev/null | head -1)
    [ -z "$blk" ] && blk="$name"
    if [ -r "/sys/block/$blk/queue/rotational" ]; then
        cat "/sys/block/$blk/queue/rotational" 2>/dev/null
        return 0
    fi
    echo "?"
    return 0
}

# ---------------------------------------------------------------------------
# NVMe detection by device path
# ---------------------------------------------------------------------------
_fo_dev_is_nvme() {
    case "${1##*/}" in
        nvme*) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Mount-option builder -- produces the recommended options list for a
# filesystem type, mountpoint, and rotational class.
#
# Args: <fstype> <mountpoint> <rotational: 0|1|?> <is_nvme: 0|1>
# Echo: comma-separated options string (no leading/trailing comma).
# ---------------------------------------------------------------------------
_fo_build_options() {
    local fstype="$1" mp="$2" rot="$3" nvme="$4"
    local opts="defaults,noatime,nodiratime"

    case "$fstype" in
        btrfs)
            # compress=zstd:3 is the speed/ratio sweet spot.
            # space_cache=v2 is the modern default; older kernels still accept.
            # discard=async: non-blocking TRIM (kernel >=5.6) prevents fio stalls.
            # autodefrag: ONLY on HDD -- destructive on SSD/NVMe (write amp).
            opts="defaults,noatime,compress=zstd:3,space_cache=v2"
            if [ "$rot" = "0" ] || [ "$nvme" = "1" ]; then
                opts="${opts},discard=async,ssd"
                # ssd_spread helps on cheap SSDs with poor FTL
                [ "$nvme" = "0" ] && opts="${opts},ssd_spread"
            else
                # HDD: autodefrag mitigates random-write fragmentation
                opts="${opts},autodefrag"
            fi
            ;;
        ext4)
            # commit=60: flush journal every 60s instead of 5s -- saves ~20-30%
            #            writes on read-heavy workloads.  Data-ordered mode
            #            (default) still syncs data before metadata, so the
            #            only risk is 55s more of lost un-synced work on a
            #            power cut -- acceptable for a desktop.
            # barrier=1 is default; we keep it for safety on consumer SSDs.
            opts="${opts},commit=60"
            # dioread_nolock helps concurrent O_DIRECT reads (databases,
            # game asset streaming); harmless on light workloads.
            opts="${opts},dioread_nolock"
            # NOTE: journal_async_commit is NOT added -- it risks filesystem
            # corruption on power loss without journal_checksum.
            ;;
        xfs)
            opts="${opts},logbsize=256k,allocsize=64k"
            ;;
        vfat)
            # EFI partition: basic safety flags, codepage 437 + UTF-8 names.
            # noatime is still useful; FAT writes directory entries for atime.
            # nosuid + nodev for security (block setuid / device-node abuse
            # via a rogue USB-mounted EFI).  NOT noexec -- grub-install and
            # efibootmgr write+execute shim binaries during bootloader
            # updates, and noexec would break them.
            opts="umask=0077,shortname=mixed,utf8=1,errors=remount-ro,nosuid,nodev"
            ;;
        swap)
            opts="defaults"
            ;;
        *)
            # Unknown FS: trust genfstab but add noatime if not there.
            return 1
            ;;
    esac

    # Mount-point specific overlays (only for data filesystems)
    case "$fstype" in
        btrfs|ext4|xfs)
            case "$mp" in
                /home)
                    # User data: no setuid/device nodes
                    opts="${opts},nodev,nosuid"
                    ;;
                /boot|/boot/efi)
                    # No need to worry about HDD/SSD class for boot (tiny)
                    opts="${opts},nosuid,nodev,noexec"
                    ;;
                /var/log)
                    opts="${opts},nodev,nosuid,noexec"
                    ;;
                /var|/var/cache|/var/tmp|/tmp)
                    opts="${opts},nodev,nosuid"
                    ;;
                /srv|/opt)
                    opts="${opts},nodev"
                    ;;
            esac
            ;;
    esac

    printf '%s\n' "$opts"
}

# ---------------------------------------------------------------------------
# Rewrite /etc/fstab mount options in-place.
#
# Args: <target_mount>  (e.g. /mnt/ai-install)
# ---------------------------------------------------------------------------
fstab_rewrite_options() {
    local target="${1:-/mnt/ai-install}"
    local fstab="$target/etc/fstab"

    if [ ! -f "$fstab" ]; then
        _fo_warn "no fstab at $fstab -- skipping rewrite"
        return 1
    fi

    _fo_load_profile

    # Detect rotational class of the target root device (for choosing SSD
    # vs HDD tuning).  We resolve the root mount's source through findmnt.
    local root_src root_is_rot root_is_nvme
    root_src=$(findmnt -no SOURCE "$target" 2>/dev/null || true)
    if [ -n "$root_src" ]; then
        root_is_rot=$(_fo_dev_is_rotational "$root_src")
        _fo_dev_is_nvme "$root_src" && root_is_nvme=1 || root_is_nvme=0
    else
        root_is_rot="$FO_ROOT_ROTATIONAL"
        root_is_nvme=0
    fi

    _fo_log "profile=$FO_PROFILE mem=${FO_MEM_MB}MB rotational=$root_is_rot nvme=$root_is_nvme"

    # Back up the original fstab before rewriting
    if [ ! -f "${fstab}.pre-optimize" ]; then
        cp -a "$fstab" "${fstab}.pre-optimize" 2>/dev/null || true
    fi

    # Build new fstab: process each data line, preserve comments.
    local tmp
    tmp=$(mktemp -p "$target/etc" .fstab.XXXXXX 2>/dev/null) || \
        tmp=$(mktemp 2>/dev/null) || { _fo_warn "mktemp failed"; return 1; }

    # Header comment
    {
        echo "# /etc/fstab -- optimized by ai-arch fstab-optimize.sh"
        echo "# HW profile: $FO_PROFILE / RAM: ${FO_MEM_MB}MB / target-rotational: $root_is_rot"
        echo "# Original saved at ${fstab}.pre-optimize"
        echo "#"
        echo "# <device>  <mountpoint>  <fstype>  <options>  <dump>  <pass>"
        echo
    } > "$tmp"

    # Stream the existing fstab.  Pass comments through verbatim; rewrite
    # option column on real entries.
    local line spec mp fstype opts dump pass new_opts
    while IFS= read -r line || [ -n "$line" ]; do
        # Comment / blank: pass through (unless it's our own header which
        # we skip to avoid duplication).
        case "$line" in
            ""|"#"*)
                case "$line" in
                    "# /etc/fstab -- optimized by ai-arch"*|\
                    "# HW profile:"*|"# Original saved at"*|\
                    "# <device>"*)
                        continue
                        ;;
                esac
                printf '%s\n' "$line" >> "$tmp"
                continue
                ;;
        esac

        # Parse data line (6 whitespace-separated fields)
        # shellcheck disable=SC2086
        set -- $line
        if [ "$#" -lt 4 ]; then
            printf '%s\n' "$line" >> "$tmp"
            continue
        fi
        spec="$1"; mp="$2"; fstype="$3"; opts="$4"
        dump="${5:-0}"; pass="${6:-0}"

        # Keep swap as-is except normalize options
        if [ "$fstype" = "swap" ]; then
            printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$spec" "$mp" "$fstype" "defaults" "$dump" "$pass" >> "$tmp"
            _fo_log "  swap: $spec  defaults"
            continue
        fi

        # Determine rot/nvme class per-device.  On a single-disk install all
        # non-swap partitions share the disk, but we resolve properly for
        # multi-disk installs.
        local dev_is_rot dev_is_nvme
        case "$spec" in
            UUID=*|LABEL=*|PARTUUID=*|PARTLABEL=*)
                local resolved
                resolved=$(blkid -l -o device -t "$spec" 2>/dev/null || true)
                if [ -n "$resolved" ]; then
                    dev_is_rot=$(_fo_dev_is_rotational "$resolved")
                    _fo_dev_is_nvme "$resolved" && dev_is_nvme=1 || dev_is_nvme=0
                else
                    dev_is_rot="$root_is_rot"; dev_is_nvme="$root_is_nvme"
                fi
                ;;
            /dev/*)
                dev_is_rot=$(_fo_dev_is_rotational "$spec")
                _fo_dev_is_nvme "$spec" && dev_is_nvme=1 || dev_is_nvme=0
                ;;
            *)
                dev_is_rot="$root_is_rot"; dev_is_nvme="$root_is_nvme"
                ;;
        esac

        new_opts=$(_fo_build_options "$fstype" "$mp" "$dev_is_rot" "$dev_is_nvme") \
            || new_opts=""
        if [ -z "$new_opts" ]; then
            # Unknown FS: at minimum add noatime if missing
            if ! printf '%s' "$opts" | grep -qw noatime; then
                new_opts="${opts},noatime"
            else
                new_opts="$opts"
            fi
        fi

        # Keep dump/pass columns from genfstab (it picks them correctly).
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$spec" "$mp" "$fstype" "$new_opts" "$dump" "$pass" >> "$tmp"
        _fo_log "  $mp ($fstype): $new_opts"
    done < "$fstab"

    # Install atomically
    mv -f "$tmp" "$fstab" 2>/dev/null || {
        _fo_warn "failed to replace $fstab"
        rm -f "$tmp" 2>/dev/null
        return 1
    }
    chmod 644 "$fstab" 2>/dev/null || true

    return 0
}

# ---------------------------------------------------------------------------
# Install tmpfs /tmp cap drop-in (40% RAM, 1M inode cap) matching live-ISO.
# Preserves the systemd default tmp.mount unit; we only add an override.
# ---------------------------------------------------------------------------
fstab_write_tmp_mount() {
    local target="${1:-/mnt/ai-install}"
    local dir="$target/etc/systemd/system/tmp.mount.d"

    mkdir -p "$dir" 2>/dev/null || { _fo_warn "mkdir $dir failed"; return 1; }

    # Escape the percent literal for systemd unit files: %% means 40%.
    cat > "$dir/size.conf" <<'TMPCONF'
# Installed by ai-arch fstab-optimize.sh -- cap /tmp at 40% RAM.
# See profile/airootfs/etc/systemd/system/tmp.mount.d/size.conf (live-ISO).
[Mount]
Options=mode=1777,strictatime,nosuid,nodev,size=40%%,nr_inodes=1m
TMPCONF
    chmod 644 "$dir/size.conf" 2>/dev/null || true

    # Ensure tmp.mount is actually enabled on the installed system.  On Arch
    # systemd ships the unit but does not enable it by default.  The
    # installer's arch-chroot step will call systemctl enable tmp.mount.
    _fo_log "tmp.mount drop-in installed (size=40%% nr_inodes=1m)"
    return 0
}

# ---------------------------------------------------------------------------
# Copy live-ISO udev rules into installed system.  These set the I/O
# scheduler (nvme->none, SATA SSD->mq-deadline, HDD->bfq) and readahead
# values as devices are hotplugged.
# ---------------------------------------------------------------------------
fstab_copy_udev_rules() {
    local target="${1:-/mnt/ai-install}"
    local src="/etc/udev/rules.d/60-ai-hw-fast-path.rules"
    local dst="$target/etc/udev/rules.d/60-ai-hw-fast-path.rules"

    if [ ! -f "$src" ]; then
        # Try the ISO profile copy too (when running from archiso chroot)
        for alt in \
            /run/archiso/airootfs/etc/udev/rules.d/60-ai-hw-fast-path.rules \
            /usr/share/ai-arch/udev/60-ai-hw-fast-path.rules; do
            if [ -f "$alt" ]; then src="$alt"; break; fi
        done
    fi

    if [ ! -f "$src" ]; then
        _fo_warn "udev rule source not found -- skipping I/O scheduler propagation"
        return 1
    fi

    mkdir -p "$target/etc/udev/rules.d" 2>/dev/null
    cp -f "$src" "$dst" 2>/dev/null || { _fo_warn "cp udev rules failed"; return 1; }
    chmod 644 "$dst" 2>/dev/null || true

    # Add a readahead rule (HDD 256 sectors, SSD 1024, NVMe 4096).  Kept
    # as a separate file so upstream refreshes don't clobber it.
    cat > "$target/etc/udev/rules.d/61-ai-readahead.rules" <<'READAHEAD'
# Readahead tuning installed by ai-arch fstab-optimize.sh.
# NVMe benefits from large readahead (low per-op overhead, high BW).
# SSDs want a middle ground.  HDDs want small to avoid seek penalty on
# random access patterns from modern workloads.
ACTION=="add|change", KERNEL=="nvme[0-9]*n[0-9]*", ATTR{bdi/read_ahead_kb}="2048"
ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/rotational}=="0", ATTR{bdi/read_ahead_kb}="512"
ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/rotational}=="1", ATTR{bdi/read_ahead_kb}="128"
READAHEAD
    chmod 644 "$target/etc/udev/rules.d/61-ai-readahead.rules" 2>/dev/null || true

    _fo_log "udev rules copied (scheduler + readahead)"
    return 0
}

# ---------------------------------------------------------------------------
# Set swappiness for the installed system.  Value depends on whether zram
# is in use (100 with zram -- since zram is much cheaper than disk swap)
# or disabled (10 -- standard desktop).
#
# Args: <target_mount> <using_zram: 1|0>
# ---------------------------------------------------------------------------
fstab_set_swappiness() {
    local target="${1:-/mnt/ai-install}"
    local zram="${2:-1}"
    local dir="$target/etc/sysctl.d"

    mkdir -p "$dir" 2>/dev/null || { _fo_warn "mkdir $dir failed"; return 1; }

    local val
    if [ "$zram" = "1" ]; then
        val=100
    else
        val=10
    fi

    # 50-ai-arch-boot.conf belongs to agent G; we install our own file so
    # we don't clobber their sysctls on subsequent runs.
    cat > "$dir/60-ai-fstab-vm.conf" <<SYSCTL
# Installer-side VM tuning (ai-arch fstab-optimize.sh).  Agent G owns
# /etc/sysctl.d/50-ai-arch-boot.conf; this file must NOT duplicate keys
# that 50-ai-arch-boot.conf sets.
#
# swappiness=$val was chosen because:
#   - zram active   => 100 (prefer compressed RAM swap over page reclaim)
#   - no zram       => 10  (desktop w/ plenty of free RAM)
# vfs_cache_pressure=50 keeps inode/dentry caches warm (fs metadata is
# hot on a desktop -- thousands of small reads per second in /home).
vm.swappiness = $val
vm.vfs_cache_pressure = 50
vm.dirty_background_ratio = 5
vm.dirty_ratio = 20
vm.dirty_expire_centisecs = 3000
SYSCTL
    chmod 644 "$dir/60-ai-fstab-vm.conf" 2>/dev/null || true

    _fo_log "swappiness=$val (zram=$zram), vfs_cache_pressure=50"
    return 0
}

# ---------------------------------------------------------------------------
# Propagate transparent_hugepage=madvise to GRUB cmdline on target.  This
# is safer than 'always' (avoids khugepaged thrash on small systems) and
# matches the live-ISO ai-hw-detect.sh setting.
# ---------------------------------------------------------------------------
fstab_set_thp_cmdline() {
    local target="${1:-/mnt/ai-install}"
    local grub="$target/etc/default/grub"

    if [ ! -f "$grub" ]; then
        _fo_warn "no $grub -- skipping THP cmdline patch"
        return 1
    fi

    # Only insert if not already present.  The installer already sets
    # GRUB_CMDLINE_LINUX_DEFAULT; we augment it.
    if grep -q 'transparent_hugepage=' "$grub"; then
        _fo_log "THP cmdline already present -- skipping"
        return 0
    fi

    # Use an awk rewrite so we preserve quoting exactly.
    local tmp
    tmp=$(mktemp -p "$target/etc/default" .grub.XXXXXX 2>/dev/null) || \
        tmp=$(mktemp 2>/dev/null) || return 1

    awk '
        /^GRUB_CMDLINE_LINUX_DEFAULT=/ {
            # Strip the closing quote, append THP+nowatchdog, re-close.
            # Match both "..." and ...
            if (match($0, /"[^"]*"/)) {
                pre  = substr($0, 1, RSTART)
                cur  = substr($0, RSTART+1, RLENGTH-2)
                post = substr($0, RSTART+RLENGTH-1)
                # Avoid double-adding
                if (cur !~ /transparent_hugepage=/) {
                    cur = cur " transparent_hugepage=madvise"
                }
                if (cur !~ /nowatchdog/) {
                    cur = cur " nowatchdog"
                }
                print pre cur post
                next
            }
        }
        { print }
    ' "$grub" > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }

    if [ -s "$tmp" ]; then
        mv -f "$tmp" "$grub" 2>/dev/null || { rm -f "$tmp"; return 1; }
        chmod 644 "$grub" 2>/dev/null || true
        _fo_log "GRUB cmdline: added transparent_hugepage=madvise nowatchdog"
    else
        rm -f "$tmp"
        _fo_warn "awk rewrite produced empty file -- left $grub untouched"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Copy zram-generator.conf to installed system.  Installer calls this iff
# the user opted out of a real swap partition OR if the system has enough
# RAM that zram alone suffices.  zram-generator is a systemd-shipped
# generator; no separate service needed -- just the config file.
# ---------------------------------------------------------------------------
fstab_copy_zram_config() {
    local target="${1:-/mnt/ai-install}"
    local src="/etc/systemd/zram-generator.conf"
    local dst="$target/etc/systemd/zram-generator.conf"

    if [ ! -f "$src" ]; then
        for alt in \
            /run/archiso/airootfs/etc/systemd/zram-generator.conf \
            /usr/share/ai-arch/systemd/zram-generator.conf; do
            if [ -f "$alt" ]; then src="$alt"; break; fi
        done
    fi

    if [ ! -f "$src" ]; then
        # Fall back to writing a known-good config inline
        cat > "$dst" <<'ZRAM'
# zram-generator installed by ai-arch fstab-optimize.sh (no live source found).
# Scales inversely with RAM: min(ram/2, 4GB).  zstd compressed.
[zram0]
zram-size = min(ram / 2, 4096)
compression-algorithm = zstd
swap-priority = 100
ZRAM
        chmod 644 "$dst" 2>/dev/null || true
        _fo_log "zram-generator.conf written (inline fallback)"
        return 0
    fi

    mkdir -p "$target/etc/systemd" 2>/dev/null
    cp -f "$src" "$dst" 2>/dev/null || { _fo_warn "zram copy failed"; return 1; }
    chmod 644 "$dst" 2>/dev/null || true
    _fo_log "zram-generator.conf copied from $src"
    return 0
}

# ---------------------------------------------------------------------------
# Swap strategy decision -- recommends whether to use zram-only, swapfile,
# or swap partition based on RAM tier and hibernation availability.
#
# Args: <ram_mb>
# Echo: one of "zram-only", "zram+swapfile", "swap-partition"
# ---------------------------------------------------------------------------
fstab_recommend_swap_strategy() {
    local ram_mb="${1:-0}"

    # <=4GB   -> zram is the single biggest memory multiplier; always use
    #            zram; skip real swap unless hibernation is on.
    # 4-16GB  -> zram + no real swap; most desktop workloads fit in RAM.
    # >16GB   -> zram still helps latency-sensitive apps, but if the user
    #            wants hibernation they need a >= RAM-sized swapfile.
    if [ "$ram_mb" -le 4096 ]; then
        echo "zram-only"
    elif [ "$ram_mb" -le 16384 ]; then
        echo "zram-only"
    else
        echo "zram+optional-swapfile"
    fi
}

# ---------------------------------------------------------------------------
# Apply ext4-specific tune2fs defaults to a freshly-formatted partition.
# Called by the installer AFTER mkfs.ext4 but BEFORE mounting.
#
# Args: <partition_device>   (e.g. /dev/nvme0n1p2)
# ---------------------------------------------------------------------------
fstab_ext4_tune() {
    local dev="${1:-}"
    [ -z "$dev" ] && return 1
    [ -b "$dev" ] || { _fo_warn "$dev is not a block device"; return 1; }

    # -e continue: remount-ro on errors is the default; continue is safer
    # for a desktop -- lets the user run fsck instead of losing the boot.
    # -o journal_data_ordered: make it explicit even though it's default.
    # -c 0 -i 0: disable time/count-based fsck triggers (systemd-fsck
    # handles periodic checks; annoying to delay boot by 10 minutes).
    tune2fs -e continue -c 0 -i 0 "$dev" 2>/dev/null || _fo_warn "tune2fs on $dev failed"

    _fo_log "ext4 tuned: $dev (errors=continue, no time/count fsck)"
    return 0
}

# ---------------------------------------------------------------------------
# Top-level orchestrator.  Called by the installer with the target mount
# and a few options.  Safe to call even if some pieces fail.
#
# Args:
#   $1 target mount (required)
#   $2 using_zram   (0 or 1, default 1)
# ---------------------------------------------------------------------------
fstab_optimize_all() {
    local target="${1:-/mnt/ai-install}"
    local using_zram="${2:-1}"

    _fo_load_profile

    _fo_log "=== optimizing filesystem defaults for $target ==="
    _fo_log "profile=$FO_PROFILE ram=${FO_MEM_MB}MB cores=$FO_CPU_CORES zram=$using_zram"

    fstab_rewrite_options "$target" || _fo_warn "fstab rewrite failed (non-fatal)"
    fstab_write_tmp_mount "$target" || _fo_warn "tmp.mount drop-in failed (non-fatal)"
    fstab_copy_udev_rules "$target" || _fo_warn "udev propagation failed (non-fatal)"
    fstab_set_swappiness "$target" "$using_zram" || _fo_warn "swappiness failed (non-fatal)"
    fstab_set_thp_cmdline "$target" || _fo_warn "THP cmdline failed (non-fatal)"

    if [ "$using_zram" = "1" ]; then
        fstab_copy_zram_config "$target" || _fo_warn "zram copy failed (non-fatal)"
    fi

    _fo_log "=== fstab optimization complete ==="
    return 0
}

# ---------------------------------------------------------------------------
# Invoked directly? Run orchestrator with $@ as args.  Sourced? No-op.
# ---------------------------------------------------------------------------
# shellcheck disable=SC2128
if [ "${BASH_SOURCE:-$0}" = "$0" ]; then
    fstab_optimize_all "$@"
fi
