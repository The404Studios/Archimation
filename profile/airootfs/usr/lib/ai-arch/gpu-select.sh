#!/bin/bash
# ai-arch/gpu-select.sh -- PRIME GPU render-node selector.
#
# Invoked by launchers (pe-launch-wrapper.sh, game wrappers, or manually) to
# pick the right /dev/dri device for a workload and set the necessary env
# variables BEFORE exec'ing the target binary.
#
# Design:
#   1. Enumerate /dev/dri/card* and identify vendor + boot_vga flag.
#   2. Prefer a non-boot_vga (dGPU) for render offload if present.
#   3. Emit a series of `export X=Y` lines on stdout so callers can:
#        eval "$(/usr/lib/ai-arch/gpu-select.sh render)"
#      or source it directly:
#        . /usr/lib/ai-arch/gpu-select.sh render
#   4. Modes:
#        render   -- pick best render node + set PRIME offload vars (default)
#        display  -- pick boot_vga device for display surface
#        compute  -- pick renderD node with largest VRAM (for LLM/AI daemon)
#        list     -- print one-line-per-device summary (no exports)
#        software -- force LLVMpipe fallback (for totally broken GPU HW)
#
# Dual-HW rule:
#   - Old HW (GT218, Intel GMA gen<8) with no Vulkan: sets LIBGL_ALWAYS_SOFTWARE=1
#     and emits GPU_TIER=software so AI daemon knows not to dispatch GPU work.
#   - New HW (RTX, RDNA3): emits DRI_PRIME=1 + __NV_PRIME_RENDER_OFFLOAD=1 +
#     VK_ICD_FILENAMES pinned to the dGPU.
#   - Hybrid (iGPU+dGPU): DRI_PRIME=1 offloads to dGPU while iGPU composites.
#
# IDEMPOTENT, FAILSAFE. Runs as any user. Never exits non-zero if the system
# has no GPU at all -- emits software fallback instead.

set -u
set +e

MODE="${1:-render}"

# --- Enumerate /dev/dri devices ------------------------------------------
# Each card has a sysfs sibling at /sys/class/drm/card*/device/ with:
#   vendor        -- 0x10de (NVIDIA), 0x1002 (AMD), 0x8086 (Intel)
#   device        -- device ID (e.g., 0x2684 = RTX 4090)
#   boot_vga      -- "1" for the card BIOS/UEFI is using for POST display
#   drm/renderD*  -- the render-only node (compute + PRIME offload)
declare -a CARDS=()        # card0, card1, ...
declare -a VENDORS=()      # 10de, 1002, 8086, unknown
declare -a RENDER_NODES=() # /dev/dri/renderD128, ...
declare -a BOOT_VGAS=()    # 0 or 1
declare -a DEV_IDS=()      # 2684, ...

for sysdrm in /sys/class/drm/card[0-9]*; do
    [ -d "$sysdrm" ] || continue
    card="${sysdrm##*/}"
    # Skip virtual/fake nodes
    [ -d "$sysdrm/device" ] || continue

    vendor=$(cat "$sysdrm/device/vendor" 2>/dev/null | tr -d '\n')
    devid=$(cat "$sysdrm/device/device" 2>/dev/null | tr -d '\n')
    boot=$(cat "$sysdrm/device/boot_vga" 2>/dev/null | tr -d '\n')

    # Strip 0x prefix for consistent lowercase compare
    vendor="${vendor#0x}"
    devid="${devid#0x}"
    vendor=$(printf '%s' "$vendor" | tr 'A-Z' 'a-z')

    # Find the matching renderD* node for this card (there is 0 or 1)
    rnode=""
    for rd in "$sysdrm"/device/drm/renderD[0-9]*; do
        [ -e "$rd" ] || continue
        rnode="/dev/dri/${rd##*/}"
        break
    done

    CARDS+=("$card")
    VENDORS+=("${vendor:-unknown}")
    DEV_IDS+=("${devid:-unknown}")
    RENDER_NODES+=("$rnode")
    BOOT_VGAS+=("${boot:-0}")
done

NUM_CARDS=${#CARDS[@]}

# --- List mode ------------------------------------------------------------
if [ "$MODE" = "list" ]; then
    if [ "$NUM_CARDS" -eq 0 ]; then
        echo "no-gpu"
        exit 0
    fi
    for i in "${!CARDS[@]}"; do
        vname="unknown"
        case "${VENDORS[$i]}" in
            10de) vname="nvidia" ;;
            1002) vname="amd" ;;
            8086) vname="intel" ;;
        esac
        echo "card=${CARDS[$i]} vendor=$vname id=${DEV_IDS[$i]} boot_vga=${BOOT_VGAS[$i]} render_node=${RENDER_NODES[$i]:-none}"
    done
    exit 0
fi

# --- No-GPU / software-fallback path -------------------------------------
if [ "$NUM_CARDS" -eq 0 ] || [ "$MODE" = "software" ]; then
    echo "export LIBGL_ALWAYS_SOFTWARE=1"
    echo "export GALLIUM_DRIVER=llvmpipe"
    echo "export VK_LOADER_DRIVERS_DISABLE=1"
    echo "export GPU_TIER=software"
    exit 0
fi

# --- Pick primary (display) and render devices ---------------------------
# "primary" = boot_vga==1 (or first card if no boot_vga set anywhere)
# "render"  = prefer non-boot_vga (dGPU); fall back to primary if only one card
primary_idx=-1
render_idx=-1

for i in "${!CARDS[@]}"; do
    if [ "${BOOT_VGAS[$i]}" = "1" ]; then
        primary_idx=$i
        break
    fi
done
# No boot_vga found -> first card wins
[ "$primary_idx" -lt 0 ] && primary_idx=0

if [ "$NUM_CARDS" -gt 1 ]; then
    for i in "${!CARDS[@]}"; do
        if [ "$i" != "$primary_idx" ]; then
            render_idx=$i
            break
        fi
    done
else
    render_idx=$primary_idx
fi

# --- Display mode: pick boot_vga device ---------------------------------
if [ "$MODE" = "display" ]; then
    echo "export AI_DISPLAY_CARD=/dev/dri/${CARDS[$primary_idx]}"
    echo "export AI_DISPLAY_VENDOR=${VENDORS[$primary_idx]}"
    exit 0
fi

# --- Compute mode: pick renderD node (first dGPU, else primary) ---------
if [ "$MODE" = "compute" ]; then
    rn="${RENDER_NODES[$render_idx]}"
    if [ -z "$rn" ]; then
        # Fall back to primary if render has no renderD*
        rn="${RENDER_NODES[$primary_idx]}"
    fi
    if [ -z "$rn" ]; then
        echo "export LIBGL_ALWAYS_SOFTWARE=1"
        echo "export GPU_TIER=software"
        exit 0
    fi
    echo "export AI_COMPUTE_NODE=$rn"
    echo "export AI_COMPUTE_VENDOR=${VENDORS[$render_idx]}"
    exit 0
fi

# --- Render mode (default): full PRIME offload setup --------------------
primary_vendor="${VENDORS[$primary_idx]}"
render_vendor="${VENDORS[$render_idx]}"
render_node="${RENDER_NODES[$render_idx]}"

echo "# gpu-select: primary=${CARDS[$primary_idx]} ($primary_vendor) render=${CARDS[$render_idx]} ($render_vendor)"
echo "export AI_PRIMARY_CARD=/dev/dri/${CARDS[$primary_idx]}"
echo "export AI_RENDER_CARD=/dev/dri/${CARDS[$render_idx]}"
[ -n "$render_node" ] && echo "export AI_RENDER_NODE=$render_node"

# DRI3 enforcement: never let the loader fall back to DRI2 (slow, no zero-copy)
echo "export LIBGL_DRI3_DISABLE=0"
echo "export MESA_GLTHREAD=true"

# Hybrid case: dGPU distinct from primary -- enable PRIME offload
if [ "$render_idx" != "$primary_idx" ]; then
    echo "export DRI_PRIME=1"
    case "$render_vendor" in
        10de)
            # NVIDIA PRIME offload -- works for both proprietary and nouveau.
            # Both env vars are needed: __NV_PRIME_RENDER_OFFLOAD triggers the
            # GLX/Vulkan layer, __VK_LAYER_NV_optimus picks the layer chain.
            echo "export __NV_PRIME_RENDER_OFFLOAD=1"
            echo "export __VK_LAYER_NV_optimus=NVIDIA_only"
            echo "export __GLX_VENDOR_LIBRARY_NAME=nvidia"
            ;;
        1002)
            # AMD PRIME works out of the box with DRI_PRIME=1; no extra vars.
            echo "export RADV_FORCE_VRS=0"
            ;;
        8086)
            # Intel as render target (rare; usually the other way round).
            echo "export MESA_LOADER_DRIVER_OVERRIDE=iris"
            ;;
    esac
fi

# --- Vulkan ICD pinning -- force the loader to use the render GPU's ICD -
# On hybrid laptops the Vulkan loader walks ICDs alphabetically -- it can land
# on the iGPU even with DRI_PRIME set because DRI_PRIME only affects GL.
vk_icd=""
case "$render_vendor" in
    10de)
        for icd in /usr/share/vulkan/icd.d/nvidia_icd.json \
                   /usr/share/vulkan/icd.d/nvidia_icd.x86_64.json \
                   /usr/share/vulkan/icd.d/nouveau_icd.x86_64.json; do
            [ -r "$icd" ] && { vk_icd="$icd"; break; }
        done
        ;;
    1002)
        for icd in /usr/share/vulkan/icd.d/radeon_icd.x86_64.json; do
            [ -r "$icd" ] && { vk_icd="$icd"; break; }
        done
        ;;
    8086)
        for icd in /usr/share/vulkan/icd.d/intel_icd.x86_64.json; do
            [ -r "$icd" ] && { vk_icd="$icd"; break; }
        done
        ;;
esac
[ -n "$vk_icd" ] && echo "export VK_ICD_FILENAMES=$vk_icd"

# --- Wayland PRIME (Hyprland / wlroots) ---------------------------------
# WLR_DRM_DEVICES tells wlroots which DRM device(s) to use, in priority order.
# We put primary first (for display) and render second (so offloaded clients
# can pick it up).  Also WLR_RENDERER_ALLOW_SOFTWARE=1 lets wlroots boot on
# GT218/Intel-Gen6 where Vulkan renderer probe fails.
if [ "$NUM_CARDS" -gt 1 ]; then
    echo "export WLR_DRM_DEVICES=/dev/dri/${CARDS[$primary_idx]}:/dev/dri/${CARDS[$render_idx]}"
fi

# --- Tier classification for downstream tooling ------------------------
# Emit GPU_TIER so the AI daemon knows whether to dispatch GPU-heavy work.
# A "software" tier means: no Vulkan, no DXVK, fall back to CPU.
gpu_tier="modern"
# Old NVIDIA (GT218 family, device ID 0a?? / 0b?? / 0c?? / 0d??)
if [ "$render_vendor" = "10de" ]; then
    case "${DEV_IDS[$render_idx]}" in
        0a*|0b*|0c*|0d*)
            gpu_tier="legacy"
            # Pre-Fermi nouveau cannot handle multi-threaded GL -- disable glthread.
            echo "export MESA_GLTHREAD=false"
            echo "export WLR_RENDERER_ALLOW_SOFTWARE=1"
            ;;
    esac
fi
# Old Intel (Gen6 Sandy Bridge or earlier -- no Vulkan)
if [ "$render_vendor" = "8086" ]; then
    case "${DEV_IDS[$render_idx]}" in
        0102|0106|010a|010b|0112|0116|0122|0126)
            gpu_tier="legacy"
            echo "export WLR_RENDERER_ALLOW_SOFTWARE=1"
            ;;
    esac
fi
echo "export GPU_TIER=$gpu_tier"

exit 0
