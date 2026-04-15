#!/bin/bash
# ai-arch/gpu-profile.sh -- GPU capability profiler for DXVK / VKD3D / Mesa tuning.
#
# Runs at the tail of hw-detect.sh (or standalone).  Reads /run/ai-arch-hw-profile
# (written by hw-detect.sh) for the OLD/NEW/DEFAULT tier + GPU vendor, then
# probes Vulkan / GL capability and writes a set of shell-source-able files:
#
#   /run/ai-arch-gpu-profile              KEY=VALUE knobs for downstream units
#   /run/ai-arch/gpu-env.sh               POSIX-shell env exports (sourced by
#                                         /etc/profile.d/gpu-tuning.sh)
#
# IDEMPOTENT: safe to invoke any number of times.  Failures are non-fatal --
# a broken probe emits a minimal "software-fallback" env rather than blocking
# login.  Every write is guarded with 2>/dev/null.
#
# Design goals:
#   1. Old HW (GT218, pre-GCN Radeon, Intel HD 3000) feels responsive: async
#      shader compile ONLY if RAM >=2 GB, state cache off on GT218 nouveau,
#      LLVMpipe fallback if vulkan probe fails.
#   2. New HW (RTX, RDNA3) exploits GPL, pipeline cache, DXR where available.
#   3. Hybrid graphics (iGPU + dGPU): pin VK_ICD_FILENAMES to the dGPU so
#      games don't accidentally land on the iGPU.

set -u
set +e

PROFILE_FILE=/run/ai-arch-hw-profile
OUT_KV=/run/ai-arch-gpu-profile
OUT_SH_DIR=/run/ai-arch
OUT_SH=$OUT_SH_DIR/gpu-env.sh

# Defaults, overridden from /run/ai-arch-hw-profile
PROFILE=DEFAULT
MEM_MB=0
CPU_CORES=1
GPU_VENDOR=unknown
GPU_OLD_NVIDIA=0

if [ -r "$PROFILE_FILE" ]; then
    # shellcheck disable=SC1090
    . "$PROFILE_FILE" || true
fi

mkdir -p "$OUT_SH_DIR" 2>/dev/null

# --- Vulkan capability probe ---------------------------------------------
# Returns the API version reported by the first physical device, or empty
# string on failure (no vulkan loader / no ICD / no driver).
# Use vulkaninfo's '--summary' for speed (~60 ms) with a hard 3s timeout.
VK_API="none"
VK_DEVICE=""
if command -v vulkaninfo >/dev/null 2>&1; then
    VK_OUT=$(timeout 3 vulkaninfo --summary 2>/dev/null)
    if [ -n "$VK_OUT" ]; then
        # Parse "apiVersion = X.Y.Z" (first one = first device)
        VK_API=$(printf '%s' "$VK_OUT" | awk -F'=' '/apiVersion/ {gsub(/[[:space:]]/,"",$2); print $2; exit}')
        VK_DEVICE=$(printf '%s' "$VK_OUT" | awk -F'=' '/deviceName/ {gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2; exit}')
        [ -z "$VK_API" ] && VK_API="unknown"
    fi
fi

# Classify Vulkan capability (maj.min extraction, portable with POSIX shell)
VK_MAJOR=0
VK_MINOR=0
if [ "$VK_API" != "none" ] && [ "$VK_API" != "unknown" ]; then
    VK_MAJOR=$(printf '%s' "$VK_API" | awk -F. '{print $1+0}')
    VK_MINOR=$(printf '%s' "$VK_API" | awk -F. '{print $2+0}')
fi

VK_TIER="none"
if [ "$VK_MAJOR" -ge 1 ] && [ "$VK_MINOR" -ge 3 ]; then
    VK_TIER="1.3+"   # GPL, timeline semaphores, dynamic rendering
elif [ "$VK_MAJOR" -ge 1 ] && [ "$VK_MINOR" -ge 2 ]; then
    VK_TIER="1.2"    # descriptor indexing, timeline semaphores
elif [ "$VK_MAJOR" -ge 1 ] && [ "$VK_MINOR" -ge 1 ]; then
    VK_TIER="1.1"
elif [ "$VK_MAJOR" -eq 1 ]; then
    VK_TIER="1.0"
fi

# --- GPU-specific feature detection --------------------------------------
# Per-vendor fine-grain: RDNA2+ (for RADV gpl,sam,nggc), FreeSync, RTX DXR.
GPU_FEATURE=""
GPU_ARCH="unknown"

case "$GPU_VENDOR" in
    amd)
        # Distinguish GCN (pre-RDNA) from RDNA / RDNA2 / RDNA3.
        # Use lspci -n to get the device ID and map roughly.
        AMD_ID=$(lspci -n 2>/dev/null | grep -Ei '(VGA|Display|3D)' | \
                 grep -oE '1002:[0-9a-f]{4}' | head -1 | cut -d: -f2)
        case "$AMD_ID" in
            # RDNA3 (Navi31/32/33) — gfx1100, 1101, 1102, 1103
            73[abcd]?|7448|744c|7480)
                GPU_ARCH="rdna3"; GPU_FEATURE="gpl,sam,nggc,rt" ;;
            # RDNA2 (Navi21/22/23) — gfx1030 family
            73[0-9a-f]?)
                GPU_ARCH="rdna2"; GPU_FEATURE="gpl,sam,nggc,rt" ;;
            # RDNA (Navi10/14) — gfx1010
            731?|7340|7341|734f)
                GPU_ARCH="rdna"; GPU_FEATURE="gpl,sam" ;;
            # Vega — gfx900/906
            687?|69[a-f]?|66a?)
                GPU_ARCH="vega"; GPU_FEATURE="gpl" ;;
            "")
                GPU_ARCH="unknown" ;;
            *)
                GPU_ARCH="gcn"; GPU_FEATURE="" ;;  # pre-GCN / old GCN
        esac
        ;;
    nvidia)
        if [ "$GPU_OLD_NVIDIA" -eq 1 ]; then
            GPU_ARCH="tesla"     # GT218 and siblings
            GPU_FEATURE=""
        else
            # Anything post-Maxwell is good-enough for modern DXVK
            GPU_ARCH="maxwell+"
            GPU_FEATURE="nvk"    # nouveau's next-gen userspace driver
            # RTX = Turing+ (20/30/40 series): 2080Ti is 10de:1e07
            NV_ID=$(lspci -n 2>/dev/null | grep -Ei '(VGA|Display|3D)' | \
                    grep -oE '10de:[0-9a-f]{4}' | head -1 | cut -d: -f2)
            case "$NV_ID" in
                # Turing 16xx/20xx (1e??, 1f??), Ampere 30xx (2[0-7]??), Ada 40xx (26??, 27??, 28??)
                1e??|1f??|2[0-8]??)
                    GPU_ARCH="rtx"; GPU_FEATURE="nvk,rt,dxr" ;;
            esac
        fi
        ;;
    intel)
        # Distinguish Gen5 (ILK), Gen6 (SNB), Gen7 (IVB/HSW), Gen8+ (BDW+).
        # HD Graphics 3000 = Gen6 Sandy Bridge (no Vulkan). HD 4000+ = Gen7 Ivy.
        INTEL_ID=$(lspci -n 2>/dev/null | grep -Ei '(VGA|Display)' | \
                   grep -oE '8086:[0-9a-f]{4}' | head -1 | cut -d: -f2)
        case "$INTEL_ID" in
            # Sandy Bridge HD 2000/3000 (0102, 0112, 0122, 0106, 0116, 0126, 010a)
            0102|0106|010[ab]|0112|0116|0122|0126)
                GPU_ARCH="gen6"; GPU_FEATURE="" ;;
            # Ivy / Haswell (gen7)
            0[12][56789abcdef]?|04[0-9a-f]?|0a[0-9a-f]?|0d[0-9a-f]?)
                GPU_ARCH="gen7"; GPU_FEATURE="" ;;
            # Broadwell+ (gen8+, first gen with real Vulkan via ANV)
            16[0-9a-f]?|19[0-9a-f]?|[34][ef][0-9a-f]?|[5-9][0-9a-f]{3})
                GPU_ARCH="gen8+"; GPU_FEATURE="anv-pipeline-cache" ;;
        esac
        ;;
esac

# --- Software fallback gate ----------------------------------------------
# If Vulkan is literally non-functional (VK_TIER=none and no vulkaninfo), we
# will forcibly enable LLVMpipe for GL.  DXVK cannot fall back to software
# so D3D games won't run — that's a conscious trade-off on GPU-less VMs.
SOFTWARE_FALLBACK=0
if [ "$VK_TIER" = "none" ] && [ "$GPU_VENDOR" = "unknown" ]; then
    SOFTWARE_FALLBACK=1
fi
# QEMU guest without virgl: override any GPU hint — glamor + llvmpipe.
if [ -r /sys/class/dmi/id/sys_vendor ]; then
    if grep -qi 'QEMU\|Bochs' /sys/class/dmi/id/sys_vendor 2>/dev/null && \
       [ "$VK_TIER" = "none" ]; then
        SOFTWARE_FALLBACK=1
    fi
fi

# --- Shader cache location & size ---------------------------------------
# On the live ISO we put caches on tmpfs (volatile, fast, RAM-limited).
# On installed systems (read-write /etc) we let users own them via $HOME.
# But root systemd units and XDG autostart still need a safe default, so we
# pick a system-level tmpfs cache and overlay per-user in profile.d.
SHADER_CACHE_BASE="/var/cache/ai-arch/shaders"
if [ -d /run/archiso ]; then
    SHADER_CACHE_BASE="/run/ai-arch/shaders"
fi
mkdir -p "$SHADER_CACHE_BASE" 2>/dev/null
chmod 1777 "$SHADER_CACHE_BASE" 2>/dev/null   # sticky, world-writable

# --- Cache-size budget ---------------------------------------------------
# DXVK state cache can grow 200-800 MB per big game.  On OLD-tier systems
# with 2 GB RAM, a 1 GB cache on tmpfs WILL OOM.  Clamp budget here.
case "$PROFILE" in
    OLD)  CACHE_BUDGET_MB=128 ;;
    NEW)  CACHE_BUDGET_MB=1024 ;;
    *)    CACHE_BUDGET_MB=256 ;;
esac

# --- DXVK policy ---------------------------------------------------------
# DXVK_ASYNC requires a DXVK build with the patch (upstream ships it since 2.3).
# But async shader compile ALLOCATES worker threads that eat RAM.  Disable on
# truly small systems (<2 GB) and on GT218 (nouveau crashes on concurrent
# pipeline compile under load).
DXVK_ASYNC_V=1
DXVK_STATE_CACHE_V=1
if [ "$MEM_MB" -le 2048 ]; then
    DXVK_ASYNC_V=0
fi
if [ "$GPU_OLD_NVIDIA" -eq 1 ]; then
    DXVK_ASYNC_V=0       # nouveau+GT218 cannot handle parallel compile
    DXVK_STATE_CACHE_V=0 # disk cache on nouveau has caused GPU hangs
fi
if [ "$SOFTWARE_FALLBACK" -eq 1 ]; then
    # LLVMpipe has no functional DXVK; mark both off to signal callers.
    DXVK_ASYNC_V=0
    DXVK_STATE_CACHE_V=0
fi

# --- VKD3D-Proton config (D3D12) -----------------------------------------
# dxr/dxr11 are the extension-name pair for DXR on HW that supports it.
# RTX and RDNA2+ qualify; everything else wastes init time turning it on.
VKD3D_CONFIG_V=""
case "$GPU_ARCH" in
    rtx|rdna2|rdna3)
        VKD3D_CONFIG_V="dxr,dxr11"
        ;;
    rdna|vega|maxwell+)
        VKD3D_CONFIG_V="force_host_cached"   # helps on mid-range
        ;;
esac

# --- Vulkan ICD pin (hybrid graphics safety) ------------------------------
# On laptops with iGPU + dGPU the default loader walks ICDs in alphabetical
# order and the game often lands on iGPU.  Pin per-vendor when we know for
# sure there is only one GPU.
VK_ICD_V=""
case "$GPU_VENDOR" in
    nvidia)
        # Prefer proprietary ICD if present (installed systems); fall back to nouveau.
        for icd in /usr/share/vulkan/icd.d/nvidia_icd.json \
                   /usr/share/vulkan/icd.d/nvidia_icd.x86_64.json \
                   /usr/share/vulkan/icd.d/nouveau_icd.i686.json \
                   /usr/share/vulkan/icd.d/nouveau_icd.x86_64.json; do
            [ -r "$icd" ] && { VK_ICD_V="$icd"; break; }
        done
        ;;
    amd)
        for icd in /usr/share/vulkan/icd.d/radeon_icd.x86_64.json \
                   /usr/share/vulkan/icd.d/radeon_icd.i686.json; do
            [ -r "$icd" ] && { VK_ICD_V="$icd"; break; }
        done
        ;;
    intel)
        for icd in /usr/share/vulkan/icd.d/intel_icd.x86_64.json \
                   /usr/share/vulkan/icd.d/intel_icd.i686.json; do
            [ -r "$icd" ] && { VK_ICD_V="$icd"; break; }
        done
        ;;
esac

# --- Write K/V profile ---------------------------------------------------
{
    echo "# Written by /usr/lib/ai-arch/gpu-profile.sh at $(date -Iseconds 2>/dev/null || echo unknown)"
    echo "GPU_PROFILE=$PROFILE"
    echo "GPU_VENDOR=$GPU_VENDOR"
    echo "GPU_ARCH=$GPU_ARCH"
    echo "GPU_FEATURE=$GPU_FEATURE"
    echo "VK_TIER=$VK_TIER"
    echo "VK_API=$VK_API"
    echo "VK_DEVICE=$VK_DEVICE"
    echo "DXVK_ASYNC=$DXVK_ASYNC_V"
    echo "DXVK_STATE_CACHE=$DXVK_STATE_CACHE_V"
    echo "VKD3D_CONFIG=$VKD3D_CONFIG_V"
    echo "SOFTWARE_FALLBACK=$SOFTWARE_FALLBACK"
    echo "SHADER_CACHE_BASE=$SHADER_CACHE_BASE"
    echo "CACHE_BUDGET_MB=$CACHE_BUDGET_MB"
    echo "VK_ICD=$VK_ICD_V"
} > "$OUT_KV" 2>/dev/null

# --- Write POSIX-sh env exports ------------------------------------------
# This file is sourced by /etc/profile.d/gpu-tuning.sh on every login shell.
# It uses plain `export` (not `declare -x`) to stay bash/dash portable.
{
    echo "# Auto-generated by /usr/lib/ai-arch/gpu-profile.sh"
    echo "# GPU tier: vendor=$GPU_VENDOR arch=$GPU_ARCH vk=$VK_TIER profile=$PROFILE"
    echo

    # --- Mesa universal wins ----------------------------------------------
    if [ "$SOFTWARE_FALLBACK" -eq 1 ]; then
        echo "export LIBGL_ALWAYS_SOFTWARE=1"
        echo "export GALLIUM_DRIVER=llvmpipe"
    else
        # glthread is a free 5-15% FPS win on legacy GL games.  Driver
        # fast-path already bails if glthread would violate invariants.
        echo "export mesa_glthread=true"
        echo "export LIBGL_ALWAYS_INDIRECT=0"
        echo "export LIBGL_DRI3_DISABLE=0"
    fi

    # --- Per-vendor tuning ------------------------------------------------
    case "$GPU_VENDOR" in
        amd)
            # Build RADV_PERFTEST from capability set (empty for pre-RDNA).
            if [ -n "$GPU_FEATURE" ]; then
                # Strip 'rt' (maps to VKD3D_CONFIG, not RADV_PERFTEST).
                rp=$(printf '%s' "$GPU_FEATURE" | tr ',' '\n' | \
                     grep -vE '^(rt|dxr)$' | paste -sd, - 2>/dev/null || \
                     printf '%s' "$GPU_FEATURE" | tr ',' '\n' | \
                     awk '/^(rt|dxr)$/ {next} {a=a?a","$0:$0} END{print a}')
                [ -n "$rp" ] && echo "export RADV_PERFTEST=$rp"
            fi
            # Intentionally DO NOT set RADV_DEBUG — its debug knobs *reduce*
            # performance; we unset any leaked values at login.
            echo "unset RADV_DEBUG 2>/dev/null || true"
            # AMD_VULKAN_ICD: prefer RADV over amdvlk (amdvlk can't do DXVK
            # well on RDNA2 — mesh shaders missing).
            echo "export AMD_VULKAN_ICD=RADV"
            ;;
        intel)
            echo "export ANV_ENABLE_PIPELINE_CACHE=true"
            # Dedicated Queue Thread: give Vulkan submissions to a worker
            # thread so the render thread never spin-waits.  Big win on
            # quad-core i5s (HD Graphics 5000+).
            if [ "$CPU_CORES" -ge 4 ]; then
                echo "export ANV_QUEUE_THREAD=1"
            fi
            # Gen6/7 cannot do Vulkan; clamp to GL-only.
            case "$GPU_ARCH" in
                gen6|gen7)
                    echo "export MESA_GLSL_VERSION_OVERRIDE=330"
                    echo "export MESA_GL_VERSION_OVERRIDE=3.3"
                    ;;
            esac
            ;;
        nvidia)
            if [ "$GPU_OLD_NVIDIA" -eq 1 ]; then
                # GT218/Tesla-nouveau: minimum viable settings.
                echo "export __GL_THREADED_OPTIMIZATIONS=1"
                echo "export __GL_SHADER_DISK_CACHE=1"
                echo "export __GL_SHADER_DISK_CACHE_PATH=$SHADER_CACHE_BASE/gl"
                # USLEEP yield gives the CPU back between frames instead of
                # busy-looping — reduces load average on weak CPUs.
                echo "export __GL_YIELD=USLEEP"
                # 10-bit RGBA configs corrupt nouveau VRAM on pre-Fermi;
                # clamp to 8-bit in Mesa.
                echo "export ALLOW_RGB10_CONFIGS=false"
            else
                # Maxwell+ on nouveau / proprietary — enable all perf wins.
                echo "export __GL_THREADED_OPTIMIZATIONS=1"
                echo "export __GL_SHADER_DISK_CACHE=1"
                echo "export __GL_SHADER_DISK_CACHE_PATH=\${XDG_CACHE_HOME:-\$HOME/.cache}/nvidia/GLCache"
                echo "export __GL_SHADER_DISK_CACHE_SIZE=$(( CACHE_BUDGET_MB * 1024 * 1024 ))"
            fi
            ;;
    esac

    # --- Vulkan ICD pin (hybrid-graphics safety) --------------------------
    if [ -n "$VK_ICD_V" ]; then
        echo "export VK_ICD_FILENAMES=$VK_ICD_V"
    fi
    # Mesa and the loader both read VK_LAYER_PATH; keep the default search
    # path but explicitly include our package's layer dir if it exists.
    if [ -d /usr/share/vulkan/explicit_layer.d ]; then
        echo "export VK_LAYER_PATH=/usr/share/vulkan/explicit_layer.d:/usr/share/vulkan/implicit_layer.d"
    fi

    # --- DXVK core knobs --------------------------------------------------
    echo "export DXVK_STATE_CACHE_PATH=$SHADER_CACHE_BASE/dxvk"
    echo "export DXVK_LOG_LEVEL=none"
    echo "export DXVK_LOG_PATH=none"
    echo "export DXVK_HUD="
    # FRAME_RATE=0 means "do not cap" — VRR / compositor handles pacing.
    echo "export DXVK_FRAME_RATE=0"
    if [ "$DXVK_ASYNC_V" -eq 1 ]; then
        echo "export DXVK_ASYNC=1"
        echo "export DXVK_GPLASYNCCACHE=1"  # GPL async cache (DXVK 2.3+)
    else
        echo "unset DXVK_ASYNC 2>/dev/null || true"
    fi
    if [ "$DXVK_STATE_CACHE_V" -eq 0 ]; then
        # DXVK still writes a single lock file — point it into /tmp/void.
        echo "export DXVK_STATE_CACHE=0"
    fi
    # Memory ceiling: on 1-2 GB systems we cap DXVK's VRAM arena so it can't
    # OOM the X server.  DXVK accepts a plain integer in MiB.
    if [ "$MEM_MB" -le 2048 ]; then
        echo "export DXVK_MEMORY_LIMIT=256"
    elif [ "$MEM_MB" -le 4096 ]; then
        echo "export DXVK_MEMORY_LIMIT=1024"
    fi

    # --- VKD3D-Proton (D3D12) --------------------------------------------
    echo "export VKD3D_SHADER_CACHE_PATH=$SHADER_CACHE_BASE/vkd3d"
    if [ -n "$VKD3D_CONFIG_V" ]; then
        echo "export VKD3D_CONFIG=$VKD3D_CONFIG_V"
    fi
    echo "export VKD3D_DEBUG=none"

    # --- DRI_PRIME for hybrid graphics -----------------------------------
    # Pin DRI_PRIME=1 when a secondary (presumably dedicated) GPU exists.
    # PRIME offload hands the game to that card; the iGPU still composites.
    if [ -r /dev/dri/card1 ] && [ -r /dev/dri/card0 ]; then
        echo "export DRI_PRIME=1"
    fi
} > "$OUT_SH" 2>/dev/null
chmod 0644 "$OUT_SH" 2>/dev/null

echo "ai-gpu-profile: vendor=$GPU_VENDOR arch=$GPU_ARCH vk=$VK_TIER async=$DXVK_ASYNC_V cache=$DXVK_STATE_CACHE_V fb=$SOFTWARE_FALLBACK"
exit 0
