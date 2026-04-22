#!/bin/sh
# /etc/profile.d/vkd3d.sh -- VKD3D-Proton (D3D12 -> Vulkan) environment baseline.

# --- Debug off ----------------------------------------------------------
: "${VKD3D_DEBUG:=none}"
export VKD3D_DEBUG

# --- Shader cache -------------------------------------------------------
# Separate from DXVK: VKD3D emits *.dxil.cache files.  Same rules as DXVK
# caches: tmpfs on live ISO, /var/cache on installed.
: "${VKD3D_SHADER_CACHE_PATH:=/var/cache/ai-arch/shaders/vkd3d}"
export VKD3D_SHADER_CACHE_PATH

# --- VKD3D_CONFIG -------------------------------------------------------
# Intentionally NOT set here — only RTX/RDNA2 should enable dxr,dxr11
# and gpu-env.sh owns that decision.  Setting it blindly on a GTX 970
# causes fallback-path stalls.

# --- Feature level ------------------------------------------------------
# D3D12 feature level cap: leave at VKD3D's auto-detect by default.
# Pin to 12_1 on old HW to avoid a game trying 12_2 on pre-RDNA2.
if [ -r /run/ai-arch-gpu-profile ]; then
    . /run/ai-arch-gpu-profile 2>/dev/null || true
    case "${GPU_ARCH:-}" in
        tesla|gen6|gen7|gcn)
            : "${VKD3D_FEATURE_LEVEL:=11_0}"
            export VKD3D_FEATURE_LEVEL
            ;;
    esac
fi
