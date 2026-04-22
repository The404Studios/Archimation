#!/bin/sh
# /etc/profile.d/dxvk.sh -- DXVK (D3D9/10/11 -> Vulkan) environment baseline.
#
# Safe defaults applied to EVERY session.  Hardware-specific tuning (async,
# state-cache on/off, memory cap) is layered by gpu-env.sh which is sourced
# earlier.  We use `: "${VAR:=default}"` so dynamic overrides win.

# --- Log level / HUD ----------------------------------------------------
# DXVK_LOG_LEVEL=info is the upstream default and costs ~1-2% FPS on
# old HW from fsync-per-frame.  Turn it off globally; users can set
# DXVK_LOG_LEVEL=info in a shell to re-enable for debugging.
: "${DXVK_LOG_LEVEL:=none}"
: "${DXVK_LOG_PATH:=none}"
: "${DXVK_HUD:=}"
export DXVK_LOG_LEVEL DXVK_LOG_PATH DXVK_HUD

# --- Frame pacing -------------------------------------------------------
# 0 = don't cap; let the compositor / VRR handle pacing.  Games that *need*
# a cap set it themselves via config file.
: "${DXVK_FRAME_RATE:=0}"
export DXVK_FRAME_RATE

# --- State cache path ---------------------------------------------------
# Fallback path if gpu-env.sh didn't set it (early-boot shell).  The
# tmpfiles.d drop-in guarantees /var/cache/ai-arch/shaders exists.
: "${DXVK_STATE_CACHE_PATH:=/var/cache/ai-arch/shaders/dxvk}"
export DXVK_STATE_CACHE_PATH

# --- Per-app config directory ------------------------------------------
# DXVK reads <exe>.dxvk.conf next to the binary.  We bundle community
# tweaks for popular games in /usr/share/dxvk-conf/ — the pe-launch-wrapper
# reads from there and copies the matching file to the exe dir.
: "${DXVK_CONFIG_FILE:=}"
export DXVK_CONFIG_FILE
