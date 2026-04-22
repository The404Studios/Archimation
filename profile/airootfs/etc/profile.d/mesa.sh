#!/bin/sh
# /etc/profile.d/mesa.sh -- universal Mesa GL/Vulkan tuning.
#
# Values here are SAFE on every GPU we target.  Hardware-specific overrides
# (RADV/ANV/nouveau) live in /run/ai-arch/gpu-env.sh which is sourced by
# /etc/profile.d/gpu-tuning.sh BEFORE this file (alphabetical profile.d
# ordering: gpu-tuning.sh < mesa.sh).  So downstream `export` here only
# fires when the dynamic file didn't set the variable.

# --- GL threading (free perf win on OpenGL apps) ------------------------
# Already set by gpu-tuning.sh on probe success; set again here for shells
# started BEFORE the probe ran (early tty login, recovery shell).
: "${mesa_glthread:=true}"
export mesa_glthread

# --- GL version over-rides (suppresses driconf warnings) ----------------
# Most games accept what Mesa advertises.  Leave MESA_GL_VERSION_OVERRIDE
# unset here so per-GPU files in gpu-env.sh can win.

# --- Shader disk cache --------------------------------------------------
# Mesa has its own cache (separate from DXVK).  Point it at a user-owned
# directory; Mesa already honours XDG_CACHE_HOME if set, but some games
# also honour MESA_SHADER_CACHE_DIR explicitly.
: "${MESA_SHADER_CACHE_DIR:=${XDG_CACHE_HOME:-$HOME/.cache}/mesa_shader_cache}"
export MESA_SHADER_CACHE_DIR
# Disable the size cap in Mesa (defaults to 1 GB).  On installed systems
# with big SSDs, 4 GB of cache accelerates load times for big games.
: "${MESA_SHADER_CACHE_MAX_SIZE:=4G}"
export MESA_SHADER_CACHE_MAX_SIZE

# --- Force RGB10 off on very old HW (gpu-profile.sh may have set this) --
# Belt-and-suspenders: if the probe failed for any reason we still want
# GT218 / HD 3000 to steer clear of 10-bit configs.
: "${ALLOW_RGB10_CONFIGS:=false}"
export ALLOW_RGB10_CONFIGS

# --- Loader search path -------------------------------------------------
# Some Vulkan ICDs ship in /opt (NVIDIA proprietary); ensure the loader
# sees them after our Arch package defaults.  Empty by default (loader
# picks sensible paths) but we set the prefix so package updates don't
# silently break hybrid graphics.
if [ -d /usr/share/vulkan/icd.d ]; then
    : "${VK_DRIVER_FILES:=}"
    # Leave VK_DRIVER_FILES / VK_ICD_FILENAMES to gpu-env.sh (vendor-pinned).
fi
