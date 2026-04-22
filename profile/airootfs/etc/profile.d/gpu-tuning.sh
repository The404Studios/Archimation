#!/bin/sh
# /etc/profile.d/gpu-tuning.sh -- source the hardware-specific GPU env file
# written by /usr/lib/ai-arch/gpu-profile.sh at boot (via ai-hw-detect.service).
#
# This is the MASTER entry point -- individual vendor files (mesa.sh,
# dxvk.sh, vkd3d.sh) below layer on top for *fallback defaults* if the
# probe hasn't run yet (e.g., user login during very early boot).
#
# POSIX sh only.  Sourced by /etc/profile which is read by bash, dash, and
# the LightDM Xsession wrapper (/etc/lightdm/Xsession).

# The runtime file is re-created on every boot by hw-detect.sh.
if [ -r /run/ai-arch/gpu-env.sh ]; then
    . /run/ai-arch/gpu-env.sh
fi

# If the generator has not written yet (race at very early login) fall back
# to a conservative software-safe baseline.  Downstream vendor scripts will
# override on the next login.
if [ -z "${DXVK_LOG_LEVEL-}" ]; then
    export DXVK_LOG_LEVEL=none
    export DXVK_HUD=
fi
if [ -z "${mesa_glthread-}" ]; then
    export mesa_glthread=true
fi
