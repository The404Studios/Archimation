#!/bin/bash
# Quick-and-dirty gdb wrapper for peloader + PuTTY crash repro.
# Not set -e because we want the pipeline to reach `tail -100` even if gdb
# reports a caught crash; but we do want unset-var detection.
set -uo pipefail
cd /opt/pe-loader
export DISPLAY=:0
export XAUTHORITY=/run/lightdm/root/:0
export LD_LIBRARY_PATH=dlls
timeout 15 gdb -batch \
  -ex 'set pagination off' \
  -ex run \
  -ex 'bt full' \
  -ex 'x/20i 0x140052260' \
  -ex 'x/16gx $rsp' \
  -ex 'info registers' \
  --args ./peloader putty64.exe 2>&1 | tail -100
