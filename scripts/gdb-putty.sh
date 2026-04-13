#!/bin/bash
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
