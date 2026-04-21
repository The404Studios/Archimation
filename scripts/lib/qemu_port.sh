#!/bin/bash
# scripts/lib/qemu_port.sh — QEMU host-forward port helpers.
#
# Problem (Session 67 handoff A4): `test-qemu-extended.sh` used hard-coded
# host port 8421 for the cortex host-forward. When two QEMU runs follow
# each other quickly (e.g. a pytest session that runs the main smoke AND
# the extended smoke, or two extended-smoke invocations via a wrapper),
# the first QEMU's teardown can leave sockets in TIME_WAIT for ~60s.
# QEMU #2 then fails to bind 8421 and the harness FAILs through no fault
# of the system-under-test.
#
# Fix: allocate a free port *per QEMU instance* instead of pinning one.
# This file provides three small shell helpers that both test-qemu.sh and
# test-qemu-extended.sh can source when they want the behavior. Keeping
# test-qemu.sh on its historical hard-coded 2222/8421 pair is deliberate
# (pkg-16 production tests rely on that stable ABI); the extended smoke
# is where collisions actually happen, so that's where the dynamic path
# is wired up today. The helper is factored separately so a future third
# script (or a CI matrix that runs N QEMUs in parallel) can opt in with
# a single `source`.
#
# Contract:
#   _qemu_port_is_free <port>   -- 0 if nothing listening on 127.0.0.1:<port>
#   _qemu_port_wait_free <port> <seconds>
#                                -- block until port is free, or fail after <seconds>
#   _qemu_port_pick <lo> <hi>    -- echo first free port in [lo, hi], or empty on exhaust
#   _qemu_port_pick_ephemeral   -- ask the kernel for an OS-assigned free port (bind :0)
#
# All helpers are pure bash + a single `python3 -c` for the ephemeral
# path (python3 is always present in the WSL Arch environment these
# scripts target, per CLAUDE.md).

# Return 0 (true) if port is currently free on 127.0.0.1, 1 otherwise.
# Uses /dev/tcp for no-new-binary probing; `ss` would also work but has
# different output on different distros, and /dev/tcp is in bash itself.
_qemu_port_is_free() {
    local port="$1"
    if [ -z "$port" ]; then
        return 2
    fi
    # /dev/tcp connect success == something is listening == NOT free.
    # `timeout 1` so a black-holed SYN doesn't hang the helper forever.
    if timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/${port}" 2>/dev/null; then
        return 1
    fi
    return 0
}

# Poll until <port> is free (or give up after <seconds>).
# Echo the port on success; echo empty + return 1 on timeout.
_qemu_port_wait_free() {
    local port="$1"
    local max_seconds="${2:-60}"
    local t0 elapsed
    t0=$(date +%s)
    while : ; do
        if _qemu_port_is_free "$port"; then
            printf '%s' "$port"
            return 0
        fi
        elapsed=$(( $(date +%s) - t0 ))
        if [ "$elapsed" -ge "$max_seconds" ]; then
            return 1
        fi
        sleep 1
    done
}

# Walk [lo..hi] and echo the first free port. Returns 1 if none found.
_qemu_port_pick() {
    local lo="${1:-8500}"
    local hi="${2:-8599}"
    local p
    for p in $(seq "$lo" "$hi"); do
        if _qemu_port_is_free "$p"; then
            printf '%s' "$p"
            return 0
        fi
    done
    return 1
}

# Ask the kernel for an ephemeral port via Python's bind(:0) trick.
# This is the cleanest path: there's no TOCTOU window because we release
# the socket immediately and QEMU picks it up on the next syscall. QEMU's
# internal bind retry handles the tiny race if something else grabs it.
# Falls back to _qemu_port_pick if python3 is unavailable.
_qemu_port_pick_ephemeral() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()' 2>/dev/null \
            && return 0
    fi
    _qemu_port_pick 8500 8599
}
