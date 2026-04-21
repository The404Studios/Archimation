#!/usr/bin/env bash
# scripts/test-bootc-attestation.sh — Agent ε / S72 Phase 1
#
# Verifies trust.ko refuses to initialize when /usr has been tampered with.
# This is THE critical test: without it, the entire measured-boot moat
# story is unverifiable.
#
# Happy-path loop:
#   1. Boot bootc image with swtpm
#   2. dmesg shows "trust: TPM2 attestation PASSED"
#   3. /dev/trust is a char device
#
# Tamper loop:
#   1. Boot same image
#   2. Pause VM (QMP `stop`)
#   3. Mount the virtio root disk on the HOST, flip one byte at
#      /usr/bin/peloader offset 100, unmount
#   4. QMP `system_reset` (cold boot with altered rootfs)
#   5. dmesg should show "trust: PCR 11 mismatch" or "attestation failed"
#   6. /dev/trust should be absent (module refused to init)
#
# Both stages are gated behind the same graceful stub pattern as
# test-bootc-rollback.sh: if the real tooling isn't present we exit 5
# with a clear message showing which stage would have blocked.
#
# Exit codes:
#   0  happy-path PASSED + tamper detected + /dev/trust absent after tamper
#   1  happy-path PASSED but tamper NOT detected (security regression!)
#   2  happy-path failed (module didn't come up HARDWARE in clean boot)
#   3  prereq missing (qemu / swtpm / OVMF)
#   4  image-build failed
#   5  graceful stub exit (no tooling)

set -uo pipefail

# ─── Paths / env ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

WORK_DIR="${WORK_DIR:-/tmp/bootc-attest}"
SWTPM_DIR="${SWTPM_DIR:-$WORK_DIR/swtpm}"
SWTPM_SOCK="$SWTPM_DIR/swtpm-sock"
QEMU_SERIAL_LOG="$WORK_DIR/serial.log"
QEMU_MONITOR_SOCK="$WORK_DIR/qmp.sock"
SSH_PORT="${SSH_PORT:-2225}"     # distinct from rollback (2224)
QCOW="$WORK_DIR/attest.qcow2"
OVMF_CODE="${OVMF_CODE:-/usr/share/edk2-ovmf/x64/OVMF_CODE.fd}"
OVMF_VARS_TEMPLATE="${OVMF_VARS_TEMPLATE:-/usr/share/edk2-ovmf/x64/OVMF_VARS.fd}"
OVMF_VARS="$WORK_DIR/OVMF_VARS.fd"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"

ALLOW_STUB="${ALLOW_STUB:-1}"

QEMU_PID=""
SWTPM_PID=""

log()    { printf '[attest] %s\n' "$*" >&2; }
stage()  { printf '\n[STAGE-%s] %s\n' "$1" "$2" >&2; }
fail()   { log "FAIL: $1"; exit "${2:-1}"; }
stub()   { log "STUB: $1 — exiting with code 5"; exit 5; }

cleanup() {
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill "$QEMU_PID" 2>/dev/null || true
        for _ in 1 2 3; do kill -0 "$QEMU_PID" 2>/dev/null || break; sleep 1; done
        kill -9 "$QEMU_PID" 2>/dev/null || true
    fi
    if [ -n "$SWTPM_PID" ] && kill -0 "$SWTPM_PID" 2>/dev/null; then
        kill "$SWTPM_PID" 2>/dev/null || true
    fi
    [ "${KEEP:-0}" = "1" ] || rm -rf "$SWTPM_DIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$WORK_DIR" "$SWTPM_DIR"
[ "${DEBUG:-0}" = "1" ] && set -x

# ─── Stage 0: tooling audit ──────────────────────────────────────────
stage 0 "audit tooling"
HAVE_QEMU=0;  command -v qemu-system-x86_64 >/dev/null 2>&1 && HAVE_QEMU=1
HAVE_SWTPM=0; command -v swtpm >/dev/null 2>&1 && HAVE_SWTPM=1
HAVE_BIB=0;   command -v bootc-image-builder >/dev/null 2>&1 && HAVE_BIB=1
HAVE_OVMF=0;  [ -f "$OVMF_CODE" ] && HAVE_OVMF=1
HAVE_SSH=0;   command -v ssh >/dev/null 2>&1 && HAVE_SSH=1
HAVE_GUESTMOUNT=0; command -v guestmount >/dev/null 2>&1 && HAVE_GUESTMOUNT=1
HAVE_QEMU_NBD=0;   command -v qemu-nbd >/dev/null 2>&1 && HAVE_QEMU_NBD=1

log "tooling: qemu=$HAVE_QEMU swtpm=$HAVE_SWTPM bib=$HAVE_BIB ovmf=$HAVE_OVMF ssh=$HAVE_SSH guestmount=$HAVE_GUESTMOUNT qemu-nbd=$HAVE_QEMU_NBD"

MISSING=0
[ "$HAVE_QEMU" = "0" ]  && MISSING=1
[ "$HAVE_SWTPM" = "0" ] && MISSING=1
[ "$HAVE_BIB" = "0" ]   && MISSING=1
[ "$HAVE_OVMF" = "0" ]  && MISSING=1
if [ "$HAVE_GUESTMOUNT" = "0" ] && [ "$HAVE_QEMU_NBD" = "0" ]; then
    MISSING=1   # need one of the two to modify the guest filesystem offline
fi
if [ "$MISSING" = "1" ]; then
    if [ "$ALLOW_STUB" = "1" ]; then
        stub "one or more of qemu/swtpm/bootc-image-builder/OVMF/guestmount|qemu-nbd missing"
    fi
    fail "required tooling missing (see tooling line above)" 3
fi

# ─── Stage 1: build + convert image ──────────────────────────────────
stage 1 "build image A and convert to qcow2"
bash "$SCRIPT_DIR/test-bootc-build.sh" 2>&1 | sed 's/^/[build] /' \
    || fail "image build failed" 4

bootc-image-builder build \
    --type qcow2 \
    --output "$QCOW" \
    localhost/archwindows-bootc:test \
    2>&1 | sed 's/^/[bib] /' \
    || fail "bootc-image-builder failed" 4

# ─── Stage 2: start swtpm ────────────────────────────────────────────
stage 2 "start swtpm"
swtpm socket --tpm2 \
    --tpmstate "dir=$SWTPM_DIR" \
    --ctrl "type=unixio,path=$SWTPM_SOCK" \
    --log "level=20,file=$WORK_DIR/swtpm.log" \
    >/dev/null 2>&1 &
SWTPM_PID=$!
for _ in 1 2 3; do [ -S "$SWTPM_SOCK" ] && break; sleep 1; done
[ -S "$SWTPM_SOCK" ] || fail "swtpm socket missing" 3
cp "$OVMF_VARS_TEMPLATE" "$OVMF_VARS"

# ─── Stage 3: boot clean image, verify HARDWARE attestation ──────────
stage 3 "boot CLEAN image, expect 'TPM2 attestation PASSED' in dmesg"
_boot_qemu() {
    qemu-system-x86_64 \
        -enable-kvm \
        -m 4096 -smp 2 \
        -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
        -drive if=pflash,format=raw,file="$OVMF_VARS" \
        -drive file="$QCOW",if=virtio,format=qcow2 \
        -device tpm-tis,tpmdev=tpm0 \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -chardev socket,id=chrtpm,path="$SWTPM_SOCK" \
        -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
        -device virtio-net-pci,netdev=net0 \
        -serial file:"$QEMU_SERIAL_LOG" \
        -qmp "unix:${QEMU_MONITOR_SOCK},server,nowait" \
        -nographic \
        -daemonize
}
_wait_ssh() {
    for i in $(seq 1 60); do
        if ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- true 2>/dev/null; then
            return 0
        fi
        sleep 5
    done
    return 1
}

_boot_qemu || fail "qemu launch failed" 2
_wait_ssh  || fail "VM never accepted SSH on clean boot" 2

DMESG_CLEAN="$(ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- 'sudo dmesg | grep -Ei "trust|attestation|PCR"' 2>&1 || true)"
log "dmesg (clean):"; printf '%s\n' "$DMESG_CLEAN" | sed 's/^/  /' >&2

case "$DMESG_CLEAN" in
    *"attestation PASSED"*|*"TPM2 attestation ok"*)
        log "clean boot: HARDWARE attestation confirmed" ;;
    *)
        fail "clean boot: did not observe attestation PASSED line" 2 ;;
esac

DEV_TRUST="$(ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- 'test -c /dev/trust && echo yes || echo no' 2>/dev/null || echo no)"
[ "$DEV_TRUST" = "yes" ] || fail "/dev/trust absent after clean boot" 2
log "clean boot: /dev/trust present"

# ─── Stage 4: pause VM ───────────────────────────────────────────────
stage 4 "pause VM (QMP stop)"
if command -v socat >/dev/null 2>&1; then
    printf '{"execute":"qmp_capabilities"}\n{"execute":"stop"}\n' \
        | socat - "UNIX-CONNECT:$QEMU_MONITOR_SOCK" >/dev/null 2>&1 \
        || fail "QMP stop failed" 2
else
    log "WARN: socat not available — cannot send QMP stop; killing QEMU for offline edit"
    kill "$QEMU_PID" 2>/dev/null || true
fi

# ─── Stage 5: tamper — flip a byte at /usr/bin/peloader offset 100 ──
stage 5 "offline tamper: mount qcow2 r/w on host, flip byte"

MNT="$WORK_DIR/mnt"
mkdir -p "$MNT"
MOUNTED=0

if [ "$HAVE_GUESTMOUNT" = "1" ]; then
    log "mounting with guestmount"
    guestmount -a "$QCOW" -m /dev/sda3:/ --rw "$MNT" \
        || fail "guestmount failed (rootfs partition may not be /dev/sda3)" 2
    MOUNTED=1
elif [ "$HAVE_QEMU_NBD" = "1" ]; then
    log "mounting with qemu-nbd"
    sudo modprobe nbd max_part=8 2>/dev/null || true
    sudo qemu-nbd --connect=/dev/nbd0 "$QCOW" \
        || fail "qemu-nbd connect failed" 2
    # Best-effort: try p3 first (typical bootc layout: EFI, xbootldr, root)
    for part in /dev/nbd0p3 /dev/nbd0p2 /dev/nbd0p1; do
        if sudo mount "$part" "$MNT" 2>/dev/null; then
            MOUNTED=1; break
        fi
    done
    if [ "$MOUNTED" = "0" ]; then
        sudo qemu-nbd --disconnect /dev/nbd0 || true
        fail "could not mount any partition via nbd" 2
    fi
fi

[ "$MOUNTED" = "1" ] || fail "rootfs not mounted — tamper impossible" 2

# Locate peloader inside the ostree deployment root. ostree lays out
# content under /ostree/deploy/<stateroot>/deployments/<csum.N>/, so
# we search broadly.
PELOADER="$(find "$MNT" -path '*/usr/bin/peloader' 2>/dev/null | head -1)"
if [ -z "$PELOADER" ]; then
    # guestfs may have mounted the ostree composefs root directly.
    PELOADER="$(find "$MNT" -name peloader -type f 2>/dev/null | head -1)"
fi
[ -n "$PELOADER" ] && [ -f "$PELOADER" ] || {
    log "WARN: peloader not found under $MNT — listing for diagnostics:"
    ls -la "$MNT" >&2 || true
    fail "peloader path not found in mounted rootfs" 2
}
log "peloader located at: $PELOADER"

# Flip byte 100 (printf | dd). We XOR with 0xFF to keep it a deterministic change.
dd if="$PELOADER" bs=1 count=1 skip=100 2>/dev/null | xxd | sed 's/^/  [before] /' >&2 || true
ORIG_BYTE="$(dd if="$PELOADER" bs=1 count=1 skip=100 2>/dev/null | od -An -tu1 | tr -d ' ')"
NEW_BYTE=$(( (${ORIG_BYTE:-0} ^ 0xFF) & 0xFF ))
printf '\\x%02x' "$NEW_BYTE" \
    | xargs -I {} printf '{}' \
    | dd of="$PELOADER" bs=1 count=1 seek=100 conv=notrunc 2>/dev/null \
    || fail "byte flip failed" 2
log "byte 100: $ORIG_BYTE -> $NEW_BYTE"

sync
if [ "$HAVE_GUESTMOUNT" = "1" ]; then
    guestunmount "$MNT" || fail "guestunmount failed" 2
else
    sudo umount "$MNT" || true
    sudo qemu-nbd --disconnect /dev/nbd0 || true
fi
log "rootfs unmounted; byte flip committed"

# ─── Stage 6: boot tampered image, expect PCR mismatch ──────────────
stage 6 "boot TAMPERED image, expect 'PCR 11 mismatch' + no /dev/trust"

# Re-launch if we killed QEMU; otherwise send QMP system_reset.
if kill -0 "${QEMU_PID:-0}" 2>/dev/null; then
    printf '{"execute":"qmp_capabilities"}\n{"execute":"system_reset"}\n' \
        | socat - "UNIX-CONNECT:$QEMU_MONITOR_SOCK" >/dev/null 2>&1 || true
else
    _boot_qemu || fail "tampered-boot qemu launch failed" 2
fi

# Wait for SSH — but if trust.ko refuses to init, the base system still
# comes up, so SSH should still work. It's `/dev/trust` that must be missing.
_wait_ssh || fail "tampered boot: VM never came up" 2

DMESG_TAMPER="$(ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- 'sudo dmesg | grep -Ei "trust|attestation|PCR"' 2>&1 || true)"
log "dmesg (tampered):"; printf '%s\n' "$DMESG_TAMPER" | sed 's/^/  /' >&2

SAW_MISMATCH=0
case "$DMESG_TAMPER" in
    *"PCR 11 mismatch"*|*"attestation failed"*|*"attestation FAILED"*|*"refusing to init"*)
        SAW_MISMATCH=1 ;;
esac

DEV_TRUST_AFTER="$(ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- 'test -c /dev/trust && echo yes || echo no' 2>/dev/null || echo no)"

if [ "$SAW_MISMATCH" = "1" ] && [ "$DEV_TRUST_AFTER" = "no" ]; then
    log "tamper detected: PCR mismatch line in dmesg AND /dev/trust absent — PASS"
    exit 0
fi

log "SECURITY REGRESSION:"
log "  PCR-mismatch line: $([ "$SAW_MISMATCH" = "1" ] && echo yes || echo NO)"
log "  /dev/trust:        $DEV_TRUST_AFTER (expected: no)"
exit 1
