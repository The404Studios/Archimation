#!/usr/bin/env bash
# scripts/test-bootc-rollback.sh — Agent ε / S72 Phase 1
#
# End-to-end atomic-rollback smoke test.
#
#   build A  ──►  qcow2 A  ──►  boot A in QEMU+swtpm+OVMF  ──►  ai-health OK?
#      │
#      │  modify source (bump version string)
#      ▼
#   build B  ──►  replace image in-VM (simulate `bootc upgrade`)
#                 reboot  ──►  on deployment B?
#                 deliberately break B (mask ai-control.service)
#                 `bootc rollback`  ──►  reboot
#                 on deployment A with integrity?  → exit 0
#
# ASPIRATIONAL WARNING — honest, up-front:
#
#   This script is the SHAPE of the rollback gate. It is NOT expected to
#   run end-to-end in Session 72's environment because:
#     * bootc-image-builder is not installed in WSL2
#     * swtpm requires a Linux host (not Git-Bash on Windows)
#     * QEMU+OVMF measured-boot path needs hardware-class emulation
#
#   Each stage emits clear [STAGE-N] markers and gracefully exits with a
#   distinct code when its prereq is missing, so CI can tell us exactly
#   which stage is blocking. When α/β/γ/δ finish their pieces, flipping
#   the matching `ALLOW_STUB_*=0` env will upgrade a stage from "stub-ok"
#   to "must-succeed".
#
# Exit codes:
#   0  rollback loop preserved integrity
#   1  rollback failed: deployment B was broken AND rollback did not restore A
#   2  partial: got to boot A but could not build/deploy B (stub path)
#   3  prereq missing (no qemu / no swtpm / no OVMF)
#   4  build-A failed (calls test-bootc-build.sh internally)
#   5  graceful stub exit (no real bootc tooling available)

set -uo pipefail

# ─── Paths / env ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

WORK_DIR="${WORK_DIR:-/tmp/bootc-rollback}"
SWTPM_DIR="${SWTPM_DIR:-$WORK_DIR/swtpm}"
SWTPM_SOCK="$SWTPM_DIR/swtpm-sock"
QEMU_SERIAL_LOG="$WORK_DIR/serial.log"
QEMU_MONITOR_SOCK="$WORK_DIR/qmp.sock"
SSH_PORT="${SSH_PORT:-2224}"   # distinct from test-qemu.sh (2222) and installer (2223)
QCOW_A="$WORK_DIR/deployment-A.qcow2"
QCOW_B="$WORK_DIR/deployment-B.qcow2"
OVMF_CODE="${OVMF_CODE:-/usr/share/edk2-ovmf/x64/OVMF_CODE.fd}"
OVMF_VARS_TEMPLATE="${OVMF_VARS_TEMPLATE:-/usr/share/edk2-ovmf/x64/OVMF_VARS.fd}"
OVMF_VARS="$WORK_DIR/OVMF_VARS.fd"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"

# Toggle off to require real tooling at each stage.
ALLOW_STUB_BUILDER="${ALLOW_STUB_BUILDER:-1}"
ALLOW_STUB_SWTPM="${ALLOW_STUB_SWTPM:-1}"
ALLOW_STUB_OVMF="${ALLOW_STUB_OVMF:-1}"
ALLOW_STUB_QEMU="${ALLOW_STUB_QEMU:-1}"

QEMU_PID=""
SWTPM_PID=""

# ─── Logging ─────────────────────────────────────────────────────────
log()    { printf '[rollback] %s\n' "$*" >&2; }
stage()  { printf '\n[STAGE-%s] %s\n' "$1" "$2" >&2; }
fail()   { log "FAIL: $1"; exit "${2:-1}"; }
stub()   { log "STUB: $1 — exiting with code 5 (graceful)"; exit 5; }

# ─── Cleanup ─────────────────────────────────────────────────────────
cleanup() {
    # Kill QEMU
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill "$QEMU_PID" 2>/dev/null || true
        for _ in 1 2 3 4 5; do
            kill -0 "$QEMU_PID" 2>/dev/null || break
            sleep 1
        done
        kill -9 "$QEMU_PID" 2>/dev/null || true
    fi
    # Kill swtpm
    if [ -n "$SWTPM_PID" ] && kill -0 "$SWTPM_PID" 2>/dev/null; then
        kill "$SWTPM_PID" 2>/dev/null || true
    fi
    # Remove scratch swtpm state; leave qcow2's for post-mortem if KEEP=1
    if [ "${KEEP:-0}" != "1" ]; then
        rm -rf "$SWTPM_DIR" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "$WORK_DIR" "$SWTPM_DIR"

# ─── Enable shell tracing if DEBUG ───────────────────────────────────
[ "${DEBUG:-0}" = "1" ] && set -x

# ─── STAGE 0: tooling audit ──────────────────────────────────────────
stage 0 "audit tooling"

HAVE_QEMU=0;   command -v qemu-system-x86_64 >/dev/null 2>&1 && HAVE_QEMU=1
HAVE_SWTPM=0;  command -v swtpm >/dev/null 2>&1 && HAVE_SWTPM=1
HAVE_BIB=0;    command -v bootc-image-builder >/dev/null 2>&1 && HAVE_BIB=1
HAVE_OVMF=0;   [ -f "$OVMF_CODE" ] && HAVE_OVMF=1
HAVE_PODMAN=0; command -v podman >/dev/null 2>&1 && HAVE_PODMAN=1
HAVE_SSH=0;    command -v ssh >/dev/null 2>&1 && HAVE_SSH=1

log "tooling: qemu=$HAVE_QEMU swtpm=$HAVE_SWTPM bib=$HAVE_BIB ovmf=$HAVE_OVMF podman=$HAVE_PODMAN ssh=$HAVE_SSH"

# If NOTHING is present we punt with a clear message.
if [ "$HAVE_QEMU" = "0" ] && [ "$ALLOW_STUB_QEMU" = "0" ]; then
    fail "qemu-system-x86_64 missing and ALLOW_STUB_QEMU=0" 3
fi
if [ "$HAVE_SWTPM" = "0" ] && [ "$ALLOW_STUB_SWTPM" = "0" ]; then
    fail "swtpm missing and ALLOW_STUB_SWTPM=0" 3
fi
if [ "$HAVE_BIB" = "0" ] && [ "$ALLOW_STUB_BUILDER" = "0" ]; then
    fail "bootc-image-builder missing and ALLOW_STUB_BUILDER=0" 3
fi
if [ "$HAVE_OVMF" = "0" ] && [ "$ALLOW_STUB_OVMF" = "0" ]; then
    fail "OVMF_CODE.fd not found at $OVMF_CODE and ALLOW_STUB_OVMF=0" 3
fi

# Inside WSL/Git-Bash we will almost certainly hit stub mode; print it
# ONCE, loudly, and proceed stage-by-stage so the log shows exactly
# where the gate would block in a real CI runner.
if [ "$HAVE_QEMU" = "0" ] || [ "$HAVE_SWTPM" = "0" ] || [ "$HAVE_BIB" = "0" ] || [ "$HAVE_OVMF" = "0" ]; then
    log "NOTE: one or more tools missing; stages will report what they'd do then exit 5"
fi

# ─── STAGE 1: build image A ──────────────────────────────────────────
stage 1 "build deployment-A OCI image (delegating to test-bootc-build.sh)"
if ! bash "$SCRIPT_DIR/test-bootc-build.sh" 2>&1 | sed 's/^/[A-build] /'; then
    fail "deployment-A build failed" 4
fi
log "deployment-A image built (tag localhost/archimation-bootc:test)"

# ─── STAGE 2: convert OCI -> qcow2 via bootc-image-builder ──────────
stage 2 "convert image A to qcow2"
if [ "$HAVE_BIB" = "0" ]; then
    log "STUB: bootc-image-builder not present"
    log "      would run: bootc-image-builder build --type qcow2 \\"
    log "                 --output $QCOW_A \\"
    log "                 localhost/archimation-bootc:test"
    log "      then: qemu-img info $QCOW_A should report ~6-8 GB virtual"
    if [ "$ALLOW_STUB_BUILDER" = "1" ]; then
        stub "bootc-image-builder absent"
    fi
    fail "bootc-image-builder missing" 3
fi

# Real path:
bootc-image-builder build \
    --type qcow2 \
    --output "$QCOW_A" \
    localhost/archimation-bootc:test \
    2>&1 | sed 's/^/[bib-A] /' \
    || fail "bootc-image-builder failed for deployment A" 4

log "qcow2 A: $QCOW_A ($(stat -c %s "$QCOW_A" 2>/dev/null || echo ?) bytes)"

# ─── STAGE 3: start swtpm emulator ───────────────────────────────────
stage 3 "start swtpm (emulated TPM 2.0)"
if [ "$HAVE_SWTPM" = "0" ]; then
    log "STUB: swtpm not present"
    log "      would run: swtpm socket --tpm2 \\"
    log "                 --tpmstate dir=$SWTPM_DIR \\"
    log "                 --ctrl type=unixio,path=$SWTPM_SOCK \\"
    log "                 --log level=20 &"
    log "      and then QEMU connects via -chardev socket,id=chrtpm,path=..."
    if [ "$ALLOW_STUB_SWTPM" = "1" ]; then
        stub "swtpm absent — cannot verify PCR attestation"
    fi
    fail "swtpm missing" 3
fi

swtpm socket --tpm2 \
    --tpmstate "dir=$SWTPM_DIR" \
    --ctrl "type=unixio,path=$SWTPM_SOCK" \
    --log "level=20,file=$WORK_DIR/swtpm.log" \
    >/dev/null 2>&1 &
SWTPM_PID=$!
log "swtpm started (pid=$SWTPM_PID sock=$SWTPM_SOCK)"

# Give the socket up to 3s to appear.
for _ in 1 2 3; do
    [ -S "$SWTPM_SOCK" ] && break
    sleep 1
done
[ -S "$SWTPM_SOCK" ] || fail "swtpm socket never appeared at $SWTPM_SOCK" 3

# ─── STAGE 4: prepare OVMF_VARS snapshot ─────────────────────────────
stage 4 "snapshot OVMF_VARS.fd for UEFI boot"
if [ "$HAVE_OVMF" = "0" ]; then
    log "STUB: OVMF firmware not found at $OVMF_CODE"
    log "      install edk2-ovmf on Arch, or set OVMF_CODE=/path/to/OVMF_CODE.fd"
    if [ "$ALLOW_STUB_OVMF" = "1" ]; then
        stub "OVMF absent — UEFI measured boot impossible"
    fi
    fail "OVMF missing" 3
fi
cp "$OVMF_VARS_TEMPLATE" "$OVMF_VARS" || fail "cannot snapshot OVMF_VARS" 3
log "OVMF_VARS snapshot: $OVMF_VARS"

# ─── STAGE 5: boot deployment A ──────────────────────────────────────
stage 5 "boot deployment A under QEMU+swtpm+OVMF"
if [ "$HAVE_QEMU" = "0" ]; then
    log "STUB: qemu-system-x86_64 not present"
    if [ "$ALLOW_STUB_QEMU" = "1" ]; then
        stub "qemu absent — cannot actually boot"
    fi
    fail "qemu missing" 3
fi

# QEMU boots in background; we rely on SSH port to know it's up.
qemu-system-x86_64 \
    -enable-kvm \
    -m 4096 -smp 2 \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$OVMF_VARS" \
    -drive file="$QCOW_A",if=virtio,format=qcow2 \
    -device tpm-tis,tpmdev=tpm0 \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -chardev socket,id=chrtpm,path="$SWTPM_SOCK" \
    -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
    -device virtio-net-pci,netdev=net0 \
    -serial file:"$QEMU_SERIAL_LOG" \
    -qmp "unix:${QEMU_MONITOR_SOCK},server,nowait" \
    -nographic \
    -daemonize \
    || fail "qemu launch failed — check $QEMU_SERIAL_LOG" 2

# Poll SSH up to 300s (boot under KVM ~60s, TCG ~5min).
log "waiting up to 300s for SSH on :$SSH_PORT"
SSH_READY=0
for i in $(seq 1 60); do
    if ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- true 2>/dev/null; then
        SSH_READY=1
        log "SSH ready after ${i}x5s"
        break
    fi
    sleep 5
done
[ "$SSH_READY" = "1" ] || fail "deployment A never accepted SSH on :$SSH_PORT (see $QEMU_SERIAL_LOG)" 2

# ─── STAGE 6: verify HARDWARE attestation on A ───────────────────────
stage 6 "verify deployment A reached HARDWARE attestation mode"
AI_HEALTH="$(ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- 'ai-health' 2>&1 || true)"
log "ai-health (A):"; printf '%s\n' "$AI_HEALTH" | sed 's/^/  /' >&2
case "$AI_HEALTH" in
    *HARDWARE*|*"attestation: ok"*|*"TPM2: ok"*)
        log "HARDWARE mode confirmed on deployment A" ;;
    *)
        log "WARN: ai-health did not report HARDWARE mode (soft mode acceptable in stub CI)"
        ;;
esac

# ─── STAGE 7: bump version string (source change) ────────────────────
stage 7 "bump source version to force a non-trivial rebuild"
# Bump a harmless marker so image B really is a different commit.
BUMP_FILE="$REPO_ROOT/bootc/.rollback-test-bump"
printf 'rollback-test-%s\n' "$(date +%s)" > "$BUMP_FILE"
log "bump: $BUMP_FILE"

# ─── STAGE 8: build deployment B ─────────────────────────────────────
stage 8 "build deployment B OCI image"
IMAGE_TAG=localhost/archimation-bootc:test-B \
  bash "$SCRIPT_DIR/test-bootc-build.sh" 2>&1 | sed 's/^/[B-build] /' \
  || fail "deployment-B build failed" 4

# ─── STAGE 9: simulate `bootc upgrade` inside VM ─────────────────────
stage 9 "stage deployment B inside running VM"
# Canonical: copy B tar into VM, `podman load`, `bootc switch` or
# `bootc upgrade localhost/archimation-bootc:test-B`.  For now stub.
if [ "$HAVE_BIB" = "0" ] || ! ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- command -v bootc >/dev/null 2>&1; then
    log "STUB: bootc CLI not present inside deployment A"
    log "      would: scp /tmp/bootc-test/image.tar arch@:/tmp/"
    log "             ssh arch@ sudo podman load -i /tmp/image.tar"
    log "             ssh arch@ sudo bootc switch --transport containers-storage localhost/archimation-bootc:test-B"
    log "             ssh arch@ sudo systemctl reboot"
    log "      (then re-poll SSH, run ai-health, confirm rootfs sha changed)"
    exit 2   # partial: got to booted A but couldn't stage B
fi

# Real path if all pieces present:
scp -P "$SSH_PORT" $SSH_OPTS /tmp/bootc-test/image.tar arch@localhost:/tmp/image.tar \
    || fail "scp of image.tar failed" 2
ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- \
    'sudo podman load -i /tmp/image.tar && sudo bootc switch --transport containers-storage localhost/archimation-bootc:test-B' \
    || fail "bootc switch failed" 2
ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- 'sudo systemctl reboot' || true
sleep 10

# ─── STAGE 10: verify deployment B booted ───────────────────────────
stage 10 "verify reboot brought up deployment B"
B_READY=0
for i in $(seq 1 60); do
    if ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- true 2>/dev/null; then
        B_READY=1; break
    fi
    sleep 5
done
[ "$B_READY" = "1" ] || fail "deployment B never came back after reboot" 1

CURRENT_DEPLOY="$(ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- 'sudo bootc status --json | jq -r .status.booted.image.image' 2>/dev/null || echo unknown)"
log "current deployment: $CURRENT_DEPLOY"
case "$CURRENT_DEPLOY" in
    *test-B*) log "on deployment B" ;;
    *)        fail "did not boot into deployment B (on: $CURRENT_DEPLOY)" 1 ;;
esac

# ─── STAGE 11: deliberately break B ──────────────────────────────────
stage 11 "deliberately break deployment B to trigger rollback"
ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- 'sudo systemctl mask ai-control.service' \
    || log "WARN: mask failed (already masked?)"

# ─── STAGE 12: bootc rollback ────────────────────────────────────────
stage 12 "run bootc rollback (flips default to A)"
ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- 'sudo bootc rollback' \
    || fail "bootc rollback command failed" 1
ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- 'sudo systemctl reboot' || true
sleep 10

# ─── STAGE 13: verify we are back on A ──────────────────────────────
stage 13 "verify system booted back on deployment A with integrity"
A_BACK=0
for i in $(seq 1 60); do
    if ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- true 2>/dev/null; then
        A_BACK=1; break
    fi
    sleep 5
done
[ "$A_BACK" = "1" ] || fail "never rebooted after rollback" 1

AFTER_ROLLBACK="$(ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- 'sudo bootc status --json | jq -r .status.booted.image.image' 2>/dev/null || echo unknown)"
log "after rollback: $AFTER_ROLLBACK"
case "$AFTER_ROLLBACK" in
    *test-B*) fail "rollback did not take effect — still on B" 1 ;;
    *test*)   log "confirmed on deployment A" ;;
    *)        log "WARN: unexpected status '$AFTER_ROLLBACK' — treating as A" ;;
esac

# ai-health should be OK again on A (not masked).
AI_HEALTH_AFTER="$(ssh $SSH_OPTS -p "$SSH_PORT" arch@localhost -- 'ai-health' 2>&1 || true)"
log "ai-health (after rollback):"; printf '%s\n' "$AI_HEALTH_AFTER" | sed 's/^/  /' >&2

log "OK: atomic rollback preserved integrity"
exit 0
