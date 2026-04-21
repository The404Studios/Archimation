# S72 / Agent ε — bootc Atomic-Rollback Test Harness

**Status:** Phase 1 kickoff. Skeleton shipped; CI gate wired; E2E runs
deferred until α/β/γ/δ lands their pieces and runner tooling (swtpm,
bootc-image-builder, OVMF) is reliable in the matrix.

**Author:** Agent ε (test harness owner)
**Date:** 2026-04-20
**Reviewers:** Agents α/β/γ/δ; user
**Related:** [s71_g_atomic_updates.md](s71_g_atomic_updates.md),
[s71_k_measured_boot.md](s71_k_measured_boot.md)

---

## Why this document exists

The atomic-rollback story is the central value proposition of the bootc
deliverable.  We tell the user:

> Upgrade.  If it breaks, reboot into the previous deployment.  The
> integrity of the prior deployment is preserved by the TPM-anchored
> measured boot — tampering breaks it.

Without automated proof that the story holds, we're trusting marketing
over engineering.  This harness is the PR gate that keeps us honest.

---

## What "atomic rollback" actually means

1. **Boot N**: system is running deployment **A** (signed composefs tree,
   PCR 11 extended to `sha256(A)`).
2. **`bootc upgrade`**: pulls container image **B**, stages deployment B
   side-by-side with A on the same filesystem.  bootc flips the
   bootloader default to B.  **No commit yet** — A is still bootable.
3. **Reboot**: bootloader offers both A and B; defaults to B.  PCR 11 =
   `sha256(B)` after firmware measures it.  trust.ko's golden table
   contains both hashes and attests OK.
4. **User finds B broken** (e.g. regression in ai-control-daemon):
   selects A at the bootloader menu → system boots A with full
   integrity, PCR 11 matches A's golden hash.
5. **Persistent rollback**: `bootc rollback` flips the default back
   permanently.  Subsequent reboots default to A until another upgrade.

Key invariants:
- A's content was never touched during B's stage — the "rollback" is a
  bootloader pointer flip, not a file recovery.
- Both deployments remain attestable after the rollback (neither is
  marked tampered).
- `/var` survives: user data, container state, logs are on a separate
  rw tree mounted at the same path in both deployments.

---

## Why QEMU + swtpm + OVMF is the canonical test loop

Measured boot requires:

1. **UEFI firmware that extends PCRs** — OVMF (edk2) is the canonical
   open-source UEFI and behaves identically to real firmware for PCR
   purposes.
2. **A TPM 2.0 device** — swtpm emulates TPM 2.0 faithfully enough that
   the kernel's `tpm_tis` driver doesn't know it's a mock.  Real
   hardware TPMs don't give us reset/replay, so swtpm is *better* for
   deterministic tests.
3. **A hypervisor that lets us pause + modify guest state** — QEMU's
   QMP (`stop`, `system_reset`) + qcow2 snapshots let us tamper offline
   and boot the tampered image in a predictable sequence.

The combination is well-worn: Fedora CoreOS, Universal Blue, and every
bootc upstream project uses it.  Agent α's choice to follow bootcrew/mono
plus M1cha/bootc-archlinux (documented in `s72_alpha_bootc_foundation.md`)
puts us on the same rails.

Canonical command shape:

```bash
swtpm socket --tpm2 \
  --tpmstate dir=/tmp/mytpm \
  --ctrl type=unixio,path=/tmp/mytpm/swtpm-sock &

qemu-system-x86_64 \
  -enable-kvm -m 4096 -smp 2 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2-ovmf/x64/OVMF_CODE.fd \
  -drive if=pflash,format=raw,file=./OVMF_VARS.fd \
  -drive file=./image.qcow2,if=virtio,format=qcow2 \
  -device tpm-tis,tpmdev=tpm0 \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -chardev socket,id=chrtpm,path=/tmp/mytpm/swtpm-sock \
  -netdev user,id=net0,hostfwd=tcp::2224-:22 \
  -device virtio-net-pci,netdev=net0 \
  -qmp unix:/tmp/qmp.sock,server,nowait \
  -serial file:./serial.log -nographic -daemonize
```

The two non-obvious bits:
- `-drive if=pflash` for both `OVMF_CODE.fd` (read-only) and a private
  copy of `OVMF_VARS.fd` (read-write).  Without the split you can't run
  two VMs concurrently against the same firmware.
- `chardev socket` + `tpmdev emulator` is the glue that routes TPM
  commands from guest → QEMU → swtpm over a Unix socket.

---

## The three critical tests (and why each one matters)

### 1. `test-bootc-build.sh` — build gate

Proves: the Containerfile produces an image; the image has the packages
we think it does.  Without this, later tests would green on broken
images because e.g. `pacman -Q trust-system` was hidden behind a pipe
that always returned 0.

Contract:
- Exit 0 if build succeeds AND `pacman -Q trust-system ai-control-daemon
  pe-loader` works inside the image.
- Writes `/tmp/bootc-test/image.tar` as the CI artifact that downstream
  jobs reuse (no re-build in rollback/attestation jobs).
- Writes `/tmp/bootc-test/build-mode` with `REAL` or `STUB` so downstream
  tests can gracefully downgrade when Agent α's Containerfile isn't
  reachable yet.

### 2. `test-bootc-rollback.sh` — the headline test

Proves: the atomic-rollback story works end-to-end with real images on
real emulated hardware.

13 explicit stages, each with a `[STAGE-N]` log marker so a CI operator
can see exactly where the harness stopped.  Current stubs gracefully
exit 5 (with a `STUB:` line naming the missing tool) until the required
local tooling is present.

Stages:
| # | What it does | Blocker tool |
|---|---|---|
| 0 | Audit tooling | — |
| 1 | Build deployment A (delegates to `test-bootc-build.sh`) | podman |
| 2 | Convert OCI A → qcow2 | bootc-image-builder |
| 3 | Start swtpm socket | swtpm |
| 4 | Snapshot OVMF_VARS | edk2-ovmf |
| 5 | Boot deployment A in QEMU | qemu-system-x86_64 |
| 6 | SSH in; verify `ai-health` reports HARDWARE mode | ssh |
| 7 | Bump a version string (touch `bootc/.rollback-test-bump`) | — |
| 8 | Build deployment B | podman |
| 9 | Stage B in the running VM (simulate `bootc upgrade`) | bootc CLI |
| 10 | Reboot; verify on deployment B | ssh + bootc status --json |
| 11 | Mask ai-control.service to deliberately break B | — |
| 12 | `bootc rollback` | bootc CLI |
| 13 | Reboot; verify back on A with integrity intact | ssh + ai-health |

### 3. `test-bootc-attestation.sh` — the moat test

Proves: trust.ko refuses to init when the rootfs has been tampered with.
This is THE test the whole measured-boot story lives or dies by.

Tamper loop:
1. Happy-path boot (image A) → `dmesg` shows `TPM2 attestation PASSED`,
   `/dev/trust` is a char device.
2. QMP `stop` pauses the VM.
3. On the host: `guestmount` (or `qemu-nbd` fallback) the qcow2 r/w,
   locate `/usr/bin/peloader`, XOR byte 100 with 0xFF, unmount.
4. QMP `system_reset` (or relaunch QEMU) boots the tampered image.
5. `dmesg` should contain `PCR 11 mismatch` / `attestation failed`.
6. `test -c /dev/trust` should FAIL — module refused to init.

If `dev/trust` IS present after tamper, the CI job emits
`::error::Security regression` and the PR is blocked.  This is the
loudest failure mode we have.

---

## CI gate strategy

`.github/workflows/bootc.yml` defines four jobs on a `needs:` chain:

```
build ─┬─► rollback-smoke
       ├─► attestation-smoke
       └─► pytest-gate
```

- **build** runs on every matching PR/push; cheap (~5 min).  Exit code
  is the PR gate.
- **rollback-smoke** and **attestation-smoke** run after `build`.  Both
  cost ~20-30 min each (bootc-image-builder + QEMU boot is the bottleneck).
- **pytest-gate** runs `tests/integration/test_bootc_lifecycle.py`; it
  reuses the build artifact and does NOT rebuild, so it's ~2 min.

Matrix strategy: for now, `ubuntu-latest` only.  When we add an Arch
runner (self-hosted or scheduled container), we'll extend the matrix.

**Path filters**: the workflow ONLY triggers on changes to `bootc/`,
`trust/`, `packages/`, or the harness itself.  This keeps the PR queue
fast for unrelated changes.

**`ALLOW_STUB_*` env toggles**: initially set to `1` in the scripts
(permissive) and `0` in the workflow (strict). As tooling lands, we
tighten the script defaults until they match CI.

**Exit 5 policy**: an exit-5 from any harness is "graceful stub" — the
job emits `::warning::` but does NOT fail the PR.  Security regressions
(exit 1 from the attestation test) DO fail the PR and are flagged with
`::error::`.

---

## What ships TODAY (Phase 1)

| Deliverable | State |
|---|---|
| `scripts/test-bootc-build.sh` | REAL — functional; falls back to a STUB image when Agent α's Containerfile is absent. |
| `scripts/test-bootc-rollback.sh` | SKELETON — 13 stages, graceful exits on missing tooling.  Runs end-to-end when swtpm + bootc-image-builder + OVMF are all present. |
| `scripts/test-bootc-attestation.sh` | SKELETON — 6 stages, same graceful-exit pattern.  Tamper path written but needs guestmount/qemu-nbd on the runner. |
| `.github/workflows/bootc.yml` | REAL — 4 jobs wired, path-filtered, artifact-chained. |
| `tests/integration/test_bootc_lifecycle.py` | REAL — 5 tests: 3 image-level gates (xfail-safe for STUB) + 2 syntactic gates on the harnesses. |
| `docs/research/s72_epsilon_test_harness.md` | REAL — this file. |

---

## What's stubbed (not shipped functional)

1. **Actual bootc upgrade inside the VM** (rollback stage 9): we have
   the scp + podman-load + bootc-switch commands documented, but we
   haven't verified them on a real image.  Unblocks when Agent α's
   image boots + Agent δ's installer brings bootc CLI inside.

2. **Partition layout in guestmount** (attestation stage 5): the tamper
   step tries `/dev/sda3` first, then walks partitions.  When Agent α's
   image has a stable layout documented, we can pin it and drop the
   walk.

3. **KVM vs TCG fallback**: the harnesses use `-enable-kvm`
   unconditionally.  If GitHub's runner doesn't provide `/dev/kvm`, the
   VM launch fails and we exit 2.  Should check and fall back to TCG
   with a longer timeout.  Tracked as a follow-up.

---

## Citations / prior art

- **bootc-image-builder**: <https://github.com/osbuild/bootc-image-builder>
  — official container that converts OCI images to bootable qcow2 / ISO.
- **Universal Blue CI**: <https://github.com/ublue-os/main/actions> —
  reference CI pipeline for bootc image rebuilds; our matrix + artifact
  pattern mirrors theirs.
- **swtpm**: <https://github.com/stefanberger/swtpm> — TPM 2.0 emulator
  used by libvirt, QEMU, and every bootc test harness upstream.
- **bootc rollback semantics**: <https://bootc-dev.github.io/bootc/man-md/bootc-rollback.8>
  — authoritative CLI reference.
- **OVMF / edk2**: <https://wiki.ubuntu.com/UEFI/EDK2> — UEFI firmware
  + PCR behavior doc.
- **ostree composefs PCR 11 semantics**: <https://github.com/containers/composefs#measurement>
  — explains why PCR 11 is the natural anchor for a signed composefs
  rootfs.
- **Fedora bootc integration tests**:
  <https://gitlab.com/fedora/bootc/tests> — worked examples of
  QEMU+swtpm lifecycle tests we can lift patterns from.

---

## Handoff to S73

By the end of S72 we expect:

- α: Containerfile produces a bootable image (currently produces an
  image; bootable under swtpm+OVMF TBD).
- β: trust.ko shipped + signed inside the image; `/dev/trust` appears
  on clean boot.
- γ: attestation opt-in wired at boot (trust.attest=hardware or
  /etc/trust/attest.conf).
- δ: bootc CLI installed inside the image so `bootc rollback` works.

At that point, flip `ALLOW_STUB_*=0` in the scripts (they already are
in CI) and the harness becomes the PR gate for real.  Any merged PR
that breaks rollback OR tamper-detection fails CI; rollback story is
proved not promised.

**Single most important thing to validate once β lands**: the tamper
test.  If `/dev/trust` is present on a boot with a flipped peloader
byte, we've got a security regression to fix before Phase 2.
