# Archimation bootc — Phase 2 status

S78 Dev D, 2026-04-21. This document tracks what S72 Phase 1 shipped, what
Phase 2 scaffolds, and what Phase 3 will need from a human operator.

## 1. What Phase 1 shipped (S72)

Reference: memory `session72_bootc_phase1_foundation.md`. Five-agent landing
(α/β/γ/δ/ε).

| Surface | Owner | File(s) |
|---|---|---|
| Containerfile + layer graph | α | `bootc/Containerfile` (~137 LOC) |
| Local builder orchestrator | α | `bootc/build-bootc.sh` (buildah > podman > docker) |
| DKMS-at-build-time + MOK key hooks | β | `bootc/build-trust-module.sh`, `bootc/trust-keys/` |
| TPM2 PCR 11 attestation | γ | `trust/kernel/trust_attest.{h,c}` (439 LOC) |
| Installer (capability matrix, 4 axes) | δ | `profile/airootfs/usr/bin/ai-install-bootc` |
| Rollback + tamper smokes (aspirational) | ε | `scripts/test-bootc-*.sh`, `.github/workflows/bootc.yml` |

Architectural moves:
- `/usr` immutable via composefs + fs-verity, measured into TPM2 PCR 11.
- `/home`, `/opt`, `/srv`, `/root` become symlinks into `/var` (M1cha layout).
- DKMS is architecturally removed from bootc installs; modules are pre-built at
  image-build time against the pinned kernel and signed by `build-trust-module.sh`.
- `archlinux:latest` is the base — we are the first serious Arch-in-OCI project.

Known gaps carried from S72:
- `bootc` binary itself not in Arch core/extra; Containerfile Step 3 is a stub.
- Initramfs is dracut, not mkinitcpio (composefs works best with dracut).
- Floating `:latest` base tag — reproducibility hit documented below §3(a).

## 2. What Phase 2 scaffolds (this session)

S78 Dev D added four deltas:

### 2.1 `bootc/Containerfile` — additive policy notes + new steps
- Header block explaining digest-pin policy (not applied yet; see §3(a)).
- Header block explaining layer-order rationale (current order IS correct; do
  not reorder COPY earlier).
- **New Step 10**: `COPY bootc/install/install.toml /usr/lib/bootc/install/50-archimation.toml`.
- **New Step 11**: enables `archimation-mok-enroll.service` for first-boot MOK
  dance (guarded `|| true` while the unit itself is pending from Agent β).
- **Extended Step 12 (was 10)**: adds OCI labels `.url`, `.documentation`,
  `.version`, `.revision`, `.created`, `.authors`. Wired to `ARG IMAGE_VERSION`
  / `ARG IMAGE_REVISION` / `ARG IMAGE_CREATED` so CI can stamp them per-build.

### 2.2 `bootc/install/install.toml` — bootc-install defaults (NEW)
- `kargs`: `trust.attest=hardware`, `rd.systemd.gpt_auto=no`, `quiet`, `splash`.
- `filesystem.type = "btrfs"` (snapshot-ready; matches ai-install-bootc default).
- `block-device` INTENTIONALLY unset — runtime disk selection is owned by
  `ai-install-bootc` (δ) which presents the menu, never a TOML-pinned default
  that would brick users whose layout differs.
- Secure-boot MOK slot COMMENTED — upstream schema has no slot yet; first-boot
  service is the path.

### 2.3 `.github/workflows/bootc-image-publish.yml` — GHCR publish pipeline (NEW)
- Not a replacement for the existing `bootc.yml` (which runs rollback +
  attestation smokes). They run in parallel pipelines.
- Four jobs: `build-image` → (`scan-image`, `smoke-image`) → `push-image`.
- `push-image` is `if: false` — DISABLED in scaffold. See §5 for enablement steps.
- Scanners: trivy (SARIF, HIGH/CRITICAL) + syft (CycloneDX + SPDX SBOMs).
- `smoke-image` verifies trust.ko presence under `/usr/lib/modules/*/extra/`
  and required OCI labels (`containers.bootc`, `ostree.bootable`,
  `org.opencontainers.image.{title,source,licenses}`).

### 2.4 `scripts/build-bootc.sh` — local wrapper (NEW)
- Thin three-stage orchestrator matching `scripts/run-full-build.sh` shape:
  wall-clock timing, `_summary` trap, `[N/3]` stage banners.
- Stage 1 reuses `scripts/build-packages.sh` if `repo/x86_64/` has < 5 pkgs,
  otherwise idempotently skips.
- Stage 2 delegates to `bootc/build-bootc.sh` (S72 Agent α's script).
- Stage 3 exports to `output/archimation-bootc-<YYYYMMDD-HHMMSS>.tar` plus
  sha256 sidecar. Parallel to `output/archimation-*.iso`.

## 3. What Phase 3 will need (human review required)

Phase 3 is the point where scaffold becomes production. All of these are
deliberate gates — not tech debt, but hand-offs that want human acknowledgement.

### 3.1 Base image digest pinning
The Containerfile's `FROM docker.io/archlinux/archlinux:latest` is a floating
tag. A reproducible build needs `@sha256:<digest>`. Deferred because:
- The digest rolls weekly; pinning without automation (Renovate/Dependabot)
  fossilises the build against last week's CVEs.
- We have no digest-bump PR workflow. Landing a pin before landing the bump
  automation means manual digest chase on every upstream mirror roll.
- Exit criterion: `.github/dependabot.yml` or a scheduled rewriter action.

### 3.2 GHCR token provisioning
`bootc-image-publish.yml::push-image` needs either:
- The repo's `GITHUB_TOKEN` with `packages: write` (already scoped on the job).
  Default path; requires no extra secret but ties publish auth to the repo.
- A dedicated `GHCR_TOKEN` PAT from a bot/service account (NOT a personal PAT).
  More auditable but requires an operator account.

Until one of those is chosen and the `if: false` guard is flipped, NO PUSH
WILL HAPPEN. The artifact is uploaded to the workflow run instead.

### 3.3 MOK enrolment dance (first-boot)
Agent β ships a project signing key; its public half lands at
`/etc/archimation/keys/mok.der` in the image. Enrolment is per-machine and
requires a three-step operator dance at first boot:
1. shim loads `/boot/efi/EFI/<vendor>/MokManager.efi`.
2. Operator enters the 12-char enrolment password (generated by
   `ai-install-bootc`, staged at `/var/lib/archimation/mok-enroll.txt`).
3. Kernel then trusts the cert for module verification.

Step 11 of the Containerfile enables `archimation-mok-enroll.service` to
prompt the user. The unit file itself is owned by Agent β in profile/airootfs
and is not yet landed (guarded `|| true` so the image build doesn't fail on
its absence).

### 3.4 DCO / signed commits
Once the image is published under `ghcr.io/fourzerofour/archimation-bootc`,
downstream operators have a legitimate expectation of commit provenance.
Phase 3 should add:
- `Signed-off-by:` requirement (DCO GitHub App).
- Optional: GPG-signed commits via branch protection rules.

## 4. Operator runbook — bake locally

Pre-requisites on an Arch host or WSL2 Arch:
```bash
pacman -S buildah podman skopeo
```

Full pipeline (packages + bake + tarball export):
```bash
bash scripts/build-bootc.sh

# dry-run (prints the builder cmd, does not bake):
ARCHIMATION_BOOTC_DRYRUN=1 bash scripts/build-bootc.sh

# skip the package build (repo/x86_64/ must already have >=5 pkgs):
SKIP_PACKAGE_BUILD=1 bash scripts/build-bootc.sh

# custom tag:
TAG=ghcr.io/you/archimation-bootc:wip bash scripts/build-bootc.sh
```

Smoke-test the resulting image:
```bash
# plain OCI inspect (not a real boot):
podman run --rm -it --entrypoint /bin/bash archimation-bootc:dev

# inside the container:
pacman -Q | wc -l                       # ~400+ packages
ls /usr/bin/pe-loader                   # our loader binary
ls /usr/lib/modules/*/extra/trust.ko    # pre-built signed module (Agent β)
systemctl list-unit-files | grep ai-    # our units enabled
```

## 5. CI hand-off — where to enable push

The workflow `.github/workflows/bootc-image-publish.yml` has four jobs stacked
`build-image` → (`scan-image`, `smoke-image`) → `push-image`.

To flip the push gate (Phase 3):

1. Merge a PR that lands `GHCR_TOKEN` as a repo secret (or confirm the
   default `GITHUB_TOKEN` is acceptable).
2. In `bootc-image-publish.yml::push-image`, change:
   ```yaml
   if: false
   ```
   to:
   ```yaml
   if: github.ref == 'refs/heads/main'
   ```
3. Optionally tighten `scan-image` to gate: change its `trivy image` flag
   `--exit-code 0` to `--exit-code 1` so HIGH/CRITICAL CVEs block the push.
4. Remove the `PHASE 2 GUARD` comment block in `push-image`.
5. Send a manual `workflow_dispatch` run to confirm push works before
   letting `push: main` trigger auto-publish.

The existing `bootc.yml` (rollback + attestation) is independent of this
publish pipeline — it gates correctness, not delivery. It can stay in its
current shape.

## 6. Files touched in S78 Dev D

| File | Delta | Purpose |
|---|---|---|
| `bootc/Containerfile` | +~60 LOC | Phase 2 notes, Step 10/11/12, OCI labels |
| `bootc/install/install.toml` | NEW ~55 LOC | bootc-install defaults |
| `.github/workflows/bootc-image-publish.yml` | NEW ~260 LOC | GHCR pipeline scaffold |
| `scripts/build-bootc.sh` | NEW ~110 LOC | Local 3-stage bake wrapper |
| `docs/bootc-phase2.md` | NEW (this file) | Phase 2 status + runbook |

No source-tree churn outside `bootc/`, `scripts/`, `.github/workflows/`,
`docs/`. No pkgrel bumps. No secret material.
