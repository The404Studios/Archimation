# S74 Agent GG — Rename Verify (ARCHWINDOWS → Archimation Sweep)

**Session:** 74
**Agent:** GG (integration verify)
**Date:** 2026-04-21
**HEAD at start:** `d5597f4` (post-EE rename commit)
**Scope:** integration verify only — no source edits, no ISO rebuild, no pkgrel bumps
**Verdict:** **MINOR-ISSUES** — source tree, profile, CI, docs all clean; one rename-sweep gap in `bootc/` (47 refs across 6 files) and a bootc-related test (4 refs). The `/etc/archwindows/` vs `/etc/archimation/` disagreement between `bootc/systemd-measure.conf` and the trust kernel/installer is the only cross-agent divergence. All builds, tests, lints pass at baseline. Safe to ship; recommend S75 sweeps `bootc/`.

---

## Exec summary

| Metric | Result |
|---|---|
| Source-tree rename completeness | CLEAN (0 refs in source C/Py per CC) |
| Docs + CLAUDE.md rename completeness | CLEAN (DD landed, 5 intentional historical in name-decision.md) |
| Profile/packages/scripts rename | MOSTLY CLEAN (EE landed but missed banner comment) |
| bootc/ rename | **NOT SWEPT** (~47 refs, no agent had it in scope) |
| Filesystem artifact renames | CLEAN for `.git`-tracked; output/*.iso.bak preserved intentionally |
| Cross-agent consistency on `/etc/archimation/` | CLEAN between CC + EE; `bootc/systemd-measure.conf` disagrees with old `/etc/archwindows/` |
| pe-loader build | CLEAN (`-Werror`, 42 .so + `loader/peloader` ELF) |
| services build | CLEAN |
| Catalysis gate | PASS (K_avg=0.093) |
| Producer-consumer lint | PASS (known=45, current_nonok=44) |
| Pytest integration | 280 pass / 24 fail / 83 skip / 1 xfail — IDENTICAL to BB baseline |
| Shell parse (`bash -n`) | CLEAN |
| YAML parse (.github/workflows/*.yml) | CLEAN |
| Manifest guard intact | YES (`verify_trust_dkms_manifest` present at scripts/build-packages.sh:99-155, trust_morphogen/quorum/algedonic.c in Kbuild) |
| PKGBUILD pkgname preservation | CLEAN (10 packages, all names intact) |
| ISO filename generator | CLEAN (`iso_name="archimation"`, `iso_label="ARCHIM_$(date +%Y%m)"`) |

---

## Four rename-agent commits (verified via `git log --oneline -10`)

| Agent | SHA | Scope | GG verification |
|---|---|---|---|
| CC | `439e59f` | source code (trust/, pe-loader/, services/, ai-control/, coherence/) | CLEAN: 0 refs in `trust/kernel/*.{c,h}`, `pe-loader/{loader,dlls,registry,include}/*.{c,h}`, `services/*/*.{c,h}`, `ai-control/**/*.py`, `coherence/**/*.{c,h}` |
| DD | `9efbf7d` | docs + CLAUDE.md + README.md | CLEAN: 5 refs remaining in `docs/architecture-name-decision.md` — all intentional historical quotes per commit message |
| EE | `d5597f4` | profile/, packages/, scripts/, .github/ | MOSTLY CLEAN: 1 residual ref in `profile/airootfs/etc/ssh/sshd_config.d/10-archimation-banner.conf` line 1 (comment header still reads `# ArchWindows pre-auth banner...`). File was correctly renamed; content header comment was not updated. Zero refs in scripts/, packages/, .github/ |
| FF | outside git | memory files | Not in-tree to verify here; trusted per FF's stated annotation process |

---

## Global grep audit

```
pattern: archwindows|arch windows|arch-windows   (case-insensitive)
scope:   *.{c,h,py,sh,md,jsonc,json,yml,txt,cfg,conf} + Makefile + PKGBUILD + Containerfile
```

**Total occurrences (excluding `.git/` and excluding `info/New Text Document.txt` which is user scratch): 57**

Breakdown by file:

| File | Count | Type |
|---|---|---|
| `bootc/trust-keys/README.md` | 23 | **unswept** — MOK key lifecycle docs, mentions `/tmp/archwindows-mok-gen`, `CN = ARCHWINDOWS Project trust.ko Signing`, `/usr/share/archwindows/trust-pub.der`, etc. |
| `bootc/README.md` | 8 | **unswept** — container image mode docs, `ghcr.io/fourzerofour/archwindows-bootc:latest` etc. |
| `bootc/build-bootc.sh` | 8 | **unswept** — build orchestrator, `TAG="archwindows-bootc:dev"`, `ARCHWINDOWS_BOOTC_DRYRUN` env var |
| `docs/architecture-name-decision.md` | 5 | **intentional** (historical quotes per DD) |
| `bootc/Containerfile` | 4 | **unswept** — OCI image labels (`org.opencontainers.image.title="archwindows-bootc"`) |
| `tests/integration/test_bootc_lifecycle.py` | 4 | **unswept** — `IMAGE_TAG = "localhost/archwindows-bootc:test"` + docstrings |
| `bootc/systemd-measure.conf` | 3 | **unswept, and one is cross-agent inconsistency** — `EXPECTED_PCR_OUT_ABS='/etc/archwindows/expected-pcr-11'` (should be `/etc/archimation/`) |
| `bootc/build-trust-module.sh` | 1 | **unswept** — `KCPPFLAGS="-DARCHWINDOWS_BOOTC_BUILD=1"` |
| `profile/airootfs/etc/ssh/sshd_config.d/10-archimation-banner.conf` | 1 | **EE miss** — file renamed but header comment still says "ArchWindows" |

Additionally: `info/New Text Document.txt` has 85 refs — this is a user scratch/notes file, not in the source tree canonical content. Left alone.

**`output/archwindows-*.iso*` files on disk (7 artifacts):** pre-rename ISO builds. Not tracked by git. No action taken (per constraints: no ISO rebuild).

---

## File-rename completeness

`find . -name '*archwindows*' -not -path './.git/*'` → only `output/archwindows-*.iso*` artifacts (listed above, pre-rename ISO files preserved).

No tracked-source filenames contain `archwindows`/`Archwindows`/`ArchWindows`/`ARCHWINDOWS`. EE's git-mv sweep is complete on filesystem names.

---

## Cross-agent consistency check

**Critical path: `/etc/<name>/expected-pcr-11` file** (written by installer, read by kernel module at init).

| Producer/Consumer | File | Path used |
|---|---|---|
| Kernel consumer (CC) | `trust/kernel/trust_attest.c:55` | `/etc/archimation/expected-pcr-11` |
| Kernel consumer (CC) | `trust/kernel/trust_attest.h:9` | `/etc/archimation/expected-pcr-11` |
| Installer producer (EE) | `profile/airootfs/usr/bin/ai-install-bootc:658,661,665` | `/etc/archimation/expected-pcr-11` |
| **bootc producer (unswept)** | `bootc/systemd-measure.conf:70` | `/etc/archwindows/expected-pcr-11` |

CC ↔ EE agree on `/etc/archimation/` — the bootc OCI build-time producer is out of sync. If a user builds via the bootc path and the kernel is new enough to include CC's rename, the PCR 11 file will be placed where the kernel doesn't look — silent attestation degradation to SOFTWARE mode with a `pr_warn`. **Not a correctness break** (falls back safely), but a rename-sweep gap.

---

## Build results

### pe-loader (`make clean && make`)

```
cc -Wall -Wextra -Werror ... (all .o + all .so + loader/peloader ELF)
```

- **Result: CLEAN.** `loader/peloader` = ELF 64-bit LSB pie executable, BuildID `58616963d487960ccc9e5e662cdb388f95a83079`
- **42 DLL .so files in dlls/.**
- Zero errors, zero warnings with `-Werror`.

### services (`make clean && make`)

```
gcc ... -o anticheat/libpe_anticheat.so
gcc -o pe-objectd ...
```

- **Result: CLEAN.** All anticheat shims, objectd broker, and SCM linked successfully.
- Pre-existing non-rename-related `-Wstringop-truncation` warnings in `battleye_shim.c:528` and `blackshield_shim.c:493` (not `-Werror` for services/; identical to pre-rename state).

---

## Catalysis gate + producer-consumer lint

```
$ python3 scripts/catalysis_analysis.py --ci --baseline scripts/catalysis_baseline.json
catalysis-gate: PASS  K_avg=0.093 (baseline 0.093, ceiling 0.140)
EXIT=0
```

```
$ python3 scripts/lint_producer_consumer.py --ci --baseline scripts/producer_consumer_baseline.json
producer-consumer lint: PASS (known=45, current_nonok=44)
EXIT=0
```

Both gates green. Renames did not disturb handler call-graph topology (expected — handlers are keyed by registry names which CC preserved).

---

## Pytest delta vs BB baseline

BB baseline (session-74 agent-BB rebuild): **280 pass / 24 fail / 83 skip / 1 xfail**.

GG this run: **280 pass / 24 fail / 83 skip / 1 xfail** — in 695.91s.

**Zero delta.** The 24 failures are the same pre-existing ones (mostly daemon-port / contusion AI endpoint / roa_conformance / test_bootc_lifecycle::rollback_harness — all pre-rename). Renames caused zero pytest regression.

---

## Shell + YAML parse

```
$ for f in scripts/*.sh profile/*.sh profile/airootfs/root/*.sh; do bash -n "$f" || echo "FAIL: $f"; done
SHELLPARSE_DONE    (no FAIL lines)

$ python3 -c "import yaml, glob; [yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')]"
YAML_OK
```

All shell scripts and GitHub Actions workflows parse successfully.

---

## Manifest guard integrity

`scripts/build-packages.sh`:

- `verify_trust_dkms_manifest()` function present at **line 99-155**.
- Invoked at **line 355**: `if ! verify_trust_dkms_manifest "$pkg_tarball"; then`
- S74 kernel sources present on disk: `trust/kernel/trust_morphogen.c`, `trust_quorum.c`, `trust_algedonic.c` — confirmed via `ls`.
- Guard reads `Kbuild` dynamically and cross-checks staged package, so new .c sources are picked up automatically. No hard-coded file list was mangled.

**Result: CLEAN.**

---

## PKGBUILD pkgname preservation

```
packages/ai-control-daemon/PKGBUILD:4:pkgname=ai-control-daemon
packages/ai-desktop-config/PKGBUILD:4:pkgname=ai-desktop-config
packages/ai-firewall/PKGBUILD:4:pkgname=ai-firewall
packages/ai-first-boot-wizard/PKGBUILD:4:pkgname=ai-first-boot-wizard
packages/pe-compat-dkms/PKGBUILD:4:pkgname=pe-compat-dkms
packages/pe-loader/PKGBUILD:4:pkgname=pe-loader
packages/trust-dkms/PKGBUILD:4:pkgname=trust-dkms
packages/trust-system/PKGBUILD:4:pkgname=trust-system
packages/windows-services/PKGBUILD:4:pkgname=windows-services
packages/wine-shim/PKGBUILD:10:pkgname=libtrust-wine-shim
```

All 10 pkgnames intact. `windows-services` correctly preserved — this is the ARCHWINDOWS-project package name (not a Microsoft reference). `pe-compat-dkms` and `ai-firewall` are present (originally listed scope expected 8 pkgnames; 10 confirmed, all preserved).

**Result: CLEAN.**

---

## ISO filename generator (no rebuild)

`profile/profiledef.sh`:
```
4:iso_name="archimation"
5:iso_label="ARCHIM_$(date +%Y%m)"
```

A rebuild would produce `archimation-YYYY.MM.DD-x86_64.iso` with volume label `ARCHIM_YYYYMM`. EE landed the generator correctly.

**Pre-rename ISO files still on disk under `output/` are preserved** (constraint: no rebuild).

---

## Known-remaining references (should be intentional)

**Only `docs/architecture-name-decision.md` (5 refs) is intentional** per DD. All other residual refs — the entire `bootc/` tree (47 refs in 6 files) + `tests/integration/test_bootc_lifecycle.py` (4 refs) + `profile/airootfs/etc/ssh/sshd_config.d/10-archimation-banner.conf` (1 ref) — are **unintended rename-sweep gaps**.

---

## Red flags

### Red flag 1: `bootc/` directory was out of scope for all four rename agents
CC covered source code, DD covered docs, EE covered profile/packages/scripts/.github — nobody had `bootc/` assigned. 47 refs across `Containerfile`, `build-bootc.sh`, `build-trust-module.sh`, `systemd-measure.conf`, `README.md`, `trust-keys/README.md` remain. This is not a correctness bug — the bootc image-mode path is aspirational (per S72 memory) and not exercised in pkg-23 or current ISO builds — but it's a coherence break. If/when someone actually runs `bash bootc/build-bootc.sh`, the produced image is tagged `archwindows-bootc:dev`, labeled `ARCHWINDOWS Project`, and writes PCR-11 at `/etc/archwindows/` which the renamed trust.ko won't read.

### Red flag 2: cross-agent path divergence on `/etc/<name>/expected-pcr-11`
`bootc/systemd-measure.conf:70` says `/etc/archwindows/expected-pcr-11`, but CC's `trust_attest.c:55` and EE's `ai-install-bootc` both say `/etc/archimation/`. Silent failure mode: kernel falls back to SOFTWARE attestation mode with a `pr_warn` banner. Not exploitable, but architecturally incoherent.

### Red flag 3: `profile/airootfs/etc/ssh/sshd_config.d/10-archimation-banner.conf` header comment
EE renamed the file correctly but didn't update the line-1 comment that still reads `# ArchWindows pre-auth banner shown on every SSH login attempt.` Cosmetic only, not functional.

### Red flag 4: `tests/integration/test_bootc_lifecycle.py`
`IMAGE_TAG = "localhost/archwindows-bootc:test"` plus 3 docstring mentions. Paired with `bootc/build-bootc.sh`'s `archwindows-bootc:dev` tag — actually consistent with the unswept bootc/ itself, so the test would still work against an unrenamed bootc image. But if S75 renames bootc/, this test needs the same sweep.

### No red flags on correctness
- No build regression.
- No pytest regression (exact baseline match).
- No lint regression.
- Manifest guard intact.
- PKGBUILD pkgnames intact.
- ISO filename generator correct.
- Cross-agent `/etc/archimation/` path consistent between CC (kernel) and EE (installer) — the only disagreement is with the unswept `bootc/systemd-measure.conf` which is aspirational surface.

---

## Final verdict

**MINOR-ISSUES** — sweep is **functionally complete for shipped code paths** but has a localized gap in the aspirational `bootc/` tree (47 refs across 6 files) plus 5 stragglers (1 banner comment, 4 test docstrings). Shipped paths (trust.ko, pe-loader, services, ai-control daemon, profile airootfs, PKGBUILDs, scripts, CI, ISO filename) are all Archimation. The `bootc/` gap only bites if someone tries to produce an OCI image, and even then falls back safely to SOFTWARE attestation.

**Recommended S75 follow-up** (~1 agent-hour):
1. `sed -i 's/archwindows/archimation/gI' bootc/*.sh bootc/*.conf bootc/README.md bootc/Containerfile bootc/trust-keys/README.md tests/integration/test_bootc_lifecycle.py` then manual review.
2. Fix `/etc/archwindows/` → `/etc/archimation/` in `bootc/systemd-measure.conf:70,77`.
3. Fix banner comment in `profile/airootfs/etc/ssh/sshd_config.d/10-archimation-banner.conf:1`.
4. Optional: delete pre-rename `output/archwindows-*.iso*` artifacts or leave as historical record.

Sweep is **safe to ship**. No rebuild required for pkg-23/current ISO.
