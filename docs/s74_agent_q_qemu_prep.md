# S74 Agent Q — QEMU Environment Readiness Audit

**Date:** 2026-04-20
**Agent:** Q (QEMU prep audit)
**Git HEAD at audit:** `d043482` (Agent L — paper-vs-impl docs)
**Scope:** Pure read-only audit of WSL Arch environment for a follow-up QEMU verify agent. **No installs. No builds. No boots.**

---

## Verdict

**READY** — green-light the follow-up QEMU verify agent.

All blocking prerequisites for the standard `test-qemu.sh` + `qemu_pe_corpus.sh` + `set_smoke_run.sh` smoke path are present. A single non-blocking `swtpm` gap applies only to the S72 bootc attestation scripts, which are out-of-scope for the standard smoke verify.

---

## One-line summary

`mkarchiso` ok, `qemu-system-x86_64` ok (10.2.0), `edk2-ovmf 202508-1` installed at new path, `/` has 918 GB free, 14.6 GiB free RAM, all 4 target scripts exist and are bash-n clean, 9 pre-K packages baked, 3 ISOs already in `output/` (one from today 13:03).

---

## Per-check results

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | `which mkarchiso` | **PASS** | `/usr/sbin/mkarchiso` (archiso 87-1) |
| 2 | `which qemu-system-x86_64` | **PASS** | `/usr/sbin/qemu-system-x86_64` (QEMU 10.2.0) |
| 3 | `pacman -Q edk2-ovmf` | **PASS** | `edk2-ovmf 202508-1` installed |
| 4 | `pacman -Q swtpm` | **WARN (non-blocking)** | Not installed. Available in `extra` repo as `swtpm 0.10.1-2`. Only needed for `test-bootc-attestation.sh` / `test-bootc-rollback.sh` (S72 aspirational). |
| 5 | OVMF firmware path discovery | **PASS (path moved)** | `/usr/share/OVMF/OVMF_CODE.fd` MISSING. `/usr/share/edk2-ovmf/x64/OVMF_CODE.fd` MISSING. Actual path: `/usr/share/edk2/x64/OVMF_CODE.4m.fd` and `/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd` (Arch `edk2-ovmf` now ships 4m variants under `edk2/x64/`). Does **not** affect `test-qemu.sh` or `qemu_pe_corpus.sh` — both use BIOS CD-ROM boot. |
| 6 | `/tmp` / root disk space | **PASS** | `/dev/sdd` 1007 GB total, 39 GB used, **918 GB available**. Far exceeds 5 GB ISO-build ask. |
| 7 | `scripts/build-iso.sh` exists & bash -n | **PASS** | 9740 bytes, executable, syntax clean |
| 8 | `scripts/test-qemu.sh` exists & bash -n | **PASS** | 39762 bytes, executable, syntax clean. Uses `-m 4096` (4 GiB guest), BIOS boot, SSH fwd :2222. |
| 9 | `scripts/set_smoke_run.sh` exists & bash -n | **PASS** | 6153 bytes, executable, syntax clean |
| 10 | `scripts/qemu_pe_corpus.sh` exists & bash -n | **PASS** | 3965 bytes, executable, syntax clean. Uses `-m 4096`, BIOS boot. |
| 11 | `free -m` memory headroom | **PASS** | Total 15,570 MiB, used 620 MiB, **free 14,633 MiB**, available 14,949 MiB. Swap 4096 MiB idle. Comfortably fits 4 GiB guest + ISO build concurrency. |
| 12 | Pre-K package count (`repo/x86_64/*.pkg.tar.zst`) | **PASS (baseline)** | **9 packages** baked. See list below. |
| 13 | Existing `output/*.iso` | **PASS** | 3 ISOs present; most recent is today 2026-04-20 13:03. See list below. |

---

## Pre-K package baseline (9 in `repo/x86_64/`)

```
ai-control-daemon-0.1.0-24-any.pkg.tar.zst
ai-desktop-config-0.2.0-31-any.pkg.tar.zst
ai-firewall-0.1.0-1-any.pkg.tar.zst
ai-first-boot-wizard-0.1.0-2-any.pkg.tar.zst
pe-compat-dkms-0.1.0-1-x86_64.pkg.tar.zst
pe-loader-0.1.0-9-x86_64.pkg.tar.zst
trust-dkms-0.1.0-8-x86_64.pkg.tar.zst
trust-system-0.1.0-2-x86_64.pkg.tar.zst
windows-services-0.1.0-6-x86_64.pkg.tar.zst
```

Future Agent K ISO-rebake should add any new Agent-K-produced pkgs on top. If count stays at 9, K shipped nothing new at the package boundary.

---

## Existing ISOs in `output/`

```
2.2G  2026-04-19 22:38  archimation-2026.04.19-x86_64.iso
2.2G  2026-04-20 08:18  archimation-2026.04.20-x86_64.iso
2.2G  2026-04-20 13:03  archimation-2026.04.20-x86_64.iso   <-- most recent
```

The 13:03 ISO is after the git HEAD cutover and may already reflect some Agent-K+L work. Future QEMU verify agent should decide whether to re-bake or test the existing 13:03 ISO first for a quick signal.

---

## Firmware-path findings

Arch Linux `edk2-ovmf 202508-1` ships firmware at the new unified path:

| Old path (hardcoded in bootc scripts) | New actual path |
|---|---|
| `/usr/share/OVMF/OVMF_CODE.fd` | missing |
| `/usr/share/edk2-ovmf/x64/OVMF_CODE.fd` | missing |
| — | **`/usr/share/edk2/x64/OVMF_CODE.4m.fd`** (use this) |
| — | **`/usr/share/edk2/x64/OVMF_VARS.4m.fd`** (vars template) |
| — | `/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd` (SecureBoot) |
| — | `/usr/share/edk2/ia32/` (32-bit equivalents) |

**Impact on standard smoke path:** None. Both `test-qemu.sh` and `qemu_pe_corpus.sh` use BIOS (SeaBIOS) CD-ROM boot and never reference OVMF.

**Impact on bootc attestation path (S72):** `scripts/test-bootc-attestation.sh:47-48` and `scripts/test-bootc-rollback.sh:52-53` hardcode the old `/usr/share/edk2-ovmf/x64/OVMF_CODE.fd` path. Both scripts accept an `OVMF_CODE=` env override and default to `ALLOW_STUB_OVMF=1` so they gracefully stub-exit. A future hardening pass should update both defaults to `/usr/share/edk2/x64/OVMF_CODE.4m.fd`. Filed as S75 handoff, **not a blocker for S74 QEMU verify.**

---

## Build-script sanity

All 4 target scripts pass `bash -n`:

- `scripts/build-iso.sh` — orchestrates mkarchiso invocation against `profile/`
- `scripts/test-qemu.sh` — the 7-point/26-probe smoke runner (writes `test-qemu-run.log`)
- `scripts/set_smoke_run.sh` — the 13-set capability gate (GREEN/YELLOW/RED classification)
- `scripts/qemu_pe_corpus.sh` — the PE-corpus harness (15+ MinGW binaries)

No syntax errors. Executable bits intact. Timestamps current (most recent is `set_smoke_run.sh` at 12:56 today — active dev).

---

## swtpm gap analysis (non-blocking)

| Script | Needs swtpm? | Action if missing |
|---|---|---|
| `test-qemu.sh` | **NO** | runs without TPM |
| `qemu_pe_corpus.sh` | **NO** | runs without TPM |
| `set_smoke_run.sh` | **NO** | runs over SSH against already-booted VM |
| `test-bootc-attestation.sh` | **YES** | currently returns exit-3 (prereq missing) — already handled as stub-graceful |
| `test-bootc-rollback.sh` | **YES** | `ALLOW_STUB_SWTPM=1` default — stubs gracefully |

**If the future agent wants to exercise bootc attestation tests too:**
```bash
wsl.exe -d Arch -- sudo pacman -S --noconfirm swtpm
```
This also requires setting `OVMF_CODE=/usr/share/edk2/x64/OVMF_CODE.4m.fd OVMF_VARS_TEMPLATE=/usr/share/edk2/x64/OVMF_VARS.4m.fd` in the environment to work around the hardcoded old-path defaults.

---

## Environment summary

| Metric | Value | Ask | Margin |
|---|---|---|---|
| Free memory | 14,949 MiB | 4096 MiB (QEMU guest) | **3.6x headroom** |
| Free disk (/ == /tmp) | 918 GiB | ~5 GiB (ISO build work dirs) | **183x headroom** |
| QEMU version | 10.2.0 | any recent | current |
| archiso version | 87-1 | any recent | current |
| edk2-ovmf | 202508-1 | any, only for UEFI path | current |

Note: WSL2 has no KVM, so QEMU runs under TCG. Expect ~82 s boot per `CLAUDE.md` testing section; BOOT_TIMEOUT=300 s is documented sufficient.

---

## Evidence: script invocations used

```
wsl.exe -d Arch -- which mkarchiso
  → /usr/sbin/mkarchiso

wsl.exe -d Arch -- which qemu-system-x86_64
  → /usr/sbin/qemu-system-x86_64

wsl.exe -d Arch -- pacman -Q edk2-ovmf
  → edk2-ovmf 202508-1

wsl.exe -d Arch -- pacman -Q swtpm
  → error: package 'swtpm' was not found   (but available via pacman -Si)

wsl.exe -d Arch -- bash -c 'find /usr/share -name "OVMF_CODE*"'
  → /usr/share/edk2/{ia32,x64}/OVMF_CODE.{4m,secboot.4m}.fd

wsl.exe -d Arch -- bash -c 'df -h /tmp'
  → /dev/sdd 1007G 39G 918G 5%

wsl.exe -d Arch -- bash -c 'free -m'
  → total 15570, used 620, free 14633, available 14949

bash -n for 4 scripts → all clean
```

---

## Blockers

**None.**

## Non-blocking follow-ups (S75 candidates)

1. `scripts/test-bootc-attestation.sh:47-48` — update OVMF default path to `/usr/share/edk2/x64/OVMF_CODE.4m.fd`
2. `scripts/test-bootc-rollback.sh:52-53` — same
3. If S74 Agent-R will run bootc attestation: `sudo pacman -S swtpm` on the WSL Arch host first
4. Consider adding a pre-flight env-probe to `scripts/build-iso.sh` that validates these paths so drift surfaces at build time, not test time

---

## Final verdict

**GREEN-LIGHT** the QEMU verify agent. Standard smoke (`test-qemu.sh`), PE corpus (`qemu_pe_corpus.sh`), and set-smoke (`set_smoke_run.sh`) all have every prerequisite satisfied with generous headroom. The environment is ready; future agent can dispatch safely.
