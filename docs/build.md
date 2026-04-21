# Build Guide

End-user build & test guide for the AI Arch Linux distribution. This
supplements the higher-level `CLAUDE.md` — use this document when you just
want working binaries / an ISO, not the design rationale.

---

## 1. Requirements

| Item | Minimum | Recommended |
|---|---|---|
| Host OS | WSL2 Arch Linux OR native Arch Linux | Native Arch (for ISO) |
| RAM | 8 GB | 16 GB |
| Free disk | 25 GB | 40 GB |
| Tools | `base-devel`, `git`, `python`, `make`, `gcc` | add `mkarchiso`, `qemu-system-x86_64`, `ccache` |

On WSL2:

```bash
# Install Arch WSL, then inside it:
sudo pacman -Syu --needed base-devel git python make gcc \
                         mkarchiso qemu archiso ccache
```

The build scripts detect an NTFS checkout (`/mnt/c/...`) and automatically
use `/tmp/ai-arch-build/` for anything that requires Unix permissions
(symlinks, device nodes, suid bits). You do **not** need to move the
checkout off NTFS.

---

## 2. Quick Start

From the repository root, inside a WSL Arch or native Arch shell:

```bash
# 1. Build the C components (PE loader, services, trust lib, coherence daemon).
make

# 2. Build the Arch packages into repo/x86_64/*.pkg.tar.zst.
bash scripts/build-packages.sh

# 3. Build the bootable ISO into output/.
bash scripts/build-iso.sh

# …or run the whole pipeline (packages + ISO):
bash scripts/run-full-build.sh
```

### Common build targets

The top-level `build.sh` orchestrator accepts targets:

```bash
bash build.sh all         # everything
bash build.sh pe-loader   # just the Windows-PE loader + DLLs
bash build.sh services    # scm, objectd, anticheat
bash build.sh packages    # Arch packages only
bash build.sh iso         # mkarchiso only (requires packages first)
bash build.sh clean       # wipe build artifacts
bash build.sh test        # PE loader test suite
```

---

## 3. Testing

### Quick syntax & unit checks (no VM needed)

```bash
bash scripts/ci.sh                   # full pipeline
CI_QUICK=1 bash scripts/ci.sh        # skip ISO + QEMU (fast)
CI_SKIP_QEMU=1 bash scripts/ci.sh    # build ISO but don't boot it
```

`scripts/ci.sh` runs six stages: Python syntax, shell syntax, C build,
package build, ISO build, QEMU smoke test. Each stage emits `PASS`,
`FAIL`, or `SKIP` and writes a full log to `logs/ci-<stage>-<ts>.log`.
Exit code is `0` on full pass, `1` on any failure, `77` if every stage
was skipped (e.g. no Arch toolchain present).

### QEMU smoke test

```bash
bash scripts/test-qemu.sh
```

Boots the latest ISO from `output/` in QEMU (TCG — no KVM in WSL2),
waits ~82 s for boot, then runs a 7-point smoke test over SSH
(port 2222):

1. SSH reachable
2. `ai-control.service` running
3. `/health` endpoint responds
4. `/system/info` endpoint responds
5. Boot-critical systemd units are active
6. NetworkManager + SSH healthy
7. Custom services (coherence, scm, objectd) are up

SSH into the running VM:

```bash
ssh -p 2222 arch@localhost     # unprivileged
ssh -p 2222 root@localhost     # root
```

The AI daemon is reachable at `http://localhost:8421/` (port 8420 inside
the VM is forwarded to 8421 on the host; QEMU port forwarding is flaky
on port 8420 directly).

### PE loader test suite

```bash
make test
# or, equivalently:
bash scripts/run-pe-tests.sh
```

---

## 4. Reproducible Builds

```bash
bash scripts/reproducible-build.sh
```

This wrapper sets the canonical reproducible-builds.org environment
(`SOURCE_DATE_EPOCH`, `KBUILD_BUILD_TIMESTAMP`, `TZ=UTC`, `LC_ALL=C`,
`PYTHONHASHSEED=0`) and then runs `scripts/build-packages.sh`. Extra
arguments are forwarded (`--force`, `--dry-run`).

### What it guarantees

- File mtimes in produced packages match the latest commit time.
- Kernel-module `__DATE__` / `__TIME__` macros are stable.
- Locale- and timezone-dependent output (tar headers, logs) is
  deterministic.

### What it does NOT guarantee

Byte-identical ISO output across two builds additionally requires:

- Identical `mkarchiso` version
- Identical pacman mirror snapshot (use
  <https://archive.archlinux.org/repos/YYYY/MM/DD/>)
- Identical `linux` + `linux-headers` versions
- Identical `gcc` / `glibc` / `squashfs-tools` / `grub` versions

If any of those drift, the hash will differ even though all sources are
reproducibly timestamped. For hash-stable ISO output, pin an Arch
archive snapshot in a container and build inside it.

---

## 5. CI

GitHub Actions runs `scripts/ci.sh` inside an `archlinux:latest`
container on every push and pull request. The workflow lives at
`.github/workflows/ci.yml`.

- Caches `/var/cache/pacman/pkg` keyed on `packages/**/PKGBUILD` hashes.
- Uses `CI_QUICK=1` — skips ISO build and QEMU (no nested-VM support on
  free-tier runners; mkarchiso needs privileged loop-device access).
- Uploads `logs/` as an artifact on failure (14-day retention).
- Timeout: 55 minutes.

To run the full ISO + QEMU stages in CI, you need a self-hosted runner
with `--privileged` container support and either KVM or a generous time
budget for TCG emulation.

---

## 6. Troubleshooting

### `makepkg` fails with odd syntax errors

Cause: CRLF line endings. Windows git with `core.autocrlf=true` injects
`\r` into PKGBUILDs. Fix:

```bash
bash scripts/build-packages.sh      # auto-strips CRLF since Session 21
# or manually:
sed -i 's/\r$//' packages/*/PKGBUILD
```

### `pacstrap: target not found: <package>`

Cause: an AUR-only package ended up in a `depends=` or
`profile/packages.x86_64`. AUR packages can't be `pacstrap`'d — they
must be built first and placed in the local repo (`repo/x86_64/`).

Fix: move the package name to `optdepends=` if it's not strictly
required, or add a PKGBUILD under `packages/` and let
`scripts/build-packages.sh` build it locally.

### `mkarchiso: command not found`

```bash
sudo pacman -S archiso
```

Note: `mkarchiso` itself needs root for pacstrap and loop-mount; run
`build-iso.sh` under `sudo` if you aren't already root.

### Trust DKMS "build failed" during pacstrap

Expected inside WSL2 — no kernel headers for the live kernel. The `.ko`
is built on first boot of the real target hardware.

### QEMU port 8420 forwarding doesn't work

WSL2 binds port 8420 inconsistently. The tests use `8421 -> 8420` port
remapping. If you need raw 8420 access from the host, SSH-tunnel instead:

```bash
ssh -p 2222 -L 8420:localhost:8420 arch@localhost
```

### `wchar_t` mismatches in PE loader DLLs

Linux `wchar_t` is 4 bytes, Windows is 2. Always use `uint16_t` for
Windows wide strings inside the PE compatibility layer. See
`pe-loader/include/` for the canonical typedefs.

### `/tmp` runs out of space during ISO build

ISO build requires ~8-12 GB free in `/tmp`. If `df -m /tmp` reports less
than 4 GB free, `build-packages.sh` will warn. Options:

```bash
# Use a different workdir (needs native Linux FS, not NTFS):
WORK_DIR=/var/tmp/ai-arch-build bash scripts/build-iso.sh
# Or clean the build cache:
rm -rf /tmp/ai-arch-build
```

### `wsl -d Arch -- bash -c '...'` garbles multi-line commands

Git Bash on Windows mangles newlines when forwarding to WSL. Write a
script file and invoke that instead:

```bash
wsl.exe -d Arch -- bash /mnt/c/path/to/script.sh
```
