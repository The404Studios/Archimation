# Quickstart

An end-to-end walkthrough for the first time you build, boot, and poke at this system. Read [`../README.md`](../README.md) first if you haven't.

## 1. Prerequisites

**Host options:**

- **WSL2 with Arch installed** (recommended on Windows). The repo lives on NTFS at `/mnt/c/...`; build scripts already handle the `/tmp` copy for Unix-permissions-required steps.
- **Native Arch Linux.** Easier path; `sudo` and normal FS semantics just work.

**Required tools (on the build host):**

- `base-devel`, `git`, `make`, `gcc`
- `mkarchiso` (for ISO build) — `pacman -S archiso`
- `qemu-system-x86_64` (for QEMU testing) — `pacman -S qemu-full` or `qemu-base`
- `ssh`, `curl`, `jq` for poking at the running VM

**Resources:**

- \~8 GB RAM free (QEMU allocates 4 GB to the guest by default; host needs headroom).
- \~10 GB free disk for packages, ISO, and QEMU state.
- A CPU with AES-NI helps the ISO compress/decompress faster but is not required.

**Git note for Windows users.** `core.autocrlf=true` breaks `makepkg` by injecting CRLF into PKGBUILDs. The build pipeline strips CRLF automatically, but if you hand-edit a PKGBUILD, save it with LF endings.

## 2. Clone and build

```bash
git clone <this-repo> arch-linux-with-full-ai-control
cd arch-linux-with-full-ai-control

# Build Arch packages: outputs to repo/x86_64/
# Expected: ~30 seconds on a modern laptop.
bash scripts/build-packages.sh

# Build the bootable ISO: outputs to output/<name>.iso
# Expected: ~5 minutes on a modern laptop with cold caches.
bash scripts/build-iso.sh
```

If you are on WSL2, run these through `wsl.exe` rather than chaining `wsl -d Arch -- bash -c '...'` from Git Bash — multi-line bash-through-Git-Bash garbles newlines. Write a throwaway script to `/mnt/c/...` and invoke it.

**Full pipeline (packages + ISO in one step):**

```bash
bash scripts/run-full-build.sh
```

**Clean everything:**

```bash
make clean
```

## 3. Boot in QEMU

The canonical smoke test boots the ISO under QEMU TCG (no KVM — WSL2 does not expose it), waits for SSH on port 2222, and runs the 30-test smoke suite against the AI daemon.

```bash
bash scripts/test-qemu.sh
```

Expected timings:

- Boot to login prompt: **\~90 s** under TCG. Feels slow; it is slow because TCG emulates every instruction.
- Smoke suite completion: another 30-60 s after SSH comes up.
- Total: **\~2 to 3 minutes** from script start.

The script prints progress, then a final `OVERALL: PASS` / `FAIL` summary with per-check results. Serial console output is logged to `/tmp/qemu-serial.log` — useful when boot fails and you need to see what the kernel printed.

## 4. SSH in and try Contusion

With the VM still running from `test-qemu.sh` (or launched by `scripts/boot-qemu.sh`):

```bash
# As the arch user (password: arch)
ssh -p 2222 arch@localhost

# As root (password: root)
ssh -p 2222 root@localhost
```

The AI daemon listens on the guest's port 8420, forwarded to the host's port **8421** (not 8420 — port forwarding conflicts are annoying):

```bash
# On the host:
curl -s http://localhost:8421/system/summary | jq .
```

**Try a Contusion natural-language command:**

```bash
# From inside the VM:
contusion "turn up the volume"
```

**Expected result in headless QEMU: this will fail.** Contusion dispatches to PulseAudio/PipeWire controls that need a real sound device and an active session bus; the QEMU guest started by the smoke test has neither. This is the expected behaviour and is documented in `docs/system-summary.md`. The failure should be graceful (non-zero exit, clear message) — a crash is a bug.

## 5. Boot with a display (VNC) and log in

`test-qemu.sh` runs headless. To see the actual XFCE desktop, use the VNC-enabled boot script:

```bash
bash scripts/boot-qemu.sh
```

Then connect a VNC viewer to `localhost:5900`. On the LightDM login screen, log in as:

- Username: `arch`
- Password: `arch`

You should see an XFCE desktop styled to look roughly like Windows 11 (Whisker menu, Adwaita-dark, Papirus-Dark). The AI panel is pinned and the Contusion launcher works if audio is plumbed through (it usually is not under QEMU).

## 6. Run a Windows binary

The PE loader is installed as `/usr/bin/peloader` and registered via `binfmt_misc`, so direct execution of `.exe` files works. A tiny self-contained `hello.exe` ships in the test fixtures:

```bash
# From inside the VM (either via SSH or a VNC terminal):
peloader /usr/share/pe-loader/tests/hello.exe
```

You should see "Hello from Windows!" on stdout. Behind the scenes the loader:

1. Parses MZ + PE headers.
2. Maps sections and applies base relocations.
3. Resolves imports against the DLL stubs in `/usr/lib/pe-compat/`.
4. Sets up an `ms_abi` stack frame and jumps to `AddressOfEntryPoint`.
5. Emits a `load` event on the event bus.

If a binary fails to load, serial/journal log lines from `pe-loader` and the cortex's `load` event reception are the first things to check. The loader logs to stderr; the daemon logs via `journalctl -u ai-control`.

**Direct double-click also works** on the XFCE desktop — `binfmt_misc` + MIME association routes `.exe` clicks through `peloader`.

## 7. Where to go next

- [`architecture.md`](architecture.md) — read this next. It explains *why* the system is shaped the way it is and what its limits are.
- [`pe-compat.md`](pe-compat.md) — what Win32 APIs actually work, which are stubbed, and how the loader is put together.
- [`build.md`](build.md) — full build pipeline, reproducibility notes, and CI.
- [`system-summary.md`](system-summary.md) — the `/system/summary` endpoint reference (useful for writing your own health checks).
- `CLAUDE.md` — not a user doc, but it contains a curated list of Known Pitfalls that will save you hours.
- `memory/MEMORY.md` — running log of what recent audit sessions found and fixed. Read the most recent three entries before opening a PR.

Happy to have you. Feedback and issues welcome; remember this is a research / hobbyist artefact, not a product.
