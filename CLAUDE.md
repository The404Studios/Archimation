# AI Arch Linux with Full AI Control

Custom Arch Linux distribution with native Windows PE execution, a biologically-inspired trust kernel module, and an autonomous AI control daemon.

## Build Instructions

All builds run inside WSL2 Arch. The project lives on NTFS (`/mnt/c/...`); build scripts automatically use `/tmp` for work directories where Unix permissions are required.

```bash
# Build PE loader + services (C compilation)
wsl -d Arch -- bash -c 'cd /mnt/c/.../arch-linux-with-full-ai-control && make'

# Build Arch packages (creates .pkg.tar.zst in repo/x86_64/)
wsl -d Arch -- bash -c 'cd /mnt/c/.../arch-linux-with-full-ai-control && bash scripts/build-packages.sh'

# Build bootable ISO (requires mkarchiso, outputs to output/)
wsl -d Arch -- bash -c 'cd /mnt/c/.../arch-linux-with-full-ai-control && bash scripts/build-iso.sh'

# Full pipeline: packages + ISO
wsl -d Arch -- bash -c 'cd /mnt/c/.../arch-linux-with-full-ai-control && bash scripts/run-full-build.sh'

# Clean all artifacts
make clean
```

The `build.sh` orchestrator accepts targets: `all`, `pe-loader`, `services`, `packages`, `iso`, `clean`, `test`.

## Key Directories

| Directory | Contents |
|---|---|
| `trust/kernel/` | Trust kernel module (`trust.ko`) -- 9 source files, DKMS packaged |
| `trust/lib/` | Userspace trust library (`libtrust`) |
| `pe-loader/` | Windows PE binary loader (C). Loads and runs .exe on Linux |
| `pe-loader/loader/` | Core loader: parser, mapper, relocator, import resolver, TLS, ABI thunks |
| `pe-loader/dlls/` | 37+ .so DLL stubs (kernel32, ntdll, user32, gdi32, d3d, etc.) |
| `pe-loader/include/` | PE headers, Win32 types, compatibility layer headers |
| `ai-control/daemon/` | Python/FastAPI AI control daemon (port 8420) |
| `ai-control/cortex/` | AI cortex decision engine |
| `services/scm/` | Windows Service Control Manager (C daemon) |
| `services/anticheat/` | Anti-cheat shims (Blackshield, Vanguard) |
| `services/objectd/` | Named object broker (cross-process Win32 objects) |
| `packages/` | Arch Linux PKGBUILDs (ai-desktop-config, trust-dkms, etc.) |
| `profile/` | Archiso profile (pacman.conf, packages.x86_64, airootfs, GRUB theme) |
| `scripts/` | Build, deploy, and test scripts |
| `firewall/` | Python firewall module |
| `tests/` | Test suites |
| `PLAN/` | Original design notes and vision documents |
| `docs/` | Architecture specs and documentation |

## Architecture (5 Layers)

```
Layer 0 -- KERNEL
  trust.ko (authority root) + binfmt_pe (MZ detection) + Linux kernel

Layer 1 -- OBJECT BROKER (pe-objectd)
  Named objects, registry hive, device namespace, session manager

Layer 2 -- PE RUNTIME (per-process)
  PE loader + 37+ DLL stubs + SEH + trust gate + WDM host

Layer 3 -- SERVICE FABRIC (scm-daemon)
  Windows + Linux service lifecycle, driver hosting, dependency graph

Layer 4 -- AI CORTEX
  Event bus + decision engine + orchestrator + autonomy controller
```

Commands flow down, events flow up. No layer calls upward.

## Testing

### QEMU smoke tests
```bash
# Boot ISO in QEMU and run 7-point smoke test
wsl -d Arch -- bash -c 'cd /mnt/c/.../arch-linux-with-full-ai-control && bash scripts/test-qemu.sh'
```

QEMU uses TCG (no KVM in WSL2). Boot takes ~82s. BOOT_TIMEOUT=300s. SSH on port 2222.

The smoke test checks: SSH connectivity, AI daemon status, /health endpoint, /system/info, boot services, NetworkManager+SSH, and custom services.

### SSH into VM
```bash
ssh -p 2222 arch@localhost     # user
ssh -p 2222 root@localhost     # root
```

### PE loader tests
```bash
make test                      # runs pe-loader test suite
```

## Known Pitfalls

### PE Loader ABI
- **wchar_t size mismatch**: Linux wchar_t = 4 bytes, Windows = 2 bytes. Always use `uint16_t` for Windows wide chars.
- **PLT interposition**: Loader binary exports symbols via `-rdynamic` that shadow DLL stubs. Fix: use static internal calls.
- **ms_abi va_list**: Must use `__builtin_ms_va_list` explicitly, not standard va_list.
- **CRT ABI mismatch**: PE imports resolve to libc's sysv_abi functions. Fix: ms_abi wrapper table (~120 wrappers in `pe_find_crt_wrapper()`).
- **COM vtables**: ALL function pointers and implementations must be `__attribute__((ms_abi))`.
- **Cross-file extern calls**: Must include `__attribute__((ms_abi))` on extern declarations.
- **MAKEINTRESOURCE**: Win32 class names/resource IDs can be small integers (<0x10000) cast to LPCSTR.

### Build / WSL2
- `wsl -d Arch --` via Git Bash converts `/mnt/c/` paths. Use `wsl.exe` instead.
- Multi-line `bash -c '...'` via Git Bash garbles newlines. Write scripts to `/mnt/c/` and invoke them.
- PKGBUILD `package()` must use `"$pkgdir/..."` (double-quoted) for ALL install destinations. Single-quoted `'$pkgdir'` won't expand.
- QEMU port forwarding on WSL2 is unreliable for port 8420. Use SSH tunnel instead.
- Trust DKMS shows "build failed" during pacstrap in WSL (no kernel headers). Expected; builds on real hardware.

### Trust System
- `trust_types.h` uses `uint32_t` (userspace), `trust_internal.h` uses `u32` (kernel). Never mix.
- `trust_uapi.h` and `trust_internal.h` both define `trust_default_caps()`. Never include both.
- `_emit_event()` in `trust_observer.py` takes a single dict with a `"type"` key, NOT `(string, dict)`.
- SCM `service_entry_t` uses `memset(0)`. New fields must have sane zero defaults.

## Key Design Decisions

### Trust System
- Token state is EMBEDDED in `trust_subject_t` (496 bytes), not a separate pool.
- APE (Authority Proof Engine) uses separate pool in `g_trust_ape`. Proofs are self-consuming (destroyed on read).
- TRC (Trust Regulation Core) uses fixed-point 8.8 cost_multiplier (256 = 1.0x).
- ISA: 6 families (AUTH, TRUST, GATE, RES, LIFE, META), 32-bit instruction word, GPU command buffer model.
- Chromosomal model: 23 segment pairs per subject (runtime A-segments + static B-segments).

### PE Loader
- DLL search order: app-dir PE DLL -> .so stubs -> search-path PE DLL.
- 5-path resolution: loader dir/dlls, exe dir, /usr/lib/pe-compat, LD_LIBRARY_PATH, ./dlls.
- binfmt_misc flags: `OCF` (open-binary, credentials, fix-binary).
- DXVK/VKD3D-Proton handle D3D9/10/11/12 translation to Vulkan.
- Anti-cheat shims return convincing Windows 10 environment data (34 fake processes, 22 kernel modules, SMBIOS data).

### AI Daemon
- Python/FastAPI on port 8420, systemd service (`ai-control.service`).
- 30+ desktop automation endpoints (window management, game launching, shortcuts).
- LLM integration via llama-cpp-python with graceful degradation.
- Compositor control: Hyprland IPC with X11 fallback (wmctrl/xdotool).

### Desktop
- XFCE with Windows 11-like appearance (Whisker menu, Adwaita-dark, Papirus-Dark icons).
- Native .exe execution via binfmt_misc + MIME type registration.
- Plymouth boot splash, GRUB theme, 3s boot timeout.
- NVIDIA support: nvidia-open-dkms with early KMS, nvidia_drm.modeset=1.
