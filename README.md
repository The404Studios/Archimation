# AI Arch Linux with Full AI Control

Arch Linux distribution with a biologically-inspired kernel trust module, native Windows PE binary execution, and an AI cortex that mediates system actions.

## ⚠ Anti-Cheat Warning

This OS includes anti-cheat compatibility shims for protected multiplayer games (`services/anticheat/`). **Connecting to live multiplayer servers (Valorant, Fortnite, EAC/BattlEye-protected games, etc.) with these shims active MAY PERMANENTLY BAN your account or HWID** — even a single connection attempt can flag the AC vendor's telemetry. The shims pass tier-1 inspection only; they do not and cannot pass live attestation.

The shims are **OFF by default** as of Session 65. To enable per-game (knowing the risk):

```bash
ai game enable-anticheat-shim --i-understand-bans <game-name>
```

Boot-time kernel anti-cheat (Riot Vanguard / `vgk.sys`, miHoYo `mhyprot2`, BattlEye boot-driver mode, Fortnite EAC) is **denylisted** — those games will refuse to launch through the shim. The supported path for tier-2 multiplayer (Apex, CS2, Dota, Fall Guys, etc.) is Steam Proton, which ships vendor-negotiated Linux EAC/BattlEye runtimes that *do* pass attestation.

The Vanguard reference shim has been moved to `services/anticheat/research/` and is no longer built by `make` — it is kept only as IOCTL-surface documentation.

## Status

- **Tests:** QEMU smoke suite, 30/30 passing at HEAD (`scripts/test-qemu.sh`). See session memory notes (`memory/MEMORY.md`) for the running audit trail.
- **CI:** see `.github/workflows/` (build + package-integrity pipelines).
- **Stability:** research / hobbyist grade. Boot, login, and the AI daemon reach a steady state in QEMU; real-hardware coverage is narrow. See [What this is NOT](#what-this-is-not).
- **Target audience:** developers interested in trust kernels, Win32 compatibility, or AI-mediated OS control. This is not a daily driver.

## What this is

**Layer 0 — `trust.ko` (Root of Authority).** A Linux kernel module that assigns each subject (process, service, user) a signed integer trust score in `[-1000, +1000]`. Scores rise through cooperative behaviour and decay through observed misbehaviour. Every privileged action is gated by a kernel-enforced score threshold. The design borrows from biology: chromosomal segment pairs per subject, an authority proof engine with self-consuming proofs, and a trust regulation core with fixed-point cost multipliers. Source: `trust/kernel/` (9 C files, DKMS-packaged).

**Layer 2 — PE loader.** A native Linux loader that maps, relocates, and runs unmodified Windows `.exe` and `.dll` files without Wine. Parser, mapper, relocator, import resolver, TLS support, SEH, and \~37 `.so` DLL stubs covering `kernel32`, `ntdll`, `user32`, `gdi32`, `advapi32`, `ws2_32`, the D3D family, and more. Registered through `binfmt_misc` with MIME type association so a double-click on an `.exe` in a file manager launches it. Source: `pe-loader/`.

**Layer 4 — AI cortex.** A Python/FastAPI daemon (`ai-control.service`, port 8420) that ingests events from lower layers, consults a decision engine, and issues commands back down. An autonomy controller gates what it can do unattended. LLM integration (via `llama-cpp-python`) is opt-in and acts as a **veto-only** last-stage check — not a principal actor. Source: `ai-control/`.

Commands flow down; events flow up. No layer calls the one above it.

## What this is NOT

- **Not a Wine replacement.** Wine covers a vastly larger Win32 surface, has 20+ years of compatibility work, and handles thousands of real applications. The PE loader here is a focused experiment in direct binary loading — it runs simple console/GUI binaries and has known gaps in COM, printing, and anything touching obscure Win32 subsystems.
- **Not a production distribution.** There is no security audit, no supported upgrade path, no long-term-support kernel pin, and no commercial backing. Use a VM.
- **Not tested against commercial Windows games.** DXVK/VKD3D-Proton are wired in and anti-cheat shims exist, but end-to-end game launches are unverified. The anti-cheat shim presents a convincing Windows 10 environment to passive inspectors only; it has NOT been validated against live anti-cheat products and is OFF by default — see the [Anti-Cheat Warning](#-anti-cheat-warning) above.
- **Not multi-user or hostile-root hardened.** Trust checks run against a root-owned daemon; a compromised root account bypasses every control.
- **Not "Full AI Control" in any autonomous sense.** The name is aspirational. Today the cortex is an event-driven policy arbiter with human-in-the-loop approval for anything destructive. See [`docs/architecture.md`](docs/architecture.md).

## Quick start

See [`docs/quickstart.md`](docs/quickstart.md) for the full walkthrough. The short version, run from WSL2 Arch or native Arch:

```bash
# Build Arch packages (~30s, outputs to repo/x86_64/)
bash scripts/build-packages.sh

# Build bootable ISO (~5 min, requires mkarchiso; outputs to output/)
bash scripts/build-iso.sh

# Boot ISO in QEMU and run the smoke suite (~3 min)
bash scripts/test-qemu.sh

# SSH into the running VM
ssh -p 2222 arch@localhost   # password: arch
```

## Documentation

| Document | Purpose |
|---|---|
| [`docs/quickstart.md`](docs/quickstart.md) | End-to-end first boot walkthrough. |
| [`docs/architecture.md`](docs/architecture.md) | 5-layer model, trust ontologies, event bus, honest limitations. |
| [`docs/pe-compat.md`](docs/pe-compat.md) | Win32 compatibility matrix and loader internals. |
| [`docs/build.md`](docs/build.md) | Full build pipeline and reproducibility notes. |
| [`docs/system-summary.md`](docs/system-summary.md) | `/system/summary` endpoint reference. |
| `CLAUDE.md` | AI-assistant-facing project map. Not a user doc. |
| `PLAN/` | Original vision documents, including the Root of Authority paper. |

## License

No `LICENSE` file is currently committed. Until one is added, assume "all rights reserved" — do not redistribute. See the `PLAN/` directory for original authorship.

## Credits

The biologically-inspired trust system (Root of Authority / RoA) is the core research contribution. The model, the 23-segment chromosomal subject layout, the Authority Proof Engine, and the Trust Regulation Core all trace to the PDF in `PLAN/Root_of_Authority_Full_Paper(full).pdf`. Readers who want to understand *why* the trust kernel looks the way it does should start there.

Lower-level infrastructure stands on the shoulders of: the Linux kernel, Arch Linux, `mkarchiso`, DXVK, VKD3D-Proton, `llama-cpp-python`, and FastAPI.

## Contributing

This project is developed in numbered "sessions", each a round of multi-agent audits followed by a consolidation commit. Session notes live in `memory/MEMORY.md` (for humans) and the per-session files it links. The pattern is: identify a concrete invariant or bug class, fix every instance across the tree, document the rule so the next session inherits it. New contributors are asked to:

1. Read at least the last three session notes before opening a PR.
2. Respect the single-source-of-truth headers called out in `CLAUDE.md`'s "Known Pitfalls" section (e.g. don't mix `trust_types.h` and `trust_internal.h`).
3. Add or extend a QEMU smoke test for any new subsystem.
