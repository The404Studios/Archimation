# ARCHIMATION — Architecture Roadmap S71

**Synthesis of 12 parallel research reports** (S71 agents A-L, 2026-04-20).

Each agent picked one architectural vector, surveyed 2024-2026 literature + code, and cost-estimated a concrete upgrade. Reports live at `docs/research/s71_{a..l}_*.md`. This document picks the winners and sequences them.

---

## Executive takeaways (ultra-compressed)

1. **The moat is `trust.ko`'s APE + chromosomal model + biological vocabulary — don't lose it.** ~1800 LOC of *observation* can migrate to an eBPF sidecar; the *authority proof engine* must stay kernel-resident. A 200-LOC `trust_lsm.c` wrapper additionally plugs trust.ko into 7 mainline LSM hooks.
2. **The trust moat has a practical hole: the kernel module itself is unsigned.** `trust-dkms` builds trust.ko with zero MOK / sign-file integration. A thirty-line fix in `trust-dkms.install` closes this. Ship before anything else.
3. **Three 1-session adoption wins** dominate the cost/value curve: (a) BTRFS auto-snapshots on every pacman tx; (b) Wine-handoff shim for 32-bit PE; (c) `linux-hardened` as an opt-in kernel package.
4. **Old hardware isn't the problem. The assumptions are.** Every research finding is "works on Arch rolling = modern kernel" friendly. The only real old-hw concession is `ai.display=x11` boot mode.
5. **New hardware has five explicit wins we're leaving on the table**: Wayland HDR/VRR, sched_ext + scx_lavd, on-device LLM tier (1B-70B), NPU acceleration (Intel/AMD XDNA2 mainlined 6.14), measured-boot TPM2 sealing.
6. **Do NOT chase io_uring in the Python daemon.** Python's io_uring story is still broken in 2026 (uvloop=epoll, granian=Tokio-not-tokio-uring). The win is finishing the S68/S69 `subprocess.run → asyncio.create_subprocess_exec` migration (~30 sites, ~300 LOC).
7. **Learning upgrade path is bandits → retrieval → LoRA**, not DPO/GRPO/PPO. 200-LOC `HandlerBanditModel` over 121 handlers beats a fine-tuned Qwen for the first iteration.
8. **ARM64 matters; RISC-V is experimental.** Apple M-series (Asahi) + Snapdragon X Elite (Qualcomm) = real user demand. RISC-V hardware is Pi-class in 2026.

---

## Priority Tiers

### Tier 1 — ship in S72 (total: ~4-6 sessions, ~1300 LOC)

| # | Item | Agent | Cost | Why now |
|---|---|---|---|---|
| 1 | **DKMS module signing** via per-install MOK + `sign-file` hook | K | 30 LOC | trust.ko's software moat is moot without it |
| 2 | **BTRFS + `snap-pac` + `grub-btrfs`** wired into `ai-install-to-disk --fs=auto` | G | 260 LOC | Turns "bad update" from brick-risk into reboot + rollback |
| 3 | **Wine-handoff shim for PE32** — reject path becomes `exec /usr/bin/wine` + `libtrust_wine_shim.so` LD_PRELOAD gating `NtOpenFile`/`NtCreateSection` | D | ~600 LOC | Closes S69 audit's #1 adoption gap (pre-2010 apps) |
| 4 | **`linux-hardened`** added to `profile/packages.x86_64` as optional | H | 1 line + docs | PKGBUILD hooks already exist at trust-dkms/PKGBUILD:92-95; one-line away |
| 5 | **pahole version guard** in `scripts/build-packages.sh` (pattern: S67's `verify_trust_dkms_manifest`) | H | ~50 LOC | BTF breakage is otherwise silent; behavioral_markov eBPF path depends on it |
| 6 | **`trust_lsm.c`** — 200 LOC wrapper registering trust.ko as a stacked LSM on 7 hooks (`file_open`, `file_permission`, `socket_{bind,connect}`, `task_kill`, `bprm_check_security`, `capable`); each shim calls existing `trust_authz_check()` | B | 200 LOC | Architectural legitimacy without breaking existing kprobe path |

**Expected outcome:** signed trust.ko on `linux-hardened`, atomic snapshot rollback, Steam-game-era Windows binaries work again via Wine fallback, trust.ko gains proper LSM registration.

### Tier 2 — high value (total: ~8-12 sessions, ~2500 LOC)

| # | Item | Agent | Cost |
|---|---|---|---|
| 7 | **`trust-bpf` sidecar Phase 1** — libbpf-rs, single fentry parity test alongside existing kprobe | A | ~800 LOC |
| 8 | **`gfx_wayland.c` Phase 1** — already 580-LOC stub (!) needs wiring to real wl_surface + shm + keyboard; env-gated `GFX_BACKEND=wayland` | E | ~500 LOC |
| 9 | **`HandlerBanditModel`** — Thompson-Sampling Beta posteriors over 121 handlers, ~10 KB RAM, sits alongside `DecisionMarkovModel` | L | ~200 LOC |
| 10 | **`scx_lavd` pilot** on `pe-compat.slice` for NEW-tier hardware, feature-flagged | I | ~100 LOC + scx pkg |
| 11 | **Per-process Landlock sandbox** in `pe-loader/loader/` spawn path (replaces 30-40% of runtime authz with battle-tested upstream) | B | ~150 LOC |
| 12 | **llama-server over Unix socket** replacing `llama-cpp-python` dep; tier-detection module (`llm_runtime.py`) picks T0-T6 by `/proc/meminfo` + GPU nodes | C | ~400 LOC |
| 13 | **XInput already landed S69** — but **SDL2 → XInput remap**, controller hotplug, force-feedback event fan-out | P-legacy | ~200 LOC |
| 14 | **`ai-cortex.slice` split** from `ai-daemon.slice` so cortex's `AllowedCPUs` can target E-cores on hybrid hosts | I | ~40 LOC |
| 15 | **Finish S68/S69 subprocess migration** — ~30 remaining `subprocess.run` sites in `compositor.py`/`gpu.py`/`screen.py`/etc. → `asyncio.create_subprocess_exec` | J | ~300 LOC |

### Tier 3 — aspirational / months (total: ~20+ sessions)

16. **UKI + systemd-boot + `sbctl` pacman-hook + TPM2-sealed LUKS2** — migrate the ISO from GRUB to systemd-boot with a signed unified kernel image; sealed LUKS2 with `--tpm2-pcrs=7+11+12` gives password-free boot bound to our signed UKI set (**Agent K, 2 sessions ISO rework**)
17. **ARM64 port Phase A** — FEX-Emu / Hangover fallback for x86 PE binaries on Asahi + Snapdragon X Elite (**Agent F, 2-3 sessions**)
18. **ARM64 port Phase B** — native Windows-ARM64 PE32+ support in pe-loader (IMAGE_FILE_MACHINE_ARM64=0xAA64); arm64 thunk + reloc types + SEH (~3-5 kLOC)
19. **Enforcement via BPF-LSM** — trust-bpf sidecar Phase 2 with `bpf_override_return(-EPERM)` for policy decisions, flag-gated (`TRUST_ENFORCEMENT=on`) (**Agent A Phase 2**)
20. **kprobe path deletion** in trust.ko after 6 months of LSM path stability — ~1800 LOC net removal
21. **OSTree / bootc retrofit** — only if user demand for "rebase to channel" materializes (Agent G long-horizon)
22. **Embedding retrieval for cortex** — sentence-transformers MiniLM ~110 ms CPU; triggered only if bandits cold-start (Agent L S73+)
23. **LoRA fine-tune Qwen2.5-1.5B** on 2-week trace dataset with KTO; only if retrieval plateaus (Agent L S74+)
24. **RISC-V experimental track** — trust.ko + AI daemon only, no native PE (no RV64 Windows ecosystem exists in 2026)

---

## Old / New hardware compatibility matrix

| Subsystem | Old (pre-2013, Sandy/Ivy Bridge, TPM 1.2 or none) | New (2020+, Alder/Zen 3+, TPM 2.0) |
|---|---|---|
| **trust.ko authority root** | ✅ identical | ✅ identical |
| **trust-bpf sidecar** (eBPF) | ⚠ requires kernel 5.4+ BTF; Arch rolling is fine, vendor kernels need pahole sideload | ✅ BPF arena (6.7+), sched_ext (6.12+) |
| **Module signing (MOK)** | ✅ works | ✅ works; UKI + TPM2 sealing unlocks password-free boot |
| **Atomic updates** | ⚠ ext4 fallback — no snapshots; snap-pac degrades to no-op. Pacman updates still work. | ✅ BTRFS subvolumes `@`/`@home`/`@var`/`@log`/`@pkg`/`@snapshots`, zstd:3, snapper |
| **PE32 via Wine shim** | ✅ works (multilib + Wine 11.0+) | ✅ works |
| **AI cortex LLM** | Markov + `Qwen2.5-1.5B-Q4_K_M` (1 GB resident, 10-14 t/s on Skylake AVX2) | 7B-14B on CPU, 70B on GPU or Apple Metal; NPU where available (XDNA2 mainlined 6.14) |
| **Wayland compositing** | ⚠ X11 via `ai.display=x11` boot mode — recommend for pre-2013 Intel IGPs | ✅ Wayland default; HDR (DRM Color Pipeline 6.8+), VRR (KDE 6.0+), fractional scaling |
| **KSPP hardening** | ⚠ ~5-10% CPU cost on pre-Haswell (no SMEP, KPTI expensive, no PCID) | ✅ ~2-4% cost on Ice Lake+ |
| **Hybrid-CPU scheduling** | ✅ EEVDF default on single/dual-core Sandy is fine | ✅ sched_ext `scx_lavd` for pe-compat.slice; E-cores for cortex batch |
| **io_uring** | ⚠ epoll fallback (kernel <5.1) | ❌ No direct daemon win (Python gap); real win = finish subprocess asyncio migration |
| **Measured boot / TPM2** | ⚠ sbctl Secure Boot only (no TPM sealing) | ✅ sbctl + UKI + TPM2 PCR 7+11+12 sealing |
| **Learning (bandits → retrieval → LoRA)** | ✅ bandits are CPU-cheap (10 KB RAM); retrieval at 100-200ms on Skylake | ✅ LoRA fine-tune Qwen2.5-1.5B in 30 min on RTX 4060 |
| **ARM64** | ❌ N/A — no 2013-era ARM64 laptops | ✅ Asahi + Snapdragon X Elite via FEX-Emu (Phase A); native WinARM64 PE (Phase B) |
| **RISC-V** | ❌ N/A | ⚠ experimental — trust.ko + daemon only, no native PE |

---

## The moat — explicitly enumerated after 12 surveys

Cross-checking which features NO competitor (Wine, VM, Silverblue, Tetragon, Cilium) has:

1. **APE self-consuming proofs** — `trust_ape.c`, Pn+1 = Hash(Pn ‖ req ‖ seed ‖ nonce ‖ ts ‖ chromosome_checksum). Uniquely ours. (Agent B confirmed: NO LSM has this.)
2. **Chromosomal 23-segment model** — `trust_chromosome.c`, meiosis + gene expression vocabulary. Uniquely ours.
3. **Fixed-point 8.8 Trust Regulation Core** — `trust_core.c`, tunable cost-multiplier per-domain. Uniquely ours.
4. **GPU-dispatch RISC ISA in kernel module** — `trust_dispatch_tables.c`, 6 families × 32-bit instruction word. Uniquely ours.
5. **Markov chi-square witness** for adaptive trust — `trust_ape_markov.c`, Theorem 3 statistical point-test. Uniquely ours.
6. **Veto-only AI cortex gating kernel driver loads** — `wdm_host_signature.c` + `scm_api.c:93` + `cortex/decision_engine.py`. Uniquely ours; no Wine, no VM, no hypervisor does all three.
7. **45K-phrase dictionary_v2 with Markov fallback** — fully offline, no LLM vendor lock. Ours.

Everything ELSE — eBPF observation, LSM hooks, Landlock sandboxing, BTRFS snapshots, UKI signing, scheduler tuning, LLM inference, compositor — is industry-standard. We should adopt it wholesale. The moat is (1) through (7).

---

## "Works on old AND new" — the unifying principle

Every Tier-1 and Tier-2 item passes this test:

- **Tier 1 #1** (DKMS MOK): works on TPM 1.2 and TPM-absent hardware with software-only measured boot.
- **Tier 1 #2** (BTRFS): `ai-install-to-disk --fs=auto` picks BTRFS for disks ≥64GB, ext4 below. Old mechanical drives stay functional.
- **Tier 1 #3** (Wine shim): multilib + Wine 11.0 works on any x86_64 CPU with IA-32 emulation (Linux 1.0-era).
- **Tier 1 #4** (`linux-hardened`): opt-in package, not default. No regression for users on `linux`.
- **Tier 1 #5** (pahole guard): build-time only, no runtime cost.
- **Tier 1 #6** (trust_lsm.c): LSM hooks stable API since 5.1; works everywhere trust.ko already works.
- **Tier 2 #7** (trust-bpf): parallel to existing kprobe path during parity phase; kprobe fallback if BTF unavailable.
- **Tier 2 #8** (Wayland): opt-in via env var; X11 remains default boot.
- **Tier 2 #9** (bandits): 10 KB RAM; works on any CPU.
- **Tier 2 #10** (scx_lavd): feature-flag + fallback to EEVDF automatic; zero-risk.
- **Tier 2 #12** (llama-server): tier detection picks 1.5B on low RAM, 7B on 8GB, 14B+ on 32GB+, no LLM at all if <4GB.

The distribution ships one ISO + one package-tree + one install path. Hardware tier is detected at install time + boot time; features adapt.

---

## What NOT to do

From the research, explicit "don't" list:

- **Don't build an OSTree-native ARCHIMATION** as primary — too much rework for unclear user demand (Agent G).
- **Don't chase Python io_uring** — ecosystem still broken in 2026; Granian is Tokio not tokio-uring (Agent J).
- **Don't start with DPO/PPO/GRPO** — 121-way handler classification is a bandit problem, not an LLM problem (Agent L).
- **Don't LTO_CLANG_FULL** — breaks BTF (Agent H).
- **Don't try native PE32 WoW64 in-tree** — 8-12 sessions to duplicate 25 years of Wine; use the handoff shim instead (Agent D).
- **Don't port to bcachefs** — Linus removed from mainline in 6.17 (Aug 2025); DKMS-only in 2026 (Agent G).
- **Don't target RISC-V as primary** — hardware is Pi-class in 2026, no Windows ecosystem (Agent F).
- **Don't adopt Windows-CA / Windows UEFI CA 2023** dual-cert without SBAT generation numbering — CVE-2023-24932 (Agent K).

---

## Sequenced plan for the next 6 sessions

- **S72**: Tier 1 items 1-5 (signing, BTRFS, Wine shim, linux-hardened, pahole guard). One ISO bake. Verify: 7-point + set_smoke + PE corpus + NEW pe32_via_wine smoke.
- **S73**: Tier 1 item 6 (trust_lsm.c) + Tier 2 item 11 (per-process Landlock). Kernel-side change; requires `linux-headers` in WSL build host to validate DKMS.
- **S74**: Tier 2 item 9 (HandlerBanditModel) + item 14 (ai-cortex.slice split) + item 15 (subprocess migration). Python-only session, fast iteration.
- **S75**: Tier 2 item 8 (Wayland Phase 1). Risky — GTK/XFCE impact. Keep X11 default; Wayland env-gated.
- **S76**: Tier 2 item 7 (trust-bpf sidecar parity). Requires libbpf-rs toolchain; dedicated build-system session.
- **S77**: Tier 2 item 10 (scx_lavd pilot) + item 12 (llama-server tier detection). New-hardware demonstration.

Total: 6 sessions → ARCHIMATION pkg-30-ish ships with signed kernel modules, atomic updates, PE32 support, Wayland optional, LSM-proper trust.ko, learning AI cortex, hybrid-CPU-aware scheduling, and on-device LLM tier.

---

## Per-agent report index

| Agent | Topic | Report | Top 1 recommendation |
|---|---|---|---|
| A | eBPF observability | `docs/research/s71_a_ebpf_observability.md` | `trust-bpf` sidecar on libbpf-rs |
| B | Modern LSM | `docs/research/s71_b_modern_lsm.md` | `trust_lsm.c` stacked LSM registration |
| C | On-device LLM | `docs/research/s71_c_on_device_llm.md` | Drop `llama-cpp-python` → `llama-server` over UDS + tier detection |
| D | WoW64 / PE32 | `docs/research/s71_d_wow64_pe32.md` | Wine-handoff shim (not native PE32) |
| E | Wayland + gaming | `docs/research/s71_e_wayland_gaming.md` | Finish `gfx_wayland.c` Phase 1; GameScope handler |
| F | RISC-V / ARM64 | `docs/research/s71_f_risc_v_arm64.md` | AArch64 Phase A (FEX), Phase B (WinARM64) |
| G | Atomic updates | `docs/research/s71_g_atomic_updates.md` | `ai-install-to-disk --fs=auto` with BTRFS + snap-pac |
| H | Kernel hardening | `docs/research/s71_h_kernel_hardening.md` | Ship `linux-hardened` opt-in + pahole guard |
| I | Hybrid CPU | `docs/research/s71_i_hybrid_cpu.md` | `scx_lavd` pilot on pe-compat.slice |
| J | io_uring | `docs/research/s71_j_io_uring.md` | Don't chase io_uring; finish subprocess migration |
| K | Measured boot | `docs/research/s71_k_measured_boot.md` | DKMS MOK signing (30 LOC) + optional UKI |
| L | RL feedback | `docs/research/s71_l_rl_feedback.md` | `HandlerBanditModel` Thompson Sampling |

---

**Total research volume: ~4,500 lines of Markdown, ~250 cited URLs, 12 concurrent agents, 2026-04-20.**

**Recommendation**: execute Tier 1 in S72 (roughly one session of parallel agent work mirroring S68/S69 structure), then evaluate against pkg-24 ISO. If all 6 Tier-1 items land + QEMU stays green, move to Tier 2.
